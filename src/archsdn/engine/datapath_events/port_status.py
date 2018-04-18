
import logging
from ipaddress import IPv4Address
import struct
from uuid import UUID

from scapy.packet import Padding, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNSRR, DNS, DNSQR

from ryu.ofproto import ether
from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import services

_log = logging.getLogger(logger_module_name(__file__))


def process_event(port_change_event):
    """
    This procedure answer to port change events, sent by the OpenFlow switches present in the sector.

    Three different types of events are handled by this procedure:
    1) New port added to the switch
    2) Existent port removed from the switch
    3) Port state changed.

    <-- Adding new Port -->
    When a new port is added to the switch, the controller registers the new port and waits for the reception of DHCP
    packets or ArchSDN discovery beacon packets. Nothing more is done.

    <-- Removing existent Port -->
    When an existent port is removed, it is necessary to remove the flows associated with this port. Flows in
    __PORT_SEGREGATION_TABLE which match the input port with the removed port are removed.
    Then, it is necessary to determine which active scenarios have been affected by the loss of this port and disable
    them. By disabling the scenarios, flows will be removed from this and other switches.
    It is preferable to determine which network scenarios are affected, for the sake of organization, instead of just
    removing all the flows which match or output packets to the removed port.

    <-- Port State Change -->
    Two port state changes are handled by ArchSDN:
      1) Link Down (OFPPS_LINK_DOWN) - Link connection was lost (cable disconnected)
        - In this case, flows in __PORT_SEGREGATION_TABLE which match the input port to the port which lost link are
          removed. Then, it is necessary to determine which active scenarios have been affected, and reinstate those
          scenarios is the priority.

      2) Link Live (OFPPS_LIVE) - Link connection was established (cable connect).
        - New state is registered and port is considered to be Up. The packets received (DHCP and ArchSDN discovery
        beacon) through the interface will determine what will happen next.


    :param port_change_event: ofp_event.EventOFPPortStateChange instance
    :return: None
    """
    assert globals.default_configs, "engine not initialised"

    ofp_port_reason = {
        0: "The port was added",
        1: "The port was removed",
        2: "Some attribute of the port has changed"
    }
    datapath_obj = port_change_event.datapath
    datapath_id = port_change_event.datapath.id
    ofp_parser = datapath_obj.ofproto_parser
    ofp = datapath_obj.ofproto
    port_no = port_change_event.port_no
    reason_num = port_change_event.reason
    switch = sector.query_entity(datapath_id)

    if reason_num in ofp_port_reason:
        _log.info(
            "Port Status Event at Switch {:016X} Port {:d} Reason: {:s}".format(
                datapath_id,
                port_no,
                ofp_port_reason[reason_num]
            )
        )

        if reason_num == 0:
            port = datapath_obj.ports[port_no]
            switch.register_port(
                port_no=port.port_no,
                hw_addr=EUI(port.hw_addr),
                name=port.name.decode('ascii'),
                config=entities.Switch.PORT_CONFIG(port.config),
                state=entities.Switch.PORT_STATE(port.state),
                curr=entities.Switch.PORT_FEATURES(port.curr),
                advertised=entities.Switch.PORT_FEATURES(port.advertised),
                supported=entities.Switch.PORT_FEATURES(port.supported),
                peer=entities.Switch.PORT_FEATURES(port.peer),
                curr_speed=port.curr_speed,
                max_speed=port.max_speed
            )

        elif reason_num == 1:
            if port_no in switch.ports:
                switch.remove_port(port_no)
            else:
                _log.warning(
                    "Port {:d} not previously registered at Switch {:016X}.".format(
                        port_no, datapath_id
                    )
                )

        else:
            port = datapath_obj.ports[port_no]

            old_config = switch.ports[port_no]['config']
            new_config = entities.Switch.PORT_CONFIG(port.config)
            if old_config != new_config:
                _log.warning(
                    "Port {:d} config at Switch {:016X} changed from {:s} to {:s}".format(
                        port_no, datapath_id, str(old_config), str(new_config)
                    )
                )
                switch.ports[port_no]['config'] = new_config

            old_state = switch.ports[port_no]['state']
            new_state = entities.Switch.PORT_STATE(port.state)
            if old_state != new_state:  # If the port state has changed...
                if entities.Switch.PORT_STATE.OFPPS_LINK_DOWN in new_state:  # Port link state is Down...

                    # Removes all flows at __PORT_SEGREGATION_TABLE matching the removed port
                    datapath_obj.send_msg(
                        ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            table_id=globals.PORT_SEGREGATION_TABLE,
                            command=ofp.OFPFC_DELETE,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(in_port=port_no)
                        )
                    )
                    globals.send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

                    def flow_filter(elem):
                        (flow_obj, switch_id) = elem
                        if switch_id != datapath_id:
                            return False
                        if flow_obj.match:
                            for match_field in flow_obj.match.fields:
                                return type(match_field) is ofp_parser.MTInPort and match_field.value == port_no

                    filtered_flows = tuple(filter(flow_filter, globals.active_flows.items()))
                    for (flow, _) in filtered_flows:
                        _log.warning(
                            "Flow with ID {:d} configured at Switch {:016X} for port {:d} was removed".format(
                                flow.cookie, port_no, datapath_id
                            )
                        )
                        del globals.active_flows[flow.cookie]
                        globals.free_cookie_id(flow.cookie)

                elif entities.Switch.PORT_STATE.OFPPS_LIVE in new_state: # Port link state is Live...
                    # TODO: This event could be used to try and reestablish previous scenarios that were once lost...
                    pass

                _log.warning(
                    "Port {:d} state at Switch {:016X} changed from {:s} to {:s}".format(
                        port_no, datapath_id, str(old_state), str(new_state)
                    )
                )
                switch.ports[port_no]['state'] = new_state

    else:
        raise Exception("Reason with value {:d} is unknown to specification.".format(reason_num))


