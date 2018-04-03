import logging
from ipaddress import ip_address, IPv4Address
import sys
import struct
from uuid import UUID
from ctypes import c_uint64

from scapy.packet import Padding, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNSRR, DNS, DNSQR

from ryu.lib import hub
from ryu.ofproto import ether
from netaddr import EUI

from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import entities


_log = logging.getLogger(logger_module_name(__file__))
__default_configs = None


#
# Topology Discovery Beacons
#
# The following globals are used for the sector topology discovery
#  __topology_beacons -> Active topology beacons
#  __beacons_hash_table -> Encoded Hash table
#
__topology_beacons = {}  # __topology_beacons[switch id] = Beacon_Task
__beacons_hash_table = {}  # __beacons_hash_table[hash] = (switch id, port_out)


#
# Cookie IDs generator
#
# The following globals are used to maintain unique and ready-to-use cookie ids.
#
# __recycled_cookie_ids -> A list of previously used cookie ids, which can be recycled
# __cookie_id_counter -> cookie ID counter
#
__recycled_cookie_ids = []
__cookie_id_counter = 0


#
# Active Flows
#
# This global is a dictionary and keeps a record of the activated flows in the sector.
#   The dictionary keys are the cookie_id's of each activated flow, and it indexes the flow and the switch ID where the
#   flow is activated.
#
__active_flows = {}  # __active_flows[cookie id] = (flow, switch id)


#
# MPLS Tunnels Information
#
# The MPLS tunnels are activated in table 1.
# Table 1 will be responsible for matching labels and sending them through the proper network interface
# When a host packet is ingressed in a tunnel, table 0 matches the packet and adds the MPLS label. Then, the packet is
#  sent to table 1 to execute the MPLS switching.
# When a MPLS packet is received, table 1 will perform one of the following actions:
#  a) Removes the MPLS header and switches the packet into the interface where the destination host is.
#  b) Updates the MPLS label and switches the packet to another interface, accordingly.
#
# MPLS Tunnels - Different types
#  From Host to Host (Same-Sector, Ingress and Egress)
#  From Host to Sector (Cross-Sector, Ingress)
#  From Sector to Host (Cross-Sector, Egress)
#  From Sector to Sector (Cross-Sector, Intermediary)
#
__active_sector_tunnels = {}  # __active_sector_tunnels[tunnel_id] = Tunnel Scenario


#
# Differentiated Services Information
#
# Services are seen in a perspective of mapped entries to outputs at the boundaries
#  When a host or a sector sends a packet through a switch port, the switch decides what to do with the packet.
#  If the packet comes from a host and there's service activate to that type of packet, the packet is ingressed in an
#   activated MPLS tunnel.
#  If the packet comes from a sector, the switch will do one of the following actions:
#    a) The packet is egressed from the MPLS tunnel (header is removed and packet is delivered to the target host).
#    b) The packet MPLS label ID is updated and the packet is switches through another interface.
#
# There are cases where a MPLS tunnel is not required. These cases exist when two hosts trying to communicate with each
#   other, are connected directly to the same switch. In this case, the switch can simply switch the packets from on
#   interface to the other.
#
#
# For future development, services requiring multicast support, can be built over MPLS tunnels.

# Different scenarios usage for MPLS Tunnels
# - Packet host ingressing (Host -> Tunnel)
# - Packet host egressing (Tunnel -> Host)
# - Packet mpls label update (Tunnel -> Tunnel)

__mapped_services = {}  # __mapped_services[switch_id]["Service"]["service details"] = (tunnel_id or port_out)
# __mapped_services[switch_id] = {
#  "ICMP4" -> __mapped_services[switch_id]["ICMP4"][(src_ip, dst_ip)] = (tunnel_id, port_out, cookies)
#  "IPv4" ->  __mapped_services[switch_id]["IP4"][(src_ip, dst_ip)][(src_port, dst_port)] = (tunnel_id, port_out, cookies)
#  "MPLS" ->  __mapped_services[switch_id]["MPLS"][port][label_id] = (tunnel_id, port_out, cookies)
# }


# Table Flows Types
__SERVICE_OF_TABLE_NUM = 0
__MPLS_OF_TABLE_NUM = 1

# Flows priority values
__DEFAULT_PRIORITY = 0x8000
__MPLS_FLOW_PRIORITY = 0x8000+1
__BASE_SERVICE_PRIORITY = 0x8000+2
__SERVICE_FLOW_PRIORITY = 0x8000+3


def __alloc_cookie_id():
    global __cookie_id_counter

    if __cookie_id_counter == 0xFFFFFFFFFFFFFFFF:
        raise ValueError("No more cookies left...")
    if len(__recycled_cookie_ids):
        cookie_id = __recycled_cookie_ids.pop()
        _log.debug("Cookie ID {:d} was acquired.".format(cookie_id))
        return cookie_id
    __cookie_id_counter = __cookie_id_counter + 1
    _log.debug("Cookie ID {:d} was acquired.".format(__cookie_id_counter))
    return __cookie_id_counter


def __free_cookie_id(cookie_id):
    global __cookie_id_counter

    if cookie_id <= 0:
        raise ValueError("Cookies cannot be zero or negative.")
    if cookie_id > __cookie_id_counter:
        raise ValueError("That cookie was not allocated.")
    if cookie_id in __recycled_cookie_ids:
        raise ValueError("Cookie already free.")
    __recycled_cookie_ids.append(cookie_id)

    while len(__recycled_cookie_ids) > 0:
        max_value = max(__recycled_cookie_ids)
        if __cookie_id_counter == max_value:
            __recycled_cookie_ids.remove(max_value)
            __cookie_id_counter = __cookie_id_counter - 1
        else:
            break
    _log.debug("Cookie ID {:d} was released.".format(cookie_id))


def __send_msg(*args, **kwargs):
    return __default_configs["send_msg"](*args, **kwargs)


def __get_datapath(*args, **kwargs):
    return __default_configs["get_datapath"](*args, **kwargs)


def initialise(default_configs):
    global __default_configs, __active_flows, __topology_beacons
    global __cookie_id_counter, __recycled_cookie_ids
    sector.initialise()

    __default_configs = default_configs
    __active_flows = {}
    __topology_beacons = {}

    __recycled_cookie_ids = []
    __cookie_id_counter = 0


def process_datapath_event(dp_event):
    assert __default_configs, "engine not initialised"

    _log.info("Datapath Event: {:s}".format(str(dp_event.__dict__)))

    datapath_obj = dp_event.dp
    datapath_id = dp_event.dp.id
    ofp_parser = datapath_obj.ofproto_parser
    ofp = datapath_obj.ofproto
    controller_uuid = database.get_database_info()["uuid"]
    central_policies_addresses = database.query_volatile_info()

    if dp_event.enter:
        ipv4_info = None
        ipv6_info = None
        if ip_address(dp_event.dp.address[0]).version is 4:
            ipv4_info = (ip_address(dp_event.dp.address[0]), dp_event.dp.address[1])
        if ip_address(dp_event.dp.address[0]).version is 6:
            ipv6_info = (ip_address(dp_event.dp.address[0]), dp_event.dp.address[1])

        assert ipv4_info or ipv6_info, 'ipv4_info and ipv6_info are None at the same time'

        def __send_discovery_beacon():
            global __beacons_hash_table

            try:
                ports = datapath_obj.ports
                _log.info("Starting beacon for Switch {:016X}".format(datapath_id))

                while datapath_obj.is_active:
                    for port_no in ports:
                        if not (ports[port_no].state & ofp.OFPPS_LINK_DOWN) and \
                                (
                                    (
                                        sector.is_port_connected(datapath_id, port_no) and
                                        isinstance(
                                            sector.query_connected_entity_id(datapath_id, port_no),
                                            entities.Sector
                                        )
                                    ) or
                                    (
                                        not sector.is_port_connected(datapath_id, port_no)
                                    )
                                ):

                            hash_val = c_uint64(hash((datapath_id, port_no))).value
                            if hash_val not in __beacons_hash_table:
                                __beacons_hash_table[hash_val] = (datapath_id, port_no)
                            beacon = Ether(
                                src=str(central_policies_addresses['mac_service']),
                                dst="FF:FF:FF:FF:FF:FF",
                                type=0xAAAA
                            ) / Raw(
                                load=struct.pack(
                                    "!H16s8s",
                                    1, controller_uuid.bytes,
                                    hash_val.to_bytes(8, byteorder='big')
                                )
                            )

                            _log.debug(
                                "Sending beacon through port {:d} of switch {:016X} with hash value {:X}".format(
                                    port_no, datapath_id, hash_val
                                )
                            )

                            datapath_obj.send_msg(
                                ofp_parser.OFPPacketOut(
                                    datapath=datapath_obj,
                                    buffer_id=ofp.OFP_NO_BUFFER,
                                    in_port=port_no,
                                    actions=[ofp_parser.OFPActionOutput(port=port_no)],
                                    data=bytes(beacon)
                                )
                            )
                    hub.sleep(3)

                hash_vals = tuple(
                    filter(
                        (lambda val: __beacons_hash_table[val][0] == datapath_id), __beacons_hash_table.keys()
                    )
                )
                for val in hash_vals:
                    del __beacons_hash_table[val]

                _log.warning("Switch {:016X} is no longer active. Beacon manager is terminating.".format(datapath_id))

            except Exception:
                custom_logging_callback(_log, logging.ERROR, *sys.exc_info())

        if sector.is_entity_registered(datapath_id):
            sector.remove_entity(datapath_id)

        #  Prepare __mapped_services to receive service activations
        __mapped_services[datapath_id] = {
            "ICMP4": {},
            "IPv4": {},
            "MPLS": {},
        }

        switch = entities.Switch(
            id=datapath_id,
            control_ip=ipv4_info[0] if ipv4_info else ipv6_info[0] if ipv6_info else None,
            control_port=6631,
            of_version=dp_event.dp.ofproto.OFP_VERSION
        )

        for port in dp_event.ports:
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
        sector.register_entity(switch)
        database.register_datapath(datapath_id=datapath_id, ipv4_info=ipv4_info, ipv6_info=ipv6_info)

        #
        # Reset Switch state and initialize bootstrap sequence
        #
        # When a switch connects, it is complex to know in which state it is.
        # So, it is preferable to clear all flows (if there are any) and restart everything.
        # Instructions order for proper reset of a switch
        #  1 -> Disable all ports, except for the control
        #  2 -> Clear all flow tables, group table and meter table

        # Stage 1 -> Disable all switching ports
        for port in dp_event.ports:
            datapath_obj.send_msg(
                ofp_parser.OFPPortMod(
                    datapath=datapath_obj,
                    port_no=port.port_no,
                    hw_addr=port.hw_addr,
                    config=ofp.OFPPC_PORT_DOWN,
                    mask=ofp.OFPPC_PORT_DOWN,
                    advertise=0
                )
            )
        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        datapath_obj.send_msg(  # Removes all flows registered in this switch.
            ofp_parser.OFPFlowMod(
                datapath=datapath_obj,
                cookie=0,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
                table_id=ofp.OFPTT_ALL,
                command=ofp.OFPFC_DELETE,
                idle_timeout=0,
                hard_timeout=0,
                priority=__BASE_SERVICE_PRIORITY,
                buffer_id=ofp.OFP_NO_BUFFER,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                match=None,
                instructions=None
            )
        )

        # OVS 2.1 and Zodiac FX do not support group mods
        # datapath.send_msg(  # Removes all groups registered in this switch.
        #     ofp_parser.OFPGroupMod(
        #         datapath=datapath,
        #         command=ofp.OFPGC_DELETE,
        #         group_id=ofp.OFPG_ALL,
        #     )
        # )

        datapath_obj.send_msg(  # Removes all meters registered in this switch.
            ofp_parser.OFPMeterMod(
                datapath=datapath_obj,
                command=ofp.OFPMC_DELETE,
                meter_id=ofp.OFPM_ALL,
            )
        )
        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        for port in dp_event.ports:
            if not (port.state & ofp.OFPPS_LINK_DOWN):
                boot_dhcp = ofp_parser.OFPFlowMod(
                    datapath=datapath_obj,
                    cookie=__alloc_cookie_id(),
                    cookie_mask=0,
                    table_id=__SERVICE_OF_TABLE_NUM,
                    command=ofp.OFPFC_ADD,
                    idle_timeout=0,
                    hard_timeout=0,
                    priority=__BASE_SERVICE_PRIORITY,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                    match=ofp_parser.OFPMatch(
                        in_port=port.port_no, eth_dst='ff:ff:ff:ff:ff:ff', eth_type=ether.ETH_TYPE_IP,
                        ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17,
                        udp_src=68, udp_dst=67
                    ),
                    instructions=[
                        ofp_parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [
                                ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                            ]
                        )
                    ]
                )
                datapath_obj.send_msg(boot_dhcp)
                __active_flows[boot_dhcp.cookie] = (boot_dhcp, datapath_obj.id)

                archsdn_beacon = ofp_parser.OFPFlowMod(
                    datapath=datapath_obj,
                    cookie=__alloc_cookie_id(),
                    cookie_mask=0,
                    table_id=__SERVICE_OF_TABLE_NUM,
                    command=ofp.OFPFC_ADD,
                    idle_timeout=0,
                    hard_timeout=0,
                    priority=__BASE_SERVICE_PRIORITY,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                    match=ofp_parser.OFPMatch(in_port=port.port_no, eth_type=0xAAAA),
                    instructions=[
                        ofp_parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [
                                ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                            ]
                        )
                    ]
                )
                datapath_obj.send_msg(archsdn_beacon)
                __active_flows[archsdn_beacon.cookie] = (archsdn_beacon, datapath_obj.id)

                mpls_packets = ofp_parser.OFPFlowMod(
                    datapath=datapath_obj,
                    cookie=__alloc_cookie_id(),
                    cookie_mask=0,
                    table_id=__SERVICE_OF_TABLE_NUM,
                    command=ofp.OFPFC_ADD,
                    idle_timeout=0,
                    hard_timeout=0,
                    priority=__MPLS_FLOW_PRIORITY,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                    match=ofp_parser.OFPMatch(in_port=port.port_no, eth_type=ether.ETH_TYPE_MPLS),
                    instructions=[ofp_parser.OFPInstructionGotoTable(table_id=__MPLS_OF_TABLE_NUM)]
                )
                datapath_obj.send_msg(mpls_packets)
                __active_flows[mpls_packets.cookie] = (mpls_packets, datapath_obj.id)

        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        for port in dp_event.ports:
            datapath_obj.send_msg(
                ofp_parser.OFPPortMod(
                    datapath=datapath_obj,
                    port_no=port.port_no,
                    hw_addr=port.hw_addr,
                    config=0,
                    mask=ofp.OFPPC_PORT_DOWN,
                    advertise=0
                )
            )
        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        if datapath_id in __topology_beacons:
            _log.warning("A beacon was already active for switch {:016X}. Canceling.".format(datapath_id))
            __topology_beacons[datapath_id].cancel()
        __topology_beacons[datapath_id] = hub.spawn(__send_discovery_beacon)
        _log.info("Switch Connect Event: {:s}".format(str(dp_event.__dict__)))

    else:
        if sector.is_entity_registered(datapath_id):
            ## Query scenarios which use this switch and initiate process establish new paths.
            if datapath_id in __topology_beacons:
                __topology_beacons[datapath_id].cancel()

            sector.remove_entity(datapath_id)
            database.remove_datapath(datapath_id)

            flows_to_remove = []
            if datapath_id in __mapped_services:
                switch_mapped_services = __mapped_services[datapath_id]
                for source_target in switch_mapped_services["ICMP4"]:
                    (tunnel_id, _, cookies) = switch_mapped_services["ICMP4"][source_target]
                    assert tunnel_id in __active_sector_tunnels, \
                        "tunnel_id {:d} not in __active_sector_tunnels".format(tunnel_id)
                    del __active_sector_tunnels[tunnel_id]
                    flows_to_remove = flows_to_remove + cookies

                for source_target in switch_mapped_services["IP4"]:
                    (tunnel_id, _, cookies) = switch_mapped_services["IP4"][source_target]
                    assert tunnel_id in __active_sector_tunnels, \
                        "tunnel_id {:d} not in __active_sector_tunnels".format(tunnel_id)
                    del __active_sector_tunnels[tunnel_id]
                    flows_to_remove = flows_to_remove + cookies

                for port_no in switch_mapped_services["MPLS"]:
                    for label_id in switch_mapped_services["MPLS"][port_no]:
                        (tunnel_id, _, cookies) = switch_mapped_services["IP4"][port_no][label_id]
                        assert tunnel_id in __active_sector_tunnels, \
                            "tunnel_id {:d} not in __active_sector_tunnels".format(tunnel_id)
                        del __active_sector_tunnels[tunnel_id]
                        flows_to_remove = flows_to_remove + cookies

            for cookie_id in flows_to_remove:
                assert cookie_id in __active_flows, "cookie_id {:d} not in __active_flows".format(cookie_id)
                del __active_flows[cookie_id]

            del __mapped_services[datapath_id]

            _log.info("Switch Disconnect Event: {:s}".format(str(dp_event.__dict__)))
        else:
            _log.warning("Trying to disconnect an unregistered Switch: {:016X}".format(datapath_id))

'''
{
    'dp': <ryu.controller.controller.Datapath object at 0x7f6985d4c518>, 
    'enter': True, 
    'ports': [
        OFPPort(port_no=1,hw_addr='e0:d4:e8:6b:4d:f8',name=b'eth0',config=0,state=4,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        OFPPort(port_no=2,hw_addr='82:2b:18:66:18:f4',name=b'eth1',config=0,state=1,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        OFPPort(port_no=3,hw_addr='f6:f2:fa:cc:1e:50',name=b'eth2',config=0,state=1,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0)
    ]
}
'''

'''
'dp': <ryu.controller.controller.Datapath object at 0x7f6985d4c518>

{
    'ofproto': <module 'ryu.ofproto.ofproto_v1_3' from '/home/carlosmf/PythonVirtEnv/controller_testing/lib/python3.6/site-packages/ryu/ofproto/ofproto_v1_3.py'>, 
    'ofproto_parser': <module 'ryu.ofproto.ofproto_v1_3_parser' from '/home/carlosmf/PythonVirtEnv/controller_testing/lib/python3.6/site-packages/ryu/ofproto/ofproto_v1_3_parser.py'>, 
    'socket': <eventlet.greenio.base.GreenSocket object at 0x7f714ce6c898>, 
    'address': ('192.168.100.103', 54921), 
    'is_active': True, 
    'send_q': <LightQueue at 0x7f714ce6ce80 maxsize=16 getters[1]>, 
    '_send_q_sem': <BoundedSemaphore at 0x7f714ce6ceb8 c=16 _w[0]>, 
    'echo_request_interval': 1.0, 
    'max_unreplied_echo_requests': 1, 
    'unreplied_echo_requests': [], 
    'xid': 2730934407, 
    'id': 123917682137323, 
    '_ports': None, 
    'flow_format': 0, 
    'ofp_brick': <ryu.controller.ofp_handler.OFPHandler object at 0x7f714d0f2f28>, 
    'state': 'main', 
    'ports': {
        1: OFPPort(port_no=1,hw_addr='42:f9:83:fe:12:b4',name=b'eth0',config=0,state=4,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        2: OFPPort(port_no=2,hw_addr='07:38:77:2c:8e:50',name=b'eth1',config=0,state=1,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        3: OFPPort(port_no=3,hw_addr='e9:c6:d3:73:3c:d9',name=b'eth2',config=0,state=4,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0)
    }
}
'''


def process_port_change_event(port_change_event):
    assert __default_configs, "engine not initialised"

    # {'datapath': <ryu.controller.controller.Datapath object at 0x7fb5da0fe2e8>, 'reason': 2, 'port_no': 1}

    #_log.info("Port Change Event: {}".format(str(port_change_event.__dict__)))
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
            if old_state != new_state:
                if entities.Switch.PORT_STATE.OFPPS_LINK_DOWN in new_state:
                    # Port is down. Detect which scenarios are affected, take them down,
                    #   send advertisements if necessary and try to rebuild the scenarios
                    def flow_filter(elem):
                        (flow, switch_id) = elem
                        if switch_id != datapath_id:
                            return False
                        if flow.match:
                            for match_field in flow.match.fields:
                                    return type(match_field) is ofp_parser.MTInPort and match_field.value == port_no
                    filtered_flows = tuple(filter(flow_filter, __active_flows.items()))

                    for (flow, _) in filtered_flows:
                        datapath_obj.send_msg(  # Removes all flows registered in this switch.
                            ofp_parser.OFPFlowMod(
                                datapath=datapath_obj,
                                cookie=flow.cookie,
                                cookie_mask=0,
                                table_id=ofp.OFPTT_ALL,
                                command=ofp.OFPFC_DELETE,
                                idle_timeout=0,
                                hard_timeout=0,
                                priority=__BASE_SERVICE_PRIORITY,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY,
                                flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                                match=ofp_parser.OFPMatch(in_port=port_no),
                                instructions=None
                            )
                        )
                        _log.warning(
                            "Flow with ID {:d} configured at Switch {:016X} for port {:d} was removed".format(
                                flow.cookie, port_no, datapath_id
                            )
                        )
                        del __active_flows[flow.cookie]
                        __free_cookie_id(flow.cookie)

                    __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

                elif entities.Switch.PORT_STATE.OFPPS_LIVE in new_state:
                    # Port is up. Restart all flows.

                    boot_dhcp = ofp_parser.OFPFlowMod(
                        datapath=datapath_obj,
                        cookie=__alloc_cookie_id(),
                        cookie_mask=0,
                        table_id=__SERVICE_OF_TABLE_NUM,
                        command=ofp.OFPFC_ADD,
                        idle_timeout=0,
                        hard_timeout=0,
                        priority=__BASE_SERVICE_PRIORITY,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY,
                        flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                        match=ofp_parser.OFPMatch(
                            in_port=port_no, eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0800,
                            ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17,
                            udp_src=68, udp_dst=67
                        ),
                        instructions=[
                            ofp_parser.OFPInstructionActions(
                                ofp.OFPIT_APPLY_ACTIONS,
                                [
                                    ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                                ]
                            )
                        ]
                    )
                    datapath_obj.send_msg(boot_dhcp)
                    __active_flows[boot_dhcp.cookie] = (boot_dhcp, datapath_obj.id)

                    archsdn_beacon = ofp_parser.OFPFlowMod(
                        datapath=datapath_obj,
                        cookie=__alloc_cookie_id(),
                        cookie_mask=0,
                        table_id=__SERVICE_OF_TABLE_NUM,
                        command=ofp.OFPFC_ADD,
                        idle_timeout=0,
                        hard_timeout=0,
                        priority=__BASE_SERVICE_PRIORITY,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY,
                        flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                        match=ofp_parser.OFPMatch(in_port=port_no, eth_type=0xAAAA),
                        instructions=[
                            ofp_parser.OFPInstructionActions(
                                ofp.OFPIT_APPLY_ACTIONS,
                                [
                                    ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                                ]
                            )
                        ]
                    )

                    datapath_obj.send_msg(archsdn_beacon)
                    __active_flows[archsdn_beacon.cookie] = (archsdn_beacon, datapath_obj.id)

                    mpls_packets = ofp_parser.OFPFlowMod(
                        datapath=datapath_obj,
                        cookie=__alloc_cookie_id(),
                        cookie_mask=0,
                        table_id=__SERVICE_OF_TABLE_NUM,
                        command=ofp.OFPFC_ADD,
                        idle_timeout=0,
                        hard_timeout=0,
                        priority=__MPLS_FLOW_PRIORITY,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY,
                        flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                        match=ofp_parser.OFPMatch(in_port=port_no, eth_type=ether.ETH_TYPE_MPLS),
                        instructions=[ofp_parser.OFPInstructionGotoTable(table_id=__MPLS_OF_TABLE_NUM)]
                    )

                    datapath_obj.send_msg(mpls_packets)
                    __active_flows[mpls_packets.cookie] = (mpls_packets, datapath_obj.id)
                    __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)
                    _log.warning(
                        "Default flows have been configured at Switch {:016X} for port {:d}".format(
                            port_no, datapath_id
                        )
                    )

                _log.warning(
                    "Port {:d} state at Switch {:016X} changed from {:s} to {:s}".format(
                        port_no, datapath_id, str(old_state), str(new_state)
                    )
                )
                switch.ports[port_no]['state'] = new_state

    else:
        raise Exception("Reason with value {:d} is unknown to specification.".format(reason_num))


def process_packet_in_event(packet_in_event):
    assert __default_configs, "engine not initialised"

    #_log.info("Packet In Event: {}".format(str(packet_in_event.__dict__)))

    msg = packet_in_event.msg
    datapath_id = msg.datapath.id
    ofp_parser = msg.datapath.ofproto_parser
    ofp = msg.datapath.ofproto
    controller_uuid = database.get_database_info()["uuid"]
    central_policies_addresses = database.query_volatile_info()
    ipv4_network = central_policies_addresses["ipv4_network"]
    ipv4_service = central_policies_addresses["ipv4_service"]
    mac_service = central_policies_addresses["mac_service"]

    # Identify and characterise packet (deep packet inspection to detect service or request)
    # Identify origin (pkt_in_port, mac source, IP source)
    # {
    #     'timestamp': 1520870994.4223557,
    #     'msg': OFPPacketIn(
    #         buffer_id=4294967295,
    #         cookie=2,
    #         data=b'\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xaa\xaa\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00p\xb3\xd5l\xd8\xeb\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    #         match=OFPMatch(
    #             oxm_fields={'pkt_in_port': 1}
    #         ),
    #         reason=1,
    #         table_id=0,
    #         total_len=60
    #     )
    # }
    #
    # {
    #   'datapath': <ryu.controller.controller.Datapath object at 0x7fdb134b1b00>,
    #   'version': 4,
    #   'msg_type': 10,
    #   'msg_len': 102,
    #   'xid': 0,
    #   'buf': b'\x04\n\x00f\x00\x00\x00\x00\xff\xff\xff\xff\x00<\x01\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x0c\x80\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xaa\xaa\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00p\xb3\xd5l\xd8\xeb\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'buffer_id': 4294967295, 'total_len': 60, 'reason': 1, 'table_id': 0, 'cookie': 4, 'match': OFPMatch(oxm_fields={'pkt_in_port': 1}), 'data': b'\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xaa\xaa\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00p\xb3\xd5l\xd8\xeb\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    # }

    pkt_in_port = None
    #in_port_mac = None

    if msg.match:
        for match_field in msg.match.fields:
            if type(match_field) is ofp_parser.MTInPort:
                pkt_in_port = match_field.value
                #in_port_mac = msg.datapath.ports[pkt_in_port].hw_addr

    pkt = Ether(msg.data)
    pkt_src_mac = EUI(pkt.src)
    pkt_dst_mac = EUI(pkt.dst)
    pkt_ethertype = pkt.type
    _log.debug(
        "Packet-In received at controller by switch {:016X} at port {:d} "
        "and sent by host {:s} to {:s} with type 0x{:04x}".format(
            datapath_id, pkt_in_port, str(pkt_src_mac), str(pkt_dst_mac), pkt_ethertype
        )
    )

    layer_num = 0
    if pkt_ethertype == 0xAAAA:  ###  ArchSDN Hello Packet : Ether Type -> 0xAAAA
        layer_num += 1
        archsdn_layer = memoryview(pkt.getlayer(layer_num).fields['load'])
        if len(archsdn_layer) < 2:
            _log.warning(
                "ArchSDN Beacon Ignored. Payload length is lower than 2. Got {:d}".format(len(archsdn_layer))
            )
            return

        (msg_type,) = struct.unpack("!H", archsdn_layer[0:struct.calcsize("!H")])
        msg_payload = archsdn_layer[2:]

        if msg_type == 1:
            msg_type_1_payload_format = "!16s8s"
            msg_type_1_payload_len = struct.calcsize(msg_type_1_payload_format)
            if len(msg_payload) < msg_type_1_payload_len:
                _log.warning(
                    "ArchSDN Beacon Ignored. It has invalid size: it's {:d} when it should be at least {:d}".format(
                        len(msg_payload), msg_type_1_payload_len
                    )
                )
                return

            (sender_controller_uuid_bytes, hash_val_bytes) = struct.unpack(
                msg_type_1_payload_format, msg_payload[0:msg_type_1_payload_len]
            )

            hash_val = int.from_bytes(hash_val_bytes, byteorder='big', signed=False)
            sender_controller_uuid = UUID(bytes=sender_controller_uuid_bytes)

            if controller_uuid != sender_controller_uuid:
                _log.debug(
                    "Switch {:016X} received Beacon Packet from a Controller with ID {:s}, with the hash value {:X}"
                    "".format(
                        datapath_id, str(sender_controller_uuid), hash_val
                    )
                )
                if not sector.is_entity_registered(sender_controller_uuid):
                    sector.register_entity(
                        entities.Sector(
                            controller_id=sender_controller_uuid
                        )
                    )
                if not sector.is_port_connected(datapath_id, pkt_in_port):
                    sector.connect_entities(
                        datapath_id, sender_controller_uuid,
                        switch_port_no=pkt_in_port
                    )

            else:
                (sender_datapath_id, sender_port_out) = __beacons_hash_table[hash_val]
                _log.debug(
                    "Switch {:016X} received Beacon Packet sent by this very own controller with the hash value "
                    "{:X}".format(
                        datapath_id, hash_val
                    )
                )

                if not sector.is_port_connected(datapath_id, pkt_in_port):
                    sector.connect_entities(
                        datapath_id, sender_datapath_id,
                        switch_a_port_no=pkt_in_port,
                        switch_b_port_no=sender_port_out
                    )

        else:
            _log.warning(
                "Ignoring ArchSDN Message received at switch {:016X} (Unknown type: {:d})".format(
                    datapath_id, msg_type
                )
            )

    elif pkt.haslayer(ARP):  # Answering to ARP Packet
        layer_num += 1
        arp_layer = pkt[ARP]
        _log.debug(
            "Received  ARP Packet from {:s} requesting the MAC address for target {:s}.".format(
                arp_layer.psrc, arp_layer.pdst
            )
        )
        if arp_layer.ptype == ether.ETH_TYPE_IP:  # Answering to ARPv4 Packet
            if arp_layer.pdst == str(ipv4_service):  # If the MAC Address is the Service MAC
                _log.debug("Arp target {:s} is the controller of this sector. ".format(arp_layer.pdst))
                mac_target_str = mac_service
            else:
                try:
                    try:
                        #  If the target is registered in this sector...
                        target_client_info = database.query_address_info(ipv4=IPv4Address(arp_layer.pdst))

                        _log.debug(
                            "Target {:s} belongs to this sector. "
                            "It is registered with client id {:d}, MAC {:s} at switch {:016X}, connected at port {:d}.".format(
                                arp_layer.pdst,
                                target_client_info["client_id"],
                                str(target_client_info["mac"]),
                                target_client_info["datapath"],
                                target_client_info["port"],
                            )
                        )
                        mac_target_str = target_client_info["mac"]
                    except database.AddressNotRegistered:
                        # The target is not registered in the sector.
                        # Ask the central manager for the controller id and client id.
                        # Then ask the respective controller for information about its client.
                        address_info = central.query_address_info(ipv4=IPv4Address(arp_layer.pdst))
                        _log.debug(
                            "Target {:s} with client id {:d} belongs to controller {:s} sector.".format(
                                arp_layer.pdst,
                                address_info.client_id,
                                address_info.controller_id
                            )
                        )
                        mac_target_str = None

                except central.NoResultsAvailable:
                    _log.debug("Target {:s} is not registered at the central manager.".format(arp_layer.pdst))
                    mac_target_str = None

            # Checks for the existence of the target in the network. If it exists, send back the ARP Reply
            if mac_target_str:
                datapath_obj = msg.datapath
                arp_response = Ether(src=str(mac_target_str), dst=pkt.src) \
                    / ARP(
                        hwtype=arp_layer.hwtype,
                        ptype=arp_layer.ptype,
                        hwlen=arp_layer.hwlen,
                        plen=arp_layer.plen,
                        op="is-at",
                        hwsrc=mac_target_str.packed,
                        psrc=arp_layer.pdst,
                        hwdst=EUI(pkt.src).packed,
                        pdst=arp_layer.psrc
                    )
                datapath_obj.send_msg(
                    ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=pkt_in_port,
                        actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(arp_response))],
                        data=bytes(arp_response)
                    )
                )
        else:
            _log.debug(
                "Ignoring ARP Packet with type: {:d}".format(arp_layer.ptype)
            )

    elif pkt.haslayer(IP):
        ip_layer = pkt[IP]
        pkt_ipv4_src = IPv4Address(ip_layer.src)
        pkt_ipv4_dst = IPv4Address(ip_layer.dst)
        _log.debug(
            "Received IP packet from host with MAC {:s}, Source IP {:s} to Destiny IP {:s}, on switch {:016X} at port {:d}".format(
                pkt.src, str(pkt_ipv4_src), str(pkt_ipv4_dst), datapath_id, pkt_in_port
            )
        )

        if pkt.haslayer(DHCP):  # https://tools.ietf.org/rfc/rfc2132.txt
            datapath_obj = msg.datapath
            bootp_layer = pkt[BOOTP]
            dhcp_layer = pkt[DHCP]

            dhcp_layer_options = dict(filter((lambda x: len(x) == 2), dhcp_layer.options))
            if 'message-type' in dhcp_layer_options:
                if dhcp_layer_options['message-type'] is 1:  # A DHCP DISCOVER packet was received

                    _log.debug(
                        "Received DHCP Discover packet from host with MAC {:s} on switch {:016X} at port {:d}".format(
                            pkt.src, datapath_id, pkt_in_port
                        )
                    )

                    try:  # search for a registration for the host at the local database
                        host_database_id = database.query_client_id(
                            datapath_id=datapath_id,
                            port_id=pkt_in_port,
                            mac=pkt_src_mac
                        )

                    except database.ClientNotRegistered:  # If not found, register a new host
                        database.register_client(
                            datapath_id=datapath_id,
                            port_id=pkt_in_port,
                            mac=pkt_src_mac
                        )
                        host_database_id = database.query_client_id(
                            datapath_id=datapath_id,
                            port_id=pkt_in_port,
                            mac=pkt_src_mac
                        )
                        try:  # Query central manager for the centralized host information
                            central_client_info = central.query_client_info(controller_uuid, host_database_id)

                        except central.ClientNotRegistered:
                            central.register_client(
                                controller_uuid=controller_uuid,
                                client_id=host_database_id
                            )
                            central_client_info = central.query_client_info(controller_uuid, host_database_id)

                        host_name = central_client_info.name
                        host_ipv4 = central_client_info.ipv4
                        host_ipv6 = central_client_info.ipv6
                        database.update_client_addresses(
                            client_id=host_database_id,
                            ipv4=host_ipv4,
                            ipv6=host_ipv6
                        )

                        if sector.is_port_connected(switch_id=datapath_id, port_id=pkt_in_port):
                            old_entity_id = sector.query_connected_entity_id(switch_id=datapath_id, port_id=pkt_in_port)
                            old_entity = sector.query_entity(old_entity_id)

                            assert isinstance(old_entity, entities.Host), "entity expected to be Host. Got {:s}".format(
                                repr(old_entity)
                            )
                            if old_entity.mac != pkt_src_mac:
                                sector.disconnect_entities(datapath_id, old_entity_id, pkt_in_port)

                        new_host = entities.Host(
                            hostname=host_name,
                            mac=pkt_src_mac,
                            ipv4=host_ipv4,
                            ipv6=host_ipv6
                        )
                        sector.register_entity(new_host)
                        sector.connect_entities(datapath_id, new_host.id, switch_port_no=pkt_in_port)

                    # It is necessary to check if the host is already registered at the controller database
                    client_info = database.query_client_info(host_database_id)

                    # A DHCP Offer packet is tailored specifically for the new host.
                    dhcp_offer = Ether(src=str(mac_service), dst=pkt.src) \
                                 / IP(src=str(ipv4_service), dst="255.255.255.255") \
                                 / UDP() \
                                 / BOOTP(
                        op="BOOTREPLY", xid=bootp_layer.xid, flags=bootp_layer.flags,
                        sname=str(controller_uuid), yiaddr=str(client_info["ipv4"]), chaddr=bootp_layer.chaddr
                    ) \
                                 / DHCP(
                        options=[
                            ("message-type", "offer"),
                            ("server_id", str(ipv4_service)),
                            ("lease_time", 43200),
                            ("subnet_mask", str(ipv4_network.netmask)),
                            ("router", str(ipv4_service)),
                            ("hostname", "{:d}".format(host_database_id).encode("ascii")),
                            ("name_server", str(ipv4_service)),
                            #("name_server", "8.8.8.8"),
                            ("domain", "archsdn".encode("ascii")),
                            ("renewal_time", 21600),
                            ("rebinding_time", 37800),
                            "end"
                        ]
                    )

                    pad = Padding(load=" " * (300 - len(dhcp_offer)))
                    dhcp_offer = dhcp_offer / pad

                    # The controller sends the DHCP Offer packet to the host.
                    datapath_obj.send_msg(
                        ofp_parser.OFPPacketOut(
                            datapath=msg.datapath,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            in_port=pkt_in_port,
                            actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_offer))],
                            data=bytes(dhcp_offer)
                        )
                    )
                    __send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)

                elif dhcp_layer_options['message-type'] is 3:  # A DHCP Request packet was received
                    try:
                        _log.debug(
                            "Received DHCP Request packet from host with MAC {:s} on switch {:016X} at port {:d}".format(
                                pkt.src, datapath_id, pkt_in_port
                            )
                        )

                        # It is necessary to check if the host is already registered at the controller database
                        client_id = database.query_client_id(datapath_id, pkt_in_port, EUI(pkt.src))
                        client_info = database.query_client_info(client_id)
                        client_ipv4 = client_info["ipv4"]

                        # Activate a flow to redirect to the controller ARP Request packets sent from the host to the
                        #   controller, from pkt_in_port.
                        arp_flow = ofp_parser.OFPFlowMod(
                            datapath=msg.datapath,
                            cookie=__alloc_cookie_id(),
                            cookie_mask=0,
                            table_id=__SERVICE_OF_TABLE_NUM,
                            command=ofp.OFPFC_ADD,
                            idle_timeout=0,
                            hard_timeout=0,
                            priority=__BASE_SERVICE_PRIORITY,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=pkt_in_port, eth_dst='ff:ff:ff:ff:ff:ff', eth_src=pkt.src, eth_type=0x0806,
                                arp_op=1, arp_spa=str(client_ipv4), arp_tpa=(str(ipv4_service), 0xFFFFFFFF),
                                arp_sha=pkt.src, arp_tha='00:00:00:00:00:00'
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionActions(
                                    ofp.OFPIT_APPLY_ACTIONS,
                                    [
                                        ofp_parser.OFPActionOutput(
                                            port=ofp.OFPP_CONTROLLER,
                                            max_len=ofp.OFPCML_NO_BUFFER
                                        )
                                    ]
                                )
                            ]
                        )
                        datapath_obj.send_msg(arp_flow)
                        __active_flows[arp_flow.cookie] = (arp_flow, datapath_obj.id)

                        # Activate a flow to redirect to the controller ICMP Request packets sent from the host to the
                        #   controller, from pkt_in_port.
                        icmp_flow = ofp_parser.OFPFlowMod(
                            datapath=msg.datapath,
                            cookie=__alloc_cookie_id(),
                            cookie_mask=0,
                            table_id=__SERVICE_OF_TABLE_NUM,
                            command=ofp.OFPFC_ADD,
                            idle_timeout=0,
                            hard_timeout=0,
                            priority=__BASE_SERVICE_PRIORITY,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=pkt_in_port, eth_src=pkt.src, eth_type=ether.ETH_TYPE_IP,
                                ipv4_src=str(client_ipv4),
                                ip_proto=1,
                                #icmpv4_type=8, icmpv4_code=0
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionActions(
                                    ofp.OFPIT_APPLY_ACTIONS,
                                    [
                                        ofp_parser.OFPActionOutput(
                                            port=ofp.OFPP_CONTROLLER,
                                            max_len=ofp.OFPCML_NO_BUFFER
                                        )
                                    ]
                                )
                            ]
                        )
                        datapath_obj.send_msg(icmp_flow)
                        __active_flows[icmp_flow.cookie] = (icmp_flow, datapath_obj.id)

                        # Activate a flow to redirect to the controller DNS packets sent from the host to the
                        #   controller, from pkt_in_port.
                        dns_flow = ofp_parser.OFPFlowMod(
                            datapath=msg.datapath,
                            cookie=__alloc_cookie_id(),
                            cookie_mask=0,
                            table_id=__SERVICE_OF_TABLE_NUM,
                            command=ofp.OFPFC_ADD,
                            idle_timeout=0,
                            hard_timeout=0,
                            priority=__BASE_SERVICE_PRIORITY,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=pkt_in_port, eth_dst=str(mac_service), eth_src=pkt.src, eth_type=ether.ETH_TYPE_IP,
                                ipv4_src=str(client_ipv4), ipv4_dst=str(ipv4_service), ip_proto=17, udp_dst=53
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionActions(
                                    ofp.OFPIT_APPLY_ACTIONS,
                                    [
                                        ofp_parser.OFPActionOutput(
                                            port=ofp.OFPP_CONTROLLER,
                                            max_len=ofp.OFPCML_NO_BUFFER)
                                    ]
                                )
                            ]
                        )
                        datapath_obj.send_msg(dns_flow)
                        __active_flows[dns_flow.cookie] = (dns_flow, datapath_obj.id)
                        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

                        #  Sending DHCP Ack to host
                        dhcp_ack = Ether(src=str(mac_service), dst=pkt.src) \
                                   / IP(src=str(ipv4_service), dst="255.255.255.255") \
                                   / UDP() / BOOTP(
                            op="BOOTREPLY", xid=bootp_layer.xid, flags=bootp_layer.flags, yiaddr=str(client_ipv4),
                            chaddr=EUI(pkt.src).packed
                        ) / DHCP(
                            options=[
                                ("message-type", "ack"),
                                ("server_id", str(ipv4_service)),
                                ("lease_time", 43200),
                                ("subnet_mask", str(ipv4_network.netmask)),
                                ("router", str(ipv4_service)),
                                ("hostname", "{:d}".format(client_id).encode("ascii")),
                                ("name_server", str(ipv4_service)),
                                ("name_server", "8.8.8.8"),
                                "end",
                            ]
                        )
                        pad = Padding(load=" " * (300 - len(dhcp_ack)))
                        dhcp_ack = dhcp_ack / pad

                        datapath_obj.send_msg(
                            ofp_parser.OFPPacketOut(
                                datapath=msg.datapath,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=pkt_in_port,
                                actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_ack))],
                                data=bytes(dhcp_ack)
                            )
                        )
                        __send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)

                    except database.ClientNotRegistered:
                        dhcp_nak = Ether(src=str(mac_service), dst=pkt.src) \
                                   / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                   / UDP() \
                                   / BOOTP(
                            op=2, xid=bootp_layer.xid,
                            yiaddr=ip_layer.src, siaddr=str(ipv4_service), giaddr=str(ipv4_service),
                            chaddr=EUI(pkt.src).packed
                        ) \
                                   / DHCP(
                            options=[
                                ("message-type", "nak"),
                                ("subnet_mask", str(ipv4_network.netmask)),
                                "end",
                            ]
                        )

                        datapath_obj.send_msg(
                            ofp_parser.OFPPacketOut(
                                datapath=msg.datapath,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=pkt_in_port,
                                actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_nak))],  #
                                data=bytes(dhcp_nak)
                            )
                        )
                        __send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)

        elif pkt.haslayer(ICMP):
            datapath_obj = msg.datapath
            icmp_layer = pkt[ICMP]
            data_layer = pkt[Raw]
            _log.debug(
                "Received ICMP Packet - Summary: {:s}".format(icmp_layer.mysummary())
            )
            if ip_layer.dst == str(ipv4_service):
                icmp_reply = Ether(src=str(mac_service), dst=pkt.src) \
                             / IP(src=str(ipv4_service), dst=ip_layer.src) \
                             / ICMP(
                                type="echo-reply",
                                id=icmp_layer.id,
                                seq=icmp_layer.seq,
                            ) \
                             / Raw(data_layer.load)

                datapath_obj.send_msg(
                    ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=pkt_in_port,
                        actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(icmp_reply))],
                        data=bytes(icmp_reply)
                    )
                )
            elif pkt_ipv4_dst in ipv4_network:  # If the destination IP belongs to the network.
                # Opens a bi-directional tunnel to target, using the same path in both directions.
                host_not_found_in_sector = False
                try:
                    addr_info_dst = database.query_address_info(ipv4=pkt_ipv4_dst)
                    target_switch_id = addr_info_dst["datapath"]
                    target_switch_port = addr_info_dst["port"]
                    source_entity_id = sector.query_connected_entity_id(datapath_id, pkt_in_port)
                    target_entity_id = sector.query_connected_entity_id(target_switch_id, target_switch_port)
                    source_entity = sector.query_entity(source_entity_id)
                    target_entity = sector.query_entity(target_entity_id)

                    for tunnel_id in __active_sector_tunnels:
                        tunnel = __active_sector_tunnels[tunnel_id]
                        if (tunnel.entity_a.id == source_entity_id and tunnel.entity_b.id == target_entity_id) or \
                                (tunnel.entity_b.id == source_entity_id and tunnel.entity_a.id == target_entity_id):
                            _log.error(
                                "ICMP Tunnel between {:s} and {:s} already exists.".format(
                                    str(source_entity_id), str(target_entity_id)
                                )
                            )
                            return

                    icmp_tunnel_scenario = sector.construct_scenario(
                        sector.ScenarioType.ICMP_TUNNEL,
                        source_entity_id,
                        target_entity_id,
                        # 100 TODO: This is not working because Zodiac FX do not seem to have queues...
                    )
                    if len(icmp_tunnel_scenario.path) == 3:
                        raise Exception("Not yet implemented : len(icmp_tunnel_scenario.path) == 3:")

                    else:
                        tunnel_cookies = []
                        a_to_b_mpls_label = icmp_tunnel_scenario.mpls_label_a
                        b_to_a_mpls_label = icmp_tunnel_scenario.mpls_label_b

                        #  Information about the path switches.
                        #  Core switches are those who are in the middle of the path, not on the edges.
                        #  Edges switches are those who perform the ingress and egress packet operations.
                        #
                        #  Tunnel implementation at path core switches
                        for (switch_id, switch_in_port, switch_out_port) in icmp_tunnel_scenario.path[2:-2]:
                            datapath_obj = __get_datapath(switch_id)
                            mpls_flow_mod = ofp_parser.OFPFlowMod(
                                datapath=datapath_obj,
                                cookie=__alloc_cookie_id(),
                                cookie_mask=0,
                                table_id=__MPLS_OF_TABLE_NUM,
                                command=ofp.OFPFC_ADD,
                                idle_timeout=0,
                                hard_timeout=0,
                                priority=__MPLS_FLOW_PRIORITY,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY,
                                flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                                match=ofp_parser.OFPMatch(
                                    in_port=switch_in_port,
                                    eth_type=ether.ETH_TYPE_MPLS,
                                    mpls_label=a_to_b_mpls_label
                                ),
                                instructions=[
                                    ofp_parser.OFPInstructionActions(
                                        ofp.OFPIT_APPLY_ACTIONS,
                                        [
                                            ofp_parser.OFPActionOutput(port=switch_out_port)
                                        ]
                                    )
                                ]
                            )
                            datapath_obj.send_msg(mpls_flow_mod)
                            tunnel_cookies.append(mpls_flow_mod.cookie)
                            __active_flows[mpls_flow_mod.cookie] = (mpls_flow_mod, datapath_obj.id)

                            mpls_flow_mod = ofp_parser.OFPFlowMod(
                                datapath=datapath_obj,
                                cookie=__alloc_cookie_id(),
                                cookie_mask=0,
                                table_id=__MPLS_OF_TABLE_NUM,
                                command=ofp.OFPFC_ADD,
                                idle_timeout=0,
                                hard_timeout=0,
                                priority=__MPLS_FLOW_PRIORITY,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY,
                                flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                                match=ofp_parser.OFPMatch(
                                    in_port=switch_out_port,
                                    eth_type=ether.ETH_TYPE_MPLS,
                                    mpls_label=b_to_a_mpls_label
                                ),
                                instructions=[
                                    ofp_parser.OFPInstructionActions(
                                        ofp.OFPIT_APPLY_ACTIONS,
                                        [
                                            ofp_parser.OFPActionOutput(port=switch_in_port)
                                        ]
                                    )
                                ]
                            )
                            datapath_obj.send_msg(mpls_flow_mod)
                            tunnel_cookies.append(mpls_flow_mod.cookie)
                            __active_flows[mpls_flow_mod.cookie] = (mpls_flow_mod, datapath_obj.id)
                            __send_msg(
                                ofp_parser.OFPBarrierRequest(datapath_obj),
                                reply_cls=ofp_parser.OFPBarrierReply
                            )
                        ###############################

                        #
                        # Side A configuration
                        # Ingressing from Side A to tunnel
                        (switch_id, switch_in_port, switch_out_port) = icmp_tunnel_scenario.path[1]
                        datapath_obj = __get_datapath(switch_id)
                        ingress_side_a_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            cookie=__alloc_cookie_id(),
                            cookie_mask=0,
                            table_id=__SERVICE_OF_TABLE_NUM,
                            command=ofp.OFPFC_ADD,
                            idle_timeout=0,
                            hard_timeout=0,
                            priority=__SERVICE_FLOW_PRIORITY,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=switch_in_port,
                                eth_src=str(source_entity.mac), eth_dst=str(target_entity.mac),
                                eth_type=ether.ETH_TYPE_IP,
                                ipv4_src=str(source_entity.ipv4), ipv4_dst=str(target_entity.ipv4), ip_proto=1
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionActions(
                                    ofp.OFPIT_APPLY_ACTIONS,
                                    [
                                        ofp_parser.OFPActionPushMpls(),
                                        ofp_parser.OFPActionSetField(mpls_label=a_to_b_mpls_label),
                                        ofp_parser.OFPActionOutput(port=switch_out_port),
                                    ]
                                ),
                            ]
                        )
                        datapath_obj.send_msg(ingress_side_a_tunnel_flow)
                        tunnel_cookies.append(ingress_side_a_tunnel_flow.cookie)
                        __active_flows[ingress_side_a_tunnel_flow.cookie] = (ingress_side_a_tunnel_flow, datapath_obj.id)
                        ###############################

                        # Egress from tunnel to Side A
                        egress_side_a_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            cookie=__alloc_cookie_id(),
                            cookie_mask=0,
                            table_id=__SERVICE_OF_TABLE_NUM,
                            command=ofp.OFPFC_ADD,
                            idle_timeout=0,
                            hard_timeout=0,
                            priority=__SERVICE_FLOW_PRIORITY,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=switch_out_port,
                                eth_type=ether.ETH_TYPE_MPLS,
                                mpls_label=b_to_a_mpls_label
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionActions(
                                    ofp.OFPIT_APPLY_ACTIONS,
                                    [
                                        ofp_parser.OFPActionPopMpls(),
                                        ofp_parser.OFPActionOutput(port=switch_in_port)
                                    ]
                                )
                            ]
                        )
                        datapath_obj.send_msg(egress_side_a_tunnel_flow)
                        tunnel_cookies.append(egress_side_a_tunnel_flow.cookie)
                        __active_flows[egress_side_a_tunnel_flow.cookie] = (
                            egress_side_a_tunnel_flow, datapath_obj.id
                        )
                        __send_msg(
                            ofp_parser.OFPBarrierRequest(datapath_obj),
                            reply_cls=ofp_parser.OFPBarrierReply
                        )
                        ###############################

                        #
                        # Side B configuration
                        # Ingressing from Side B to tunnel
                        (switch_id, switch_in_port, switch_out_port) = icmp_tunnel_scenario.path[-2]
                        datapath_obj = __get_datapath(switch_id)
                        ingress_side_b_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            cookie=__alloc_cookie_id(),
                            cookie_mask=0,
                            table_id=__SERVICE_OF_TABLE_NUM,
                            command=ofp.OFPFC_ADD,
                            idle_timeout=0,
                            hard_timeout=0,
                            priority=__SERVICE_FLOW_PRIORITY,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=switch_out_port,
                                eth_src=str(target_entity.mac), eth_dst=str(source_entity.mac),
                                eth_type=ether.ETH_TYPE_IP,
                                ipv4_src=str(target_entity.ipv4), ipv4_dst=str(source_entity.ipv4), ip_proto=1
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionActions(
                                    ofp.OFPIT_APPLY_ACTIONS,
                                    [
                                        ofp_parser.OFPActionPushMpls(),
                                        ofp_parser.OFPActionSetField(mpls_label=b_to_a_mpls_label),
                                        ofp_parser.OFPActionOutput(port=switch_in_port)
                                    ]
                                ),
                            ]
                        )
                        datapath_obj.send_msg(ingress_side_b_tunnel_flow)
                        tunnel_cookies.append(ingress_side_b_tunnel_flow.cookie)
                        __active_flows[ingress_side_b_tunnel_flow.cookie] = (
                            ingress_side_b_tunnel_flow, datapath_obj.id
                        )
                        ###############################

                        # Egress from tunnel to Side B
                        egress_side_b_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            cookie=__alloc_cookie_id(),
                            cookie_mask=0,
                            table_id=__SERVICE_OF_TABLE_NUM,
                            command=ofp.OFPFC_ADD,
                            idle_timeout=0,
                            hard_timeout=0,
                            priority=__SERVICE_FLOW_PRIORITY,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=switch_in_port,
                                eth_type=ether.ETH_TYPE_MPLS,
                                mpls_label=a_to_b_mpls_label
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionActions(
                                    ofp.OFPIT_APPLY_ACTIONS,
                                    [
                                        ofp_parser.OFPActionPopMpls(),
                                        ofp_parser.OFPActionOutput(port=switch_out_port)
                                    ]
                                )
                            ]
                        )
                        datapath_obj.send_msg(egress_side_b_tunnel_flow)
                        tunnel_cookies.append(egress_side_b_tunnel_flow.cookie)
                        __active_flows[egress_side_b_tunnel_flow.cookie] = (
                            egress_side_b_tunnel_flow, datapath_obj.id
                        )
                        __send_msg(
                            ofp_parser.OFPBarrierRequest(datapath_obj),
                            reply_cls=ofp_parser.OFPBarrierReply
                        )
                        ###############################

                        # Registering the allocated service for one way...
                        __mapped_services[switch_id]["ICMP4"][(source_entity.ipv4, target_entity.ipv4)] = (
                            id(icmp_tunnel_scenario), None, tunnel_cookies
                        )
                        # ...and registering for the other way.
                        __mapped_services[switch_id]["ICMP4"][(target_entity.ipv4, source_entity.ipv4)] = (
                            id(icmp_tunnel_scenario), None, tunnel_cookies
                        )

                        # Keep the scenario object alive, otherwise the bandwidth reservation is removed.
                        __active_sector_tunnels[id(icmp_tunnel_scenario)] = icmp_tunnel_scenario

                        # Reinsert the ICMP packet into the OpenFlow Pipeline, in order to properly process it.
                        msg.datapath.send_msg(
                            ofp_parser.OFPPacketOut(
                                datapath=msg.datapath,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=pkt_in_port,
                                actions=[
                                    ofp_parser.OFPActionOutput(port=ofp.OFPP_TABLE, max_len=len(msg.data)),
                                ],
                                data=msg.data
                            )
                        )

                        _log.warning(
                            "ICMP4 tunnel opened between hosts {:s} and {:s}.".format(
                                source_entity.hostname, target_entity.hostname
                            )
                        )

                except database.AddressNotRegistered:
                    host_not_found_in_sector = True

                if host_not_found_in_sector:
                    try:
                        addr_info = central.query_address_info(ipv4=pkt_ipv4_dst)
                        raise AssertionError(
                            "Support for hosts in other sectors, is Not implemented {}.".format(str(addr_info))
                        )

                    except central.NoResultsAvailable:
                        _log.error("Target {:s} is not registered at the central manager.".format(str(pkt_ipv4_dst)))

            else:
                _log.error("Target {:s} is currently not reachable.".format(str(pkt_ipv4_dst)))

        elif pkt.haslayer(DNS):
            datapath_obj = msg.datapath
            udp_layer = pkt[UDP]
            dns_layer = pkt[DNS]
            DNSQR_layer = pkt[DNSQR]

            _log.debug("Received DNS Packet - Summary: {:s}".format(dns_layer.mysummary()))
            qname_split = DNSQR_layer.qname.decode().split(".")[:-1]
            _log.debug(qname_split)
            if len(qname_split) == 3 and qname_split[-1] == "archsdn":
                try:
                    client_id = int(qname_split[0])
                except ValueError as ve:
                    raise ValueError("DNS Query malformed. Client ID invalid.")

                if "-" in qname_split[1]:
                    try:
                        controller_uuid = UUID(qname_split[1])
                    except ValueError:
                        raise ValueError("DNS Query malformed. Controller ID invalid.")
                elif str.isalnum(qname_split[1]):
                    try:
                        controller_uuid = UUID(int=int(qname_split[1]))
                    except ValueError:
                        try:
                            controller_uuid = UUID(int=int(qname_split[1], 16))
                        except ValueError:
                            raise ValueError("DNS Query malformed. Controller ID invalid.")
                else:
                    raise ValueError("DNS Query malformed. Controller ID invalid")

                # Query Central for Destination IP
                # Return to client the IP
                try:
                    client_info = central.query_client_info(controller_uuid, client_id)
                    dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                                / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                                / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='ok',
                                      an=DNSRR(rrname=DNSQR_layer.qname, rdata=str(client_info["ipv4"]))
                                      )
                except database.ClientNotRegistered:
                    dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                                / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                                / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='name-error')

                datapath_obj.send_msg(
                    ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=pkt_in_port,
                        actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dns_reply))],
                        data=bytes(dns_reply)
                    )
                )

        else:
            # If the packet is not DHCP, ARP, DNS or ICMP, then it is probably a regular data packet...
            # In this case, it is necessary to identify the service and establish a communication path with the proper QoS
            # try:
            #     source_client_id = database.query_client_id(datapath_id=datapath_id, port_id=pkt_in_port, mac=EUI(pkt.src))
            #     target_address_info = database.query_address_information(ipv4=IPv4Address(arp_layer.pdst))
            #
            #     # _log.debug("address_info: {}".format(target_address_info))
            #     source_entity = (cluster_network.Entity.HOST, source_client_id)
            #     target_entity = (cluster_network.Entity.HOST, target_address_info["client_id"])
            #
            #     if not tunnels_manager.isPathActive(source_entity, target_entity):
            #         shortest_path_source_to_target = cluster_network.QueryLocalPath(source_entity, target_entity)
            #         _log.debug(
            #             "shortest path from {} to {}: Hash: {} Path: {}".format(
            #                 source_entity, target_entity, hash(shortest_path_source_to_target),
            #                 shortest_path_source_to_target)
            #         )
            #         tunnels_manager.Activate_Local_Tunnel(shortest_path_source_to_target)
            #
            #     if not tunnels_manager.isPathActive(target_entity, source_entity):
            #         shortest_path_target_to_source = cluster_network.QueryLocalPath(target_entity, source_entity)
            #         _log.debug(
            #             "shortest path from {} to {}: Hash: {} Path: {}".format(
            #                 target_entity, source_entity, hash(shortest_path_target_to_source),
            #                 shortest_path_target_to_source
            #             )
            #         )
            #         tunnels_manager.Activate_Local_Tunnel(shortest_path_target_to_source)
            #
            #     arp_response = Ether(src=str(target_address_info["mac"]), dst=pkt.src) \
            #                    / ARP(
            #         hwtype=arp_layer.hwtype,
            #         ptype=arp_layer.ptype,
            #         hwlen=arp_layer.hwlen,
            #         plen=arp_layer.plen,
            #         op="is-at",
            #         hwsrc=target_address_info["mac"].packed,
            #         psrc=str(IPv4Address(arp_layer.pdst)),
            #         hwdst=EUI(pkt.src).packed,
            #         pdst=arp_layer.psrc
            #     )
            #     msg.datapath.send_msg(
            #         ofp_parser.OFPPacketOut(
            #             datapath=msg.datapath,
            #             buffer_id=ofp.OFP_NO_BUFFER,
            #             pkt_in_port=pkt_in_port,
            #             actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(arp_response))],
            #             data=bytes(arp_response)
            #         )
            #     )
            #
            # except database.Exceptions.Address_Not_Registered:
            #     client_info = central.query_client_info(ipv4=IPv4Address(arp_layer.pdst))
            #     _log.debug("client_info: {}".format(client_info))
            pass
    else:
        layers = []

        if _log.getEffectiveLevel() == logging.DEBUG:
            counter = 0
            while True:
                layer = pkt.getlayer(counter)
                if layer is not None:
                    layers.append("{:s}".format(str(layer.name)))
                else:
                    break
                counter += 1
        _log.debug("Ignoring Received Packet. Don't know what to do with it. Layers: [{:s}]".format("][".join(layers)))

