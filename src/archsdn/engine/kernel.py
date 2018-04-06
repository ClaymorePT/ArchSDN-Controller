"""
    This module implements the core procedures which handle OpenFlow switch events. The following documentation are
    development annotations to better understand the internal procedures of ArchSDN.

    Currently, three different types of events are being processed:
    - ryu.controller.dpset.EventDP -> Switch connect/disconnect events
    - ryu.controller.ofp_event.EventOFPPacketIn -> Packet-In events (packets sent by switches to controllers)
    - ryu.controller.ofp_event.EventOFPPortStateChange -> Port state change events (connect/disconnect/add/remove)

    The process is simple. The controller reacts when:
    - An OpenFlow switch connects or disconnects.
    - An OpenFlow switch port connectivity state changes or is added/removed.
    - When an OpenFlow switch receives an incoming packet from a connected switch.

    ArchSDN has a conservative/clean approach to incoming packet processing.
    To avoid being overwhelmed by packets sent by OpenFlow switches, ArchSDN implements several flows in a switch when
      it connects to the controller. This way, only specific types of packets are sent to the controller, maintaining
      a maximum availability.

    !!! Important !!! - From the beginning, ArchSDN only allows one host to be connected to one port at a time.
    ArchSDN does not supports multiple hosts connected to a switch port, using hubs or non-managed switches.


    <-- OpenFlow Tables -->
    ArchSDN segregates flow filtering using 5 different tables:
    - Table 0 -> Port Segregation + Default Settings
    - Table 1 -> Hosts Filtering
    - Table 2 -> Sectors Filtering
    - Table 3 -> MPLS Filtering
    - Table 4 -> Foreign Hosts Filtering


    - Table 0 -> Port Segregation + Default Settings
      - Implements the DHCP Discovery packet filtering and ArchSDN topology discovery beacon, for ports which it has not
        yet been establish to where they are connected.
      - Implements the initial flow match, which redirects the packet to other forward tables, depending upon to where
        the input port is connected. One of the following five different results will happen.
        1) If input port is connected to an Host, it sends the packet to Table 1.
        2) If input port is connected to a Sector, it sends the packet to Table 2.
        3) If input port is connected to a Switch, it sends the packet to Table 3.
        4) If it is not known to where the port is connected and, if the packet is one of the two default flows (DHCP or
          ArchSDN topology discovery beacon), send it to the Controller.
        5) If it is not one of the above, discard the packet (table-miss).

    - Table 1 -> Host Filtering
      - Implements the flows to deal with the activated services for connected Hosts.
      - Depending upon the destination to which a host wants to send packets, one of the following three different
        results will happen:
        1) The packet is switched to another port, if the destination is connected to the same switch.
        2) The packet is encapsulated with a MPLS header with the proper label value and sent to Table 3 (MPLS tunnel
          ingression).
        3) If it is not one of the above, discard the packet (table-miss).

    - Table 2 -> Sectors Filtering
      - Implements the flows to deal with packets arriving to the switch from other sectors.
      - These packets are always encapsulated with an MPLS header.
      - Depending upon the MPLS header label value, one of the following three different results will happen:
        1) If the tunnel endpoint is the switch, the packet MPLS header is removed and the packet is sent to Table 4.
        2) The MPLS header is updated and the packet is sent to Table 3 (MPLS tunnel redirection).
        3) If it is not one of the above, discard the packet (table-miss).

    - Table 3 -> MPLS Filtering
      - Implements the flows to filter MPLS packets sent by other sector switches and redirected by Table 1 or Table 2.
      - Depending upon the MPLS header label value, one of the following three different results will happen:
        1) If the switch is the Tunnel endpoint, the MPLS label header is removed and the packet is sent to Table 4.
        2) Depending upon the MPLS header label value, the packet is switched to another port.
        3) If it is not one of the above, discard the packet (table-miss).

    - Table 4 -> Remote Host Filtering
      - Implements the flows to filter packets sent by hosts not connected to the switch and without MPLS header.
      - Depending upon the packet structure, one of the following two different results will happen:
        1) The packet destination is verified. If the destination host is connected to the switch, the packet is
        switched to the host port.
        2) The packet is dropped (table-miss), due to missing destination.


    <-- OpenFlow Flows Priority -->
      - OpenFlow flows are evaluated according to:
        1) Flow priority -> Evaluated from the highest to the lowest value.
        2) Flow position at the table -> From the first to the last.
      - When a flow is inserted, it will always be inserted in the table above all the other flows with an equal
        priority and bellow the flows with higher priority.
      - ArchSDN inserts flows in the switch flow tables with specific priorities, without considering the flow row
        position in relation to other previous flows with the same priority.

      - ArchSDN specifies different priorities for its Flow Tables.
        -> Table 0:
           - Match Input Port -> 2000
           - DHCP and ArchSDN topology discovery Beacon -> 1000

        -> Table 1:
           - IP ports (DNS/DHCP/other applications) -> 4000
           - TCP/UDP/ICMP/other IP protocols -> 3000
             - ICMP with specific destination -> 3500
             - ICMP with network destination -> 3250
           - ARP/IPv4/IPv6 -> 2000
           - VLAN ID -> 1000

        -> Table 2:
           - MPLS Switch -> 3000
           - MPLS Pop Label -> 2000
           - MPLS Change Label -> 1000

        -> Table 3:
           - MPLS Switch -> 3000
           - MPLS Pop Label -> 2000
           - MPLS Change Label -> 1000

        -> Table 4:
           - IP ports (DNS/DHCP/other applications) -> 4000
           - TCP/UDP/ICMP/other IP protocols -> 3000
           - IPv4/IPv6 -> 2000
           - VLAN ID -> 1000


    <-- OpenFlow switch default flows -->
    When a switch connects to ArchSDN, default flows are installed in Table 0 and 1:
      - Table 0:
        -> DHCP packet (sent by hosts using a DHCP client process).
          -> The reception of a DHCP Discovery Packet, signals the controller that a host may be attempting to begin the
            registration process in the network.
        -> ArchSDN topology discovery beacon (sent by other sector switches).
          -> The reception of am ArchSDN discovery beacon, will signal one of two actions:
            1) The controller is seeing a discovery beacon sent by itself through another switch, indicating the presence
            of a local sector link.
            2) The controller is seeing a discovery beacon sent by another controller from a different sector, indicating
            the presence of a cross-sector link.
        -> Table-Miss flow.

      - Table 1:
        -> ARP packets redirect flow
          -> All ARP packets sent from hosts are redirected to the controller and answered by it.
        -> DNS packets redirect flow
          -> DNS packets sent from hosts to the network service IP are redirected to the controller and answered by it.
        -> ICMP packets redirect flow
          -> ICMP packets sent from hosts to the network service are redirected to the controller and answered by it.

      - Table 2,3 and 4 have no default flows, except for the Table-Miss flow.

    The Table-Miss flow is used to match every packet and discard it (OFPIT_CLEAR_ACTIONS).
      It matches all fields (ofp_parser.OFPMatch()) and has the lowest priority value (0). Table-Miss flow always uses
      a cookie value equal to zero.


    <-- Activated flows when a host is registered -->
    When a host is registered by the controller, the controller inserts the port segregation flow into Table 0.
      - This flow indicates the presence of a host at a specific port. All packets sent by the host should be processed
        by Table 1.
      - The port segregation flow, matches the port_in value and the packet source MAC address. The packet will only be
        sent to Table 1 if both fields match.


    <-- Activated flows when a new link to a local switch is discovered and registered -->
    When a new link that connects two switches from the same sector is discovered, the controller inserts the port
    segregation flow into Table 0.
      - This flow indicates the presence of a switch at a specific port. All packets sent by the switch, should be
        processed by Table 2.


"""


import logging
from ipaddress import ip_address, IPv4Address
import sys
import struct
from uuid import UUID
from ctypes import c_uint64

from scapy.packet import Padding, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNSRR, DNS, DNSQR

from ryu.lib import hub
from ryu.ofproto import ether, inet
from netaddr import EUI

from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import entities

# Table Flows Types
__PORT_SEGREGATION_TABLE = 0
__HOST_FILTERING_TABLE = 1
__SECTOR_FILTERING_TABLE = 2
__MPLS_FILTERING_TABLE = 3
__FOREIGN_HOST_FILTERING_TABLE = 4

__ARCHSDN_TABLES = {
    __PORT_SEGREGATION_TABLE,
    __HOST_FILTERING_TABLE,
    __SECTOR_FILTERING_TABLE,
    __MPLS_FILTERING_TABLE,
    __FOREIGN_HOST_FILTERING_TABLE
}

# Flows priority values
__TABLE_0_PORT_PRIORITY = 2000
__TABLE_0_DISCOVERY_PRIORITY = 1000

__TABLE_1_LAYER_5_PRIORITY = 4000
__TABLE_1_LAYER_4_SPECIFIC_PRIORITY = 3500
__TABLE_1_LAYER_4_NETWORK_PRIORITY = 3250
__TABLE_1_LAYER_4_PRIORITY = 3000
__TABLE_1_LAYER_3_PRIORITY = 2000
__TABLE_1_VLAN_PRIORITY = 1000

__TABLE_2_MPLS_SWITCH_PRIORITY = 3000
__TABLE_2_MPLS_POP_PRIORITY = 2000
__TABLE_2_MPLS_CHANGE_PRIORITY = 1000

__TABLE_3_MPLS_SWITCH_PRIORITY = 3000
__TABLE_3_MPLS_POP_PRIORITY = 2000
__TABLE_3_MPLS_CHANGE_PRIORITY = 1000

__TABLE_4_LAYER_5_PRIORITY = 4000
__TABLE_4_LAYER_4_PRIORITY = 3000
__TABLE_4_LAYER_3_PRIORITY = 2000
__TABLE_4_VLAN_PRIORITY = 1000

__TABLE_MISS_PRIORITY = 0



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
__active_sector_scenarios = {}  # __active_sector_scenarios[scenario id] = Scenario


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
#  "IPv4" ->  __mapped_services[switch_id]["IPv4"][(src_ip, dst_ip)][(src_port, dst_port)] = (tunnel_id, port_out, cookies)
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
            _log.debug("Cookie ID {:d} was recycled.".format(max_value))
            __cookie_id_counter = __cookie_id_counter - 1
        else:
            break
    _log.debug("Cookie ID {:d} was released.".format(cookie_id))


def __send_msg(*args, **kwargs):
    return __default_configs["send_msg"](*args, **kwargs)


def __get_datapath(*args, **kwargs):
    return __default_configs["get_datapath"](*args, **kwargs)


def initialise(default_configs):
    '''
    Initialise kernel module.

    :param default_configs: module configuration
    :return: None
    '''
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
    ipv4_network = central_policies_addresses["ipv4_network"]
    ipv4_service = central_policies_addresses["ipv4_service"]
    mac_service = central_policies_addresses["mac_service"]

    if dp_event.enter: # If Switch is connecting...
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
                table_id=ofp.OFPTT_ALL,
                command=ofp.OFPFC_DELETE,
                buffer_id=ofp.OFP_NO_BUFFER,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP
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


        # Stage 2 -> Configure Tables with default flows.

        # Inserting Table-Miss flows for all tables
        for table_no in __ARCHSDN_TABLES:
            datapath_obj.send_msg(
                ofp_parser.OFPFlowMod(
                    datapath=datapath_obj,
                    table_id=table_no,
                    command=ofp.OFPFC_ADD,
                    priority=__TABLE_MISS_PRIORITY,
                    flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                    match=ofp_parser.OFPMatch(),
                    instructions=[
                        ofp_parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, [])
                    ]
                )
            )

        #  Default Flows for __PORT_SEGREGATION_TABLE are:
        #  - DHCP Boot
        #  - ArchSDN Discovery Beacon
        #  - Table-Miss

        boot_dhcp = ofp_parser.OFPFlowMod(
            datapath=datapath_obj,
            cookie=__alloc_cookie_id(),
            table_id=__PORT_SEGREGATION_TABLE,
            command=ofp.OFPFC_ADD,
            priority=__TABLE_0_DISCOVERY_PRIORITY,
            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
            match=ofp_parser.OFPMatch(
                eth_dst='ff:ff:ff:ff:ff:ff', eth_type=ether.ETH_TYPE_IP,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=inet.IPPROTO_UDP,
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

        archsdn_beacon = ofp_parser.OFPFlowMod(
            datapath=datapath_obj,
            cookie=__alloc_cookie_id(),
            table_id=__PORT_SEGREGATION_TABLE,
            command=ofp.OFPFC_ADD,
            priority=__TABLE_0_DISCOVERY_PRIORITY,
            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
            match=ofp_parser.OFPMatch(eth_type=0xAAAA),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                    ]
                )
            ]
        )

        #  Default Flows for __HOST_FILTERING_TABLE are:
        #  - ARP packets whose destination are IPs within the service network, are redirected to controller.
        #  - ICMP packets destined to the service IP network, are redirected to controller.
        #  - DNS packets destined to the service IP network, are redirected to controller.
        #  - IPv4 packets sent by a network host to another network host, are redirected to controller.

        # Activate a flow to redirect to the controller ARP Request packets sent from the host to the
        #   controller, from pkt_in_port.
        arp_flow = ofp_parser.OFPFlowMod(
            datapath=datapath_obj,
            cookie=__alloc_cookie_id(),
            table_id=__HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=__TABLE_1_LAYER_3_PRIORITY,
            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
            match=ofp_parser.OFPMatch(
                eth_dst='ff:ff:ff:ff:ff:ff', eth_type=ether.ETH_TYPE_ARP,
                arp_op=1, arp_tpa=(str(ipv4_service), 0xFFFFFFFF), arp_tha='00:00:00:00:00:00'
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

        # Activate a flow to redirect to the controller ICMP Request packets sent from the host to the
        #   controller, from pkt_in_port.
        service_icmp_flow = ofp_parser.OFPFlowMod(
            datapath=datapath_obj,
            cookie=__alloc_cookie_id(),
            table_id=__HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=__TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
            match=ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, eth_dst=str(mac_service),
                ipv4_dst=str(ipv4_service),
                ip_proto=inet.IPPROTO_ICMP, icmpv4_type=8, icmpv4_code=0
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

        # Activate a flow to redirect to the controller DNS packets sent from the host to the
        #   controller, from pkt_in_port.
        service_dns_flow = ofp_parser.OFPFlowMod(
            datapath=datapath_obj,
            cookie=__alloc_cookie_id(),
            table_id=__HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=__TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
            match=ofp_parser.OFPMatch(
                eth_dst=str(mac_service), eth_type=ether.ETH_TYPE_IP,
                ipv4_dst=str(ipv4_service),
                ip_proto=inet.IPPROTO_UDP, udp_dst=53
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

        # Activate a flow to redirect to the controller, ipv4 packets sent by a network host to another network host.
        default_ipv4_flow = ofp_parser.OFPFlowMod(
            datapath=datapath_obj,
            cookie=__alloc_cookie_id(),
            table_id=__HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=__TABLE_1_LAYER_3_PRIORITY,
            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
            match=ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_src=(str(ipv4_network.network_address), str(ipv4_network.netmask)),
                ipv4_dst=(str(ipv4_network.network_address), str(ipv4_network.netmask)),
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

        datapath_obj.send_msg(boot_dhcp)
        datapath_obj.send_msg(archsdn_beacon)
        datapath_obj.send_msg(arp_flow)
        datapath_obj.send_msg(service_icmp_flow)
        datapath_obj.send_msg(service_dns_flow)
        datapath_obj.send_msg(default_ipv4_flow)
        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        __active_flows[boot_dhcp.cookie] = (boot_dhcp, datapath_obj.id)
        __active_flows[archsdn_beacon.cookie] = (archsdn_beacon, datapath_obj.id)
        __active_flows[arp_flow.cookie] = (arp_flow, datapath_obj.id)
        __active_flows[service_icmp_flow.cookie] = (service_icmp_flow, datapath_obj.id)
        __active_flows[service_dns_flow.cookie] = (service_dns_flow, datapath_obj.id)
        __active_flows[default_ipv4_flow.cookie] = (default_ipv4_flow, datapath_obj.id)


        # Stage 3 -> Enable all switching ports TODO: and send DHCP FORCERENEW ?? rfc3203
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

        assert datapath_id not in __topology_beacons, \
            "A beacon was already active for switch {:016X}.".format(datapath_id)

        __topology_beacons[datapath_id] = hub.spawn(__send_discovery_beacon)
        _log.info("Switch Connect Event: {:s}".format(str(dp_event.__dict__)))

    else: # If Switch is disconnecting...
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
                    assert tunnel_id in __active_sector_scenarios, \
                        "tunnel_id {:d} not in __active_sector_tunnels".format(tunnel_id)
                    del __active_sector_scenarios[tunnel_id]
                    flows_to_remove = flows_to_remove + cookies

                for source_target in switch_mapped_services["IPv4"]:
                    (tunnel_id, _, cookies) = switch_mapped_services["IPv4"][source_target]
                    assert tunnel_id in __active_sector_scenarios, \
                        "tunnel_id {:d} not in __active_sector_tunnels".format(tunnel_id)
                    del __active_sector_scenarios[tunnel_id]
                    flows_to_remove = flows_to_remove + cookies

                for port_no in switch_mapped_services["MPLS"]:
                    for label_id in switch_mapped_services["MPLS"][port_no]:
                        (tunnel_id, _, cookies) = switch_mapped_services["IP4"][port_no][label_id]
                        assert tunnel_id in __active_sector_scenarios, \
                            "tunnel_id {:d} not in __active_sector_tunnels".format(tunnel_id)
                        del __active_sector_scenarios[tunnel_id]
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
            if old_state != new_state: # If the port state has changed...
                if entities.Switch.PORT_STATE.OFPPS_LINK_DOWN in new_state:  # Port link state is Down...

                    # Removes all flows at __PORT_SEGREGATION_TABLE matching the removed port
                    datapath_obj.send_msg(
                        ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            table_id=__PORT_SEGREGATION_TABLE,
                            command=ofp.OFPFC_DELETE,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(in_port=port_no)
                        )
                    )
                    __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

                    def flow_filter(elem):
                        (flow_obj, switch_id) = elem
                        if switch_id != datapath_id:
                            return False
                        if flow_obj.match:
                            for match_field in flow_obj.match.fields:
                                return type(match_field) is ofp_parser.MTInPort and match_field.value == port_no

                    filtered_flows = tuple(filter(flow_filter, __active_flows.items()))
                    for (flow, _) in filtered_flows:
                        _log.warning(
                            "Flow with ID {:d} configured at Switch {:016X} for port {:d} was removed".format(
                                flow.cookie, port_no, datapath_id
                            )
                        )
                        del __active_flows[flow.cookie]
                        __free_cookie_id(flow.cookie)

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
            "Received IP packet from host with MAC {:s}, Source IP {:s} to Destiny IP {:s}, "
            "on switch {:016X} at port {:d}".format(
                pkt.src, str(pkt_ipv4_src), str(pkt_ipv4_dst), datapath_id, pkt_in_port
            )
        )

        if ip_layer.haslayer(DHCP):  # https://tools.ietf.org/rfc/rfc2132.txt
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

                        port_segregation_flow = ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            cookie=__alloc_cookie_id(),
                            table_id=__PORT_SEGREGATION_TABLE,
                            command=ofp.OFPFC_ADD,
                            priority=__TABLE_0_PORT_PRIORITY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(
                                in_port=pkt_in_port,
                                eth_src=pkt_src_mac,
                            ),
                            instructions=[
                                ofp_parser.OFPInstructionGotoTable(table_id=__HOST_FILTERING_TABLE)
                            ]
                        )

                        datapath_obj.send_msg(port_segregation_flow)
                        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

                        __active_flows[port_segregation_flow.cookie] = (port_segregation_flow, datapath_obj.id)


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

        elif ip_layer.haslayer(ICMP):
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
                    tunnel_cookies = []

                    if (pkt_ipv4_src, pkt_ipv4_dst) in __mapped_services[datapath_id]["ICMP4"]:
                        _log.error(
                            "ICMP Tunnel between {:s} and {:s} already exists.".format(
                                str(source_entity_id), str(target_entity_id)
                            )
                        )
                        return

                    icmp_tunnel_scenario = sector.construct_scenario(
                        sector.ScenarioRequest.TWO_WAY,
                        source_entity_id,
                        target_entity_id,
                        # 100 TODO: This is not working because Zodiac FX do not seem to have queues...
                    )

                    if icmp_tunnel_scenario.length == 3:
                        # If the hosts are connected to the same switch, there's no need to create an MPLS tunnel.
                        #   It is only necessary to forward the packets from one network interface to the other.

                        (side_a_switch_id, switch_in_port, switch_out_port) = icmp_tunnel_scenario.path[1]
                        side_b_switch_id = side_a_switch_id
                        single_switch_obj = __get_datapath(side_a_switch_id)
                        side_a_flow = ofp_parser.OFPFlowMod(
                            datapath=single_switch_obj,
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
                                        ofp_parser.OFPActionOutput(port=switch_out_port),
                                    ]
                                ),
                            ]
                        )
                        single_switch_obj.send_msg(side_a_flow)
                        tunnel_cookies.append(side_a_flow.cookie)
                        __active_flows[side_a_flow.cookie] = (side_a_flow, side_a_switch_id)

                        side_b_flow = ofp_parser.OFPFlowMod(
                            datapath=single_switch_obj,
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
                                        ofp_parser.OFPActionOutput(port=switch_in_port)
                                    ]
                                ),
                            ]
                        )
                        single_switch_obj.send_msg(side_b_flow)
                        tunnel_cookies.append(side_b_flow.cookie)
                        __active_flows[side_b_flow.cookie] = (side_b_flow, side_b_switch_id)

                    else:
                        mpls_label = icmp_tunnel_scenario.mpls_label

                        #  Information about the path switches.
                        #  Core switches are those who are in the middle of the path, not on the edges.
                        #  Edges switches are those who perform the ingress and egress packet procedures.
                        #
                        #  Tunnel implementation at path core switches
                        for (middle_switch_id, switch_in_port, switch_out_port) in icmp_tunnel_scenario.path[2:-2]:
                            middle_switch_obj = __get_datapath(middle_switch_id)
                            mpls_flow_mod = ofp_parser.OFPFlowMod(
                                datapath=middle_switch_obj,
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
                                    mpls_label=mpls_label
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
                            middle_switch_obj.send_msg(mpls_flow_mod)
                            tunnel_cookies.append(mpls_flow_mod.cookie)
                            __active_flows[mpls_flow_mod.cookie] = (mpls_flow_mod, middle_switch_id)

                            mpls_flow_mod = ofp_parser.OFPFlowMod(
                                datapath=middle_switch_obj,
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
                                    mpls_label=mpls_label
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
                            middle_switch_obj.send_msg(mpls_flow_mod)
                            tunnel_cookies.append(mpls_flow_mod.cookie)
                            __active_flows[mpls_flow_mod.cookie] = (mpls_flow_mod, middle_switch_id)
                            __send_msg(
                                ofp_parser.OFPBarrierRequest(middle_switch_obj),
                                reply_cls=ofp_parser.OFPBarrierReply
                            )
                        ###############################

                        #
                        # Side A configuration
                        # Ingressing from Side A to tunnel
                        (side_a_switch_id, switch_in_port, switch_out_port) = icmp_tunnel_scenario.path[1]
                        side_a_switch_obj = __get_datapath(side_a_switch_id)
                        ingress_side_a_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=side_a_switch_obj,
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
                                        ofp_parser.OFPActionSetField(mpls_label=mpls_label),
                                        ofp_parser.OFPActionOutput(port=switch_out_port),
                                    ]
                                ),
                            ]
                        )
                        side_a_switch_obj.send_msg(ingress_side_a_tunnel_flow)
                        tunnel_cookies.append(ingress_side_a_tunnel_flow.cookie)
                        __active_flows[ingress_side_a_tunnel_flow.cookie] = (ingress_side_a_tunnel_flow, side_a_switch_id)
                        ###############################

                        # Egress from tunnel to Side A
                        egress_side_a_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=side_a_switch_obj,
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
                                mpls_label=mpls_label
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
                        side_a_switch_obj.send_msg(egress_side_a_tunnel_flow)
                        tunnel_cookies.append(egress_side_a_tunnel_flow.cookie)
                        __active_flows[egress_side_a_tunnel_flow.cookie] = (egress_side_a_tunnel_flow, side_a_switch_id)
                        __send_msg(ofp_parser.OFPBarrierRequest(side_a_switch_obj), reply_cls=ofp_parser.OFPBarrierReply)
                        ###############################

                        #
                        # Side B configuration
                        # Ingressing from Side B to tunnel
                        (side_b_switch_id, switch_in_port, switch_out_port) = icmp_tunnel_scenario.path[-2]
                        side_b_switch_obj = __get_datapath(side_b_switch_id)
                        ingress_side_b_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=side_b_switch_obj,
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
                                        ofp_parser.OFPActionSetField(mpls_label=mpls_label),
                                        ofp_parser.OFPActionOutput(port=switch_in_port)
                                    ]
                                ),
                            ]
                        )
                        side_b_switch_obj.send_msg(ingress_side_b_tunnel_flow)
                        tunnel_cookies.append(ingress_side_b_tunnel_flow.cookie)
                        __active_flows[ingress_side_b_tunnel_flow.cookie] = (ingress_side_b_tunnel_flow, side_b_switch_id)
                        ###############################

                        # Egress from tunnel to Side B
                        egress_side_b_tunnel_flow = ofp_parser.OFPFlowMod(
                            datapath=side_b_switch_obj,
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
                                mpls_label=mpls_label
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
                        side_b_switch_obj.send_msg(egress_side_b_tunnel_flow)
                        tunnel_cookies.append(egress_side_b_tunnel_flow.cookie)
                        __active_flows[egress_side_b_tunnel_flow.cookie] = (egress_side_b_tunnel_flow, side_b_switch_id)
                        __send_msg(
                            ofp_parser.OFPBarrierRequest(side_b_switch_obj),
                            reply_cls=ofp_parser.OFPBarrierReply
                        )
                        ###############################

                    # Registering the allocated service for one way...
                    __mapped_services[side_a_switch_id]["ICMP4"][(source_entity.ipv4, target_entity.ipv4)] = (
                        id(icmp_tunnel_scenario), None, tunnel_cookies
                    )
                    # ...and registering for the other way.
                    __mapped_services[side_b_switch_id]["ICMP4"][(target_entity.ipv4, source_entity.ipv4)] = (
                        id(icmp_tunnel_scenario), None, tunnel_cookies
                    )

                    # Keep the scenario object alive, otherwise the bandwidth reservation is removed.
                    __active_sector_scenarios[id(icmp_tunnel_scenario)] = icmp_tunnel_scenario

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

        elif ip_layer.haslayer(DNS):
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

        elif ip_layer.haslayer(UDP) or ip_layer.haslayer(TCP):
            # If the packet is not DHCP, ARP, DNS or ICMP, then it is probably a regular data packet.
            # Lets create two uni-directional tunnels for TCP and UDP traffic, where the implemented QoS metrics will
            #   depend upon the service characteristics.
            #

            if pkt_ipv4_dst not in ipv4_network:  # If the destination IP belongs to other networks...
                _log.warning("Traffic towards destination {:s} is not supported.".format(str(pkt_ipv4_dst)))
                return
            if pkt_ipv4_dst == ipv4_network.broadcast_address:
                _log.warning("Broadcast traffic ({:s}) is not supported.".format(str(pkt_ipv4_dst)))
                return
            if pkt_ipv4_dst.is_multicast:
                _log.warning("Multicast traffic ({:s}) is not supported.".format(str(pkt_ipv4_dst)))
                return

            udp_layer = None
            tcp_layer = None
            src_port = None
            dst_port = None
            if ip_layer.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            elif ip_layer.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
            else:
                raise AssertionError(
                    "Something is wrong. IP Packet is supposed to be UDP or TCP, but scapy seems to be confused."
                )

            __mapped_ipv4_services = __mapped_services[datapath_id]["IPv4"]
            if (pkt_ipv4_src, pkt_ipv4_dst) in __mapped_ipv4_services and \
                    (src_port, dst_port) in __mapped_ipv4_services[(pkt_ipv4_src, pkt_ipv4_dst)]:
                _log.error(
                    "IPv4 tunnel for TCP and UDP traffic from {:s} to {:s}, "
                    "using source port {:d} and destiny port {:d} already exists.".format(
                        str(pkt_ipv4_src), str(pkt_ipv4_dst), src_port, dst_port
                    )
                )
                return

            addr_info_dst = database.query_address_info(ipv4=pkt_ipv4_dst)
            target_switch_id = addr_info_dst["datapath"]
            target_switch_port = addr_info_dst["port"]
            source_entity_id = sector.query_connected_entity_id(datapath_id, pkt_in_port)
            target_entity_id = sector.query_connected_entity_id(target_switch_id, target_switch_port)
            source_entity = sector.query_entity(source_entity_id)
            target_entity = sector.query_entity(target_entity_id)
            tunnel_cookies = []

            uni_tunnel_scenario = sector.construct_scenario(
                sector.ScenarioRequest.ONE_WAY,
                source_entity_id,
                target_entity_id,
                # 100 TODO: This is not working because Zodiac FX does not seem to have queues...
            )

            if len(uni_tunnel_scenario.path) == 3:
                # If the hosts are connected to the same switch, there's no need to create an MPLS tunnel.
                #   It is only necessary to forward the packets from one network interface to the other.

                #if src_port is None and dst_port is None:


                (single_switch_id, switch_in_port, switch_out_port) = uni_tunnel_scenario.path[1]
                single_switch_obj = __get_datapath(single_switch_id)
                # For TCP Data
                flow_tcp = ofp_parser.OFPFlowMod(
                    datapath=single_switch_obj,
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
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_src=str(source_entity.ipv4), ipv4_dst=str(target_entity.ipv4),
                        ip_proto=inet.IPPROTO_TCP, tcp_src=src_port, tcp_dst=dst_port
                    ),
                    instructions=[
                        ofp_parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [
                                ofp_parser.OFPActionOutput(port=switch_out_port),
                            ]
                        ),
                    ]
                )
                single_switch_obj.send_msg(flow_tcp)
                tunnel_cookies.append(flow_tcp.cookie)
                __active_flows[flow_tcp.cookie] = (flow_tcp, single_switch_id)

                # For UDP Data
                flow_udp = ofp_parser.OFPFlowMod(
                    datapath=single_switch_obj,
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
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_src=str(source_entity.ipv4), ipv4_dst=str(target_entity.ipv4),
                        ip_proto=inet.IPPROTO_UDP, udp_src=src_port, udp_dst=dst_port
                    ),
                    instructions=[
                        ofp_parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [
                                ofp_parser.OFPActionOutput(port=switch_out_port),
                            ]
                        ),
                    ]
                )
                single_switch_obj.send_msg(flow_udp)
                tunnel_cookies.append(flow_udp.cookie)
                __active_flows[flow_udp.cookie] = (flow_udp, single_switch_id)

                __send_msg(
                    ofp_parser.OFPBarrierRequest(single_switch_obj),
                    reply_cls=ofp_parser.OFPBarrierReply
                )

            else:
                #  Information about the path switches.
                #  Core switches are those who are in the middle of the path, not on the edges.
                #  Core switches only perform MPLS label switching.
                #  Edges switches are those who perform the ingress and egress packet operations.
                #  Only paths whose length is greater than 3, have edge switches.
                #  Only paths whose length is greater than 4, have core switches.
                if len(uni_tunnel_scenario.path) > 4:
                    #  Tunnel implementation at core path switches
                    for (middle_switch_id, switch_in_port, switch_out_port) in uni_tunnel_scenario.path[2:-2]:
                        middle_switch_obj = __get_datapath(middle_switch_id)
                        mpls_flow_mod = ofp_parser.OFPFlowMod(
                            datapath=middle_switch_obj,
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
                                mpls_label=uni_tunnel_scenario.mpls_label
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
                        middle_switch_obj.send_msg(mpls_flow_mod)
                        tunnel_cookies.append(mpls_flow_mod.cookie)
                        __active_flows[mpls_flow_mod.cookie] = (mpls_flow_mod, middle_switch_id)
                        __send_msg(
                            ofp_parser.OFPBarrierRequest(middle_switch_obj),
                            reply_cls=ofp_parser.OFPBarrierReply
                        )
                    ###############################

                #
                #  Tunnel configuration from ingressing side
                (ingressing_switch_id, switch_in_port, switch_out_port) = uni_tunnel_scenario.path[1]
                ingressing_switch_obj = __get_datapath(ingressing_switch_id)

                # For TCP Data
                ingress_side_a_tunnel_flow_tcp = ofp_parser.OFPFlowMod(
                    datapath=ingressing_switch_obj,
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
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_src=str(source_entity.ipv4), ipv4_dst=str(target_entity.ipv4),
                        ip_proto=inet.IPPROTO_TCP, tcp_src=src_port, tcp_dst=dst_port
                    ),
                    instructions=[
                        ofp_parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [
                                ofp_parser.OFPActionPushMpls(),
                                ofp_parser.OFPActionSetField(mpls_label=uni_tunnel_scenario.mpls_label),
                                ofp_parser.OFPActionOutput(port=switch_out_port),
                            ]
                        ),
                    ]
                )
                ingressing_switch_obj.send_msg(ingress_side_a_tunnel_flow_tcp)
                tunnel_cookies.append(ingress_side_a_tunnel_flow_tcp.cookie)
                __active_flows[ingress_side_a_tunnel_flow_tcp.cookie] = (ingress_side_a_tunnel_flow_tcp, ingressing_switch_id)

                # For UDP Data
                ingress_side_a_tunnel_flow_udp = ofp_parser.OFPFlowMod(
                    datapath=ingressing_switch_obj,
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
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_src=str(source_entity.ipv4), ipv4_dst=str(target_entity.ipv4),
                        ip_proto=inet.IPPROTO_UDP, udp_src=src_port, udp_dst=dst_port
                    ),
                    instructions=[
                        ofp_parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            [
                                ofp_parser.OFPActionPushMpls(),
                                ofp_parser.OFPActionSetField(mpls_label=uni_tunnel_scenario.mpls_label),
                                ofp_parser.OFPActionOutput(port=switch_out_port),
                            ]
                        ),
                    ]
                )
                ingressing_switch_obj.send_msg(ingress_side_a_tunnel_flow_udp)
                tunnel_cookies.append(ingress_side_a_tunnel_flow_udp.cookie)
                __active_flows[ingress_side_a_tunnel_flow_udp.cookie] = (ingress_side_a_tunnel_flow_udp, ingressing_switch_id)

                __send_msg(
                    ofp_parser.OFPBarrierRequest(ingressing_switch_obj),
                    reply_cls=ofp_parser.OFPBarrierReply
                )
                ###############################

                # Tunnel configuration from egressing side
                (egress_switch_id, switch_in_port, switch_out_port) = uni_tunnel_scenario.path[-2]
                egress_switch_obj = __get_datapath(egress_switch_id)
                egress_side_b_tunnel_flow = ofp_parser.OFPFlowMod(
                    datapath=egress_switch_obj,
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
                        mpls_label=uni_tunnel_scenario.mpls_label
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
                egress_switch_obj.send_msg(egress_side_b_tunnel_flow)
                tunnel_cookies.append(egress_side_b_tunnel_flow.cookie)
                __active_flows[egress_side_b_tunnel_flow.cookie] = (egress_side_b_tunnel_flow, egress_switch_id)
                __send_msg(
                    ofp_parser.OFPBarrierRequest(egress_switch_obj),
                    reply_cls=ofp_parser.OFPBarrierReply
                )

            # Registering the allocated service for one way...
            if (source_entity.ipv4, target_entity.ipv4) not in __mapped_ipv4_services:
                __mapped_ipv4_services[(source_entity.ipv4, target_entity.ipv4)] = {}

            __mapped_ipv4_services[(source_entity.ipv4, target_entity.ipv4)][(src_port, dst_port)] = (
                id(uni_tunnel_scenario), None, tunnel_cookies
            )

            # Keep the scenario object alive, otherwise the bandwidth reservation is removed.
            __active_sector_scenarios[id(uni_tunnel_scenario)] = uni_tunnel_scenario

            # Reinsert the IPv4 packet into the OpenFlow Pipeline, in order to properly process it.
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
                "IPv4 tunnel for TCP and UDP traffic, opened between hosts {:s} and {:s}.".format(
                    source_entity.hostname, target_entity.hostname
                )
            )

        else:
            _log.warning(
                "IP packet Type ({:X}), sent from {:s} to {:s}, is not supported. ".format(
                    ip_layer.proto, ip_layer.src, ip_layer.dst
                )
            )
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

