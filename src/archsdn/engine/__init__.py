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
           - DHCP and ArchSDN topology discovery Beacon -> 2000
           - Match Input Port -> 1000


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

__all__ = [
    'initialise',
    'process_datapath_event',
    'process_packet_in_event',
    'process_port_change_event',
]

from archsdn.engine import sector
from archsdn.engine.datapath_events import \
    process_datapath_event, \
    process_packet_in_event, \
    process_port_change_event


def initialise(default_configs):
    """
    Initialise kernel module.

    :param default_configs: module configuration
    :return: None
    """
    sector.initialise()

    globals.default_configs = default_configs
    globals.active_flows = {}
    globals.topology_beacons = {}

    globals.recycled_cookie_ids = []
    globals.cookie_id_counter = 0
