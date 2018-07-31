
import sys
import logging
from ipaddress import IPv4Address
import struct
from uuid import UUID
import time

from scapy.packet import Padding, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNSRR, DNS, DNSQR

from ryu.lib import hub
from ryu.ofproto import ether
from netaddr import EUI

from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn.engine import globals
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import services
from archsdn import p2p_requests
from archsdn.engine.exceptions import PathNotFound

from archsdn.engine.datapath_events.packet_in_events.archsdn_L2 import process_archsdn_control
from archsdn.engine.datapath_events.packet_in_events.arp import process_arp

_log = logging.getLogger(logger_module_name(__file__))


def process_event(packet_in_event):
    assert globals.default_configs, "engine not initialised"

    msg = packet_in_event.msg
    datapath_id = msg.datapath.id
    datapath_ofp_parser = msg.datapath.ofproto_parser
    datapath_ofp = msg.datapath.ofproto
    controller_uuid = database.get_database_info()["uuid"]
    central_policies_addresses = database.query_volatile_info()
    ipv4_network = central_policies_addresses["ipv4_network"]
    ipv4_service = central_policies_addresses["ipv4_service"]
    mac_service = central_policies_addresses["mac_service"]

    pkt_in_port = None
    if msg.match:
        for match_field in msg.match.fields:
            if type(match_field) is datapath_ofp_parser.MTInPort:
                pkt_in_port = match_field.value

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

    if pkt_ethertype == 0xAAAA:  # ArchSDN Hello Packet : Ether Type -> 0xAAAA
        process_archsdn_control(packet_in_event)

    elif pkt.haslayer(ARP):  # Answering to ARP Packet
        process_arp(packet_in_event)

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

        if \
                pkt_ipv4_src == IPv4Address("0.0.0.0") and \
                pkt_ipv4_dst == IPv4Address("255.255.255.255") and \
                ip_layer.haslayer(DHCP):
                    pass  # Let DHCP traffic pass

        elif pkt_ipv4_dst not in ipv4_network:
            _log.warning("Traffic towards destination {:s} is not supported.".format(str(pkt_ipv4_dst)))
            return
        elif pkt_ipv4_dst == ipv4_network.broadcast_address:
            _log.warning("Broadcast traffic ({:s}) is not supported.".format(str(pkt_ipv4_dst)))
            return
        elif pkt_ipv4_dst.is_multicast:
            _log.warning("Multicast traffic ({:s}) is not supported.".format(str(pkt_ipv4_dst)))
            return

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
                        assert not sector.is_entity_registered(new_host), "Entity {:s} is already registered.".format(
                            str(new_host)
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
                                # ("name_server", "8.8.8.8"),
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
                        datapath_ofp_parser.OFPPacketOut(
                            datapath=msg.datapath,
                            buffer_id=datapath_ofp.OFP_NO_BUFFER,
                            in_port=datapath_ofp.OFPP_CONTROLLER,
                            actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_offer))],
                            data=bytes(dhcp_offer)
                        )
                    )
                    globals.send_msg(
                        datapath_ofp_parser.OFPBarrierRequest(msg.datapath),
                        reply_cls=datapath_ofp_parser.OFPBarrierReply
                    )

                elif dhcp_layer_options['message-type'] is 3:  # A DHCP Request packet was received
                    try:
                        _log.debug(
                            "Received DHCP Request packet from host with MAC {:s} "
                            "on switch {:016X} at port {:d}".format(
                                pkt.src, datapath_id, pkt_in_port
                            )
                        )

                        # It is necessary to check if the host is already registered at the controller database
                        client_id = database.query_client_id(datapath_id, pkt_in_port, EUI(pkt.src))
                        client_info = database.query_client_info(client_id)
                        client_ipv4 = client_info["ipv4"]

                        # Activate segregation flow at the switch port for the detected sector host
                        services.host_segregation_flow_activation(datapath_obj, pkt_in_port, pkt.src)

                        #  Sending DHCP Ack to host
                        dhcp_ack = Ether(src=str(mac_service), dst=pkt.src) \
                            / IP(src=str(ipv4_service), dst="255.255.255.255") \
                            / UDP() / BOOTP(
                                op="BOOTREPLY", xid=bootp_layer.xid, flags=bootp_layer.flags, yiaddr=str(client_ipv4),
                                chaddr=EUI(pkt.src).packed
                            ) \
                            / DHCP(
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
                            datapath_ofp_parser.OFPPacketOut(
                                datapath=msg.datapath,
                                buffer_id=datapath_ofp.OFP_NO_BUFFER,
                                in_port=datapath_ofp.OFPP_CONTROLLER,
                                actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_ack))],
                                data=bytes(dhcp_ack)
                            )
                        )
                        globals.send_msg(
                            datapath_ofp_parser.OFPBarrierRequest(msg.datapath),
                            reply_cls=datapath_ofp_parser.OFPBarrierReply
                        )

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
                            datapath_ofp_parser.OFPPacketOut(
                                datapath=msg.datapath,
                                buffer_id=datapath_ofp.OFP_NO_BUFFER,
                                in_port=datapath_ofp.OFPP_CONTROLLER,
                                actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_nak))],
                                data=bytes(dhcp_nak)
                            )
                        )
                        globals.send_msg(
                            datapath_ofp_parser.OFPBarrierRequest(msg.datapath),
                            reply_cls=datapath_ofp_parser.OFPBarrierReply
                        )

        elif ip_layer.haslayer(ICMP):  # ICMPv4 services
            datapath_obj = msg.datapath
            icmp_layer = pkt[ICMP]
            data_layer = pkt[Raw]
            _log.debug(
                "Received ICMP Packet - Summary: {:s}".format(icmp_layer.mysummary())
            )
            if ip_layer.dst == str(ipv4_service):
                # If the destination IP is the service IP, the controller should immediately answer.
                icmp_reply = Ether(src=str(mac_service), dst=pkt.src) \
                             / IP(src=str(ipv4_service), dst=ip_layer.src) \
                             / ICMP(
                                type="echo-reply",
                                id=icmp_layer.id,
                                seq=icmp_layer.seq,
                            ) \
                             / Raw(data_layer.load)

                datapath_obj.send_msg(
                    datapath_ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=datapath_ofp.OFP_NO_BUFFER,
                        in_port=datapath_ofp.OFPP_CONTROLLER,
                        actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(icmp_reply))],
                        data=bytes(icmp_reply)
                    )
                )
            elif pkt_ipv4_dst in ipv4_network:  # If the destination IP belongs to the network.
                # Opens a bi-directional tunnel to target, using the same path in both directions.
                target_host_not_found_in_sector = False
                try:
                    addr_info_dst = database.query_address_info(ipv4=pkt_ipv4_dst)
                    target_switch_id = addr_info_dst["datapath"]
                    target_switch_port = addr_info_dst["port"]
                    host_a_entity_id = sector.query_connected_entity_id(datapath_id, pkt_in_port)
                    host_b_entity_id = sector.query_connected_entity_id(target_switch_id, target_switch_port)
                    start_time = time.time()

                    # Construct a BiDirectional Path between Host A and Host B.
                    bidirectional_path = sector.construct_bidirectional_path(
                        host_a_entity_id,
                        host_b_entity_id,
                        allocated_bandwith=100
                    )

                    # Allocate MPLS label for tunnel
                    if len(bidirectional_path) >= 3:
                        mpls_label = globals.alloc_mpls_label_id()
                    else:
                        mpls_label = None

                    # Activating the ICMP service between hosts in the same sector.
                    local_service_scenario = services.icmpv4_flow_activation(bidirectional_path, mpls_label)

                    global_path_search_id = (
                        str(controller_uuid),
                        pkt_ipv4_src,
                        pkt_ipv4_dst,
                        "ICMPv4"
                    )

                    globals.set_active_scenario(
                        global_path_search_id,
                        (
                            (id(local_service_scenario),), tuple()
                        )
                    )

                    # Reinsert the ICMP packet into the OpenFlow Pipeline, in order to properly process it.
                    msg.datapath.send_msg(
                        datapath_ofp_parser.OFPPacketOut(
                            datapath=msg.datapath,
                            buffer_id=datapath_ofp.OFP_NO_BUFFER,
                            in_port=pkt_in_port,
                            actions=[
                                datapath_ofp_parser.OFPActionOutput(
                                    port=datapath_ofp.OFPP_TABLE,
                                    max_len=len(msg.data)
                                ),
                            ],
                            data=msg.data
                        )
                    )

                    _log.info(
                        "ICMPv4 Scenario with ID {:s} is now active. "
                        "Implemented in {:f} seconds. "
                        "Path has length {:d}. "
                        "".format(
                            str(global_path_search_id),
                            time.time() - start_time,
                            len(bidirectional_path)
                        )
                    )

                except database.AddressNotRegistered:
                    target_host_not_found_in_sector = True

                if target_host_not_found_in_sector:
                    # If the target host does not exist in the same sector, it is necessary to start a parallel
                    #  process which will implement the cross-sector ICMP service between the hosts.
                    # Query host info details directly from foreign sector

                    def remote_host_icmpv4_task(dp_id, p_in_port, global_path_search_id, task_token):
                        # Warning!!! task_token is not a useless argument. The task token exists only to signal
                        #   the existence of a task execution. Once task_token goes out of context,
                        #   the token is destroyed.
                        try:
                            start_time = time.time()
                            target_ipv4 = global_path_search_id[2]
                            target_host_info = central.query_address_info(ipv4=target_ipv4)
                            host_a_entity_id = sector.query_connected_entity_id(dp_id, p_in_port)
                            target_sector_id = target_host_info.controller_id
                            adjacent_sectors_ids = sector.query_sectors_ids()

                            if len(adjacent_sectors_ids) == 0:
                                raise PathNotFound("No adjacent sectors available.")

                            if target_sector_id in adjacent_sectors_ids:
                                # The possible communication links to the target sector
                                possible_links = sector.query_edges_to_sector(target_host_info.controller_id)
                                selected_link = tuple()
                                bidirectional_path = tuple()

                                while possible_links:
                                    # First, lets choose a link to the adjacent sector, according to the q-value
                                    links_never_used = tuple(
                                        filter(
                                            (lambda link: globals.get_q_value((link[0], link[1]), target_ipv4) == 0),
                                            possible_links
                                        )
                                    )
                                    if len(links_never_used):
                                        selected_link = links_never_used[0]
                                    else:
                                        selected_link = max(
                                            possible_links,
                                            key=(lambda link: globals.get_q_value((link[0], link[1]), target_ipv4))
                                        )
                                    try:
                                        # If the target sector IS adjacent to this sector, contact it directly
                                        # and establish a path
                                        bidirectional_path = sector.construct_bidirectional_path(
                                            host_a_entity_id,
                                            target_sector_id,
                                            allocated_bandwith=100,
                                            next_sector_hash=selected_link[2]
                                        )
                                        break
                                    except PathNotFound:
                                        possible_links.remove(selected_link)
                                        if len(possible_links) == 0:
                                            raise

                                assert len(bidirectional_path), "bidirectional_path path length cannot be zero."
                                assert isinstance(selected_link, tuple), "selected_link expected to be tuple"

                                # Allocate MPLS label for tunnel (required when communicating with Sectors)
                                local_mpls_label = globals.alloc_mpls_label_id()

                                # Knowing which switch connects to the sector and through which port
                                chosen_edge = (selected_link[0], selected_link[1])
                                selected_sector_proxy = p2p_requests.get_controller_proxy(target_sector_id)
                                service_activation_result = selected_sector_proxy.activate_scenario(
                                    {
                                        "global_path_search_id": global_path_search_id,
                                        "sector_requesting_service": str(controller_uuid),
                                        "mpls_label": local_mpls_label,
                                        "hash_val": globals.get_hash_val(*chosen_edge),
                                    }
                                )

                                forward_q_value = 0 if "q_value" not in service_activation_result else \
                                service_activation_result["q_value"]

                                if service_activation_result["success"]:
                                    kspl = globals.get_known_shortest_path(
                                        chosen_edge,
                                        target_ipv4
                                    )
                                    if kspl and kspl > service_activation_result["path_length"] + 1:
                                        globals.set_known_shortest_path(
                                            chosen_edge,
                                            target_ipv4,
                                            service_activation_result["path_length"] + 1
                                        )
                                    else:
                                        globals.set_known_shortest_path(
                                            chosen_edge,
                                            target_ipv4,
                                            service_activation_result["path_length"] + 1
                                        )
                                    kspl = globals.get_known_shortest_path(
                                        chosen_edge,
                                        target_ipv4
                                    )
                                    assert kspl, "kspl cannot be Zero or None."

                                    reward = bidirectional_path.remaining_bandwidth_average / kspl

                                    old_q_value = globals.get_q_value(chosen_edge, target_ipv4)
                                    new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, reward)
                                    globals.set_q_value(chosen_edge, target_ipv4, new_q_value)

                                    local_service_scenario = services.icmpv4_flow_activation(
                                        bidirectional_path,
                                        local_mpls_label,
                                        target_ipv4
                                    )

                                    globals.set_active_scenario(
                                        global_path_search_id,
                                        (
                                            (id(local_service_scenario),), (target_sector_id,)
                                        )
                                    )

                                    _log.info(
                                        "Adjacent Sector: {:s}; "
                                        "Chosen link: {:s}; "
                                        "Updated Q-Values -> "
                                        "Old Q-Value: {:f}; "
                                        "New Q-Value: {:f}; "
                                        "Reward: {:f}; "
                                        "Forward Q-Value: {:f}."
                                        "KSPL: {:d};"
                                        "".format(
                                            str(target_sector_id), str(chosen_edge),
                                            old_q_value, new_q_value, reward, forward_q_value, kspl
                                        )
                                    )
                                else:
                                    old_q_value = globals.get_q_value(chosen_edge, target_ipv4)
                                    new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                                    globals.set_q_value(chosen_edge, target_ipv4, new_q_value)

                                    _log.info(
                                        "Adjacent Sector: {:s}; "
                                        "Chosen link: {:s}; "
                                        "Updated Q-Values -> "
                                        "Old Q-Value: {:f}; "
                                        "New Q-Value: {:f}; "
                                        "Reward: {:f}; "
                                        "Forward Q-Value: {:f}."
                                        "".format(
                                            str(target_sector_id), str(chosen_edge),
                                            old_q_value, new_q_value, -1, forward_q_value
                                        )
                                    )

                                    _log.error(
                                        "Cannot establish an ICMPv4 path to sector {:s}.".format(
                                            str(target_sector_id)
                                        )
                                    )

                            else:
                                # The possible communication links to the target sector
                                possible_links = []
                                for adjacent_sector in adjacent_sectors_ids:
                                    for edge in sector.query_edges_to_sector(adjacent_sector):
                                        possible_links.append((edge[0], edge[1], edge[2], adjacent_sector))

                                _log.debug(
                                    "Available Sector Links for exploration: [{:s}]".format(
                                        "][".join(tuple((str(i) for i in possible_links)))
                                    )
                                )

                                while possible_links:
                                    # First, lets choose a link to the adjacent sector, according to the q-value
                                    links_never_used = tuple(
                                        filter(
                                            (lambda link: globals.get_q_value(
                                                (link[0], link[1]), target_ipv4
                                            ) == 0),
                                            possible_links
                                        )
                                    )
                                    if len(links_never_used):
                                        selected_link = links_never_used[0]
                                    else:
                                        selected_link = max(
                                            possible_links,
                                            key=(lambda link: globals.get_q_value((link[0], link[1]), target_ipv4))
                                        )
                                    possible_links.remove(selected_link)

                                    chosen_edge = selected_link[0:2]
                                    selected_sector_id = selected_link[3]

                                    _log.debug(
                                        "Selected Link {:s}{:s}".format(
                                            str(selected_link),
                                            " from {}.".format(possible_links) if len(possible_links) else "."
                                        )
                                    )
                                    try:
                                        bidirectional_path = sector.construct_bidirectional_path(
                                            host_a_entity_id,
                                            selected_sector_id,
                                            allocated_bandwith=100,
                                            next_sector_hash=selected_link[2]
                                        )
                                    except PathNotFound:
                                        if len(possible_links) == 0:
                                            raise
                                        continue  # Go back to the beginning of the cycle and try again with a new link

                                    assert len(bidirectional_path), "bidirectional_path path length cannot be zero."
                                    assert isinstance(selected_link, tuple), "selected_link expected to be tuple"
                                    assert selected_sector_id is not None, "selected_sector_id cannot be None"

                                    # Allocate MPLS label for tunnel (required when communicating with Sectors)
                                    local_mpls_label = globals.alloc_mpls_label_id()
                                    try:
                                        selected_sector_proxy = p2p_requests.get_controller_proxy(selected_sector_id)
                                        service_activation_result = selected_sector_proxy.activate_scenario(
                                            {
                                                "global_path_search_id": global_path_search_id,
                                                "sector_requesting_service": str(controller_uuid),
                                                "mpls_label": local_mpls_label,
                                                "hash_val": globals.get_hash_val(*chosen_edge),

                                            }
                                        )
                                    except Exception as ex:
                                        service_activation_result = {"success": False, "reason": str(ex)}

                                    forward_q_value = 0 if "q_value" not in service_activation_result else \
                                        service_activation_result["q_value"]

                                    if service_activation_result["success"]:
                                        kspl = globals.get_known_shortest_path(
                                            chosen_edge,
                                            pkt_ipv4_dst
                                        )
                                        if kspl and kspl > service_activation_result["path_length"] + 1:
                                            globals.set_known_shortest_path(
                                                chosen_edge,
                                                pkt_ipv4_dst,
                                                service_activation_result["path_length"] + 1
                                            )
                                        else:
                                            globals.set_known_shortest_path(
                                                chosen_edge,
                                                pkt_ipv4_dst,
                                                service_activation_result["path_length"] + 1
                                            )
                                        # Update kspl value since it may have been changed.
                                        kspl = globals.get_known_shortest_path(
                                            chosen_edge,
                                            pkt_ipv4_dst
                                        )
                                        assert kspl, "kspl cannot be Zero or None."

                                        reward = bidirectional_path.remaining_bandwidth_average / kspl

                                        old_q_value = globals.get_q_value(chosen_edge, pkt_ipv4_dst)
                                        new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, reward)
                                        globals.set_q_value(chosen_edge, pkt_ipv4_dst, new_q_value)

                                        _log.info(
                                            "Chosen link: {:s}; "
                                            "Old Q-Value: {:f}; "
                                            "New Q-Value: {:f}; "
                                            "Reward: {:f}; "
                                            "Forward Q-Value: {:f}."
                                            "KSPL: {:d}."
                                            "".format(
                                                str(selected_link),
                                                old_q_value, new_q_value, reward, forward_q_value, kspl
                                            )
                                        )

                                        local_service_scenario = services.icmpv4_flow_activation(
                                            bidirectional_path,
                                            local_mpls_label,
                                            target_ipv4
                                        )

                                        globals.set_active_scenario(
                                            global_path_search_id,
                                            (
                                                (id(local_service_scenario),), (selected_sector_id,)
                                            )
                                        )

                                        _log.info(
                                            "ICMPv4 Scenario with ID {:s} is now active. "
                                            "Implemented in {:f} seconds. "
                                            "Global Path has length {:d}. "
                                            "Local Path has length {:d}. "
                                            "".format(
                                                str(global_path_search_id),
                                                time.time() - start_time,
                                                len(bidirectional_path) + service_activation_result["path_length"],
                                                len(bidirectional_path)
                                            )
                                        )
                                        break

                                    else:
                                        old_q_value = globals.get_q_value(chosen_edge, pkt_ipv4_dst)
                                        new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                                        globals.set_q_value(chosen_edge, pkt_ipv4_dst, new_q_value)

                                        _log.info(
                                            "Chosen link: {:s}; "
                                            "Old Q-Value: {:f}; "
                                            "New Q-Value: {:f}; "
                                            "Reward: {:f}; "
                                            "Forward Q-Value: {:f}."
                                            "".format(
                                                str(chosen_edge),
                                                old_q_value, new_q_value, -1, forward_q_value
                                            )
                                        )

                                        _log.error(
                                            "Failed to implement path to host {:s} at sector {:s}. Reason {:s}."
                                            "".format(
                                                target_host_info.name,
                                                str(target_host_info.controller_id),
                                                service_activation_result["reason"]
                                            )
                                        )

                                        if len(adjacent_sectors_ids) == 0:
                                            _log.error(
                                                "Adjacent sectors alternatives is exhausted. "
                                                "Cannot establish ICMPv4 communication to sector {:s}".format(
                                                    str(target_sector_id)
                                                )
                                            )

                        except central.NoResultsAvailable:
                            _log.error(
                                "Target {:s} is not registered at the central manager.".format(str(pkt_ipv4_dst)))
                            custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())

                        except PathNotFound:
                            _log.error("Failed to activate path. An available path was not found in the network.")
                            custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())

                        except Exception as ex:
                            _log.error("Failed to activate path. Reason {:s}.".format(str(ex)))
                            custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())

                    #  End of Task Definition



                    try:
                        global_path_search_id = (
                            str(controller_uuid),
                            pkt_ipv4_src,
                            pkt_ipv4_dst,
                            "ICMPv4"
                        )

                        if globals.is_scenario_active(global_path_search_id):
                            error_str = "ICMPv4 scenario with ID {:s} is already implemented.".format(
                                str(global_path_search_id)
                            )
                            _log.warning(error_str)

                        else:
                            hub.spawn(
                                remote_host_icmpv4_task,
                                datapath_id,
                                pkt_in_port,
                                global_path_search_id,
                                globals.register_implementation_task(global_path_search_id, "IPv4", "ICMP")
                            )

                    except globals.ImplementationTaskExists:
                            _log.warning(
                                "ICMPv4 service task is already running for the ipv4 source/target pair "
                                "({:s}, {:s}).".format(
                                    str(pkt_ipv4_src), str(pkt_ipv4_dst)
                                )
                            )

            else:
                # If the destination IP is in a different network, return ICMP Network Unreachable
                icmp_reply = Ether(src=str(mac_service), dst=pkt.src) \
                             / IP(src=str(ipv4_service), dst=ip_layer.src) \
                             / ICMP(
                    type="dest-unreach",
                    code="network-unreachable",
                    id=icmp_layer.id,
                    seq=icmp_layer.seq,
                ) \
                             / Raw(data_layer.load)

                datapath_obj.send_msg(
                    datapath_ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=datapath_ofp.OFP_NO_BUFFER,
                        in_port=datapath_ofp.OFPP_CONTROLLER,
                        actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(icmp_reply))],
                        data=bytes(icmp_reply)
                    )
                )

                _log.error("Target {:s} is currently not reachable.".format(str(pkt_ipv4_dst)))

        elif ip_layer.haslayer(DNS):  # DNS service management
            datapath_obj = msg.datapath
            udp_layer = pkt[UDP]
            dns_layer = pkt[DNS]
            DNSQR_layer = pkt[DNSQR]

            _log.debug("Received DNS Packet - Summary: {:s}".format(dns_layer.mysummary()))
            qname_split = DNSQR_layer.qname.decode().split(".")[:-1]
            if len(qname_split) == 3 and qname_split[-1] == "archsdn":
                try:
                    query_client_id = int(qname_split[0])
                except ValueError as ve:
                    raise ValueError("DNS Query malformed. Client ID invalid.")

                if "-" in qname_split[1]:
                    try:
                        query_controller_uuid = UUID(qname_split[1])
                    except ValueError:
                        raise ValueError("DNS Query malformed. Controller ID invalid.")
                elif str.isalnum(qname_split[1]):
                    try:
                        query_controller_uuid = UUID(int=int(qname_split[1]))
                    except ValueError:
                        try:
                            query_controller_uuid = UUID(int=int(qname_split[1], 16))
                        except ValueError:
                            raise ValueError("DNS Query malformed. Controller ID invalid.")
                else:
                    raise ValueError("DNS Query malformed. Controller ID invalid")

                # Query Central for Destination IP
                # Return to client the IP
                _log.info(
                    "DNS Query request for Client {:d} at Sector {:s}".format(
                        query_client_id,
                        str(query_controller_uuid),
                    )
                )
                if controller_uuid == query_controller_uuid:  # If the client is part of this sector
                    try:
                        client_info = database.query_client_info(query_client_id)
                        dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                                    / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                    / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                                    / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='ok',
                                          an=DNSRR(rrname=DNSQR_layer.qname, rdata=str(client_info["ipv4"]))
                                          )
                        _log.info(
                            "Client {:d} at Sector {:s} record found locally!: {:s}".format(
                                query_client_id,
                                str(query_controller_uuid),
                                str(client_info)
                            )
                        )
                    except database.ClientNotRegistered:
                        dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                                    / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                    / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                                    / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='name-error')
                        _log.error(
                            "Client {:d} at Sector {:s} record does not exist".format(
                                query_client_id,
                                str(query_controller_uuid),
                            )
                        )
                else:  # If the client is part of a foreign sector
                    try:
                        client_info = central.query_client_info(query_controller_uuid, query_client_id)
                        dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                            / IP(src=str(ipv4_service), dst=ip_layer.src) \
                            / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                            / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='ok',
                                  an=DNSRR(rrname=DNSQR_layer.qname, rdata=str(client_info.ipv4))
                                  )
                        _log.info(
                            "Client {:d} at Sector {:s} record found at central management!: {:s}".format(
                                query_client_id,
                                str(query_controller_uuid),
                                str(client_info)
                            )
                        )
                    except central.ClientNotRegistered:
                        dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                                    / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                    / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                                    / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='name-error')
                        _log.error(
                            "Client {:d} at Sector {:s} record does not exist".format(
                                query_client_id,
                                str(query_controller_uuid),
                            )
                        )

                datapath_obj.send_msg(
                    datapath_ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=datapath_ofp.OFP_NO_BUFFER,
                        in_port=datapath_ofp.OFPP_CONTROLLER,
                        actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dns_reply))],
                        data=bytes(dns_reply)
                    )
                )

        elif ip_layer.haslayer(IP):  # Generic IPv4 service management

            if ip_layer.dst == str(ipv4_service):
                # If the destination IP is the ipv4_service, return ICMP Port Unreachable.
                # TODO: Implement a redirect flow and send all packets directed at the ipv4_service IP, to a local TAP
                #   device serving all the necessary services.
                icmp_reply = Ether(src=str(mac_service), dst=pkt.src) \
                             / IP(src=str(ipv4_service), dst=ip_layer.src) \
                             / ICMP(
                    type="dest-unreach",
                    code="port-unreachable",
                    id=0,
                    seq=0,
                )

                msg.datapath.send_msg(
                    datapath_ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=datapath_ofp.OFP_NO_BUFFER,
                        in_port=datapath_ofp.OFPP_CONTROLLER,
                        actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(icmp_reply))],
                        data=bytes(icmp_reply)
                    )
                )
                _log.error("Service Ports are currently not reachable.")

            elif pkt_ipv4_dst in ipv4_network:
                # Opens a unidirectional tunnel to target, using the same path in both directions.
                target_host_not_found_in_sector = False

                global_path_search_id = (
                    str(controller_uuid),
                    pkt_ipv4_src,
                    pkt_ipv4_dst,
                    "IPv4"
                )

                try:
                    addr_info_dst = database.query_address_info(ipv4=pkt_ipv4_dst)
                    target_switch_id = addr_info_dst["datapath"]
                    target_switch_port = addr_info_dst["port"]
                    host_a_entity_id = sector.query_connected_entity_id(datapath_id, pkt_in_port)
                    host_b_entity_id = sector.query_connected_entity_id(target_switch_id, target_switch_port)

                    # Construct a UniDirectional_path Path between Host A and Host B.
                    unidirectional_path = sector.construct_unidirectional_path(
                        host_a_entity_id,
                        host_b_entity_id
                    )

                    # Allocate MPLS label for tunnel
                    if len(unidirectional_path) >= 3:
                        mpls_label = globals.alloc_mpls_label_id()
                    else:
                        mpls_label = None

                    # Activating the Generic IPv4 service between hosts in the same sector.
                    local_service_scenario = services.ipv4_generic_flow_activation(unidirectional_path, mpls_label)

                    globals.set_active_scenario(
                        global_path_search_id,
                        (
                            (id(local_service_scenario),), tuple()
                        )
                    )

                    _log.warning(
                        "IPv4 data flow opened from host {:s} to host {:s}.".format(
                            str(host_a_entity_id), str(host_b_entity_id)
                        )
                    )

                except database.AddressNotRegistered:
                    target_host_not_found_in_sector = True

                if target_host_not_found_in_sector:
                    # If the target host does not exist in the same sector, it is necessary to start a parallel
                    #  process which will implement the cross-sector Generic IPv4 data flow from host A to host B.
                    # Query host info details directly from foreign sector

                    def remote_host_generic_ipv4_task(dp_id, p_in_port, global_path_search_id, task_token):
                        # Warning!!! task_token is not a useless argument. The task token exists only to signal
                        #   the existence of a task execution. Once task_token goes out of context,
                        #   the token is destroyed.
                        try:
                            start_time = time.time()
                            target_ipv4 = global_path_search_id[2]
                            target_ipv4_str = str(target_ipv4)
                            target_host_info = central.query_address_info(ipv4=target_ipv4)
                            host_a_entity_id = sector.query_connected_entity_id(dp_id, p_in_port)
                            target_sector_id = target_host_info.controller_id
                            adjacent_sectors_ids = sector.query_sectors_ids()

                            if len(adjacent_sectors_ids) == 0:
                                raise PathNotFound("No adjacent sectors available.")

                            if target_sector_id in adjacent_sectors_ids:
                                # If the target sector IS adjacent to this sector, contact it directly and establish
                                #  a path
                                unidirectional_path = sector.construct_unidirectional_path(
                                    host_a_entity_id,
                                    target_sector_id,
                                )

                                # Allocate MPLS label for tunnel (required when communicating with Sectors)
                                local_mpls_label = globals.alloc_mpls_label_id()

                                # Knowing which switch connects to the sector and through which port
                                (switch_id, _, port_out) = unidirectional_path.path[-2]
                                selected_sector_proxy = p2p_requests.get_controller_proxy(target_sector_id)
                                service_activation_result = selected_sector_proxy.activate_scenario(
                                    {
                                        "global_path_search_id": global_path_search_id,
                                        "sector_requesting_service": str(controller_uuid),
                                        "mpls_label": local_mpls_label,
                                        "hash_val": globals.get_hash_val(switch_id, port_out),
                                    }
                                )

                                forward_q_value = 0 if "q_value" not in service_activation_result else \
                                    service_activation_result["q_value"]

                                if service_activation_result["success"]:
                                    kspl = globals.get_known_shortest_path(
                                        target_host_info.controller_id,
                                        target_ipv4
                                    )
                                    if kspl and kspl > service_activation_result["path_length"] + 1:
                                        globals.set_known_shortest_path(
                                            target_host_info.controller_id,
                                            target_ipv4,
                                            service_activation_result["path_length"] + 1
                                        )
                                    else:
                                        globals.set_known_shortest_path(
                                            target_host_info.controller_id,
                                            target_ipv4,
                                            service_activation_result["path_length"] + 1
                                        )
                                    kspl = globals.get_known_shortest_path(
                                        target_host_info.controller_id,
                                        target_ipv4
                                    )
                                    assert kspl, "kspl cannot be Zero or None."

                                    reward = unidirectional_path.remaining_bandwidth_average / kspl

                                    old_q_value = globals.get_q_value(target_host_info.controller_id, target_ipv4_str)
                                    new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, reward)
                                    globals.set_q_value(target_host_info.controller_id, target_ipv4_str, new_q_value)

                                    local_service_scenario = services.ipv4_generic_flow_activation(
                                        unidirectional_path,
                                        local_mpls_label,
                                        target_ipv4
                                    )

                                    globals.set_active_scenario(
                                        global_path_search_id,
                                        (
                                            (id(local_service_scenario),), (target_sector_id,)
                                        )
                                    )

                                    _log.info(
                                        "Adjacent Sector: {:s}; "
                                        "Updated Q-Values -> "
                                        "Old Q-Value: {:f}; "
                                        "New Q-Value: {:f}; "
                                        "Reward: {:f}; "
                                        "Forward Q-Value: {:f}; "
                                        "KSPL: {:d}"
                                        "".format(
                                            str(target_host_info.controller_id),
                                            old_q_value, new_q_value, reward, forward_q_value, kspl
                                        )
                                    )

                                    _log.info(
                                        "IPv4 Scenario with ID {:s} is now active. "
                                        "Implemented in {:f} seconds. "
                                        "Path has length {:d}. "
                                        "".format(
                                            str(global_path_search_id),
                                            time.time() - start_time,
                                            len(unidirectional_path) + service_activation_result["path_length"]
                                        )
                                    )
                                else:
                                    old_q_value = globals.get_q_value(target_host_info.controller_id, target_ipv4_str)
                                    new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                                    globals.set_q_value(target_host_info.controller_id, target_ipv4_str, new_q_value)

                                    _log.info(
                                        "Adjacent Sector: {:s}; "
                                        "Updated Q-Values -> "
                                        "Old Q-Value: {:f}; "
                                        "New Q-Value: {:f}; "
                                        "Reward: {:f}; "
                                        "Forward Q-Value: {:f}."
                                        "".format(
                                            str(target_host_info.controller_id),
                                            old_q_value, new_q_value, -1, forward_q_value
                                        )
                                    )

                                    _log.error(
                                        "Cannot establish a generic IPv4 flow path to sector {:s}.".format(
                                            str(target_sector_id)
                                        )
                                    )

                            else:
                                # If the target sector IS NOT adjacent to this sector, lets select the best adjacent
                                #   sector used in the past...
                                while len(adjacent_sectors_ids):
                                    _log.debug(
                                        "Available adjacent sectors for exploration: {}".format(adjacent_sectors_ids)
                                    )
                                    sectors_never_used = tuple(
                                        filter(
                                            (lambda sector_id: globals.get_q_value(sector_id, target_ipv4) == 0),
                                            adjacent_sectors_ids
                                        )
                                    )
                                    if len(sectors_never_used):
                                        selected_sector_id = sectors_never_used[0]
                                    else:
                                        selected_sector_id = max(
                                            adjacent_sectors_ids,
                                            key=(lambda sector_id: globals.get_q_value(sector_id, target_ipv4))
                                        )

                                    adjacent_sectors_ids.remove(selected_sector_id)
                                    _log.debug(
                                        "{:s} sector selected".format(
                                            str(selected_sector_id),
                                            " from {}.".format(adjacent_sectors_ids) if len(
                                                adjacent_sectors_ids) else "."
                                        )
                                    )
                                    unidirectional_path = sector.construct_unidirectional_path(
                                        host_a_entity_id,
                                        selected_sector_id,
                                    )

                                    assert len(unidirectional_path), "bidirectional_path path length cannot be zero."

                                    # Allocate MPLS label for tunnel (required when communicating with Sectors)
                                    local_mpls_label = globals.alloc_mpls_label_id()

                                    (switch_id, _, port_out) = unidirectional_path.path[-2]
                                    selected_sector_proxy = p2p_requests.get_controller_proxy(selected_sector_id)
                                    try:
                                        service_activation_result = selected_sector_proxy.activate_scenario(
                                            {
                                                "global_path_search_id": global_path_search_id,
                                                "sector_requesting_service": str(controller_uuid),
                                                "mpls_label": local_mpls_label,
                                                "hash_val": globals.get_hash_val(switch_id, port_out),

                                            }
                                        )
                                    except Exception as ex:
                                        service_activation_result = {"success": False, "reason": str(ex)}

                                    forward_q_value = 0 if "q_value" not in service_activation_result else \
                                        service_activation_result["q_value"]

                                    if service_activation_result["success"]:
                                        kspl = globals.get_known_shortest_path(
                                            selected_sector_id,
                                            pkt_ipv4_dst
                                        )
                                        if kspl and kspl > service_activation_result["path_length"] + 1:
                                            globals.set_known_shortest_path(
                                                selected_sector_id,
                                                pkt_ipv4_dst,
                                                service_activation_result["path_length"] + 1
                                            )
                                        else:
                                            globals.set_known_shortest_path(
                                                selected_sector_id,
                                                pkt_ipv4_dst,
                                                service_activation_result["path_length"] + 1
                                            )
                                        # Update kspl value since it may have been changed.
                                        kspl = globals.get_known_shortest_path(
                                            selected_sector_id,
                                            pkt_ipv4_dst
                                        )
                                        assert kspl, "kspl cannot be Zero or None."

                                        reward = unidirectional_path.remaining_bandwidth_average / kspl

                                        old_q_value = globals.get_q_value(selected_sector_id, pkt_ipv4_dst)
                                        new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, reward)
                                        globals.set_q_value(selected_sector_id, pkt_ipv4_dst, new_q_value)

                                        _log.info(
                                            "Selected Sector: {:s}; "
                                            "Updated Q-Values -> "
                                            "Old Q-Value: {:f}; "
                                            "New Q-Value: {:f}; "
                                            "Reward: {:f}; "
                                            "Forward Q-Value: {:f}; "
                                            "KSPL: {:d}"
                                            "".format(
                                                str(selected_sector_id),
                                                old_q_value, new_q_value, reward, forward_q_value, kspl
                                            )
                                        )

                                        local_service_scenario = services.ipv4_generic_flow_activation(
                                            unidirectional_path,
                                            local_mpls_label,
                                            target_ipv4
                                        )

                                        globals.set_active_scenario(
                                            global_path_search_id,
                                            (
                                                (id(local_service_scenario),), (selected_sector_id,)
                                            )
                                        )

                                        _log.info(
                                            "IPv4 Scenario with ID {:s} is now active. "
                                            "Implemented in {:f} seconds. "
                                            "Global Path has length {:d}. "
                                            "Local Path has length {:d}. "
                                            "".format(
                                                str(global_path_search_id),
                                                time.time() - start_time,
                                                len(unidirectional_path) + service_activation_result["path_length"],
                                                len(unidirectional_path)
                                            )
                                        )
                                        break

                                    else:
                                        old_q_value = globals.get_q_value(selected_sector_id, pkt_ipv4_dst)
                                        new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                                        globals.set_q_value(selected_sector_id, pkt_ipv4_dst, new_q_value)

                                        _log.info(
                                            "Selected Sector: {:s}; "
                                            "Updated Q-Values -> "
                                            "Old Q-Value: {:f}; "
                                            "New Q-Value: {:f}; "
                                            "Reward: {:f}; "
                                            "Forward Q-Value: {:f}."
                                            "".format(
                                                str(selected_sector_id),
                                                old_q_value, new_q_value, -1, forward_q_value
                                            )
                                        )

                                        _log.error(
                                            "Failed to implement path to host {:s} at sector {:s}. Reason {:s}."
                                            "".format(
                                                target_host_info.name,
                                                str(target_host_info.controller_id),
                                                service_activation_result["reason"]
                                            )
                                        )

                                        if len(adjacent_sectors_ids) == 0:
                                            _log.error(
                                                "Adjacent sectors alternatives is exhausted. "
                                                "Cannot establish IPv4 generic flow to sector {:s}".format(
                                                    str(target_sector_id)
                                                )
                                            )

                        except central.NoResultsAvailable:
                            _log.error(
                                "Target {:s} is not registered at the central manager.".format(str(pkt_ipv4_dst)))
                            custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())

                        except PathNotFound:
                            _log.error("Failed to activate path. An available path was not found in the network.")
                            custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())

                        except Exception as ex:
                            _log.error("Failed to activate path. Reason {:s}.".format(str(ex)))
                            custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())

                    #  End of Task Definition

                    try:
                        if globals.is_scenario_active(global_path_search_id):
                            error_str = "IPv4 generic flow scenario with ID {:s} is already implemented.".format(
                                str(global_path_search_id)
                            )
                            _log.warning(error_str)

                        else:
                            hub.spawn(
                                remote_host_generic_ipv4_task,
                                datapath_id,
                                pkt_in_port,
                                global_path_search_id,
                                globals.register_implementation_task(global_path_search_id, "IPv4", "*")
                            )

                    except globals.ImplementationTaskExists:
                            _log.warning(
                                "IPv4 generic service task is already running for the ipv4 source/target pair "
                                "({:s}, {:s}).".format(
                                    str(pkt_ipv4_src), str(pkt_ipv4_dst)
                                )
                            )

            else:
                _log.error("Target {:s} is currently not reachable.".format(str(pkt_ipv4_dst)))

        else:
            _log.warning(
                "IP packet Type ({:X}), sent from {:s} to {:s}, is not supported. Discarding packet.".format(
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

