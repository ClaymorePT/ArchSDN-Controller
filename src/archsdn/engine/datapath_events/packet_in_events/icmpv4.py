
import sys
import logging
from ipaddress import IPv4Address
import time
from random import sample
from copy import deepcopy

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP

from ryu.lib import hub
from netaddr import EUI

from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn.engine import globals
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import services
from archsdn import p2p
from archsdn.engine.exceptions import PathNotFound

_log = logging.getLogger(logger_module_name(__file__))
packet_buffer = {}
experimental_data = {}

def process_icmpv4_packet(packet_in_event):
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

    ip_layer = pkt[IP]
    pkt_ipv4_src = IPv4Address(ip_layer.src)
    pkt_ipv4_dst = IPv4Address(ip_layer.dst)
    _log.debug(
        "Received IPv4 packet from host with MAC {:s}, Source IPv4 {:s} to Destiny IPv4 {:s}, "
        "on switch {:016X} at port {:d}".format(
            pkt.src, str(pkt_ipv4_src), str(pkt_ipv4_dst), datapath_id, pkt_in_port
        )
    )

    datapath_obj = msg.datapath
    icmp_layer = pkt[ICMP]
    data_layer = pkt[Raw]
    _log.debug(
        "Received ICMPv4 Packet - Summary: {:s}".format(icmp_layer.mysummary())
    )
    if ip_layer.dst == str(ipv4_service):
        # If the destination IPv4 is the service IPv4, the controller should immediately answer.
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
    elif pkt_ipv4_dst in ipv4_network:  # If the destination IPv4 belongs to the network.
        global_path_search_id = (
            str(controller_uuid),
            pkt_ipv4_src,
            pkt_ipv4_dst,
            "ICMPv4"
        )
        if global_path_search_id not in packet_buffer:
            packet_buffer[global_path_search_id] = []
        packet_buffer[global_path_search_id].append(deepcopy(msg.data))

        tmp_task_token = globals.register_implementation_task(global_path_search_id, "IPv4", "ICMP")


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

            # Activating the ICMPv4 service between hosts in the same sector.
            #  If bidirectional_path has more than 1 switch (more than three elements), then it requires an MPLS label
            local_service_scenario = services.icmpv4_flow_activation(
                bidirectional_path,
                globals.alloc_mpls_label_id() if len(bidirectional_path) >= 3 else None
            )

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

            # Reinsert the ICMPv4 packet into the OpenFlow Pipeline, in order to properly process it.
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

            def remote_host_icmpv4_task(dp_id, p_in_port, global_path_search_id, task_token, datapath_obj):
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

                    if not adjacent_sectors_ids:
                        raise PathNotFound("No adjacent sectors available.")

                    # The possible communication links to the target sector
                    selected_link = None # TODO: Move these to inside the while cycle
                    bidirectional_path = None
                    path_exploration = globals.should_explore()

                    possible_links = []
                    for adjacent_sector in adjacent_sectors_ids:
                        for edge in sector.query_edges_to_sector(adjacent_sector):
                            possible_links.append((edge[0], edge[1], edge[2], adjacent_sector))

                    possible_links = sorted(
                        possible_links, key=(lambda k: k[3] == target_host_info.controller_id), reverse=True
                    )
                    _log.debug(
                        "Available Sector Links for exploration:\n  {:s}".format(
                            "\n  ".join(tuple((str(i) for i in possible_links)))
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
                            if path_exploration:
                                selected_link = sample(possible_links, 1)[0]
                            else:
                                selected_link = max(
                                    possible_links,
                                    key=(lambda link: globals.get_q_value((link[0], link[1]), target_ipv4))
                                )

                        possible_links.remove(selected_link)

                        chosen_edge = selected_link[0:2]
                        selected_sector_id = selected_link[3]
                        _log.info("{:d} available edges.".format(len(possible_links)))
                        _log.info(
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
                                raise PathNotFound("All links to adjacent sectors have been tried.")
                            continue  # Go back to the beginning of the cycle and try again with a new link

                        assert selected_link is not None, "selected_link cannot be None"
                        assert bidirectional_path is not None, "bidirectional_path cannot be None"

                        assert len(bidirectional_path), "bidirectional_path path length cannot be zero."
                        assert isinstance(selected_link, tuple), "selected_link expected to be tuple"
                        assert selected_sector_id is not None, "selected_sector_id cannot be None"

                        # Allocate MPLS label for tunnel (required when communicating with Sectors)
                        local_mpls_label = globals.alloc_mpls_label_id()
                        try:
                            selected_sector_proxy = p2p.get_controller_proxy(selected_sector_id)
                            service_activation_result = selected_sector_proxy.activate_scenario(
                                {
                                    "global_path_search_id": global_path_search_id,
                                    "sector_requesting_service": str(controller_uuid),
                                    "mpls_label": local_mpls_label,
                                    "hash_val": globals.get_hash_val(*chosen_edge),
                                    "path_exploration": path_exploration
                                }
                            )
                        except Exception as ex:
                            globals.free_mpls_label_id(local_mpls_label)
                            del bidirectional_path  # Destroy previously allocated path and free reservations
                            _log.info("Sector {:s} returned the following error: {:s}".format(
                                str(selected_sector_id), str(ex))
                            )
                            if len(possible_links) == 0:
                                raise PathNotFound("All links to adjacent sectors have been tried.")
                            continue  # Go back to the beginning of the cycle and try again with a new link

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
                                "Forward Q-Value: {:f}; "
                                "KSPL: {:d}; "
                                "Path Exploration: {:s}."
                                "".format(
                                    str(selected_link),
                                    old_q_value, new_q_value, reward, forward_q_value, kspl,
                                    "True" if path_exploration else "False"
                                )
                            )

                            local_service_scenario = services.icmpv4_flow_activation(
                                bidirectional_path,
                                local_mpls_label,
                                service_activation_result["mpls_label"],
                                target_ipv4
                            )

                            globals.set_active_scenario(
                                global_path_search_id,
                                (
                                    (id(local_service_scenario),), (selected_sector_id,)
                                )
                            )

                            time_taken = time.time() - start_time
                            if pkt_ipv4_dst not in experimental_data:
                                experimental_data[pkt_ipv4_dst] = []

                            experimental_data[pkt_ipv4_dst].append(
                                (time_taken, len(bidirectional_path) + service_activation_result["path_length"], path_exploration)
                            )

                            if len(experimental_data[pkt_ipv4_dst]) == 100:
                                _log.info(
                                    "  \n".join((str(data) for data in experimental_data[pkt_ipv4_dst]))
                                )
                                experimental_data[pkt_ipv4_dst] = []

                            _log.info(
                                "ICMPv4 Scenario with ID {:s} is now active. "
                                "Implemented in {:f} seconds. "
                                "Global Path has length {:d}. "
                                "Local Path has length {:d}. "
                                "".format(
                                    str(global_path_search_id),
                                    time_taken,
                                    len(bidirectional_path) + service_activation_result["path_length"],
                                    len(bidirectional_path)
                                )
                            )

                            # Reinsert the ICMPv4 packet into the OpenFlow Pipeline, in order to properly process it.
                            def send_pkts(datapath_obj, p_in_port, global_path_search_id):
                                hub.sleep(0.1)
                                while packet_buffer[global_path_search_id]:
                                    pkt_data = packet_buffer[global_path_search_id].pop()
                                    datapath_obj.send_msg(
                                        datapath_obj.ofproto_parser.OFPPacketOut(
                                            datapath=datapath_obj,
                                            buffer_id=datapath_obj.ofproto.OFP_NO_BUFFER,
                                            in_port=p_in_port,
                                            actions=[
                                                datapath_obj.ofproto_parser.OFPActionOutput(
                                                    port=datapath_obj.ofproto.OFPP_TABLE,
                                                    max_len=len(pkt_data)
                                                ),
                                            ],
                                            data=pkt_data
                                        )
                                    )
                                globals.send_msg(datapath_obj.ofproto_parser.OFPBarrierRequest(datapath_obj),
                                                 reply_cls=datapath_obj.ofproto_parser.OFPBarrierReply)

                            hub.spawn(
                                send_pkts,
                                datapath_obj, p_in_port, global_path_search_id
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
                                "Forward Q-Value: {:f}; "
                                "Path Exploration: {:s}."
                                "".format(
                                    str(chosen_edge),
                                    old_q_value, new_q_value, -1, forward_q_value,
                                    "True" if path_exploration else "False"
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

                            if len(possible_links) == 0:
                                str_error = "Failed to activate Scenario with ID {:s}. " \
                                            "All possible links to adjacent sectors have been tried. " \
                                            "Cannot establish ICMPv4 communication to sector {:s}".format(
                                                str(global_path_search_id),
                                                str(target_sector_id)
                                            )
                                _log.error(
                                    str_error
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

            if globals.is_scenario_active(global_path_search_id):
                _log.warning(
                    "ICMPv4 scenario with ID {:s} is already implemented.".format(
                        str(global_path_search_id)
                    )
                )

            else:
                hub.spawn(
                    remote_host_icmpv4_task,
                    datapath_id,
                    pkt_in_port,
                    global_path_search_id,
                    tmp_task_token,
                    msg.datapath
                )

    else:
        # If the destination IP is in a different network, return ICMPv4 Network Unreachable
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
