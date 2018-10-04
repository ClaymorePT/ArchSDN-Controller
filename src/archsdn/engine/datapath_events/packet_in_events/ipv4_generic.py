
import sys
import logging
from ipaddress import IPv4Address
import time
from random import sample

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


def process_ipv4_generic_packet(packet_in_event):  # Generic IPv4 service management
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
        "Received IP packet from host with MAC {:s}, Source IP {:s} to Destiny IP {:s}, "
        "on switch {:016X} at port {:d}".format(
            pkt.src, str(pkt_ipv4_src), str(pkt_ipv4_dst), datapath_id, pkt_in_port
        )
    )

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

        global_path_search_id = (  # The global identification for this service
            str(controller_uuid),
            pkt_ipv4_src,
            pkt_ipv4_dst,
            "IPv4"
        )

        # Create a task token which will represent this execution task in this controller
        tmp_task_token = globals.register_implementation_task(global_path_search_id, "IPv4", "*")

        # Initialize flag
        target_host_not_found_in_sector = False

        # Opens a unidirectional tunnel to target, using the same path in both directions.
        try:
            addr_info_dst = database.query_address_info(ipv4=pkt_ipv4_dst)
            target_switch_id = addr_info_dst["datapath"]
            target_switch_port = addr_info_dst["port"]
            host_a_entity_id = sector.query_connected_entity_id(datapath_id, pkt_in_port)
            host_b_entity_id = sector.query_connected_entity_id(target_switch_id, target_switch_port)
            start_time = time.time()

            # Construct a UniDirectional_path Path between Host A and Host B.
            unidirectional_path = sector.construct_unidirectional_path(
                host_a_entity_id,
                host_b_entity_id
            )

            # Activating the Generic IPv4 service between hosts in the same sector.
            local_service_scenario = services.ipv4_generic_flow_activation(
                unidirectional_path,
                globals.alloc_mpls_label_id() if len(unidirectional_path) >= 3 else None  # Allocate MPLS label
            )

            globals.set_active_scenario(
                global_path_search_id,
                (
                    (id(local_service_scenario),), tuple()
                )
            )

            _log.info(
                "IPv4 Generic Scenario with ID {:s} is now active. "
                "Implemented in {:f} seconds. "
                "Path has length {:d}. "
                "".format(
                    str(global_path_search_id),
                    time.time() - start_time,
                    len(unidirectional_path)
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
                    target_host_info = central.query_address_info(ipv4=target_ipv4)
                    host_a_entity_id = sector.query_connected_entity_id(dp_id, p_in_port)
                    target_sector_id = target_host_info.controller_id
                    adjacent_sectors_ids = sector.query_sectors_ids()

                    if not adjacent_sectors_ids:
                        raise PathNotFound("No adjacent sectors available.")

                    # Decide if a path should be explored or selected from previous q-values
                    path_exploration = globals.should_explore()

                    # The possible communication links to the adjacent sectors
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
                        # The possible communication links to the target sector
                        selected_link = None
                        unidirectional_path = None

                        # Sockets Cache
                        socket_cache = {}

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

                        possible_links.remove(selected_link)   # Remove the selected link from the choice list
                        chosen_edge = selected_link[0:2]       # Chosen edge to use
                        selected_sector_id = selected_link[3]  # Sector through which the scenario will proceed

                        _log.debug(
                            "Selected Link {:s}{:s}".format(
                                str(selected_link),
                                " from {}.".format(possible_links) if len(possible_links) else "."
                            )
                        )
                        try:
                            unidirectional_path = sector.construct_unidirectional_path(
                                host_a_entity_id,
                                selected_sector_id,
                                next_sector_hash=selected_link[2]
                            )

                        except PathNotFound:
                            if len(possible_links) == 0:
                                raise PathNotFound("All links to adjacent sectors have been tried.")
                            continue  # Go back to the beginning of the cycle and try again with the next available link

                        assert selected_link is not None, "selected_link cannot be None"
                        assert unidirectional_path is not None, "unidirectional_path cannot be None"

                        assert len(unidirectional_path), "unidirectional_path path length cannot be zero."
                        assert isinstance(selected_link, tuple), "selected_link expected to be tuple"
                        assert selected_sector_id is not None, "selected_sector_id cannot be None"

                        # Allocate MPLS label for tunnel (required when communicating with Sectors)
                        local_mpls_label = globals.alloc_mpls_label_id()
                        try:
                            if selected_sector_id not in socket_cache:
                                socket_cache[selected_sector_id] = p2p.get_controller_proxy(selected_sector_id)
                            selected_sector_proxy = socket_cache[selected_sector_id]

                            service_activation_result = selected_sector_proxy.activate_scenario(
                                {
                                    "global_path_search_id": global_path_search_id,
                                    "sector_requesting_service": str(controller_uuid),
                                    "mpls_label": local_mpls_label,
                                    "hash_val": globals.get_hash_val(*chosen_edge),
                                    "path_exploration": path_exploration,
                                }
                            )
                        except Exception as ex:
                            globals.free_mpls_label_id(local_mpls_label)
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

                            reward = unidirectional_path.remaining_bandwidth_average / kspl

                            old_q_value = globals.get_q_value(chosen_edge, pkt_ipv4_dst)
                            new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, reward)
                            globals.set_q_value(chosen_edge, pkt_ipv4_dst, new_q_value)

                            _log.info(
                                "\n"
                                "Selected Sector: {:s}\n"
                                "Chosen link: {:s}\n"
                                "Updated Q-Values:\n"
                                "  Old Q-Value: {:f}\n"
                                "  New Q-Value: {:f}\n"
                                "  Reward: {:f}\n"
                                "  Forward Q-Value: {:f}\n"
                                "  KSPL: {:d}\n"
                                "Path Exploration: {:s}"
                                "".format(
                                    str(selected_sector_id), str(chosen_edge),
                                    old_q_value, new_q_value, reward, forward_q_value, kspl,
                                    "True" if path_exploration else "False"
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
                                "\n"
                                "Selected Sector: {:s}\n"
                                "Chosen link: {:s}\n"
                                "Updated Q-Values:\n"
                                "  Old Q-Value: {:f}\n"
                                "  New Q-Value: {:f}\n"
                                "  Reward: {:f}\n"
                                "  Forward Q-Value: {:f}\n"
                                "Path exploration: {:s}"
                                "".format(
                                    str(selected_sector_id), str(chosen_edge),
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
                        tmp_task_token
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

