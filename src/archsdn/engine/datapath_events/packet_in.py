
import sys
import logging
from ipaddress import IPv4Address
import time

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS

from ryu.lib import hub
from netaddr import EUI

from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn.engine import globals
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import services
from archsdn import p2p_requests
from archsdn.engine.exceptions import PathNotFound

from archsdn.engine.datapath_events.packet_in_events.archsdn_L2 import process_archsdn_control
from archsdn.engine.datapath_events.packet_in_events.arp import process_arp
from archsdn.engine.datapath_events.packet_in_events.dhcp import process_dhcp_packet
from archsdn.engine.datapath_events.packet_in_events.dns import process_dns_packet
from archsdn.engine.datapath_events.packet_in_events.icmpv4 import process_icmpv4_packet

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
            process_dhcp_packet(packet_in_event)

        elif ip_layer.haslayer(ICMP):  # ICMPv4 services
            process_icmpv4_packet(packet_in_event)

        elif ip_layer.haslayer(DNS):
            process_dns_packet(packet_in_event)

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

