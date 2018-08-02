
import sys
import logging

from uuid import UUID
from ipaddress import IPv4Address

from archsdn.helpers import logger_module_name, custom_logging_callback


_log = logging.getLogger(logger_module_name(__file__))


def activate_icmpv4_scenario(scenario_request):
    from archsdn import central
    from archsdn import database
    from archsdn.engine import sector
    from archsdn.engine import globals
    from archsdn.engine import services
    from archsdn.p2p import get_controller_proxy
    from archsdn.engine.exceptions import PathNotFound
    from archsdn.engine.entities import Sector

    assert isinstance(scenario_request, dict), \
        "scenario_request is expected to be of dict type. Got {:s}.".format(repr(scenario_request))
    missing_args = tuple(
        filter(
            (lambda arg: arg not in scenario_request.keys()),
            ('global_path_search_id', 'mpls_label', 'sector_requesting_service', 'hash_val')
        )
    )
    if missing_args:
        raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

    global_path_search_id = scenario_request['global_path_search_id']
    sector_requesting_service_id = UUID(scenario_request['sector_requesting_service'])
    scenario_mpls_label = scenario_request['mpls_label']
    scenario_hash_val = scenario_request['hash_val'] # hash value which identifies the switch that sends the traffic
    source_ipv4_str = global_path_search_id[1]
    target_ipv4_str = global_path_search_id[2]
    target_ipv4 = IPv4Address(global_path_search_id[2])
    target_host_info = central.query_address_info(ipv4=target_ipv4_str)
    this_controller_id = database.get_database_info()['uuid']

    try:
        # Maintain an active token during the duration of this task. When the task is terminated, the token will
        #   be removed.
        active_task_token = globals.register_implementation_task(global_path_search_id, "IPv4", "ICMP")

        if target_host_info.controller_id == this_controller_id:
            # This IS the target sector

            # Trying to activate the local path, to finish the global path.
            bidirectional_path = sector.construct_bidirectional_path(
                sector_requesting_service_id,  # Sector from which the scenario request came
                target_host_info.name,  # Target Hostname which identifies the host entity in this sector.
                allocated_bandwith=100,  # Requested bandwidth for ICMP path
                previous_sector_hash=scenario_hash_val  # hash value which identifies the switch that sends the traffic
            )
            # Implementation notes:
            #  'scenario_hash_val' is necessary for the sector controller. In the use-case where multiple switches
            #   are connected to the same sector, the controller from that sector uses the 'scenario_hash_val' to
            #   distinguish between switches. The 'scenario_hash_val' is sent in each discovery beacon, and stored
            #   by the controller which receives them.

            assert len(bidirectional_path), "bidirectional_path path length cannot be zero."

            # Allocate MPLS label for tunnel
            if len(bidirectional_path) >= 3:
                local_mpls_label = globals.alloc_mpls_label_id()
            else:
                local_mpls_label = None

            local_service_scenario = services.icmpv4_flow_activation(
                bidirectional_path, local_mpls_label, scenario_mpls_label, source_ipv4=source_ipv4_str
            )
            # If it reached here, then it means the path was successfully activated.
            globals.set_active_scenario(
                global_path_search_id,
                ((id(local_service_scenario),), (sector_requesting_service_id,))
            )

            _log.debug(
                "Local Scenario with Global ID {:s} and local length {:d} is now active.".format(
                    str(global_path_search_id),
                    len(bidirectional_path)
                )
            )

            return {
                "success": True,
                "global_path_search_id": global_path_search_id,
                "q_value": 1,
                "path_length": len(bidirectional_path) - 1
            }

        else:
            # This IS NOT the target sector
            adjacent_sectors_ids = sector.query_sectors_ids()

            adjacent_sectors_ids.remove(sector_requesting_service_id)

            if len(adjacent_sectors_ids) == 0:
                return {"success": False, "reason": "No available sectors to explore."}

            if target_host_info.controller_id in adjacent_sectors_ids:
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
                    possible_links.remove(selected_link)
                    try:
                        # If the target sector IS adjacent to this sector, contact it directly and establish path
                        bidirectional_path = sector.construct_bidirectional_path(
                            sector_requesting_service_id,
                            target_host_info.controller_id,
                            allocated_bandwith=100,
                            previous_sector_hash=scenario_hash_val,
                            next_sector_hash=selected_link[2]
                        )
                        break

                    except PathNotFound:
                        if len(possible_links) == 0:
                            raise
                        continue

                assert len(bidirectional_path), "bidirectional_path path length cannot be zero."
                assert isinstance(selected_link, tuple), "selected_link expected to be tuple"

                # Allocate MPLS label for tunnel (required when communicating with Sectors)
                local_mpls_label = globals.alloc_mpls_label_id()
                chosen_edge = (selected_link[0], selected_link[1])
                selected_sector_proxy = get_controller_proxy(target_host_info.controller_id)
                try:
                    service_activation_result = selected_sector_proxy.activate_scenario(
                        {
                            "global_path_search_id": global_path_search_id,
                            "sector_requesting_service": str(this_controller_id),
                            "mpls_label": local_mpls_label,
                            "hash_val": globals.get_hash_val(*chosen_edge),
                        }
                    )
                except Exception as ex:
                    service_activation_result = {"success": False, "reason": str(ex)}

                forward_q_value = 0 if "q_value" not in service_activation_result else service_activation_result[
                    "q_value"]

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

                    local_service_scenario = services.sector_to_sector_mpls_flow_activation(
                        bidirectional_path, local_mpls_label, scenario_mpls_label
                    )

                    globals.set_active_scenario(
                        global_path_search_id,
                        (
                            (id(local_service_scenario),),
                            (sector_requesting_service_id, target_host_info.controller_id)
                        )
                    )

                    _log.info(
                        "Adjacent Sector: {:s}; "
                        "Chosen link: {:s}; "
                        "Updated Q-Values -> "
                        "Old Q-Value: {:f}; "
                        "New Q-Value: {:f}; "
                        "Reward: {:f}; "
                        "Forward Q-Value: {:f};"
                        "KSPL: {:d};"
                        "".format(
                            str(target_host_info.controller_id), str(chosen_edge),
                            old_q_value, new_q_value, reward, forward_q_value, kspl
                        )
                    )

                    _log.debug(
                        "Local Scenario with Global ID {:s} with local length {:d} is now active.".format(
                            str(global_path_search_id),
                            len(bidirectional_path)
                        )
                    )

                    return {
                        "success": True,
                        "global_path_search_id": global_path_search_id,
                        "q_value": new_q_value,
                        "path_length": len(bidirectional_path) + service_activation_result["path_length"] - 1
                    }
                else:
                    old_q_value = globals.get_q_value(target_host_info.controller_id, target_ipv4)
                    new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                    globals.set_q_value(target_host_info.controller_id, target_ipv4, new_q_value)

                    _log.info(
                        "Adjacent Sector: {:s}; "
                        "Chosen link: {:s}; "
                        "Updated Q-Values -> "
                        "Old Q-Value: {:f}; "
                        "New Q-Value: {:f}; "
                        "Reward: {:f}; "
                        "Forward Q-Value: {:f}.".format(
                            str(target_host_info.controller_id), str(chosen_edge),
                            old_q_value, new_q_value, -1, forward_q_value
                        )
                    )
                    _log.debug(
                        "Failed to activate Scenario with ID {:s} through sector {:s}. Reason: {:s}."
                        "".format(
                            str(target_host_info.controller_id),
                            str(global_path_search_id),
                            service_activation_result["reason"]
                        ),
                    )

                    return {
                        "success": False,
                        "reason": "No available sectors to explore.",
                    }

            else:

                _log.debug("Available adjacent sectors for exploration: {}".format(adjacent_sectors_ids))
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
                        # Acquire a bidirectional path
                        bidirectional_path = sector.construct_bidirectional_path(
                            sector_requesting_service_id,
                            selected_sector_id,
                            allocated_bandwith=100,
                            previous_sector_hash=scenario_hash_val,
                            next_sector_hash=selected_link[2]
                        )
                    except PathNotFound:
                        continue

                    assert len(bidirectional_path), "bidirectional_path path length cannot be zero."
                    assert isinstance(selected_link, tuple), "selected_link expected to be tuple"
                    assert selected_sector_id is not None, "selected_sector_id cannot be None"

                    # Allocate MPLS label for tunnel (required when communicating with Sectors)
                    local_mpls_label = globals.alloc_mpls_label_id()
                    try:
                        selected_sector_proxy = get_controller_proxy(selected_sector_id)
                        service_activation_result = selected_sector_proxy.activate_scenario(
                            {
                                "global_path_search_id": global_path_search_id,
                                "sector_requesting_service": str(this_controller_id),
                                "mpls_label": local_mpls_label,
                                "hash_val": globals.get_hash_val(*chosen_edge),
                            }
                        )
                    except Exception as ex:
                        service_activation_result = {"success": False, "reason": str(ex)}

                    forward_q_value = 0 if "q_value" not in service_activation_result else service_activation_result["q_value"]

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

                        entity_a_obj = sector.query_entity(bidirectional_path.entity_a)
                        entity_b_obj = sector.query_entity(bidirectional_path.entity_b)

                        if isinstance(entity_a_obj, Sector) and isinstance(entity_b_obj, Sector):
                            local_service_scenario = services.sector_to_sector_mpls_flow_activation(
                                bidirectional_path, local_mpls_label, scenario_mpls_label
                            )
                        else:
                            local_service_scenario = services.icmpv4_flow_activation(
                                bidirectional_path, local_mpls_label, scenario_mpls_label
                            )

                        globals.set_active_scenario(
                            global_path_search_id,
                            (
                                (id(local_service_scenario),),
                                (sector_requesting_service_id, selected_sector_id)
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
                                str(selected_sector_id), str(chosen_edge),
                                old_q_value, new_q_value, reward, forward_q_value, kspl
                            )
                        )

                        _log.debug(
                            "Local Scenario with global ID {:s} with local length {:d} is now active.".format(
                                str(global_path_search_id),
                                len(bidirectional_path)
                            )
                        )
                        return {
                            "success": True,
                            "global_path_search_id": global_path_search_id,
                            "q_value": new_q_value,
                            "path_length": len(bidirectional_path) + service_activation_result["path_length"] - 1
                        }

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
                                str(selected_sector_id), str(chosen_edge),
                                old_q_value, new_q_value, -1, forward_q_value
                            )
                        )

                        _log.error(
                            "Failed to activate Scenario with Global ID {:s} through Sector {:s}. Reason {:s}.".format(
                                str(global_path_search_id),
                                str(selected_sector_id),
                                service_activation_result["reason"]
                            )
                        )

                error_str = "Failed to activate Scenario with ID {:s}. " \
                            "All possible links to adjacent sectors have been tried.".format(
                                str(global_path_search_id),
                            )
                _log.error(error_str)
                return {
                    "success": False,
                    "reason": error_str,
                }

    except globals.ImplementationTaskExists:
        error_str = "Global task with ID {:s} is already being executed".format(str(global_path_search_id))
        _log.error(error_str)
        custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
        return {"success": False, "reason": error_str}

    except PathNotFound:
        error_str = "Failed to implement path to sector {:s}. " \
                    "An available path was not found in the network.".format(
                        str(target_host_info.controller_id)
                    )
        _log.error(error_str)
        custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
        return {"success": False, "reason": error_str}

    except Exception as ex:
        error_str = "Failed to implement path to host {:s} at sector {:s}. Reason {:s}.".format(
            target_host_info.name,
            str(target_host_info.controller_id),
            str(type(ex))
        )
        _log.error(error_str)
        custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
        return {"success": False, "reason": error_str}


