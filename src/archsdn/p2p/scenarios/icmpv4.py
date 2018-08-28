
import sys
import logging
from uuid import UUID
from ipaddress import IPv4Address
from random import sample

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
    scenario_hash_val = scenario_request['hash_val']  # hash value which identifies the switch that sends the traffic
    path_exploration = scenario_request['path_exploration']
    source_ipv4 = IPv4Address(global_path_search_id[1])
    target_ipv4_str = global_path_search_id[2]
    target_ipv4 = IPv4Address(global_path_search_id[2])
    target_host_info = central.query_address_info(ipv4=target_ipv4_str)
    this_controller_id = database.get_database_info()['uuid']
    source_controller = UUID(global_path_search_id[0])

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
            local_mpls_label = globals.alloc_mpls_label_id()

            local_service_scenario = services.icmpv4_flow_activation(
                bidirectional_path, scenario_mpls_label, local_mpls_label, source_ipv4=source_ipv4
            )
            # If it reached here, then it means the path was successfully activated.
            globals.set_active_scenario(
                global_path_search_id,
                ((id(local_service_scenario),), (sector_requesting_service_id,))
            )

            _log.info(
                "Local Scenario with Global ID {:s} and local length {:d} is now active.".format(
                    str(global_path_search_id),
                    len(bidirectional_path)
                )
            )

            active_task_token = None
            return {
                "success": True,
                "global_path_search_id": global_path_search_id,
                "q_value": 1,
                "path_length": len(bidirectional_path) - 1,
                "mpls_label": local_mpls_label,
            }

        else:
            # This IS NOT the target sector
            adjacent_sectors_ids = sector.query_sectors_ids()

            # Removing from the list of choices, the sector requesting the service
            adjacent_sectors_ids.remove(sector_requesting_service_id)

            # Remove source controller if present
            if source_controller in adjacent_sectors_ids:
                adjacent_sectors_ids.remove(source_controller)

            if len(adjacent_sectors_ids) == 0:
                return {"success": False, "reason": "No available sectors to explore."}

            possible_links = []
            for adjacent_sector in adjacent_sectors_ids:
                for edge in sector.query_edges_to_sector(adjacent_sector):
                    possible_links.append((edge[0], edge[1], edge[2], adjacent_sector))

            possible_links = sorted(
                possible_links, key=(lambda k: k[3] == target_host_info.controller_id), reverse=True
            )

            _log.debug(
                "Available Sector Links for exploration:  {:s}".format(
                    "\n  ".join(tuple((str(i) for i in possible_links)))
                )
            )

            while possible_links:
                # The possible communication links to the target sector
                selected_link = None
                bidirectional_path = None

                # Socket Cache
                socket_cache = {}

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
                    # Acquire a bidirectional path
                    bidirectional_path = sector.construct_bidirectional_path(
                        sector_requesting_service_id,
                        selected_sector_id,
                        allocated_bandwith=100,
                        previous_sector_hash=scenario_hash_val,
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
                    if selected_sector_id not in socket_cache:
                        socket_cache[selected_sector_id] = get_controller_proxy(selected_sector_id)
                    selected_sector_proxy = socket_cache[selected_sector_id]

                    service_activation_result = selected_sector_proxy.activate_scenario(
                        {
                            "global_path_search_id": global_path_search_id,
                            "sector_requesting_service": str(this_controller_id),
                            "mpls_label": local_mpls_label,
                            "hash_val": globals.get_hash_val(*chosen_edge),
                            "path_exploration": path_exploration,
                        }
                    )
                except Exception as ex:
                    globals.free_mpls_label_id(local_mpls_label)
                    _log.debug("Sector {:s} returned the following error: {:s}".format(
                        str(selected_sector_id), str(ex))
                    )
                    if len(possible_links) == 0:
                        raise PathNotFound("All links to adjacent sectors have been tried.")
                    continue  # Go back to the beginning of the cycle and try again with a new link

                forward_q_value = 0 if "q_value" not in service_activation_result \
                    else service_activation_result["q_value"]

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
                        bidirectional_path,
                        local_mpls_label, scenario_mpls_label, service_activation_result["mpls_label"]
                    )

                    globals.set_active_scenario(
                        global_path_search_id,
                        (
                            (id(local_service_scenario),),
                            (sector_requesting_service_id, selected_sector_id)
                        )
                    )

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
                        "Path Exploration: {:s}."
                        "".format(
                            str(selected_sector_id), str(chosen_edge),
                            old_q_value, new_q_value, reward, forward_q_value, kspl,
                            "True" if path_exploration else "False"
                        )
                    )

                    _log.info(
                        "Local Scenario with global ID {:s} with local length {:d} is now active.".format(
                            str(global_path_search_id),
                            len(bidirectional_path)
                        )
                    )
                    active_task_token = None
                    return {
                        "success": True,
                        "global_path_search_id": global_path_search_id,
                        "q_value": new_q_value,
                        "path_length": len(bidirectional_path) + service_activation_result["path_length"] - 1,
                        "mpls_label": local_mpls_label,
                    }

                else:
                    old_q_value = globals.get_q_value(chosen_edge, target_ipv4)
                    new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                    globals.set_q_value(chosen_edge, target_ipv4, new_q_value)

                    _log.info(
                        "\n"
                        "Selected Sector: {:s}\n"
                        "Chosen link: {:s}\n"
                        "Updated Q-Values:\n"
                        "  Old Q-Value: {:f}\n"
                        "  New Q-Value: {:f}\n"
                        "  Reward: {:f}\n"
                        "  Forward Q-Value: {:f}\n"
                        "Path Exploration: {:s}."
                        "".format(
                            str(selected_sector_id), str(chosen_edge),
                            old_q_value, new_q_value, -1, forward_q_value,
                            "True" if path_exploration else "False"
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
                        "All possible links to adjacent sectors have been tried." \
                        "".format(str(global_path_search_id))
            _log.error(error_str)
            active_task_token = None
            return {
                "success": False,
                "reason": error_str,
            }

    except globals.ImplementationTaskExists:
        active_task_token = None
        error_str = "Global task with ID {:s} is already being executed".format(str(global_path_search_id))
        _log.error(error_str)
        custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())
        return {"success": False, "reason": error_str}

    except PathNotFound:
        active_task_token = None
        error_str = "Failed to implement path to sector {:s}. " \
                    "An available path was not found in the network.".format(
                        str(target_host_info.controller_id)
                    )
        _log.error(error_str)
        custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())
        return {"success": False, "reason": error_str}

    except Exception as ex:
        active_task_token = None
        error_str = "Failed to implement path to host {:s} at sector {:s}. Reason {:s}.".format(
            target_host_info.name,
            str(target_host_info.controller_id),
            str(type(ex))
        )
        _log.error(error_str)
        custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())
        return {"success": False, "reason": error_str}


