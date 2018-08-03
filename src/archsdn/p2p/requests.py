
import sys
import logging
from uuid import UUID

from archsdn import database
from archsdn.helpers import logger_module_name, custom_logging_callback


_log = logging.getLogger(logger_module_name(__file__))


def __query_address_info(*args, **kwargs):
    return database.query_address_info(*args, **kwargs)


def __activate_scenario(scenario_request):
    from archsdn import database
    from archsdn.engine import globals
    from archsdn.p2p.scenarios.generic_ipv4 import activate_generic_ipv4_scenario
    from archsdn.p2p.scenarios.icmpv4 import activate_icmpv4_scenario

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
    scenario_mpls_label = scenario_request['mpls_label']
    scenario_hash_val = scenario_request['hash_val']  # hash value which identifies the switch that sends the traffic

    assert isinstance(scenario_mpls_label, int) and scenario_mpls_label >= 0, \
        "scenario_mpls_label expected to be non negative  int"
    assert isinstance(scenario_hash_val, int) and scenario_hash_val >= 0, \
        "scenario_hash_val expected to be non negative int"

    source_controller_id = UUID(global_path_search_id[0])
    scenario_type = global_path_search_id[3]
    this_controller_id = database.get_database_info()['uuid']

    assert isinstance(scenario_type, str), "scenario_type expected to be str"

    if source_controller_id == this_controller_id:
        error_str = "Path search has reached the source controller. Cancelling..."
        _log.warning(error_str)
        return {"success": False, "reason": error_str}

    if globals.is_scenario_active(global_path_search_id):
        error_str = "Scenario with ID {:s} is already implemented.".format(str(global_path_search_id))
        _log.warning(error_str)
        return {"success": False, "reason": error_str}

    if scenario_type == 'ICMPv4': # Handling ICMPv4 Scenario Request
        return activate_icmpv4_scenario(scenario_request)

    elif scenario_type == 'IPv4':  # Handling IPv4 Generic Scenario Request
        return activate_generic_ipv4_scenario(scenario_request)

    else:
        error_str = "Failed to activate Scenario with ID {:s}. Invalid Scenario Type: {:s}" \
                    "".format(str(global_path_search_id), scenario_type)

        _log.error(error_str)
        return {
            "success": False,
            "reason": error_str,
        }


def __terminate_scenario(scenario_request):
    from archsdn.engine import globals
    from archsdn.p2p import get_controller_proxy

    assert isinstance(scenario_request, dict), \
        "scenario_request is expected to be of dict type. Got {:s}.".format(repr(scenario_request))
    missing_args = tuple(
        filter(
            (lambda arg: arg not in scenario_request.keys()),
            ('global_path_search_id', 'requesting_sector_id')
        )
    )

    if missing_args:
        raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

    global_path_search_id = scenario_request["global_path_search_id"]

    if not globals.is_scenario_active(global_path_search_id):
        return {
            "success": False,
            "reason": "Path with ID {:s} registration does not exist.".format(str(global_path_search_id))
        }

    try:
        this_controller_id = database.get_database_info()['uuid']
        requesting_sector_id = UUID(scenario_request["requesting_sector_id"])
        (local_scenarios_ids_list, adjacent_sectors_ids) = globals.get_active_scenario(global_path_search_id, True)
        local_scenarios_to_kill = []

        for network_service in globals.mapped_services:
            for service_type in globals.mapped_services[network_service]:
                for service_key in tuple(globals.mapped_services[network_service][service_type]):
                    scenario = globals.mapped_services[network_service][service_type][service_key]

                    if id(scenario) in local_scenarios_ids_list:
                        local_scenarios_to_kill.append(scenario)
                        del globals.mapped_services[network_service][service_type][service_key]

        _log.debug(
            "Local Scenarios to be destroyed: {:s}".format(
                str(tuple((id(i) for i in local_scenarios_to_kill)))
            )
        )

        for sector_id in set(adjacent_sectors_ids) - {requesting_sector_id}:
            sector_proxy = get_controller_proxy(sector_id)
            _log.debug(
                "Contacting Sector {:s} to destroy path {:s}...".format(
                    str(sector_id),
                    str(global_path_search_id)
                )
            )
            res = sector_proxy.terminate_scenario(
                {
                    "global_path_search_id": global_path_search_id,
                    "requesting_sector_id": str(this_controller_id)
                }
            )
            _log.debug(
                "Sector {:s} answer is: {:s}".format(
                    str(sector_id),
                    str(res)
                )
            )
        _log.warning(
            "Global scenario {:s} destroyed.".format(str(global_path_search_id))
        )
        return {"success": True, "global_path_search_id": global_path_search_id}

    except Exception as ex:
        error_str = "Failed to terminate scenario with ID {:s}. Reason {:s}.".format(
            str(global_path_search_id),
            str(type(ex))
        )
        _log.error(error_str)
        custom_logging_callback(_log, logging.DEBUG, *sys.exc_info())
        raise Exception(error_str)


server_requests = {
    "query_address_info": __query_address_info,
    "activate_scenario": __activate_scenario,
    "terminate_scenario": __terminate_scenario
}
