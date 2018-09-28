
import logging

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database

_log = logging.getLogger(logger_module_name(__file__))


def process_event(flow_removed_event):
    from archsdn import p2p

    msg = flow_removed_event.msg
    dp = msg.datapath
    ofp = dp.ofproto
    this_controller_id = database.get_database_info()['uuid']

    if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
        _log.info("Flow with Cookie ID {:d} has Timed Out".format(msg.cookie))
        local_scenarios_to_kill = []

        for network_service in globals.mapped_services:
            for service_type in globals.mapped_services[network_service]:
                for service_key in tuple(globals.mapped_services[network_service][service_type]):
                    scenario = globals.mapped_services[network_service][service_type][service_key]

                    if scenario.has_flow(msg.cookie):
                        local_scenarios_to_kill.append(scenario)
                        del globals.mapped_services[network_service][service_type][service_key]

        _log.info(
            "Local Scenarios to be destroyed: {:s}".format(
                str(tuple((str(i) for i in local_scenarios_to_kill)))
            )
        )

        global_scenarios_to_kill = []
        for scenario in local_scenarios_to_kill:
            for global_path_search_id in globals.get_active_scenarios_keys():
                (local_scenarios_ids_list, _) = globals.get_active_scenario(global_path_search_id)
                if id(scenario) in local_scenarios_ids_list:
                    global_scenarios_to_kill.append(global_path_search_id)

        # Kill global services starting, ending or passing through this sector, which use this port
        for global_path_search_id in filter(globals.is_scenario_active, global_scenarios_to_kill):
            (_, adjacent_sectors_ids) = globals.get_active_scenario(global_path_search_id, True)

            for sector_id in adjacent_sectors_ids:
                sector_proxy = p2p.get_controller_proxy(sector_id)
                _log.info(
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
                _log.info(
                    "Sector {:s} answer is: {:s}".format(
                        str(sector_id),
                        str(res)
                    )
                )

    else:
        _log.info("Unsupported flow removed reason value: {:d}".format(msg.reason))

