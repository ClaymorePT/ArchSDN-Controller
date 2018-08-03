
import logging

from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn.engine import sector
from archsdn.engine import entities
from archsdn import database



_log = logging.getLogger(logger_module_name(__file__))


def process_event(port_change_event):
    from archsdn import p2p

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
    assert globals.default_configs, "engine not initialised"

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
    this_controller_id = database.get_database_info()['uuid']
    ipv4_services = globals.mapped_services["IPv4"]
    mpls_services = globals.mapped_services["MPLS"]

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

            # Removes all flows registered in this switch, registered at table PORT_SEGREGATION_TABLE
            #   and matching port_no.
            datapath_obj.send_msg(
                ofp_parser.OFPFlowMod(
                    datapath=datapath_obj,
                    table_id=globals.PORT_SEGREGATION_TABLE,
                    command=ofp.OFPFC_DELETE,
                    match=ofp_parser.OFPMatch(in_port=port_no)
                )
            )
            globals.send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        elif reason_num == 1:
            if port_no in switch.ports:
                if sector.is_port_connected(datapath_id, port_no):
                    # Kill services in the sector which use this port
                    connected_entity_id = sector.query_connected_entity_id(datapath_id, port_no)
                    local_scenarios_to_kill = []

                    for network_service in globals.mapped_services:
                        for service_type in globals.mapped_services[network_service]:
                            for service_key in tuple(globals.mapped_services[network_service][service_type]):
                                scenario = globals.mapped_services[network_service][service_type][service_key]

                                if scenario.uses_edge(datapath_id, connected_entity_id, port_no):
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

                    # Removes all flows at PORT_SEGREGATION_TABLE matching the removed port
                    datapath_obj.send_msg(
                        ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            table_id=globals.PORT_SEGREGATION_TABLE,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            command=ofp.OFPFC_DELETE,
                            match=ofp_parser.OFPMatch(in_port=port_no)
                        )
                    )
                    globals.send_msg(
                        ofp_parser.OFPBarrierRequest(datapath_obj),
                        reply_cls=ofp_parser.OFPBarrierReply
                    )

                    sector.disconnect_entities(datapath_id, connected_entity_id, port_no)

                switch.remove_port(port_no)
            else:
                _log.warning(
                    "Port {:d} not previously registered at Switch {:016X}.".format(
                        port_no, datapath_id
                    )
                )

        else:
            # For some reason, OpenVSwitch sends events about ports that have already been removed.
            if port_no in datapath_obj.ports and port_no in switch.ports:
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
                if old_state != new_state:  # If the port state has changed...
                    _log.warning(
                        "Port {:d} state at Switch {:016X} changed from {:s} to {:s}".format(
                            port_no, datapath_id, str(old_state), str(new_state)
                        )
                    )

                    if entities.Switch.PORT_STATE.OFPPS_LINK_DOWN in new_state:  # Port link state is Down...
                        if sector.is_port_connected(datapath_id, port_no):
                            # Kill services in the sector which use this port
                            connected_entity_id = sector.query_connected_entity_id(datapath_id, port_no)
                            local_scenarios_to_kill = []

                            for network_service in globals.mapped_services:
                                for service_type in globals.mapped_services[network_service]:
                                    for service_key in tuple(globals.mapped_services[network_service][service_type]):
                                        scenario = globals.mapped_services[network_service][service_type][service_key]

                                        if scenario.uses_edge(datapath_id, connected_entity_id, port_no):
                                            local_scenarios_to_kill.append(scenario)
                                            del globals.mapped_services[network_service][service_type][service_key]

                            _log.info(
                                "Local Scenarios to be destroyed: {:s}".format(
                                    str(tuple((id(i) for i in local_scenarios_to_kill)))
                                )
                            )

                            global_scenarios_to_kill = []
                            for scenario in local_scenarios_to_kill:
                                for global_path_search_id in globals.get_active_scenarios_keys():
                                    (local_scenarios_ids_list, _) = globals.get_active_scenario(global_path_search_id)
                                    if id(scenario) in local_scenarios_ids_list:
                                        global_scenarios_to_kill.append(global_path_search_id)

                            _log.info(
                                "Global Scenarios to be destroyed: {:s}".format(
                                    str(tuple((str(i) for i in global_scenarios_to_kill)))
                                )
                            )
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

                            # Removes all flows at PORT_SEGREGATION_TABLE matching the removed port
                            datapath_obj.send_msg(
                                ofp_parser.OFPFlowMod(
                                    datapath=datapath_obj,
                                    table_id=globals.PORT_SEGREGATION_TABLE,
                                    out_port=ofp.OFPP_ANY,
                                    out_group=ofp.OFPG_ANY,
                                    command=ofp.OFPFC_DELETE,
                                    match=ofp_parser.OFPMatch(in_port=port_no)
                                )
                            )
                            globals.send_msg(
                                ofp_parser.OFPBarrierRequest(datapath_obj),
                                reply_cls=ofp_parser.OFPBarrierReply
                            )

                            sector.disconnect_entities(datapath_id, connected_entity_id, port_no)

                    elif entities.Switch.PORT_STATE.OFPPS_LIVE in new_state:  # Port link state is Live...
                        # TODO: Do this.. maybe... This event could be used to try and reestablish previous lost
                        # scenarios.
                        pass

                    switch.ports[port_no]['state'] = new_state



    else:
        raise Exception("Reason with value {:d} is unknown to specification.".format(reason_num))


