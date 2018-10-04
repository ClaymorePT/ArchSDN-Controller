
import logging
from ipaddress import ip_address
import sys
import struct
from ctypes import c_uint64

from scapy.packet import Raw
from scapy.layers.l2 import Ether

from ryu.lib import hub
from netaddr import EUI

from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn.engine import globals
from archsdn import database
from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import services

_log = logging.getLogger(logger_module_name(__file__))


def process_event(dp_event):
    from archsdn import p2p
    assert globals.default_configs, "engine not initialised"

    datapath_obj = dp_event.dp
    datapath_id = dp_event.dp.id
    ofp_parser = datapath_obj.ofproto_parser
    ofp = datapath_obj.ofproto
    controller_uuid = database.get_database_info()["uuid"]
    central_policies_addresses = database.query_volatile_info()
    mac_service = central_policies_addresses["mac_service"]
    this_controller_id = database.get_database_info()['uuid']

    if dp_event.enter:  # If Switch is connecting...
        ipv4_info = None
        ipv6_info = None
        if ip_address(dp_event.dp.address[0]).version is 4:
            ipv4_info = (ip_address(dp_event.dp.address[0]), dp_event.dp.address[1])
        if ip_address(dp_event.dp.address[0]).version is 6:
            ipv6_info = (ip_address(dp_event.dp.address[0]), dp_event.dp.address[1])

        assert ipv4_info or ipv6_info, 'ipv4_info and ipv6_info are None at the same time'

        def __send_discovery_beacon():
            try:
                _log.info("Starting beacon for Switch {:016X}".format(datapath_id))

                while datapath_obj.is_active:
                    switch = sector.query_entity(datapath_id)
                    ports = switch.ports

                    def filter_port(port_no):
                        if not (0 < port_no <= ofp.OFPP_MAX):
                            return False
                        if ports[port_no]["state"] & ofp.OFPPS_LINK_DOWN:
                            return False
                        if sector.is_port_connected(datapath_id, port_no) and \
                            isinstance(
                                sector.query_entity(sector.query_connected_entity_id(datapath_id, port_no)),
                                (entities.Switch, entities.Host)
                            ):
                            return False
                        return True

                    for port_no in filter(filter_port, ports):
                        hash_val = c_uint64(hash((datapath_id, port_no))).value
                        if hash_val not in globals.beacons_hash_table:
                            globals.beacons_hash_table[hash_val] = (datapath_id, port_no)
                        beacon = Ether(
                            src=str(ports[port_no]["hw_addr"]),
                            dst="FF:FF:FF:FF:FF:FF",
                            type=0xAAAA
                        ) / Raw(
                            load=struct.pack(
                                "!H16s8s",
                                1, controller_uuid.bytes,
                                hash_val.to_bytes(8, byteorder='big')
                            )
                        )

                        _log.debug(
                            "Sending beacon through port {:d} ({:s}) of switch {:016X} with hash value {:X}".format(
                                port_no, ports[port_no]["name"], datapath_id, hash_val
                            )
                        )

                        datapath_obj.send_msg(
                            ofp_parser.OFPPacketOut(
                                datapath=datapath_obj,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=ofp.OFPP_CONTROLLER,
                                actions=[ofp_parser.OFPActionOutput(port=port_no)],
                                data=bytes(beacon)
                            )
                        )
                    hub.sleep(3)

                hash_vals = tuple(
                    filter(
                        (lambda index_key: globals.beacons_hash_table[index_key][0] == datapath_id),
                        globals.beacons_hash_table.keys()
                    )
                )
                for value in hash_vals:
                    del globals.beacons_hash_table[value]

                del globals.topology_beacons[datapath_id]
                _log.warning("Switch {:016X} is no longer active. Beacon manager is terminating.".format(datapath_id))

            except Exception:
                custom_logging_callback(_log, logging.ERROR, *sys.exc_info())

        assert not sector.is_entity_registered(datapath_id), \
            "Switch with ID {:d} is already registered.".format(datapath_id)

        switch = entities.Switch(
            id=datapath_id,
            control_ip=ipv4_info[0] if ipv4_info else ipv6_info[0] if ipv6_info else None,
            control_port=6631,
            of_version=dp_event.dp.ofproto.OFP_VERSION
        )
        for port in dp_event.ports:
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
        sector.register_entity(switch)
        database.register_datapath(datapath_id=datapath_id, ipv4_info=ipv4_info, ipv6_info=ipv6_info)

        services.init_switch_flows(datapath_obj)  # Initialise the switch with default flows.

        assert datapath_id not in globals.topology_beacons, \
            "A beacon was already active for switch {:016X}.".format(datapath_id)

        globals.topology_beacons[datapath_id] = hub.spawn(__send_discovery_beacon)
        _log.debug("Switch Connect Event: {:s}".format(str(dp_event.__dict__)))

    else:  # If Switch is disconnecting...
        assert sector.is_entity_registered(datapath_id), \
            "Trying to disconnect an unregistered Switch: {:016X}".format(datapath_id)

        # Kill services in the sector which use this Switch
        local_scenarios_to_kill = []

        for network_service in globals.mapped_services:
            for service_type in globals.mapped_services[network_service]:
                for service_key in tuple(globals.mapped_services[network_service][service_type]):
                    scenario = globals.mapped_services[network_service][service_type][service_key]

                    if scenario.has_entity(datapath_id):
                        local_scenarios_to_kill.append(scenario)
                        del globals.mapped_services[network_service][service_type][service_key]

        _log.debug(
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

        _log.debug(
            "Global Scenarios to be destroyed: {:s}".format(
                str(tuple((str(i) for i in global_scenarios_to_kill)))
            )
        )

        # Kill global services starting, ending or passing through this sector, which use this port
        for global_path_search_id in filter(globals.is_scenario_active, global_scenarios_to_kill):
            (_, adjacent_sectors_ids) = globals.get_active_scenario(global_path_search_id, True)

            for sector_id in adjacent_sectors_ids:

                sector_proxy = p2p.get_controller_proxy(sector_id)
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

        sector.remove_entity(datapath_id)
        database.remove_datapath(datapath_id)

        _log.info("Switch Disconnect Event: {:s}".format(str(dp_event.__dict__)))


