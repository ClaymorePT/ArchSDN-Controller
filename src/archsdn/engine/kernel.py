import logging
from ipaddress import ip_address
import sys
import struct
from functools import partial

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from ryu.lib import hub
from netaddr import EUI

from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import entities


_log = logging.getLogger(logger_module_name(__file__))
__default_configs = None
__implemented_flows = {}  # __implemented_flows[datapath_id][cookie_id] = [FlowMod]
__datapath_beacons = {}  # __datapath_beacons[datapath_id] = Beacon_Task

__recycled_cookie_ids = []
__cookie_id_counter = 0


def __alloc_cookieID():
    global __cookie_id_counter

    if __cookie_id_counter == 0xFFFFFFFFFFFFFFFF:
        raise ValueError("No more cookies left...")
    if len(__recycled_cookie_ids):
        return __recycled_cookie_ids.pop()
    __cookie_id_counter = __cookie_id_counter + 1
    return __cookie_id_counter

def __free_cookieID(cookie_id):
    global __cookie_id_counter
    if cookie_id <= 0:
        raise ValueError("Cookies cannot be zero or negative.")
    if cookie_id > __cookie_id_counter:
        raise ValueError("That cookie was not allocated.")
    if cookie_id in __recycled_cookie_ids:
        raise ValueError("Cookie already free.")
    __recycled_cookie_ids.append(cookie_id)

    while len(__recycled_cookie_ids) > 0:
        max_value = max(__recycled_cookie_ids)
        if __cookie_id_counter == max_value:
            __recycled_cookie_ids.remove(max_value)
            __cookie_id_counter = __cookie_id_counter - 1
        else:
            break




def __send_msg(*args, **kwargs):
    return __default_configs["send_msg"](*args, **kwargs)


def __get_datapath(*args, **kwargs):
    return __default_configs["get_datapath"](*args, **kwargs)


def initialise(default_configs):
    global __default_configs, __implemented_flows, __datapath_beacons
    global __cookie_id_counter, __recycled_cookie_ids
    sector.initialise()

    __default_configs = default_configs
    __implemented_flows = {}
    __datapath_beacons = {}

    __recycled_cookie_ids = []
    __cookie_id_counter = 0




def process_datapath_event(dp_event):
    assert __default_configs, "engine not initialised"

    _log.info("Datapath Event: {:s}".format(str(dp_event.__dict__)))

    datapath_obj = dp_event.dp
    datapath_id = dp_event.dp.id
    ofp_parser = datapath_obj.ofproto_parser
    ofp = datapath_obj.ofproto
    controller_uuid = database.get_database_info()["uuid"]
    central_policies_addresses = database.query_volatile_info()
    # {
    #     'ipv4_network': IPv4Network(_ipv4_network),
    #     'ipv6_network': IPv6Network(_ipv6_network),
    #     'ipv4_service': IPv4Address(_ipv4_service),
    #     'ipv6_service': IPv6Address(_ipv6_service),
    #     : EUI(_mac_service),
    # }

    if dp_event.enter:
        ipv4_info = None
        ipv6_info = None
        if ip_address(dp_event.dp.address[0]).version is 4:
            ipv4_info = (ip_address(dp_event.dp.address[0]), dp_event.dp.address[1])
        if ip_address(dp_event.dp.address[0]).version is 6:
            ipv6_info = (ip_address(dp_event.dp.address[0]), dp_event.dp.address[1])

        assert ipv4_info or ipv6_info, 'ipv4_info and ipv6_info are None at the same time'

        def __send_discovery_beacon():
            try:
                ports = datapath_obj.ports
                _log.info("Starting beacon for Switch {:016X}".format(datapath_id))

                while datapath_obj.is_active:
                    for port_no in ports:
                        if not (ports[port_no].state & ofp.OFPPS_LINK_DOWN) and \
                                (
                                    (
                                        sector.is_port_connected(datapath_id, port_no) and
                                        isinstance(
                                            sector.query_connected_entity_id(datapath_id, port_no),
                                            entities.Sector
                                        )
                                    ) or
                                    (
                                        not sector.is_port_connected(datapath_id, port_no)
                                    )
                                ):
                            beacon = Ether(
                                src=str(central_policies_addresses['mac_service']),
                                dst="FF:FF:FF:FF:FF:FF",
                                type=0xAAAA
                            ) / Raw(
                                load=struct.pack("!H16sQH", 1, controller_uuid.bytes, datapath_id, port_no)
                            )

                            _log.debug(
                                "Sending beacon through port {:d} of switch {:016X}".format(port_no, datapath_id)
                            )

                            datapath_obj.send_msg(
                                ofp_parser.OFPPacketOut(
                                    datapath=datapath_obj,
                                    buffer_id=ofp.OFP_NO_BUFFER,
                                    in_port=port_no,
                                    actions=[ofp_parser.OFPActionOutput(port=port_no)],
                                    data=bytes(beacon)
                                )
                            )
                    hub.sleep(3)

                _log.warning("Switch {:016X} is no longer active. Beacon manager is terminating.".format(datapath_id))

            except Exception:
                custom_logging_callback(_log, logging.ERROR, *sys.exc_info())

        if sector.is_entity_registered(datapath_id):
            sector.remove_entity(datapath_id)

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

        __implemented_flows[datapath_id] = {}

        #
        # Reset Switch state and initialize bootstrap sequence
        #
        # When a switch connects, it is complex to know in which state it is.
        # So, it is preferable to clear all flows (if there are any) and restart everything.
        # Instructions order for proper reset of a switch
        #  1 -> Disable all ports, except for the control
        #  2 -> Clear all flow tables, group table and meter table

        # Stage 1 -> Disable all switching ports
        for port in dp_event.ports:
            datapath_obj.send_msg(
                ofp_parser.OFPPortMod(
                    datapath=datapath_obj,
                    port_no=port.port_no,
                    hw_addr=port.hw_addr,
                    config=ofp.OFPPC_PORT_DOWN,
                    mask=ofp.OFPPC_PORT_DOWN,
                    advertise=0
                )
            )
        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        datapath_obj.send_msg(  # Removes all flows registered in this switch.
            ofp_parser.OFPFlowMod(
                datapath=datapath_obj,
                cookie=0,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
                table_id=ofp.OFPTT_ALL,
                command=ofp.OFPFC_DELETE,
                idle_timeout=0,
                hard_timeout=0,
                priority=ofp.OFP_DEFAULT_PRIORITY,
                buffer_id=ofp.OFP_NO_BUFFER,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                match=None,
                instructions=None
            )
        )

        # OVS 2.1 and Zodiac FX do not support group mods
        # datapath.send_msg(  # Removes all groups registered in this switch.
        #     ofp_parser.OFPGroupMod(
        #         datapath=datapath,
        #         command=ofp.OFPGC_DELETE,
        #         group_id=ofp.OFPG_ALL,
        #     )
        # )

        datapath_obj.send_msg(  # Removes all meters registered in this switch.
            ofp_parser.OFPMeterMod(
                datapath=datapath_obj,
                command=ofp.OFPMC_DELETE,
                meter_id=ofp.OFPM_ALL,
            )
        )
        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        for port in dp_event.ports:
            __implemented_flows[datapath_id][port.port_no] = []

        for port in dp_event.ports:
            if not (port.state & ofp.OFPPS_LINK_DOWN):
                match = ofp_parser.OFPMatch(
                    in_port=port.port_no, eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0800,
                    ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17,
                    udp_src=68, udp_dst=67
                )
                actions = [ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                boot_dhcp = ofp_parser.OFPFlowMod(
                    datapath=datapath_obj,
                    cookie=__alloc_cookieID(),
                    cookie_mask=0,
                    table_id=0,
                    command=ofp.OFPFC_ADD,
                    idle_timeout=0,
                    hard_timeout=0,
                    priority=ofp.OFP_DEFAULT_PRIORITY,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                    match=match,
                    instructions=inst
                )

                datapath_obj.send_msg(boot_dhcp)
                __implemented_flows[datapath_id][port.port_no].append(boot_dhcp)


                match = ofp_parser.OFPMatch(in_port=port.port_no, eth_type=0xAAAA)
                actions = [ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

                archsdn_beacon = ofp_parser.OFPFlowMod(
                    datapath=datapath_obj,
                    cookie=__alloc_cookieID(),
                    cookie_mask=0,
                    table_id=0,
                    command=ofp.OFPFC_ADD,
                    idle_timeout=0,
                    hard_timeout=0,
                    priority=ofp.OFP_DEFAULT_PRIORITY,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                    match=match,
                    instructions=inst
                )

                datapath_obj.send_msg(archsdn_beacon)
                __implemented_flows[datapath_id][port.port_no].append(archsdn_beacon)

        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        for port in dp_event.ports:
            datapath_obj.send_msg(
                ofp_parser.OFPPortMod(
                    datapath=datapath_obj,
                    port_no=port.port_no,
                    hw_addr=port.hw_addr,
                    config=0,
                    mask=ofp.OFPPC_PORT_DOWN,
                    advertise=0
                )
            )
        __send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

        if datapath_id in __datapath_beacons:
            _log.warning("A beacon was already active for switch {:016X}. Canceling.".format(datapath_id))
            __datapath_beacons[datapath_id].cancel()
        __datapath_beacons[datapath_id] = hub.spawn(__send_discovery_beacon)
        _log.info("Switch Connect Event: {:s}".format(str(dp_event.__dict__)))

    else:
        if sector.is_entity_registered(datapath_id):
            ## Query scenarios which use this switch and initiate process establish new paths.
            if datapath_id in __datapath_beacons:
                __datapath_beacons[datapath_id].cancel()

            sector.remove_entity(datapath_id)
            database.remove_datapath(datapath_id)
            for port_no in __implemented_flows[datapath_id]:
                for flow in __implemented_flows[datapath_id][port_no]:
                    __free_cookieID(flow.cookie)
            del __implemented_flows[datapath_id]

            _log.info("Switch Disconnect Event: {:s}".format(str(dp_event.__dict__)))
        else:
            _log.warning("Trying to disconnect an unregistered Switch: {:016X}".format(datapath_id))

'''
{
    'dp': <ryu.controller.controller.Datapath object at 0x7f6985d4c518>, 
    'enter': True, 
    'ports': [
        OFPPort(port_no=1,hw_addr='e0:d4:e8:6b:4d:f8',name=b'eth0',config=0,state=4,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        OFPPort(port_no=2,hw_addr='82:2b:18:66:18:f4',name=b'eth1',config=0,state=1,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        OFPPort(port_no=3,hw_addr='f6:f2:fa:cc:1e:50',name=b'eth2',config=0,state=1,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0)
    ]
}
'''

'''
'dp': <ryu.controller.controller.Datapath object at 0x7f6985d4c518>

{
    'ofproto': <module 'ryu.ofproto.ofproto_v1_3' from '/home/carlosmf/PythonVirtEnv/controller_testing/lib/python3.6/site-packages/ryu/ofproto/ofproto_v1_3.py'>, 
    'ofproto_parser': <module 'ryu.ofproto.ofproto_v1_3_parser' from '/home/carlosmf/PythonVirtEnv/controller_testing/lib/python3.6/site-packages/ryu/ofproto/ofproto_v1_3_parser.py'>, 
    'socket': <eventlet.greenio.base.GreenSocket object at 0x7f714ce6c898>, 
    'address': ('192.168.100.103', 54921), 
    'is_active': True, 
    'send_q': <LightQueue at 0x7f714ce6ce80 maxsize=16 getters[1]>, 
    '_send_q_sem': <BoundedSemaphore at 0x7f714ce6ceb8 c=16 _w[0]>, 
    'echo_request_interval': 1.0, 
    'max_unreplied_echo_requests': 1, 
    'unreplied_echo_requests': [], 
    'xid': 2730934407, 
    'id': 123917682137323, 
    '_ports': None, 
    'flow_format': 0, 
    'ofp_brick': <ryu.controller.ofp_handler.OFPHandler object at 0x7f714d0f2f28>, 
    'state': 'main', 
    'ports': {
        1: OFPPort(port_no=1,hw_addr='42:f9:83:fe:12:b4',name=b'eth0',config=0,state=4,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        2: OFPPort(port_no=2,hw_addr='07:38:77:2c:8e:50',name=b'eth1',config=0,state=1,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0), 
        3: OFPPort(port_no=3,hw_addr='e9:c6:d3:73:3c:d9',name=b'eth2',config=0,state=4,curr=2056,advertised=0,supported=0,peer=0,curr_speed=0,max_speed=0)
    }
}
'''


def process_port_change_event(port_change_event):
    assert __default_configs, "engine not initialised"

    # {'datapath': <ryu.controller.controller.Datapath object at 0x7fb5da0fe2e8>, 'reason': 2, 'port_no': 1}

    _log.info("Port Change Event: {}".format(str(port_change_event.__dict__)))


    ofp_port_reason = {
        0: "The port was added",
        1: "The port was removed",
        2: "Some attribute of the port has changed"
    }

    if port_change_event.reason in ofp_port_reason:
        _log.info(
            "Port Status Event at Switch {:016X} Port {:d} Reason: {:s}".format(
                port_change_event.datapath.id,
                port_change_event.port_no,
                ofp_port_reason[port_change_event.reason]
            )
        )
    else:
        raise Exception("Reason with value {:d} is unknown to specification.".format(port_change_event.reason))


def process_packet_in_event(packet_in_event):
    assert __default_configs, "engine not initialised"

    # Identify and characterise packet (deep packet inspection to detect service or request)
    # Identify origin (in_port, mac source, IP source)


    _log.info("Packet In Event: {}".format(str(packet_in_event.__dict__)))
    #
    # if not this_controller_uuid:
    #     this_controller_uuid = database.GetDatabaseInfo()["uuid"]
    #
    # ofp_parser = msg.datapath.ofproto_parser
    # ofp = msg.datapath.ofproto
    # this_datapath_id = msg.datapath.id
    # in_port = None
    # in_port_mac = None
    #
    # volatile_information = database.QueryVolatileInfo()
    # ipv4_network = volatile_information["ipv4_network"]
    # ipv4_service_str = str(volatile_information["ipv4_service"])
    # mac_service = volatile_information["mac_service"]
    #
    # if msg.match:
    #     for match_field in msg.match.fields:
    #         if type(match_field) is ofp_parser.MTInPort:
    #             in_port = match_field.value
    #             in_port_mac = msg.datapath.ports[in_port].hw_addr
    #
    #
    # pkt = Ether(msg.data)
    # _log.debug("-"*150)
    # _log.debug(
    #     "Packet-In at {:s} from {:d}, port {:d} with type 0x{:04x}".format(
    #         time.ctime(timestamp), msg.datapath.id, in_port, pkt.type
    #     )
    # )
    # #_log.debug("\n".join(("{}:{}".format(key, msg.datapath.__dict__['ports'][key]) for key in msg.datapath.__dict__['ports'])))
    # # _log.info("Ethernet Packet - Source: {:s}; Destiny: {:s}; EtherType: 0x{:04x}".format(
    # #     pkt.src, pkt.dst, pkt.type)
    # # )
    #
    # layer_num = 0
    # if pkt.type == 0xBBBB:  ###  ArchSDN Hello Packet : Ether Type -> 0xAAAA
    #     layer_num += 1
    #     archsdn_layer = memoryview(pkt.getlayer(layer_num).fields['load'])
    #     if len(archsdn_layer) < 2:
    #         _log.warning(
    #             "ArchSDN Beacon Ignored. Payload length is lower than 2.".format(len(archsdn_layer))
    #         )
    #         return
    #
    #     (msg_type,) = struct.unpack("!H", archsdn_layer[0:2])
    #     msg_payload = archsdn_layer[2:]
    #
    #     if msg_type == 1:
    #         if (len(msg_payload) < 24):
    #             _log.warning(
    #                 "ArchSDN Beacon Ignored. It has invalid size: it's {:d} when it should be at least 24".format(
    #                     len(msg_payload)
    #                 )
    #             )
    #             return
    #
    #         (sender_controller_uuid_bytes, sender_datapath_id, port_out) = struct.unpack("!16sQH", msg_payload[0:26])
    #         sender_controller_uuid = uuid.UUID(bytes=sender_controller_uuid_bytes)
    #
    #         _log.debug(
    #             "{:s}Received Beacon Packet from Controller {:s} using Switch {:d}".format(
    #                 " "*layer_num*2, str(sender_controller_uuid), sender_datapath_id
    #             )
    #         )
    #
    #         if this_controller_uuid != sender_controller_uuid:
    #             if not cluster_network.isConnected2Sector(this_datapath_id, in_port, sender_controller_uuid):
    #                 cluster_network.RegisterSector(this_datapath_id, in_port, sender_controller_uuid, port_out)
    #             # Don't remove flow in this port, because it may be connected to a switch and other controllers
    #             #   might send their beacons at a later time.
    #         else:
    #             if not cluster_network.isSwitchConnected2Switch(sender_datapath_id, this_datapath_id, in_port):
    #                 cluster_network.ConnectToSwitch(this_datapath_id, sender_datapath_id, in_port)
    #             if not cluster_network.isSwitchConnected2Switch(this_datapath_id, sender_datapath_id, port_out):
    #                 cluster_network.ConnectToSwitch(sender_datapath_id, this_datapath_id, port_out)
    #     else:
    #         _log.warning("Ignored ArchSDN Message (Unknown type: {:d})".format(msg_type))
    #
    # elif pkt.haslayer(DHCP):  # https://tools.ietf.org/rfc/rfc2132.txt
    #     layer_num += 1
    #     ipv4_layer = pkt[IP]
    #     bootp_layer = pkt[BOOTP]
    #     dhcp_layer = pkt[DHCP]
    #
    #     dhcp_layer_options = dict(filter((lambda x: len(x) == 2), dhcp_layer.options))
    #     if 'message-type' in dhcp_layer_options:
    #         if dhcp_layer_options['message-type'] is 1:  # A DHCP DISCOVER packet was received
    #             central_proxy = get_central_proxy()
    #             try:
    #                 _log.debug(
    #                     "{:s}Received DHCP Discover packet from host with MAC {:s} on Switch {:d} at port {:d}".format(
    #                         " " * layer_num * 2, pkt.src, this_datapath_id, in_port
    #                     )
    #                 )
    #
    #                 client_id = database.Query_Client_ID(this_datapath_id, in_port, EUI(pkt.src))
    #                 client_info = database.Query_Client_Info(client_id)  # Lets try to check if the host is registered
    #                 hostname = central_proxy.QueryClientInfo(location=(this_controller_uuid, client_id))["name"]
    #
    #             # Exception is raised if host is not registered at the controller database
    #             except database.Exceptions.Client_Not_Registered:
    #                 # Controller registers a new host at the local database, then at the Central and updates the
    #                 #   local host registration with the IPs supplied by Central.
    #
    #                 client_id = database.Register_Client(this_datapath_id, in_port, EUI(pkt.src))
    #                 (client_ipv4, client_ipv6, hostname) = central_proxy.RegisterClient(
    #                     controller_uuid=this_controller_uuid, client_id=client_id
    #                 )
    #                 database.Update_Client_Addresses(client_id=client_id, ipv4=client_ipv4, ipv6=client_ipv6)
    #                 client_info = database.Query_Client_Info(client_id)
    #
    #             client_ipv4 = client_info["ipv4"]
    #             client_ipv6 = client_info["ipv6"]
    #
    #             # A DHCP Offer packet is tailored specifically for the new host.
    #             dhcp_offer = Ether(src=str(mac_service), dst=pkt.src) \
    #                         /IP(src=ipv4_service_str, dst="255.255.255.255") \
    #                         /UDP() \
    #                         /BOOTP(
    #                             op="BOOTREPLY", xid=bootp_layer.xid, flags=bootp_layer.flags,
    #                             sname=str(this_controller_uuid), yiaddr=str(client_ipv4), chaddr=bootp_layer.chaddr
    #                         ) \
    #                         /DHCP(
    #                             options=[
    #                                 ("message-type", "offer"),
    #                                 ("server_id", ipv4_service_str),
    #                                 ("lease_time", 43200),
    #                                 ("subnet_mask", str(ipv4_network.netmask)),
    #                                 ("router", ipv4_service_str),
    #                                 ("hostname", "{:d}".format(client_id).encode("ascii")),
    #                                 ("name_server", ipv4_service_str),
    #                                 ("name_server", "8.8.8.8"),
    #                                 ("domain", "archsdn".encode("ascii")),
    #                                 ("renewal_time", 21600),
    #                                 ("rebinding_time", 37800),
    #                                 "end"
    #                             ]
    #                         )
    #
    #             pad = Padding(load=" "*(300-len(dhcp_offer)))
    #             dhcp_offer = dhcp_offer / pad
    #
    #             # The controller sends the DHCP Offer packet to the host.
    #             msg.datapath.send_msg(
    #                 ofp_parser.OFPPacketOut(
    #                     datapath=msg.datapath,
    #                     buffer_id=ofp.OFP_NO_BUFFER,
    #                     in_port=in_port,
    #                     actions=[ofp_parser.OFPActionOutput(port=in_port, max_len=len(dhcp_offer))],  #
    #                     data=bytes(dhcp_offer)
    #                 )
    #             )
    #             ctrl_send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)
    #
    #         elif dhcp_layer_options['message-type'] is 3:  # A DHCP Request packet was received
    #             try:
    #                 _log.debug(
    #                     "{:s}Received DHCP Request packet from host with MAC {:s} on Switch {:d} at port {:d}".format(
    #                         " " * layer_num * 2, pkt.src, this_datapath_id, in_port
    #                     )
    #                 )
    #
    #                 # It is necessary to check if the host is already registered at the controller database
    #                 client_id = database.Query_Client_ID(this_datapath_id, in_port, EUI(pkt.src))
    #                 client_info = database.Query_Client_Info(client_id)
    #                 client_ipv4 = client_info["ipv4"]
    #
    #                 # Activate a flow to redirect to the controller ARP Request packets sent from the host to the
    #                 #   controller, from in_port.
    #                 match = ofp_parser.OFPMatch(
    #                     in_port=in_port, eth_dst='ff:ff:ff:ff:ff:ff', eth_src=pkt.src, eth_type=0x0806,
    #                     arp_op=1, arp_spa=str(client_ipv4), arp_tpa=(ipv4_service_str, 0xFFFFFFFF),
    #                     arp_sha=pkt.src, arp_tha='00:00:00:00:00:00'
    #                 )
    #                 actions = [ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)]
    #                 inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    #                 msg.datapath.send_msg(
    #                     ofp_parser.OFPFlowMod(
    #                         datapath=msg.datapath,
    #                         cookie=0,
    #                         cookie_mask=0,
    #                         table_id=0,
    #                         command=ofp.OFPFC_ADD,
    #                         idle_timeout=0,
    #                         hard_timeout=0,
    #                         priority=ofp.OFP_DEFAULT_PRIORITY,
    #                         buffer_id=ofp.OFP_NO_BUFFER,
    #                         out_port=ofp.OFPP_ANY,
    #                         out_group=ofp.OFPG_ANY,
    #                         flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
    #                         match=match,
    #                         instructions=inst
    #                     )
    #                 )
    #
    #                 # Activate a flow to redirect to the controller ICMP Request packets sent from the host to the
    #                 #   controller, from in_port.
    #                 match = ofp_parser.OFPMatch(
    #                     in_port=in_port, eth_dst=str(mac_service), eth_src=pkt.src, eth_type=ETHER_TYPES["IPv4"],
    #                     ip_proto=1, icmpv4_type=8, icmpv4_code=0
    #                 )
    #                 actions = [ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)]
    #                 inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    #                 msg.datapath.send_msg(
    #                     ofp_parser.OFPFlowMod(
    #                         datapath=msg.datapath,
    #                         cookie=0,
    #                         cookie_mask=0,
    #                         table_id=0,
    #                         command=ofp.OFPFC_ADD,
    #                         idle_timeout=0,
    #                         hard_timeout=0,
    #                         priority=ofp.OFP_DEFAULT_PRIORITY,
    #                         buffer_id=ofp.OFP_NO_BUFFER,
    #                         out_port=ofp.OFPP_ANY,
    #                         out_group=ofp.OFPG_ANY,
    #                         flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
    #                         match=match,
    #                         instructions=inst
    #                     )
    #                 )
    #
    #                 # Activate a flow to redirect to the controller DNS packets sent from the host to the
    #                 #   controller, from in_port.
    #                 match = ofp_parser.OFPMatch(
    #                     in_port=in_port, eth_dst=str(mac_service), eth_src=pkt.src, eth_type=ETHER_TYPES["IPv4"],
    #                     ipv4_src=str(client_ipv4), ipv4_dst=ipv4_service_str, ip_proto=17, udp_dst=53
    #                 )
    #                 actions = [ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)]
    #                 inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    #                 msg.datapath.send_msg(
    #                     ofp_parser.OFPFlowMod(
    #                         datapath=msg.datapath,
    #                         cookie=0,
    #                         cookie_mask=0,
    #                         table_id=0,
    #                         command=ofp.OFPFC_ADD,
    #                         idle_timeout=0,
    #                         hard_timeout=0,
    #                         priority=ofp.OFP_DEFAULT_PRIORITY,
    #                         buffer_id=ofp.OFP_NO_BUFFER,
    #                         out_port=ofp.OFPP_ANY,
    #                         out_group=ofp.OFPG_ANY,
    #                         flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
    #                         match=match,
    #                         instructions=inst
    #                     )
    #                 )
    #                 ctrl_send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)
    #
    #
    #                 #  Sending DHCP Ack to host
    #                 dhcp_ack = Ether(src=str(mac_service), dst=pkt.src) \
    #                             / IP(src=ipv4_service_str, dst="255.255.255.255") \
    #                             / UDP() / BOOTP(
    #                     op="BOOTREPLY", xid=bootp_layer.xid, flags=bootp_layer.flags, yiaddr=str(client_ipv4),
    #                     chaddr=EUI(pkt.src).packed
    #                 ) / DHCP(
    #                     options=[
    #                         ("message-type", "ack"),
    #                         ("server_id", ipv4_service_str),
    #                         ("lease_time", 43200),
    #                         ("subnet_mask", str(ipv4_network.netmask)),
    #                         ("router", ipv4_service_str),
    #                         ("hostname", "{:d}".format(client_id).encode("ascii")),
    #                         ("name_server", ipv4_service_str),
    #                         ("name_server", "8.8.8.8"),
    #                         "end",
    #                     ]
    #                 )
    #                 pad = Padding(load=" "*(300 - len(dhcp_ack)))
    #                 dhcp_ack = dhcp_ack / pad
    #
    #                 msg.datapath.send_msg(
    #                     ofp_parser.OFPPacketOut(
    #                         datapath=msg.datapath,
    #                         buffer_id=ofp.OFP_NO_BUFFER,
    #                         in_port=in_port,
    #                         actions=[ofp_parser.OFPActionOutput(port=in_port, max_len=len(dhcp_ack))],
    #                         data=bytes(dhcp_ack)
    #                     )
    #                 )
    #                 ctrl_send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)
    #
    #                 if not cluster_network.isHostRegistered(client_id):
    #                     cluster_network.ConnectHost(this_datapath_id, in_port, client_id, EUI(pkt.src))
    #
    #             except database.Exceptions.Client_Not_Registered:
    #
    #                 dhcp_nak = Ether(src=str(mac_service), dst=pkt.src) \
    #                            / IP(src=ipv4_service_str, dst=ipv4_layer.src) \
    #                            / UDP() \
    #                            / BOOTP(
    #                                 op=2, xid=bootp_layer.xid,
    #                                 yiaddr=ipv4_layer.src, siaddr=ipv4_service_str, giaddr=ipv4_service_str,
    #                                 chaddr=EUI(pkt.src).packed
    #                             ) \
    #                            / DHCP(
    #                                 options=[
    #                                     ("message-type", "nak"),
    #                                     ("subnet_mask", str(ipv4_network.netmask)),
    #                                     "end",
    #                                 ]
    #                             )
    #
    #                 msg.datapath.send_msg(
    #                     ofp_parser.OFPPacketOut(
    #                         datapath=msg.datapath,
    #                         buffer_id=ofp.OFP_NO_BUFFER,
    #                         in_port=in_port,
    #                         actions=[ofp_parser.OFPActionOutput(port=in_port, max_len=len(dhcp_nak))],  #
    #                         data=bytes(dhcp_nak)
    #                     )
    #                 )
    #                 ctrl_send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)
    #
    # elif pkt.haslayer(ARP):  # Answering to ARP Packet
    #     layer_num += 1
    #     arp_layer = pkt[ARP]
    #     _log.debug(
    #         "{:s}Received  ARP Packet - Summary:\n{:s}".format(" " * layer_num * 2, arp_layer.mysummary())
    #     )
    #     if arp_layer.ptype == ETHER_TYPES["IPv4"]:  # Answering to ARPv4 Packet
    #         if arp_layer.pdst == ipv4_service_str:  # If the MAC Address is the Service MAC
    #             arp_response = Ether(src=str(mac_service), dst=pkt.src) \
    #                         / ARP(
    #                             hwtype=arp_layer.hwtype,
    #                             ptype=arp_layer.ptype,
    #                             hwlen=arp_layer.hwlen,
    #                             plen=arp_layer.plen,
    #                             op="is-at",
    #                             hwsrc=mac_service.packed,
    #                             psrc=ipv4_service_str,
    #                             hwdst=EUI(pkt.src).packed,
    #                             pdst=arp_layer.psrc
    #                         )
    #             msg.datapath.send_msg(
    #                 ofp_parser.OFPPacketOut(
    #                     datapath=msg.datapath,
    #                     buffer_id=ofp.OFP_NO_BUFFER,
    #                     in_port=in_port,
    #                     actions=[ofp_parser.OFPActionOutput(port=in_port, max_len=len(arp_response))],
    #                     data=bytes(arp_response)
    #                 )
    #             )
    #         else:  # If it is something else...
    #             try:
    #                 source_client_id = database.Query_Client_ID(datapath_id=this_datapath_id, port_id=in_port, mac=EUI(pkt.src))
    #                 target_address_info = database.Query_Address_Information(ipv4=IPv4Address(arp_layer.pdst))
    #
    #                 #_log.debug("address_info: {}".format(target_address_info))
    #                 source_entity = (cluster_network.Entity.HOST, source_client_id)
    #                 target_entity = (cluster_network.Entity.HOST, target_address_info["client_id"])
    #
    #                 if not tunnels_manager.isPathActive(source_entity, target_entity):
    #                     shortest_path_source_to_target = cluster_network.QueryLocalPath(source_entity, target_entity)
    #                     _log.debug(
    #                         "shortest path from {} to {}: Hash: {} Path: {}".format(
    #                             source_entity, target_entity, hash(shortest_path_source_to_target),
    #                             shortest_path_source_to_target)
    #                     )
    #                     tunnels_manager.Activate_Local_Tunnel(shortest_path_source_to_target)
    #
    #                 if not tunnels_manager.isPathActive(target_entity, source_entity):
    #                     shortest_path_target_to_source = cluster_network.QueryLocalPath(target_entity, source_entity)
    #                     _log.debug(
    #                         "shortest path from {} to {}: Hash: {} Path: {}".format(
    #                             target_entity, source_entity, hash(shortest_path_target_to_source),
    #                             shortest_path_target_to_source
    #                         )
    #                     )
    #                     tunnels_manager.Activate_Local_Tunnel(shortest_path_target_to_source)
    #
    #                 arp_response = Ether(src=str(target_address_info["mac"]), dst=pkt.src) \
    #                                / ARP(
    #                     hwtype=arp_layer.hwtype,
    #                     ptype=arp_layer.ptype,
    #                     hwlen=arp_layer.hwlen,
    #                     plen=arp_layer.plen,
    #                     op="is-at",
    #                     hwsrc=target_address_info["mac"].packed,
    #                     psrc=str(IPv4Address(arp_layer.pdst)),
    #                     hwdst=EUI(pkt.src).packed,
    #                     pdst=arp_layer.psrc
    #                 )
    #                 msg.datapath.send_msg(
    #                     ofp_parser.OFPPacketOut(
    #                         datapath=msg.datapath,
    #                         buffer_id=ofp.OFP_NO_BUFFER,
    #                         in_port=in_port,
    #                         actions=[ofp_parser.OFPActionOutput(port=in_port, max_len=len(arp_response))],
    #                         data=bytes(arp_response)
    #                     )
    #                 )
    #
    #             except database.Exceptions.Address_Not_Registered:
    #                 central_proxy = get_central_proxy()
    #                 client_info = central_proxy.QueryClientInfo(ipv4=IPv4Address(arp_layer.pdst))
    #                 _log.debug("client_info: {}".format(client_info))
    #     #elif arp_layer.ptype == ETHER_TYPES["IPv6"]:  # Answering to ARPv6 Packet
    #     #    # TODO: implementar ARP reply com IPv6.
    #     #    pass
    #
    #     else:
    #         _log.debug(
    #             "{:s}Ignoring ARP Packet with type {:d}".format(" " * layer_num * 2, arp_layer.ptype)
    #         )
    #
    #
    # elif pkt.haslayer(ICMP):
    #     layer_num += 1
    #     ip_layer = pkt[IP]
    #     icmp_layer = pkt[ICMP]
    #     data_layer = pkt[Raw]
    #     _log.debug(
    #         "{:s}Received ICMP Packet - Summary:\n{:s}".format(" " * layer_num * 2, icmp_layer.mysummary())
    #     )
    #     if ip_layer.dst == ipv4_service_str:
    #         icmp_reply = Ether(src=str(mac_service), dst=pkt.src) \
    #             / IP(src=ipv4_service_str, dst=ip_layer.src) \
    #             / ICMP(
    #                 type="echo-reply",
    #                 id=icmp_layer.id,
    #                 seq=icmp_layer.seq,
    #             ) \
    #             / Raw(data_layer.load)
    #
    #         msg.datapath.send_msg(
    #             ofp_parser.OFPPacketOut(
    #                 datapath=msg.datapath,
    #                 buffer_id=ofp.OFP_NO_BUFFER,
    #                 in_port=in_port,
    #                 actions=[ofp_parser.OFPActionOutput(port=in_port, max_len=len(icmp_reply))],
    #                 data=bytes(icmp_reply)
    #             )
    #         )
    #
    # elif pkt.haslayer(DNS):
    #     layer_num += 1
    #     ip_layer = pkt[IP]
    #     udp_layer = pkt[UDP]
    #     dns_layer = pkt[DNS]
    #     DNSQR_layer = pkt[DNSQR]
    #
    #     _log.debug(
    #         "{:s}Received DNS Packet - Summary:\n{:s}".format(" " * layer_num * 2, dns_layer.mysummary())
    #     )
    #     qname_split = DNSQR_layer.qname.decode().split(".")[:-1]
    #     _log.debug(qname_split)
    #     if len(qname_split) == 3 and qname_split[-1] == "archsdn":
    #         central_proxy = get_central_proxy()
    #
    #         try:
    #             client_id = int(qname_split[0])
    #         except ValueError as ve:
    #             raise ValueError("DNS Query malformed. Client ID invalid.")
    #
    #         if "-" in qname_split[1]:
    #             try:
    #                 controller_uuid = uuid.UUID(qname_split[1])
    #             except ValueError:
    #                 raise ValueError("DNS Query malformed. Controller ID invalid.")
    #         elif str.isalnum(qname_split[1]):
    #             try:
    #                 controller_uuid = uuid.UUID(int=int(qname_split[1]))
    #             except ValueError:
    #                 try:
    #                     controller_uuid = uuid.UUID(int=int(qname_split[1], 16))
    #                 except ValueError:
    #                     raise ValueError("DNS Query malformed. Controller ID invalid.")
    #         else:
    #             raise ValueError("DNS Query malformed. Controller ID invalid")
    #
    #         # Query Central for Destination IP
    #         # Return to client the IP
    #         try:
    #             client_info = central_proxy.QueryClientInfo(location=(controller_uuid, client_id))
    #             dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
    #                         / IP(src=ipv4_service_str, dst=ip_layer.src) \
    #                         / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
    #                         / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='ok',
    #                               an=DNSRR(rrname=DNSQR_layer.qname, rdata=str(client_info["ipv4"]))
    #                               )
    #         except ClientNotRegistered:
    #             dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
    #                         / IP(src=ipv4_service_str, dst=ip_layer.src) \
    #                         / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
    #                         / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='name-error')
    #
    #         msg.datapath.send_msg(
    #             ofp_parser.OFPPacketOut(
    #                 datapath=msg.datapath,
    #                 buffer_id=ofp.OFP_NO_BUFFER,
    #                 in_port=in_port,
    #                 actions=[ofp_parser.OFPActionOutput(port=in_port, max_len=len(dns_reply))],
    #                 data=bytes(dns_reply)
    #             )
    #         )
    # else:
    #     layers = []
    #
    #     if _log.getEffectiveLevel() == logging.DEBUG:
    #         counter = 0
    #         while True:
    #             layer = pkt.getlayer(counter)
    #             if (layer != None):
    #                 layers.append("{:s}".format(str(layer.name)))
    #             else:
    #                 break
    #             counter += 1
    #     _log.debug(
    #         "{:s}Ignoring Received Packet :\n  {:s}".format(" " * layer_num * 2, "\n  ".join(layers))
    #     )
    #
    #
