
import logging
from ipaddress import IPv4Address
import struct
from uuid import UUID

from scapy.packet import Padding, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNSRR, DNS, DNSQR

from ryu.ofproto import ether
from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import services

_log = logging.getLogger(logger_module_name(__file__))


def process_event(port_change_event):
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

        elif reason_num == 1:
            if port_no in switch.ports:
                switch.remove_port(port_no)
            else:
                _log.warning(
                    "Port {:d} not previously registered at Switch {:016X}.".format(
                        port_no, datapath_id
                    )
                )

        else:
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
                if entities.Switch.PORT_STATE.OFPPS_LINK_DOWN in new_state:  # Port link state is Down...

                    # Removes all flows at __PORT_SEGREGATION_TABLE matching the removed port
                    datapath_obj.send_msg(
                        ofp_parser.OFPFlowMod(
                            datapath=datapath_obj,
                            table_id=globals.PORT_SEGREGATION_TABLE,
                            command=ofp.OFPFC_DELETE,
                            out_port=ofp.OFPP_ANY,
                            out_group=ofp.OFPG_ANY,
                            flags=ofp.OFPFF_SEND_FLOW_REM | ofp.OFPFF_CHECK_OVERLAP,
                            match=ofp_parser.OFPMatch(in_port=port_no)
                        )
                    )
                    globals.send_msg(ofp_parser.OFPBarrierRequest(datapath_obj), reply_cls=ofp_parser.OFPBarrierReply)

                    def flow_filter(elem):
                        (flow_obj, switch_id) = elem
                        if switch_id != datapath_id:
                            return False
                        if flow_obj.match:
                            for match_field in flow_obj.match.fields:
                                return type(match_field) is ofp_parser.MTInPort and match_field.value == port_no

                    filtered_flows = tuple(filter(flow_filter, globals.active_flows.items()))
                    for (flow, _) in filtered_flows:
                        _log.warning(
                            "Flow with ID {:d} configured at Switch {:016X} for port {:d} was removed".format(
                                flow.cookie, port_no, datapath_id
                            )
                        )
                        del globals.active_flows[flow.cookie]
                        globals.free_cookie_id(flow.cookie)

                elif entities.Switch.PORT_STATE.OFPPS_LIVE in new_state: # Port link state is Live...
                    # TODO: This event could be used to try and reestablish previous scenarios that were once lost...
                    pass

                _log.warning(
                    "Port {:d} state at Switch {:016X} changed from {:s} to {:s}".format(
                        port_no, datapath_id, str(old_state), str(new_state)
                    )
                )
                switch.ports[port_no]['state'] = new_state

    else:
        raise Exception("Reason with value {:d} is unknown to specification.".format(reason_num))


def process_packet_in_event(packet_in_event):
    assert globals.default_configs, "engine not initialised"

    msg = packet_in_event.msg
    datapath_id = msg.datapath.id
    ofp_parser = msg.datapath.ofproto_parser
    ofp = msg.datapath.ofproto
    controller_uuid = database.get_database_info()["uuid"]
    central_policies_addresses = database.query_volatile_info()
    ipv4_network = central_policies_addresses["ipv4_network"]
    ipv4_service = central_policies_addresses["ipv4_service"]
    mac_service = central_policies_addresses["mac_service"]

    pkt_in_port = None
    if msg.match:
        for match_field in msg.match.fields:
            if type(match_field) is ofp_parser.MTInPort:
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

    layer_num = 0
    if pkt_ethertype == 0xAAAA:  # ArchSDN Hello Packet : Ether Type -> 0xAAAA
        layer_num += 1
        archsdn_layer = memoryview(pkt.getlayer(layer_num).fields['load'])
        if len(archsdn_layer) < 2:
            _log.warning(
                "ArchSDN Beacon Ignored. Payload length is lower than 2. Got {:d}".format(len(archsdn_layer))
            )
            return

        (msg_type,) = struct.unpack("!H", archsdn_layer[0:struct.calcsize("!H")])
        msg_payload = archsdn_layer[2:]
        datapath_obj = msg.datapath

        if msg_type == 1:
            msg_type_1_payload_format = "!16s8s"
            msg_type_1_payload_len = struct.calcsize(msg_type_1_payload_format)
            if len(msg_payload) < msg_type_1_payload_len:
                _log.warning(
                    "ArchSDN Beacon Ignored. It has invalid size: it's {:d} when it should be at least {:d}".format(
                        len(msg_payload), msg_type_1_payload_len
                    )
                )
                return

            (sender_controller_uuid_bytes, hash_val_bytes) = struct.unpack(
                msg_type_1_payload_format, msg_payload[0:msg_type_1_payload_len]
            )

            hash_val = int.from_bytes(hash_val_bytes, byteorder='big', signed=False)
            sender_controller_uuid = UUID(bytes=sender_controller_uuid_bytes)

            if controller_uuid != sender_controller_uuid:
                _log.debug(
                    "Switch {:016X} received Beacon Packet from a Controller with ID {:s}, with the hash value {:X}"
                    "".format(
                        datapath_id, str(sender_controller_uuid), hash_val
                    )
                )
                if not sector.is_entity_registered(sender_controller_uuid):
                    sector.register_entity(
                        entities.Sector(
                            controller_id=sender_controller_uuid
                        )
                    )
                if not sector.is_port_connected(datapath_id, pkt_in_port):
                    sector.connect_entities(
                        datapath_id, sender_controller_uuid,
                        switch_port_no=pkt_in_port
                    )

                    # Activate segregation flow at the switch port for the detected sector
                    services.sector_segregation_flow_activation(datapath_obj, pkt_in_port)

            else:
                (sender_datapath_id, sender_port_out) = globals.beacons_hash_table[hash_val]
                _log.debug(
                    "Switch {:016X} received Beacon Packet sent by this very own controller with the hash value "
                    "{:X}".format(
                        datapath_id, hash_val
                    )
                )

                if not sector.is_port_connected(datapath_id, pkt_in_port):
                    sector.connect_entities(
                        datapath_id, sender_datapath_id,
                        switch_a_port_no=pkt_in_port,
                        switch_b_port_no=sender_port_out
                    )
                    # Activate segregation flow at the switch port for the detected sector switch
                    services.switch_segregation_flow_activation(datapath_obj, pkt_in_port)

        else:
            _log.warning(
                "Ignoring ArchSDN Message received at switch {:016X} (Unknown type: {:d})".format(
                    datapath_id, msg_type
                )
            )

    elif pkt.haslayer(ARP):  # Answering to ARP Packet
        layer_num += 1
        arp_layer = pkt[ARP]
        _log.debug(
            "Received  ARP Packet from {:s} requesting the MAC address for target {:s}.".format(
                arp_layer.psrc, arp_layer.pdst
            )
        )
        if arp_layer.ptype == ether.ETH_TYPE_IP:  # Answering to ARPv4 Packet
            if arp_layer.pdst == str(ipv4_service):  # If the MAC Address is the Service MAC
                _log.debug("Arp target {:s} is the controller of this sector. ".format(arp_layer.pdst))
                mac_target_str = mac_service
            else:
                try:
                    try:
                        #  If the target is registered in this sector...
                        target_client_info = database.query_address_info(ipv4=IPv4Address(arp_layer.pdst))

                        _log.debug(
                            "Target {:s} belongs to this sector. "
                            "It is registered with client id {:d}, MAC {:s} at switch {:016X}, connected at port {:d}.".format(
                                arp_layer.pdst,
                                target_client_info["client_id"],
                                str(target_client_info["mac"]),
                                target_client_info["datapath"],
                                target_client_info["port"],
                            )
                        )
                        mac_target_str = target_client_info["mac"]
                    except database.AddressNotRegistered:
                        # The target is not registered in the sector.
                        # Ask the central manager for the controller id and client id.
                        # Then ask the respective controller for information about its client.
                        address_info = central.query_address_info(ipv4=IPv4Address(arp_layer.pdst))
                        _log.debug(
                            "Target {:s} with client id {:d} belongs to controller {:s} sector.".format(
                                arp_layer.pdst,
                                address_info.client_id,
                                address_info.controller_id
                            )
                        )
                        mac_target_str = None

                except central.NoResultsAvailable:
                    _log.debug("Target {:s} is not registered at the central manager.".format(arp_layer.pdst))
                    mac_target_str = None

            # Checks for the existence of the target in the network. If it exists, send back the ARP Reply
            if mac_target_str:
                datapath_obj = msg.datapath
                arp_response = Ether(src=str(mac_target_str), dst=pkt.src) \
                    / ARP(
                        hwtype=arp_layer.hwtype,
                        ptype=arp_layer.ptype,
                        hwlen=arp_layer.hwlen,
                        plen=arp_layer.plen,
                        op="is-at",
                        hwsrc=mac_target_str.packed,
                        psrc=arp_layer.pdst,
                        hwdst=EUI(pkt.src).packed,
                        pdst=arp_layer.psrc
                    )
                datapath_obj.send_msg(
                    ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=pkt_in_port,
                        actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(arp_response))],
                        data=bytes(arp_response)
                    )
                )
        else:
            _log.debug(
                "Ignoring ARP Packet with type: {:d}".format(arp_layer.ptype)
            )

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

        if ip_layer.haslayer(DHCP):  # https://tools.ietf.org/rfc/rfc2132.txt
            datapath_obj = msg.datapath
            bootp_layer = pkt[BOOTP]
            dhcp_layer = pkt[DHCP]

            dhcp_layer_options = dict(filter((lambda x: len(x) == 2), dhcp_layer.options))
            if 'message-type' in dhcp_layer_options:
                if dhcp_layer_options['message-type'] is 1:  # A DHCP DISCOVER packet was received

                    _log.debug(
                        "Received DHCP Discover packet from host with MAC {:s} on switch {:016X} at port {:d}".format(
                            pkt.src, datapath_id, pkt_in_port
                        )
                    )

                    try:  # search for a registration for the host at the local database
                        host_database_id = database.query_client_id(
                            datapath_id=datapath_id,
                            port_id=pkt_in_port,
                            mac=pkt_src_mac
                        )

                    except database.ClientNotRegistered:  # If not found, register a new host
                        database.register_client(
                            datapath_id=datapath_id,
                            port_id=pkt_in_port,
                            mac=pkt_src_mac
                        )
                        host_database_id = database.query_client_id(
                            datapath_id=datapath_id,
                            port_id=pkt_in_port,
                            mac=pkt_src_mac
                        )
                        try:  # Query central manager for the centralized host information
                            central_client_info = central.query_client_info(controller_uuid, host_database_id)

                        except central.ClientNotRegistered:
                            central.register_client(
                                controller_uuid=controller_uuid,
                                client_id=host_database_id
                            )
                            central_client_info = central.query_client_info(controller_uuid, host_database_id)

                        host_name = central_client_info.name
                        host_ipv4 = central_client_info.ipv4
                        host_ipv6 = central_client_info.ipv6
                        database.update_client_addresses(
                            client_id=host_database_id,
                            ipv4=host_ipv4,
                            ipv6=host_ipv6
                        )

                        if sector.is_port_connected(switch_id=datapath_id, port_id=pkt_in_port):
                            old_entity_id = sector.query_connected_entity_id(switch_id=datapath_id, port_id=pkt_in_port)
                            old_entity = sector.query_entity(old_entity_id)

                            assert isinstance(old_entity, entities.Host), "entity expected to be Host. Got {:s}".format(
                                repr(old_entity)
                            )
                            if old_entity.mac != pkt_src_mac:
                                sector.disconnect_entities(datapath_id, old_entity_id, pkt_in_port)

                        new_host = entities.Host(
                            hostname=host_name,
                            mac=pkt_src_mac,
                            ipv4=host_ipv4,
                            ipv6=host_ipv6
                        )
                        sector.register_entity(new_host)
                        sector.connect_entities(datapath_id, new_host.id, switch_port_no=pkt_in_port)

                    # It is necessary to check if the host is already registered at the controller database
                    client_info = database.query_client_info(host_database_id)

                    # A DHCP Offer packet is tailored specifically for the new host.
                    dhcp_offer = Ether(src=str(mac_service), dst=pkt.src) \
                                 / IP(src=str(ipv4_service), dst="255.255.255.255") \
                                 / UDP() \
                                 / BOOTP(
                        op="BOOTREPLY", xid=bootp_layer.xid, flags=bootp_layer.flags,
                        sname=str(controller_uuid), yiaddr=str(client_info["ipv4"]), chaddr=bootp_layer.chaddr
                    ) \
                                 / DHCP(
                        options=[
                            ("message-type", "offer"),
                            ("server_id", str(ipv4_service)),
                            ("lease_time", 43200),
                            ("subnet_mask", str(ipv4_network.netmask)),
                            ("router", str(ipv4_service)),
                            ("hostname", "{:d}".format(host_database_id).encode("ascii")),
                            ("name_server", str(ipv4_service)),
                            #("name_server", "8.8.8.8"),
                            ("domain", "archsdn".encode("ascii")),
                            ("renewal_time", 21600),
                            ("rebinding_time", 37800),
                            "end"
                        ]
                    )

                    pad = Padding(load=" " * (300 - len(dhcp_offer)))
                    dhcp_offer = dhcp_offer / pad

                    # The controller sends the DHCP Offer packet to the host.
                    datapath_obj.send_msg(
                        ofp_parser.OFPPacketOut(
                            datapath=msg.datapath,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            in_port=pkt_in_port,
                            actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_offer))],
                            data=bytes(dhcp_offer)
                        )
                    )
                    globals.send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)

                elif dhcp_layer_options['message-type'] is 3:  # A DHCP Request packet was received
                    try:
                        _log.debug(
                            "Received DHCP Request packet from host with MAC {:s} on switch {:016X} at port {:d}".format(
                                pkt.src, datapath_id, pkt_in_port
                            )
                        )

                        # It is necessary to check if the host is already registered at the controller database
                        client_id = database.query_client_id(datapath_id, pkt_in_port, EUI(pkt.src))
                        client_info = database.query_client_info(client_id)
                        client_ipv4 = client_info["ipv4"]

                        # Activate segregation flow at the switch port for the detected sector host
                        services.host_segregation_flow_activation(datapath_obj, pkt_in_port, pkt.src)

                        #  Sending DHCP Ack to host
                        dhcp_ack = Ether(src=str(mac_service), dst=pkt.src) \
                                   / IP(src=str(ipv4_service), dst="255.255.255.255") \
                                   / UDP() / BOOTP(
                            op="BOOTREPLY", xid=bootp_layer.xid, flags=bootp_layer.flags, yiaddr=str(client_ipv4),
                            chaddr=EUI(pkt.src).packed
                        ) / DHCP(
                            options=[
                                ("message-type", "ack"),
                                ("server_id", str(ipv4_service)),
                                ("lease_time", 43200),
                                ("subnet_mask", str(ipv4_network.netmask)),
                                ("router", str(ipv4_service)),
                                ("hostname", "{:d}".format(client_id).encode("ascii")),
                                ("name_server", str(ipv4_service)),
                                ("name_server", "8.8.8.8"),
                                "end",
                            ]
                        )
                        pad = Padding(load=" " * (300 - len(dhcp_ack)))
                        dhcp_ack = dhcp_ack / pad

                        datapath_obj.send_msg(
                            ofp_parser.OFPPacketOut(
                                datapath=msg.datapath,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=pkt_in_port,
                                actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_ack))],
                                data=bytes(dhcp_ack)
                            )
                        )
                        globals.send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)

                    except database.ClientNotRegistered:
                        dhcp_nak = Ether(src=str(mac_service), dst=pkt.src) \
                                   / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                   / UDP() \
                                   / BOOTP(
                            op=2, xid=bootp_layer.xid,
                            yiaddr=ip_layer.src, siaddr=str(ipv4_service), giaddr=str(ipv4_service),
                            chaddr=EUI(pkt.src).packed
                        ) \
                                   / DHCP(
                            options=[
                                ("message-type", "nak"),
                                ("subnet_mask", str(ipv4_network.netmask)),
                                "end",
                            ]
                        )

                        datapath_obj.send_msg(
                            ofp_parser.OFPPacketOut(
                                datapath=msg.datapath,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=pkt_in_port,
                                actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_nak))],  #
                                data=bytes(dhcp_nak)
                            )
                        )
                        globals.send_msg(ofp_parser.OFPBarrierRequest(msg.datapath), reply_cls=ofp_parser.OFPBarrierReply)

        elif ip_layer.haslayer(ICMP):
            datapath_obj = msg.datapath
            icmp_layer = pkt[ICMP]
            data_layer = pkt[Raw]
            _log.debug(
                "Received ICMP Packet - Summary: {:s}".format(icmp_layer.mysummary())
            )
            if ip_layer.dst == str(ipv4_service):
                icmp_reply = Ether(src=str(mac_service), dst=pkt.src) \
                             / IP(src=str(ipv4_service), dst=ip_layer.src) \
                             / ICMP(
                                type="echo-reply",
                                id=icmp_layer.id,
                                seq=icmp_layer.seq,
                            ) \
                             / Raw(data_layer.load)

                datapath_obj.send_msg(
                    ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=pkt_in_port,
                        actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(icmp_reply))],
                        data=bytes(icmp_reply)
                    )
                )
            elif pkt_ipv4_dst in ipv4_network:  # If the destination IP belongs to the network.
                # Opens a bi-directional tunnel to target, using the same path in both directions.
                host_not_found_in_sector = False
                try:
                    addr_info_dst = database.query_address_info(ipv4=pkt_ipv4_dst)
                    target_switch_id = addr_info_dst["datapath"]
                    target_switch_port = addr_info_dst["port"]
                    host_a_entity_id = sector.query_connected_entity_id(datapath_id, pkt_in_port)
                    host_b_entity_id = sector.query_connected_entity_id(target_switch_id, target_switch_port)

                    # Activating the ICMP service between hosts in the same sector.
                    services.icmpv4_flow_activation(host_a_entity_id, host_b_entity_id)

                    # Reinsert the ICMP packet into the OpenFlow Pipeline, in order to properly process it.
                    msg.datapath.send_msg(
                        ofp_parser.OFPPacketOut(
                            datapath=msg.datapath,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            in_port=pkt_in_port,
                            actions=[
                                ofp_parser.OFPActionOutput(port=ofp.OFPP_TABLE, max_len=len(msg.data)),
                            ],
                            data=msg.data
                        )
                    )

                    _log.warning(
                        "ICMP4 tunnel opened between hosts {:s} and {:s}.".format(
                            str(host_a_entity_id), str(host_b_entity_id)
                        )
                    )

                except database.AddressNotRegistered:
                    host_not_found_in_sector = True

                if host_not_found_in_sector:
                    try:
                        addr_info = central.query_address_info(ipv4=pkt_ipv4_dst)
                        raise AssertionError(
                            "Support for hosts in other sectors, is Not implemented {}.".format(str(addr_info))
                        )

                    except central.NoResultsAvailable:
                        _log.error("Target {:s} is not registered at the central manager.".format(str(pkt_ipv4_dst)))

            else:
                _log.error("Target {:s} is currently not reachable.".format(str(pkt_ipv4_dst)))

        elif ip_layer.haslayer(DNS):
            datapath_obj = msg.datapath
            udp_layer = pkt[UDP]
            dns_layer = pkt[DNS]
            DNSQR_layer = pkt[DNSQR]

            _log.debug("Received DNS Packet - Summary: {:s}".format(dns_layer.mysummary()))
            qname_split = DNSQR_layer.qname.decode().split(".")[:-1]
            _log.debug(qname_split)
            if len(qname_split) == 3 and qname_split[-1] == "archsdn":
                try:
                    client_id = int(qname_split[0])
                except ValueError as ve:
                    raise ValueError("DNS Query malformed. Client ID invalid.")

                if "-" in qname_split[1]:
                    try:
                        controller_uuid = UUID(qname_split[1])
                    except ValueError:
                        raise ValueError("DNS Query malformed. Controller ID invalid.")
                elif str.isalnum(qname_split[1]):
                    try:
                        controller_uuid = UUID(int=int(qname_split[1]))
                    except ValueError:
                        try:
                            controller_uuid = UUID(int=int(qname_split[1], 16))
                        except ValueError:
                            raise ValueError("DNS Query malformed. Controller ID invalid.")
                else:
                    raise ValueError("DNS Query malformed. Controller ID invalid")

                # Query Central for Destination IP
                # Return to client the IP
                try:
                    client_info = central.query_client_info(controller_uuid, client_id)
                    dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                                / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                                / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='ok',
                                      an=DNSRR(rrname=DNSQR_layer.qname, rdata=str(client_info["ipv4"]))
                                      )
                except database.ClientNotRegistered:
                    dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                                / IP(src=str(ipv4_service), dst=ip_layer.src) \
                                / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                                / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='name-error')

                datapath_obj.send_msg(
                    ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=pkt_in_port,
                        actions=[ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dns_reply))],
                        data=bytes(dns_reply)
                    )
                )

        # elif ip_layer.haslayer(UDP) or ip_layer.haslayer(TCP):
        #     # If the packet is not DHCP, ARP, DNS or ICMP, then it is probably a regular data packet.
        #     # Lets create two uni-directional tunnels for TCP and UDP traffic, where the implemented QoS metrics will
        #     #   depend upon the service characteristics.
        #     #
        #
        #     if pkt_ipv4_dst not in ipv4_network:  # If the destination IP belongs to other networks...
        #         _log.warning("Traffic towards destination {:s} is not supported.".format(str(pkt_ipv4_dst)))
        #         return
        #     if pkt_ipv4_dst == ipv4_network.broadcast_address:
        #         _log.warning("Broadcast traffic ({:s}) is not supported.".format(str(pkt_ipv4_dst)))
        #         return
        #     if pkt_ipv4_dst.is_multicast:
        #         _log.warning("Multicast traffic ({:s}) is not supported.".format(str(pkt_ipv4_dst)))
        #         return
        #
        #     udp_layer = None
        #     tcp_layer = None
        #     src_port = None
        #     dst_port = None
        #     if ip_layer.haslayer(UDP):
        #         udp_layer = pkt[UDP]
        #         src_port = udp_layer.sport
        #         dst_port = udp_layer.dport
        #     elif ip_layer.haslayer(TCP):
        #         tcp_layer = pkt[TCP]
        #         src_port = tcp_layer.sport
        #         dst_port = tcp_layer.dport
        #     else:
        #         raise AssertionError(
        #             "Something is wrong. IP Packet is supposed to be UDP or TCP, but scapy seems to be confused."
        #         )
        #
        #
        #     from archsdn.engine.services.switch_ipv4_generic_flow import ipv4_generic_flow_activation
        #
        #     # Activating the IPv4 generic service between hosts in the same sector.
        #     ipv4_generic_flow_activation(host_a_entity_id, host_b_entity_id)
        #
        #
        #     # Reinsert the IPv4 packet into the OpenFlow Pipeline, in order to properly process it.
        #     msg.datapath.send_msg(
        #         ofp_parser.OFPPacketOut(
        #             datapath=msg.datapath,
        #             buffer_id=ofp.OFP_NO_BUFFER,
        #             in_port=pkt_in_port,
        #             actions=[
        #                 ofp_parser.OFPActionOutput(port=ofp.OFPP_TABLE, max_len=len(msg.data)),
        #             ],
        #             data=msg.data
        #         )
        #     )
        #
        #     _log.warning(
        #         "IPv4 tunnel for TCP and UDP traffic, opened between hosts {:s} and {:s}.".format(
        #             host_a_entity.hostname, host_b_entity.hostname
        #         )
        #     )

        else:
            _log.warning(
                "IP packet Type ({:X}), sent from {:s} to {:s}, is not supported. ".format(
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

