
import logging
from ipaddress import IPv4Address

from scapy.packet import Padding
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database
from archsdn import central
from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import services

_log = logging.getLogger(logger_module_name(__file__))


# https://tools.ietf.org/rfc/rfc2132.txt

def process_dhcp_packet(packet_in_event):
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
                assert not sector.is_entity_registered(new_host), "Entity {:s} is already registered.".format(
                    str(new_host)
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
                        # ("name_server", "8.8.8.8"),
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
                datapath_ofp_parser.OFPPacketOut(
                    datapath=msg.datapath,
                    buffer_id=datapath_ofp.OFP_NO_BUFFER,
                    in_port=datapath_ofp.OFPP_CONTROLLER,
                    actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_offer))],
                    data=bytes(dhcp_offer)
                )
            )
            globals.send_msg(
                datapath_ofp_parser.OFPBarrierRequest(msg.datapath),
                reply_cls=datapath_ofp_parser.OFPBarrierReply
            )

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
                    ) \
                    / DHCP(
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
                    datapath_ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=datapath_ofp.OFP_NO_BUFFER,
                        in_port=datapath_ofp.OFPP_CONTROLLER,
                        actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_ack))],
                        data=bytes(dhcp_ack)
                    )
                )
                globals.send_msg(
                    datapath_ofp_parser.OFPBarrierRequest(msg.datapath),
                    reply_cls=datapath_ofp_parser.OFPBarrierReply
                )

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
                    datapath_ofp_parser.OFPPacketOut(
                        datapath=msg.datapath,
                        buffer_id=datapath_ofp.OFP_NO_BUFFER,
                        in_port=datapath_ofp.OFPP_CONTROLLER,
                        actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dhcp_nak))],
                        data=bytes(dhcp_nak)
                    )
                )
                globals.send_msg(
                    datapath_ofp_parser.OFPBarrierRequest(msg.datapath),
                    reply_cls=datapath_ofp_parser.OFPBarrierReply
                )

