
import logging
from ipaddress import IPv4Address

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS

from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database

from archsdn.engine.datapath_events.packet_in_events.archsdn_L2 import process_archsdn_control
from archsdn.engine.datapath_events.packet_in_events.arp import process_arp
from archsdn.engine.datapath_events.packet_in_events.dhcp import process_dhcp_packet
from archsdn.engine.datapath_events.packet_in_events.dns import process_dns_packet
from archsdn.engine.datapath_events.packet_in_events.icmpv4 import process_icmpv4_packet
from archsdn.engine.datapath_events.packet_in_events.ipv4_generic import process_ipv4_generic_packet

_log = logging.getLogger(logger_module_name(__file__))


def process_event(packet_in_event):
    assert globals.default_configs, "engine not initialised"

    msg = packet_in_event.msg
    datapath_id = msg.datapath.id
    datapath_ofp_parser = msg.datapath.ofproto_parser
    central_policies_addresses = database.query_volatile_info()
    ipv4_network = central_policies_addresses["ipv4_network"]

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
            process_ipv4_generic_packet(packet_in_event)

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

