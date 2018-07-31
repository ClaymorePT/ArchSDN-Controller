
import logging
from uuid import UUID

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNSRR, DNS, DNSQR

from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database
from archsdn import central

_log = logging.getLogger(logger_module_name(__file__))


def process_dns_packet(packet_in_event):  # DNS service management
    assert globals.default_configs, "engine not initialised"

    msg = packet_in_event.msg
    datapath_id = msg.datapath.id
    datapath_ofp_parser = msg.datapath.ofproto_parser
    datapath_ofp = msg.datapath.ofproto
    controller_uuid = database.get_database_info()["uuid"]
    central_policies_addresses = database.query_volatile_info()
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

    datapath_obj = msg.datapath
    ip_layer = pkt[IP]
    udp_layer = pkt[UDP]
    dns_layer = pkt[DNS]
    DNSQR_layer = pkt[DNSQR]

    _log.debug("Received DNS Packet - Summary: {:s}".format(dns_layer.mysummary()))
    qname_split = DNSQR_layer.qname.decode().split(".")[:-1]
    if len(qname_split) == 3 and qname_split[-1] == "archsdn":
        try:
            query_client_id = int(qname_split[0])
        except ValueError:
            raise ValueError("DNS Query malformed. Client ID invalid.")

        if "-" in qname_split[1]:
            try:
                query_controller_uuid = UUID(qname_split[1])
            except ValueError:
                raise ValueError("DNS Query malformed. Controller ID invalid.")
        elif str.isalnum(qname_split[1]):
            try:
                query_controller_uuid = UUID(int=int(qname_split[1]))
            except ValueError:
                try:
                    query_controller_uuid = UUID(int=int(qname_split[1], 16))
                except ValueError:
                    raise ValueError("DNS Query malformed. Controller ID invalid.")
        else:
            raise ValueError("DNS Query malformed. Controller ID invalid")

        # Query Central for Destination IP
        # Return to client the IP
        _log.info(
            "DNS Query request for Client {:d} at Sector {:s}".format(
                query_client_id,
                str(query_controller_uuid),
            )
        )
        if controller_uuid == query_controller_uuid:  # If the client is part of this sector
            try:
                client_info = database.query_client_info(query_client_id)
                dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                            / IP(src=str(ipv4_service), dst=ip_layer.src) \
                            / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                            / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='ok',
                                  an=DNSRR(rrname=DNSQR_layer.qname, rdata=str(client_info["ipv4"]))
                                  )
                _log.info(
                    "Client {:d} at Sector {:s} record found locally!: {:s}".format(
                        query_client_id,
                        str(query_controller_uuid),
                        str(client_info)
                    )
                )
            except database.ClientNotRegistered:
                dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                            / IP(src=str(ipv4_service), dst=ip_layer.src) \
                            / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                            / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='name-error')
                _log.error(
                    "Client {:d} at Sector {:s} record does not exist".format(
                        query_client_id,
                        str(query_controller_uuid),
                    )
                )
        else:  # If the client is part of a foreign sector
            try:
                client_info = central.query_client_info(query_controller_uuid, query_client_id)
                dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                    / IP(src=str(ipv4_service), dst=ip_layer.src) \
                    / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                    / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='ok',
                          an=DNSRR(rrname=DNSQR_layer.qname, rdata=str(client_info.ipv4))
                          )
                _log.info(
                    "Client {:d} at Sector {:s} record found at central management!: {:s}".format(
                        query_client_id,
                        str(query_controller_uuid),
                        str(client_info)
                    )
                )
            except central.ClientNotRegistered:
                dns_reply = Ether(src=str(mac_service), dst=pkt.src) \
                            / IP(src=str(ipv4_service), dst=ip_layer.src) \
                            / UDP(dport=udp_layer.sport, sport=udp_layer.dport) \
                            / DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, rcode='name-error')
                _log.error(
                    "Client {:d} at Sector {:s} record does not exist".format(
                        query_client_id,
                        str(query_controller_uuid),
                    )
                )

        datapath_obj.send_msg(
            datapath_ofp_parser.OFPPacketOut(
                datapath=msg.datapath,
                buffer_id=datapath_ofp.OFP_NO_BUFFER,
                in_port=datapath_ofp.OFPP_CONTROLLER,
                actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(dns_reply))],
                data=bytes(dns_reply)
            )
        )

