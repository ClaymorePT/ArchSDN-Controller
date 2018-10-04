import logging
from ipaddress import IPv4Address

from scapy.layers.l2 import Ether, ARP
from ryu.ofproto import ether
from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database
from archsdn import central
from archsdn import p2p

_log = logging.getLogger(logger_module_name(__file__))


def process_arp(packet_in_event):
    assert globals.default_configs, "engine not initialised"

    msg = packet_in_event.msg
    datapath_id = msg.datapath.id
    datapath_ofp_parser = msg.datapath.ofproto_parser
    datapath_ofp = msg.datapath.ofproto
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


    arp_layer = pkt[ARP]
    _log.debug(
        "Received  ARP Packet from {:s} requesting the MAC address for target {:s}.".format(
            arp_layer.psrc, arp_layer.pdst
        )
    )
    if arp_layer.ptype == ether.ETH_TYPE_IP:  # Answering to ARPv4 Packet
        if not (IPv4Address(arp_layer.psrc) in ipv4_network and IPv4Address(arp_layer.pdst) in ipv4_network):
            _log.debug(
                "Ignoring ARP Packet with incorrect IPv4 network addresses. Source: {:s}; Destination: {:s}".format(
                    arp_layer.psrc, arp_layer.pdst
                )
            )
            return

        if arp_layer.pdst == str(ipv4_service):  # If the MAC Address is the Service MAC
            _log.debug("Arp target {:s} is the controller of this sector. ".format(arp_layer.pdst))
            mac_target = mac_service
        else:
            try:
                try:
                    #  If the target is registered in this sector...
                    target_client_info = database.query_address_info(ipv4=IPv4Address(arp_layer.pdst))
                    mac_target = target_client_info["mac"]

                    _log.debug(
                        "Target {:s} belongs to this sector. "
                        "It is registered with client id {:d}, MAC {:s} at switch {:016X}, "
                        "connected at port {:d}.".format(
                            arp_layer.pdst,
                            target_client_info["client_id"],
                            str(mac_target),
                            target_client_info["datapath"],
                            target_client_info["port"],
                        )
                    )

                except database.AddressNotRegistered:
                    # The target is not registered in the sector.
                    # Ask the central manager for the controller id and client id.
                    # Then ask the respective controller for information about its client.
                    address_info = central.query_address_info(ipv4=IPv4Address(arp_layer.pdst))
                    controller_proxy = p2p.get_controller_proxy(address_info.controller_id)
                    target_client_info = controller_proxy.query_address_info(ipv4=IPv4Address(arp_layer.pdst))
                    mac_target = target_client_info["mac"]

                    _log.debug(
                        "Target {:s} with client id {:d} belongs to controller {:s} sector and has MAC {:s}".format(
                            arp_layer.pdst,
                            address_info.client_id,
                            str(address_info.controller_id),
                            str(mac_target)
                        )
                    )

            except central.NoResultsAvailable:
                _log.debug("Target {:s} is not registered at the central manager.".format(arp_layer.pdst))
                mac_target = None

        # Checks for the existence of the target in the network. If it exists, send back the ARP Reply
        if mac_target:
            datapath_obj = msg.datapath
            arp_response = Ether(src=str(mac_target), dst=pkt.src) \
                / ARP(
                    hwtype=arp_layer.hwtype,
                    ptype=arp_layer.ptype,
                    hwlen=arp_layer.hwlen,
                    plen=arp_layer.plen,
                    op="is-at",
                    hwsrc=mac_target.packed,
                    psrc=arp_layer.pdst,
                    hwdst=EUI(pkt.src).packed,
                    pdst=arp_layer.psrc
                )
            datapath_obj.send_msg(
                datapath_ofp_parser.OFPPacketOut(
                    datapath=msg.datapath,
                    buffer_id=datapath_ofp.OFP_NO_BUFFER,
                    in_port=datapath_ofp.OFPP_CONTROLLER,
                    actions=[datapath_ofp_parser.OFPActionOutput(port=pkt_in_port, max_len=len(arp_response))],
                    data=bytes(arp_response)
                )
            )
    else:
        _log.debug(
            "Ignoring ARP Packet with type: {:d}".format(arp_layer.ptype)
        )
