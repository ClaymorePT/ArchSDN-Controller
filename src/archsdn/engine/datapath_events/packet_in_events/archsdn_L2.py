import logging
import struct
from uuid import UUID

from scapy.layers.l2 import Ether

from netaddr import EUI

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database
from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import services

_log = logging.getLogger(logger_module_name(__file__))


def process_archsdn_control(packet_in_event):
    assert globals.default_configs, "engine not initialised"

    msg = packet_in_event.msg
    datapath_id = msg.datapath.id
    datapath_ofp_parser = msg.datapath.ofproto_parser
    controller_uuid = database.get_database_info()["uuid"]

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
                        switch_port_no=pkt_in_port,
                        hash_val=hash_val
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

                    sender_datapath_obj = globals.get_datapath_obj(sender_datapath_id)
                    services.switch_segregation_flow_activation(sender_datapath_obj, sender_port_out)
                    _log.debug(
                        "Connecting switch {:016X} using port {:d} to switch {:016X} at port {:d}".format(
                            datapath_id, sender_datapath_id, pkt_in_port, sender_port_out
                        )
                    )

        else:
            _log.warning(
                "Ignoring ArchSDN Message received at switch {:016X} (Unknown type: {:d})".format(
                    datapath_id, msg_type
                )
            )
