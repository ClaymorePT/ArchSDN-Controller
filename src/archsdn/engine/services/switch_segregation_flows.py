import logging

from archsdn.helpers import logger_module_name
from archsdn.engine import globals

from ryu.ofproto import ether, inet

_log = logging.getLogger(logger_module_name(__file__))


def sector_segregation_flow_activation(switch_obj, in_port):
    ofp_parser = switch_obj.ofproto_parser
    ofp = switch_obj.ofproto

    port_segregation_flow = ofp_parser.OFPFlowMod(
        datapath=switch_obj,
        cookie=0,
        table_id=globals.PORT_SEGREGATION_TABLE,
        command=ofp.OFPFC_ADD,
        priority=globals.PORT_TABLE_PORT_PRIORITY,
        match=ofp_parser.OFPMatch(
            in_port=in_port, eth_type=ether.ETH_TYPE_MPLS
        ),
        instructions=[
            ofp_parser.OFPInstructionGotoTable(table_id=globals.SECTOR_FILTERING_TABLE)
        ]
    )

    switch_obj.send_msg(port_segregation_flow)
    globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)


def switch_segregation_flow_activation(switch_obj, in_port):
    ofp_parser = switch_obj.ofproto_parser
    ofp = switch_obj.ofproto

    port_segregation_flow = ofp_parser.OFPFlowMod(
        datapath=switch_obj,
        cookie=0,
        table_id=globals.PORT_SEGREGATION_TABLE,
        command=ofp.OFPFC_ADD,
        priority=globals.PORT_TABLE_PORT_PRIORITY,
        match=ofp_parser.OFPMatch(
            in_port=in_port, eth_type=ether.ETH_TYPE_MPLS
        ),
        instructions=[
            ofp_parser.OFPInstructionGotoTable(table_id=globals.MPLS_FILTERING_TABLE)
        ]
    )

    switch_obj.send_msg(port_segregation_flow)
    globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)


def host_segregation_flow_activation(switch_obj, in_port, host_mac_addr):
    ofp_parser = switch_obj.ofproto_parser
    ofp = switch_obj.ofproto

    port_segregation_flow = ofp_parser.OFPFlowMod(
        datapath=switch_obj,
        cookie=0,
        table_id=globals.PORT_SEGREGATION_TABLE,
        command=ofp.OFPFC_ADD,
        priority=globals.PORT_TABLE_PORT_PRIORITY,
        match=ofp_parser.OFPMatch(
            in_port=in_port,
            eth_src=host_mac_addr,
        ),
        instructions=[
            ofp_parser.OFPInstructionGotoTable(table_id=globals.HOST_FILTERING_TABLE)
        ]
    )

    switch_obj.send_msg(port_segregation_flow)
    globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)

    

