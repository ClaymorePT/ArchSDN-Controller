import logging

from ryu.ofproto import ether, inet

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn.engine import sector
from archsdn.engine.entities import Host, Sector
from archsdn.engine.services.abstracts import Service

_log = logging.getLogger(logger_module_name(__file__))


class __ICMPv4Service(Service):

    def __init__(self, bidirectional_path, terminate_path_callback, mpls_label=None):
        self.__bidirectional_path = bidirectional_path
        self.__terminate_path = terminate_path_callback
        self.__mpls_label = mpls_label

    def __del__(self):
        self.__terminate_path()

    @property
    def label(self):
        return self.__mpls_label

    def uses_edge(self, node_a, node_b, output_port):
        return self.__bidirectional_path.uses_edge((node_a, node_b, output_port))


def __icmpv4_flow_activation_host_to_host(bidirectional_path, mpls_label):
    assert isinstance(bidirectional_path, sector.SectorPath), "bidirectional_path expected to be sector.SectorPath"
    assert bidirectional_path.is_bidirectional(), "bidirectional_path expected to be a bidiretional sector.SectorPath"

    entity_a_id = bidirectional_path.entity_a
    entity_b_id = bidirectional_path.entity_b
    switches_info = bidirectional_path.switches_info
    host_a_entity_obj = sector.query_entity(entity_a_id)
    host_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(host_a_entity_obj, Host), "a_entity_obj type is not Host"
    assert isinstance(host_b_entity_obj, Host), "b_entity_obj type is not Host"

    tunnel_cookies = []

    if len(bidirectional_path) == 3:
        # If the hosts are connected to the same switch, there's no need to create an MPLS tunnel.
        #   It is only necessary to forward the packets from one network interface to the other.

        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]
        single_switch_obj = globals.get_datapath_obj(unique_switch_id)
        single_switch_ofp_parser = single_switch_obj.ofproto_parser
        single_switch_ofp = single_switch_obj.ofproto

        side_a_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            flags=single_switch_ofp.OFPFF_SEND_FLOW_REM | single_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=single_switch_ofp_parser.OFPMatch(
                eth_dst=str(host_b_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4), ip_proto=inet.IPPROTO_ICMP
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionOutput(port=switch_out_port),
                    ]
                ),
            ]
        )

        side_b_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            flags=single_switch_ofp.OFPFF_SEND_FLOW_REM | single_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=single_switch_ofp_parser.OFPMatch(
                eth_dst=str(host_a_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_b_entity_obj.ipv4), ipv4_dst=str(host_a_entity_obj.ipv4), ip_proto=inet.IPPROTO_ICMP
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
                    ]
                ),
            ]
        )

        single_switch_obj.send_msg(side_a_flow)
        single_switch_obj.send_msg(side_b_flow)
        tunnel_cookies.append(side_a_flow.cookie)
        tunnel_cookies.append(side_b_flow.cookie)
        globals.active_flows[side_a_flow.cookie] = (side_a_flow, unique_switch_id)
        globals.active_flows[side_b_flow.cookie] = (side_b_flow, unique_switch_id)

    else:
        # Multiswitch path requires an MPLS label to build a tunnel.
        assert isinstance(mpls_label, int), "mpls_label is not int"
        assert 0 <= mpls_label < pow(2, 20), "mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

        #  Information about the path switches.
        #  Core switches are those who are in the middle of the path, not on the edges.
        #  Edges switches are those who perform the ingress and egress packet procedures.
        #
        #  Tunnel implementation at path core switches
        for (middle_switch_id, switch_in_port, switch_out_port) in switches_info[1:-1]:
            middle_switch_obj = globals.get_datapath_obj(middle_switch_id)
            middle_switch_ofp_parser = middle_switch_obj.ofproto_parser
            middle_switch_ofp = middle_switch_obj.ofproto

            mpls_flow_mod = middle_switch_ofp_parser.OFPFlowMod(
                datapath=middle_switch_obj,
                cookie=globals.alloc_cookie_id(),
                table_id=globals.MPLS_FILTERING_TABLE,
                command=middle_switch_ofp.OFPFC_ADD,
                priority=globals.TABLE_3_MPLS_SWITCH_PRIORITY,
                flags=middle_switch_ofp.OFPFF_SEND_FLOW_REM | middle_switch_ofp.OFPFF_CHECK_OVERLAP,
                match=middle_switch_ofp_parser.OFPMatch(
                    in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
                ),
                instructions=[
                    middle_switch_ofp_parser.OFPInstructionActions(
                        middle_switch_ofp.OFPIT_APPLY_ACTIONS,
                        [
                            middle_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                        ]
                    )
                ]
            )
            middle_switch_obj.send_msg(mpls_flow_mod)
            tunnel_cookies.append(mpls_flow_mod.cookie)
            globals.active_flows[mpls_flow_mod.cookie] = (mpls_flow_mod, middle_switch_id)

            mpls_flow_mod = middle_switch_ofp_parser.OFPFlowMod(
                datapath=middle_switch_obj,
                cookie=globals.alloc_cookie_id(),
                table_id=globals.MPLS_FILTERING_TABLE,
                command=middle_switch_ofp.OFPFC_ADD,
                priority=globals.TABLE_3_MPLS_SWITCH_PRIORITY,
                flags=middle_switch_ofp.OFPFF_SEND_FLOW_REM | middle_switch_ofp.OFPFF_CHECK_OVERLAP,
                match=middle_switch_ofp_parser.OFPMatch(
                    in_port=switch_out_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
                ),
                instructions=[
                    middle_switch_ofp_parser.OFPInstructionActions(
                        middle_switch_ofp.OFPIT_APPLY_ACTIONS,
                        [
                            middle_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
                        ]
                    )
                ]
            )
            middle_switch_obj.send_msg(mpls_flow_mod)
            tunnel_cookies.append(mpls_flow_mod.cookie)
            globals.active_flows[mpls_flow_mod.cookie] = (mpls_flow_mod, middle_switch_id)
            globals.send_msg(
                middle_switch_ofp_parser.OFPBarrierRequest(middle_switch_obj),
                reply_cls=middle_switch_ofp_parser.OFPBarrierReply
            )
        ###############################

        #
        # Side A configuration
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]

        side_a_switch_obj = globals.get_datapath_obj(unique_switch_id)
        side_a_switch_ofp_parser = side_a_switch_obj.ofproto_parser
        side_a_switch_ofp = side_a_switch_obj.ofproto
        # Host A to Host B specific ICMP4 flow - Side A
        side_a_host_to_mpls_flow = side_a_switch_ofp_parser.OFPFlowMod(
            datapath=side_a_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=side_a_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            flags=side_a_switch_ofp.OFPFF_SEND_FLOW_REM | side_a_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_a_switch_ofp_parser.OFPMatch(
                eth_dst=str(host_b_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4), ip_proto=inet.IPPROTO_ICMP
            ),
            instructions=[
                side_a_switch_ofp_parser.OFPInstructionActions(
                    side_a_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_a_switch_ofp_parser.OFPActionPushMpls(),
                        side_a_switch_ofp_parser.OFPActionSetField(mpls_label=mpls_label),
                    ]
                ),
                side_a_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.MPLS_FILTERING_TABLE),
            ]
        )
        print("-" * 10, side_a_host_to_mpls_flow)

        # MPLS ingression flow
        side_a_mpls_flow_mod = side_a_switch_ofp_parser.OFPFlowMod(
            datapath=side_a_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=side_a_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_3_MPLS_SWITCH_PRIORITY,
            flags=side_a_switch_ofp.OFPFF_SEND_FLOW_REM | side_a_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_a_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
            ),
            instructions=[
                side_a_switch_ofp_parser.OFPInstructionActions(
                    side_a_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_a_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                )
            ]
        )

        # Egress from tunnel to Side A
        egress_side_a_tunnel_flow = side_a_switch_ofp_parser.OFPFlowMod(
            datapath=side_a_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=side_a_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_3_MPLS_POP_PRIORITY,
            flags=side_a_switch_ofp.OFPFF_SEND_FLOW_REM | side_a_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_a_switch_ofp_parser.OFPMatch(
                in_port=switch_out_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
            ),
            instructions=[
                side_a_switch_ofp_parser.OFPInstructionActions(
                    side_a_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_a_switch_ofp_parser.OFPActionPopMpls(),
                    ]
                ),
                side_a_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.FOREIGN_HOST_FILTERING_TABLE)
            ]
        )

        # Host B to Host A specific ICMP4 flow - Side A
        foreign_host_side_a_flow = side_a_switch_ofp_parser.OFPFlowMod(
            datapath=side_a_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.FOREIGN_HOST_FILTERING_TABLE,
            command=side_a_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_5_LAYER_4_SPECIFIC_PRIORITY,
            flags=side_a_switch_ofp.OFPFF_SEND_FLOW_REM | side_a_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_a_switch_ofp_parser.OFPMatch(
                eth_src=str(host_b_entity_obj.mac), eth_dst=str(host_a_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_b_entity_obj.ipv4), ipv4_dst=str(host_a_entity_obj.ipv4), ip_proto=inet.IPPROTO_ICMP
            ),
            instructions=[
                side_a_switch_ofp_parser.OFPInstructionActions(
                    side_a_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_a_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
                    ]
                ),
            ]
        )

        side_a_switch_obj.send_msg(side_a_host_to_mpls_flow)
        side_a_switch_obj.send_msg(side_a_mpls_flow_mod)
        side_a_switch_obj.send_msg(egress_side_a_tunnel_flow)
        side_a_switch_obj.send_msg(foreign_host_side_a_flow)
        globals.send_msg(
            side_a_switch_ofp_parser.OFPBarrierRequest(side_a_switch_obj),
            reply_cls=side_a_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_cookies.append(side_a_host_to_mpls_flow.cookie)
        tunnel_cookies.append(side_a_mpls_flow_mod.cookie)
        tunnel_cookies.append(egress_side_a_tunnel_flow.cookie)
        tunnel_cookies.append(foreign_host_side_a_flow.cookie)

        globals.active_flows[side_a_host_to_mpls_flow.cookie] = (side_a_host_to_mpls_flow, unique_switch_id)
        globals.active_flows[side_a_mpls_flow_mod.cookie] = (side_a_mpls_flow_mod, unique_switch_id)
        globals.active_flows[egress_side_a_tunnel_flow.cookie] = (egress_side_a_tunnel_flow, unique_switch_id)
        globals.active_flows[foreign_host_side_a_flow.cookie] = (foreign_host_side_a_flow, unique_switch_id)
        ###############################

        #
        # Side B configuration
        (side_b_switch_id, switch_in_port, switch_out_port) = switches_info[-1]
        side_b_switch_obj = globals.get_datapath_obj(side_b_switch_id)
        side_b_switch_ofp_parser = side_b_switch_obj.ofproto_parser
        side_b_switch_ofp = side_b_switch_obj.ofproto

        # Host B to Host A specific ICMP4 flow - Side B
        ingress_side_b_tunnel_flow = side_b_switch_ofp_parser.OFPFlowMod(
            datapath=side_b_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=side_b_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            flags=side_b_switch_ofp.OFPFF_SEND_FLOW_REM | side_b_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_b_switch_ofp_parser.OFPMatch(
                eth_dst=str(host_b_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_b_entity_obj.ipv4), ipv4_dst=str(host_a_entity_obj.ipv4), ip_proto=inet.IPPROTO_ICMP
            ),
            instructions=[
                side_b_switch_ofp_parser.OFPInstructionActions(
                    side_b_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_b_switch_ofp_parser.OFPActionPushMpls(),
                        side_b_switch_ofp_parser.OFPActionSetField(mpls_label=mpls_label),
                    ]
                ),
                side_b_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.MPLS_FILTERING_TABLE),
            ]
        )

        # MPLS Side B ingression flow
        side_b_mpls_flow_mod = side_b_switch_ofp_parser.OFPFlowMod(
            datapath=side_b_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=side_b_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_3_MPLS_SWITCH_PRIORITY,
            flags=side_b_switch_ofp.OFPFF_SEND_FLOW_REM | side_b_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_b_switch_ofp_parser.OFPMatch(
                in_port=switch_out_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
            ),
            instructions=[
                side_b_switch_ofp_parser.OFPInstructionActions(
                    side_b_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_b_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
                    ]
                )
            ]
        )

        # Egress from tunnel to Side B
        egress_side_b_tunnel_flow = side_b_switch_ofp_parser.OFPFlowMod(
            datapath=side_b_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=side_b_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_3_MPLS_POP_PRIORITY,
            flags=side_b_switch_ofp.OFPFF_SEND_FLOW_REM | side_b_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_b_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
            ),
            instructions=[
                side_b_switch_ofp_parser.OFPInstructionActions(
                    side_b_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_b_switch_ofp_parser.OFPActionPopMpls(),
                    ]
                ),
                side_b_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.FOREIGN_HOST_FILTERING_TABLE),
            ]
        )

        # Host A to Host B specific ICMP4 flow - Side B
        foreign_host_side_b_flow = side_b_switch_ofp_parser.OFPFlowMod(
            datapath=side_b_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.FOREIGN_HOST_FILTERING_TABLE,
            command=side_b_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_5_LAYER_4_SPECIFIC_PRIORITY,
            flags=side_b_switch_ofp.OFPFF_SEND_FLOW_REM | side_b_switch_ofp.OFPFF_CHECK_OVERLAP,
            match=side_b_switch_ofp_parser.OFPMatch(
                eth_src=str(host_a_entity_obj.mac), eth_dst=str(host_b_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4), ip_proto=inet.IPPROTO_ICMP
            ),
            instructions=[
                side_b_switch_ofp_parser.OFPInstructionActions(
                    side_b_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        side_b_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        side_b_switch_obj.send_msg(ingress_side_b_tunnel_flow)
        side_b_switch_obj.send_msg(side_b_mpls_flow_mod)
        side_b_switch_obj.send_msg(egress_side_b_tunnel_flow)
        side_b_switch_obj.send_msg(foreign_host_side_b_flow)
        globals.send_msg(
            side_b_switch_ofp_parser.OFPBarrierRequest(side_b_switch_obj),
            reply_cls=side_b_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_cookies.append(ingress_side_b_tunnel_flow.cookie)
        tunnel_cookies.append(side_b_mpls_flow_mod.cookie)
        tunnel_cookies.append(egress_side_b_tunnel_flow.cookie)
        tunnel_cookies.append(foreign_host_side_b_flow.cookie)

        globals.active_flows[ingress_side_b_tunnel_flow.cookie] = (ingress_side_b_tunnel_flow, side_b_switch_id)
        globals.active_flows[side_b_mpls_flow_mod.cookie] = (side_b_mpls_flow_mod, side_b_switch_id)
        globals.active_flows[egress_side_b_tunnel_flow.cookie] = (egress_side_b_tunnel_flow, side_b_switch_id)
        globals.active_flows[foreign_host_side_b_flow.cookie] = (foreign_host_side_b_flow, unique_switch_id)
        ###############################


def __icmpv4_flow_activation_host_to_sector(bidirectional_path, mpls_label):
    entity_a_id = bidirectional_path[0]
    entity_b_id = bidirectional_path[-1]
    host_a_entity_obj = sector.query_entity(entity_a_id)
    host_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(host_a_entity_obj, Host), "a_entity_obj type is not Host"
    assert isinstance(host_b_entity_obj, Sector), "b_entity_obj type is not Sector"

    raise Exception("Flow activation from Host to Sector is not implemented yet.")


def __icmpv4_flow_activation_sector_to_host(bidirectional_path, mpls_label):
    entity_a_id = bidirectional_path[0]
    entity_b_id = bidirectional_path[-1]
    host_a_entity_obj = sector.query_entity(entity_a_id)
    host_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(host_a_entity_obj, Sector), "a_entity_obj type is not Sector"
    assert isinstance(host_b_entity_obj, Host), "b_entity_obj type is not Host"

    raise Exception("Flow activation from Sector to Host is not implemented yet.")


def __icmpv4_flow_activation_sector_to_sector(bidirectional_path, mpls_label):
    entity_a_id = bidirectional_path[0]
    entity_b_id = bidirectional_path[-1]
    host_a_entity_obj = sector.query_entity(entity_a_id)
    host_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(host_a_entity_obj, Sector), "a_entity_obj type is not Sector"
    assert isinstance(host_b_entity_obj, Sector), "b_entity_obj type is not Sector"

    raise Exception("Flow activation from Sector to Sector is not implemented yet.")


__activators = {
    (Host, Host): __icmpv4_flow_activation_host_to_host,
    (Host, Sector): __icmpv4_flow_activation_host_to_sector,
    (Sector, Host): __icmpv4_flow_activation_sector_to_host,
    (Sector, Sector): __icmpv4_flow_activation_sector_to_sector,
}


def icmpv4_flow_activation(bidirectional_path, mpls_label):
    """
        ICMP v4 Flow Activation

        This procedure contemplates 4 different scenarios:
        -> (Host, Host)
        -> (Host, Sector)
        -> (Sector, Sector)
        -> (Sector, Host)


    :param bidirectional_path:
    :param mpls_label:
    :return:
    """

    assert isinstance(bidirectional_path, sector.SectorPath), "bidirectional_path expected to be sector.SectorPath"
    assert bidirectional_path.is_bidirectional(), "bidirectional_path expected to be a bidiretional sector.SectorPath"

    host_a_entity_obj = sector.query_entity(bidirectional_path.entity_a)
    host_b_entity_obj = sector.query_entity(bidirectional_path.entity_b)

    __activators[(type(host_a_entity_obj), type(host_b_entity_obj))](bidirectional_path, mpls_label)

