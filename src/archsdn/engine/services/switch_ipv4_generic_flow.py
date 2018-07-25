import logging

from ryu.ofproto import ether, inet

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn.engine import sector
from archsdn.engine.entities import Host, Sector
from archsdn.engine.services.abstracts import Service

_log = logging.getLogger(logger_module_name(__file__))


class __GenericIPv4Service(Service):

    def __init__(self, unidirectional, scenario_flows, mpls_label=None):
        self.__unidirectional_path = unidirectional
        self.__scenario_flows = scenario_flows
        self.__mpls_label = mpls_label

    def __del__(self):
        for flow_set in self.__scenario_flows:
            for flow in flow_set:
                switch_obj = globals.get_datapath_obj(flow.datapath.id)
                if switch_obj.is_active:
                    switch_ofp_parser = switch_obj.ofproto_parser
                    switch_ofp = switch_obj.ofproto
                    _log.debug("Removing flow with cookie ID 0x{:x}.".format(flow.cookie))

                    switch_obj.send_msg(  # Removes the registered flow from this switch.
                        switch_ofp_parser.OFPFlowMod(
                            datapath=switch_obj,
                            cookie=flow.cookie,
                            cookie_mask=0xFFFFFFFFFFFFFFFF,
                            table_id=switch_ofp.OFPTT_ALL,
                            command=switch_ofp.OFPFC_DELETE,
                            out_port=switch_ofp.OFPP_ANY,
                            out_group=switch_ofp.OFPG_ANY,
                        )
                    )
                    globals.send_msg(
                        switch_ofp_parser.OFPBarrierRequest(switch_obj),
                        reply_cls=switch_ofp_parser.OFPBarrierReply
                    )
        globals.free_mpls_label_id(self.__mpls_label)

    @property
    def label(self):
        return self.__mpls_label

    def uses_edge(self, node_a_id, node_b_id, output_port):
        return self.__unidirectional_path.uses_edge((node_a_id, node_b_id, output_port))

    def has_entity(self, entity_id):
        return self.__unidirectional_path.has_entity(entity_id)

    @property
    def service_q_value(self):
        return self.__unidirectional_path.service_q_value


def __ipv4_flow_activation_host_to_host(unidirectional_path, mpls_label):
    host_a_entity_id = unidirectional_path.entity_a
    host_b_entity_id = unidirectional_path.entity_b
    switches_info = unidirectional_path.switches_info
    host_a_entity_obj = sector.query_entity(host_a_entity_id)
    host_b_entity_obj = sector.query_entity(host_b_entity_id)

    assert isinstance(host_a_entity_obj, Host), "a_entity_obj type is not Host"
    assert isinstance(host_b_entity_obj, Host), "b_entity_obj type is not Host"

    if len(switches_info) == 1:
        # If the hosts are connected to the same switch, there's no need to create an MPLS tunnel.
        #   It is only necessary to forward the packets from one network interface to the other.

        # if src_port is None and dst_port is None:

        (single_switch_id, switch_in_port, switch_out_port) = switches_info[0]
        single_switch_obj = globals.get_datapath_obj(single_switch_id)
        single_switch_ofp_parser = single_switch_obj.ofproto_parser
        single_switch_ofp = single_switch_obj.ofproto

        # For All IPv4 Data
        flow_ipv4 = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.HOST_TABLE_LAYER_3_GENERIC_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4)
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
        single_switch_obj.send_msg(flow_ipv4)
        globals.send_msg(
            single_switch_ofp_parser.OFPBarrierRequest(single_switch_obj),
            reply_cls=single_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = ((flow_ipv4,), tuple(), tuple())

    else:
        # Multiswitch path requires an MPLS label to build a tunnel.
        assert isinstance(mpls_label, int), "mpls_label is not int"
        assert 0 <= mpls_label < pow(2, 20), "mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

        #  Information about the path switches.
        #  Core switches are those who are in the middle of the path, not on the edges.
        #  Edges switches are those who perform the ingress and egress packet procedures.
        #
        #  Tunnel implementation at path core switches
        mpls_tunnel_flows = []
        for (middle_switch_id, switch_in_port, switch_out_port) in switches_info[1:-1]:
            middle_switch_obj = globals.get_datapath_obj(middle_switch_id)
            middle_switch_ofp_parser = middle_switch_obj.ofproto_parser
            middle_switch_ofp = middle_switch_obj.ofproto

            mpls_flow_mod = middle_switch_ofp_parser.OFPFlowMod(
                datapath=middle_switch_obj,
                cookie=globals.alloc_cookie_id(),
                table_id=globals.MPLS_FILTERING_TABLE,
                command=middle_switch_ofp.OFPFC_ADD,
                priority=globals.SECTOR_TABLE_MPLS_SWITCH_PRIORITY,
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
            globals.send_msg(
                middle_switch_ofp_parser.OFPBarrierRequest(middle_switch_obj),
                reply_cls=middle_switch_ofp_parser.OFPBarrierReply
            )
            mpls_tunnel_flows.append(mpls_flow_mod)
        ###############################

        #
        #  Tunnel configuration from the ingressing side
        (ingressing_switch_id, ingressing_switch_in_port, ingressing_switch_out_port) = switches_info[0]
        ingressing_switch_obj = globals.get_datapath_obj(ingressing_switch_id)
        ingressing_switch_ofp_parser = ingressing_switch_obj.ofproto_parser
        ingressing_switch_ofp = ingressing_switch_obj.ofproto

        # For IPv4 Data
        ingress_side_a_tunnel_flow = ingressing_switch_ofp_parser.OFPFlowMod(
            datapath=ingressing_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=ingressing_switch_ofp.OFPFC_ADD,
            priority=globals.HOST_TABLE_LAYER_3_GENERIC_PRIORITY,
            match=ingressing_switch_ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4)
            ),
            instructions=[
                ingressing_switch_ofp_parser.OFPInstructionActions(
                    ingressing_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ingressing_switch_ofp_parser.OFPActionPushMpls(),
                        ingressing_switch_ofp_parser.OFPActionSetField(mpls_label=mpls_label),
                    ]
                ),
                ingressing_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.MPLS_FILTERING_TABLE),
            ]
        )

        # MPLS ingression flow
        side_a_mpls_flow_mod = ingressing_switch_ofp_parser.OFPFlowMod(
            datapath=ingressing_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=ingressing_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_SWITCH_PRIORITY,
            match=ingressing_switch_ofp_parser.OFPMatch(
                in_port=ingressing_switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
            ),
            instructions=[
                ingressing_switch_ofp_parser.OFPInstructionActions(
                    ingressing_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ingressing_switch_ofp_parser.OFPActionOutput(port=ingressing_switch_out_port)
                    ]
                )
            ]
        )

        ingressing_switch_obj.send_msg(ingress_side_a_tunnel_flow)
        ingressing_switch_obj.send_msg(side_a_mpls_flow_mod)
        globals.send_msg(
            ingressing_switch_ofp_parser.OFPBarrierRequest(ingressing_switch_obj),
            reply_cls=ingressing_switch_ofp_parser.OFPBarrierReply
        )

        ###############################

        # Tunnel configuration from egressing side
        (egress_switch_id, egress_switch_in_port, egress_switch_out_port) = switches_info[-1]
        egress_switch_obj = globals.get_datapath_obj(egress_switch_id)
        egressing_switch_ofp_parser = egress_switch_obj.ofproto_parser
        egressing_switch_ofp = egress_switch_obj.ofproto

        # MPLS egression flow
        egress_side_b_tunnel_flow = egressing_switch_ofp_parser.OFPFlowMod(
            datapath=egress_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=egressing_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_POP_PRIORITY,
            match=egressing_switch_ofp_parser.OFPMatch(
                in_port=egress_switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
            ),
            instructions=[
                egressing_switch_ofp_parser.OFPInstructionActions(
                    egressing_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        egressing_switch_ofp_parser.OFPActionPopMpls(),
                    ]
                ),
                egressing_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.FOREIGN_HOST_FILTERING_TABLE)
            ]
        )

        # Flow for IPv4 data sent from Host A to Host B
        foreign_host_flow = egressing_switch_ofp_parser.OFPFlowMod(
            datapath=egress_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.FOREIGN_HOST_FILTERING_TABLE,
            command=egressing_switch_ofp.OFPFC_ADD,
            priority=globals.FOREIGN_HOST_TABLE_LAYER_4_SPECIFIC_PRIORITY,
            match=egressing_switch_ofp_parser.OFPMatch(
                eth_src=str(host_a_entity_obj.mac), eth_dst=str(host_b_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4)
            ),
            instructions=[
                egressing_switch_ofp_parser.OFPInstructionActions(
                    egressing_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        egressing_switch_ofp_parser.OFPActionOutput(port=egress_switch_out_port)
                    ]
                ),
            ]
        )

        egress_switch_obj.send_msg(egress_side_b_tunnel_flow)
        egress_switch_obj.send_msg(foreign_host_flow)
        globals.send_msg(
            egressing_switch_ofp_parser.OFPBarrierRequest(egress_switch_obj),
            reply_cls=egressing_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = (
            (
                ingress_side_a_tunnel_flow,
                side_a_mpls_flow_mod,
            ),
            (
                egress_side_b_tunnel_flow,
                foreign_host_flow,
            ),
            tuple()
        )

    return __GenericIPv4Service(unidirectional_path, tunnel_flows, mpls_label)


def __ipv4_flow_activation_host_to_sector(unidirectional_path, local_mpls_label, target_ipv4):
    host_entity_id = unidirectional_path.entity_a
    sector_entity_id = unidirectional_path.entity_b
    switches_info = unidirectional_path.switches_info
    host_entity_obj = sector.query_entity(host_entity_id)
    sector_entity_obj = sector.query_entity(sector_entity_id)

    assert isinstance(host_entity_obj, Host), "host_entity_obj type is not Host"
    assert isinstance(sector_entity_obj, Sector), "sector_entity_obj type is not Sector"

    if len(switches_info) == 1:
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]
        single_switch_obj = globals.get_datapath_obj(unique_switch_id)
        single_switch_ofp_parser = single_switch_obj.ofproto_parser
        single_switch_ofp = single_switch_obj.ofproto

        ingress_from_local_host_to_foreign_host_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.HOST_TABLE_LAYER_3_GENERIC_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, ipv4_dst=str(target_ipv4), ipv4_src=str(host_entity_obj.ipv4)
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionPushMpls(),
                        single_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                    ]
                ),
                single_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.MPLS_FILTERING_TABLE),
            ]
        )

        ingress_to_sector_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_SWITCH_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
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

        single_switch_obj.send_msg(ingress_from_local_host_to_foreign_host_flow)
        single_switch_obj.send_msg(ingress_to_sector_flow)

        globals.send_msg(
            single_switch_ofp_parser.OFPBarrierRequest(single_switch_obj),
            reply_cls=single_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = (
            (ingress_from_local_host_to_foreign_host_flow,),
            tuple(),
            (ingress_to_sector_flow,)
        )

    else:
        # Multiswitch path requires an MPLS label to build a tunnel.
        assert isinstance(local_mpls_label, int), "mpls_label is not int"
        assert 0 <= local_mpls_label < pow(2, 20), "mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

        #  Information about the path switches.
        #  Core switches are those who are in the middle of the path, not on the edges.
        #  Edges switches are those who perform the ingress and egress packet procedures.
        #
        #  Tunnel implementation at path core switches
        mpls_tunnel_flows = []
        for (middle_switch_id, switch_in_port, switch_out_port) in switches_info[1:-1]:
            middle_switch_obj = globals.get_datapath_obj(middle_switch_id)
            middle_switch_ofp_parser = middle_switch_obj.ofproto_parser
            middle_switch_ofp = middle_switch_obj.ofproto

            mpls_flow_mod = middle_switch_ofp_parser.OFPFlowMod(
                datapath=middle_switch_obj,
                cookie=globals.alloc_cookie_id(),
                table_id=globals.MPLS_FILTERING_TABLE,
                command=middle_switch_ofp.OFPFC_ADD,
                priority=globals.MPLS_TABLE_MPLS_SWITCH_PRIORITY,
                match=middle_switch_ofp_parser.OFPMatch(
                    in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
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
            mpls_tunnel_flows.append(mpls_flow_mod)

            globals.send_msg(
                middle_switch_ofp_parser.OFPBarrierRequest(middle_switch_obj),
                reply_cls=middle_switch_ofp_parser.OFPBarrierReply
            )
        ###############################

        #
        # Host Side configuration
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]

        local_host_side_switch_obj = globals.get_datapath_obj(unique_switch_id)
        local_host_side_switch_ofp_parser = local_host_side_switch_obj.ofproto_parser
        local_host_side_switch_ofp = local_host_side_switch_obj.ofproto

        # Local Host to Foreign Host generic IPv4 flow - Side A
        local_host_to_foreign_host_ingression_flow = local_host_side_switch_ofp_parser.OFPFlowMod(
            datapath=local_host_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=local_host_side_switch_ofp.OFPFC_ADD,
            priority=globals.HOST_TABLE_LAYER_3_GENERIC_PRIORITY,
            match=local_host_side_switch_ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, ipv4_src=str(host_entity_obj.ipv4), ipv4_dst=str(target_ipv4)
            ),
            instructions=[
                local_host_side_switch_ofp_parser.OFPInstructionActions(
                    local_host_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        local_host_side_switch_ofp_parser.OFPActionPushMpls(),
                        local_host_side_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                    ]
                ),
                local_host_side_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.MPLS_FILTERING_TABLE),
            ]
        )

        # Ingression from Local Host into Local Path flow
        ingression_into_local_path_flow = local_host_side_switch_ofp_parser.OFPFlowMod(
            datapath=local_host_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=local_host_side_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_SWITCH_PRIORITY,
            match=local_host_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
            ),
            instructions=[
                local_host_side_switch_ofp_parser.OFPInstructionActions(
                    local_host_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        local_host_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                )
            ]
        )

        local_host_side_switch_obj.send_msg(local_host_to_foreign_host_ingression_flow)
        local_host_side_switch_obj.send_msg(ingression_into_local_path_flow)
        globals.send_msg(
            local_host_side_switch_ofp_parser.OFPBarrierRequest(local_host_side_switch_obj),
            reply_cls=local_host_side_switch_ofp_parser.OFPBarrierReply
        )
        ###############################

        #
        # Sector Side configuration
        (sector_side_switch_id, switch_in_port, switch_out_port) = switches_info[-1]
        sector_side_switch_obj = globals.get_datapath_obj(sector_side_switch_id)
        sector_side_switch_ofp_parser = sector_side_switch_obj.ofproto_parser
        sector_side_switch_ofp = sector_side_switch_obj.ofproto

        # Local Path to Sector Label Changing specific flow
        ingress_to_sector_from_local_tunnel_flow = sector_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=sector_side_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_CHANGE_PRIORITY,
            match=sector_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
            ),
            instructions=[
                sector_side_switch_ofp_parser.OFPInstructionActions(
                    sector_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        sector_side_switch_obj.send_msg(ingress_to_sector_from_local_tunnel_flow)

        globals.send_msg(
            sector_side_switch_ofp_parser.OFPBarrierRequest(sector_side_switch_obj),
            reply_cls=sector_side_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = (
            (
                local_host_to_foreign_host_ingression_flow,
                ingression_into_local_path_flow,
            ),
            (ingress_to_sector_from_local_tunnel_flow,),
            tuple(mpls_tunnel_flows)
        )
        ###############################

    return __GenericIPv4Service(unidirectional_path, tunnel_flows, local_mpls_label)


def __ipv4_flow_activation_sector_to_host(unidirectional_path, local_mpls_label, sector_mpls_label, source_ipv4):
    sector_entity_id = unidirectional_path.entity_a
    host_entity_id = unidirectional_path.entity_b
    switches_info = unidirectional_path.switches_info
    sector_entity_obj = sector.query_entity(sector_entity_id)
    host_entity_obj = sector.query_entity(host_entity_id)

    assert isinstance(sector_entity_obj, Sector), "sector_entity_obj type is not Sector"
    assert isinstance(host_entity_obj, Host), "host_entity_obj type is not Host"

    if len(switches_info) == 1:
        # If the hosts are connected to the same switch, there's no need to create an MPLS tunnel.
        #   It is only necessary to forward the packets from one network interface to the other.

        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]
        single_switch_obj = globals.get_datapath_obj(unique_switch_id)
        single_switch_ofp_parser = single_switch_obj.ofproto_parser
        single_switch_ofp = single_switch_obj.ofproto

        egression_from_sector_side_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_POP_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=sector_mpls_label
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionPopMpls(),
                    ]
                ),
                single_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.FOREIGN_HOST_FILTERING_TABLE)
            ]
        )

        foreign_host_egression_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.FOREIGN_HOST_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.FOREIGN_HOST_TABLE_LAYER_3_GENERIC_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, ipv4_src=str(source_ipv4), ipv4_dst=str(host_entity_obj.ipv4)
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        single_switch_obj.send_msg(egression_from_sector_side_flow)
        single_switch_obj.send_msg(foreign_host_egression_flow)

        globals.send_msg(
            single_switch_ofp_parser.OFPBarrierRequest(single_switch_obj),
            reply_cls=single_switch_ofp_parser.OFPBarrierReply
        )
        tunnel_flows = (
            tuple(),
            (foreign_host_egression_flow,),
            (egression_from_sector_side_flow,),
        )

    else:
        # Multiswitch path requires an MPLS label to build a tunnel.
        assert isinstance(local_mpls_label, int), "local_mpls_label is not int"
        assert 0 <= local_mpls_label < pow(2, 20), "local_mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

        #  Information about the path switches.
        #  Core switches are those who are in the middle of the path, not on the edges.
        #  Edges switches are those who perform the ingress and egress packet procedures.
        #
        #  Tunnel implementation at path core switches
        mpls_tunnel_flows = []
        for (middle_switch_id, switch_in_port, switch_out_port) in switches_info[1:-1]:
            middle_switch_obj = globals.get_datapath_obj(middle_switch_id)
            middle_switch_ofp_parser = middle_switch_obj.ofproto_parser
            middle_switch_ofp = middle_switch_obj.ofproto

            mpls_flow_mod = middle_switch_ofp_parser.OFPFlowMod(
                datapath=middle_switch_obj,
                cookie=globals.alloc_cookie_id(),
                table_id=globals.MPLS_FILTERING_TABLE,
                command=middle_switch_ofp.OFPFC_ADD,
                priority=globals.MPLS_TABLE_MPLS_SWITCH_PRIORITY,
                match=middle_switch_ofp_parser.OFPMatch(
                    in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
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
            mpls_tunnel_flows.append(mpls_flow_mod)

            globals.send_msg(
                middle_switch_ofp_parser.OFPBarrierRequest(middle_switch_obj),
                reply_cls=middle_switch_ofp_parser.OFPBarrierReply
            )
        ###############################

        #
        # Sector Side configuration
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]

        sector_side_switch_obj = globals.get_datapath_obj(unique_switch_id)
        sector_side_switch_ofp_parser = sector_side_switch_obj.ofproto_parser
        sector_side_switch_ofp = sector_side_switch_obj.ofproto

        # Sector to Local Path Label Update flow
        sector_to_local_path_label_update_flow = sector_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=sector_side_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_CHANGE_PRIORITY,
            match=sector_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=sector_mpls_label
            ),
            instructions=[
                sector_side_switch_ofp_parser.OFPInstructionActions(
                    sector_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_side_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                        sector_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )
        sector_side_switch_obj.send_msg(sector_to_local_path_label_update_flow)
        globals.send_msg(
            sector_side_switch_ofp_parser.OFPBarrierRequest(sector_side_switch_obj),
            reply_cls=sector_side_switch_ofp_parser.OFPBarrierReply
        )
        ###############################

        #
        # Local Host Side configuration
        (side_b_switch_id, switch_in_port, switch_out_port) = switches_info[-1]
        local_host_side_switch_obj = globals.get_datapath_obj(side_b_switch_id)
        local_host_side_switch_ofp_parser = local_host_side_switch_obj.ofproto_parser
        local_host_side_side_b_switch_ofp = local_host_side_switch_obj.ofproto

        # Egress from tunnel to Side B
        egress_local_tunnel_flow = local_host_side_switch_ofp_parser.OFPFlowMod(
            datapath=local_host_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=local_host_side_side_b_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_POP_PRIORITY,
            match=local_host_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
            ),
            instructions=[
                local_host_side_switch_ofp_parser.OFPInstructionActions(
                    local_host_side_side_b_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        local_host_side_switch_ofp_parser.OFPActionPopMpls(),
                    ]
                ),
                local_host_side_switch_ofp_parser.OFPInstructionGotoTable(table_id=globals.FOREIGN_HOST_FILTERING_TABLE),
            ]
        )

        # Host A to Host B generic IPv4 flow - Side B
        egress_foreign_host_to_local_host_flow = local_host_side_switch_ofp_parser.OFPFlowMod(
            datapath=local_host_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.FOREIGN_HOST_FILTERING_TABLE,
            command=local_host_side_side_b_switch_ofp.OFPFC_ADD,
            priority=globals.FOREIGN_HOST_TABLE_LAYER_3_GENERIC_PRIORITY,
            match=local_host_side_switch_ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, ipv4_src=str(source_ipv4), ipv4_dst=str(host_entity_obj.ipv4)
            ),
            instructions=[
                local_host_side_switch_ofp_parser.OFPInstructionActions(
                    local_host_side_side_b_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        local_host_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        local_host_side_switch_obj.send_msg(egress_local_tunnel_flow)
        local_host_side_switch_obj.send_msg(egress_foreign_host_to_local_host_flow)
        globals.send_msg(
            local_host_side_switch_ofp_parser.OFPBarrierRequest(local_host_side_switch_obj),
            reply_cls=local_host_side_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = (
            (sector_to_local_path_label_update_flow,),
            (
                egress_local_tunnel_flow,
                egress_foreign_host_to_local_host_flow,
            ),
            tuple(mpls_tunnel_flows)
        )
        ###############################

    return __GenericIPv4Service(unidirectional_path, tunnel_flows, local_mpls_label)


__activators = {
    (Host, Host): __ipv4_flow_activation_host_to_host,
    (Host, Sector): __ipv4_flow_activation_host_to_sector,
    (Sector, Host): __ipv4_flow_activation_sector_to_host,
}


def ipv4_generic_flow_activation(unidirectional_path,  *args, **kwargs):
    """
        IPv4 Generic Flow Activation

        This procedure contemplates 4 different scenarios:
        -> (Host, Host)
        -> (Host, Sector)
        -> (Sector, Host)


    :param unidirectional_path:
    :param mpls_label:
    :return:
    """

    assert isinstance(unidirectional_path, sector.SectorPath), "unidirectional_path expected to be sector.SectorPath"
    assert not unidirectional_path.is_bidirectional(), \
        "unidirectional_path expected to be an unidiretional sector.SectorPath"

    host_a_entity_obj = sector.query_entity(unidirectional_path.entity_a)
    host_b_entity_obj = sector.query_entity(unidirectional_path.entity_b)
    mapped_ipv4_services = globals.mapped_services["IPv4"]["*"]

    if (type(host_a_entity_obj), type(host_b_entity_obj)) not in __activators:
        raise TypeError(
            "Scenario {:s} Not supported. "
            "IPv4 generic service is only supported for the following scenarios: [{:s}].".format(
                str((type(host_a_entity_obj), type(host_b_entity_obj))),
                "; ".join(tuple((str(scn) for scn in __activators)))
            )
        )

    # Checking if IPv4 generic service is already established
    if (host_a_entity_obj.id, host_b_entity_obj.id) in mapped_ipv4_services:
        raise Exception(
            "IPv4 service for generic traffic from {:s} to {:s}, already exists.".format(
                str(host_a_entity_obj.id,), str(host_b_entity_obj.id)
            )
        )

    # Attempt to activate the service
    ipv4_service = __activators[(type(host_a_entity_obj), type(host_b_entity_obj))](
        unidirectional_path,  *args, **kwargs
    )

    # Registering the established service
    mapped_ipv4_services[(host_a_entity_obj.id, host_b_entity_obj.id)] = ipv4_service

    return ipv4_service
