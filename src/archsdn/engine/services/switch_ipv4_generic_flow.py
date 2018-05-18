import logging

from ryu.ofproto import ether, inet

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn.engine import sector
from archsdn.engine.entities import Host, Sector
from archsdn.engine.services.abstracts import Service

_log = logging.getLogger(logger_module_name(__file__))


class __GenericIPv4Service(Service):

    def __init__(self, unidirectional_path, scenario_flows, mpls_label=None):
        self.__unidirectional_path = unidirectional_path
        self.__scenario_flows = scenario_flows
        self.__mpls_label = mpls_label

    def __del__(self):
        flows = self.__scenario_flows[0] + self.__scenario_flows[1] + self.__scenario_flows[2]
        for flow in flows:
            switch_obj = flow.datapath
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

    def uses_edge(self, node_a, node_b, output_port):
        return self.__unidirectional_path.uses_edge((node_a, node_b, output_port))


def __ipv4_flow_activation_host_to_host(unidirectional_path, mpls_label):
    assert isinstance(unidirectional_path, sector.SectorPath), "unidirectional_path expected to be sector.SectorPath"
    assert not unidirectional_path.is_bidirectional(), \
        "unidirectional_path expected to be an unidirectional sector.SectorPath"

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
        flow_tcp = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_3_GENERIC_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                eth_dst=str(host_b_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4)
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
        single_switch_obj.send_msg(flow_tcp)
        globals.send_msg(
            single_switch_ofp_parser.OFPBarrierRequest(single_switch_obj),
            reply_cls=single_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = ((flow_tcp,), tuple(), tuple())

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
                priority=globals.TABLE_2_MPLS_SWITCH_PRIORITY,
                match=middle_switch_ofp_parser.OFPMatch(
                    in_port=switch_in_port,
                    eth_type=ether.ETH_TYPE_MPLS,
                    mpls_label=mpls_label
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
        #  Tunnel configuration from ingressing side
        (ingressing_switch_id, switch_in_port, switch_out_port) = switches_info[0]
        ingressing_switch_obj = globals.get_datapath_obj(ingressing_switch_id)
        ingressing_switch_ofp_parser = ingressing_switch_obj.ofproto_parser
        ingressing_switch_ofp = ingressing_switch_obj.ofproto

        # For IPv4 Data
        ingress_side_a_tunnel_flow = ingressing_switch_ofp_parser.OFPFlowMod(
            datapath=ingressing_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.HOST_FILTERING_TABLE,
            command=ingressing_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_3_GENERIC_PRIORITY,
            match=ingressing_switch_ofp_parser.OFPMatch(
                eth_dst=str(host_b_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_a_entity_obj.ipv4), ipv4_dst=str(host_b_entity_obj.ipv4)
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
            priority=globals.TABLE_3_MPLS_SWITCH_PRIORITY,
            match=ingressing_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=mpls_label
            ),
            instructions=[
                ingressing_switch_ofp_parser.OFPInstructionActions(
                    ingressing_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ingressing_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
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
        (egress_switch_id, switch_in_port, switch_out_port) = switches_info[-1]
        egress_switch_obj = globals.get_datapath_obj(egress_switch_id)
        egressing_switch_ofp_parser = egress_switch_obj.ofproto_parser
        egressing_switch_ofp = egress_switch_obj.ofproto

        # MPLS egression flow
        egress_side_b_tunnel_flow = egressing_switch_ofp_parser.OFPFlowMod(
            datapath=egress_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=egressing_switch_ofp.OFPFC_ADD,
            priority=globals.TABLE_2_MPLS_POP_PRIORITY,
            match=egressing_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port,
                eth_type=ether.ETH_TYPE_MPLS,
                mpls_label=mpls_label
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
            priority=globals.TABLE_4_LAYER_4_SPECIFIC_PRIORITY,
            match=egressing_switch_ofp_parser.OFPMatch(
                eth_src=str(host_b_entity_obj.mac), eth_dst=str(host_a_entity_obj.mac), eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(host_b_entity_obj.ipv4), ipv4_dst=str(host_a_entity_obj.ipv4), ip_proto=inet.IPPROTO_ICMP
            ),
            instructions=[
                egressing_switch_ofp_parser.OFPInstructionActions(
                    egressing_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        egressing_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
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


def __ipv4_flow_activation_host_to_sector(unidirectional_path, mpls_label):
    entity_a_id = unidirectional_path[0]
    entity_b_id = unidirectional_path[-1]
    host_a_entity_obj = sector.query_entity(entity_a_id)
    host_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(host_a_entity_obj, Host), "a_entity_obj type is not Host"
    assert isinstance(host_b_entity_obj, Sector), "b_entity_obj type is not Sector"

    raise Exception("Flow activation from Host to Sector is not implemented yet.")


def __ipv4_flow_activation_sector_to_host(unidirectional_path, mpls_label):
    entity_a_id = unidirectional_path[0]
    entity_b_id = unidirectional_path[-1]
    host_a_entity_obj = sector.query_entity(entity_a_id)
    host_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(host_a_entity_obj, Sector), "a_entity_obj type is not Sector"
    assert isinstance(host_b_entity_obj, Host), "b_entity_obj type is not Host"

    raise Exception("Flow activation from Sector to Host is not implemented yet.")


def __ipv4_flow_activation_sector_to_sector(unidirectional_path, mpls_label):
    entity_a_id = unidirectional_path[0]
    entity_b_id = unidirectional_path[-1]
    host_a_entity_obj = sector.query_entity(entity_a_id)
    host_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(host_a_entity_obj, Sector), "a_entity_obj type is not Sector"
    assert isinstance(host_b_entity_obj, Sector), "b_entity_obj type is not Sector"

    raise Exception("Flow activation from Sector to Sector is not implemented yet.")


__activators = {
    (Host, Host): __ipv4_flow_activation_host_to_host,
    (Host, Sector): __ipv4_flow_activation_host_to_sector,
    (Sector, Host): __ipv4_flow_activation_sector_to_host,
    (Sector, Sector): __ipv4_flow_activation_sector_to_sector,
}


def ipv4_generic_flow_activation(unidirectional_path, mpls_label):
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

    if (type(host_a_entity_obj), type(host_b_entity_obj)) == (Sector, Sector):
        raise TypeError("Sector to Sector tunnel IPv4 tunnel makes no sense.")

    # Checking if IPv4 generic service is already established
    mapped_ipv4_services = globals.mapped_services["IPv4"]["*"]
    if (host_a_entity_obj.id, host_b_entity_obj.id) in mapped_ipv4_services:
        raise Exception(
            "IPv4 service for generic traffic from {:s} to {:s}, already exists.".format(
                str(host_a_entity_obj.id,), str(host_b_entity_obj.id)
            )
        )

    # Attempt to activate the service
    ipv4_service = __activators[(type(host_a_entity_obj), type(host_b_entity_obj))](unidirectional_path, mpls_label)

    # Registering the established service
    mapped_ipv4_services[(host_a_entity_obj.id, host_b_entity_obj.id)] = ipv4_service
