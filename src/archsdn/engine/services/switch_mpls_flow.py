import logging

from ryu.ofproto import ether

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn.engine import sector
from archsdn.engine.entities import Sector
from archsdn.engine.services.abstracts import Service

_log = logging.getLogger(logger_module_name(__file__))


class __MPLSService(Service):

    def __init__(self, local_path, scenario_flows, mpls_label):
        self.__local_path = local_path
        self.__scenario_flows = scenario_flows
        self.__mpls_label = mpls_label

    def __del__(self):
        flows = []
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
                globals.free_cookie_id(flow.cookie)
        globals.free_mpls_label_id(self.__mpls_label)

    def __str__(self):
        return "MPLS Service at 0x{:x}".format(id(self))

    @property
    def label(self):
        return self.__mpls_label

    def uses_edge(self, node_a_id, node_b_id, output_port):
        return self.__local_path.uses_edge((node_a_id, node_b_id, output_port))

    def has_entity(self, entity_id):
        return self.__local_path.has_entity(entity_id)

    def has_flow(self, cookie_id):
        for flow_set in self.__scenario_flows:
            for flow in flow_set:
                if flow.cookie == cookie_id:
                    return True
        return False

    @property
    def service_q_value(self):
        return self.__local_path.service_q_value


def __bidirectional_mpls_flow_activation(
        bidirectional_path, local_mpls_label, sector_a_mpls_label, sector_b_mpls_label
):
    entity_a_id = bidirectional_path.entity_a
    entity_b_id = bidirectional_path.entity_b
    switches_info = bidirectional_path.switches_info
    sector_a_entity_obj = sector.query_entity(entity_a_id)
    sector_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(sector_a_entity_obj, Sector), "sector_a_entity_obj type is not Sector"
    assert isinstance(sector_b_entity_obj, Sector), "sector_b_entity_obj type is not Sector"

    assert isinstance(local_mpls_label, int), "local_mpls_label is not int"
    assert 0 <= local_mpls_label < pow(2, 20), "local_mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

    assert isinstance(sector_a_mpls_label, int), "sector_a_mpls_label is not int"
    assert 0 <= sector_a_mpls_label < pow(2, 20), \
        "sector_a_mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

    assert isinstance(sector_b_mpls_label, int), "sector_b_mpls_label is not int"
    assert 0 <= sector_b_mpls_label < pow(2, 20), \
        "sector_b_mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

    mapped_mpls_services = globals.mapped_services["MPLS"]["TwoWay"]

    if ((sector_a_entity_obj.id, sector_a_mpls_label),
        (sector_b_entity_obj.id, sector_b_mpls_label)) in mapped_mpls_services:
        raise Exception(
            "MPLS service to cross traffic coming from Sector {:s} with Lable {:d}, "
            "directed to Sector {:s} with label {:d} is already implemented.".format(
                str(sector_a_entity_obj.id), sector_a_mpls_label, str(sector_b_entity_obj.id), sector_b_mpls_label
            )
        )

    if len(switches_info) == 1:
        # When there's only one switch in the path, it is only necessary to change the labels and switch the packets
        #  from one port to another

        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]
        single_switch_obj = globals.get_datapath_obj(unique_switch_id)
        single_switch_ofp_parser = single_switch_obj.ofproto_parser
        single_switch_ofp = single_switch_obj.ofproto

        label_change_sector_a_to_b_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_CHANGE_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=sector_a_mpls_label
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                        single_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        label_change_sector_b_to_a_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_CHANGE_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                in_port=switch_out_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=sector_b_mpls_label
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                        single_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
                    ]
                ),
            ]
        )

        single_switch_obj.send_msg(label_change_sector_a_to_b_flow)
        single_switch_obj.send_msg(label_change_sector_b_to_a_flow)

        globals.send_msg(
            single_switch_ofp_parser.OFPBarrierRequest(single_switch_obj),
            reply_cls=single_switch_ofp_parser.OFPBarrierReply
        )
        tunnel_flows = (
            (label_change_sector_a_to_b_flow,),
            (label_change_sector_b_to_a_flow,),
            tuple(),
        )

    else:
        # Multiswitch path requires an MPLS label to build a tunnel.

        #  Information about the path switches.
        #  Core switches are those who are in the middle of the path, not on the edges.
        #  Edges switches are those who perform the ingress and egress packet procedures.
        #
        #  Tunnel implementation at path core switches
        mpls_tunnel_flows = []
        for (middle_switch_id, switch_in_port, switch_out_port) in switches_info[1:-1]:
            assert isinstance(middle_switch_id, int), "middle_switch_id expected to be int. Got {:s}".format(
                repr(middle_switch_id)
            )
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

            mpls_flow_mod = middle_switch_ofp_parser.OFPFlowMod(
                datapath=middle_switch_obj,
                cookie=globals.alloc_cookie_id(),
                table_id=globals.MPLS_FILTERING_TABLE,
                command=middle_switch_ofp.OFPFC_ADD,
                priority=globals.MPLS_TABLE_MPLS_SWITCH_PRIORITY,
                match=middle_switch_ofp_parser.OFPMatch(
                    in_port=switch_out_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
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
            mpls_tunnel_flows.append(mpls_flow_mod)
            globals.send_msg(
                middle_switch_ofp_parser.OFPBarrierRequest(middle_switch_obj),
                reply_cls=middle_switch_ofp_parser.OFPBarrierReply
            )
        ###############################

        #
        # Sector A Side configuration
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]

        sector_a_side_switch_obj = globals.get_datapath_obj(unique_switch_id)
        sector_a_side_switch_ofp_parser = sector_a_side_switch_obj.ofproto_parser
        sector_a_side_switch_ofp = sector_a_side_switch_obj.ofproto

        # Sector A to Local Path Label Update flow
        sector_a_to_local_path_label_update_flow = sector_a_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_a_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=sector_a_side_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_CHANGE_PRIORITY,
            match=sector_a_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=sector_a_mpls_label
            ),
            instructions=[
                sector_a_side_switch_ofp_parser.OFPInstructionActions(
                    sector_a_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_a_side_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                        sector_a_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        # Local Path to Sector A Label Update flow
        local_path_to_sector_a_label_update_flow = sector_a_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_a_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=sector_a_side_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_CHANGE_PRIORITY,
            match=sector_a_side_switch_ofp_parser.OFPMatch(
                in_port=switch_out_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
            ),
            instructions=[
                sector_a_side_switch_ofp_parser.OFPInstructionActions(
                    sector_a_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_a_side_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
                    ]
                ),
            ]
        )

        sector_a_side_switch_obj.send_msg(sector_a_to_local_path_label_update_flow)
        sector_a_side_switch_obj.send_msg(local_path_to_sector_a_label_update_flow)
        globals.send_msg(
            sector_a_side_switch_ofp_parser.OFPBarrierRequest(sector_a_side_switch_obj),
            reply_cls=sector_a_side_switch_ofp_parser.OFPBarrierReply
        )
        ###############################

        #
        # Sector B Side configuration
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[-1]

        sector_b_side_switch_obj = globals.get_datapath_obj(unique_switch_id)
        sector_b_side_switch_ofp_parser = sector_b_side_switch_obj.ofproto_parser
        sector_b_side_switch_ofp = sector_b_side_switch_obj.ofproto

        # Sector B to Local Path Label Update flow
        sector_b_to_local_path_label_update_flow = sector_b_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_b_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=sector_b_side_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_CHANGE_PRIORITY,
            match=sector_b_side_switch_ofp_parser.OFPMatch(
                in_port=switch_out_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=sector_b_mpls_label
            ),
            instructions=[
                sector_b_side_switch_ofp_parser.OFPInstructionActions(
                    sector_b_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_b_side_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                        sector_b_side_switch_ofp_parser.OFPActionOutput(port=switch_in_port)
                    ]
                ),
            ]
        )

        # Local Path to Sector B Label Update flow
        local_path_to_sector_b_label_update_flow = sector_b_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_b_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=sector_b_side_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_CHANGE_PRIORITY,
            match=sector_b_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
            ),
            instructions=[
                sector_b_side_switch_ofp_parser.OFPInstructionActions(
                    sector_b_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_b_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        sector_b_side_switch_obj.send_msg(sector_b_to_local_path_label_update_flow)
        sector_b_side_switch_obj.send_msg(local_path_to_sector_b_label_update_flow)
        globals.send_msg(
            sector_b_side_switch_ofp_parser.OFPBarrierRequest(sector_b_side_switch_obj),
            reply_cls=sector_b_side_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = (
            (
                sector_a_to_local_path_label_update_flow,
                local_path_to_sector_a_label_update_flow,
            ),
            (
                sector_b_to_local_path_label_update_flow,
                local_path_to_sector_b_label_update_flow,
            ),
            tuple(mpls_tunnel_flows)
        )
        ###############################

    mpls_service = __MPLSService(bidirectional_path, tunnel_flows, local_mpls_label)
    mapped_mpls_services[
        (sector_a_entity_obj.id, sector_a_mpls_label),
        (sector_b_entity_obj.id, sector_b_mpls_label)
    ] = mpls_service
    return mpls_service


def __unidirectional_mpls_flow_activation(
        unidirectional_path, local_mpls_label, requesting_sector_mpls_label
):
    entity_a_id = unidirectional_path.entity_a
    entity_b_id = unidirectional_path.entity_b
    switches_info = unidirectional_path.switches_info
    sector_a_entity_obj = sector.query_entity(entity_a_id)
    sector_b_entity_obj = sector.query_entity(entity_b_id)

    assert isinstance(sector_a_entity_obj, Sector), "sector_a_entity_obj type is not Sector"
    assert isinstance(sector_b_entity_obj, Sector), "sector_b_entity_obj type is not Sector"

    # Multiswitch path requires an MPLS label to build a tunnel.
    assert isinstance(local_mpls_label, int), "local_mpls_label is not int"
    assert 0 <= local_mpls_label < pow(2, 20), "local_mpls_label expected to be between 0 and {:X}".format(pow(2, 20))
    assert isinstance(requesting_sector_mpls_label, int), "requesting_sector_mpls_label is not int"
    assert 0 <= requesting_sector_mpls_label < pow(2, 20), \
        "requesting_sector_mpls_label expected to be between 0 and {:X}".format(pow(2, 20))

    mapped_mpls_services = globals.mapped_services["MPLS"]["OneWay"]

    if ((sector_a_entity_obj.id, requesting_sector_mpls_label), (sector_b_entity_obj.id, None)) in mapped_mpls_services:
        raise Exception(
            "MPLS Unidirectional service to redirect traffic coming from Sector {:s} with Lable {:d}, to Sector {:s} is"
            " already implemented."
            "".format(
                str(sector_a_entity_obj.id), requesting_sector_mpls_label, str(sector_b_entity_obj.id)
            )
        )

    if len(switches_info) == 1:
        # When there's only one switch in the path, it is only necessary to change the labels and switch the packets
        #  from one port to another

        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]
        single_switch_obj = globals.get_datapath_obj(unique_switch_id)
        single_switch_ofp_parser = single_switch_obj.ofproto_parser
        single_switch_ofp = single_switch_obj.ofproto

        label_change_sector_a_to_b_flow = single_switch_ofp_parser.OFPFlowMod(
            datapath=single_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=single_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_CHANGE_PRIORITY,
            match=single_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=requesting_sector_mpls_label
            ),
            instructions=[
                single_switch_ofp_parser.OFPInstructionActions(
                    single_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        single_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                        single_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        single_switch_obj.send_msg(label_change_sector_a_to_b_flow)

        globals.send_msg(
            single_switch_ofp_parser.OFPBarrierRequest(single_switch_obj),
            reply_cls=single_switch_ofp_parser.OFPBarrierReply
        )
        tunnel_flows = (
            (label_change_sector_a_to_b_flow,),
            tuple(),
            tuple(),
        )
    else:

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
        # Sector A Side configuration
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[0]

        sector_a_side_switch_obj = globals.get_datapath_obj(unique_switch_id)
        sector_a_side_switch_ofp_parser = sector_a_side_switch_obj.ofproto_parser
        sector_a_side_switch_ofp = sector_a_side_switch_obj.ofproto

        # Sector A to Local Path Label Update flow
        sector_a_to_local_path_label_update_flow = sector_a_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_a_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.SECTOR_FILTERING_TABLE,
            command=sector_a_side_switch_ofp.OFPFC_ADD,
            priority=globals.SECTOR_TABLE_MPLS_CHANGE_PRIORITY,
            match=sector_a_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=requesting_sector_mpls_label
            ),
            instructions=[
                sector_a_side_switch_ofp_parser.OFPInstructionActions(
                    sector_a_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_a_side_switch_ofp_parser.OFPActionSetField(mpls_label=local_mpls_label),
                        sector_a_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        sector_a_side_switch_obj.send_msg(sector_a_to_local_path_label_update_flow)
        globals.send_msg(
            sector_a_side_switch_ofp_parser.OFPBarrierRequest(sector_a_side_switch_obj),
            reply_cls=sector_a_side_switch_ofp_parser.OFPBarrierReply
        )
        ###############################

        #
        # Sector B Side configuration
        (unique_switch_id, switch_in_port, switch_out_port) = switches_info[-1]

        sector_b_side_switch_obj = globals.get_datapath_obj(unique_switch_id)
        sector_b_side_switch_ofp_parser = sector_b_side_switch_obj.ofproto_parser
        sector_b_side_switch_ofp = sector_b_side_switch_obj.ofproto

        # Local Path to Sector B Label Update flow
        local_path_to_sector_b_label_update_flow = sector_b_side_switch_ofp_parser.OFPFlowMod(
            datapath=sector_b_side_switch_obj,
            cookie=globals.alloc_cookie_id(),
            table_id=globals.MPLS_FILTERING_TABLE,
            command=sector_b_side_switch_ofp.OFPFC_ADD,
            priority=globals.MPLS_TABLE_MPLS_SWITCH_PRIORITY,
            match=sector_b_side_switch_ofp_parser.OFPMatch(
                in_port=switch_in_port, eth_type=ether.ETH_TYPE_MPLS, mpls_label=local_mpls_label
            ),
            instructions=[
                sector_b_side_switch_ofp_parser.OFPInstructionActions(
                    sector_b_side_switch_ofp.OFPIT_APPLY_ACTIONS,
                    [
                        sector_b_side_switch_ofp_parser.OFPActionOutput(port=switch_out_port)
                    ]
                ),
            ]
        )

        sector_b_side_switch_obj.send_msg(local_path_to_sector_b_label_update_flow)
        globals.send_msg(
            sector_b_side_switch_ofp_parser.OFPBarrierRequest(sector_b_side_switch_obj),
            reply_cls=sector_b_side_switch_ofp_parser.OFPBarrierReply
        )

        tunnel_flows = (
            (
                sector_a_to_local_path_label_update_flow,
            ),
            (
                local_path_to_sector_b_label_update_flow,
            ),
            tuple(mpls_tunnel_flows)
        )
        ###############################

    mpls_service = __MPLSService(unidirectional_path, tunnel_flows, local_mpls_label)
    mapped_mpls_services[
        (sector_a_entity_obj.id, requesting_sector_mpls_label), (sector_b_entity_obj.id, None)
    ] = mpls_service
    return mpls_service


def sector_to_sector_mpls_flow_activation(local_path, *args, **kwargs):
    """
        MPLS Flow Activation

        This procedure contemplates the following scenarios:
        -> (Sector, Sector)


    :param local_path:
    :return:
    """

    assert isinstance(local_path, sector.SectorPath), "bidirectional_path expected to be sector.SectorPath"

    sector_a_entity_obj = sector.query_entity(local_path.entity_a)
    sector_b_entity_obj = sector.query_entity(local_path.entity_b)

    if (type(sector_a_entity_obj), type(sector_b_entity_obj)) != (Sector, Sector):
        raise TypeError("MPLS Flow activation is only supported for Sector to Sector scenarios,")

    if local_path.is_bidirectional():
        # Attempt to activate the service
        return __bidirectional_mpls_flow_activation(local_path, *args, **kwargs)

    else:
        # Attempt to activate the service
        return __unidirectional_mpls_flow_activation(local_path, *args, **kwargs)



