import logging

from archsdn.helpers import logger_module_name
from archsdn.engine import globals
from archsdn import database

from ryu.ofproto import ether, inet

_log = logging.getLogger(logger_module_name(__file__))


def init_switch_flows(switch_obj):
    ofp_parser = switch_obj.ofproto_parser
    ofp = switch_obj.ofproto

    central_policies_addresses = database.query_volatile_info()
    ipv4_network = central_policies_addresses["ipv4_network"]
    ipv4_service = central_policies_addresses["ipv4_service"]
    mac_service = central_policies_addresses["mac_service"]

    #  Prepare __mapped_services to receive service activations
    #globals.mapped_services[switch_obj.id] = {
    #    "ICMP4": {},
    #    "IPv4": {},
    #    "MPLS": {},
    #}

    #
    # Reset Switch state and initialize bootstrap sequence
    #
    # When a switch connects, it is complex to know in which state it is.
    # So, it is preferable to clear all flows (if there are any) and restart everything.
    # Instructions order for proper reset of a switch
    #  1 -> Disable all ports, except for the control
    #  2 -> Clear all flow tables, group table and meter table

    switch_obj.send_msg(
        ofp_parser.OFPRoleRequest(
            switch_obj,
            ofp.OFPCR_ROLE_MASTER,
            0)
    )
    globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)

    # Stage 1 -> Disable all switching ports
    # for port_obj in switch_obj.ports.values():
    #     switch_obj.send_msg(
    #         ofp_parser.OFPPortMod(
    #             datapath=switch_obj,
    #             port_no=port_obj.port_no,
    #             hw_addr=port_obj.hw_addr,
    #             config=ofp.OFPPC_PORT_DOWN,
    #             mask=ofp.OFPPC_PORT_DOWN,
    #             advertise=0
    #         )
    #     )
    # globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)

    switch_obj.send_msg(  # Removes all flows registered in this switch.
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            table_id=ofp.OFPTT_ALL,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            command=ofp.OFPFC_DELETE,
        )
    )

    # OVS 2.1 and Zodiac FX do not support group mods
    # datapath.send_msg(  # Removes all groups registered in this switch.
    #     ofp_parser.OFPGroupMod(
    #         datapath=datapath,
    #         command=ofp.OFPGC_DELETE,
    #         group_id=ofp.OFPG_ALL,
    #     )
    # )

    switch_obj.send_msg(  # Removes all meters registered in this switch.
        ofp_parser.OFPMeterMod(
            datapath=switch_obj,
            command=ofp.OFPMC_DELETE,
            meter_id=ofp.OFPM_ALL,
        )
    )
    globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)

    # Stage 2 -> Configure Tables with default flows.

    # Inserting Table-Miss flows for all tables
    for table_no in globals.ARCHSDN_TABLES:
        switch_obj.send_msg(
            ofp_parser.OFPFlowMod(
                datapath=switch_obj,
                table_id=table_no,
                command=ofp.OFPFC_ADD,
                priority=globals.TABLE_MISS_PRIORITY,
                match=ofp_parser.OFPMatch(),
                instructions=[
                    ofp_parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, [])
                ]
            )
        )

    #  Default Flows for __PORT_SEGREGATION_TABLE are:
    #  - DHCP Boot
    #  - ArchSDN Discovery Beacon
    #  - Table-Miss
    default_flows = []

    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.PORT_SEGREGATION_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_0_DISCOVERY_PRIORITY,
            match=ofp_parser.OFPMatch(
                eth_dst='ff:ff:ff:ff:ff:ff', eth_type=ether.ETH_TYPE_IP,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=inet.IPPROTO_UDP,
                udp_src=68, udp_dst=67
            ),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                    ]
                )
            ]
        )
    )

    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.PORT_SEGREGATION_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_0_DISCOVERY_PRIORITY,
            match=ofp_parser.OFPMatch(eth_type=0xAAAA),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                    ]
                )
            ]
        )
    )

    #  Default Flows for __HOST_FILTERING_TABLE are:
    #  - DHCP packets from registered hosts, are redirected to controller.
    #  - ARP packets whose destination are IPs within the service network, are redirected to controller.
    #  - ICMP packets destined to the service IP network, are redirected to controller.
    #  - DNS packets destined to the service IP network, are redirected to controller.
    #  - IPv4 packets sent by a network host to another network host, are redirected to controller.

    # Flow for DHCP Requests
    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            match=ofp_parser.OFPMatch(
                eth_dst='ff:ff:ff:ff:ff:ff', eth_type=ether.ETH_TYPE_IP,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=inet.IPPROTO_UDP,
                udp_src=68, udp_dst=67
            ),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER)
                    ]
                )
            ]
        )
    )

    # Flow for ARP Requests
    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_3_GENERIC_PRIORITY,
            match=ofp_parser.OFPMatch(
                eth_dst='ff:ff:ff:ff:ff:ff', eth_type=ether.ETH_TYPE_ARP,
                arp_op=1, arp_tha='00:00:00:00:00:00',
                arp_spa=(str(ipv4_network.network_address), str(ipv4_network.netmask)),
                arp_tpa=(str(ipv4_network.network_address), str(ipv4_network.netmask)),
            ),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)
                    ]
                )
            ]
        )
    )

    # Activate a flow to redirect to the controller ICMP packets sent from the host to the
    #   controller, from pkt_in_port.
    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            match=ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP, eth_dst=str(mac_service),
                ipv4_dst=str(ipv4_service),
                ip_proto=inet.IPPROTO_ICMP,
            ),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)
                    ]
                )
            ]
        )
    )

    # Activate a flow to redirect to the controller DNS packets sent from the host to the
    #   controller, from pkt_in_port.
    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            match=ofp_parser.OFPMatch(
                eth_dst=str(mac_service), eth_type=ether.ETH_TYPE_IP,
                ipv4_dst=str(ipv4_service),
                ip_proto=inet.IPPROTO_UDP, udp_dst=53
            ),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)
                    ]
                )
            ]
        )
    )

    # Activate a flow to redirect to the controller, ipv4 packets sent by a network host to another network host.
    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_3_DEFAULT_PRIORITY,
            match=ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_src=(str(ipv4_network.network_address), str(ipv4_network.netmask)),
                ipv4_dst=(str(ipv4_network.network_address), str(ipv4_network.netmask)),
            ),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)
                    ]
                )
            ]
        )
    )

    # Service Denial for irregular packets
    # Activate a flow to drop ICMP Request packets, which the ipv4_source address is the service address
    default_flows.append(
        ofp_parser.OFPFlowMod(
            datapath=switch_obj,
            cookie=0,
            table_id=globals.HOST_FILTERING_TABLE,
            command=ofp.OFPFC_ADD,
            priority=globals.TABLE_1_LAYER_4_SPECIFIC_PRIORITY,
            match=ofp_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_src=str(ipv4_service),
                ip_proto=inet.IPPROTO_ICMP,
            ),
            instructions=[
                ofp_parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, [])
            ]
        )
    )


    for flow in default_flows:
        switch_obj.send_msg(flow)
    globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)

    # Stage 3 -> Enable all switching ports TODO: and send DHCP FORCERENEW ?? rfc3203
    # for port_obj in switch_obj.ports.values():
    #     switch_obj.send_msg(
    #         ofp_parser.OFPPortMod(
    #             datapath=switch_obj,
    #             port_no=port_obj.port_no,
    #             hw_addr=port_obj.hw_addr,
    #             config=0,
    #             mask=ofp.OFPPC_PORT_DOWN,
    #             advertise=0
    #         )
    #     )
    # globals.send_msg(ofp_parser.OFPBarrierRequest(switch_obj), reply_cls=ofp_parser.OFPBarrierReply)
