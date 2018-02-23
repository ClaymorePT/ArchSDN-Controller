import unittest
import time
import logging
import sys
from uuid import UUID
from netaddr import EUI
from ipaddress import IPv4Address, IPv6Address

from archsdn import database

log = logging.getLogger()
if sys.flags.debug:
    log.setLevel(logging.DEBUG)

database_location = ":memory:"


class DefaultInitAndclose(unittest.TestCase):
    def setUp(self):
        database.initialise(location=database_location, controller_id=UUID(int=1))

    def tearDown(self):
        database.close()

    def test_get_default_info(self):
        info = database.get_database_info()
        self.assertIsInstance(info, dict)
        self.assertIn("uuid", info)
        self.assertIn("creation_date", info)
        self.assertIsInstance(info["uuid"], UUID)
        self.assertIsInstance(info["creation_date"], time.struct_time)
        self.assertEqual(info["uuid"], UUID(int=1))
        self.assertLessEqual(info["creation_date"], time.localtime())


class DatabaseDatapathsOperations(unittest.TestCase):
    def setUp(self):
        database.initialise(location=database_location, controller_id=UUID(int=1))

    def tearDown(self):
        database.close()

    def test_addDatapath_ipv4(self):
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345))

    def test_addDatapath_ipv6(self):
        database.register_datapath(datapath_id=1, ipv6_info=(IPv6Address(1), 12345))

    def test_addDatapath_ipv4_ipv6(self):
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                   ipv6_info=(IPv6Address(1), 12345))

    def test_double_datapath_registration_exception(self):
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345))
        with self.assertRaises(database.DatapathAlreadyRegistered):
            database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345))
        with self.assertRaises(database.DatapathAlreadyRegistered):
            database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.2"), 1))


    def test_remove_datapath(self):
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                   ipv6_info=(IPv6Address(1), 12345))
        database.remove_datapath(datapath_id=1)
        with self.assertRaises(database.DatapathNotRegistered):
            database.query_datapath_info(datapath_id=1)

    def test_datapath_is_registered(self):
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                   ipv6_info=(IPv6Address(1), 12345))
        self.assertTrue(database.is_datapath_registered(datapath_id=1))
        database.remove_datapath(datapath_id=1)
        self.assertFalse(database.is_datapath_registered(datapath_id=1))


    def test_dump_datapath_ids(self):
            database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                       ipv6_info=(IPv6Address(1), 12345))
            database.register_datapath(datapath_id=2, ipv4_info=(IPv4Address("192.168.1.2"), 12345),
                                       ipv6_info=(IPv6Address(2), 12345))
            self.assertEquals(database.dump_datapth_registered_ids(), (1,2))


    def test_query_datapath_info(self):
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                   ipv6_info=(IPv6Address(1), 12345))
        datapath_info = database.query_datapath_info(datapath_id=1)
        self.assertIsInstance(datapath_info, dict)
        self.assertIn("ipv4", datapath_info)
        self.assertIn("ipv4_port", datapath_info)
        self.assertIn("ipv6", datapath_info)
        self.assertIn("ipv6_port", datapath_info)
        self.assertIn("registration_date", datapath_info)
        self.assertIsInstance(datapath_info["ipv4"], IPv4Address)
        self.assertIsInstance(datapath_info["ipv4_port"], int)
        self.assertIsInstance(datapath_info["ipv6"], IPv6Address)
        self.assertIsInstance(datapath_info["ipv6_port"], int)
        self.assertIsInstance(datapath_info["registration_date"], time.struct_time)
        self.assertEqual(datapath_info["ipv4"], IPv4Address("192.168.1.1"))
        self.assertEqual(datapath_info["ipv4_port"], 12345)
        self.assertEqual(datapath_info["ipv6"], IPv6Address(1))
        self.assertEqual(datapath_info["ipv6_port"], 12345)
        self.assertLessEqual(datapath_info["registration_date"], time.localtime())


class DatabaseClientsOperations(unittest.TestCase):
    def setUp(self):
        database.initialise(location=database_location, controller_id=UUID(int=1))
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                   ipv6_info=(IPv6Address(1), 12345))

    def tearDown(self):
        database.close()

    def test_register_client(self):
        client_id = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        database.update_client_addresses(client_id, ipv4=IPv4Address("10.0.0.2"), ipv6=IPv6Address(1))

    def test_query_host_client(self):
        client_id = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        database.update_client_addresses(client_id, ipv4=IPv4Address("10.0.0.2"), ipv6=IPv6Address(1))
        client_info = database.query_client_info(client_id=client_id)
        self.assertIsInstance(client_info, dict)
        self.assertIn("datapath", client_info)
        self.assertIn("port", client_info)
        self.assertIn("mac", client_info)
        self.assertIn("ipv4", client_info)
        self.assertIn("ipv6", client_info)
        self.assertIn("registration_date", client_info)
        self.assertIsInstance(client_info["datapath"], int)
        self.assertIsInstance(client_info["port"], int)
        self.assertIsInstance(client_info["mac"], EUI)
        self.assertIsInstance(client_info["ipv4"], IPv4Address)
        self.assertIsInstance(client_info["ipv6"], IPv6Address)
        self.assertIsInstance(client_info["registration_date"], time.struct_time)
        self.assertEqual(client_info["datapath"], 1)
        self.assertEqual(client_info["port"], 1)
        self.assertEqual(client_info["mac"], EUI(10))
        self.assertEqual(client_info["ipv4"], IPv4Address("10.0.0.2"))
        self.assertEqual(client_info["ipv6"], IPv6Address(1))
        self.assertLessEqual(client_info["registration_date"], time.localtime())


    def test_dump_datapath_clients(self):
        client_id_1 = database.register_client(datapath_id=1, port_id=1, mac=EUI(12))
        client_id_2 = database.register_client(datapath_id=1, port_id=2, mac=EUI(13))
        client_id_3 = database.register_client(datapath_id=2, port_id=1, mac=EUI(14))
        client_id_4 = database.register_client(datapath_id=2, port_id=2, mac=EUI(15))
        self.assertEquals(database.dump_datapth_registered_clients_ids(1), (client_id_1, client_id_2))
        self.assertEquals(database.dump_datapth_registered_clients_ids(2), (client_id_3, client_id_4))


    def test_double_register_client(self):
        client_id = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        database.update_client_addresses(client_id, ipv4=IPv4Address("10.0.0.2"), ipv6=IPv6Address(1))
        with self.assertRaises(database.ClientAlreadyRegistered):
            database.register_client(datapath_id=1, port_id=1, mac=EUI(10))

    def test_query_client_id(self):
        client_id = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        client_id_query = database.query_client_id(datapath_id=1, port_id=1, mac=EUI(10))
        self.assertEqual(client_id, client_id_query)

    def test_remove_client(self):
        client_id = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        database.remove_client(client_id)
        with self.assertRaises(database.ClientNotRegistered):
            database.remove_client(client_id)


class DatabaseFlowsOperations(unittest.TestCase):
    def setUp(self):
        database.initialise(location=database_location, controller_id=UUID(int=1))
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                   ipv6_info=(IPv6Address(1), 12345))

    def tearDown(self):
        database.close()

    def test_save_flow(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        datapath_id = 1
        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )
        database.save_flow(datapath_id=datapath_id, flow_description=testing_flow.to_jsondict())

    def test_query_flow_info(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        datapath_id = 1
        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )

        cookie_id = database.save_flow(datapath_id=datapath_id, flow_description=testing_flow.to_jsondict())
        flow_info = database.query_flow(datapath_id=datapath_id, cookie_id=cookie_id)
        self.assertIsInstance(flow_info, tuple)
        self.assertEqual(len(flow_info), 2)
        self.assertIsInstance(flow_info[0], dict)
        self.assertIsInstance(flow_info[1], time.struct_time)
        self.assertIn("OFPFlowMod", flow_info[0])
        self.assertIn("cookie", flow_info[0]["OFPFlowMod"])
        self.assertEqual(flow_info[0]["OFPFlowMod"]["cookie"], cookie_id)
        self.assertLessEqual(flow_info[1], time.localtime())

    def test_remove_flow(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        datapath_id = 1
        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )

        cookie_id = database.save_flow(datapath_id=datapath_id, flow_description=testing_flow.to_jsondict())
        database.remove_flow(datapath_id=datapath_id, cookie_id=cookie_id)

    def test_inexistent_flow(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        datapath_id = 1
        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )

        cookie_id = database.save_flow(datapath_id=datapath_id, flow_description=testing_flow.to_jsondict())
        database.remove_flow(datapath_id=datapath_id, cookie_id=cookie_id)
        with self.assertRaises(database.FlowNotRegistered):
            database.remove_flow(datapath_id=datapath_id, cookie_id=cookie_id)

    def test_unregistered_datapath(self):
        with self.assertRaises(database.DatapathNotRegistered):
            database.query_flow(datapath_id=2, cookie_id=0)
        with self.assertRaises(database.DatapathNotRegistered):
            database.remove_flow(datapath_id=2, cookie_id=0)

    def test_get_all_flows(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )

        cookie_id_1 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        cookie_id_2 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        cookie_id_3 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        cookie_ids = database.query_flow_ids(datapath_id=1)
        self.assertIsInstance(cookie_ids, tuple)
        self.assertEqual(cookie_ids, (cookie_id_1, cookie_id_2, cookie_id_3))


class DatabaseDatapathAndClientsOperations(unittest.TestCase):
    def setUp(self):
        database.initialise(location=database_location, controller_id=UUID(int=1))
        database.register_datapath(datapath_id=1, ipv4_info=(IPv4Address("192.168.1.1"), 12345),
                                   ipv6_info=(IPv6Address(1), 12345))

    def tearDown(self):
        database.close()

    def test_delete_all_associated_clients(self):
        client_id_1 = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        client_id_2 = database.register_client(datapath_id=1, port_id=2, mac=EUI(10))

        database.remove_datapath(datapath_id=1)
        with self.assertRaises(database.ClientNotRegistered):
            database.remove_client(client_id_1)
        with self.assertRaises(database.ClientNotRegistered):
            database.query_client_info(client_id_2)

    def test_delete_all_associated_flows(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )

        cookie_id_1 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        cookie_id_2 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        database.remove_datapath(datapath_id=1)
        with self.assertRaises(database.DatapathNotRegistered):
            database.remove_flow(datapath_id=1, cookie_id=cookie_id_1)
        with self.assertRaises(database.DatapathNotRegistered):
            database.query_flow(datapath_id=1, cookie_id=cookie_id_2)

    def test_double_delete_inexistent_flow(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )

        cookie_id_1 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        cookie_id_2 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        database.remove_datapath(datapath_id=1)
        with self.assertRaises(database.DatapathNotRegistered):
            database.remove_flow(datapath_id=1, cookie_id=cookie_id_1)
        with self.assertRaises(database.DatapathNotRegistered):
            database.remove_flow(datapath_id=1, cookie_id=cookie_id_2)

    def test_double_query_info_inexistent_flow(self):
        from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput, OFPInstructionActions, OFPFlowMod
        from ryu.ofproto.ofproto_v1_3 import \
            OFPP_CONTROLLER, OFPCML_NO_BUFFER, OFPIT_APPLY_ACTIONS, OFPFC_ADD, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM, \
            OFPFF_CHECK_OVERLAP

        testing_flow = OFPFlowMod(
            0,
            0,  # Lets use this field to index a dictionary with every active flow in the Switch.
            0, 0, OFPFC_ADD, 0, 0, 0, 0, OFPP_ANY, OFPG_ANY, OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP,
            OFPMatch(
                in_port=0,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_type=0x0800,
                ipv4_src="0.0.0.0", ipv4_dst="255.255.255.255", ip_proto=17, udp_src=68,
                udp_dst=67
            ),
            [OFPInstructionActions(OFPIT_APPLY_ACTIONS,
                                   [OFPActionOutput(port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER)])]
        )

        cookie_id_1 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        cookie_id_2 = database.save_flow(datapath_id=1, flow_description=testing_flow.to_jsondict())
        database.remove_datapath(datapath_id=1)
        with self.assertRaises(database.DatapathNotRegistered):
            database.query_flow(datapath_id=1, cookie_id=cookie_id_1)
        with self.assertRaises(database.DatapathNotRegistered):
            database.query_flow(datapath_id=1, cookie_id=cookie_id_2)


