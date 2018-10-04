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
        self.assertEqual(database.dump_datapth_registered_ids(), (1, 2))

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
        self.assertEqual(database.dump_datapth_registered_clients_ids(1), (client_id_1, client_id_2))
        self.assertEqual(database.dump_datapth_registered_clients_ids(2), (client_id_3, client_id_4))

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

    def test_query_address_info_ipv4(self):
        client_id = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        database.update_client_addresses(client_id, ipv4=IPv4Address("10.0.0.2"), ipv6=IPv6Address(2))
        address_info = database.query_address_info(ipv4=IPv4Address("10.0.0.2"))
        self.assertIsInstance(address_info, dict)
        self.assertIn("client_id", address_info)
        self.assertIn("mac", address_info)
        self.assertIn("ipv6", address_info)
        self.assertIn("datapath", address_info)
        self.assertIn("port", address_info)
        self.assertIn("registration_date", address_info)
        self.assertIsInstance(address_info["client_id"], int)
        self.assertIsInstance(address_info["mac"], EUI)
        self.assertIsInstance(address_info["ipv6"], IPv6Address)
        self.assertIsInstance(address_info["datapath"], int)
        self.assertIsInstance(address_info["port"], int)
        self.assertIsInstance(address_info["registration_date"], time.struct_time)
        self.assertEqual(address_info["client_id"], client_id)
        self.assertEqual(address_info["mac"], EUI(10))
        self.assertEqual(address_info["ipv6"], IPv6Address(2))
        self.assertEqual(address_info["datapath"], 1)
        self.assertEqual(address_info["port"], 1)
        self.assertLessEqual(address_info["registration_date"], time.localtime())

    def test_query_address_info_ipv6(self):
        client_id = database.register_client(datapath_id=1, port_id=1, mac=EUI(10))
        database.update_client_addresses(client_id, ipv4=IPv4Address("10.0.0.2"), ipv6=IPv6Address(2))
        address_info = database.query_address_info(ipv6=IPv6Address(2))
        self.assertIsInstance(address_info, dict)
        self.assertIn("client_id", address_info)
        self.assertIn("mac", address_info)
        self.assertIn("ipv4", address_info)
        self.assertIn("datapath", address_info)
        self.assertIn("port", address_info)
        self.assertIn("registration_date", address_info)
        self.assertIsInstance(address_info["client_id"], int)
        self.assertIsInstance(address_info["mac"], EUI)
        self.assertIsInstance(address_info["ipv4"], IPv4Address)
        self.assertIsInstance(address_info["datapath"], int)
        self.assertIsInstance(address_info["port"], int)
        self.assertIsInstance(address_info["registration_date"], time.struct_time)
        self.assertEqual(address_info["client_id"], client_id)
        self.assertEqual(address_info["mac"], EUI(10))
        self.assertEqual(address_info["ipv4"], IPv4Address("10.0.0.2"))
        self.assertEqual(address_info["datapath"], 1)
        self.assertEqual(address_info["port"], 1)
        self.assertLessEqual(address_info["registration_date"], time.localtime())


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

