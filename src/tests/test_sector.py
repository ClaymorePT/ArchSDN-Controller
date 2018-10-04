import unittest
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from netaddr import EUI

from ryu.ofproto import ofproto_v1_3

from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import exceptions


class ManageSwitch(unittest.TestCase):
    def setUp(self):
        self.switch_1 = entities.Switch(
            id=123456,
            control_ip=IPv4Address('192.168.123.1'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )

    def test_register_port(self):
        self.switch_1.register_port(
            port_no=1,
            hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
            name=b'eth0'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )

    def test_remove_port(self):
        self.switch_1.register_port(
            port_no=1,
            hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
            name=b'eth0'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        self.switch_1.remove_port(1)

    def test_double_port_registration(self):
        self.switch_1.register_port(
            port_no=1,
            hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
            name=b'eth0'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        with self.assertRaises(exceptions.PortAlreadyRegistered):
            self.switch_1.register_port(
                port_no=1,
                hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
                name=b'eth0'.decode('ascii'),
                config=entities.Switch.PORT_CONFIG(0),
                state=entities.Switch.PORT_STATE(4),
                curr=entities.Switch.PORT_FEATURES(2056),
                advertised=entities.Switch.PORT_FEATURES(0),
                supported=entities.Switch.PORT_FEATURES(0),
                peer=entities.Switch.PORT_FEATURES(0),
                curr_speed=0,
                max_speed=100
            )

    def test_port_not_registered(self):
        with self.assertRaises(exceptions.PortNotRegistered):
            self.switch_1.remove_port(1)


class ManageSector(unittest.TestCase):
    def setUp(self):
        self.sector_1 = entities.Sector(
            controller_id=UUID(int=1)
        )

    def test_register_port(self):
        self.sector_1.register_port(mac=EUI('11:22:33:44:55:66'))

    def test_remove_port(self):
        self.sector_1.register_port(mac=EUI('11:22:33:44:55:66'))
        self.sector_1.remove_port(mac=EUI('11:22:33:44:55:66'))

    def test_double_port_registration(self):
        self.sector_1.register_port(mac=EUI('11:22:33:44:55:66'))
        with self.assertRaises(exceptions.PortAlreadyRegistered):
            self.sector_1.register_port(mac=EUI('11:22:33:44:55:66'))

    def test_port_not_registered(self):
        with self.assertRaises(exceptions.PortNotRegistered):
            self.sector_1.remove_port(mac=EUI('11:22:33:44:55:66'))


class EntitiesManagement(unittest.TestCase):
    def setUp(self):
        sector.initialise()
        self.entities = (
            entities.Switch(
                id=123456,
                control_ip=IPv4Address('192.168.123.1'),
                control_port=6631,
                of_version=ofproto_v1_3.OFP_VERSION
            ),
            entities.Host(
                hostname='host_1',
                mac=EUI('11:22:33:44:55:66'),
                ipv4=IPv4Address('10.0.0.1'),
                ipv6=IPv6Address('fd61:7263:6873:646e::1')
            ),
            entities.Sector(
                controller_id=UUID(int=1)
            )
        )

    def tearDown(self):
        pass

    def test_register_switch(self):
        for entity in self.entities:
            with self.subTest(entity=entity):
                sector.register_entity(entity)
                self.assertTrue(sector.is_entity_registered(entity.id))

    def test_double_switch_registration(self):
        for entity in self.entities:
            with self.subTest(entity=entity):
                sector.register_entity(entity)
                self.assertTrue(sector.is_entity_registered(entity.id))
                with self.assertRaises(exceptions.EntityAlreadyRegistered):
                    sector.register_entity(entity)

    def test_remove_switch_registration(self):
        for entity in self.entities:
            with self.subTest(entity=entity):
                sector.register_entity(entity)
                self.assertTrue(sector.is_entity_registered(entity.id))
                sector.remove_entity(entity.id)

                with self.assertRaises(exceptions.EntityNotRegistered):
                    sector.remove_entity(entity.id)


class ConnectEntities(unittest.TestCase):
    def setUp(self):
        sector.initialise()

        self.switch_1 = entities.Switch(
            id=1,
            control_ip=IPv4Address('192.168.123.1'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )
        self.switch_1.register_port(
            port_no=1,
            hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
            name=b'eth0'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        self.switch_1.register_port(
            port_no=2,
            hw_addr=EUI('e0:d4:e8:6b:4d:f9'),
            name=b'eth1'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        self.switch_1.register_port(
            port_no=3,
            hw_addr=EUI('e0:d4:e8:6b:4d:fa'),
            name=b'eth2'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        self.switch_2 = entities.Switch(
            id=2,
            control_ip=IPv4Address('192.168.123.2'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )
        self.switch_2.register_port(
            port_no=1,
            hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
            name=b'eth0'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        self.host = entities.Host(
            hostname='host_1',
            mac=EUI('11:22:33:44:55:66'),
            ipv4=IPv4Address('10.0.0.1'),
            ipv6=IPv6Address('fd61:7263:6873:646e::1')
        )
        self.sector = entities.Sector(
            controller_id=UUID(int=1)
        )
        sector.register_entity(self.switch_1)
        sector.register_entity(self.switch_2)
        sector.register_entity(self.host)
        sector.register_entity(self.sector)

    def test_connect_entities(self):
        sector.connect_entities(self.switch_1.id, self.host.id, switch_port_no=1)
        sector.connect_entities(self.switch_1.id, self.switch_2.id, switch_a_port_no=2, switch_b_port_no=1)
        sector.connect_entities(self.switch_1.id, self.sector.id, switch_port_no=3, hash_val=0x0000)
        entity_id_1 = sector.query_connected_entity_id(self.switch_1.id, 1)
        entity_id_2 = sector.query_connected_entity_id(self.switch_1.id, 2)
        entity_id_3 = sector.query_connected_entity_id(self.switch_1.id, 3)
        self.assertTrue(
            isinstance(
                sector.query_entity(entity_id_1), entities.Host
            )
        )
        self.assertTrue(
            isinstance(
                sector.query_entity(entity_id_2), entities.Switch
            )
        )
        self.assertTrue(
            isinstance(
                sector.query_entity(entity_id_3), entities.Sector
            )
        )


class DisconnectEntities(unittest.TestCase):
    def setUp(self):
        sector.initialise()

        self.switch_1 = entities.Switch(
            id=1,
            control_ip=IPv4Address('192.168.123.1'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )
        self.switch_1.register_port(
            port_no=1,
            hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
            name=b'eth0'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        self.switch_2 = entities.Switch(
            id=2,
            control_ip=IPv4Address('192.168.123.2'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )
        self.switch_2.register_port(
            port_no=1,
            hw_addr=EUI('e0:d4:e8:6b:4d:f8'),
            name=b'eth0'.decode('ascii'),
            config=entities.Switch.PORT_CONFIG(0),
            state=entities.Switch.PORT_STATE(4),
            curr=entities.Switch.PORT_FEATURES(2056),
            advertised=entities.Switch.PORT_FEATURES(0),
            supported=entities.Switch.PORT_FEATURES(0),
            peer=entities.Switch.PORT_FEATURES(0),
            curr_speed=0,
            max_speed=100
        )
        self.host = entities.Host(
            hostname='host_1',
            mac=EUI('11:22:33:44:55:66'),
            ipv4=IPv4Address('10.0.0.1'),
            ipv6=IPv6Address('fd61:7263:6873:646e::1')
        )
        self.sector = entities.Sector(
            controller_id=UUID(int=1)
        )
        sector.register_entity(self.switch_1)
        sector.register_entity(self.switch_2)
        sector.register_entity(self.host)
        sector.register_entity(self.sector)

    def test_connect_switch_to_sector(self):
        sector.connect_entities(self.switch_1.id, self.host.id, switch_port_no=1)
        sector.disconnect_entities(self.switch_1.id, self.host.id, 1)
        self.assertTrue(not sector.are_entities_connected(self.switch_1.id, self.host.id))
        self.assertTrue(not sector.are_entities_connected(self.switch_1.id, self.host.id))

    def test_connect_switch_to_sector_no_port(self):
        sector.connect_entities(self.switch_1.id, self.host.id, switch_port_no=1)
        sector.disconnect_entities(self.switch_1.id, self.host.id)
        self.assertTrue(not sector.are_entities_connected(self.switch_1.id, self.host.id))
        self.assertTrue(not sector.are_entities_connected(self.switch_1.id, self.host.id))
