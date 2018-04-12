import unittest
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from netaddr import EUI

from ryu.ofproto import ofproto_v1_3

from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import exceptions


class CreateTunnel(unittest.TestCase):
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
            hw_addr=EUI('e0:00:00:00:01:01'),
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
            hw_addr=EUI('e0:00:00:00:01:02'),
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
        self.switch_2 = entities.Switch(
            id=2,
            control_ip=IPv4Address('192.168.123.2'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )
        self.switch_2.register_port(
            port_no=1,
            hw_addr=EUI('e0:00:00:00:02:01'),
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
        self.switch_2.register_port(
            port_no=2,
            hw_addr=EUI('e0:00:00:00:02:02'),
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
        self.switch_3 = entities.Switch(
            id=3,
            control_ip=IPv4Address('192.168.123.3'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )
        self.switch_3.register_port(
            port_no=1,
            hw_addr=EUI('e0:00:00:00:03:01'),
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
        self.switch_3.register_port(
            port_no=2,
            hw_addr=EUI('e0:00:00:00:03:02'),
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
        self.host_1 = entities.Host(
            hostname='host_1',
            mac=EUI('FE:00:00:00:00:01'),
            ipv4=IPv4Address('10.0.0.1'),
            ipv6=IPv6Address('fd61:7263:6873:646e::1')
        )
        self.host_2 = entities.Host(
            hostname='host_2',
            mac=EUI('FE:00:00:00:00:02'),
            ipv4=IPv4Address('10.0.0.2'),
            ipv6=IPv6Address('fd61:7263:6873:646e::2')
        )
        sector.register_entity(self.switch_1)
        sector.register_entity(self.switch_2)
        sector.register_entity(self.switch_3)
        sector.register_entity(self.host_1)
        sector.register_entity(self.host_2)

    def test_create_tunnel_with_bandwidth_4_elements(self):
        sector.connect_entities(self.switch_1.id, self.host_1.id, switch_port_no=1)
        sector.connect_entities(self.switch_2.id, self.host_2.id, switch_port_no=1)
        sector.connect_entities(self.switch_1.id, self.switch_2.id, switch_a_port_no=2, switch_b_port_no=2)

        scenario = sector.construct_bidirectional_path(
            self.host_1.id,
            self.host_2.id,
            100
        )

        self.assertTrue(isinstance(scenario, sector.SectorPath))
        self.assertTrue(scenario.has_entity(self.host_1.id))
        self.assertTrue(scenario.has_entity(self.host_2.id))
        self.assertTrue(scenario.has_entity(self.switch_1.id))
        self.assertTrue(scenario.has_entity(self.switch_2.id))
        self.assertTrue(scenario.uses_edge((self.host_1.id, self.switch_1.id, 1)))
        self.assertTrue(scenario.uses_edge((self.host_2.id, self.switch_2.id, 1)))
        self.assertTrue(scenario.uses_edge((self.switch_1.id, self.switch_2.id, 2)))
        self.assertTrue(scenario.uses_edge((self.switch_2.id, self.switch_1.id, 2)))

        self.assertFalse(scenario.uses_edge((self.host_1.id, self.switch_1.id, 2)))

    def test_create_tunnel_with_bandwidth_5_elements(self):
        sector.connect_entities(self.switch_1.id, self.host_1.id, switch_port_no=1)
        sector.connect_entities(self.switch_1.id, self.switch_2.id, switch_a_port_no=2, switch_b_port_no=1)
        sector.connect_entities(self.switch_2.id, self.switch_3.id, switch_a_port_no=2, switch_b_port_no=1)
        sector.connect_entities(self.switch_3.id, self.host_2.id, switch_port_no=2)

        scenario = sector.construct_bidirectional_path(
            self.host_1.id,
            self.host_2.id,
            100
        )

        self.assertTrue(isinstance(scenario, sector.SectorPath))
        self.assertTrue(scenario.has_entity(self.host_1.id))
        self.assertTrue(scenario.has_entity(self.host_2.id))
        self.assertTrue(scenario.has_entity(self.switch_1.id))
        self.assertTrue(scenario.has_entity(self.switch_2.id))
        self.assertTrue(scenario.uses_edge((self.host_1.id, self.switch_1.id, 1)))
        self.assertTrue(scenario.uses_edge((self.switch_1.id, self.host_1.id, 1)))
        self.assertTrue(scenario.uses_edge((self.switch_1.id, self.switch_2.id, 2)))
        self.assertTrue(scenario.uses_edge((self.switch_2.id, self.switch_1.id, 1)))
        self.assertTrue(scenario.uses_edge((self.switch_2.id, self.switch_3.id, 2)))
        self.assertTrue(scenario.uses_edge((self.switch_3.id, self.switch_2.id, 1)))
        self.assertTrue(scenario.uses_edge((self.host_2.id, self.switch_3.id, 2)))
        self.assertTrue(scenario.uses_edge((self.switch_3.id, self.host_2.id, 2)))

    def test_create_tunnel_with_bandwidth_delete_and_recreate(self):
        sector.connect_entities(self.switch_1.id, self.host_1.id, switch_port_no=1)
        sector.connect_entities(self.switch_2.id, self.host_2.id, switch_port_no=1)
        sector.connect_entities(self.switch_1.id, self.switch_2.id, switch_a_port_no=2, switch_b_port_no=2)

        scenario = sector.construct_bidirectional_path(
            self.host_1.id,
            self.host_2.id,
            100
        )
        del scenario
        sector.construct_unidirectional_path(
            self.host_1.id,
            self.host_2.id,
            100
        )

    def test_fail_to_create_tunnel_no_bandwidth_available(self):
        sector.connect_entities(self.switch_1.id, self.host_1.id, switch_port_no=1)
        sector.connect_entities(self.switch_2.id, self.host_2.id, switch_port_no=1)
        sector.connect_entities(self.switch_1.id, self.switch_2.id, switch_a_port_no=2, switch_b_port_no=2)

        with self.assertRaises(exceptions.PathNotFound):
            sector.construct_bidirectional_path(
                self.host_1.id,
                self.host_2.id,
                1000
            )

        scenario = sector.construct_bidirectional_path(
            self.host_1.id,
            self.host_2.id,
            100
        )
        with self.assertRaises(exceptions.PathNotFound):
            sector.construct_unidirectional_path(
                self.host_1.id,
                self.host_2.id,
                100
            )
