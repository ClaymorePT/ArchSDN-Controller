import unittest
from ipaddress import IPv4Address

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


class RegisterSwitch(unittest.TestCase):
    def setUp(self):
        sector.initialise()
        self.switch_1 = entities.Switch(
            id=123456,
            control_ip=IPv4Address('192.168.123.1'),
            control_port=6631,
            of_version=ofproto_v1_3.OFP_VERSION
        )

    def tearDown(self):
        pass

    def test_register_switch(self):
        sector.register_entity(self.switch_1)
        self.assertTrue(sector.is_entity_registered(self.switch_1))

    def test_double_switch_registration(self):
        sector.register_entity(self.switch_1)
        self.assertTrue(sector.is_entity_registered(self.switch_1))
        with self.assertRaises(exceptions.EntityAlreadyRegistered):
            sector.register_entity(self.switch_1)

    def test_remove_switch_registration(self):
        sector.register_entity(self.switch_1)
        self.assertTrue(sector.is_entity_registered(self.switch_1))
        sector.remove_entity(self.switch_1)

        with self.assertRaises(exceptions.EntityNotRegistered):
            sector.remove_entity(self.switch_1)

