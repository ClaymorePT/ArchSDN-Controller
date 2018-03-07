import unittest
from ipaddress import IPv4Address

from ryu.ofproto import ofproto_v1_3

from archsdn.engine import sector
from archsdn.engine import entities
from archsdn.engine import exceptions


class RegisterEntities(unittest.TestCase):
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
