from abc import ABC, abstractmethod
from uuid import UUID
from ipaddress import IPv4Address, IPv6Address
from enum import IntFlag

from netaddr import EUI

from ryu.ofproto.ofproto_protocol import _versions, _supported_versions
from archsdn.engine.exceptions import PortAlreadyRegistered, PortNotRegistered


class Entity(ABC):

    def __repr__(self):
        return "<{:s} type> object at address 0x{:X}".format(type(self).__name__, id(self))

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def __hash__(self):
        pass

    @property
    @abstractmethod
    def id(self):
        pass


class Switch(Entity):
    class PORT_CONFIG(IntFlag):
        OFPPC_PORT_DOWN = 1 << 0
        OFPPC_NO_RECV = 1 << 2
        OFPPC_NO_FWD = 1 << 5
        OFPPC_NO_PACKET_IN = 1 << 6

    class PORT_STATE(IntFlag):
        OFPPS_LINK_DOWN = 1 << 0
        OFPPS_BLOCKED = 1 << 1
        OFPPS_LIVE = 1 << 2

    class PORT_FEATURES(IntFlag):
        OFPPF_10MB_HD = 1 << 0
        OFPPF_10MB_FD = 1 << 1
        OFPPF_100MB_HD = 1 << 2
        OFPPF_100MB_FD = 1 << 3
        OFPPF_1GB_HD = 1 << 4
        OFPPF_1GB_FD = 1 << 5
        OFPPF_10GB_FD = 1 << 6
        OFPPF_40GB_FD = 1 << 7
        OFPPF_100GB_FD = 1 << 8
        OFPPF_1TB_FD = 1 << 9
        OFPPF_OTHER = 1 << 10
        OFPPF_COPPER = 1 << 11
        OFPPF_FIBER = 1 << 12
        OFPPF_AUTONEG = 1 << 13
        OFPPF_PAUSE = 1 << 14
        OFPPF_PAUSE_ASYM = 1 << 15

    def __init__(self, id, control_ip, control_port, of_version):
        assert isinstance(id, int), "dp is not an int instance. Got {:s}".format(
            repr(id)
        )
        assert 0 <= id <= 0xFFFFFFFFFFFFFFFF, "id value is not valid. Got 0x{:016x}".format(
            id
        )
        assert isinstance(control_ip, (IPv4Address, IPv6Address)), \
            "control_ip is not an instance of IPv4Address or IPv6Address. Got {:s}".format(repr(control_ip))
        assert isinstance(control_port, int), "control_port is not an int instance. Got {:s}".format(
            repr(control_port)
        )
        assert 0 <= control_port <= 0xFFFF, "control_port value is not valid. Got {:d}".format(
            control_port
        )
        assert isinstance(of_version, int), "of_version is not an int instance. Got {:s}".format(
            repr(of_version)
        )
        assert of_version in _supported_versions, "of_version is not supported. Got 0x{:0x}".format(
            of_version
        )

        self.__id = id
        self.__control_ip = control_ip
        self.__control_port = control_port
        self.__ports = {}
        self.__of_version = of_version

    def __str__(self):
        return "<Switch type> object at address 0x{:x}: datapath_id= 0x{:016x}".format(
            id(self), self.__id
        )

    def __hash__(self):
        return self.__id

    @property
    def id(self):
        '''
            Gets the Switch Identification
        '''
        return self.__id

    @property
    def ports(self):
        return self.__ports

    @property
    def of_version(self):
        return self.__of_version

    def register_port(
            self,
            port_no, hw_addr, name, config, state, curr, advertised, supported, peer, curr_speed, max_speed
        ):
        assert isinstance(port_no, int), "port_no is not int. Got {:s}".format(repr(port_no))
        assert 1 <= port_no <= 0xFFFFFFFFFFFFFFFF, "1 <= port_no <= 0xFFFFFFFFFFFFFFFF. Got {:d}".format(port_no)
        assert isinstance(hw_addr, EUI), "hw_addr is not EUI. Got {:s}".format(repr(hw_addr))
        assert isinstance(name, str), "name is not str. Got {:s}".format(repr(name))
        assert isinstance(config, Switch.PORT_CONFIG), "config is not Switch.PORT_CONFIG. Got {:s}".format(repr(config))
        assert isinstance(state, Switch.PORT_STATE), "state is not Switch.PORT_STATE. Got {:s}".format(repr(state))
        assert isinstance(curr, Switch.PORT_FEATURES), "curr is not Switch.PORT_FEATURES. Got {:s}".format(repr(curr))
        assert isinstance(advertised, Switch.PORT_FEATURES), "advertised is not Switch.PORT_FEATURES. Got {:s}".format(repr(advertised))
        assert isinstance(supported, Switch.PORT_FEATURES), "supported is not Switch.PORT_FEATURES. Got {:s}".format(repr(supported))
        assert isinstance(peer, Switch.PORT_FEATURES), "peer is not Switch.PORT_FEATURES. Got {:s}".format(repr(peer))
        assert isinstance(max_speed, int), "max_speed is not int. Got {:s}".format(repr(max_speed))
        assert 0 <= max_speed <= 0xFFFFFFFFFFFFFFFF, "0 <= max_speed <= 0xFFFFFFFFFFFFFFFF. Got {:d}".format(
            max_speed)
        assert isinstance(curr_speed, int), "curr_speed is not int. Got {:s}".format(repr(curr_speed))
        assert 0 <= curr_speed <= max_speed, "0 <= curr_speed <= max_speed. Got {:d}".format(curr_speed)

        if port_no in self.__ports:
            raise PortAlreadyRegistered()

        self.__ports[port_no] = {
            'hw_addr': hw_addr,
            'name': name,
            'config': config,
            'state': state,
            'curr': curr,
            'advertised': advertised,
            'supported': supported,
            'peer': peer,
            'curr_speed': curr_speed,
            'max_speed': max_speed
        }

    def remove_port(self, port_no):
        assert isinstance(port_no, int), "port_no is not int. Got {:s}".format(repr(port_no))
        assert 1 <= port_no <= 0xFFFFFFFFFFFFFFFF, "1 <= port_no <= 0xFFFFFFFFFFFFFFFF. Got {:d}".format(port_no)

        if port_no not in self.__ports:
            raise PortNotRegistered()
        del self.__ports[port_no]


class Host(Entity):
    def __init__(self, hostname, mac, ipv4=None, ipv6=None):
        assert isinstance(hostname, str), \
            "hostname is not str.  Got {:s}".format(repr(hostname))
        assert len(hostname) != 0, "hostname length cannot be zero"
        assert isinstance(mac, EUI), \
            "mac is not an EUI object.  Got {:s}".format(repr(mac))
        assert isinstance(ipv4, (IPv4Address, type(None))), \
            "ipv4 is not None or instance of IPv4Address. Got {:s}".format(repr(ipv4))
        assert isinstance(ipv6, (IPv6Address, type(None))), \
            "ipv4 is not None or instance of IPv6Address. Got {:s}".format(repr(ipv6))
        assert not (ipv4 is None and ipv6 is None), "ipv4 and ipv6 cannot be None at the same time"

        self.__hostname = hostname
        self.__mac = mac
        self.__ipv4 = ipv4
        self.__ipv6 = ipv6

    def __str__(self):
        return "<Host type> object at address 0x{:x}: hostname= {:s}; mac= {:s}; ipv4= {:s};  ipv6= {:s}".format(
            id(self), str(self.__hostname), str(self.__mac), str(self.__ipv4), str(self.__ipv6)
        )

    def __hash__(self):
        return hash(self.__hostname)

    @property
    def id(self):
        '''
            Gets the Host Identification
        '''
        return self.__hostname

    @property
    def hostname(self):
        '''

        :return:
        '''
        return self.__hostname

    @property
    def mac(self):
        '''

        :return:
        '''
        return self.__mac

    @property
    def ipv4(self):
        '''

        :return:
        '''
        return self.__ipv4

    @property
    def ipv6(self):
        '''

        :return:
        '''
        return self.__ipv6


class Sector(Entity):
    def __init__(self, controller_id):
        assert isinstance(controller_id, UUID), "controller_id is not UUID. Got {:s}".format(
            repr(controller_id)
        )
        self.__controller_id = controller_id
        self.__ports = set()

    def __str__(self):
        return "<Sector type> object at address 0x{:x}: controller_id= {:s};".format(
            id(self), str(self.__controller_id)
        )

    def __hash__(self):
        return hash(self.__controller_id)

    @property
    def id(self):
        '''
            Gets the Sector Identification
        '''
        return self.__controller_id

    def register_port(self, mac):
        assert isinstance(mac, EUI), "mac is not EUI. Got {:s}".format(repr(mac))

        if mac in self.__ports:
            raise PortAlreadyRegistered()
        self.__ports.add(mac)

    def remove_port(self, mac):
        assert isinstance(mac, EUI), "mac is not EUI. Got {:s}".format(repr(mac))

        if mac not in self.__ports:
            raise PortNotRegistered()
        self.__ports.remove(mac)


