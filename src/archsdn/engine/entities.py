from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address

from ryu.ofproto.ofproto_protocol import _supported_versions


class Entity(ABC):

    def __repr__(self):
        return "<{:s} type> object at address 0x{:x}".format(type(self).__name__, id(self))

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
        return self.ports

