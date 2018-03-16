# coding=utf-8

import logging
from abc import ABC, abstractmethod
from uuid import UUID
from netaddr import EUI
from ipaddress import IPv4Address, IPv6Address, ip_network
import time
import sys
import pickle

from archsdn.helpers import logger_module_name

__log = logging.getLogger(logger_module_name(__file__))

__loading_dict = {}


def __register_msg(cls):
    def load_obj(state):
        obj = cls.__new__(cls)
        if state:
            obj.__setstate__(state)
        return obj
    __loading_dict[cls.__name__] = load_obj


def dumps(obj):
    data = (type(obj).__name__, obj.__getstate__())
    return pickle.dumps(data)


def loads(obj_bytes):
    (obj_name, obj_state) = pickle.loads(obj_bytes)
    assert isinstance(obj_name, str), "obj_name is not str"
    assert obj_name in __loading_dict, "class {:s} not registered".format(obj_name)
    return __loading_dict[obj_name](obj_state)

########################
## Abstract Messages ###
########################


class BaseMessage(ABC):
    '''
        Abstract Base Message for all message types
    '''
    _version = 1

    @abstractmethod
    def __getstate__(self):
        pass

    @abstractmethod
    def __setstate__(self, d):
        pass

    def __repr__(self):
        if sys.flags.debug:
            return str(self)
        return "{:s} at address 0x{:X}".format(
            str(self.__class__), id(self)
        )

    def __str__(self):
        return "{:s}: {:s}".format(
            str(self.__class__),
            "; ".join(list(("{}: {}".format(key, self.__dict__[key]) for key in self.__dict__)))
        )


class BaseError(BaseMessage, BaseException):
    '''
        Abstract Base Message for Errors
    '''
    pass


class RequestMessage(BaseMessage):
    '''
        Abstract Base Message for Requests
    '''
    pass


class ReplyMessage(BaseMessage):
    '''
        Abstract Base Message for Replies
    '''
    pass


########################
### Request Messages ###
########################

class REQWithoutState(RequestMessage):
    '''
        Base Message for messages which have no internal state.
        It implements the __getstate__ and __setstate__ for no state serialization.
    '''
    def __getstate__(self):
        return False

    def __setstate__(self, s):
        pass


class REQLocalTime(REQWithoutState):
    '''
        Message used to request the central time.
        Used mostly for debug.
    '''
    pass


class REQCentralNetworkPolicies(REQWithoutState):
    '''
        Message used to request the network centralized policies-
    '''
    pass


class REQRegisterController(RequestMessage):
    '''
        Message used to register controllers at the central manager.
        Attributes:
            - Controller ID - (uuid.UUID)
            - Controller IPv4 Info Tuple
              - IPv4 (ipaddress.IPv4Address)
              - Port (int) [0;0xFFFF]
            - Controller IPv6 Info Tuple
              - IPv6 (ipaddress.IPv6Address)
              - Port (int) [0;0xFFFF]
    '''

    def __init__(self, controller_id, ipv4_info=None, ipv6_info=None):
        assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"
        assert not ((ipv4_info is None) and (ipv6_info is None)), \
            "ipv4_info and ipv6_info cannot be null at the same time"
        assert (
                   isinstance(ipv4_info, tuple) and
                   isinstance(ipv4_info[0], IPv4Address) and
                   isinstance(ipv4_info[1], int)
               ) or ipv4_info is None, "ipv4_info is invalid: {:s}".format(str(ipv4_info))
        assert (
                    isinstance(ipv6_info, tuple) and
                    isinstance(ipv6_info[0], IPv6Address) and
                    isinstance(ipv6_info[1], int)
               ) or ipv6_info is None, "ipv6_info is invalid: {:s}".format(str(ipv6_info))

        self.controller_id = controller_id
        self.ipv4_info = ipv4_info
        self.ipv6_info = ipv6_info

    def __getstate__(self):
        return (
            self.controller_id.bytes,
            (self.ipv4_info[0].packed, self.ipv4_info[1]) if self.ipv4_info != None else None,
            (self.ipv6_info[0].packed, self.ipv6_info[1]) if self.ipv6_info != None else None
        )

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state[0])
        self.ipv4_info = (IPv4Address(state[1][0]), state[1][1]) if state[1] != None else None
        self.ipv6_info = (IPv6Address(state[2][0]), state[2][1]) if state[2] != None else None


class REQQueryControllerInfo(RequestMessage):
    '''
        Message used to request the detailed information about a controller.
        Attributes:
            - Controller ID - (uuid.UUID)
    '''
    def __init__(self, controller_id):
        assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"

        self.controller_id = controller_id

    def __getstate__(self):
        return self.controller_id.bytes

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state)


class REQUnregisterController(RequestMessage):
    '''
        Message used to remove a Controller registration.
        Attributes:
            - Controller ID - (uuid.UUID)
    '''

    def __init__(self, controller_id):
        assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"

        self.controller_id = controller_id

    def __getstate__(self):
        return self.controller_id.bytes

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state)


class REQIsControllerRegistered(RequestMessage):
    '''
        Message used to check if a Controller is Registered.
        Attributes:
            - Controller ID - (uuid.UUID)
    '''

    def __init__(self, controller_id):
        assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"

        self.controller_id = controller_id

    def __getstate__(self):
        return self.controller_id.bytes

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state)


class REQUpdateControllerInfo(RequestMessage):
    '''
        Message used to update the controller information
        Attributes:
            - Controller ID - (uuid.UUID)
            - Controller IPv4 Info Tuple
              - IPv4 (ipaddress.IPv4Address)
              - Port (int) [0;0xFFFF]
            - Controller IPv6 Info Tuple
              - IPv6 (ipaddress.IPv6Address)
              - Port (int) [0;0xFFFF]
    '''

    def __init__(self, controller_id, ipv4_info=None, ipv6_info=None):
        assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"
        #        assert not ((ipv4_info is None) and (
        #                    ipv6_info is None)), "ipv4_info and ipv6_info cannot be null at the same time"
        #        assert ipv4_info(ipv4_info) or ipv4_info is None, "ipv4_info is invalid"
        #        assert ipv6_info(ipv6_info) or ipv6_info is None, "ipv6_info is invalid"

        self.controller_id = controller_id
        self.ipv4_info = ipv4_info
        self.ipv6_info = ipv6_info

    def __getstate__(self):
        return (
            self.controller_id.bytes,
            (self.ipv4_info[0].packed, self.ipv4_info[1]) if self.ipv4_info != None else None,
            (self.ipv6_info[0].packed, self.ipv6_info[1]) if self.ipv6_info != None else None
        )

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state[0])
        self.ipv4_info = (IPv4Address(state[1][0]), state[1][1]) if state[1] != None else None
        self.ipv6_info = (IPv6Address(state[2][0]), state[2][1]) if state[2] != None else None


class REQRegisterControllerClient(RequestMessage):
    '''
        Message used to Register a network Client.
        Attributes:
            - Controller ID - (uuid.UUID)
            - Client ID - (int) [0;0xFFFFFFFF]
    '''
    def __init__(self, controller_id, client_id):
        assert isinstance(controller_id, UUID), \
            "uuid is not a uuid.UUID object instance: {:s}".format(repr(controller_id))
        assert isinstance(client_id, int), "client_id is not a int object instance: {:s}".format(repr(client_id))
        assert 0 < client_id < 0xFFFFFFFF, "client_id value is invalid: value {:d}".format(client_id)
        self.controller_id = controller_id
        self.client_id = client_id

    def __getstate__(self):
        return (
            self.controller_id.bytes,
            self.client_id.to_bytes(4, 'big')
        )

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state[0])
        self.client_id = int.from_bytes(state[1], 'big')


class REQRemoveControllerClient(RequestMessage):
    '''
        Message used to Remove a network Client Registration.
        Attributes:
            - Controller ID - (uuid.UUID)
            - Client ID - (int) [0;0xFFFFFFFF]
    '''
    def __init__(self, controller_id, client_id):
        assert isinstance(controller_id, UUID), \
            "uuid is not a uuid.UUID object instance: {:s}".format(repr(controller_id))
        assert isinstance(client_id, int), "client_id is not a int object instance: {:s}".format(repr(client_id))
        assert 0 < client_id < 0xFFFFFFFF, "client_id value is invalid: value {:d}".format(client_id)
        self.controller_id = controller_id
        self.client_id = client_id

    def __getstate__(self):
        return (
            self.controller_id.bytes,
            self.client_id.to_bytes(4, 'big')
        )

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state[0])
        self.client_id = int.from_bytes(state[1], 'big')


class REQIsClientAssociated(RequestMessage):
    '''
        Message used to query if a specific network Client registration exists.
        Attributes:
            - Controller ID - (uuid.UUID)
            - Client ID - (int) [0;0xFFFFFFFF]
    '''
    def __init__(self, controller_id, client_id):
        assert isinstance(controller_id, UUID), \
            "uuid is not a uuid.UUID object instance: {:s}".format(repr(controller_id))
        assert isinstance(client_id, int), "client_id is not a int object instance: {:s}".format(repr(client_id))
        assert 0 < client_id < 0xFFFFFFFF, "client_id value is invalid: value {:d}".format(client_id)
        self.controller_id = controller_id
        self.client_id = client_id

    def __getstate__(self):
        return (
            self.controller_id.bytes,
            self.client_id.to_bytes(4, 'big')
        )

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state[0])
        self.client_id = int.from_bytes(state[1], 'big')


class REQClientInformation(RequestMessage):
    '''
        Message used to query the information of a specific network Client registration.
        Attributes:
            - Controller ID - (uuid.UUID)
            - Client ID - (int) [0;0xFFFFFFFF]
    '''
    def __init__(self, controller_id, client_id):
        assert isinstance(controller_id, UUID), \
            "uuid is not a uuid.UUID object instance: {:s}".format(repr(controller_id))
        assert isinstance(client_id, int), "client_id is not a int object instance: {:s}".format(repr(client_id))
        assert 0 < client_id < 0xFFFFFFFF, "client_id value is invalid: value {:d}".format(client_id)
        self.controller_id = controller_id
        self.client_id = client_id

    def __getstate__(self):
        return (
            self.controller_id.bytes,
            self.client_id.to_bytes(4, 'big')
        )

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state[0])
        self.client_id = int.from_bytes(state[1], 'big')


class REQUnregisterAllClients(RequestMessage):
    '''
        Message used to remove all client registrations from a Controller.
        Attributes:
            - Controller ID - (uuid.UUID)
    '''

    def __init__(self, controller_id):
        assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"

        self.controller_id = controller_id

    def __getstate__(self):
        return self.controller_id.bytes

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state)


class REQAddressInfo(RequestMessage):
    '''
        Message used to request information about the network addresses.
        Attributes (one is required):
              - IPv4 (ipaddress.IPv4Address) - Optional
              - IPv6 (ipaddress.IPv6Address) - Optional

    '''

    def __init__(self, ipv4=None, ipv6=None):
        assert not ((ipv4 is None) and (ipv6 is None)), "ipv4 and ipv6 cannot be null at the same time"
        assert isinstance(ipv4, IPv4Address) or ipv4 is None, "ipv4 is invalid"
        assert isinstance(ipv6, IPv6Address) or ipv6 is None, "ipv6 is invalid"

        self.ipv4 = ipv4
        self.ipv6 = ipv6

    def __getstate__(self):
        return (
            self.ipv4.packed if self.ipv4 else None,
            self.ipv6.packed if self.ipv6 else None,
        )

    def __setstate__(self, state):
        self.ipv4 = IPv4Address(state[0]) if state[0] else None
        self.ipv6 = IPv6Address(state[1]) if state[1] else None


__register_msg(REQLocalTime)
__register_msg(REQCentralNetworkPolicies)
__register_msg(REQRegisterController)
__register_msg(REQQueryControllerInfo)
__register_msg(REQUnregisterController)
__register_msg(REQIsControllerRegistered)
__register_msg(REQUpdateControllerInfo)
__register_msg(REQRegisterControllerClient)
__register_msg(REQRemoveControllerClient)
__register_msg(REQIsClientAssociated)
__register_msg(REQClientInformation)
__register_msg(REQUnregisterAllClients)
__register_msg(REQAddressInfo)


########################
###  Reply Messages  ###
########################

class RPLWithoutState(ReplyMessage):
    '''
        Base Message for Replies with no state
    '''
    def __getstate__(self):
        return False

    def __setstate__(self, s):
        pass


class RPLSuccess(RPLWithoutState):
    '''
        Message returned when a Request is successfully processed.
    '''
    pass


class RPLAfirmative(RPLWithoutState):
    '''
        Afirmative Message returned as the result of the evaluation of a Proposition Request Message
    '''
    pass


class RPLNegative(RPLWithoutState):
    '''
        Message returned when a Request is successfully processed.
    '''
    pass


class RPLLocalTime(ReplyMessage):
    '''
        Message used to reply the local time.
    '''
    def __init__(self):
        self.__time = time.time()

    def __getstate__(self):
        return self.__time

    def __setstate__(self, state):
        self.__time = state


class RPLCentralNetworkPolicies(ReplyMessage):
    '''
        Message used to reply the network policies configurations
    '''

    def __init__(self, ipv4_network, ipv6_network, ipv4_service, ipv6_service, mac_service, registration_date):
        self.ipv4_network = ipv4_network
        self.ipv6_network = ipv6_network
        self.ipv4_service = ipv4_service
        self.ipv6_service = ipv6_service
        self.mac_service = mac_service
        self.registration_date = registration_date

    def __getstate__(self):
        return (
            self.ipv4_network.network_address.packed, int(self.ipv4_network.prefixlen),
            self.ipv6_network.network_address.packed, int(self.ipv6_network.prefixlen),
            self.ipv4_service.packed,
            self.ipv6_service.packed,
            int(self.mac_service),
            self.registration_date
        )

    def __setstate__(self, state):
        self.ipv4_network = ip_network((state[0], state[1]))
        self.ipv6_network = ip_network((state[2], state[3]))
        self.ipv4_service = IPv4Address(state[4])
        self.ipv6_service = IPv6Address(state[5])
        self.mac_service = EUI(state[6])
        self.registration_date = state[7]


class RPLControllerInformation(ReplyMessage):
    '''
        Message used by central manager to reply with the controller information
    '''

    def __init__(self, ipv4, ipv4_port, ipv6, ipv6_port, name, registration_date):
        self.ipv4 = ipv4
        self.ipv4_port = ipv4_port
        self.ipv6 = ipv6
        self.ipv6_port = ipv6_port
        self.name = name
        self.registration_date = registration_date

    def __getstate__(self):
        return (
            self.ipv4.packed, self.ipv4_port,
            self.ipv6.packed, self.ipv6_port,
            self.name.encode('ascii'),
            self.registration_date
        )

    def __setstate__(self, state):
        self.ipv4 = IPv4Address(state[0])
        self.ipv4_port = state[1]
        self.ipv6 = IPv6Address(state[2])
        self.ipv6_port = state[3]
        self.name = state[4].decode('ascii')
        self.registration_date = state[5]


class RPLClientInformation(ReplyMessage):
    '''
        Message used by central manager to reply with the controller information
    '''

    def __init__(self, ipv4, ipv6, name, registration_date):
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.name = name
        self.registration_date = registration_date

    def __getstate__(self):
        return (
            self.ipv4.packed,
            self.ipv6.packed,
            self.name.encode('ascii'),
            self.registration_date
        )

    def __setstate__(self, state):
        self.ipv4 = IPv4Address(state[0])
        self.ipv6 = IPv6Address(state[1])
        self.name = state[2].decode('ascii')
        self.registration_date = state[3]


class RPLAddressInfo(ReplyMessage):
    '''
        Message used by the central manager to reply with the information about the queried network address
    '''

    def __init__(self, controller_id, client_id, name, registration_date):
        assert isinstance(controller_id, UUID), \
            "uuid is not a uuid.UUID object instance: {:s}".format(repr(controller_id))
        assert isinstance(client_id, int), "client_id is not a int object instance: {:s}".format(repr(client_id))
        assert 0 <= client_id < 0xFFFFFFFF, "client_id value is invalid: value {:d}".format(client_id)

        self.controller_id = controller_id
        self.client_id = client_id
        self.name = name
        self.registration_date = registration_date

    def __getstate__(self):
        return (
            self.controller_id.bytes,
            self.client_id.to_bytes(4, 'big'),
            self.name.encode('ascii'),
            self.registration_date

        )

    def __setstate__(self, state):
        self.controller_id = UUID(bytes=state[0])
        self.client_id = int.from_bytes(state[1], 'big')
        self.name = state[2].decode('ascii')
        self.registration_date = state[3]


__register_msg(RPLSuccess)
__register_msg(RPLAfirmative)
__register_msg(RPLNegative)
__register_msg(RPLLocalTime)
__register_msg(RPLCentralNetworkPolicies)
__register_msg(RPLControllerInformation)
__register_msg(RPLClientInformation)
__register_msg(RPLAddressInfo)

###########################
## Subscription Messages ##
###########################


########################
###  Error Messages  ###
########################


class RPLGenericError(BaseError):
    '''
        Message used to reply a generic error
    '''
    def __init__(self, reason):
        assert isinstance(reason, str), "reason argument is not a string"
        self.reason = reason

    def __getstate__(self):
        return self.reason

    def __setstate__(self, state):
        self.reason = state

    def __str__(self):
        return "{}: {}".format(self.__class__, self.reason)


class RPLErrorNoState(BaseError):
    '''
        Error message with no state
    '''

    def __init__(self):
        pass

    def __getstate__(self):
        return False

    def __setstate__(self, state):
        pass


class RPLNoResultsAvailable(RPLErrorNoState):
    '''
         Error message to reply the absence of results
    '''
    pass


class RPLControllerNotRegistered(RPLErrorNoState):
    '''
       Error message to reply the absence of a controller registration
    '''
    pass


class RPLControllerAlreadyRegistered(RPLErrorNoState):
    '''
       Error message to reply that a controller registration already exists
    '''
    pass


class RPLClientNotRegistered(RPLErrorNoState):
    '''
       Error message to reply the absence of a network client registration
    '''
    pass


class RPLClientAlreadyRegistered(RPLErrorNoState):
    '''
       Error message to reply that a network client registration already exists
    '''
    pass


class RPLIPv4InfoAlreadyRegistered(RPLErrorNoState):
    '''
       Error message to reply that a specific IPv4 is already being used
    '''
    pass


class RPLIPv6InfoAlreadyRegistered(RPLErrorNoState):
    '''
        Error message to reply that a specific IPv6 is already being used
    '''
    pass


__register_msg(RPLGenericError)
__register_msg(RPLNoResultsAvailable)
__register_msg(RPLControllerNotRegistered)
__register_msg(RPLControllerAlreadyRegistered)
__register_msg(RPLClientNotRegistered)
__register_msg(RPLClientAlreadyRegistered)
__register_msg(RPLIPv4InfoAlreadyRegistered)
__register_msg(RPLIPv6InfoAlreadyRegistered)
