import blosc
import logging
from eventlet import sleep
from eventlet.green import zmq
from eventlet.semaphore import BoundedSemaphore
from archsdn import zmq_messages
from uuid import UUID
from ipaddress import IPv4Address, IPv6Address
from archsdn.zmq_messages import loads, dumps
from archsdn.helpers import logger_module_name

__semaphore = None
__context = None
__socket = None
__pool = None
__location = None

__socket_timeout = 2000  # receive timeout milliseconds
__socket_connect_timeout = 2000  # receive timeout milliseconds
__socket_retries = 3  # number of retries before fail
_log = logging.getLogger(logger_module_name(__file__))


# Central communication exceptions
class CentralException(Exception):
    pass


class ConnectionFailed(CentralException):
    pass


class MakeRequestFailed(CentralException):
    pass


class UnexpectedResponse(CentralException):
    def __init__(self, response):
        self.response = response


class ControllerAlreadyRegistered(CentralException):
    pass


class ControllerNotRegistered(CentralException):
    pass


class ClientNotRegistered(CentralException):
    pass


class ClientAlreadyRegistered(CentralException):
    pass


class IPv4InfoAlreadyRegistered(CentralException):
    pass


class IPv6InfoAlreadyRegistered(CentralException):
    pass

class NoResultsAvailable(CentralException):
    pass


def initialise(central_ip, central_port):
    global __semaphore, __context, __socket, __location, __pool
    _log.info(
        "Initializing communication to central manager (ip: {:s}; port: {:d})".format(
            str(central_ip),
            central_port
        )
    )

    __location = "tcp://{:s}:{:d}".format(str(central_ip), central_port)
    __semaphore = BoundedSemaphore()
    __context = zmq.Context()
    __pool = zmq.Poller()
    __socket = __context.socket(zmq.REQ)
    __socket.connect(__location)
    __pool.register(__socket, zmq.POLLIN)
    _log.info("Initializing communication to central manager is complete.")


def __make_request(obj):
    global __socket
    assert __semaphore and __context and __location, "communication not initialised"

    obj_byte_seq = blosc.compress(dumps(obj))
    retries_left = __socket_retries

    while retries_left:
        __socket.send(obj_byte_seq)
        events = dict(__pool.poll(__socket_timeout))

        if events and events[__socket] == zmq.POLLIN:
            return loads(blosc.decompress(__socket.recv(), as_bytearray=True))

        else:
            _log.warning(
                "No response from central manager, retrying ({:d} out of {:d}) …".format(
                    __socket_retries - retries_left + 1,
                    __socket_retries
                )
            )
            __socket.setsockopt(zmq.LINGER, 0)
            __socket.close()
            __pool.unregister(__socket)
            retries_left -= 1
            if retries_left == 0:
                _log.error("Central manager seems to be offline. Aborting.")
                raise ConnectionFailed()
            _log.warning("Reconnecting and resending...")
            # Create new connection
            __socket = __context.socket(zmq.REQ)
            __socket.connect(__location)
            __pool.register(__socket, zmq.POLLIN)


def query_central_network_policies():
    assert __semaphore and __context and __socket and __location, "communication not initialised"

    with __semaphore:
        msg = zmq_messages.REQCentralNetworkPolicies()

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLCentralNetworkPolicies):
            return answer

        raise UnexpectedResponse(answer)



def register_controller(controller_id, ipv4_info=None, ipv6_info=None):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
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

    with __semaphore:
        msg = zmq_messages.REQRegisterController(
            controller_id, ipv4_info, ipv6_info
        )

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLSuccess):
            return

        if isinstance(answer, zmq_messages.RPLControllerAlreadyRegistered):
            raise ControllerAlreadyRegistered()

        if isinstance(answer, zmq_messages.RPLIPv4InfoAlreadyRegistered):
            raise IPv4InfoAlreadyRegistered()

        if isinstance(answer, zmq_messages.RPLIPv6InfoAlreadyRegistered):
            raise IPv6InfoAlreadyRegistered()

        raise UnexpectedResponse(answer)


def is_controller_registered(controller_id):
    assert __semaphore and __context and __socket and __location, "communication not initialised"

    with __semaphore:
        msg = zmq_messages.REQIsControllerRegistered(
            controller_id
        )

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLAfirmative):
            return True

        if isinstance(answer, zmq_messages.RPLNegative):
            return False

        raise UnexpectedResponse(answer)


def update_controller_address(controller_id, ipv4_info=None, ipv6_info=None):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
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

    with __semaphore:
        msg = zmq_messages.REQUpdateControllerInfo(
            controller_id, ipv4_info, ipv6_info
        )

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLSuccess):
            return

        if isinstance(answer, zmq_messages.RPLControllerNotRegistered):
            raise ControllerNotRegistered()

        if isinstance(answer, zmq_messages.RPLIPv4InfoAlreadyRegistered):
            raise IPv4InfoAlreadyRegistered()

        if isinstance(answer, zmq_messages.RPLIPv6InfoAlreadyRegistered):
            raise IPv6InfoAlreadyRegistered()

        raise UnexpectedResponse(answer)


def query_controller_info(controller_id):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
    assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"

    with __semaphore:
        msg = zmq_messages.REQQueryControllerInfo(
            controller_id
        )

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLControllerInformation):
            return answer

        if isinstance(answer, zmq_messages.RPLControllerNotRegistered):
            raise ControllerNotRegistered()

        raise UnexpectedResponse(answer)


def unregister_controller(controller_id):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
    assert isinstance(controller_id, UUID), "uuid is not a uuid.UUID object instance"

    with __semaphore:
        msg = zmq_messages.REQUnregisterController(
            controller_id
        )

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLSuccess):
            return

        if isinstance(answer, zmq_messages.RPLControllerNotRegistered):
            raise ControllerNotRegistered()

        raise UnexpectedResponse(answer)


def register_client(controller_uuid, client_id):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
    assert isinstance(controller_uuid, UUID), \
        "controller_uuid is not an UUID instance: type {}".format(type(controller_uuid))
    assert isinstance(client_id, int), "host_local_id is not int"
    assert client_id >= 0, "client_id is cannot be negative"

    with __semaphore:
        msg = zmq_messages.REQRegisterControllerClient(
            controller_uuid, client_id
        )

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLSuccess):
            return

        if isinstance(answer, zmq_messages.RPLControllerNotRegistered):
            raise ControllerNotRegistered()

        if isinstance(answer, zmq_messages.RPLClientAlreadyRegistered):
            raise ClientAlreadyRegistered()

        raise UnexpectedResponse(answer)


def query_client_info(controller_uuid, client_id):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
    assert isinstance(controller_uuid, UUID), \
        "controller_uuid is not an UUID instance: type {}".format(type(controller_uuid))
    assert isinstance(client_id, int), "host_local_id is not int"
    assert client_id >= 0, "client_id is cannot be negative"

    with __semaphore:
        msg = zmq_messages.REQClientInformation(
            controller_uuid, client_id
        )

        answer = __make_request(msg)
        if isinstance(answer, zmq_messages.RPLClientInformation):
            return answer

        if isinstance(answer, zmq_messages.RPLClientNotRegistered):
            raise ClientNotRegistered()

        raise UnexpectedResponse(answer)


def remove_client(controller_uuid, client_id):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
    assert isinstance(controller_uuid, UUID), \
        "controller_uuid is not an UUID instance: type {}".format(type(controller_uuid))
    assert isinstance(client_id, int), "host_local_id is not int"
    assert client_id >= 0, "client_id is cannot be negative"

    with __semaphore:
        msg = zmq_messages.REQRemoveControllerClient(
            controller_uuid, client_id
        )

        answer = __make_request(msg)

        if isinstance(answer, zmq_messages.RPLSuccess):
            return
        if isinstance(answer, zmq_messages.RPLClientNotRegistered):
            raise ClientNotRegistered()
        if isinstance(answer, zmq_messages.RPLControllerNotRegistered):
            raise ControllerNotRegistered()
        raise UnexpectedResponse(answer)


def query_address_info(ipv4=None, ipv6=None):
    assert __semaphore and __context and __socket and __location, "communication not initialised"
    assert not ((ipv4 is None) and (ipv6 is None)), "ipv4 and ipv6 cannot be null at the same time"
    assert isinstance(ipv4, IPv4Address) or ipv4 is None, "ipv4 is invalid"
    assert isinstance(ipv6, IPv6Address) or ipv6 is None, "ipv6 is invalid"

    with __semaphore:
        msg = zmq_messages.REQAddressInfo(ipv4, ipv6)

        answer = __make_request(msg)

        if isinstance(answer, zmq_messages.RPLAddressInfo):
            return answer
        if isinstance(answer, zmq_messages.RPLNoResultsAvailable):
            raise NoResultsAvailable()

