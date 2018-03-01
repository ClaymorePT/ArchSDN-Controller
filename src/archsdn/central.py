import blosc
import zmq
from eventlet import sleep
from eventlet.green import zmq
from eventlet.semaphore import BoundedSemaphore
from archsdn import zmq_messages
from uuid import UUID
from ipaddress import IPv4Address, IPv6Address
from archsdn.zmq_messages import loads, dumps


__semaphore = None
__context = None
__socket = None
__location = None

__socket_timeout = 2000  # receive timeout milliseconds


# Central communication exceptions
class CentralException(Exception):
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


def initialise(central_ip, central_port):
    global __semaphore, __context, __socket, __location
    __semaphore = BoundedSemaphore()
    __context = zmq.Context()
    __location = "tcp://{:s}:{:d}".format(str(central_ip), central_port)
    __socket = __context.socket(zmq.REQ)
    __socket.connect(__location)
    __socket.RCVTIMEO = __socket_timeout  # receive timeout milliseconds


def __make_request(obj):
    global __socket
    assert __semaphore and __context and __location, "communication not initialised"

    if not __socket:
        __socket = __context.socket(zmq.REQ)
        __socket.connect(__location)
        __socket.RCVTIMEO = __socket_timeout  # receive timeout milliseconds

    retry_attemtps = 3  # magic number - tries three times to reconnect before giving up.
    while True:
        try:
            if retry_attemtps:
                __socket.send(blosc.compress(dumps(obj)))
                return loads(blosc.decompress(__socket.recv(), as_bytearray=True))
            __socket = None
            raise MakeRequestFailed()

        except zmq.ZMQError as ex:
            retry_attemtps -= 1
            if ex.errno == zmq.EAGAIN:
                sleep(seconds=1)
                __socket = __context.socket(zmq.REQ)
                __socket.connect(__location)
                __socket.RCVTIMEO = __socket_timeout  # receive timeout milliseconds


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

