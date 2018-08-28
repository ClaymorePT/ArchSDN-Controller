
import sys
import logging
import pickle
import blosc
import struct

from uuid import UUID

from eventlet.green import socket
from ryu.lib import hub

from archsdn import central
from archsdn.helpers import logger_module_name, custom_logging_callback

_log = logging.getLogger(logger_module_name(__file__))

_socket_timeout = 2000  # receive timeout milliseconds


class __PeerProxy:

    __counter = 0

    def __init__(self, location):
        try:
            self.__closed = True
            self.__socket = None
            self.__counter = __class__.__counter
            __class__.__counter += 1
            _log.debug("Initializing communication to peer ({:s}: {:d})".format(str(location), self.__counter))

            self.__location = (str(location[0]), location[1])
            self.__stream_client = hub.StreamClient(self.__location)
            self.__socket = self.__stream_client.connect()
            if self.__socket:
                self.__socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.__socket.settimeout(_socket_timeout)
                self.__closed = False

        except Exception:
            custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
            raise

    def __del__(self):
        _log.debug("Destroying proxy with id: {:d}".format(self.__counter))
        if not self.__closed:
            if self.__stream_client is not None:
                self.__stream_client.stop()
                self.__socket.shutdown(socket.SHUT_RDWR)
                self.__socket.close()
            self.__closed = True

    def __getattr__(self, func_name):
        from archsdn.p2p.requests import server_requests
        from archsdn.p2p import UnexpectedResponse

        if func_name not in server_requests:
            raise AttributeError("Proxy object has no attribute '{:s}'".format(func_name))

        if self.__closed:
            raise Exception("Socket Closed")

        def remote_method_call(*args, **kwargs):
            try:
                _log.debug(
                    "Peer Proxy ({:d}) connected to {:s}, requesting \"{:s}\" with args {:s}".format(
                        self.__counter,
                        str(self.__location),
                        func_name,
                        str((args, kwargs))
                    )
                )
                encoded_request_bytes = blosc.compress(pickle.dumps((func_name, args, kwargs)))
                self.__socket.sendall(
                    struct.pack(
                        "!H{:d}s".format(len(encoded_request_bytes)),
                        len(encoded_request_bytes),
                        encoded_request_bytes
                    )
                )

                # First, receive the length of the request
                received_bytes = 0
                buf = bytearray(2)
                while received_bytes < 2:
                    data_bytes = self.__socket.recv(2 - received_bytes, socket.MSG_WAITALL)
                    if data_bytes:
                        memoryview(buf)[received_bytes:received_bytes+len(data_bytes)] = data_bytes
                        received_bytes += len(data_bytes)
                    else:
                        raise Exception("Socket Closed")
                    # _log.debug("data_bytes: {:d}".format(len(data_bytes)))
                msg_len = struct.unpack("!H", buf)[0]

                # Then, receive the encoded request
                received_bytes = 0
                buf = bytearray(msg_len)
                while received_bytes < msg_len:
                    data_bytes = self.__socket.recv(msg_len - received_bytes, socket.MSG_WAITALL)
                    if data_bytes:
                        memoryview(buf)[received_bytes:received_bytes+len(data_bytes)] = data_bytes
                        received_bytes += len(data_bytes)
                    else:
                        raise Exception("Socket Closed")
                    # _log.debug("data_bytes: {:d}".format(len(data_bytes)))
                answer = pickle.loads(blosc.decompress(buf))

                if not isinstance(answer, tuple):
                    raise UnexpectedResponse("Received wrong data type.")
                if answer[0]:
                    raise UnexpectedResponse(answer[1])

                _log.debug(
                    "Peer Proxy ({:d}) answer is \"{:s}\"".format(
                        self.__counter,
                        str(answer)
                    )
                )
                return answer[1]

            except Exception:
                custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
                if self.__socket is not None:
                    self.__socket.shutdown(socket.SHUT_RDWR)
                    self.__socket.close()
                self.__closed = True
                raise
        return remote_method_call


def get_controller_proxy(controller_id):
    assert isinstance(controller_id, UUID), "controller_id expected to be UUID. Got {:s}".format(repr(controller_id))

    controller_info = central.query_controller_info(controller_id)

    if controller_info.ipv6:
        location = (controller_info.ipv6, controller_info.ipv6_port)
    elif controller_info.ipv4:
        location = (controller_info.ipv4, controller_info.ipv4_port)
    else:
        raise AttributeError("Cannot acquire the controller {:s} network address.".format(str(controller_id)))

    return __PeerProxy(location)