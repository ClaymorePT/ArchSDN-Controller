
import sys
import logging
import pickle
import struct
from ipaddress import IPv4Address, IPv6Address

import blosc
from eventlet.green import socket
from ryu.lib import hub

from archsdn.helpers import logger_module_name, custom_logging_callback


_log = logging.getLogger(logger_module_name(__file__))
_server_stream = None
_socket_timeout = 2000  # receive timeout milliseconds


def initialize_server(ip, port):
    global _server_stream
    from archsdn.p2p.requests import server_requests

    assert isinstance(ip, (IPv4Address, IPv6Address)), \
        "ip is not a valid IPv4Address or IPv6Address object. Got instead {:s}".format(repr(ip))
    assert isinstance(port, int), \
        "port is not a valid int object. Got instead {:s}".format(repr(port))
    assert 0 < port < 0xFFFF, \
        "port range invalid. Should be between 0 and 0xFFFF. Got {:d}".format(port)

    def client_handler(client_skt, client_addr):
        client_skt.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client_skt.settimeout(_socket_timeout)

        try:
            while True:
                _log.debug("Serving {:s}".format(str(client_addr)))
                # First, receive the length of the request
                received_bytes = 0
                buf = bytearray(2)
                while received_bytes < 2:
                    data_bytes = client_skt.recv(2-received_bytes, socket.MSG_WAITALL)
                    if data_bytes:
                        memoryview(buf)[received_bytes:received_bytes+len(data_bytes)] = data_bytes
                        received_bytes += len(data_bytes)
                    else:
                        return
                msg_len = struct.unpack("!H", buf)[0]

                # Then, receive the encoded request
                received_bytes = 0
                buf = bytearray(msg_len)
                while received_bytes < msg_len:
                    data_bytes = client_skt.recv(msg_len - received_bytes, socket.MSG_WAITALL)
                    if data_bytes:
                        memoryview(buf)[received_bytes:received_bytes+len(data_bytes)] = data_bytes
                        received_bytes += len(data_bytes)
                    else:
                        return

                func_name = None
                try:
                    request = pickle.loads(blosc.decompress(buf))
                    _log.debug("Request received: {:s}".format(str(request)))

                    assert isinstance(request, tuple), "request type is not tuple"
                    assert len(request) == 3, "request length is not equal to 3"
                    assert isinstance(request[0], str), "request function name parameter is not string"
                    assert request[0] in server_requests, "function name is not registered "

                    func_name = request[0]
                    args = request[1]
                    kwargs = request[2]

                    _log.debug(
                        "Client is requesting {:s} with data {:s}.".format(
                            func_name,
                            str((args, kwargs))
                        )
                    )
                    answer = (0, server_requests[func_name](*args, **kwargs))

                except KeyError:
                    answer = (1, "Unknown Request: '{:s}'".format(repr(func_name)))

                except Exception as ex:
                    custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
                    if sys.flags.debug:
                        answer = (1, "Unknown Request: {}".format(str(ex)))
                    else:
                        answer = (1, "Internal Error. Cannot process request.")

                answer_data = blosc.compress(pickle.dumps(answer))
                client_skt.sendall(
                    struct.pack("!H{:d}s".format(len(answer_data)), len(answer_data), answer_data)
                )

        except Exception:
            custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
    try:
        _server_stream = hub.StreamServer((str(ip), port), client_handler)
        hub.spawn(_server_stream.serve_forever)
        _log.warning("P2P Server initialized.")
    except OSError as ex:
        if ex.errno == 98:
            _log.error(
                "Cannot initialize P2P server. Address {:s} with port {:d} is already being used.".format(
                    str(ip),
                    port
                )
            )
        else:
            _log.error(str(ex))
        raise


def shutdown_server():
    _server_stream.server.close()


