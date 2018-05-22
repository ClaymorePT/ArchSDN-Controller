'''

This module implements the P2P communication server.
Peers communicate by sending messages from one to another.
These messages carry requests.

Requests that require information which may not be ready-available, should respond with a request ticket.
This ticket contains a request identification. The request answer will be later sent.

It is the responsibility of the peer which performs the request, to deal with the asynchronous nature of the requests.
A peer must wait for a message indicating the success or failure to complete a request, to react accordingly.

Requests are structured as tuples:
(peer ID, Request name, data_dict{})

Replies are structured as tuples:
(Reply name, result structure)

'''

import sys
import logging
import pickle
import time
import blosc

from uuid import UUID
from ipaddress import IPv4Address, IPv6Address
from threading import Thread

from eventlet.green import zmq
from eventlet.semaphore import BoundedSemaphore

from ryu.lib import hub

from archsdn import central
from archsdn import database
from archsdn.helpers import logger_module_name, custom_logging_callback
from archsdn.engine.exceptions import PathNotFound


_log = logging.getLogger(logger_module_name(__file__))

_server_context = None
_clients_context = zmq.Context()
_server_socket = None

_tasks_under_execution = {}

_socket_timeout = 2000  # receive timeout milliseconds
_socket_connect_timeout = 2000  # receive timeout milliseconds
_socket_retries = 3  # number of retries before fail

_connection_objects = {}


class ConnectionFailed(Exception):
    pass


class UnexpectedResponse(Exception):
    def __init__(self, response):
        self.response = response


class __PeerProxy:

    def __init__(self, location):
        _log.info("Initializing communication to peer ({:s})".format(str(location)))

        self.__location = "tcp://{:s}:{:d}".format(str(location[0]), location[1])
        self.__semaphore = BoundedSemaphore()
        self.__pool = zmq.Poller()

        self.__socket = _clients_context.socket(zmq.REQ)
        self.__socket.connect(self.__location)
        self.__pool.register(self.__socket)
        self.__pool.register(self.__socket, zmq.POLLIN)

        self.__source_peer_id = database.get_database_info()["uuid"]

    def __getattr__(self, func_name):
        if func_name not in _requests:
            raise AttributeError("Proxy object has no attribute '{:s}'".format(func_name))

        def remote_method_call(*args, **kwargs):
            with self.__semaphore:
                try:
                    retries_left = 3
                    obj_byte_seq = blosc.compress(pickle.dumps((func_name, args, kwargs)))
                    while retries_left:
                        self.__socket.send(obj_byte_seq)
                        events = dict(self.__pool.poll(_socket_timeout))

                        if events and events[self.__socket] == zmq.POLLIN:
                            answer = pickle.loads(blosc.decompress(self.__socket.recv()))
                            if not isinstance(answer, tuple):
                                raise UnexpectedResponse("Received wrong data type.")
                            if answer[0]:
                                raise UnexpectedResponse(answer[1])
                            return answer[1]

                        else:
                            _log.warning(
                                "No response from peer, retrying ({:d} out of {:d}) …".format(
                                    _socket_retries - retries_left + 1,
                                    _socket_retries
                                )
                            )
                            self.__socket.setsockopt(zmq.LINGER, 0)
                            self.__socket.close()
                            self.__pool.unregister(self.__socket)
                            retries_left -= 1
                            if retries_left == 0:
                                _log.error("Peer seems to be offline. Aborting.")
                                raise ConnectionFailed()
                            _log.warning("Reconnecting and resending...")
                            # Create new connection
                            self.__socket = _clients_context.socket(zmq.REQ)
                            self.__socket.connect(self.__location)
                            self.__pool.register(self.__socket, zmq.POLLIN)

                except Exception:
                    custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
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
        raise AttributeError("Cannot aquire the controller {:s} network address.".format(str(controller_id)))

    if controller_id not in _connection_objects:
        _connection_objects[controller_id] = __PeerProxy(location)
    return _connection_objects[controller_id]


def initialize_server(ip, port):
    global _server_context, _server_socket
    assert isinstance(ip, (IPv4Address, IPv6Address)), \
        "ip is not a valid IPv4Address or IPv6Address object. Got instead {:s}".format(repr(ip))
    assert isinstance(port, int), \
        "port is not a valid int object. Got instead {:s}".format(repr(port))
    assert 0 < port < 0xFFFF, \
        "port range invalid. Should be between 0 and 0xFFFF. Got {:d}".format(port)

    # Prepare our context and sockets
    _server_context = zmq.Context()

    # Socket to receive clients
    _server_socket = _server_context.socket(zmq.ROUTER)
    _server_socket.bind("tcp://{:s}:{:d}".format(str(ip), port))

    # Socket to talk to workers
    workers_socket = _server_context.socket(zmq.DEALER)
    workers_socket.bind("inproc://workers")

    def recv_and_process(this_worker_id):
        _log.warning("ZMQ context for worker {:d} is starting.".format(this_worker_id))

        client_socket = _server_context.socket(zmq.REP)
        client_socket.connect("inproc://workers")

        while True:
            try:
                request = pickle.loads(blosc.decompress(client_socket.recv()))
                _log.debug("Request received: {:s}".format(str(request)))
                assert isinstance(request, tuple), "request type is not tuple"
                assert len(request) == 3, "request length is not equal to 3"
                assert isinstance(request[0], str), "request function name parameter is not string"
                assert request[0] in _requests, "function name is not registered "

                func_name = request[0]
                args = request[1]
                kwargs = request[2]

                try:
                    _log.info(
                        "Client is requesting {:s} with data {:s}.".format(
                            func_name,
                            str((args, kwargs))
                        )
                    )
                    answer = (0, _requests[func_name](*args, **kwargs))

                except KeyError:
                    answer = (1, "Unknown Request: '{:s}'".format(repr(func_name)))

                except Exception as ex:
                    custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
                    if sys.flags.debug:
                        answer = (1, "Unknown Request: {}".format(str(ex)))
                    else:
                        answer = (1, "Internal Error. Cannot process request.")

                client_socket.send(blosc.compress(pickle.dumps(answer)))

            except zmq.ContextTerminated as ex:
                _log.error(str(ex))
                break

            except zmq.ZMQerror as ex:
                _log.error(str(ex))

            except Exception as ex:
                client_socket.send(pickle.dumps((1, str(ex))))
                _log.error(str(ex))

        _log.warning("ZMQ context is shutting down.")

    for worker_id in range(0, 4):
        hub.spawn(recv_and_process, worker_id)
    t = Thread(target=zmq.proxy, args=(_server_socket, workers_socket))
    t.start()
    _log.warning("P2P Server initialized.")


def shutdown_server():
    _server_context.destroy()
    _clients_context.destroy()


def __req_local_time(*args, **kwargs):
    return time.asctime()


def __publish_event(*args, **kwargs):
    pass


def __query_address_info(*args, **kwargs):
    return database.query_address_info(*args, **kwargs)


def __activate_scenario(scenario_request):
    from archsdn import database
    from archsdn.engine import sector
    from archsdn.engine import globals
    from archsdn.engine import services

    assert isinstance(scenario_request, dict), \
        "scenario_request is expected to be of dict type. Got {:s}.".format(repr(scenario_request))
    missing_args = tuple(
        filter(
            (lambda arg: arg not in scenario_request.keys()),
            ('global_path_search_id', 'mpls_label', 'sector_requesting_service', 'hash_val')
        )
    )
    if missing_args:
        raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

    global_path_search_id = scenario_request['global_path_search_id']
    sector_requesting_service_id = UUID(scenario_request['sector_requesting_service'])
    scenario_mpls_label = scenario_request['mpls_label']
    scenario_hash_val = scenario_request['hash_val']

    source_ipv4 = global_path_search_id[1]
    target_ipv4 = global_path_search_id[2]
    scenario_type = global_path_search_id[3]
    target_host_info = central.query_address_info(ipv4=target_ipv4)

    this_controller_id = database.get_database_info()['uuid']

    assert isinstance(scenario_type, str), "scenario_type expected to be str"
    try:
        if scenario_type == 'ICMPv4':
            active_icmp4_tasks = globals.scenario_implementation_tasks["IPv4"]["ICMP"]

            if global_path_search_id in globals.active_remote_scenarios:
                error_str = "ICMPv4 scenario with ID {:s} is already implemented.".format(str(global_path_search_id))
                _log.warning(error_str)
                return {"success": False, "reason": error_str}

            if global_path_search_id in active_icmp4_tasks:
                error_str = "ICMPv4 service task is already running for target host {:s}.".format(
                    target_host_info.name
                )
                _log.warning(error_str)
                return {"success": False, "reason": error_str}

            else:
                active_icmp4_tasks[global_path_search_id] = True

            if target_host_info.controller_id == this_controller_id:
                # This IS the target sector
                bidirectional_path = sector.construct_bidirectional_path(
                    sector_requesting_service_id,
                    target_host_info.name,
                    allocated_bandwith=100,
                    sector_a_hash_val=scenario_hash_val
                )
                assert len(bidirectional_path), "bidirectional_path path length cannot be zero."

                # Allocate MPLS label for tunnel
                if len(bidirectional_path) >= 3:
                    local_mpls_label = globals.alloc_mpls_label_id()
                else:
                    local_mpls_label = None

                local_service_scenario = services.icmpv4_flow_activation(
                    bidirectional_path, local_mpls_label, scenario_mpls_label, source_ipv4=source_ipv4
                )

                globals.active_sector_scenarios[id(local_service_scenario)] = local_service_scenario
                globals.active_remote_scenarios[global_path_search_id] = (
                    (id(local_service_scenario),), (sector_requesting_service_id,)
                )

                if global_path_search_id in active_icmp4_tasks:
                    del active_icmp4_tasks[global_path_search_id]
                else:
                    assert False, "global_path_search_id {:s} not in active_icmp4_tasks".format(
                        str(global_path_search_id)
                    )

                kspl = globals.get_known_shortest_path(this_controller_id, target_ipv4)
                if kspl:
                    if kspl > len(bidirectional_path):
                        globals.set_known_shortest_path(this_controller_id, target_ipv4, len(bidirectional_path))
                else:
                    globals.set_known_shortest_path(this_controller_id, target_ipv4, len(bidirectional_path))
                kspl = globals.get_known_shortest_path(this_controller_id, target_ipv4)
                assert kspl, "kspl cannot be Zero or None."

                reward = bidirectional_path.remaining_bandwidth_average/kspl*len(bidirectional_path)

                old_q_value = globals.get_q_value(this_controller_id, target_ipv4)
                new_q_value = globals.calculate_new_qvalue(old_q_value, 1, reward)
                globals.set_q_value(this_controller_id, target_ipv4, new_q_value)

                _log.debug(
                    "Old Q-Value: {:f}; New Q-Value: {:f}; Reward: {:f}; Forward Q-Value: {:f}.".format(
                        old_q_value, new_q_value, reward, 1
                    )
                )

                _log.info("Remote Scenario with ID {:s} is now active.".format(str(global_path_search_id)))

                return {
                    "success": True,
                    "global_path_search_id": global_path_search_id,
                    "q_value": new_q_value,
                    "path_length": len(bidirectional_path)
                }

            else:
                # This IS NOT the target sector
                adjacent_sectors_ids = sector.query_sectors_ids()
                adjacent_sectors_ids.remove(sector_requesting_service_id)

                if len(adjacent_sectors_ids) == 0:
                    return {"success": False, "reason": "No available sectors to explore."}

                if target_host_info.controller_id in adjacent_sectors_ids:
                    # If the target sector IS adjacent to this sector, contact it directly and establish path
                    bidirectional_path = sector.construct_bidirectional_path(
                        sector_requesting_service_id,
                        target_host_info.controller_id,
                        allocated_bandwith=100,
                        sector_a_hash_val=scenario_hash_val
                    )
                    assert len(bidirectional_path), "bidirectional_path path length cannot be zero."

                    # Allocate MPLS label for tunnel
                    if len(bidirectional_path) >= 3:
                        local_mpls_label = globals.alloc_mpls_label_id()
                    else:
                        local_mpls_label = None

                    (switch_id, _, port_out) = bidirectional_path.path[-2]
                    selected_sector_proxy = get_controller_proxy(target_host_info.controller_id)
                    service_activation_result = selected_sector_proxy.activate_scenario(
                        {
                            "global_path_search_id": global_path_search_id,
                            "sector_requesting_service": str(this_controller_id),
                            "mpls_label": local_mpls_label,
                            "hash_val": globals.get_hash_val(switch_id, port_out),
                        }
                    )

                    forward_q_value = service_activation_result["qvalue"]
                    if service_activation_result["success"]:
                        kspl = globals.get_known_shortest_path(this_controller_id, target_ipv4)
                        if kspl:
                            if kspl > len(bidirectional_path):
                                globals.set_known_shortest_path(this_controller_id, target_ipv4,
                                                                len(bidirectional_path))
                        else:
                            globals.set_known_shortest_path(this_controller_id, target_ipv4, len(bidirectional_path))
                        kspl = globals.get_known_shortest_path(this_controller_id, target_ipv4)
                        assert kspl, "kspl cannot be Zero or None."

                        reward = bidirectional_path.remaining_bandwidth_average / kspl * len(bidirectional_path)

                        old_q_value = globals.get_q_value(this_controller_id, target_ipv4)
                        new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, reward)
                        globals.set_q_value(this_controller_id, target_ipv4, new_q_value)

                        local_service_scenario = services.sector_to_sector_mpls_flow_activation(
                            bidirectional_path, local_mpls_label, scenario_mpls_label
                        )

                        globals.active_sector_scenarios[id(local_service_scenario)] = local_service_scenario
                        globals.active_remote_scenarios[global_path_search_id] = (
                            (id(local_service_scenario),), (sector_requesting_service_id, target_host_info.controller_id)
                        )

                        if global_path_search_id in active_icmp4_tasks:
                            del active_icmp4_tasks[global_path_search_id]
                        else:
                            assert False, "global_path_search_id {:s} not in active_icmp4_tasks".format(
                                str(global_path_search_id)
                            )

                        _log.debug(
                            "Old Q-Value: {:f}; New Q-Value: {:f}; Reward: {:f}; Forward Q-Value: {:f}.".format(
                                old_q_value, new_q_value, reward, forward_q_value
                            )
                        )

                        _log.info("Remote Scenario with ID {:s} is now active.".format(str(global_path_search_id)))

                        return {
                            "success": True,
                            "global_path_search_id": global_path_search_id,
                            "q_value": new_q_value,
                            "path_length": len(bidirectional_path) + service_activation_result["path_length"]
                        }
                    else:
                        old_q_value = globals.get_q_value(this_controller_id, target_ipv4)
                        new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                        globals.set_q_value(this_controller_id, target_ipv4, new_q_value)

                        _log.debug(
                            "Old Q-Value: {:f}; New Q-Value: {:f}; Reward: {:f}; Forward Q-Value: {:f}.".format(
                                old_q_value, new_q_value, -1, forward_q_value
                            )
                        )
                        _log.error("Failed to activate Scenario with ID {:s}. "
                                   "No available sectors to explore.".format(str(global_path_search_id)))

                        return {"success": False, "reason": "No available sectors to explore."}

                else:
                    while len(adjacent_sectors_ids):
                        for sector_id in adjacent_sectors_ids:
                            if sector_id not in globals.QValues:
                                globals.QValues[sector_id] = {}

                        # Selecting a Sector based on the Q-Value
                        sectors_never_used = tuple(
                            filter(
                                (lambda sec: target_ipv4 not in globals.QValues[sec]),
                                adjacent_sectors_ids
                            )
                        )
                        if len(sectors_never_used):
                            selected_sector_id = sectors_never_used[0]

                        else:
                            selected_sector_id = max(
                                adjacent_sectors_ids,
                                key=(lambda ent: globals.QValues[ent][target_ipv4])
                            )
                        adjacent_sectors_ids.remove(selected_sector_id)
                        ####################

                        # Acquire a bidirectional path
                        bidirectional_path = sector.construct_bidirectional_path(
                            sector_requesting_service_id,
                            selected_sector_id,
                            allocated_bandwith=100
                        )
                        assert len(bidirectional_path), "bidirectional_path path length cannot be zero."

                        # Allocate MPLS label for local path
                        if len(bidirectional_path) >= 3:
                            local_mpls_label = globals.alloc_mpls_label_id()
                        else:
                            local_mpls_label = None

                        (switch_id, _, port_out) = bidirectional_path.path[-2]
                        selected_sector_proxy = get_controller_proxy(selected_sector_id)
                        service_activation_result = selected_sector_proxy.activate_scenario(
                            {
                                "global_path_search_id": global_path_search_id,
                                "sector_requesting_service": str(this_controller_id),
                                "mpls_label": local_mpls_label,
                                "hash_val": globals.get_hash_val(switch_id, port_out),
                            }
                        )

                        forward_q_value = service_activation_result["qvalue"]
                        kspl = globals.get_known_shortest_path(this_controller_id, target_ipv4)
                        if kspl:
                            if kspl > len(bidirectional_path):
                                globals.set_known_shortest_path(this_controller_id, target_ipv4,
                                                                len(bidirectional_path))
                        else:
                            globals.set_known_shortest_path(this_controller_id, target_ipv4, len(bidirectional_path))
                        kspl = globals.get_known_shortest_path(this_controller_id, target_ipv4)
                        assert kspl, "kspl cannot be Zero or None."

                        if not service_activation_result["success"]:
                            old_q_value = globals.get_q_value(this_controller_id, target_ipv4)
                            new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, -1)
                            globals.set_q_value(this_controller_id, target_ipv4, new_q_value)

                            _log.debug(
                                "Old Q-Value: {:f}; New Q-Value: {:f}; Reward: {:f}; Forward Q-Value: {:f}.".format(
                                    old_q_value, new_q_value, -1, forward_q_value
                                )
                            )

                            _log.error(
                                "Failed to activate Scenario with ID {:s}. Reason {:s}.".format(
                                    str(global_path_search_id),
                                    service_activation_result["reason"]
                                )
                            )

                        else:
                            reward = bidirectional_path.remaining_bandwidth_average / kspl * len(bidirectional_path)
                            old_q_value = globals.get_q_value(this_controller_id, target_ipv4)
                            new_q_value = globals.calculate_new_qvalue(old_q_value, forward_q_value, reward)
                            globals.set_q_value(this_controller_id, target_ipv4, new_q_value)

                            _log.debug(
                                "Old Q-Value: {:f}; New Q-Value: {:f}; Reward: {:f}; Forward Q-Value: {:f}.".format(
                                    old_q_value, new_q_value, reward, forward_q_value
                                )
                            )

                            local_service_scenario = services.icmpv4_flow_activation(
                                bidirectional_path, local_mpls_label, scenario_mpls_label
                            )

                            globals.active_sector_scenarios[id(local_service_scenario)] = local_service_scenario
                            globals.active_remote_scenarios[global_path_search_id] = (
                                (id(local_service_scenario),), (sector_requesting_service_id, target_host_info.controller_id)
                            )

                            if global_path_search_id in active_icmp4_tasks:
                                del active_icmp4_tasks[global_path_search_id]
                            else:
                                assert False, "global_path_search_id {:s} not in active_icmp4_tasks".format(
                                    str(global_path_search_id)
                                )

                            _log.info("Remote Scenario with ID {:s} is now active.".format(str(global_path_search_id)))
                            return {
                                "success": True,
                                "global_path_search_id": global_path_search_id,
                                "q_value": new_q_value,
                                "path_length": len(bidirectional_path) + service_activation_result["path_length"]
                            }

                    error_str = "Failed to activate Scenario with ID {:s}. " \
                                "Alternative adjacent sectors options is exhausted.".format(
                                    str(global_path_search_id),
                                )
                    _log.error(error_str)
                    return {"success": False, "reason": error_str}

        else:
            error_str = "Failed to activate Scenario with ID {:s}. Invalid Scenario Type: {:s}".format(
                            str(global_path_search_id),
                            scenario_type
                        )

            _log.error(error_str)
            return {"success": False, "reason": error_str}

    except PathNotFound:
        error_str = "Failed to implement path to sector {:s}. " \
                    "An available path was not found in the network.".format(
                        str(target_host_info.controller_id)
                    )
        _log.error(error_str)
        custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
        return {"success": False, "reason": error_str}

    except Exception as ex:
        error_str = "Failed to implement path to host {:s} at sector {:s}. Reason {:s}.".format(
            target_host_info.name,
            str(target_host_info.controller_id),
            str(type(ex))
        )
        _log.error(error_str)
        custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
        return {"success": False, "reason": error_str}


_requests = {
    "req_local_time": __req_local_time,
    "publish_event": __publish_event,
    "query_address_info": __query_address_info,
    "activate_scenario": __activate_scenario,
}
