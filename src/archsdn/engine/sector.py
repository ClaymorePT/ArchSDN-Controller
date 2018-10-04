"""
    Sector Module

    This module is used to manage the sector structure and to provide solutions to scenarios requests.

    Two types of scenarios are supported
    - Bidirectional Communication between two hosts
    - Unidirectional Communication from one host to another

"""

import logging
from threading import RLock
from functools import partial
from abc import ABC, abstractmethod
from copy import copy, deepcopy
from ipaddress import IPv4Address, IPv6Address

import networkx as nx

from archsdn.helpers import logger_module_name
from archsdn.engine.entities import \
    Switch, Host, Sector, RemoteHost

from archsdn.engine.exceptions import \
    EntityAlreadyRegistered, EntityNotRegistered, \
    LinkException, SwitchPortAlreadyConnected, PortNotUsed, PortNotRegistered, \
    EntitiesAlreadyConnected, EntitiesNotConnected, PathNotFound

_log = logging.getLogger(logger_module_name(__file__))

__net = None
__lock = None
__entities = None
__suported_entities = {Switch, Host, Sector, RemoteHost}
__suported_entities_str = ", ".join((str(i) for i in __suported_entities))

__sector_initialized = False


class SectorPath(ABC):
    @abstractmethod
    def __del__(self):
        pass

    @abstractmethod
    def __len__(self):
        pass

    @property
    @abstractmethod
    def id(self):
        pass

    @property
    @abstractmethod
    def entity_a(self):
        pass

    @property
    @abstractmethod
    def entity_b(self):
        pass

    @property
    @abstractmethod
    def switches_info(self):
        pass

    @property
    @abstractmethod
    def remaining_bandwidth_average(self):
        pass

    @property
    @abstractmethod
    def path(self):
        pass

    @abstractmethod
    def has_entity(self, entity_id):
        pass

    @abstractmethod
    def uses_edge(self, edge):
        pass

    @abstractmethod
    def is_bidirectional(self):
        pass


class __OneDirectionPath(SectorPath):
    def __init__(self, sector_path, bandwidth_dealocation_callback, remaining_bandwidth_average=None):
        assert len(sector_path) >= 3, "sector_path length expected to be equal or higher than 3"

        if not isinstance(query_entity(sector_path[0]), (Host, Sector)):
            _log.info("sector_path: {:s}".format(str(sector_path)))
            assert False, "first entity ID in sector path must be Host or Sector"

        if not isinstance(query_entity(sector_path[-1]), (Host, Sector)):
            _log.info("sector_path: {:s}".format(str(sector_path)))
            assert False, "last entity ID in sector path must be Host or Sector"

        for (middle_switch_id, switch_in_port, switch_out_port) in sector_path[1:-1]:
            if not isinstance(query_entity(middle_switch_id), Switch):
                _log.info("sector_path: {:s}".format(str(sector_path)))
                assert False, "middle entity ID in sector path must be Switch"


        self.__sector_path = sector_path
        self.__bandwidth_dealocation_callback = bandwidth_dealocation_callback
        self.__remaining_bandwidth_average = remaining_bandwidth_average

    def __del__(self):
        self.__bandwidth_dealocation_callback()

    def __len__(self):
        return len(self.__sector_path) - 1

    def id(self):
        return id(self)

    @property
    def entity_a(self):
        return copy(self.__sector_path[0])

    @property
    def entity_b(self):
        return copy(self.__sector_path[-1])

    @property
    def switches_info(self):
        if len(self.__sector_path) == 3:
            return (copy(self.__sector_path[1]),)
        else:
            return tuple((copy(elem) for elem in self.__sector_path[1:-1]))

    @property
    def path(self):
        return deepcopy(self.__sector_path)

    @property
    def remaining_bandwidth_average(self):
        return self.__remaining_bandwidth_average

    def has_entity(self, entity_id):
        if self.__sector_path[0] == entity_id or self.__sector_path[-1] == entity_id:
            return True
        for (switch_id, _, _) in self.__sector_path[1:-1]:
            if entity_id == switch_id:
                return True

    def uses_edge(self, edge):
        # (node_a_id) --edge_port-- > (node_b_id)
        (node_a_id, node_b_id, edge_port) = edge
        path_len = len(self.__sector_path)

        if path_len == 3:
            entity_a_id = self.__sector_path[0]
            (switch_id, in_port, out_port) = self.__sector_path[1]
            entity_b_id = self.__sector_path[2]
            # (entity_a_id) ---in_port---> (switch_id)
            if (entity_a_id == node_a_id) and (switch_id == node_b_id) and (in_port == edge_port):
                return True

            # (entity_a_id) <---in_port--- (switch_id)
            if (switch_id == node_a_id) and (entity_a_id == node_b_id) and (in_port == edge_port):
                return True

            # (switch_id_current) ---out_port_current---> (entity_b_id)
            if (switch_id == node_a_id) and (entity_b_id == node_b_id) and (out_port == edge_port):
                return True

            # (switch_id_current) <---in_port_id_after--- (entity_b_id)
            if (entity_b_id == node_a_id) and (switch_id == node_b_id) and (entity_b_id == edge_port):
                return True
        else:
            for i in range(1, path_len-1):
                if i == 1:
                    entity_a_id = self.__sector_path[0]
                    (switch_id, in_port, out_port) = self.__sector_path[i]
                    (switch_id_after, in_port_id_after, _) = self.__sector_path[i + 1]
                    # (entity_a_id) ---in_port---> (switch_id)
                    if (entity_a_id == node_a_id) and (switch_id == node_b_id) and (in_port == edge_port):
                        return True

                    # (entity_a_id) <---in_port--- (switch_id)
                    if (switch_id == node_a_id) and (entity_a_id == node_b_id) and (in_port == edge_port):
                        return True

                    # (switch_id_current) ---out_port_current---> (switch_id_after)
                    if (switch_id == node_a_id) and (switch_id_after == node_b_id) and (out_port == edge_port):
                        return True

                    # (switch_id_current) <---in_port_id_after--- (switch_id_after)
                    if (switch_id_after == node_a_id) and (switch_id == node_b_id) and (in_port_id_after == edge_port):
                        return True

                elif i == path_len-2:
                    (switch_id_before, _, out_port_id_before) = self.__sector_path[i - 1]
                    (switch_id, in_port, out_port) = self.__sector_path[i]
                    entity_b_id = self.__sector_path[len(self.__sector_path)-1]

                    # (switch_id_before) ---out_port_id_before---> (switch_id_current)
                    if (switch_id_before == node_a_id) and (switch_id == node_b_id) and (
                            out_port_id_before == edge_port):
                        return True

                    # (switch_id_before) <---in_port_current--- (switch_id_current)
                    if (switch_id == node_a_id) and (switch_id_before == node_b_id) and (
                            in_port == edge_port):
                        return True

                    # (switch_id) ---out_port---> (entity_b_id)
                    if (entity_b_id == node_a_id) and (switch_id == node_b_id) and (out_port == edge_port):
                        return True

                    # (entity_b_id) <---out_port--- (switch_id)
                    if (switch_id == node_a_id) and (entity_b_id == node_b_id) and (out_port == edge_port):
                        return True

                else:
                    (switch_id_current, in_port_current, out_port_current) = self.__sector_path[i]
                    (switch_id_before, _, out_port_id_before) = self.__sector_path[i-1]
                    (switch_id_after, in_port_id_after, _) = self.__sector_path[i+1]

                    # (switch_id_before) ---out_port_id_before---> (switch_id_current)
                    if (switch_id_before == node_a_id) and (switch_id_current == node_b_id) and (out_port_id_before == edge_port):
                        return True

                    # (switch_id_before) <---in_port_current--- (switch_id_current)
                    if (switch_id_current == node_a_id) and (switch_id_before == node_b_id) and (in_port_current == edge_port):
                        return True

                    # (switch_id_current) ---out_port_current---> (switch_id_after)
                    if (switch_id_current == node_a_id) and (switch_id_after == node_b_id) and (out_port_current == edge_port):
                        return True

                    # (switch_id_current) <---in_port_id_after--- (switch_id_after)
                    if (switch_id_after == node_a_id) and (switch_id_current == node_b_id) and (in_port_id_after == edge_port):
                        return True
        return False

    def is_bidirectional(self):
        return False


class __BiDirectionPath(SectorPath):
    def __init__(self, sector_path, bandwidth_dealocation_callback, remaining_bandwidth_average=None):
        assert len(sector_path) >= 3, "sector_path length expected to be equal or higher than 3"

        if not isinstance(query_entity(sector_path[0]), (Host, Sector)):
            _log.info("sector_path: {:s}".format(str(sector_path)))
            assert False, "first entity ID in sector path must be Host or Sector"

        if not isinstance(query_entity(sector_path[-1]), (Host, Sector)):
            _log.info("sector_path: {:s}".format(str(sector_path)))
            assert False, "last entity ID in sector path must be Host or Sector"

        for (middle_switch_id, switch_in_port, switch_out_port) in sector_path[1:-1]:
            if not isinstance(query_entity(middle_switch_id), Switch):
                _log.info("sector_path: {:s}".format(str(sector_path)))
                assert False, "middle entity ID in sector path must be Switch"

        self.__sector_path = sector_path
        self.__bandwidth_dealocation_callback = bandwidth_dealocation_callback
        self.__remaining_bandwidth_average = remaining_bandwidth_average

    def __del__(self):
        self.__bandwidth_dealocation_callback()

    def __len__(self):
        return len(self.__sector_path) - 1

    def id(self):
        return id(self)

    @property
    def entity_a(self):
        return copy(self.__sector_path[0])

    @property
    def entity_b(self):
        return copy(self.__sector_path[-1])

    @property
    def switches_info(self):
        if len(self.__sector_path) == 3:
            return (copy(self.__sector_path[1]),)
        else:
            return tuple((copy(elem) for elem in self.__sector_path[1:-1]))

    @property
    def path(self):
        return deepcopy(self.__sector_path)

    @property
    def remaining_bandwidth_average(self):
        return self.__remaining_bandwidth_average

    def has_entity(self, entity_id):
        if self.__sector_path[0] == entity_id or self.__sector_path[-1] == entity_id:
            return True
        for (switch_id, _, _) in self.__sector_path[1:-1]:
            if entity_id == switch_id:
                return True

    def uses_edge(self, edge):
        # (node_a_id) --edge_port-- > (node_b_id)
        (node_a_id, node_b_id, edge_port) = edge
        path_len = len(self.__sector_path)

        if path_len == 3:
            entity_a_id = self.__sector_path[0]
            (switch_id, in_port, out_port) = self.__sector_path[1]
            entity_b_id = self.__sector_path[2]
            # (entity_a_id) ---in_port---> (switch_id)
            if (entity_a_id == node_a_id) and (switch_id == node_b_id) and (in_port == edge_port):
                return True

            # (entity_a_id) <---in_port--- (switch_id)
            if (switch_id == node_a_id) and (entity_a_id == node_b_id) and (in_port == edge_port):
                return True

            # (switch_id_current) ---out_port_current---> (entity_b_id)
            if (switch_id == node_a_id) and (entity_b_id == node_b_id) and (out_port == edge_port):
                return True

            # (switch_id_current) <---in_port_id_after--- (entity_b_id)
            if (entity_b_id == node_a_id) and (switch_id == node_b_id) and (entity_b_id == edge_port):
                return True

        else:
            for i in range(1, path_len-1):
                if i == 1:
                    entity_a_id = self.__sector_path[0]
                    (switch_id, in_port, out_port) = self.__sector_path[i]
                    (switch_id_after, in_port_id_after, _) = self.__sector_path[i + 1]
                    # (entity_a_id) ---in_port---> (switch_id)
                    if (entity_a_id == node_a_id) and (switch_id == node_b_id) and (in_port == edge_port):
                        return True

                    # (entity_a_id) <---in_port--- (switch_id)
                    if (switch_id == node_a_id) and (entity_a_id == node_b_id) and (in_port == edge_port):
                        return True

                    # (switch_id_current) ---out_port_current---> (switch_id_after)
                    if (switch_id == node_a_id) and (switch_id_after == node_b_id) and (out_port == edge_port):
                        return True

                    # (switch_id_current) <---in_port_id_after--- (switch_id_after)
                    if (switch_id_after == node_a_id) and (switch_id == node_b_id) and (in_port_id_after == edge_port):
                        return True

                elif i == path_len-2:
                    (switch_id_before, _, out_port_id_before) = self.__sector_path[i - 1]
                    (switch_id, in_port, out_port) = self.__sector_path[i]
                    entity_b_id = self.__sector_path[len(self.__sector_path)-1]

                    # (switch_id_before) ---out_port_id_before---> (switch_id_current)
                    if (switch_id_before == node_a_id) and (switch_id == node_b_id) and (
                            out_port_id_before == edge_port):
                        return True

                    # (switch_id_before) <---in_port_current--- (switch_id_current)
                    if (switch_id == node_a_id) and (switch_id_before == node_b_id) and (
                            in_port == edge_port):
                        return True

                    # (switch_id) ---out_port---> (entity_b_id)
                    if (entity_b_id == node_a_id) and (switch_id == node_b_id) and (out_port == edge_port):
                        return True

                    # (entity_b_id) <---out_port--- (switch_id)
                    if (switch_id == node_a_id) and (entity_b_id == node_b_id) and (out_port == edge_port):
                        return True

                else:
                    (switch_id_current, in_port_current, out_port_current) = self.__sector_path[i]
                    (switch_id_before, _, out_port_id_before) = self.__sector_path[i-1]
                    (switch_id_after, in_port_id_after, _) = self.__sector_path[i+1]

                    # (switch_id_before) ---out_port_id_before---> (switch_id_current)
                    if (switch_id_before == node_a_id) and (switch_id_current == node_b_id) and (out_port_id_before == edge_port):
                        return True

                    # (switch_id_before) <---in_port_current--- (switch_id_current)
                    if (switch_id_current == node_a_id) and (switch_id_before == node_b_id) and (in_port_current == edge_port):
                        return True

                    # (switch_id_current) ---out_port_current---> (switch_id_after)
                    if (switch_id_current == node_a_id) and (switch_id_after == node_b_id) and (out_port_current == edge_port):
                        return True

                    # (switch_id_current) <---in_port_id_after--- (switch_id_after)
                    if (switch_id_after == node_a_id) and (switch_id_current == node_b_id) and (in_port_id_after == edge_port):
                        return True
            return False

    def is_bidirectional(self):
        return True


def initialise():
    global __net, __lock, __entities, __sector_initialized
    __net = nx.MultiDiGraph()
    __lock = RLock()
    __entities = dict(((i, {}) for i in __suported_entities))
    __sector_initialized = True


def query_entity(entity_id):
    assert __sector_initialized, "sector not initialised"

    with __lock:
        if not __net.has_node(entity_id):
            raise EntityNotRegistered()

        for entity_type in __entities:
            if entity_id in __entities[entity_type]:
                return __entities[entity_type][entity_id]


def register_entity(entity):
    assert __sector_initialized, "sector not initialised"

    assert isinstance(entity, tuple(__suported_entities)), \
        "entity is not a supported entity ({:s}): got instead {:s}".format(
            __suported_entities_str,
            repr(entity)
        )

    with __lock:
        if __net.has_node(entity.id):
            raise EntityAlreadyRegistered()

        __net.add_node(entity.id)
        __entities[type(entity)][entity.id] = entity


def remove_entity(entity_id):
    assert __sector_initialized, "sector not initialised"

    with __lock:
        if not __net.has_node(entity_id):
            raise EntityNotRegistered()
        __net.remove_node(entity_id)
        for entity_type in __entities:
            if entity_id in __entities[entity_type]:
                del __entities[entity_type][entity_id]


def is_entity_registered(entity_id):
    assert __sector_initialized, "sector not initialised"

    with __lock:
        return __net.has_node(entity_id)


def connect_entities(entity_a_id, entity_b_id, **kwargs):
    """
        This method connects two entities. There are three possible combinations.
            1 - (Switch, Host)
            2 - (Switch, Switch)
            3 - (Switch, Sector)

        :param entity_a_id:
        :param entity_b_id:
        :param kwargs: 1- switch_port_no; 2- (switch_a_port_no, switch_b_port_no); 3- (port_no, sector_id)
        :return: None
    """
    assert __sector_initialized, "sector not initialised"

    with __lock:
        entity_a = query_entity(entity_a_id)
        entity_b = query_entity(entity_b_id)

        #  1st Case - (Switch, Host)
        if isinstance(entity_a, Switch) and isinstance(entity_b, Host):
            missing_args = tuple(filter((lambda arg: arg not in kwargs), ('switch_port_no', )))
            if len(missing_args):
                raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

            if not isinstance(kwargs['switch_port_no'], int):
                raise TypeError("switch_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_port_no'])))
            if kwargs['switch_port_no'] not in entity_a.ports:
                raise ValueError(
                    "switch_port_no {:d} is is not valid for switch {:d}. Ports available {:s}".format(
                        kwargs['switch_port_no'], entity_a_id, str(tuple(entity_a.ports.keys()))
                    )
                )

            _log.debug(
                "Attempting to connect Switch {:s} with Host {:s} through port {:d}".format(
                    str(entity_a_id), str(entity_b_id), kwargs['switch_port_no']
                )
            )
            if __net.has_edge(entity_a_id, entity_b_id, kwargs['switch_port_no']) or \
                    __net.has_edge(entity_b_id, entity_a_id, kwargs['switch_port_no']):
                raise EntitiesAlreadyConnected()

            if len(
                    tuple(
                        filter(
                            (lambda ent: __net.has_edge(entity_a_id, ent, kwargs['switch_port_no'])),
                            __net[entity_a_id]
                        )
                    )
            ):
                raise SwitchPortAlreadyConnected(kwargs['switch_port_no'])
            max_link_speed = entity_a.ports[kwargs['switch_port_no']]['max_speed']

            _log.debug(
                "Creating link from Switch {:s} to Host {:s} using port {:d}".format(
                    str(entity_a_id), str(entity_b_id), kwargs['switch_port_no']
                )
            )
            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_port_no'],
                data={
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed
                }
            )
            _log.debug(
                "Creating link from Host {:s} to Switch {:s} using port {:d}".format(
                    str(entity_b_id), str(entity_a_id), kwargs['switch_port_no']
                )
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_port_no'],
                data={
                    'source_mac': entity_b.mac,
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed
                }
            )
            _log.debug(
                "Switch {:s} is now connected to Host {:s}".format(str(entity_a_id), str(entity_b_id))
            )

        # 2nd Case - (Switch, Switch)
        elif isinstance(entity_a, Switch) and isinstance(entity_b, Switch):
            missing_args = tuple(filter((lambda arg: arg not in kwargs), ('switch_a_port_no', 'switch_b_port_no')))
            if len(missing_args):
                raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

            if not isinstance(kwargs['switch_a_port_no'], int):
                raise TypeError("switch_a_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_a_port_no'])))
            if kwargs['switch_a_port_no'] not in entity_a.ports:
                raise ValueError(
                    "switch_a_port_no {:d} is is not valid for switch_a {:d}. Ports available {:s}".format(
                        kwargs['switch_a_port_no'], entity_a_id, str(tuple(entity_a.ports.keys()))
                    )
                )

            if not isinstance(kwargs['switch_b_port_no'], int):
                raise TypeError("switch_b_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_b_port_no'])))
            if kwargs['switch_b_port_no'] not in entity_b.ports:
                raise ValueError(
                    "switch_b_port_no {:d} is is not valid for switch_b {:d}. Ports available {:s}".format(
                        kwargs['switch_b_port_no'], entity_b_id, str(tuple(entity_b.ports.keys()))
                    )
                )

            _log.debug(
                "Attempting to connect Switch {:s} with Switch {:s} using ports {:d} and {:d}".format(
                    str(entity_a_id), str(entity_b_id), kwargs['switch_a_port_no'], kwargs['switch_b_port_no']
                )
            )
            if __net.has_edge(entity_a_id, entity_b_id, kwargs['switch_a_port_no']) or \
                    __net.has_edge(entity_b_id, entity_a_id, kwargs['switch_b_port_no']) :
                raise EntitiesAlreadyConnected()

            if len(
                    tuple(
                        filter(
                            (lambda ent: __net.has_edge(entity_a_id, ent, kwargs['switch_a_port_no'])),
                            __net[entity_a_id]

                        )
                    )
            ):
                raise SwitchPortAlreadyConnected(kwargs['switch_a_port_no'])

            if len(
                    tuple(
                        filter(
                            (lambda ent: __net.has_edge(entity_b_id, ent, kwargs['switch_b_port_no'])),
                            __net[entity_b_id]
                        )
                    )
            ):
                raise SwitchPortAlreadyConnected(kwargs['switch_b_port_no'])

            max_link_speed_a = entity_a.ports[kwargs['switch_a_port_no']]['max_speed']
            max_link_speed_b = entity_b.ports[kwargs['switch_b_port_no']]['max_speed']

            _log.debug(
                "Creating link from Switch {:s} to Switch {:s} using port {:d}".format(
                    str(entity_a_id), str(entity_b_id), kwargs['switch_a_port_no']
                )
            )
            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_a_port_no'],
                data={
                    'source_mac': entity_a.ports[kwargs['switch_a_port_no']]["hw_addr"],
                    'destiny_mac': entity_b.ports[kwargs['switch_b_port_no']]["hw_addr"],
                    'max_speed': max_link_speed_a,
                    'available_speed': max_link_speed_a
                }
            )
            _log.debug(
                "Creating link from Switch {:s} to Switch {:s} using port {:d}".format(
                    str(entity_b_id), str(entity_a_id), kwargs['switch_b_port_no']
                )
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_b_port_no'],
                data={
                    'source_mac': entity_b.ports[kwargs['switch_b_port_no']]["hw_addr"],
                    'destiny_mac': entity_a.ports[kwargs['switch_a_port_no']]["hw_addr"],
                    'max_speed': max_link_speed_b,
                    'available_speed': max_link_speed_b
                }
            )
            _log.debug(
                "Switch {:s} is now connected to Switch {:s}".format(str(entity_a_id), str(entity_b_id))
            )

        # 3rd Case - (Switch, Sector)
        elif isinstance(entity_a, Switch) and isinstance(entity_b, Sector):
            missing_args = tuple(filter((lambda arg: arg not in kwargs), ('switch_port_no', 'hash_val')))
            if len(missing_args):
                raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

            if not isinstance(kwargs['switch_port_no'], int):
                raise TypeError("switch_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_port_no'])))
            if kwargs['switch_port_no'] not in entity_a.ports:
                raise ValueError(
                    "switch_port_no {:d} is is not valid for switch {:d}. Ports available {:s}".format(
                        kwargs['switch_port_no'], entity_a_id, str(tuple(entity_a.ports.keys()))
                    )
                )

            _log.debug(
                "Attempting to connect Switch {:s} with Sector {:s} through port {:d}.".format(
                    str(entity_a_id), str(entity_b_id), kwargs['switch_port_no']
                )
            )
            if __net.has_edge(entity_a_id, entity_b_id, kwargs['switch_port_no']) or \
                    __net.has_edge(entity_b_id, entity_a_id, kwargs['switch_port_no']) :
                raise EntitiesAlreadyConnected()

            if len(
                    tuple(
                        filter(
                            (lambda ent: __net.has_edge(entity_a_id, ent, kwargs['switch_port_no'])),
                            __net[entity_a_id]
                        )
                    )
            ):
                raise SwitchPortAlreadyConnected(kwargs['switch_port_no'])
            max_link_speed = entity_a.ports[kwargs['switch_port_no']]['max_speed']

            _log.debug(
                "Creating link from Switch {:s} to Sector {:s} using port {:d}".format(
                    str(entity_a_id), str(entity_b_id), kwargs['switch_port_no']
                )
            )
            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_port_no'],
                data={
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed,
                    'hash_val': kwargs['hash_val']
                }
            )

            _log.debug(
                "Creating link from Sector {:s} to Switch {:s} using port {:d}".format(
                    str(entity_b_id), str(entity_a_id), kwargs['switch_port_no']
                )
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_port_no'],
                data={
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed,
                    'hash_val': kwargs['hash_val']
                }
            )
            _log.debug(
                "Switch {:s} is now connected to Sector {:s}".format(str(entity_a_id), str(entity_b_id))
            )

        else:
            raise LinkException(
                "Invalid entities combination to link: {:s} with {:s}".format(
                    type(entity_a).__name__,
                    type(entity_b).__name__
                )
            )


def query_connected_entity_id(switch_id, port_id):
    """
    :param switch_id: Switch entity ID
    :param port_id: Switch Port
    :return:
    """
    assert __sector_initialized, "sector not initialised"
    assert isinstance(port_id, int), \
        "switch_a_port_no type expected to be int. Got {:s}".format(type(port_id).__name__)

    with __lock:
        switch = query_entity(switch_id)

        if port_id not in switch.ports:
            raise ValueError(
                "port {:d} is not registered for switch {:016X}.".format(
                    port_id, switch_id
                )
            )

        for entity_id in __net[switch_id]:
            if __net.has_edge(switch_id, entity_id, port_id):
                return entity_id

        raise PortNotUsed()


def query_sectors_ids():
    with __lock:
        return set(filter((lambda ent_id: ent_id in __entities[Sector]), __net.nodes()))


def query_edges_to_sector(sector_id):
    with __lock:
        sector_id_obj = query_entity(sector_id)
        if not isinstance(sector_id_obj, Sector):
            raise TypeError("sector_id must reference a registered Sector")

        edges = []

        for switch_id in __net[sector_id]:
            for port_in in __net[sector_id][switch_id]:
                link_data = __net[sector_id][switch_id][port_in]['data']
                edges.append((switch_id, port_in, link_data["hash_val"]))

        return edges


def query_address_host(ipv4=None, ipv6=None):
    assert not ((ipv4 is None) and (ipv6 is None)), "ipv4 and ipv6 cannot be null at the same time"
    assert isinstance(ipv4, IPv4Address) or ipv4 is None, "ipv4 is invalid"
    assert isinstance(ipv6, IPv6Address) or ipv6 is None, "ipv6 is invalid"

    with __lock:
        res = tuple(
            filter(
                (lambda ent: isinstance(ent, (Host, RemoteHost)) and (ent.ipv4 == ipv4 or ent.ipv6 == ipv6)),
                __net.nodes()
            )
        )

        assert len(res) in (0, 1), \
            "There are too many entities registered with the same network address. ({:s})".format(str(res))

        if len(res) == 0:
            raise EntityNotRegistered()
        return res[0]


def is_port_connected(switch_id, port_id):
    """
    :param switch_id: Switch entity ID
    :param port_id: Switch Port
    :return:
    """
    assert __sector_initialized, "sector not initialised"
    assert isinstance(port_id, int), \
        "switch_a_port_no type expected to be int. Got {:s}".format(type(port_id).__name__)

    with __lock:
        switch = query_entity(switch_id)

        if port_id not in switch.ports:
            raise PortNotRegistered()

        for entity_id in __net[switch_id]:
            if __net.has_edge(switch_id, entity_id, port_id):
                return True

        return False


def are_entities_connected(entity_a_id, entity_b_id):
    assert __sector_initialized, "sector not initialised"

    with __lock:
        if not __net.has_node(entity_a_id) or not __net.has_node(entity_b_id):
            raise EntityNotRegistered()
        return __net.has_edge(entity_a_id, entity_b_id)


def disconnect_entities(entity_a_id, entity_b_id, port_a=None):
    """
        This method connects two entities. There are three possible combinations.
        1 - (Switch, Host)
        2 - (Switch, Switch)
        3 - (Switch, Sector)

        :param entity_a_id:
        :param entity_b_id:
        :param port_a:
        :return:
    """

    assert __sector_initialized, "sector not initialised"
    if not isinstance(port_a, (int, type(None))):
        raise TypeError("port_a type expected to be int or None. Got {:s}".format(type(port_a)))

    with __lock:
        entity_a = query_entity(entity_a_id)
        entity_b = query_entity(entity_b_id)
        if port_a:
            if port_a not in entity_a.ports:
                raise ValueError("switch_port_no {:d} is is not valid for switch {:d}.".format(port_a, entity_a_id))

            if not __net.has_edge(entity_a_id, entity_b_id, port_a):
                raise EntitiesNotConnected()

        #  1st Case - (Switch, Host)
        if isinstance(entity_a, Switch) and isinstance(entity_b, Host):
            if port_a:
                __net.remove_edge(entity_a_id, entity_b_id, port_a)
                __net.remove_edge(entity_b_id, entity_a_id, port_a)
            else:
                for port in tuple(__net[entity_a_id][entity_b_id].keys()):
                    __net.remove_edge(entity_a_id, entity_b_id, port)
                for port in tuple(__net[entity_b_id][entity_a_id].keys()):
                    __net.remove_edge(entity_b_id, entity_a_id, port)

        # 2nd Case - (Switch, Switch)
        elif isinstance(entity_a, Switch) and isinstance(entity_b, Switch):
            entity_a_mac = __net[entity_a_id][entity_b_id][port_a]["data"]["source_mac"]
            entity_b_mac = __net[entity_a_id][entity_b_id][port_a]["data"]["destiny_mac"]

            if port_a:
                port_b = None
                for port_b in __net[entity_b_id][entity_a_id]:
                    link_data = __net[entity_b_id][entity_a_id][port_b]["data"]
                    if link_data["source_mac"] == entity_b_mac and link_data["destiny_mac"] == entity_a_mac:
                        break

                assert port_b, "Link inconsistency. Entity {:s} is not connected to entity {:s} when it should.".format(
                    str(entity_a), str(entity_b)
                )
                __net.remove_edge(entity_a_id, entity_b_id, port_a)
                __net.remove_edge(entity_b_id, entity_a_id, port_b)
            else:
                for port in tuple(__net[entity_a_id][entity_b_id].keys()):
                    __net.remove_edge(entity_a_id, entity_b_id, port)
                for port in tuple(__net[entity_b_id][entity_a_id].keys()):
                    __net.remove_edge(entity_b_id, entity_a_id, port)

        # 3rd Case - (Switch, Sector)
        elif isinstance(entity_a, Switch) and isinstance(entity_b, Sector):
            if port_a:
                __net.remove_edge(entity_a_id, entity_b_id, port_a)
                __net.remove_edge(entity_b_id, entity_a_id, port_a)
            else:
                for port in tuple(__net[entity_a_id][entity_b_id].keys()):
                    __net.remove_edge(entity_a_id, entity_b_id, port)
                for port in tuple(__net[entity_b_id][entity_a_id].keys()):
                    __net.remove_edge(entity_b_id, entity_a_id, port)

        else:
            raise LinkException(
                "Invalid entities combination to disconnect: {:s} with {:s}".format(
                    type(entity_a).__name__,
                    type(entity_b).__name__
                )
            )


def construct_unidirectional_path(
        origin_id,
        target_id,
        allocated_bandwith=None,
        previous_sector_hash=None,
        next_sector_hash=None,
):
    try:
        with __lock:
            path = []  # Discovered Path
            edges = []  # Path graph edges used for reservation

            if not is_entity_registered(origin_id) or not is_entity_registered(target_id):
                raise EntityNotRegistered()

            # Make a copy of the network graph
            net_cpy = __net.copy()

            origin_ent_is_sector = True if isinstance(query_entity(origin_id), Sector) else False
            target_ent_is_sector = True if isinstance(query_entity(target_id), Sector) else False

            # If hash values are provided
            if origin_ent_is_sector and previous_sector_hash is not None:
                remove_links = []
                for dst_id in net_cpy[origin_id]:
                    for port_id in net_cpy[origin_id][dst_id]:
                        if net_cpy[origin_id][dst_id][port_id]['data']['hash_val'] != previous_sector_hash:
                            remove_links.append((dst_id, port_id))

                for (dst_id, port_id) in remove_links:
                    net_cpy.remove_edge(origin_id, dst_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((origin_id, dst_id, port_id))))
                    net_cpy.remove_edge(dst_id, origin_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((dst_id, origin_id, port_id))))

            if target_ent_is_sector and next_sector_hash is not None:
                remove_links = []
                for switch_id in net_cpy[target_id]:
                    for port_id in net_cpy[target_id][switch_id]:
                        if net_cpy[target_id][switch_id][port_id]['data']['hash_val'] != next_sector_hash:
                            remove_links.append((switch_id, port_id))

                for (switch_id, port_id) in remove_links:
                    net_cpy.remove_edge(target_id, switch_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((target_id, switch_id, port_id))))
                    net_cpy.remove_edge(switch_id, target_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((switch_id, target_id, port_id))))

            # Remove Nodes which are Sectors but are neither an origin sector or a target sector.
            # This will prevent the shortest path algorithm from choosing paths which bo through Sector Nodes in the
            #   topology.
            for node_id in tuple(net_cpy.nodes()):
                if isinstance(query_entity(node_id), Sector):
                    if not (
                        (origin_ent_is_sector and node_id == origin_id) or
                        (target_ent_is_sector and node_id == target_id)
                    ):
                        net_cpy.remove_node(node_id)

            # Remove edges that cannot fulfill the required bandwidth
            if allocated_bandwith:
                for (node_a, node_b, port) in tuple(net_cpy.edges(keys=True)):
                    if __net[node_a][node_b][port]['data']['available_speed'] < allocated_bandwith:
                        _log.debug(
                            "Removing edge {:s} for lacking enough bandwidth."
                            " {:d} is required."
                            " Only {:d} is available.".format(
                                str((node_a, node_b, port)),
                                allocated_bandwith,
                                __net[node_a][node_b][port]['data']['available_speed']
                            )
                        )
                        net_cpy.remove_edge(node_a, node_b, port)

            shortest_path = nx.shortest_path(net_cpy, origin_id, target_id)
            assert len(shortest_path) >= 3, "shortest_path must have at least 3 nodes. It has {:d}".format(
                len(shortest_path)
            )
            remaining_bandwidth_average = []
            #  Create a path with ports, using the calculated shortest_path
            #  (host or sector, in_port switch), (port_in, switch id, port out), (host or sector, in_port switch)
            if len(shortest_path) == 3:  # If the path only has 3 elements (source, middle switch, destiny)
                head_id = shortest_path[0]
                tail_id = shortest_path[2]
                switch_id = shortest_path[1]
                port_in = max(
                    (port for port in net_cpy[switch_id][head_id]),
                    key=(lambda p: net_cpy[switch_id][head_id][p]['data']['available_speed'])
                )
                port_out = max(
                    (port for port in net_cpy[switch_id][tail_id]),
                    key=(lambda p: net_cpy[switch_id][tail_id][p]['data']['available_speed'])
                )
                path.append(head_id)
                path.append((switch_id, port_in, port_out))
                path.append(tail_id)
                edges = [
                    (head_id, switch_id, port_in),
                    (switch_id, tail_id, port_out),
                ]
                if allocated_bandwith:
                    link_data = __net[head_id][switch_id][port_in]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                    )
                    link_data = __net[switch_id][tail_id][port_out]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                    )
                    __net[head_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                    __net[switch_id][tail_id][port_out]['data']['available_speed'] -= allocated_bandwith
                else:
                    link_data = __net[head_id][switch_id][port_in]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed']) / link_data['max_speed']
                    )
                    link_data = __net[switch_id][tail_id][port_out]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed']) / link_data['max_speed']
                    )

            else:  # If the path has more than 3 elements (source, ...[middle switches]... , destiny)
                head_id = shortest_path[0]
                tail_id = shortest_path[-1]
                path.append(head_id)
                for i in range(1, len(shortest_path)-1):
                    before_ent_id = shortest_path[i-1]
                    after_ent_id = shortest_path[i+1]
                    switch_id = shortest_path[i]
                    port_in = max(
                        (port for port in net_cpy[switch_id][before_ent_id]),
                        key=(lambda p: net_cpy[switch_id][before_ent_id][p]['data']['available_speed'])
                    )
                    port_out = max(
                        (port for port in net_cpy[switch_id][after_ent_id]),
                        key=(lambda p: net_cpy[switch_id][after_ent_id][p]['data']['available_speed'])
                    )
                    if before_ent_id == head_id:
                        edges.append((before_ent_id, switch_id, port_in))
                        link_data = __net[before_ent_id][switch_id][port_in]['data']
                        if allocated_bandwith:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                            )
                            __net[before_ent_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        else:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed']) / link_data['max_speed']
                            )

                    elif after_ent_id == tail_id:
                        edges.append((switch_id, after_ent_id, port_out))
                        link_data = __net[switch_id][after_ent_id][port_out]['data']
                        if allocated_bandwith:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                            )
                            __net[switch_id][after_ent_id][port_out]['data']['available_speed'] -= allocated_bandwith
                        else:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed']) / link_data['max_speed']
                            )

                    path.append((switch_id, port_in, port_out))
                    edges.append((switch_id, after_ent_id, port_out))
                    link_data = __net[switch_id][after_ent_id][port_out]['data']
                    if allocated_bandwith:
                        remaining_bandwidth_average.append(
                            (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                        )
                        __net[switch_id][after_ent_id][port_out]['data']['available_speed'] -= allocated_bandwith
                    else:
                        remaining_bandwidth_average.append(
                            (link_data['available_speed']) / link_data['max_speed']
                        )
                path.append(tail_id)

            def remove_scenario():
                with __lock:
                    if allocated_bandwith:
                        for (from_ent, to_ent, network_port) in edges:
                            if __net.has_edge(from_ent, to_ent, network_port):
                                __net[from_ent][to_ent][network_port]['data']['available_speed'] += allocated_bandwith
            if allocated_bandwith:
                assert len(remaining_bandwidth_average), "remaining_bandwidth_average length is zero. This cannot be..."

            sector_path = __OneDirectionPath(
                path,
                partial(
                    remove_scenario
                ),
                sum(remaining_bandwidth_average) * 100.0 / len(remaining_bandwidth_average)
            )

            _log.debug(
                "Unidirectional Path allocated{:s}\n{:s}{:s}".format(
                    " with reservation ({:d})".format(allocated_bandwith) if allocated_bandwith else ".",
                    "  Path: ([{:s}])\n".format("][".join(tuple((str(i) for i in path)))),
                    "  Edges ([{:s}]).".format("][".join(tuple((str(i) for i in edges))))
                )
            )

            return sector_path

    except nx.exception.NetworkXNoPath:
        _log.warning(
            "Path not found between entities {:s} and {:s}{:s}.".format(
                str(origin_id),
                str(target_id),
                " capable of accommodating {:d} for bandwidth reservation".format(
                    allocated_bandwith
                ) if allocated_bandwith else ""
            )
        )
        raise PathNotFound()


def construct_bidirectional_path(
        origin_id,
        target_id,
        allocated_bandwith=None,
        previous_sector_hash=None,
        next_sector_hash=None
):
    """
        Constructs the scenario specified by :param scenario_type.

    """

    try:
        with __lock:
            path = []  # Discovered Path
            edges = []  # Path graph edges used for reservation

            if not (origin_id) or not is_entity_registered(target_id):
                raise EntityNotRegistered()

            # Make a copy of the network graph
            net_cpy = __net.copy()

            origin_ent_is_sector = True if isinstance(query_entity(origin_id), Sector) else False
            target_ent_is_sector = True if isinstance(query_entity(target_id), Sector) else False

            # If hash values are provided
            if origin_ent_is_sector and previous_sector_hash is not None:
                remove_links = []
                for dst_id in net_cpy[origin_id]:
                    for port_id in net_cpy[origin_id][dst_id]:
                        if net_cpy[origin_id][dst_id][port_id]['data']['hash_val'] != previous_sector_hash:
                            remove_links.append((dst_id, port_id))

                for (dst_id, port_id) in remove_links:
                    net_cpy.remove_edge(origin_id, dst_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((origin_id, dst_id, port_id))))
                    net_cpy.remove_edge(dst_id, origin_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((dst_id, origin_id, port_id))))

            if target_ent_is_sector and next_sector_hash is not None:
                remove_links = []
                for switch_id in net_cpy[target_id]:
                    for port_id in net_cpy[target_id][switch_id]:
                        _log.debug("target_id: {:s}   switch_id: {:d}".format(str(target_id), switch_id))
                        _log.debug("next_sector_hash: {:d}    hash_val: {:d}".format(next_sector_hash, net_cpy[target_id][switch_id][port_id]['data']['hash_val']))
                        if net_cpy[target_id][switch_id][port_id]['data']['hash_val'] != next_sector_hash:
                            remove_links.append((switch_id, port_id))

                for (switch_id, port_id) in remove_links:
                    net_cpy.remove_edge(target_id, switch_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((target_id, switch_id, port_id))))
                    net_cpy.remove_edge(switch_id, target_id, port_id)
                    _log.debug("Removed edge {:s} from temporary topology.".format(str((switch_id, target_id, port_id))))

            # Remove Nodes which are Sectors but are neither an origin sector or a target sector.
            # This will prevent the shortest path algorithm from choosing paths which bo through Sector Nodes in the
            #   topology.
            for node_id in tuple(net_cpy.nodes()):
                if isinstance(query_entity(node_id), Sector):
                    if not (
                        (origin_ent_is_sector and node_id == origin_id) or
                        (target_ent_is_sector and node_id == target_id)
                    ):
                        net_cpy.remove_node(node_id)

            # Remove edges that cannot fulfill the required bandwidth
            if allocated_bandwith:
                for (node_a, node_b, port) in tuple(net_cpy.edges(keys=True)):
                    if __net[node_a][node_b][port]['data']['available_speed'] < allocated_bandwith:
                        _log.debug(
                            "Removing edge {:s} for lacking enough bandwidth."
                            " {:d} is required."
                            " Only {:d} is available.".format(
                                str((node_a, node_b, port)),
                                allocated_bandwith,
                                __net[node_a][node_b][port]['data']['available_speed']
                            )
                        )
                        net_cpy.remove_edge(node_a, node_b, port)
            # __log.debug(
            #     "edges: {:s}".format(str(tuple(net_cpy.edges)))
            # )
            shortest_path = nx.shortest_path(net_cpy, origin_id, target_id)
            assert len(shortest_path) >= 3, "shortest_path must have at least 3 nodes. It has {:d}".format(
                len(shortest_path)
            )

            remaining_bandwidth_average = []
            #  Create a path with ports, using the calculated shortest_path
            #  (host or sector, in_port switch), (port_in, switch id, port out), (host or sector, in_port switch)
            if len(shortest_path) == 3:  # If the path only has 3 elements (source, middle switch, destiny)
                head_id = shortest_path[0]
                tail_id = shortest_path[2]
                switch_id = shortest_path[1]
                port_in = max(
                    (port for port in net_cpy[switch_id][head_id]),
                    key=(lambda p: net_cpy[switch_id][head_id][p]['data']['available_speed'])
                )
                port_out = max(
                    (port for port in net_cpy[switch_id][tail_id]),
                    key=(lambda p: net_cpy[switch_id][tail_id][p]['data']['available_speed'])
                )
                path.append(head_id)
                path.append((switch_id, port_in, port_out))
                path.append(tail_id)
                edges = [
                    (switch_id, head_id, port_in),
                    (head_id, switch_id, port_in),
                    (switch_id, tail_id, port_out),
                    (tail_id, switch_id, port_out),
                ]

                if allocated_bandwith:
                    link_data = __net[switch_id][head_id][port_in]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                    )
                    link_data = __net[head_id][switch_id][port_in]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                    )
                    link_data = __net[switch_id][tail_id][port_out]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                    )
                    link_data = __net[tail_id][switch_id][port_out]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                    )
                    __net[switch_id][head_id][port_in]['data']['available_speed'] -= allocated_bandwith
                    __net[head_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                    __net[switch_id][tail_id][port_out]['data']['available_speed'] -= allocated_bandwith
                    __net[tail_id][switch_id][port_out]['data']['available_speed'] -= allocated_bandwith

                else:
                    link_data = __net[switch_id][head_id][port_in]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed']) / link_data['max_speed']
                    )
                    link_data = __net[head_id][switch_id][port_in]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed']) / link_data['max_speed']
                    )
                    link_data = __net[switch_id][tail_id][port_out]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed']) / link_data['max_speed']
                    )
                    link_data = __net[tail_id][switch_id][port_out]['data']
                    remaining_bandwidth_average.append(
                        (link_data['available_speed']) / link_data['max_speed']
                    )

            else:  # If the path has more than 3 elements (source, ...[middle switches]... , destiny)
                head_id = shortest_path[0]
                tail_id = shortest_path[-1]
                path.append(head_id)
                for i in range(1, len(shortest_path)-1):
                    before_ent_id = shortest_path[i-1]
                    after_ent_id = shortest_path[i+1]
                    switch_id = shortest_path[i]
                    port_in = max(
                        (port for port in net_cpy[switch_id][before_ent_id]),
                        key=(lambda p: net_cpy[switch_id][before_ent_id][p]['data']['available_speed'])
                    )
                    port_out = max(
                        (port for port in net_cpy[switch_id][after_ent_id]),
                        key=(lambda p: net_cpy[switch_id][after_ent_id][p]['data']['available_speed'])
                    )
                    path.append((switch_id, port_in, port_out))
                    if before_ent_id == head_id:
                        edges.append((before_ent_id, switch_id, port_in))
                        link_data = __net[before_ent_id][switch_id][port_in]['data']
                        if allocated_bandwith:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                            )
                            __net[before_ent_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        else:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed']) / link_data['max_speed']
                            )
                    elif after_ent_id == tail_id:
                        edges.append((after_ent_id, switch_id, port_out))
                        link_data = __net[after_ent_id][switch_id][port_out]['data']
                        if allocated_bandwith:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                            )
                            __net[after_ent_id][switch_id][port_out]['data']['available_speed'] -= allocated_bandwith
                        else:
                            remaining_bandwidth_average.append(
                                (link_data['available_speed']) / link_data['max_speed']
                            )

                    edges.append((switch_id, before_ent_id, port_in))
                    edges.append((switch_id, after_ent_id, port_out))
                    if allocated_bandwith:
                        link_data = __net[switch_id][before_ent_id][port_in]['data']
                        remaining_bandwidth_average.append(
                            (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                        )
                        link_data = __net[switch_id][after_ent_id][port_out]['data']
                        remaining_bandwidth_average.append(
                            (link_data['available_speed'] - allocated_bandwith) / link_data['max_speed']
                        )
                        __net[switch_id][before_ent_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        __net[switch_id][after_ent_id][port_out]['data']['available_speed'] -= allocated_bandwith
                    else:
                        link_data = __net[switch_id][before_ent_id][port_in]['data']
                        remaining_bandwidth_average.append(
                            (link_data['available_speed']) / link_data['max_speed']
                        )
                        link_data = __net[switch_id][after_ent_id][port_out]['data']
                        remaining_bandwidth_average.append(
                            (link_data['available_speed']) / link_data['max_speed']
                        )

                path.append(tail_id)

            def remove_scenario(allocated_bandwith, edges):
                with __lock:
                    if allocated_bandwith:
                        for (from_ent, to_ent, network_port) in edges:
                            if __net.has_edge(from_ent, to_ent, network_port):
                                __net[from_ent][to_ent][network_port]['data']['available_speed'] += allocated_bandwith

            if allocated_bandwith:
                assert len(remaining_bandwidth_average), "remaining_bandwidth_average length is zero. This cannot be..."

            sector_path = __BiDirectionPath(
                path,
                partial(
                    remove_scenario,
                    allocated_bandwith,
                    edges
                ),
                sum(remaining_bandwidth_average)*100.0/len(remaining_bandwidth_average) if allocated_bandwith else None
            )

            _log.debug(
                "Bidirectional Path allocated{:s}\n{:s}{:s}".format(
                    " with reservation ({:d})".format(allocated_bandwith) if allocated_bandwith else ".",
                    "  Path: ([{:s}])\n".format("][".join(tuple((str(i) for i in path)))),
                    "  Edges ([{:s}]).".format("][".join(tuple((str(i) for i in edges))))
                )
            )
            return sector_path

    except nx.exception.NetworkXNoPath:
        _log.warning(
            "Path not found between entities {:s} and {:s}{:s}.".format(
                str(origin_id),
                str(target_id),
                " capable of accommodating {:d} for bandwidth reservation".format(allocated_bandwith)
                if allocated_bandwith else ""
            )
        )
        raise PathNotFound()

