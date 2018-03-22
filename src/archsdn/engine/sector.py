import logging
from threading import RLock
from enum import Enum, auto
from functools import partial
from abc import ABC, abstractmethod

import networkx as nx

from archsdn.helpers import logger_module_name
from archsdn.engine.entities import \
    Switch, Host, Sector

from archsdn.engine.exceptions import \
    EntityAlreadyRegistered, EntityNotRegistered, \
    LinkException, SwitchPortAlreadyConnected, PortNotUsed, PortNotRegistered, \
    EntitiesAlreadyConnected, EntitiesNotConnected, PathNotFound

__log = logging.getLogger(logger_module_name(__file__))

__net = None
__lock = None
__entities = None
__suported_entities = {Switch, Host, Sector}
__suported_entities_str = ", ".join((str(i) for i in __suported_entities))

__sector_initialized = False


class ScenarioType(Enum):
    ICMP_TUNNEL = auto()
    UNIDIRECTIONAL_TUNNEL = auto()


class NetworkScenario(ABC):
    @property
    @abstractmethod
    def type(self):
        pass

    @property
    @abstractmethod
    def path(self):
        pass

    @abstractmethod
    def has_entity(self, entity_id):
        pass

    @abstractmethod
    def has_edge(self, edge):
        pass


class __ImplementedScenario(NetworkScenario):
    def __init__(self, scenario_type, path, edges, remove_scenario):
        assert isinstance(scenario_type, ScenarioType), "scenario_type expected to be {:s}. Got {:s}.".format(
            ScenarioType.__name__, str(type(scenario_type))
        )
        assert isinstance(remove_scenario, partial), \
            "unregister_scenario expected to be functools.partial object. Got {:s}".format(
                str(type(remove_scenario))
            )
        self.__type = scenario_type
        self.__path = path
        self.__edges = edges
        self.__remove_scenario = remove_scenario

    @property
    def type(self):
        return self.__type

    @property
    def path(self):
        return self.__path

    def has_entity(self, entity_id):
        if entity_id == self.__path[0] or entity_id == self.__path[-1]:
            return True

        for elem in self.__path[1:-1]:
            if entity_id == elem[0]:
                return True
        return False

    def has_edge(self, edge):
        return edge in self.__edges

    def __del__(self):
        # remove the bandwidth allocation from the sector, when this object is removed
        self.__remove_scenario()

    def __str__(self):
        return "Network Scenario - Type {:s}; Path: [{:s}]".format(
                    str(self.__type),
                    "][".join(tuple((str(i) for i in self.__path)))
                )


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
    '''
        This method connects two entities. There are three possible combinations.
            1 - (Switch, Host)
            2 - (Switch, Switch)
            3 - (Switch, Sector)

        :param entity_a_id:
        :param entity_b_id:
        :param kwargs: 1- switch_port_no; 2- (switch_a_port_no, switch_b_port_no); 3- (port_no, sector_id)
        :return: None
    '''
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
                    "switch_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_port_no'], entity_a_id
                    )
                )

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

            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_port_no'],
                data={
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed
                }
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_port_no'],
                data={
                    'source_mac': entity_b.mac,
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed
                }
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
                    "switch_a_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_a_port_no'], entity_a_id
                    )
                )

            if not isinstance(kwargs['switch_b_port_no'], int):
                raise TypeError("switch_b_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_b_port_no'])))
            if kwargs['switch_b_port_no'] not in entity_a.ports:
                raise ValueError(
                    "switch_b_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_b_port_no'], entity_b_id
                    )
                )

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

            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_a_port_no'],
                data={
                    'source_mac': entity_a.ports[kwargs['switch_a_port_no']]["hw_addr"],
                    'destiny_mac': entity_b.ports[kwargs['switch_b_port_no']]["hw_addr"],
                    'max_speed': max_link_speed_a,
                    'available_speed': max_link_speed_a
                }
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

        # 3rd Case - (Switch, Sector)
        elif isinstance(entity_a, Switch) and isinstance(entity_b, Sector):
            missing_args = tuple(filter((lambda arg: arg not in kwargs), ('switch_port_no', )))
            if len(missing_args):
                raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

            if not isinstance(kwargs['switch_port_no'], int):
                raise TypeError("switch_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_port_no'])))
            if kwargs['switch_port_no'] not in entity_a.ports:
                raise ValueError(
                    "switch_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_port_no'], entity_a_id
                    )
                )
            if len(
                    tuple(
                        filter(
                            (lambda ent: __net.has_edge(entity_a_id, ent, kwargs['switch_port_no'])),
                            __net[entity_a_id]
                        )
                    )
            ):
                raise SwitchPortAlreadyConnected(kwargs['switch_port_no'])
            max_link_speed = entity_a.ports[kwargs['switch_a_port_no']]['max_speed']

            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_port_no'],
                data={
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed
                }
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_port_no'],
                data={
                    'max_speed': max_link_speed,
                    'available_speed': max_link_speed
                }
            )

        else:
            raise LinkException(
                "Invalid entities combination to link: {:s} with {:s}".format(
                    type(entity_a).__name__,
                    type(entity_b).__name__
                )
            )


def query_connected_entity_id(switch_id, port_id):
    '''

    :param switch_id: Switch entity ID
    :param port_id: Switch Port
    :return:
    '''
    assert __sector_initialized, "sector not initialised"
    assert isinstance(port_id, int), \
        "switch_a_port_no type expected to be int. Got {:s}".format(type(port_id).__name__)

    with __lock:
        switch = query_entity(switch_id)

        if port_id not in switch.ports:
            raise ValueError(
                "switch {:d} is is not valid for switch {:016X}.".format(
                    port_id, switch_id
                )
            )

        for entity_id in __net[switch_id]:
            if __net.has_edge(switch_id, entity_id, port_id):
                return entity_id

        raise PortNotUsed()


def is_port_connected(switch_id, port_id):
    '''

    :param switch_id: Switch entity ID
    :param port_id: Switch Port
    :return:
    '''
    assert __sector_initialized, "sector not initialised"
    assert isinstance(port_id, int), \
        "switch_a_port_no type expected to be int. Got {:s}".format(type(port_id).__name__)

    with __lock:
        switch = query_entity(switch_id)

        if port_id not in switch.ports:
            raise PortNotRegistered()

        for entity_id in __net[switch_id]:
            if port_id in __net[switch_id][entity_id]:
                return True

        return False


def are_entities_connected(entity_a_id, entity_b_id):
    assert __sector_initialized, "sector not initialised"

    with __lock:
        if not __net.has_node(entity_a_id) or not __net.has_node(entity_b_id):
            raise EntityNotRegistered()
        return __net.has_edge(entity_a_id, entity_b_id)


def disconnect_entities(entity_a_id, entity_b_id, port_a=None):
    '''
        This method connects two entities. There are three possible combinations.
        1 - (Switch, Host)
        2 - (Switch, Switch)
        3 - (Switch, Sector)

        :param entity_a_id:
        :param entity_b_id:
        :param port_a:
        :return:
    '''

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
            entity_a_mac = __net[entity_a_id][entity_b_id][port_a]["source_mac"]
            entity_b_mac = __net[entity_a_id][entity_b_id][port_a]["destiny_mac"]

            if port_a:
                port_b = None
                for port_b in __net[entity_b_id][entity_a_id]:
                    link_data = __net[entity_b_id][entity_a_id][port_b]
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


def construct_scenario(
        scenario_type,
        origin_id,
        target_id,
        allocated_bandwith = None
):
    '''
        Constructs the scenario specified by :param scenario_type.

        :param scenario_type:
        :param origin_id:
        :param target_id:
        :param allocated_bandwith:
        :return:
    '''
    assert isinstance(scenario_type, ScenarioType), "scenario_type expected to be Scenario. Got {:s}".format(
        type(scenario_type)
    )
    try:
        with __lock:
            path = []  # Discovered Path
            edges = []  # Path graph edges used for reservation

            if not is_entity_registered(origin_id) or not is_entity_registered(target_id):
                raise EntityNotRegistered()

            def remove_scenario():
                with __lock:
                    if allocated_bandwith:
                        for (from_ent, to_ent, network_port) in edges:
                            __net[from_ent][to_ent][network_port]['data']['available_speed'] += allocated_bandwith

            if scenario_type is ScenarioType.ICMP_TUNNEL:
                # Make a copy of the network graph
                net_cpy = __net.copy()

                # Remove edges that cannot fulfill the required bandwidth
                if allocated_bandwith:
                    for (node_a, node_b, port) in tuple(net_cpy.edges(keys=True)):
                        if net_cpy[node_a][node_b][port]['data']['available_speed'] < allocated_bandwith:
                            net_cpy.remove_edge(node_a, node_b, port)

                shortest_path = nx.shortest_path(net_cpy, origin_id, target_id)
                assert len(shortest_path) >= 3, "shortest_path must have at least 3 nodes. It has {:d}".format(
                    len(shortest_path)
                )

                #  Create a path with ports, using the calculated shortest_path
                #  (host or sector, in_port switch), (port_in, switch id, port out), (host or sector, in_port switch)
                path = []
                edges = []
                if len(shortest_path) == 3:  # If the path only has 3 elements (source, middle switch, destiny)
                    head_id = shortest_path[0]
                    tail_id = shortest_path[2]
                    switch_id = shortest_path[1]
                    port_in = max(
                        (port for port in __net[switch_id][head_id]),
                        key=(lambda p: __net[switch_id][head_id][p]['data']['available_speed'])
                    )
                    port_out = max(
                        (port for port in __net[switch_id][tail_id]),
                        key=(lambda p: __net[switch_id][tail_id][p]['data']['available_speed'])
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
                        __net[switch_id][head_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        __net[head_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        __net[switch_id][tail_id][port_out]['data']['available_speed'] -= allocated_bandwith
                        __net[tail_id][switch_id][port_out]['data']['available_speed'] -= allocated_bandwith

                else:  # If the path has more than 3 elements (source, ...[middle switches]... , destiny)
                    head_id = shortest_path[0]
                    tail_id = shortest_path[-1]
                    path.append(head_id)
                    for i in range(1, len(shortest_path)-1):
                        before_ent_id = shortest_path[i-1]
                        after_ent_id = shortest_path[i+1]
                        switch_id = shortest_path[i]
                        port_in = max(
                            (port for port in __net[switch_id][before_ent_id]),
                            key=(lambda p: __net[switch_id][before_ent_id][p]['data']['available_speed'])
                        )
                        port_out = max(
                            (port for port in __net[switch_id][after_ent_id]),
                            key=(lambda p: __net[switch_id][after_ent_id][p]['data']['available_speed'])
                        )
                        path.append((switch_id, port_in, port_out))
                        if before_ent_id == head_id:
                            edges.append((before_ent_id, switch_id, port_in))
                            if allocated_bandwith:
                                __net[before_ent_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        elif after_ent_id == tail_id:
                            edges.append((after_ent_id, switch_id, port_out))
                            if allocated_bandwith:
                                __net[after_ent_id][switch_id][port_out]['data']['available_speed'] -= allocated_bandwith

                        edges.append((switch_id, before_ent_id, port_in))
                        edges.append((switch_id, after_ent_id, port_out))
                        if allocated_bandwith:
                            __net[switch_id][before_ent_id][port_in]['data']['available_speed'] -= allocated_bandwith
                            __net[switch_id][after_ent_id][port_out]['data']['available_speed'] -= allocated_bandwith

                    path.append(tail_id)

            elif scenario_type is ScenarioType.UNIDIRECTIONAL_TUNNEL:
                # Make a copy of the network graph
                net_cpy = __net.copy()

                # Remove edges that cannot fulfill the required bandwidth
                if allocated_bandwith:
                    for (node_a, node_b, port) in tuple(net_cpy.edges(keys=True)):
                        if net_cpy[node_a][node_b][port]['data']['available_speed'] < allocated_bandwith:
                            net_cpy.remove_edge(node_a, node_b, port)

                shortest_path = nx.shortest_path(net_cpy, origin_id, target_id)
                assert len(shortest_path) >= 3, "shortest_path must have at least 3 nodes. It has {:d}".format(
                    len(shortest_path)
                )

                #  Create a path with ports, using the calculated shortest_path
                #  (host or sector, in_port switch), (port_in, switch id, port out), (host or sector, in_port switch)
                if len(shortest_path) == 3:  # If the path only has 3 elements (source, middle switch, destiny)
                    head_id = shortest_path[0]
                    tail_id = shortest_path[2]
                    switch_id = shortest_path[1]
                    port_in = max(
                        (port for port in __net[switch_id][head_id]),
                        key=(lambda p: __net[switch_id][head_id][p]['data']['available_speed'])
                    )
                    port_out = max(
                        (port for port in __net[switch_id][tail_id]),
                        key=(lambda p: __net[switch_id][tail_id][p]['data']['available_speed'])
                    )
                    path.append(head_id)
                    path.append((switch_id, port_in, port_out))
                    path.append(tail_id)
                    edges = [
                        (head_id, switch_id, port_in),
                        (switch_id, tail_id, port_out),
                    ]
                    if allocated_bandwith:
                        __net[head_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        __net[switch_id][tail_id][port_out]['data']['available_speed'] -= allocated_bandwith

                else:  # If the path has more than 3 elements (source, ...[middle switches]... , destiny)
                    head_id = shortest_path[0]
                    tail_id = shortest_path[-1]
                    path.append(head_id)
                    for i in range(1, len(shortest_path)-1):
                        before_ent_id = shortest_path[i-1]
                        after_ent_id = shortest_path[i+1]
                        switch_id = shortest_path[i]
                        port_in = max(
                            (port for port in __net[switch_id][before_ent_id]),
                            key=(lambda p: __net[switch_id][before_ent_id][p]['data']['available_speed'])
                        )
                        port_out = max(
                            (port for port in __net[switch_id][after_ent_id]),
                            key=(lambda p: __net[switch_id][after_ent_id][p]['data']['available_speed'])
                        )
                        if before_ent_id == head_id:
                            edges.append((before_ent_id, switch_id, port_in))
                            if allocated_bandwith:
                                __net[before_ent_id][switch_id][port_in]['data']['available_speed'] -= allocated_bandwith
                        elif after_ent_id == tail_id:
                            edges.append((switch_id, after_ent_id, port_out))
                            if allocated_bandwith:
                                __net[switch_id][after_ent_id][port_out]['data']['available_speed'] -= allocated_bandwith

                        edges.append((switch_id, after_ent_id, port_out))
                        if allocated_bandwith:
                            __net[switch_id][after_ent_id][port_out]['data']['available_speed'] -= allocated_bandwith
                    path.append(tail_id)

            __log.debug(
                "Created Scenario Type {:s} for path {:s} for edges {:s} {:s}.".format(
                    str(scenario_type),
                    "][".join(tuple((str(i) for i in path))),
                    "][".join(tuple((str(i) for i in edges))),
                    "with reservation ({:d})".format(allocated_bandwith) if allocated_bandwith else ""
                )
            )
            network_scenario = __ImplementedScenario(
                scenario_type,
                path,
                edges,
                partial(
                    remove_scenario
                )
            )
            return network_scenario

    except nx.exception.NetworkXNoPath:
        __log.warning(
            "Type {:s} Path not found between entities {:s} and {:s}{:s}.".format(
                str(scenario_type),
                str(origin_id),
                str(target_id),
                " capable of accommodating {:d} for bandwidth reservation".format(
                    allocated_bandwith
                ) if allocated_bandwith else ""
            )
        )
        raise PathNotFound()

