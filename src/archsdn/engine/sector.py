import logging
from threading import RLock

import networkx as nx

from archsdn.helpers import logger_module_name
from archsdn.engine.entities import \
    Switch, Host, Sector

from archsdn.engine.exceptions import \
    EntityAlreadyRegistered, EntityNotRegistered, \
    LinkException, SwitchPortAlreadyConnected, PortNotUsed, PortNotRegistered, \
    EntitiesAlreadyConnected, EntitiesNotConnected

__log = logging.getLogger(logger_module_name(__file__))

__net = None
__lock = None
__entities = None
__suported_entities = {Switch, Host, Sector}
__suported_entities_str = ", ".join((str(i) for i in __suported_entities))

__sector_initialized = False


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

            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_port_no'],
                data={}
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_port_no'],
                data={
                    'source_mac': entity_b.mac
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

            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_a_port_no'],
                data={
                    'source_mac': entity_a.ports[kwargs['switch_a_port_no']]["hw_addr"],
                    'destiny_mac': entity_b.ports[kwargs['switch_b_port_no']]["hw_addr"]
                }
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_b_port_no'],
                data={
                    'source_mac': entity_b.ports[kwargs['switch_b_port_no']]["hw_addr"],
                    'destiny_mac': entity_a.ports[kwargs['switch_a_port_no']]["hw_addr"]
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

            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_port_no'],
                data={}
            )
            __net.add_edge(
                entity_b_id, entity_a_id, kwargs['switch_port_no'],
                data={}
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
