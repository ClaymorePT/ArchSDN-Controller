import logging
from threading import RLock

import networkx as nx

from archsdn.helpers import logger_module_name
from archsdn.engine.entities import \
    Switch, Host, Sector

from archsdn.engine.exceptions import \
    EntityAlreadyRegistered, EntityNotRegistered, \
    LinkException, SwitchPortAlreadyConnected, PortNotUsed, PortNotRegistered

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
            if len(missing_args) > 0:
                raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

            if not isinstance(kwargs['switch_port_no'], int):
                TypeError("switch_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_port_no'])))
            if kwargs['switch_port_no'] in entity_a.ports:
                ValueError(
                    "switch_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_port_no'], entity_a_id
                    )
                )

            if len(
                    tuple(
                        filter(
                            (lambda entity: kwargs['switch_port_no'] in __net[entity_a_id][entity]),
                            __net[entity_a_id]
                        )
                    )
            ) > 0:
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
            if len(missing_args) > 0:
                raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

            if not isinstance(kwargs['switch_a_port_no'], int):
                TypeError("switch_a_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_a_port_no'])))
            if kwargs['switch_a_port_no'] in entity_a.ports:
                ValueError(
                    "switch_a_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_a_port_no'], entity_a_id
                    )
                )

            if not isinstance(kwargs['switch_b_port_no'], int):
                TypeError("switch_b_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_b_port_no'])))
            if kwargs['switch_b_port_no'] in entity_a.ports:
                ValueError(
                    "switch_b_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_b_port_no'], entity_b_id
                    )
                )

            if len(
                    tuple(
                        filter(
                            (lambda entity: kwargs['switch_a_port_no'] in __net[entity_a_id][entity]),
                            __net[entity_a_id]
                        )
                    )
            ) > 0:
                raise SwitchPortAlreadyConnected(kwargs['switch_a_port_no'])

            if len(
                    tuple(
                        filter(
                            (lambda entity: kwargs['switch_b_port_no'] in __net[entity_b_id][entity]),
                            __net[entity_b_id]
                        )
                    )
            ) > 0:
                raise SwitchPortAlreadyConnected(kwargs['switch_b_port_no'])

            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_a_port_no'],
                data={}
            )
            __net.add_edge(
                entity_a_id, entity_b_id, kwargs['switch_b_port_no'],
                data={}
            )

        # 3rd Case - (Switch, Sector)
        elif isinstance(entity_a, Switch) and isinstance(entity_b, Sector):
            missing_args = tuple(filter((lambda arg: arg not in kwargs), ('switch_port_no', )))
            if len(missing_args) > 0:
                raise TypeError("The following arguments are missing: {:s}".format(", ".join(missing_args)))

            if not isinstance(kwargs['switch_port_no'], int):
                TypeError("switch_port_no type expected to be int. Got {:s}".format(type(kwargs['switch_port_no'])))
            if kwargs['switch_port_no'] in entity_a.ports:
                ValueError(
                    "switch_port_no {:d} is is not valid for switch {:d}.".format(
                        kwargs['switch_port_no'], entity_a_id
                    )
                )
            if len(
                    tuple(
                        filter(
                            (lambda entity: kwargs['switch_port_no'] in __net[entity_a_id][entity]),
                            __net[entity_a_id]
                        )
                    )
            ) > 0:
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
            ValueError(
                "switch {:d} is is not valid for switch {:016X}.".format(
                    port_id, switch_id
                )
            )
        for entity_id in __net[switch_id]:
            if port_id in __net[switch_id][entity_id]:
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


