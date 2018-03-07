import logging
from threading import Lock

import networkx as nx

from archsdn.helpers import logger_module_name
from archsdn.engine.entities import \
    Switch, Host, Sector

from archsdn.engine.exceptions import \
    EntityAlreadyRegistered, EntityNotRegistered

__log = logging.getLogger(logger_module_name(__file__))

__net = None
__lock = None
__entities = None
__suported_entities = {Switch, Host, Sector}


def initialise():
    global __net, __lock, __entities
    __net = nx.MultiDiGraph()
    __lock = Lock()
    __entities = dict(((i, {}) for i in __suported_entities))


def query_entity(entity_id):
    assert __entities, "sector not initialised"
    with __lock:
        if not __net.has_node(entity_id):
            raise EntityNotRegistered()

        for entity_type in __entities:
            if entity_id in __entities[entity_type]:
                return __entities[entity_type][entity_id]


def register_entity(entity):
    assert __entities, "sector not initialised"
    assert isinstance(entity, tuple(__suported_entities)), \
        "entity is not a supported entity ({:s}): got instead {:s}".format(
            ", ".join((str(i) for i in __suported_entities)),
            repr(entity)
        )

    with __lock:
        if __net.has_node(entity.id):
            raise EntityAlreadyRegistered()

        __net.add_node(entity.id)
        __entities[type(entity)][entity.id] = entity


def remove_entity(entity):
    assert __entities, "sector not initialised"
    assert isinstance(entity, tuple(__suported_entities)), \
        "entity is not a supported entity ({:s}): got instead {:s}".format(
            ", ".join((str(i) for i in __suported_entities)),
            repr(entity)
        )

    with __lock:
        if not entity.id in __entities[type(entity)]:
            raise EntityNotRegistered()
        __net.remove_node(entity.id)
        del __entities[type(entity)][entity.id]


def is_entity_registered(entity_id):
    assert __entities, "sector not initialised"

    with __lock:
        return __net.has_node(entity_id)

#
# def connect_entities(entity_a, entity_b, link):
#     assert isinstance(entity_a, (Switch,)), \
#         "entity_a is not an instance of Sector: got instead {:s}".format(repr(entity_a))
#     assert isinstance(entity_b, (Switch,)), \
#         "entity_b is not an instance of Sector: got instead {:s}".format(repr(entity_b))
#
#     __net.add_edge(entity_a, entity_b, link)







