import logging
from threading import Lock

import networkx as nx

from archsdn.helpers import logger_module_name
from archsdn.engine.entities import \
    Entity, Switch

from archsdn.engine.exceptions import \
    EntityAlreadyRegistered, EntityNotRegistered

__log = logging.getLogger(logger_module_name(__file__))

__net = None
__lock = None
__entities = None
__suported_entities = {Switch}


def initialise():
    global __net, __lock, __entities
    __net = nx.MultiDiGraph()
    __lock = Lock()
    __entities = dict(((i, {}) for i in __suported_entities))


def register_entity(entity):
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


def is_entity_registered(entity):
    assert isinstance(entity, tuple(__suported_entities)), \
        "entity is not a supported entity ({:s}): got instead {:s}".format(
            ", ".join((str(i) for i in __suported_entities)),
            repr(entity)
        )

    with __lock:
        return entity.id in __entities[type(entity)]

