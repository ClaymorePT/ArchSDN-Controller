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
__switches = None


def initialise():
    global __net, __lock, __switches
    __net = nx.MultiDiGraph()
    __lock = Lock()
    __switches = {}


def register_entity(entity):
    assert isinstance(entity, Entity), \
        "entity is not an instance of Entity: got instead {:s}".format(repr(entity))

    with __lock:
        if __net.has_node(entity.id):
            raise EntityAlreadyRegistered()

        __net.add_node(entity.id)
        if isinstance(entity, Switch):
            __switches[entity.id] = entity


def remove_entity(entity):
    assert isinstance(entity, Entity), \
        "entity is not an instance of Entity: got instead {:s}".format(repr(entity))

    with __lock:
        if not __net.has_node(entity.id):
            raise EntityNotRegistered()
        __net.remove_node(entity.id)


def is_entity_registered(entity):
    assert isinstance(entity, Entity), \
        "entity is not an instance of Entity: got instead {:s}".format(repr(entity))

    with __lock:
        return __net.has_node(entity.id)

