__all__ = [
    "initialise",
    "get_database_info",
    "close",
    "register_datapath",
    "is_datapath_registered",
    "query_datapath_info",
    "remove_datapath",
    "dump_datapth_registered_ids",
    "dump_datapth_registered_clients_ids",
    "save_flow",
    "query_flow",
    "remove_flow",
    "query_flow_ids",
    "register_client",
    "query_client_info",
    "query_client_id",
    "query_address_information",
    "remove_client",
    "update_client_addresses",
    "query_volatile_info",
    "update_volatile_information",
    "ClientNotRegistered",
    "ClientAlreadyRegistered",
    "DatapathNotRegistered",
    "DatapathAlreadyRegistered",
    "FlowAlreadyRegistered",
    "FlowNotRegistered",
    "AddressNotRegistered"
]


import sys
#import atexit
import logging

#from threading import Thread
#from queue import Queue
#from eventlet.queue import LightQueue as Queue
#import eventlet
#from eventlet.event import Event
#from eventlet import spawn

from archsdn.helpers import logger_module_name

from archsdn.database.internals.generic import initialise as __initialise
from archsdn.database.internals.generic import infos as __get_database_info
from archsdn.database.internals.generic import close as __close
from archsdn.database.internals.datapath import register as __register_datapath
from archsdn.database.internals.datapath import query_info as __query_datapath_info
from archsdn.database.internals.datapath import remove as __remove_datapath
from archsdn.database.internals.datapath import is_registered as __is_datapath_registered
from archsdn.database.internals.datapath import dump_ids as __dump_datapth_registered_ids
from archsdn.database.internals.datapath import dump_datapath_clients_ids as __dump_datapth_registered_clients_ids
from archsdn.database.internals.flow import save as __save_flow
from archsdn.database.internals.flow import info as __query_flow
from archsdn.database.internals.flow import remove as __remove_flow
from archsdn.database.internals.flow import get_cookie_ids as __get_flow_ids
from archsdn.database.internals.clients import register as __register_client
from archsdn.database.internals.clients import query_info as __query_client_info
from archsdn.database.internals.clients import query_client_id as __query_client_id
from archsdn.database.internals.clients import query_address_info as __query_address_information
from archsdn.database.internals.clients import remove as __remove_client
from archsdn.database.internals.clients import update_addresses as __update_client_addresses

from archsdn.database.internals.exceptions import \
    Client_Not_Registered as __Client_Not_Registered, \
    Client_Already_Registered as __Client_Already_Registered, \
    Datapath_Not_Registered as __Datapath_Not_Registered, \
    Datapath_Already_Registered as __Datapath_Already_Registered, \
    Flow_Already_Registered as __Flow_Already_Registered, \
    Flow_Not_Registered as __Flow_Not_Registered, \
    Address_Not_Registered as __Address_Not_Registered

from archsdn.database.volatile_data import \
    query_volatile_info as __query_volatile_info, \
    update_volatile_information as __update_volatile_information


_callbacks = {
    "initialise": __initialise,
    "close": __close,
    "get_database_info": __get_database_info,
    "register_datapath": __register_datapath,
    "is_datapath_registered": __is_datapath_registered,
    "query_datapath_info": __query_datapath_info,
    "remove_datapath": __remove_datapath,
    "dump_datapth_registered_ids": __dump_datapth_registered_ids,
    "dump_datapth_registered_clients_ids": __dump_datapth_registered_clients_ids,
    "save_flow": __save_flow,
    "query_flow": __query_flow,
    "remove_flow": __remove_flow,
    "query_flow_ids": __get_flow_ids,
    "register_client": __register_client,
    "query_client_info": __query_client_info,
    "query_client_id": __query_client_id,
    "query_address_info": __query_address_information,
    "remove_client": __remove_client,
    "update_client_addresses": __update_client_addresses,
    "query_volatile_info": __query_volatile_info,
    "update_volatile_information": __update_volatile_information
}

_exceptions = {
    "ClientNotRegistered": __Client_Not_Registered,
    "ClientAlreadyRegistered": __Client_Already_Registered,
    "DatapathNotRegistered": __Datapath_Not_Registered,
    "DatapathAlreadyRegistered": __Datapath_Already_Registered,
    "Flow_AlreadyRegistered": __Flow_Already_Registered,
    "FlowNotRegistered": __Flow_Not_Registered,
    "AddressNotRegistered": __Address_Not_Registered,
}

_log = logging.getLogger(logger_module_name(__file__))
#_shutdown = None
class __Wrapper:
    def __init__(self, wrapped):
        global _shutdown

        self.__wrapped = wrapped
        # self.__pool = eventlet.GreenPool()
        # self.__shutdown_event = Event()
        #
        # def database_thread_main(start_event):
        #     try:
        #         start_event.send()
        #         self.__pool.waitall()
        #
        #     except Exception:
        #         custom_logging_callback(_log, logging.ERROR, *sys.exc_info())
        #     finally:
        #         _log.debug("Database thread is shutting down...")
        #         self.__shutdown_event.send()
        #
        # def shutdown():
        #     self.__pool.
        #
        #     self.__funcs_queue.put(None)
        #     self.__shutdown_event.wait()
        #
        # _shutdown = shutdown
        #
        # boot_event = Event()
        # self.__database_thread = Thread(target=database_thread_main, args=(boot_event,))
        # self.__database_thread.start()
        # boot_event.wait()


    def __getattr__(self, name):
        if name in _exceptions:
            return _exceptions[name]

        if name not in _callbacks:
            raise AttributeError("module has no member called {:s}".format(name))

        def attr(*args, **kwargs):
            return _callbacks[name](*args, **kwargs)
            # event = Event()
            #
            # def cr(*args, **kwargs):
            #     try:
            #         print("5" * 20)
            #         event.send(_callbacks[name](*args, **kwargs))
            #         print("6" * 20)
            #
            #     except Exception:
            #         event.send_exception(*sys.exc_info())
            #
            # print("1" * 20)
            # self.__pool.spawn(cr)
            # print("4" * 20)
            # result = event.wait()
            # print("7" * 20)
            # print(result)
            # return result

        return attr


sys.modules[__name__] = __Wrapper(sys.modules[__name__])
#assert _shutdown, "_shutdown is None. This means the Wrapper was not initialized."
#atexit.register(_shutdown)
