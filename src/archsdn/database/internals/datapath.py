from time import time, localtime
import logging
from copy import deepcopy


from .exceptions import DatapathNotRegistered, DatapathAlreadyRegistered
from .data_validation import is_ipv4_port_tuple, is_ipv6_port_tuple

from ...database import data

_log = logging.getLogger(__name__)

def query_info(datapath_id):
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"

    try:
        with data.database_semaphore:

            res = data.database_data["datapaths"][datapath_id]

            datapath_info = {
                "ipv4": deepcopy(res["ipv4"]),
                "ipv4_port": deepcopy(res["ipv4_port"]),
                "ipv6": deepcopy(res["ipv6"]),
                "ipv6_port": deepcopy(res["ipv6_port"]),
                "registration_date": localtime(res["registration_date"]),
            }
            _log.debug("Querying Datapath {:d} Info: {:s}".format(datapath_id, str(datapath_info)))
            return datapath_info

    except KeyError:
        _log.debug("Datapath not registered 0x{:016X}.".format(datapath_id))
        raise DatapathNotRegistered()

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def register(datapath_id, ipv4_info=None, ipv6_info=None):
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    assert not ((ipv4_info is None) and (ipv6_info is None)), "ipv4_info and ipv6_info cannot be None at the same time"
    assert is_ipv4_port_tuple(ipv4_info) or ipv4_info is None, "ipv4_info is invalid"
    assert is_ipv6_port_tuple(ipv6_info) or ipv6_info is None, "ipv6_info is invalid"

    try:

        with data.database_semaphore:
            if datapath_id in data.database_data["datapaths"]:
                _log.debug("Datapath already registered 0x{:016X}.".format(datapath_id))
                raise DatapathAlreadyRegistered()

            for dp_id in data.database_data["datapaths"]:
                datapath_data = data.database_data["datapaths"][dp_id]
                if ipv4_info:
                    if datapath_data["ipv4"] == ipv4_info[0] and datapath_data["ipv4_port"] == ipv4_info[1]:
                        _log.debug(
                            "Datapath 0x{:016X} is already registered with IPv4 info {:s}.".format(
                                dp_id,
                                str(ipv4_info)
                            )
                        )
                        raise DatapathAlreadyRegistered()

                if ipv6_info:
                    if datapath_data["ipv6"] == ipv6_info[0] and datapath_data["ipv6_port"] == ipv6_info[1]:
                        _log.debug(
                            "Datapath 0x{:016X} is already registered with IPv6 info {:s}.".format(
                                dp_id,
                                str(ipv6_info)
                            )
                        )
                        raise DatapathAlreadyRegistered()

            data.database_data["datapaths"][datapath_id] = {
                "ipv4": None if ipv4_info is None else deepcopy(ipv4_info[0]),
                "ipv4_port": None if ipv4_info is None else deepcopy(ipv4_info[1]),
                "ipv6": None if ipv6_info is None else deepcopy(ipv6_info[0]),
                "ipv6_port": None if ipv6_info is None else deepcopy(ipv6_info[1]),
                "registration_date": time()
            }

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def remove(datapath_id):
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    try:

        with data.database_semaphore:
            client_ids_to_remove = tuple(
                id for id in data.database_data["clients"].keys()
                if data.database_data["clients"][id]["datapath"] == datapath_id
            )

            for client_id in client_ids_to_remove:
                del data.database_data["clients"][client_id]
            del data.database_data["datapaths"][datapath_id]

    except KeyError:
        _log.debug("Cannot remove Datapath {:d}: Not Registered".format(datapath_id))
        raise DatapathNotRegistered()

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def is_registered(datapath_id):
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"

    try:
        with data.database_semaphore:
            return datapath_id in data.database_data["datapaths"]

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def dump_ids():
    try:
        _log.debug("Dumping all Datapaths IDs")
        with data.database_semaphore:
            return tuple(data.database_data["datapaths"].keys())

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def dump_datapath_clients_ids(datapath_id):
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"

    try:
        _log.debug("Dumping all registered hosts for datapath {:d}".format(datapath_id))
        with data.database_semaphore:

            return tuple(
                id for id in data.database_data["clients"].keys()
                if data.database_data["clients"][id]["datapath"] == datapath_id
            )

    except Exception as ex:
        _log.error(str(ex))
        raise ex
