from time import time, localtime
import logging
from contextlib import closing
from netaddr import EUI
from ipaddress import IPv4Address, IPv6Address
from copy import deepcopy

from .exceptions import ClientNotRegistered, ClientAlreadyRegistered, AddressNotRegistered

from ...database import data

_log = logging.getLogger(__name__)

def query_info(client_id):
    assert isinstance(client_id, int), "client_id is not int"
    assert client_id >= 0,  "client_id cannot be negative"

    try:
        with data.database_semaphore:
            res = data.database_data["clients"][client_id]

            client_info = {
                "client_id": client_id,
                "mac": deepcopy(res["mac"]),
                "ipv4": deepcopy(res["ipv4"]),
                "ipv6": deepcopy(res["ipv6"]),
                "datapath": res["datapath"],
                "port": res["port_id"],
                "registration_date": localtime(res["registration_date"]),
            }
            _log.debug("Querying Client {:d} info: {:s}".format(client_id, str(client_info)))
            return client_info

    except KeyError:
        _log.debug("Client {:d} not registered".format(client_id))
        raise ClientNotRegistered()

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def query_client_id(datapath_id, port_id, mac):
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    assert isinstance(port_id, int), "port_id is not int"
    assert isinstance(mac, EUI), "mac is not EUI"

    try:
        with data.database_semaphore:
            for client_id in data.database_data["clients"]:
                c_data = data.database_data["clients"][client_id]
                if c_data["datapath"] == datapath_id and c_data["port_id"] == port_id and c_data["mac"] == mac:
                    return client_id

            _log.debug(
                "Client not registered at datapath 0x{:016X}, connected to port id {:d} with MAC {:s}".format(
                    datapath_id,
                    port_id,
                    str(mac)
                )
            )
            raise ClientNotRegistered()

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def query_address_info(ipv4=None, ipv6=None):
    assert isinstance(ipv4, (IPv4Address, type(None))), "ipv4 is not IPv4Address or None"
    assert isinstance(ipv6, (IPv6Address, type(None))), "ipv6 is not IPv6Address or None"
    assert sum(tuple((i is not None for i in (ipv4, ipv6)))) == 1, \
        "can only use one argument (ipv4 or ipv6) at a time"

    try:
        with data.database_semaphore:
            if ipv4:
                for client_id in data.database_data["clients"]:
                    c_data = data.database_data["clients"][client_id]
                    if c_data["ipv4"] == ipv4:
                        return {
                            "client_id": client_id,
                            "mac": deepcopy(c_data["mac"]),
                            "ipv6": deepcopy(c_data["ipv6"]),
                            "datapath": deepcopy(c_data["datapath"]),
                            "port": c_data["port_id"],
                            "registration_date": localtime(c_data["registration_date"]),
                        }
                raise AddressNotRegistered()
            if ipv6:
                for client_id in data.database_data["clients"]:
                    c_data = data.database_data["clients"][client_id]
                    if c_data["ipv6"] == ipv6:
                        return {
                            "client_id": client_id,
                            "mac": deepcopy(c_data["mac"]),
                            "ipv4": deepcopy(c_data["ipv4"]),
                            "datapath": deepcopy(c_data["datapath"]),
                            "port": c_data["port_id"],
                            "registration_date": localtime(c_data["registration_date"]),
                        }
                raise AddressNotRegistered()

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def register(datapath_id, port_id, mac):
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    assert isinstance(port_id, int), "port_id is not int"
    assert isinstance(mac, EUI), "mac is not EUI"

    try:
        with data.database_semaphore:
            for client_id in data.database_data["clients"]:
                c_data = data.database_data["clients"][client_id]
                if c_data["datapath"] == datapath_id and c_data["port_id"] == port_id and c_data["mac"] == mac:
                    raise ClientAlreadyRegistered()

            if len(data.database_data["clients"]):
                client_id = max(data.database_data["clients"].keys()) + 1
            else:
                client_id = 1

            data.database_data["clients"][client_id] = {
                "mac": deepcopy(mac),
                "ipv4": None,
                "ipv6": None,
                "datapath": deepcopy(datapath_id),
                "port_id": port_id,
                "registration_date": time(),
            }

            _log.debug("Client Registered with ID {:d} at Datapath {:d}, Port {:d} with MAC {:s}".format(
                client_id, datapath_id, port_id, str(mac)
            ))
            return client_id

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def remove(client_id):
    assert isinstance(client_id, int), "client_id is not int"
    assert client_id >= 0,  "client_id cannot be negative"
    try:
        with data.database_semaphore:
            del data.database_data["clients"][client_id]
            _log.debug("Client with ID {:d} was removed.".format(client_id))

    except KeyError:
        _log.error("Client with ID {:d} is not registered.".format(client_id))
        raise ClientNotRegistered()

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def update_addresses(client_id, ipv4=None, ipv6=None):
    assert isinstance(client_id, int), "client_id is not int"
    assert client_id >= 0,  "client_id cannot be negative"
    assert not ((ipv4 is None) and (ipv6 is None)), "ipv4 and ipv6 cannot be None at the same time"
    assert isinstance(ipv4, IPv4Address) or ipv4 is None, "ipv4 expected to be IPv4Address or None"
    assert isinstance(ipv6, IPv6Address) or ipv6 is None, "ipv6 expected to be IPv6Address or None"

    try:
        with data.database_semaphore:

            if client_id not in data.database_data["clients"]:
                _log.error("Client with ID {:d} is not registered.".format(client_id))
                raise ClientNotRegistered()

            c_data = data.database_data["clients"][client_id]
            if ipv4:
                c_data["ipv4"] = deepcopy(ipv4)
                _log.debug("Updated Client {:d} IPv4 with address {:s}".format(client_id, str(ipv4)))

            if ipv6:
                c_data["ipv6"] = deepcopy(ipv6)
                _log.debug("Updated Client {:d} IPv6 with address {:s}".format(client_id, str(ipv6)))

            return client_id

    except Exception as ex:
        _log.error(str(ex))
        raise ex