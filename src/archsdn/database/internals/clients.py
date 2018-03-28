import time
import logging
from contextlib import closing
from netaddr import EUI
from ipaddress import IPv4Address, IPv6Address
from sqlite3 import IntegrityError
from .shared_data import GetConnector
from .exceptions import ClientNotRegistered, ClientAlreadyRegistered,AddressNotRegistered

_log = logging.getLogger(__name__)

def query_info(client_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(client_id, int), "client_id is not int"
    assert client_id >= 0,  "client_id cannot be negative"

    try:
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT client_id, mac, ipv4, ipv6, datapath, port_id, registration_date "
                                    "FROM clients_view WHERE clients_view.client_id == ?", (client_id,))

            res = db_cursor.fetchone()
            if res is None:
                assert not GetConnector().in_transaction, "database with active transaction"
                raise ClientNotRegistered()

            client_info = {
                "client_id": res[0],
                "mac": EUI(int.from_bytes(res[1], "big")),
                "ipv4": IPv4Address(res[2]),
                "ipv6": IPv6Address(res[3]),
                "datapath": res[4],
                "port": res[5],
                "registration_date": time.localtime(res[6]),
            }
            _log.debug("Querying Client {:d} info: {:s}".format(client_id, str(client_info)))
            assert not GetConnector().in_transaction, "database with active transaction"
            return client_info
    except Exception as ex:
        assert not GetConnector().in_transaction, "database with active transaction"
        raise ex


def query_client_id(datapath_id, port_id, mac):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    assert isinstance(port_id, int), "port_id is not int"
    assert isinstance(mac, EUI), "mac is not EUI"

    try:
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT client_id FROM clients_view "
                                "WHERE (clients_view.datapath == ?) AND "
                                "(clients_view.port_id == ?) AND "
                                "(clients_view.mac == ?)", (datapath_id, port_id, mac.packed))

            res = db_cursor.fetchone()
            if res is None:
                assert not GetConnector().in_transaction, "database with active transaction"
                raise ClientNotRegistered()
            return res[0]
    except Exception as ex:
        assert not GetConnector().in_transaction, "database with active transaction"
        raise ex


def query_address_info(ipv4=None, ipv6=None):
    assert isinstance(ipv4, (IPv4Address, type(None))), "ipv4 is not IPv4Address or None"
    assert isinstance(ipv6, (IPv6Address, type(None))), "ipv6 is not IPv6Address or None"
    assert sum(tuple((i is not None for i in (ipv4, ipv6)))) == 1, \
        "can only use one argument (ipv4 or ipv6) at a time"


    try:
        with closing(GetConnector().cursor()) as db_cursor:
            if ipv4:
                db_cursor.execute("SELECT client_id, mac, ipv6, datapath, port_id, registration_date "
                                    "FROM clients_view WHERE clients_view.ipv4 == ?", (int(ipv4),))

                res = db_cursor.fetchone()
                if res is None:
                    assert not GetConnector().in_transaction, "database with active transaction"
                    raise AddressNotRegistered()

                return {
                    "client_id": res[0],
                    "mac": EUI(int.from_bytes(res[1], "big")),
                    "ipv6": IPv6Address(res[2]),
                    "datapath": res[3],
                    "port": res[4],
                    "registration_date": time.localtime(res[5]),
                }
            if ipv6:
                db_cursor.execute("SELECT client_id, mac, ipv4, datapath, port_id, registration_date "
                                  "FROM clients_view WHERE clients_view.ipv6 == ?", (ipv6.packed,))

                res = db_cursor.fetchone()
                if res is None:
                    assert not GetConnector().in_transaction, "database with active transaction"
                    raise AddressNotRegistered()

                return {
                    "client_id": res[0],
                    "mac": EUI(int.from_bytes(res[1], "big")),
                    "ipv4": IPv4Address(res[2]),
                    "datapath": res[3],
                    "port": res[4],
                    "registration_date": time.localtime(res[5]),
                }

    except Exception as ex:
        assert not GetConnector().in_transaction, "database with active transaction"
        raise ex



def register(datapath_id, port_id, mac):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    assert isinstance(port_id, int), "port_id is not int"
    assert isinstance(mac, EUI), "mac is not EUI"

    try:
        database_connector = GetConnector()
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("INSERT INTO clients(datapath, datapath_port, mac) "
                              "VALUES (?,?,?)", (datapath_id, port_id, mac.packed))
            client_id = db_cursor.lastrowid

            _log.debug("Client Registered with ID {:d} at Datapath {:d}, Port {:d} with MAC {:s}".format(
                client_id, datapath_id, port_id, str(mac)
            ))
            database_connector.commit()
            assert not GetConnector().in_transaction, "database with active transaction"
            return client_id

    except IntegrityError as ex:
        assert not GetConnector().in_transaction, "database with active transaction"
        if "UNIQUE constraint failed" in str(ex):
            raise ClientAlreadyRegistered()
        raise ex


def remove(client_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(client_id, int), "client_id is not int"
    assert client_id >= 0,  "client_id cannot be negative"
    try:
        database_connector = GetConnector()
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("DELETE FROM clients WHERE clients.id == ?", (client_id,))

            if db_cursor.rowcount == 0:
                database_connector.rollback()
                assert not GetConnector().in_transaction, "database with active transaction"
                raise ClientNotRegistered()

            assert db_cursor.rowcount == 1, "More than one client registry was removed. This should not happen."
            database_connector.commit()
            _log.debug("Client with ID {:d} was removed.".format(client_id))
            assert not GetConnector().in_transaction, "database with active transaction"
    except Exception as ex:
        assert not GetConnector().in_transaction, "database with active transaction"
        raise ex


def update_addresses(client_id, ipv4=None, ipv6=None):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(client_id, int), "client_id is not int"
    assert client_id >= 0,  "client_id cannot be negative"
    assert not ((ipv4 is None) and (ipv6 is None)), "ipv4 and ipv6 cannot be None at the same time"
    assert isinstance(ipv4, IPv4Address) or ipv4 is None, "ipv4 expected to be IPv4Address or None"
    assert isinstance(ipv6, IPv6Address) or ipv6 is None, "ipv6 expected to be IPv6Address or None"

    try:
        database_connector = GetConnector()
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT count(id) FROM clients WHERE clients.id == ?", (client_id,))
            res = db_cursor.fetchone()
            if res[0] == 0:
                assert not GetConnector().in_transaction, "database with active transaction"
                raise ClientNotRegistered()

            if ipv4:
                db_cursor.execute("INSERT INTO clients_ipv4s(ipv4)  VALUES (?) ", (int(ipv4), ))
                ipv4_id = db_cursor.lastrowid
                db_cursor.execute("UPDATE clients SET ipv4 = ? WHERE clients.id == ?", (ipv4_id, client_id))
                _log.debug("Updated Client {:d} IPv4 with address {:s}".format(client_id, str(ipv4)))

            if ipv6:
                db_cursor.execute("INSERT INTO clients_ipv6s(ipv6)  VALUES (?) ", (ipv6.packed, ))
                ipv6_id = db_cursor.lastrowid
                db_cursor.execute("UPDATE clients SET ipv6 = ? WHERE clients.id == ?", (ipv6_id, client_id))
                _log.debug("Updated Client {:d} IPv6 with address {:s}".format(client_id, str(ipv6)))

            client_id = db_cursor.lastrowid
            database_connector.commit()
            assert not GetConnector().in_transaction, "database with active transaction"
            return client_id

    except IntegrityError as ex:
        assert not GetConnector().in_transaction, "database with active transaction"
        if "UNIQUE constraint failed" in str(ex):
            raise ClientAlreadyRegistered()
        raise ex