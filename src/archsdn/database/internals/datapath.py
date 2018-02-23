import time
import logging
from contextlib import closing
from ipaddress import IPv4Address, IPv6Address
from sqlite3 import IntegrityError
from .shared_data import GetConnector
from .exceptions import Datapath_Not_Registered, Datapath_Already_Registered
from .data_validation import is_ipv4_port_tuple, is_ipv6_port_tuple

_log = logging.getLogger(__name__)

def query_info(datapath_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"

    try:
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT ipv4, ipv4_port, ipv6, ipv6_port, registration_date FROM "
                                    "datapaths_view WHERE datapaths_view.datapath_id == ?", (datapath_id,))
            res = db_cursor.fetchone()
            if res is None:
                raise Datapath_Not_Registered()

            datapath_info = {"ipv4": IPv4Address(res[0]) if res[0] else None,
                    "ipv4_port": res[1],
                    "ipv6": IPv6Address(res[2]) if res[2] else None,
                    "ipv6_port": res[3],
                    "registration_date": time.localtime(res[4])
                    }
            _log.debug("Querying Datapath {:d} Info: {:s}".format(datapath_id, str(datapath_info)))
            return datapath_info

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def register(datapath_id, ipv4_info=None, ipv6_info=None):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    assert not ((ipv4_info is None) and (ipv6_info is None)), "ipv4_info and ipv6_info cannot be None at the same time"
    assert is_ipv4_port_tuple(ipv4_info) or ipv4_info is None, "ipv4_info is invalid"
    assert is_ipv6_port_tuple(ipv6_info) or ipv6_info is None, "ipv6_info is invalid"

    try:
        database_connector = GetConnector()
        with closing(GetConnector().cursor()) as db_cursor:
            ipv4_id = None
            if ipv4_info:
                db_cursor.execute("INSERT INTO datapath_ipv4s(ipv4, port) VALUES(?, ?)", (int(ipv4_info[0]), ipv4_info[1]))
                ipv4_id = db_cursor.lastrowid

            ipv6_id = None
            if ipv6_info:
                db_cursor.execute("INSERT INTO datapath_ipv6s(ipv6, port) VALUES(?, ?)",
                                  (ipv6_info[0].packed, ipv6_info[1]))

                ipv6_id = db_cursor.lastrowid

            database_connector.execute("INSERT INTO datapaths(id, ipv4, ipv6) VALUES (?,?,?);",
                                       (datapath_id, ipv4_id, ipv6_id))

            database_connector.commit()
            _log.debug("Datapath {:d}: Registered".format(datapath_id))
            assert not GetConnector().in_transaction, "database with active transaction"

    except IntegrityError as ex:
        _log.error(str(ex))
        assert not GetConnector().in_transaction, "database with active transaction"
        if "UNIQUE constraint failed" in str(ex):
            raise Datapath_Already_Registered()
        raise ex


def remove(datapath_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"
    try:
        database_connector = GetConnector()
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("DELETE FROM datapaths WHERE datapaths.id == ?", (datapath_id,))
            if db_cursor.rowcount == 0:
                _log.debug("Cannot remove Datapath {:d}: Not Registered".format(datapath_id))
                raise Datapath_Not_Registered()

            database_connector.commit()
            assert not GetConnector().in_transaction, "database with active transaction"

    except Exception as ex:
        _log.error(str(ex))
        assert not GetConnector().in_transaction, "database with active transaction"
        raise ex


def is_registered(datapath_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"

    try:
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT count(id) FROM datapaths WHERE datapaths.id == ?", (datapath_id,))

            if db_cursor.fetchone()[0]:
                _log.debug("Checking if datapath {:d} is registered: True".format(datapath_id))
                return True
            _log.debug("Checking if datapath {:d} is registered: False".format(datapath_id))
            return False
    except Exception as ex:
        _log.error(str(ex))
        raise ex


def dump_ids():
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"

    try:
        _log.debug("Dumping all Datapaths IDs")
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT id FROM datapaths")
            return tuple(res[0] for res in db_cursor.fetchall())

    except Exception as ex:
        _log.error(str(ex))
        raise ex


def dump_datapath_clients_ids(datapath_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert datapath_id >= 0, "datapath_id should be >= 0"

    try:
        _log.debug("Dumping all registered hosts for datapath {:d}".format(datapath_id))
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT id FROM clients WHERE clients.datapath == ?", (datapath_id,))
            return tuple(res[0] for res in db_cursor.fetchall())

    except Exception as ex:
        _log.error(str(ex))
        raise ex
