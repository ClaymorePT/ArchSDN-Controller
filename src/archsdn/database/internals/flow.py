import logging
from contextlib import closing
import time
import pickle
from zlib import compress, decompress
from sqlite3 import IntegrityError

from .shared_data import GetConnector
from .exceptions import Flow_Already_Registered, Flow_Not_Registered, Datapath_Not_Registered

_log = logging.getLogger(__name__)


def save(datapath_id, flow_description):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id not int"
    assert datapath_id >= 0, "datapath_id cannot be negative"
    assert isinstance(flow_description, dict), "flow_mod is not a dict"
    assert len(flow_description) == 1, "flow_mod dict has more than one key"
    assert "OFPFlowMod" in flow_description, "OFPFlowMod not present in dict"

    try:
        database_connector = GetConnector()
        with closing(GetConnector().cursor()) as db_cursor:
            cookie_id = 0  # Lets find a cookie ID available value
            while True:
                db_cursor.execute("SELECT count(*) FROM flow_mods WHERE cookie_id==?", (cookie_id,))
                if db_cursor.fetchone()[0] == 0:
                    break
                cookie_id += 1

            flow_description["OFPFlowMod"]["cookie"] = cookie_id
            db_cursor.execute("INSERT INTO flow_mods(cookie_id, datapath, compressed_json) VALUES (?,?,?)",
                              (cookie_id, datapath_id, compress(pickle.dumps(flow_description))))
            database_connector.commit()
            _log.debug(
                "Registered Flow for Datapath {:d} with Cookie {:d}: {:s}".format(
                    datapath_id, cookie_id, str(flow_description)
                )
            )
            assert not GetConnector().in_transaction, "database with active transaction"
            return cookie_id  # Flow Cookie ID

    except IntegrityError as ex:
        _log.error(str(ex))
        assert not GetConnector().in_transaction, "database with active transaction"
        if "UNIQUE constraint failed" in str(ex):
            raise Flow_Already_Registered()
        raise ex
    except Exception as ex:
        _log.error(str(ex))
        assert not GetConnector().in_transaction, "database with active transaction"
        raise ex


def info(datapath_id, cookie_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert isinstance(cookie_id, int), "cookie_id is not int"

    try:
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT datapath, compressed_flow, registration_date FROM datapath_flows "
                              "WHERE (datapath_flows.cookie_id == ?)", (cookie_id,)
                              )
            res = db_cursor.fetchone()
            if res is None:
                db_cursor.execute("SELECT count(id) FROM datapaths WHERE datapaths.id == ? ", (datapath_id,))
                if db_cursor.fetchone()[0] == 0:
                    _log.debug(
                        "Getting Flow info for Cookie {:d} but does not exist.".format(cookie_id)
                    )
                    raise Datapath_Not_Registered()

                _log.debug("Getting Flow info for Cookie {:d} but flow does not exist.".format(cookie_id))
                raise Flow_Not_Registered()

            datapath_id = res[0]
            flow_description = pickle.loads(decompress(res[1]))
            flow_info = (flow_description, time.localtime(res[2]))
            assert isinstance(flow_description, dict), "flow_description is not dict: it's {:s}".format(repr(flow_description))
            _log.debug(
                "Getting Flow info for Datapath {:d}, Cookie {:d}: {:s}".format(datapath_id, cookie_id, str(flow_info))
            )
            return flow_info

    except IntegrityError as ex:
        _log.error(str(ex))
        if "UNIQUE constraint failed" in str(ex):
            raise Flow_Already_Registered()
        raise ex
    except Exception as ex:
        _log.error(str(ex))
        raise ex


def remove(datapath_id, cookie_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"
    assert isinstance(cookie_id, int), "cookie_id is not int"
    try:
        database_connector = GetConnector()
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("DELETE FROM flow_mods "
                              "WHERE (flow_mods.datapath == ?) AND "
                              "(flow_mods.cookie_id == ?)", (datapath_id, cookie_id))
            database_connector.commit()
            assert not GetConnector().in_transaction, "database with active transaction"

            if db_cursor.rowcount == 0:
                db_cursor.execute("SELECT count(id) FROM datapaths WHERE datapaths.id == ?", (datapath_id,))
                if db_cursor.fetchone()[0] == 0:
                    _log.debug(
                        "Getting Flow info for Datapath {:d}, Cookie {:d} but Datapath does not exist.".format(
                            datapath_id, cookie_id)
                    )
                    raise Datapath_Not_Registered()
                _log.debug(
                    "Removing Flow for Datapath {:d}, Cookie {:d} but flow does not exist.".format(
                        datapath_id, cookie_id)
                )
                raise Flow_Not_Registered()
            assert db_cursor.rowcount == 1, "More than one flow was deleted. This should not happen."
            _log.debug("Removed Flow for Datapath {:d} with Cookie {:d}.".format(datapath_id, cookie_id))
    except Exception as ex:
        assert not GetConnector().in_transaction, "database with active transaction"
        _log.error(str(ex))
        raise ex


def get_cookie_ids(datapath_id):
    assert GetConnector(), "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"
    assert isinstance(datapath_id, int), "datapath_id is not int"

    try:
        with closing(GetConnector().cursor()) as db_cursor:
            db_cursor.execute("SELECT cookie_id FROM flow_mods WHERE flow_mods.datapath == ?", (datapath_id, ))
            cookie_ids = tuple((x[0] for x in db_cursor.fetchall()))
            _log.debug("Getting Flows IDs for Datapath {:d}: {:s}".format(datapath_id, str(cookie_ids)))

            return cookie_ids
    except Exception as ex:
        _log.error(str(ex))
        raise ex
