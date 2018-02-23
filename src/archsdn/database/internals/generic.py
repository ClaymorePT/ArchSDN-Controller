import logging
import time
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import UUID, uuid4

from .shared_data import GetConnector, SetConnector

_log = logging.getLogger(__name__)


def initialise(location=":memory:", controller_id=None):
    assert GetConnector() is None, "database already initialized"
    assert (isinstance(location, Path) and location.cwd().exists()) or\
           (isinstance(location, str) and location == ":memory:"), \
        "location is not a valid instance of Path nor str equal to ':memory:' -> {:s}".format(repr(location))
    assert isinstance(controller_id, (UUID, type(None))), "controller_id not UUID nor None"

    if controller_id is None:
        controller_id = uuid4()

    if location == ":memory:":
        _log.info("Initializing Database in Memory")
    else:
        location = str(location.absolute())
        _log.info("Initializing Database in File at {:s}".format(location))

    database_connector = sqlite3.connect(
        location,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        isolation_level='DEFERRED'
    )
    SetConnector(database_connector)
    database_connector.enable_load_extension(True)

    with closing(GetConnector().cursor()) as db_cursor:
        db_cursor.execute("SELECT count(*) FROM sqlite_master "
                          "WHERE type == 'table' AND name == 'configurations'")
        res = db_cursor.fetchone()[0]
        if res == 0:
            if location == ":memory:":
                _log.info("database does not exist in memory... creating!")
            else:
                _log.info("database does not exist... creating!")
            with open(Path(str(Path(__file__).parents[1])+"/database.sql"), "r") as database_sql_fp:
                sql_str = "".join(database_sql_fp.readlines())
                database_connector.executescript(sql_str)
                database_connector.execute("INSERT INTO configurations(uuid) VALUES (?);", (controller_id.bytes,))
                database_connector.commit()
        else:
            _log.info("Database exists! Using it and ignoring id present in config file")
            db_cursor.execute("SELECT uuid, creation_date FROM configurations")
            (controller_uuid, creation_date) = db_cursor.fetchone()
            _log.info("database with UUID {:s} created in {:s}".format(str(UUID(bytes=controller_uuid)), str(time.ctime(creation_date))))


def infos():
    assert GetConnector() is not None, "database not initialized"
    assert not GetConnector().in_transaction, "database with active transaction"

    with closing(GetConnector().cursor()) as db_cursor:
        res = db_cursor.execute("SELECT uuid, creation_date FROM configurations").fetchone()
        return {
            "uuid": UUID(bytes=res[0]),
            "creation_date": time.localtime(res[1])
        }


def close():
    assert GetConnector(), "database not initialized"

    database_connector = GetConnector()
    database_connector.commit()
    database_connector.close()
    SetConnector(None)
