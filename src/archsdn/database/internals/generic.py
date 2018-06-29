import logging
from time import time, ctime, localtime

from pathlib import Path
from uuid import UUID, uuid4
from copy import deepcopy

from eventlet.semaphore import BoundedSemaphore

from ...database import data

_log = logging.getLogger(__name__)


class FakeSemaphore():
    def __init__(self):
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def initialise(location=":memory:", controller_id=None):
    assert (isinstance(location, Path) and location.cwd().exists()) or\
           (isinstance(location, str) and location == ":memory:"), \
        "location is not a valid instance of Path nor str equal to ':memory:' -> {:s}".format(repr(location))
    assert isinstance(controller_id, (UUID, type(None))), "controller_id not UUID nor None"

    if controller_id is None:
        controller_id = uuid4()

    if isinstance(location, str) and location == ":memory:":
        _log.info("Initializing Database in Memory")

        data.database_data = {
            "configurations": {
                "uuid": deepcopy(controller_id),
                "creation_date": time()
            },
            "clients": {},
            "datapaths": {},
        }
        data.database_semaphore = FakeSemaphore()

    elif isinstance(location, Path):
        raise Exception("Only nemory database is supported.")
        # if location.exists():
        #     _log.info("Database exists! Using it and ignoring id present in config file")
        #
        # else:
        #     _log.info("Initializing Database in File at {:s}".format(str(location)))

    _log.info(
        "database with UUID {:s} created in {:s}".format(
            str(data.database_data["configurations"]["uuid"]),
            str(ctime(data.database_data["configurations"]["creation_date"]))
        )
    )


def infos():
    with data.database_semaphore:

        return {
            "uuid": deepcopy(data.database_data["configurations"]["uuid"]),
            "creation_date": localtime(data.database_data["configurations"]["creation_date"])
        }


def close():
    _log.warning("Database is being closed...")

