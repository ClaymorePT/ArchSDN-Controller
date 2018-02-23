# This is just a module to keep a reference to the database connector.
# This is necessary because the Python multiprocessing module is not capable of serializing sqlite3 database connectors.
#
database_connector = None

def GetConnector():
    return database_connector

def SetConnector(conn):
    global database_connector
    database_connector = conn