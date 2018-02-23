--
-- File generated with SQLiteStudio v3.1.1 on Wed Mar 22 01:45:04 2017
--
-- Text encoding used: UTF-8
--
PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Table: clients
DROP TABLE IF EXISTS clients;

CREATE TABLE clients (
  id            INTEGER  PRIMARY KEY ASC ON CONFLICT ROLLBACK AUTOINCREMENT,
  datapath      INTEGER  NOT NULL,
  datapath_port INTEGER  NOT NULL,
  mac           BLOB     NOT NULL,
  ipv4                   REFERENCES clients_ipv4s (id),
  ipv6                   REFERENCES clients_ipv6s (id),
  register_date DATETIME DEFAULT (CAST (strftime('%s', 'now') AS INTEGER) ),
  CONSTRAINT unique_client_registration UNIQUE (
    datapath ASC,
    mac ASC,
    datapath_port ASC
  )
  ON CONFLICT ROLLBACK
);


-- Table: clients_ipv4s
DROP TABLE IF EXISTS clients_ipv4s;

CREATE TABLE clients_ipv4s (
  id   INTEGER PRIMARY KEY ASC ON CONFLICT ROLLBACK AUTOINCREMENT,
  ipv4 INTEGER CONSTRAINT ipv4_unique UNIQUE
               NOT NULL
);


-- Table: clients_ipv6s
DROP TABLE IF EXISTS clients_ipv6s;

CREATE TABLE clients_ipv6s (
  id   INTEGER PRIMARY KEY ASC ON CONFLICT ROLLBACK AUTOINCREMENT,
  ipv6 BLOB    CONSTRAINT ipv6_unique UNIQUE ON CONFLICT ROLLBACK
);


-- Table: configurations
DROP TABLE IF EXISTS configurations;

CREATE TABLE configurations (
  uuid          BLOB     NOT NULL,
  creation_date DATETIME NOT NULL
                         DEFAULT (CAST (strftime('%s', 'now') AS INTEGER) )
);


-- Table: datapath_ipv4s
DROP TABLE IF EXISTS datapath_ipv4s;

CREATE TABLE datapath_ipv4s (
  id   INTEGER PRIMARY KEY ASC ON CONFLICT ROLLBACK AUTOINCREMENT,
  ipv4 INTEGER NOT NULL,
  port INTEGER NOT NULL,
  CONSTRAINT unique_ipv4_port UNIQUE (
    ipv4 ASC,
    port ASC
  )
  ON CONFLICT ROLLBACK
);


-- Table: datapath_ipv6s
DROP TABLE IF EXISTS datapath_ipv6s;

CREATE TABLE datapath_ipv6s (
  id   INTEGER PRIMARY KEY ASC ON CONFLICT ROLLBACK AUTOINCREMENT,
  ipv6 BLOB    NOT NULL,
  port INTEGER NOT NULL,
  CONSTRAINT unique_ipv6_port UNIQUE (
    ipv6 ASC,
    port ASC
  )
  ON CONFLICT ROLLBACK
);



-- Table: datapaths
DROP TABLE IF EXISTS datapaths;

CREATE TABLE datapaths (
  id                INTEGER  PRIMARY KEY ASC ON CONFLICT ROLLBACK,
  ipv4                       REFERENCES datapath_ipv4s (id),
  ipv6                       REFERENCES datapath_ipv6s (id),
  registration_date DATETIME DEFAULT (CAST (strftime('%s', 'now') AS INTEGER) ),
  CONSTRAINT unique_registration UNIQUE (
    id
  )
  ON CONFLICT ROLLBACK,
  CONSTRAINT unique_address_port UNIQUE (
    ipv4
  )
  ON CONFLICT ROLLBACK
)
WITHOUT ROWID;


-- Table: flow_mods
DROP TABLE IF EXISTS flow_mods;

CREATE TABLE flow_mods (
  cookie_id         INTEGER  CONSTRAINT cookie_id_unique PRIMARY KEY ASC ON CONFLICT ROLLBACK
                             CONSTRAINT cookie_id_not_negative CHECK (cookie_id >= 0),
  datapath                   REFERENCES datapaths (id)
                             NOT NULL ON CONFLICT ROLLBACK,
  compressed_json   TEXT     NOT NULL,
  registration_date DATETIME DEFAULT (CAST (strftime('%s', 'now') AS INTEGER) )
)
WITHOUT ROWID;


-- Trigger: delete_client
DROP TRIGGER IF EXISTS delete_client;
CREATE TRIGGER delete_client
        BEFORE DELETE
            ON clients
      FOR EACH ROW
BEGIN
  DELETE FROM clients_ipv4s
        WHERE clients_ipv4s.id == old.ipv4;
  DELETE FROM clients_ipv6s
        WHERE clients_ipv6s.id == old.ipv6;
END;


-- Trigger: delete_datapath
DROP TRIGGER IF EXISTS delete_datapath;
CREATE TRIGGER delete_datapath
        BEFORE DELETE
            ON datapaths
      FOR EACH ROW
BEGIN
  DELETE FROM clients
        WHERE clients.datapath == old.id;
  DELETE FROM flow_mods
        WHERE flow_mods.datapath == old.id;
  DELETE FROM datapath_ipv4s
        WHERE datapath_ipv4s.id == old.ipv4;
  DELETE FROM datapath_ipv6s
        WHERE datapath_ipv6s.id == old.ipv6;
END;


-- View: clients_view
DROP VIEW IF EXISTS clients_view;
CREATE VIEW clients_view AS
  SELECT clients.id AS client_id,
         clients.mac AS mac,
         clients_ipv4s.ipv4 AS ipv4,
         clients_ipv6s.ipv6 AS ipv6,
         datapaths.id AS datapath,
         clients.datapath_port AS port_id,
         clients.register_date AS registration_date
    FROM clients
         LEFT JOIN
         datapaths ON datapaths.id == clients.datapath
         LEFT JOIN
         clients_ipv4s ON clients_ipv4s.id == clients.ipv4
         LEFT JOIN
         clients_ipv6s ON clients_ipv6s.id == clients.ipv6
   ORDER BY client_id ASC;


-- View: datapath_flows
DROP VIEW IF EXISTS datapath_flows;
CREATE VIEW datapath_flows AS
  SELECT datapaths.id AS datapath,
         flow_mods.cookie_id AS cookie_id,
         flow_mods.compressed_json AS compressed_flow,
         flow_mods.registration_date AS registration_date
    FROM datapaths
         LEFT JOIN
         flow_mods ON flow_mods.datapath == datapaths.id
   ORDER BY datapath,
            cookie_id ASC;


-- View: datapaths_view
DROP VIEW IF EXISTS datapaths_view;
CREATE VIEW datapaths_view AS
  SELECT datapaths.id AS datapath_id,
         datapath_ipv4s.ipv4 AS ipv4,
         datapath_ipv4s.port AS ipv4_port,
         datapath_ipv6s.ipv6 AS ipv6,
         datapath_ipv6s.port AS ipv6_port,
         datapaths.registration_date AS registration_date
    FROM datapaths
         LEFT JOIN
         datapath_ipv4s ON datapath_ipv4s.id == datapaths.ipv4
         LEFT JOIN
         datapath_ipv6s ON datapath_ipv6s.id == datapaths.ipv6
   ORDER BY datapath_id ASC;


COMMIT TRANSACTION;
PRAGMA foreign_keys = on;
