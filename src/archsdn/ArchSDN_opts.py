from ryu import cfg
from uuid import uuid4

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt('archSDN_id', default=str(uuid4()), help='ArchSDN controller id'),  # Controller UUID
    cfg.StrOpt('archSDN_controllerIP', default="0.0.0.0", help='ArchSDN controller IP'), #
    cfg.StrOpt('archSDN_controllerPort', default=12345, help='ArchSDN controller port'),
    cfg.StrOpt('archSDN_centralIP', default="0.0.0.0", help='ArchSDN central manager IP'),  #
    cfg.StrOpt('archSDN_centralPort', default=12345, help='ArchSDN central manager port'),
    cfg.StrOpt('archSDN_dbLocation', default=":memory:", help='ArchSDN database location'),
    cfg.StrOpt('archSDN_logLevel', default="INFO", help='ArchSDN logger level'),
])
