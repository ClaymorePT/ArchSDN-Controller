__all__ = ['start_controller']

import subprocess
import sys
import signal
import logging
import pathlib
from archsdn.arg_parsing import parse_arguments
from archsdn.helpers import custom_logging_callback, logger_module_name

__process = None
__log_format = '[{asctime:^s}][{levelname:^8s}][{name:s}|{funcName:s}|{lineno:d}]: {message:s}'
__log_datefmt = '%Y/%m/%d|%H:%M:%S.%f (%Z)'
__log = None


def quit_callback(signum, frame):
    if __log:
        __log.warning("Shutting down controller...")
    if __process:
        __process.terminate()


def start_controller():
    global __process, __log
    try:
        signal.signal(signal.SIGINT, quit_callback)
        signal.signal(signal.SIGTERM, quit_callback)

        parsed_args = parse_arguments()

        if sys.flags.debug:
            logging.basicConfig(format=__log_format, datefmt=__log_datefmt, style='{', level=logging.DEBUG)
        else:
            logging.basicConfig(format=__log_format, datefmt=__log_datefmt, style='{', level=parsed_args.logLevel)
        __log = logging.getLogger(logger_module_name(__file__))

        __log.info('{:s}'.format(str(parsed_args)))
        ofp_port_default = 6631

        if parsed_args.cip is None:
            raise Exception("Central Manager IP was not provided.")

        args = [
            'ryu-manager',
            '--config-file',
            '/'.join((str(pathlib.Path(__file__).parent), "ryu.conf")),
            '--verbose',
            '--default-log-level'
        ]
        if parsed_args.logLevel == 'DEBUG':
            args.append(str(logging._nameToLevel['DEBUG']))
            args.append('--enable-debugger')
        else:
            args.append(str(logging._nameToLevel[parsed_args.logLevel]))

        args = args + [
            '--ofp-tcp-listen-port', '{:d}'.format(ofp_port_default),
            '--user-flags', '/'.join((str(pathlib.Path(__file__).parent), "ArchSDN_opts.py")),
        ]

        if parsed_args.uuid and parsed_args.uuid != 'random':
            args.append('--archSDN_id')
            args.append(str(parsed_args.uuid))

        args.append('--archSDN_controllerIP')
        args.append(str(parsed_args.ip))
        args.append('--archSDN_controllerPort')
        args.append(str(parsed_args.port))
        args.append('--archSDN_centralIP')
        args.append(str(parsed_args.cip))
        args.append('--archSDN_centralPort')
        args.append(str(parsed_args.cport))

        if parsed_args.storage and parsed_args.storage != ':memory:':
            args.append('--archSDN_dbLocation')
            args.append(str(parsed_args.storage))

        args.append('--archSDN_logLevel')
        args.append(str(parsed_args.logLevel))

        args.append('/'.join((str(pathlib.Path(__file__).parent), "ArchSDN.py")))

        __process = subprocess.Popen(
            args,
            stdout=sys.stdout,
            stderr=sys.stderr
        )

        __process.wait()
    except Exception as ex:
        custom_logging_callback(__log, logging.ERROR, *sys.exc_info())
        sys.exit(str(ex))




