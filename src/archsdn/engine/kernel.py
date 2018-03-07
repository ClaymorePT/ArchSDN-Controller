import logging

from archsdn.helpers import logger_module_name


_log = logging.getLogger(logger_module_name(__file__))
__default_configs = None


def initialise(default_configs):
    global __default_configs

    __default_configs = default_configs


def process_datapath_event(dp_event):
    assert __default_configs, "engine not initialised"

    if dp_event.enter:
        _log.info("Switch Connect Event: {}".format(str(dp_event.dp.__dict__)))
    else:
        _log.info("Switch Disconnect Event: {}".format(str(dp_event.dp.__dict__)))


def process_packet_in_event(packet_in_event):
    assert __default_configs, "engine not initialised"

    _log.info("Packet In Event: {}".format(str(packet_in_event.__dict__)))


def process_port_change_event(port_change_event):
    assert __default_configs, "engine not initialised"


    ofp_port_reason = {
        0: "The port was added",
        1: "The port was removed",
        2: "Some attribute of the port has changed"
    }

    if port_change_event.reason in ofp_port_reason:
        _log.info(
            "Port Status Event at Switch {:d} Port {:d} Reason: {:s}".format(
                port_change_event.datapath.id,
                port_change_event.port_no,
                ofp_port_reason[port_change_event.reason]
            )
        )
    else:
        raise Exception("Reason with value {:d} is unknown to specification.".format(port_change_event.reason))




