import logging
from archsdn.helpers import logger_module_name
from threading import Lock
from eventlet.semaphore import Semaphore
from ipaddress import IPv4Address, IPv6Address
from random import uniform


_log = logging.getLogger(logger_module_name(__file__))

# Table Flows Types
PORT_SEGREGATION_TABLE = 0
HOST_FILTERING_TABLE = 1
SECTOR_FILTERING_TABLE = 2
MPLS_FILTERING_TABLE = 3
FOREIGN_HOST_FILTERING_TABLE = 4

ARCHSDN_TABLES = {
    PORT_SEGREGATION_TABLE,
    HOST_FILTERING_TABLE,
    SECTOR_FILTERING_TABLE,
    MPLS_FILTERING_TABLE,
    FOREIGN_HOST_FILTERING_TABLE
}

# Flows priority values
# TABLE 0 -> PORT_SEGREGATION_TABLE
PORT_TABLE_DISCOVERY_PRIORITY = 2000
PORT_TABLE_PORT_PRIORITY = 1000

# TABLE 1 -> HOST_FILTERING_TABLE
HOST_TABLE_LAYER_5_PRIORITY = 4000
HOST_TABLE_LAYER_4_SPECIFIC_PRIORITY = 3500
HOST_TABLE_LAYER_4_NETWORK_PRIORITY = 3250
HOST_TABLE_LAYER_4_DEFAULT_PRIORITY = 3000
HOST_TABLE_LAYER_3_SPECIFIC_PRIORITY = 2500
HOST_TABLE_LAYER_3_GENERIC_PRIORITY = 2250
HOST_TABLE_LAYER_3_DEFAULT_PRIORITY = 2000
HOST_TABLE_VLAN_PRIORITY = 1000

# TABLE 2 -> SECTOR_FILTERING_TABLE
SECTOR_TABLE_MPLS_SWITCH_PRIORITY = 3000
SECTOR_TABLE_MPLS_POP_PRIORITY = 2000
SECTOR_TABLE_MPLS_CHANGE_PRIORITY = 1000

# TABLE 3 -> MPLS_FILTERING_TABLE
MPLS_TABLE_MPLS_SWITCH_PRIORITY = 3000
MPLS_TABLE_MPLS_POP_PRIORITY = 2000
MPLS_TABLE_MPLS_CHANGE_PRIORITY = 1000

# TABLE 4 -> FOREIGN_HOST_FILTERING_TABLE
FOREIGN_HOST_TABLE_LAYER_5_PRIORITY = 4000
FOREIGN_HOST_TABLE_LAYER_4_SPECIFIC_PRIORITY = 3500
FOREIGN_HOST_TABLE_LAYER_4_NETWORK_PRIORITY = 3250
FOREIGN_HOST_TABLE_LAYER_4_DEFAULT_PRIORITY = 3000
FOREIGN_HOST_TABLE_LAYER_3_SPECIFIC_PRIORITY = 2500
FOREIGN_HOST_TABLE_LAYER_3_GENERIC_PRIORITY = 2250
FOREIGN_HOST_TABLE_LAYER_3_DEFAULT_PRIORITY = 2000
FOREIGN_HOST_TABLE_VLAN_PRIORITY = 1000

TABLE_MISS_PRIORITY = 0

# Flows Timeout
ICMPV4_FLOW_TIMEOUT = 5

# Default kernel configuration
default_configs = None

# Sector QValues
QValues = {}  # QValues[chosen_link][IPv4/IPv6] = Q-Value
q_alpha = 0.9
q_beta = 0.1
EXPLORATION_PROBABILITY = 0.25  # Floating point value between 0 and 1


def should_explore():
    return uniform(0, 1) <= EXPLORATION_PROBABILITY


# Known Shortest Path Length to target
kspl = {}  # kspl[chosen_link][IPv4/IPv6] = minimum length


def get_known_shortest_path(choice, host_address):
    assert isinstance(choice, tuple), "sector_id expected to be (switch_id, port_id) tuple"
    assert isinstance(choice[0], int) and choice[0] > 0, "choice 0 tuple element must be a Switch ID"
    assert isinstance(choice[1], int) and choice[1] > 0, "choice 1 tuple element must be a Port ID"
    assert isinstance(host_address, IPv4Address) or isinstance(host_address, IPv6Address), \
        "host_address expected to be IPv4Address or IPv6Address"

    if choice not in kspl:
        kspl[choice] = {host_address: None}
    if host_address not in kspl[choice]:
        kspl[choice][host_address] = None
    return kspl[choice][host_address]


def set_known_shortest_path(choice, host_address, path_length):
    assert isinstance(choice, tuple), "sector_id expected to be (switch_id, port_id) tuple"
    assert isinstance(choice[0], int) and choice[0] > 0, "choice 0 tuple element must be a Switch ID"
    assert isinstance(choice[1], int) and choice[1] > 0, "choice 1 tuple element must be a Port ID"
    assert isinstance(host_address, IPv4Address) or isinstance(host_address, IPv6Address), \
        "host_address expected to be IPv4Address or IPv6Address"
    assert isinstance(path_length, int) and path_length > 0, "path_length expected to be int and > 0"

    if choice not in kspl:
        kspl[choice] = {host_address: path_length}
    else:
        kspl[choice][host_address] = path_length


def get_q_value(choice, host_address):
    assert isinstance(choice, tuple), "sector_id expected to be (switch_id, port_id) tuple"
    assert isinstance(choice[0], int) and choice[0] > 0, "choice 0 tuple element must be a Switch ID"
    assert isinstance(choice[1], int) and choice[1] > 0, "choice 1 tuple element must be a Port ID"
    assert isinstance(host_address, IPv4Address) or isinstance(host_address, IPv6Address), \
        "host_address expected to be IPv4Address or IPv6Address"

    if choice not in QValues:
        QValues[choice] = {host_address: 0}
    else:
        if host_address not in QValues[choice]:
            QValues[choice][host_address] = 0
    return QValues[choice][host_address]


def set_q_value(choice, host_address, q_value):
    assert isinstance(choice, tuple), "sector_id expected to be (switch_id, port_id) tuple"
    assert isinstance(choice[0], int) and choice[0] > 0, "choice 0 tuple element must be a Switch ID"
    assert isinstance(choice[1], int) and choice[1] > 0, "choice 1 tuple element must be a Port ID"
    assert isinstance(host_address, IPv4Address) or isinstance(host_address, IPv6Address), \
        "host_address expected to be IPv4Address or IPv6Address"
    assert isinstance(q_value, int) or isinstance(q_value, float), "q_value expected to be int or float"

    if choice not in QValues:
        QValues[choice] = {host_address: q_value}
    else:
        QValues[choice][host_address] = q_value


def calculate_new_qvalue(old_value, forward_value, reward):
    assert isinstance(old_value, int) or isinstance(old_value, float), "old_value expected to be int or float"
    assert isinstance(forward_value, int) or isinstance(forward_value, float), \
        "forward_value expected to be int or float"
    assert isinstance(reward, int) or isinstance(reward, float), "reward expected to be int or float"

    return old_value + q_alpha * (reward + q_beta*forward_value - old_value)


# Active implementation  scenario tasks
#  This dictionary keeps a record of the active tasks to implement scenarios which need multiple controllers
#   coordination

class ImplementationTaskExists(Exception):
    pass


class __ImplementationTask():
    __scenario_implementation_tasks = {
        "IPv4": {
            "ICMP": set(),
            # "UDP": set(), # TODO: Implement specific UDP scenario flows
            # "TCP": set(), # TODO: Implement specific TCP scenario flows
            "*": set(),
        },
        "MPLS": {
            "*": set()
        }
    }

    def __init__(self, task_id, first_layer, second_layer="*"):
        self.__first_layer = None
        self.__second_layer = None
        self.__taskID = None

        if first_layer not in __class__.__scenario_implementation_tasks:
            raise AttributeError("first_layer argument is invalid.")

        if second_layer not in __class__.__scenario_implementation_tasks[first_layer]:
            raise AttributeError("second_layer argument is invalid.")

        if task_id in __class__.__scenario_implementation_tasks[first_layer][second_layer]:
            raise ImplementationTaskExists()

        self.__first_layer = first_layer
        self.__second_layer = second_layer
        self.__taskID = task_id
        __class__.__scenario_implementation_tasks[first_layer][second_layer].add(task_id)

    def __del__(self):
        if self.__taskID:
            __class__.__scenario_implementation_tasks[self.__first_layer][self.__second_layer].remove(self.__taskID)


def register_implementation_task(*args, **kwargs):
    return __ImplementationTask(*args, **kwargs)


# Topology Discovery Beacons
#
# The following globals are used for the sector topology discovery
#  __topology_beacons -> Active topology beacons
#  __beacons_hash_table -> Encoded Hash table
#
topology_beacons = {}  # __topology_beacons[switch id] = Beacon_Task
beacons_hash_table = {}  # __beacons_hash_table[hash] = (switch id, port_out)


def get_hash_val(switch_id, port_id):
    res = tuple(filter((lambda item: item[1] == (switch_id, port_id)), beacons_hash_table.items()))
    if res:
        return res[0][0]
    raise KeyError("No hash available for specified key.")


#
# MPLS Tunnels Information
#
# The MPLS tunnels are activated in table 1.
# Table 1 will be responsible for matching labels and sending them through the proper network interface
# When a host packet is ingressed in a tunnel, table 0 matches the packet and adds the MPLS label. Then, the packet is
#  sent to table 1 to execute the MPLS switching.
# When a MPLS packet is received, table 1 will perform one of the following actions:
#  a) Removes the MPLS header and switches the packet into the interface where the destination host is.
#  b) Updates the MPLS label and switches the packet to another interface, accordingly.
#
# MPLS Tunnels - Different types
#  From Host to Host (Same-Sector, Ingress and Egress)
#  From Host to Sector (Cross-Sector, Ingress)
#  From Sector to Host (Cross-Sector, Egress)
#  From Sector to Sector (Cross-Sector, Intermediary)
#

__active_scenarios = {}
__active_scenarios_sem = Semaphore(value=1)
# active_scenarios[global scenario id] = ((local scenarios ids, ), (adjacent sectors_ids which use this scenario, ))
# global scenario id -> (origin_sector_id, source_ipv4_node, destination_ipv4_node, service_type)
#
# service_type -> ("ICMPv4", "MPLS")
#


def set_active_scenario(key, data):
    with __active_scenarios_sem:
        assert key not in __active_scenarios, "scenario already active"

        __active_scenarios[key] = data


def get_active_scenario(key, remove=False):
    with __active_scenarios_sem:
        assert key in __active_scenarios, "scenario not active"
        temp = __active_scenarios[key]
        if remove:
            del __active_scenarios[key]
        return temp


def is_scenario_active(key):
    with __active_scenarios_sem:
        return key in __active_scenarios


def delete_active_scenario(key):
    with __active_scenarios_sem:
        assert key in __active_scenarios, "scenario not active"

        del __active_scenarios[key]


def get_active_scenarios_keys():
    with __active_scenarios_sem:
        return tuple(__active_scenarios.keys())

#
# Differentiated Services Information
#
# Services are seen in a perspective of mapped entries to outputs at the boundaries
#  When a host or a sector sends a packet through a switch port, the switch decides what to do with the packet.
#  If the packet comes from a host and there's service activate to that type of packet, the packet is ingressed in an
#   activated MPLS tunnel.
#  If the packet comes from a sector, the switch will do one of the following actions:
#    a) The packet is egressed from the MPLS tunnel (header is removed and packet is delivered to the target host).
#    b) The packet MPLS label ID is updated and the packet is switches through another interface.
#
# There are cases where a MPLS tunnel is not required. These cases exist when two hosts trying to communicate with each
#   other, are connected directly to the same switch. In this case, the switch can simply switch the packets from on
#   interface to the other.
#
#
# For future development, services requiring multicast support, can be built over MPLS tunnels.

# Different scenarios usage for MPLS Tunnels
# - Packet host ingressing (Host -> Tunnel)
# - Packet host egressing (Tunnel -> Host)
# - Packet mpls label update (Tunnel -> Tunnel)


mapped_services = {
    "IPv4": {
        "ICMP": {},
        # "UDP": set(), # TODO: Implement specific UDP scenario flows
        # "TCP": set(), # TODO: Implement specific TCP scenario flows
        "*": {},
    },
    "MPLS": {
        "OneWay": {},
        "TwoWay": {},
    }
}

# __mapped_services[switch_id]["Service"]["service details"] = (tunnel_id or port_out)
# __mapped_services[switch_id] = {
#  "ICMP4" -> __mapped_services["ICMPv4"][(src_ip, dst_ip)] = (tunnel_id, port_out, cookies)
#  "IPv4" ->  __mapped_services["IPv4"][(src_ip, dst_ip)][(src_port, dst_port)] = (tunnel_id, port_out, cookies)
#  "MPLS" ->  __mapped_services["MPLS"][port][label_id] = (tunnel_id, port_out, cookies)
# }


#
# Cookie IDs generator
#
# The following globals are used to maintain unique and ready-to-use cookie ids.
#
# __recycled_cookie_ids -> A list of previously used cookie ids, which can be recycled
# __cookie_id_counter -> cookie ID counter
#
__recycled_cookie_ids = []
__cookie_id_counter = 0
__cookies_lock = Lock()


def alloc_cookie_id():
    global __cookie_id_counter

    with __cookies_lock:
        if __cookie_id_counter == 0xFFFFFFFFFFFFFFFF:
            raise ValueError("No more cookies left...")
        if len(__recycled_cookie_ids):
            cookie_id = __recycled_cookie_ids.pop()
            _log.debug("Cookie ID {:d} was acquired.".format(cookie_id))
            return cookie_id
        __cookie_id_counter = __cookie_id_counter + 1
        _log.debug("Cookie ID {:d} was acquired.".format(__cookie_id_counter))
        return __cookie_id_counter


def free_cookie_id(cookie_id):
    global __cookie_id_counter

    with __cookies_lock:
        if cookie_id <= 0:
            raise ValueError("Cookies cannot be zero or negative.")
        if cookie_id > __cookie_id_counter:
            raise ValueError("That cookie was not allocated.")
        if cookie_id in __recycled_cookie_ids:
            raise ValueError("Cookie already free.")
        __recycled_cookie_ids.append(cookie_id)

        while len(__recycled_cookie_ids) > 0:
            max_value = max(__recycled_cookie_ids)
            if __cookie_id_counter == max_value:
                __recycled_cookie_ids.remove(max_value)
                _log.debug("Cookie ID {:d} was recycled.".format(max_value))
                __cookie_id_counter = __cookie_id_counter - 1
            else:
                break
        _log.debug("Cookie ID {:d} was released.".format(cookie_id))


#
# MPLS reserved ids
# https://tools.ietf.org/html/rfc7274
# https://www.iana.org/assignments/mpls-label-values/mpls-label-values.xhtml
__recycled_mpls_labels = []
__mpls_label_id_counter = 16
__mpls_lock = Lock()


def alloc_mpls_label_id():
    global __mpls_label_id_counter

    with __mpls_lock:
        if __mpls_label_id_counter == 0x100000:  # 0x100000 is the maximum label ID value
            raise ValueError("No MPLS labels available.")
        if len(__recycled_mpls_labels):
            return __recycled_mpls_labels.pop()
        __mpls_label_id_counter = __mpls_label_id_counter + 1
        return __mpls_label_id_counter


def free_mpls_label_id(label_id):
    global __mpls_label_id_counter

    with __mpls_lock:
        if label_id <= 16:
            raise ValueError("Mpls label ID value must be higher than 16")
        if label_id > __mpls_label_id_counter or label_id in __recycled_mpls_labels:
            raise ValueError("Label ID was not allocated")

        __recycled_mpls_labels.append(label_id)

        while len(__recycled_mpls_labels) > 0:
            max_value = max(__recycled_mpls_labels)
            if __mpls_label_id_counter == max_value:
                __recycled_mpls_labels.remove(max_value)
                __mpls_label_id_counter = __mpls_label_id_counter - 1
            else:
                break


def send_msg(*args, **kwargs):
    return default_configs["send_msg"](*args, **kwargs)


def get_datapath_obj(*args, **kwargs):
    return default_configs["get_datapath"](*args, **kwargs)

