from ipaddress import IPv4Address, IPv6Address


def is_ipv4_port_tuple(ipv4_info):
    return isinstance(ipv4_info, tuple) and \
           len(ipv4_info) == 2 and \
           isinstance(ipv4_info[0], IPv4Address) and \
           isinstance(ipv4_info[1], int) and \
           0 < ipv4_info[1] <= 0xFFFF


def is_ipv6_port_tuple(ipv6_info):
    return isinstance(ipv6_info, tuple) and \
           len(ipv6_info) == 2 and \
           isinstance(ipv6_info[0], IPv6Address) and \
           isinstance(ipv6_info[1], int) and \
           0 < ipv6_info[1] <= 0xFFFF
