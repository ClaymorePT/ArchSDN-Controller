from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
from netaddr import EUI


_ipv4_network = None
_ipv6_network = None
_ipv4_service = None
_ipv6_service = None
_mac_service = None


def UpdateVolatileInformation(
        ipv4_network = None,
        ipv6_network = None,
        ipv4_service = None,
        ipv6_service = None,
        mac_service  = None,
):
    global _ipv4_network, _ipv6_network, _ipv4_service, _ipv6_service, _mac_service
    assert not (ipv4_network is None and
                ipv6_network is None and
                ipv4_service is None and
                ipv6_service is None and
                mac_service is None
                ), "No arguments have been passed."

    if ipv4_network:
        _ipv4_network = ipv4_network
    if ipv6_network:
        _ipv6_network = ipv6_network
    if ipv4_service:
        _ipv4_service = ipv4_service
    if ipv6_service:
        _ipv6_service = ipv6_service
    if mac_service:
        _mac_service = mac_service


def QueryVolatileInfo():
    return {
        'ipv4_network': IPv4Network(_ipv4_network),
        'ipv6_network': IPv6Network(_ipv6_network),
        'ipv4_service': IPv4Address(_ipv4_service),
        'ipv6_service': IPv6Address(_ipv6_service),
        'mac_service': EUI(_mac_service),
    }

