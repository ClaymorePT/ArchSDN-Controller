import pathlib
import argparse
import ipaddress
from uuid import UUID

def validate_path(location):
    if location == ":memory:":
        return location
    loc = pathlib.Path(location)
    loc_parent = loc.parent
    if not loc_parent.exists():
        raise argparse.ArgumentTypeError("Location {:s} does not exist.".format(str(loc_parent)))
    return(loc)


def validate_id(id):
    try:
        if id == 'random':
            return id
        try:
            return UUID(int=int(id))
        except ValueError:
            return UUID(id)
    except Exception:
        raise argparse.ArgumentTypeError("Controller ID is invalid: {:s}.".format(str(id)))



def validate_address(address):
    try:
        ip = ipaddress.ip_address(address)
        if (not ip.is_multicast and not ip.is_unspecified) or \
                (ip == ipaddress.IPv4Address('0.0.0.0')) or \
                (ip == ipaddress.IPv6Address('::')):
            return ip
        else:
            raise argparse.ArgumentTypeError("Invalid IP address: {:s}".format(address))
    except Exception:
        raise argparse.ArgumentTypeError("Invalid IP address: {:s}".format(address))

def validate_ipv4network(address):
    try:
        ip = ipaddress.IPv4Network(address)
        if ip.is_private:
            return ip
        else:
            raise argparse.ArgumentTypeError("Invalid IPv4 network address: {:s}".format(address))
    except Exception:
        raise argparse.ArgumentTypeError("Invalid IPv4 network address: {:s}".format(address))

def validate_ipv6network(address):
    try:
        ip = ipaddress.IPv6Network(address)
        if ip.is_private:
            return ip
        else:
            raise argparse.ArgumentTypeError("Invalid IPv6 network address: {:s}".format(address))
    except Exception:
        raise argparse.ArgumentTypeError("Invalid IPv6 network address: {:s}".format(address))

def validate_port(port):
    try:
        p = int(port)
        if p in range(1024, 0xFFFF):
            return p
        else:
            raise argparse.ArgumentTypeError("Invalid Port: {:s}".format(port))
    except Exception:
        raise argparse.ArgumentTypeError("Invalid Port: {:s}".format(port))


def parse_arguments():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l", "--logLevel",
        help="Logging Level (default: %(default)s)",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        type=str
    )
    parser.add_argument(
        "-s", "--storage",
        help="SQLite3 Database Location (default: %(default)s)",
        default=':memory:',
        type=validate_path
    )
    parser.add_argument(
        "-id", "--uuid",
        help="Controller UUID (default: %(default)s)",
        default='random',
        type=validate_id
    )
    parser.add_argument(
        "-ip", "--ip",
        help="Controller IP (default: %(default)s)",
        default='0.0.0.0',
        type=validate_address
    )
    parser.add_argument(
        "-p", "--port",
        help="Controller Port (default: %(default)s)",
        default=12345,
        type=int
    )
    parser.add_argument(
        "-cip", "--cip",
        help="Central Management Server IP (default: %(default)s)",
        default='127.0.0.1',
        type=validate_address
    )
    parser.add_argument(
        "-cp", "--cport",
        help="Central Management Server Port (default: %(default)s)",
        default=12345,
        type=int
    )
    parser.add_argument(
        "-ofip", "--ofip",
        help="OpenFlow Service IP ",
        type=validate_address
    )
    parser.add_argument(
        "-ofp", "--ofport",
        help="OpenFlow Service Port (default: %(default)s)",
        default=6631,
        type=int
    )

    return parser.parse_args()