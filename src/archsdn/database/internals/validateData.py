
def validate_address(ip_addr):
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_addr)
        if ip.is_multicast:
            return False
        return True
    except Exception:
        return False


def validate_port(port):
    if not isinstance(port, int):
        return False
    if port < 0 or port > 0xFFFF:
        return False
    return True
