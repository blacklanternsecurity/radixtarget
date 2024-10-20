import ipaddress


def host_size_key(host):
    """
    Used for sorting by host size, so that parent dns names / ip subnets always come first

    Notes:
    - we have to use str(host) to break the tie between two hosts of the same length, e.g. evilcorp.com and evilcorp.net
    """
    host = make_ip(host)
    if is_ip(host):
        # bigger IP subnets should come first
        return (-host.num_addresses, str(host))
    # smaller domains should come first
    return (len(host), str(host))


def is_ip(host):
    """Check if the given host is an instance of an IP address.

    Args:
        host (Any): The host to check.

    Returns:
        bool: True if the host is an instance of an IP address, False otherwise.
    """
    return ipaddress._IPAddressBase in host.__class__.__mro__


def make_ip(host):
    """Convert a host to an IP network or return it as a lowercase string.

    This function checks if the provided host is a string or an IP address.
    If it is not a string and not an IP address, a ValueError is raised.
    If the host is a valid IP address or network, it is converted to an
    ipaddress.IPv4Network or ipaddress.IPv6Network object. If the host
    cannot be converted, it is returned as a lowercase string.

    Args:
        host (str or ipaddress): The host to convert.

    Raises:
        ValueError: If the host is not of str or ipaddress type.

    Returns:
        ipaddress.IPv4Network or ipaddress.IPv6Network or str: The converted
        IP network or the lowercase string representation of the host.
    """
    if not isinstance(host, str):
        if not is_ip(host):
            raise ValueError(
                f'Host "{host}" must be of str or ipaddress type, not "{type(host)}"'
            )
    try:
        return ipaddress.ip_network(host, strict=False)
    except Exception:
        return host.lower()
