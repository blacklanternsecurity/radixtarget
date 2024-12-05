import re
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


dns_name_regex = re.compile(r"^[\w]+[\w.-]*$", re.I)


def is_dns_name(host):
    """
    Check if the given host is a valid DNS name.

    This function uses a regular expression to determine if the provided
    host string matches the pattern of a valid DNS name. The pattern allows
    alphanumeric characters, underscores, hyphens, and periods, and is case-insensitive.

    Args:
        host (str): The host string to check.

    Returns:
        bool: True if the host is a valid DNS name, False otherwise.
    """
    return bool(dns_name_regex.match(host))


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
            raise ValueError(f'Host "{host}" must be of str or ipaddress type, not "{type(host)}"')
    try:
        return ipaddress.ip_network(host, strict=False)
    except Exception:
        return host.lower()


def network_to_bits(network):
    network_value = int(network.network_address)
    for i in range(network.prefixlen):
        yield (network_value >> (network.max_prefixlen - 1 - i)) & 1


def merge_subnets(network1, network2):
    if network1.version != network2.version:
        raise ValueError(f"Cannot merge networks of different versions: {network1} and {network2}")
    # make sure network1 comes before network2
    if network1.network_address > network2.network_address:
        network1, network2 = network2, network1
    if not network1.prefixlen == network2.prefixlen:
        raise ValueError(f"Cannot merge networks with different prefix lengths: {network1} and {network2}")
    supernet1 = network1.supernet(1)
    supernet2 = network2.supernet(1)
    if supernet1 != supernet2:
        raise ValueError(f"Cannot merge networks {network1} and {network2} because their supernets are not the same")
    return supernet1
