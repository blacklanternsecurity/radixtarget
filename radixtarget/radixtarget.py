import copy
from hashlib import sha1

from radixtarget.tree.ip import IPRadixTree
from radixtarget.tree.dns import DNSRadixTree
from radixtarget.helpers import is_ip, make_ip, host_size_key


sentinel = object()


class RadixTarget:
    """
    A class representing a target. Can contain an unlimited number of hosts, IPs, or IP ranges.

    Attributes:
        strict_scope (bool): Flag indicating whether to consider child domains in-scope.
            If set to True, only the exact hosts specified and not their children are considered part of the target.

    Examples:
        Basic usage
        >>> target = RadixTarget("evilcorp.com", "1.2.3.0/24")
        >>> len(target)
        257
        >>> "www.evilcorp.com" in target
        True
        >>> "1.2.3.4" in target
        True
        >>> "4.3.2.1" in target
        False

        Target comparison
        >>> target2 = RadixTarget("www.evilcorp.com")
        >>> target2 == target
        False
        >>> target2 in target
        True
        >>> target in target2
        False

    Notes:
        - If you do not want to include child subdomains, use `strict_scope=True`
    """

    def __init__(self, *targets, strict_dns_scope=False, acl_mode=False):
        """
        Initialize a Target object.

        Args:
            *targets: One or more targets (e.g., domain names, IP ranges) to be included in this Target.
            strict_scope (bool): Whether to consider subdomains of target domains in-scope
            acl_mode (bool): If a host is already in the target, don't add it unnecessarily (more efficient)

        Notes:
            - The strict_scope flag can be set to restrict scope calculation to only exactly-matching hosts and not their child subdomains.
        """
        self._hash = None
        self.strict_dns_scope = strict_dns_scope
        self.acl_mode = acl_mode
        self.ip_tree = IPRadixTree()
        self.dns_tree = DNSRadixTree(strict_scope=strict_dns_scope)
        self._hosts = set()
        self.add(targets)

    def get(self, host, raise_error=False):
        host = make_ip(host)
        if is_ip(host):
            return self.ip_tree.search(host, raise_error=raise_error)
        else:
            return self.dns_tree.search(host, raise_error=raise_error)

    def search(self, host, raise_error=False):
        return self.get(host, raise_error=raise_error)

    def insert(self, t, data=None):
        self.add(t, data=data)

    def add(self, t, data=None):
        """
        Add a target or merge hosts from another Target object into this Target.

        Args:
            t: The target to be added. It can be either a string, ipaddress object, or another Target object.

        Examples:
            >>> target.add('example.com')
        """
        if isinstance(t, self.__class__):
            t = t.hosts
        if not isinstance(t, (list, tuple, set)):
            t = [t]
        for single_target in sorted(t, key=host_size_key):
            self._add(single_target, data=data)

    def _add(self, single_target, data=None):
        host = make_ip(single_target)
        self.add_host(host, data=data)

    def add_host(self, host, data=None):
        host = make_ip(host)
        try:
            result = self.search(host, raise_error=True)
        except KeyError:
            result = sentinel
        # if we're in acl mode, we skip adding hosts that are already in the target
        if self.acl_mode and result is not sentinel:
            return
        self._add_host(host, data=data)

    def _add_host(self, host, data=None):
        self._hash = None
        self._hosts.add(host)
        if is_ip(host):
            self.ip_tree.insert(host, data=data)
        else:
            self.dns_tree.insert(host, data=data)

    @property
    def hosts(self):
        """
        Returns all hosts in the target.
        """
        return self._hosts

    @property
    def sorted_hosts(self):
        return sorted(self._hosts, key=host_size_key)

    def copy(self):
        """
        Creates and returns a copy of the Target object, including a shallow copy of the `_events` attributes.

        Returns:
            Target: A new Target object with the same attributes as the original.
                    A shallow copy of the `_events` dictionary is made.

        Examples:
            >>> original_target = RadixTarget("example.com")
            >>> copied_target = original_target.copy()
            >>> copied_target is original_target
            False
            >>> copied_target == original_target
            True
            >>> copied_target in original_target
            True
            >>> original_target in copied_target
            True

        Notes:
            - The `scan` object reference is kept intact in the copied Target object.
        """
        self_copy = self.__class__(
            strict_dns_scope=self.strict_dns_scope, acl_mode=self.acl_mode
        )
        self_copy._hosts = set(self._hosts)
        self_copy.ip_tree = copy.copy(self.ip_tree)
        self_copy.dns_tree = copy.copy(self.dns_tree)
        return self_copy

    def _contains(self, other):
        try:
            self.get(other, raise_error=True)
            return True
        except KeyError:
            return False

    @property
    def hash(self):
        if self._hash is None:
            # Create a new SHA-1 hash object
            sha1_hash = sha1()
            # Update the SHA-1 object with the hash values of each object
            for host in [str(h).encode() for h in self.sorted_hosts]:
                sha1_hash.update(host)
            if self.strict_dns_scope:
                sha1_hash.update(b"\x00")
            self._hash = sha1_hash.digest()
        return self._hash

    def __str__(self):
        return ",".join([str(h) for h in self.sorted_hosts][:5]) + (
            ",..." if len(self.hosts) > 5 else ""
        )

    def __iter__(self):
        yield from self.hosts

    def __contains__(self, other):
        # if "other" is a Target, iterate over its hosts and check if they are in self
        if isinstance(other, self.__class__):
            for h in other.hosts:
                if not self._contains(h):
                    return False
            return True
        else:
            return self._contains(other)

    def __bool__(self):
        return bool(self._hosts)

    def __eq__(self, other):
        return self.hash == other.hash

    def __len__(self):
        """
        Calculates and returns the total number of hosts within this target, not counting duplicate hosts.

        Returns:
            int: The total number of unique hosts present within the target's `_hosts`.

        Examples:
            >>> target = RadixTarget("evilcorp.com", "1.2.3.0/24")
            >>> len(target)
            257

        Notes:
            - If a host is represented as an IP network, all individual IP addresses in that network are counted.
            - For other types of hosts, each unique host is counted as one.
        """
        num_hosts = 0
        for host in self._hosts:
            if is_ip(host):
                num_hosts += host.num_addresses
            else:
                num_hosts += 1
        return num_hosts
