import copy
from hashlib import sha1
from contextlib import suppress

from radixtarget.tree.ip import IPRadixTree
from radixtarget.tree.dns import DNSRadixTree
from radixtarget.helpers import is_ip, is_dns_name, make_ip, host_size_key


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
        self.ipv4_tree = IPRadixTree()
        self.ipv6_tree = IPRadixTree()
        self.dns_tree = DNSRadixTree(strict_scope=strict_dns_scope)
        self._hosts = set()
        self.add(targets)

    def get_node(self, host, raise_error=False):
        host = make_ip(host)
        node = None
        if is_ip(host):
            if host.version == 4:
                node = self.ipv4_tree.get_node(host, raise_error=raise_error)
            else:
                node = self.ipv6_tree.get_node(host, raise_error=raise_error)
        elif is_dns_name(host):
            node = self.dns_tree.get_node(host, raise_error=raise_error)
        else:
            raise ValueError(f"Invalid host: '{host}'")
        return node

    def delete_node(self, host):
        host = make_ip(host)
        self.hosts.discard(host)
        if is_ip(host):
            if host.version == 4:
                return self.ipv4_tree.delete_node(host)
            else:
                return self.ipv6_tree.delete_node(host)
        elif is_dns_name(host):
            return self.dns_tree.delete_node(host)
        else:
            raise ValueError(f"Invalid host: '{host}'")

    def get(self, host, raise_error=False):
        node = self.get_node(host, raise_error=raise_error)
        return getattr(node, "data", None)

    def search(self, host, raise_error=False):
        # alias for get
        return self.get(host, raise_error=raise_error)

    def get_data(self, host, raise_error=False):
        # alias for get
        return self.get(host, raise_error=raise_error)

    def get_host(self, host, raise_error=False):
        node = self.get_node(host, raise_error=raise_error)
        return getattr(node, "host", None)

    def insert(self, t, data=None):
        """
        Alias for add
        """
        return self.add(t, data=data)

    def put(self, t, data=None):
        """
        Alias for add
        """
        return self.add(t, data=data)

    def add(self, t, data=None):
        """
        Add a target or merge hosts from another Target object into this Target.

        Args:
            t: The target to be added. It can be either a string, ipaddress object, or another Target object.

        Examples:
            >>> target.add('example.com')
        """
        results = []
        if isinstance(t, self.__class__):
            t = t.hosts
        if not isinstance(t, (list, tuple, set)):
            t = [t]
        for host in sorted(t, key=host_size_key):
            results.append(self._add(host, data=data))
        return results

    def _add(self, host, data=None):
        """
        A no-op layer for custom functionality.

        If you need to perform special tasks when adding a host, you can override this method.
        """
        return self._add_host(host, data=data)

    def _add_host(self, host, data=None):
        if self.acl_mode:
            with suppress(KeyError):
                self.search(host, raise_error=True)
                # if we're in acl mode, we skip adding hosts that are already in the target
                return
        host = make_ip(host)
        self._hash = None
        self._hosts.add(host)
        if is_ip(host):
            if host.version == 4:
                return self.ipv4_tree.insert(host, data=data)
            else:
                return self.ipv6_tree.insert(host, data=data)
        elif is_dns_name(host):
            return self.dns_tree.insert(host, data=data)
        else:
            raise ValueError(f"Invalid host: '{host}'")

    def prune(self):
        return self.ipv4_tree.prune() + self.ipv6_tree.prune() + self.dns_tree.prune()

    def defrag(self):
        cleaned_hosts = set()
        new_hosts = set()
        for tree in [self.ipv4_tree, self.ipv6_tree]:
            _cleaned, _new = tree.defrag()
            cleaned_hosts.update(_cleaned)
            new_hosts.update(_new)
        self._hosts.difference_update(cleaned_hosts)
        self._hosts.update(new_hosts)
        return cleaned_hosts, new_hosts

    @property
    def hosts(self):
        """
        Returns all hosts in the target.
        """
        return self._hosts

    @property
    def sorted_hosts(self):
        return sorted(self._hosts, key=host_size_key)

    @property
    def all_nodes(self):
        return self.ipv4_tree.all_nodes + self.ipv6_tree.all_nodes + self.dns_tree.all_nodes

    @property
    def nodes_by_host(self):
        return self.ipv4_tree.nodes_by_host | self.ipv6_tree.nodes_by_host | self.dns_tree.nodes_by_host

    def _hash_value(self):
        return [str(h).encode() for h in self.sorted_hosts]

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
        self_copy = self.__class__(strict_dns_scope=self.strict_dns_scope, acl_mode=self.acl_mode)
        self_copy._hosts = set(self._hosts)
        self_copy.ipv4_tree = copy.copy(self.ipv4_tree)
        self_copy.ipv6_tree = copy.copy(self.ipv6_tree)
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
            for host in self._hash_value():
                sha1_hash.update(host)
            if self.strict_dns_scope:
                sha1_hash.update(b"\x00")
            self._hash = sha1_hash.digest()
        return self._hash

    def __str__(self):
        return ",".join([str(h) for h in self.sorted_hosts][:5]) + (",..." if len(self.hosts) > 5 else "")

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
