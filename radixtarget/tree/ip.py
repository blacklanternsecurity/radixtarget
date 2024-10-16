import ipaddress

from .base import BaseRadixTree, RadixTreeNode

sentinel = object()


class IPRadixTree(BaseRadixTree):
    """A radix tree for efficient IP network lookups."""

    def insert(self, network, data=None):
        """Add an IP network to the tree.

        Args:
            network: IP network to insert (string or ipaddress.IPv4Network/IPv6Network).
            data: Optional data to associate with the network. Defaults to the network itself.
        """
        network = ipaddress.ip_network(network, strict=False)
        if data is None:
            data = network
        node = self.root
        network_value = int(network.network_address)
        for i in range(network.prefixlen):
            current_bit = (network_value >> (network.max_prefixlen - 1 - i)) & 1
            if current_bit not in node.children:
                node.children[current_bit] = RadixTreeNode()
            node = node.children[current_bit]
        node.host = network
        node.data = data

    def search(self, query, raise_error=False):
        """Find the most specific matching entry for a given IP address or network.

        Args:
            query: IP address or network to search for (string or ipaddress object).
            raise_error: If True, raise KeyError when no match is found. Defaults to False.

        Returns:
            The data associated with the most specific matching network, or None if no match.

        Raises:
            KeyError: If raise_error is True and no match is found.
        """
        query_network = ipaddress.ip_network(query, strict=False)
        ip_value = int(query_network.network_address)
        query_prefixlen = query_network.prefixlen

        node = self.root
        matched_data = sentinel
        for i in range(query_prefixlen):
            current_bit = (ip_value >> (query_network.max_prefixlen - 1 - i)) & 1
            if current_bit in node.children:
                node = node.children[current_bit]
                if node.host and node.host.prefixlen <= query_prefixlen:
                    if query_network.network_address in node.host:
                        matched_data = node.data
            else:
                break

        if matched_data is sentinel:
            if raise_error:
                raise KeyError(f'IP "{query}" not found')
            return None
        return matched_data
