import ipaddress

from .base import BaseRadixTree, RadixTreeNode


class IPRadixTree(BaseRadixTree):

    def insert(self, network, data=None):
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

    def search(self, query):
        query_network = ipaddress.ip_network(query, strict=False)
        ip_value = int(query_network.network_address)
        query_prefixlen = query_network.prefixlen

        node = self.root
        matched_data = None
        for i in range(query_prefixlen):
            current_bit = (ip_value >> (query_network.max_prefixlen - 1 - i)) & 1
            if current_bit in node.children:
                node = node.children[current_bit]
                if node.host and node.host.prefixlen <= query_prefixlen:
                    if query_network.network_address in node.host:
                        matched_data = node.data
            else:
                break
        return matched_data
