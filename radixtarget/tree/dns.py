from .base import BaseRadixTree, RadixTreeNode


class DNSRadixTree(BaseRadixTree):
    def insert(self, hostname, data=None):
        if data is None:
            data = hostname
        parts = hostname.split(".")
        node = self.root
        # Reverse the parts of the hostname for proper hierarchy (TLD to subdomain)
        for part in reversed(parts):
            if part not in node.children:
                node.children[part] = RadixTreeNode()
            node = node.children[part]
        node.data = data

    def search(self, hostname):
        parts = hostname.split(".")
        node = self.root
        matched_data = None
        # Search through the tree in the order from TLD to subdomain
        for part in reversed(parts):
            if part in node.children:
                node = node.children[part]
                if node.data:
                    matched_data = node.data
            else:
                break
        return matched_data
