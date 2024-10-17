from .base import BaseRadixTree, RadixTreeNode, sentinel


class DNSRadixTree(BaseRadixTree):
    """A radix tree for efficient DNS hostname lookups.

    This tree stores hostnames in reverse order (TLD to subdomain) for hierarchical matching.
    """

    def __init__(self, strict_scope=False):
        super().__init__()
        self.strict_scope = strict_scope

    def insert(self, hostname, data=None):
        """Add a hostname to the tree.

        Args:
            hostname (str): The hostname to insert.
            data: Optional data to associate with the hostname. Defaults to the hostname itself.
        """
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

    def search(self, hostname, raise_error=False):
        """Find the most specific matching entry for a given hostname.

        Args:
            hostname (str): The hostname to search for.

        Returns:
            The data associated with the most specific matching hostname, or None if no match.
        """
        parts = hostname.split(".")
        node = self.root
        matched_data = sentinel
        # Search through the tree in the order from TLD to subdomain
        for i, part in enumerate(reversed(parts)):
            if part in node.children:
                node = node.children[part]
                # if strict scope is not enabled, every part must match
                if self.strict_scope and i + 1 < len(parts):
                    continue
                matched_data = node.data
            else:
                break
        if matched_data is sentinel:
            if raise_error:
                raise KeyError(f'Hostname "{hostname}" not found')
            return None
        return matched_data
