from .base import BaseRadixTree, RadixTreeNode, sentinel


class DNSRadixTree(BaseRadixTree):
    """A radix tree for efficient DNS hostname lookups.

    This tree stores hostnames in reverse order (TLD to subdomain) for hierarchical matching.
    """

    def __init__(self, strict_scope=False, **kwargs):
        super().__init__(**kwargs)
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
        node.host = hostname
        node.data = data

    def delete_node(self, query):
        parts = list(reversed(query.split(".")))
        node = self.root
        if parts:
            for part in parts[:-1]:
                if part in node.children:
                    node = node.children[part]
                else:
                    raise KeyError(f'Hostname "{query}" not found')
        node_index = parts[-1]
        old_node = node.children[node_index]
        if old_node.host is None:
            raise KeyError(f'Hostname "{query}" not found')
        if old_node.children:
            # replace the node with a blank/passthrough
            new_node = self.node_class()
            new_node.children = old_node.children
            node.children[node_index] = new_node
        else:
            del node.children[node_index]

    def get_node(self, hostname, raise_error=False):
        """Find the most specific matching entry for a given hostname.

        Args:
            hostname (str): The hostname to search for.

        Returns:
            The data associated with the most specific matching hostname, or None if no match.
        """
        parts = hostname.split(".")
        node = self.root
        matched_node = sentinel
        # Search through the tree in the order from TLD to subdomain
        for i, part in enumerate(reversed(parts)):
            if part in node.children:
                node = node.children[part]
                # if strict scope is not enabled, every part must match
                if self.strict_scope and i + 1 < len(parts):
                    continue
                if node.data is not sentinel:
                    matched_node = node
            else:
                break
        if matched_node is sentinel:
            if raise_error:
                raise KeyError(f'Hostname "{hostname}" not found')
            return None
        return matched_node
