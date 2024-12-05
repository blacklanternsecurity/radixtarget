sentinel = object()


class RadixTreeNode:
    __slots__ = ("children", "host", "data")

    def __init__(self):
        self.children = {}
        self.host = None
        self.data = sentinel

    @property
    def all_child_nodes(self):
        nodes = []
        if self.host is not None:
            nodes.append(self)
        for child in self.children.values():
            nodes.extend(child.all_child_nodes)
        return nodes

    @property
    def nodes_by_host(self):
        return {node.host: node for node in self.all_child_nodes}

    def prune(self):
        """
        Prune dead nodes
        """
        pruned = 0
        while 1:
            new_pruned = 0
            # prune intermediate nodes with no children
            for segment, child in list(self.children.items()):
                if child.host is None and not child.children:
                    del self.children[segment]
                    new_pruned += 1
                    continue
                new_pruned += child.prune()
            if new_pruned == 0:
                break
            pruned += new_pruned
        return pruned


class BaseRadixTree:
    node_class = RadixTreeNode

    def __init__(self):
        self.root = self.node_class()

    def get(self, *args, **kwargs):
        return self.get_data(*args, **kwargs)

    def search(self, *args, **kwargs):
        return self.get_data(*args, **kwargs)

    def get_data(self, query, raise_error=False):
        node = self.get_node(query, raise_error)
        return getattr(node, "data", None)

    def get_host(self, query, raise_error=False):
        node = self.get_node(query, raise_error)
        return getattr(node, "host", None)

    @property
    def all_nodes(self):
        return self.root.all_child_nodes

    @property
    def nodes_by_host(self):
        return self.root.nodes_by_host

    def prune(self):
        return self.root.prune()
