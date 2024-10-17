sentinel = object()


class RadixTreeNode:
    __slots__ = ("children", "host", "data")

    def __init__(self):
        self.children = {}
        self.host = None
        self.data = sentinel


class BaseRadixTree:
    def __init__(self):
        self.root = RadixTreeNode()
