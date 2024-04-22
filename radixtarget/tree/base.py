class RadixTreeNode:
    def __init__(self):
        self.children = {}
        self.host = None
        self.data = None


class BaseRadixTree:
    def __init__(self):
        self.root = RadixTreeNode()
