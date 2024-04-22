import ipaddress

from .tree.ip import IPRadixTree
from .tree.dns import DNSRadixTree


class RadixTarget:
    def __init__(self):
        self.ip_tree = IPRadixTree()
        self.dns_tree = DNSRadixTree()

    def insert(self, host, data=None):
        host = self.make_ip(host)
        if self.is_ip(host):
            self.ip_tree.insert(host, data=data)
        else:
            self.dns_tree.insert(host, data=data)

    def search(self, host):
        host = self.make_ip(host)
        if self.is_ip(host):
            return self.ip_tree.search(host)
        else:
            return self.dns_tree.search(host)

    def make_ip(self, host):
        try:
            return ipaddress.ip_network(host)
        except Exception:
            return str(host).lower()

    def is_ip(self, host):
        return ipaddress._IPAddressBase in host.__class__.__mro__
