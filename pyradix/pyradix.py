import ipaddress

from .tree.ip import IPRadixTree
from .tree.dns import DNSRadixTree


class RadixTree:
    def __init__(self):
        self.ip_tree = IPRadixTree()
        self.dns_tree = DNSRadixTree()

    def insert(self, host):
        host = self.make_ip(host)
        if self.is_ip(host):
            self.ip_tree.insert(host)
        else:
            self.dns_tree.insert(host)

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
            return str(host)

    def is_ip(self, host):
        try:
            ipaddress.ip_network(host)
            return True
        except Exception:
            pass
        print(f"{host} is not an IP network!!!!")
        return False
