import time
import random
import logging
import ipaddress
from pathlib import Path

log = logging.getLogger("radixtarget.test")

cidr_list_path = Path(__file__).parent / "cidrs.txt"

from radixtarget import RadixTarget


def test_radixtarget():
    rt = RadixTarget()

    for _ in range(2):

        # ipv4
        rt.insert("192.168.1.0/24")
        assert rt.search("192.168.1.10") == ipaddress.ip_network("192.168.1.0/24")
        assert rt.search("192.168.2.10") is None
        rt.insert(ipaddress.ip_network("10.0.0.0/8"))
        assert rt.search("10.255.255.255") == ipaddress.ip_network("10.0.0.0/8")
        rt.insert(ipaddress.ip_network("172.16.12.1"))
        assert rt.search("172.16.12.1") == ipaddress.ip_network("172.16.12.1/32")
        rt.insert("8.8.8.0/24", "custom_data_8")
        assert rt.search("8.8.8.8") == "custom_data_8"

        # ipv6
        rt.insert("dead::/64")
        assert rt.search("dead::beef") == ipaddress.ip_network("dead::/64")
        assert rt.search("dead:cafe::beef") == None
        rt.insert("cafe::babe")
        assert rt.search("cafe::babe") == ipaddress.ip_network("cafe::babe/128")
        rt.insert("beef::/120", "custom_beef")
        assert rt.search("beef::bb") == "custom_beef"

        # networks
        rt.insert("192.168.128.0/24")
        assert rt.search("192.168.128.0/28") == ipaddress.ip_network("192.168.128.0/24")
        assert rt.search("192.168.128.0/23") == None
        rt.insert("babe::/64")
        assert rt.search("babe::/96") == ipaddress.ip_network("babe::/64")
        assert rt.search("babe::/63") == None

        # ipv4 / ipv6 confusion
        rand_int = random.randint(0, 2**32 - 1)
        ipv4_address = ipaddress.IPv4Address(rand_int)
        ipv6_address = ipaddress.IPv6Address(rand_int << (128 - 32))
        ipv6_network = ipaddress.IPv6Network(f"{ipv6_address}/32")
        rt.insert(ipv4_address)
        assert rt.search(ipv4_address)
        assert not rt.search(ipv6_address)
        assert not rt.search(ipv6_network)

        # dns
        rt.insert("net")
        rt.insert("www.example.com")
        rt.insert("test.www.example.com")
        assert rt.search("net") == "net"
        assert rt.search("evilcorp.net") == "net"
        assert rt.search("www.example.com") == "www.example.com"
        assert rt.search("asdf.test.www.example.com") == "test.www.example.com"
        assert rt.search("example.com") is None
        rt.insert("evilcorp.co.uk", "custom_data")
        assert rt.search("www.evilcorp.co.uk") == "custom_data"

        # speed benchmark
        cidrs = open(cidr_list_path).read().splitlines()
        log.critical(len(cidrs))
        for c in cidrs:
            rt.insert(c)

        iterations = 10000

        start = time.time()
        for i in range(iterations):
            random_ip = ipaddress.ip_address(random.randint(0, 2**32 - 1))
            rt.search(random_ip)
        end = time.time()
        elapsed = end - start
        log.critical(
            f"{iterations:,} iterations in {elapsed:.4f} seconds ({int(iterations/elapsed)}/s)"
        )
