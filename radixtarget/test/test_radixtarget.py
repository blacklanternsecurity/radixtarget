import time
import pytest
import random
import logging
import ipaddress
from pathlib import Path

from radixtarget.tree.ip import IPRadixTree
from radixtarget.tree.dns import DNSRadixTree
from radixtarget.helpers import network_to_bits, merge_subnets, host_size_key

log = logging.getLogger("radixtarget.test")

cidr_list_path = Path(__file__).parent / "cidrs.txt"

from radixtarget import RadixTarget


def test_radixtarget():
    """
    Tests various functionalities of the Target library, including:

    - Initialization and comparison of Target objects with different IPs and domains.
    - Checking membership of IPs, subnets, and domains within Target objects.
    - Hashing and equality checks for Target objects.
    - Sorting of network and domain events based on size.
    - Insertion and search operations in IP and DNS radix trees.
    - Handling of strict DNS scope and error-raising during searches.
    - Performance benchmarking for IP search operations.
    - Ensuring correct handling of ACL mode for subnets and domains.
    - Verifying strict DNS scope doesn't interfere with ACL operations.
    """

    target1 = RadixTarget("api.publicapis.org", "8.8.8.8/30", "2001:4860:4860::8888/126")
    target2 = RadixTarget("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    target3 = RadixTarget("8.8.8.8/29", "publicapis.org", "2001:4860:4860::8888/125")
    target4 = RadixTarget("8.8.8.8/29")
    target5 = RadixTarget()
    assert not target5
    assert len(target1) == 9
    assert len(target4) == 8
    assert "8.8.8.9" in target1
    assert "8.8.8.12" not in target1
    assert "8.8.8.8/31" in target1
    assert "8.8.8.8/30" in target1
    assert "8.8.8.8/29" not in target1
    assert "2001:4860:4860::8889" in target1
    assert "2001:4860:4860::888c" not in target1
    assert "www.api.publicapis.org" in target1
    assert "api.publicapis.org" in target1
    assert "publicapis.org" not in target1
    assert target1 in target2
    assert target2 not in target1
    assert target3 in target2
    assert target2 == target3
    assert target4 != target1

    assert ipaddress.ip_network("8.8.8.8/30") in target1
    assert ipaddress.ip_network("8.8.8.8/30") in target1.hosts

    assert not target5
    assert len(target1) == 9
    assert len(target4) == 8
    assert "8.8.8.9" in target1
    assert "8.8.8.12" not in target1
    assert "8.8.8.8/31" in target1
    assert "8.8.8.8/30" in target1
    assert "8.8.8.8/29" not in target1
    assert "2001:4860:4860::8889" in target1
    assert "2001:4860:4860::888c" not in target1
    assert "www.api.publicapis.org" in target1
    assert "api.publicapis.org" in target1
    assert "publicapis.org" not in target1

    assert str(target1.get("8.8.8.9")) == "8.8.8.8/30"
    assert target1.get("8.8.8.12") is None
    assert str(target1.get("2001:4860:4860::8889")) == "2001:4860:4860::8888/126"
    assert target1.get("2001:4860:4860::888c") is None
    assert str(target1.get("www.api.publicapis.org")) == "api.publicapis.org"
    assert target1.get("publicapis.org") is None

    target = RadixTarget("evilcorp.com")
    assert not "com" in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = RadixTarget("evilcorp.com", strict_dns_scope=True)
    assert not "com" in strict_target
    assert "evilcorp.com" in strict_target
    assert not "www.evilcorp.com" in strict_target

    target = RadixTarget()
    target.add("evilcorp.com")
    assert not "com" in target
    assert "evilcorp.com" in target
    assert "www.evilcorp.com" in target
    strict_target = RadixTarget(strict_dns_scope=True)
    strict_target.add("evilcorp.com")
    assert not "com" in strict_target
    assert "evilcorp.com" in strict_target
    assert not "www.evilcorp.com" in strict_target

    # test target hashing

    target1 = RadixTarget()
    target1.add("evilcorp.com")
    target1.add("1.2.3.4/24")
    target1.add("evilcorp.net")
    assert target1.hash == b"\xf7N\x89-\x7f(\xb3\xbe\n\xb9\xc5\xc3\x96\xee;\xecJ\xeb\xa8u"

    target2 = RadixTarget()
    target2.add("evilcorp.org")
    target2.add("evilcorp.com")
    target2.add("1.2.3.4/24")
    target2.add("evilcorp.net")
    assert target2.hash == b"\xbe\xcf\xf3\x06\xcb`\xc9\xd17\x14\x1c\r\xc18\x95{4\xcb9\x8a"

    target3 = RadixTarget(*list(target1))
    assert target3.hash == b"\xf7N\x89-\x7f(\xb3\xbe\n\xb9\xc5\xc3\x96\xee;\xecJ\xeb\xa8u"

    target4 = RadixTarget(*list(target1), strict_dns_scope=True)
    assert target4.hash == b"stC\xd6\xd7\xa7\xf8\xfc\\4\xbd\x81NT\x17\xc6Nn'B"

    # make sure it's a sha1 hash
    assert isinstance(target1.hash, bytes)
    assert len(target1.hash) == 20

    # hashes shouldn't match yet
    assert target1.hash != target2.hash
    # add missing host
    target1.add("evilcorp.org")
    # now they should match
    assert target1.hash == target2.hash

    # test target sorting
    big_subnet = "1.2.3.4/24"
    medium_subnet = "1.2.3.4/28"
    small_subnet = "1.2.3.4/30"
    ip_event = "1.2.3.4"
    parent_domain = "evilcorp.com"
    grandparent_domain = "www.evilcorp.com"
    greatgrandparent_domain = "api.www.evilcorp.com"
    target = RadixTarget()
    assert host_size_key(ipaddress.ip_address("1.2.3.4")) == (-1, "1.2.3.4/32")
    assert host_size_key(big_subnet) == (-256, "1.2.3.0/24")
    assert host_size_key(medium_subnet) == (-16, "1.2.3.0/28")
    assert host_size_key(small_subnet) == (-4, "1.2.3.4/30")
    assert host_size_key(ip_event) == (-1, "1.2.3.4/32")
    assert host_size_key(parent_domain) == (12, "evilcorp.com")
    assert host_size_key(grandparent_domain) == (16, "www.evilcorp.com")
    assert host_size_key(greatgrandparent_domain) == (20, "api.www.evilcorp.com")
    events = [
        big_subnet,
        medium_subnet,
        small_subnet,
        ip_event,
        parent_domain,
        grandparent_domain,
        greatgrandparent_domain,
    ]
    random.shuffle(events)
    assert sorted(events, key=host_size_key) == [
        big_subnet,
        medium_subnet,
        small_subnet,
        ip_event,
        parent_domain,
        grandparent_domain,
        greatgrandparent_domain,
    ]

    # merging targets
    target1 = RadixTarget("1.2.3.4/24", "evilcorp.net")
    target2 = RadixTarget("evilcorp.com", "evilcorp.net")
    assert sorted([str(h) for h in target1]) == ["1.2.3.0/24", "evilcorp.net"]
    assert sorted([str(h) for h in target2]) == ["evilcorp.com", "evilcorp.net"]
    target1.add(target2)
    assert sorted([str(h) for h in target1]) == [
        "1.2.3.0/24",
        "evilcorp.com",
        "evilcorp.net",
    ]
    assert str(target1) == "1.2.3.0/24,evilcorp.com,evilcorp.net"

    # copying
    target3 = target1.copy()
    assert target3 == target1
    assert target3 is not target1
    assert sorted([str(h) for h in target3]) == [
        "1.2.3.0/24",
        "evilcorp.com",
        "evilcorp.net",
    ]

    target1.add(["www.evilcorp.com", "www.evilcorp.net", "test.www.evilcorp.com"])
    assert str(target1) == "1.2.3.0/24,evilcorp.com,evilcorp.net,www.evilcorp.com,www.evilcorp.net,..."

    target = RadixTarget("evilcorp.com", "test.com")
    assert target.search("azure.com") is None

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
        assert rt.search("dead:cafe::beef") is None
        rt.insert("cafe::babe")
        assert rt.search("cafe::babe") == ipaddress.ip_network("cafe::babe/128")
        rt.insert("beef::/120", "custom_beef")
        assert rt.search("beef::bb") == "custom_beef"

        # networks
        rt.insert("192.168.128.0/24")
        assert rt.search("192.168.128.0/28") == ipaddress.ip_network("192.168.128.0/24")
        assert rt.search("192.168.128.0/23") is None
        rt.insert("babe::/64")
        assert rt.search("babe::/96") == ipaddress.ip_network("babe::/64")
        assert rt.search("babe::/63") is None

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

        with pytest.raises(ValueError, match=".*must be of str or ipaddress type.*"):
            rt.insert(b"asdf")

        with pytest.raises(ValueError, match=".*must be of str or ipaddress type.*"):
            rt.search(b"asdf")

        assert "net" in rt.dns_tree.root.children
        assert "com" in rt.dns_tree.root.children

        # Tests for strict_scope parameter
        dns_rt_strict_scope = DNSRadixTree(strict_scope=True)
        dns_rt_strict_scope.insert("example.com")
        assert dns_rt_strict_scope.search("example.com") == "example.com"
        assert dns_rt_strict_scope.search("com") is None
        assert dns_rt_strict_scope.search("www.example.com") is None
        assert dns_rt_strict_scope.search("nonexistent.com") is None
        assert dns_rt_strict_scope.search("test.www.example.com", raise_error=False) is None
        with pytest.raises(KeyError):
            dns_rt_strict_scope.search("test.www.example.com", raise_error=True)

        # Tests for raise_error parameter
        dns_rt = DNSRadixTree()
        dns_rt.insert("example.com")
        assert dns_rt.search("example.com") == "example.com"
        assert dns_rt.search("nonexistent.com") is None
        assert dns_rt.search("nonexistent.com", raise_error=False) is None
        with pytest.raises(KeyError):
            dns_rt.search("nonexistent.com", raise_error=True)
        ip_rt = IPRadixTree()
        ip_rt.insert("192.168.0.0/16")
        assert ip_rt.search("192.168.1.1") == ipaddress.ip_network("192.168.0.0/16")
        assert ip_rt.search("10.0.0.1") is None
        assert ip_rt.search("10.0.0.1", raise_error=False) is None
        with pytest.raises(KeyError):
            ip_rt.search("10.0.0.1", raise_error=True)

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
        log.critical(f"{iterations:,} iterations in {elapsed:.4f} seconds ({int(iterations/elapsed)}/s)")

        # make sure child subnets/IPs don't get added to whitelist/blacklist
        target = RadixTarget("1.2.3.4/24", "1.2.3.4/28", acl_mode=True)
        assert sorted([str(h) for h in target.hosts]) == ["1.2.3.0/24"]
        target = RadixTarget("1.2.3.4/28", "1.2.3.4/24", acl_mode=True)
        assert sorted([str(h) for h in target.hosts]) == ["1.2.3.0/24"]
        target = RadixTarget("1.2.3.4/28", "1.2.3.4", acl_mode=True)
        assert sorted([str(h) for h in target.hosts]) == ["1.2.3.0/28"]
        target = RadixTarget("1.2.3.4", "1.2.3.4/28", acl_mode=True)
        assert sorted([str(h) for h in target.hosts]) == ["1.2.3.0/28"]

        # same but for domains
        target = RadixTarget("evilcorp.com", "www.evilcorp.com", acl_mode=True)
        assert sorted([str(h) for h in target.hosts]) == ["evilcorp.com"]
        target = RadixTarget("www.evilcorp.com", "evilcorp.com", acl_mode=True)
        assert sorted([str(h) for h in target.hosts]) == ["evilcorp.com"]

        # make sure strict_scope doesn't mess us up
        target = RadixTarget("evilcorp.co.uk", "www.evilcorp.co.uk", acl_mode=True, strict_dns_scope=True)
        assert sorted([str(h) for h in target.hosts]) == [
            "evilcorp.co.uk",
            "www.evilcorp.co.uk",
        ]
        assert "evilcorp.co.uk" in target
        assert "www.evilcorp.co.uk" in target
        assert not "api.evilcorp.co.uk" in target
        assert not "api.www.evilcorp.co.uk" in target

        # test with invalid inputs
        with pytest.raises(ValueError, match=".*Invalid host: 'http://example.com'.*"):
            target = RadixTarget("http://example.com")
        target = RadixTarget("example.com")
        with pytest.raises(ValueError, match=".*Invalid host: 'evilcorp.com:80'.*"):
            target.get("evilcorp.com:80")
        with pytest.raises(ValueError, match=".*Invalid host: 'www.evilcorp.com:80'.*"):
            target.add("www.evilcorp.com:80")
        with pytest.raises(ValueError, match=".*Invalid host: 'evilcorp.com:80'.*"):
            "evilcorp.com:80" in target

    # push that coverage
    target = RadixTarget()
    target.put("1.2.3.254/32")
    target.put("1.2.3.255/32")
    target.delete_node("1.2.3.255/32")
    with pytest.raises(KeyError):
        target.delete_node("1.2.3.255/32")
    
    target = RadixTarget()
    target.put("0.0.0.0/0")
    target.put('0.0.0.1/32')
    target.delete_node('0.0.0.0/0')
    assert target.get('0.0.0.1/32') == ipaddress.ip_network('0.0.0.1/32')
    assert target.get_data('0.0.0.1/32') == ipaddress.ip_network('0.0.0.1/32')

    target = RadixTarget()
    target.insert("www.example.com", "val1")
    with pytest.raises(KeyError):
        target.delete_node("www.evilcorp.com")
    assert target.dns_tree.get("www.example.com") == "val1"
    assert target.dns_tree.get_host("www.example.com") == "www.example.com"
    target.delete_node("www.example.com")



def test_ipv4_ipv6_same_bits():
    # ipv4 and ipv6 host with same bits
    bits_ipv4 = list(network_to_bits(ipaddress.ip_network("1.0.0.0/30")))
    assert bits_ipv4 == [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    bits_ipv6 = list(network_to_bits(ipaddress.ip_network("100::/30")))
    assert bits_ipv6 == [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    target = RadixTarget()
    target.insert("1.0.0.0/30", "val1")
    target.insert("100::/30", "val2")
    assert target.search("1.0.0.1") == "val1"
    assert target.search("100::1") == "val2"

    target = RadixTarget()
    target.insert("0.0.0.0/0", "val1")
    target.insert("::/0", "val2")
    target.insert("1.2.3.4/32", "val3")
    target.insert("dead::beef/128", "val4")
    assert target.search("0.0.0.0") == "val1"
    assert target.search("::") == "val2"
    assert target.search("1.2.3.4") == "val3"
    assert target.search("dead::beef") == "val4"
    target.delete_node("0.0.0.0/0")
    with pytest.raises(KeyError):
        target.search("0.0.0.0", raise_error=True)
    assert target.search("::") == "val2"
    assert target.search("1.2.3.4") == "val3"
    assert target.search("dead::beef") == "val4"
    target.delete_node("::/0")
    with pytest.raises(KeyError):
        target.search("::", raise_error=True)
    assert target.search("1.2.3.4") == "val3"
    assert target.search("dead::beef") == "val4"
    with pytest.raises(ValueError):
        target.delete_node(" asdf")


def test_prune():
    # ip pruning
    target = RadixTarget()
    target.insert("192.168.0.0/24")
    target.insert("192.168.0.0/30")
    assert (
        "".join([str(b) for b in network_to_bits(ipaddress.ip_network("192.168.0.0/30"))])
        == "110000001010100000000000000000"
    )
    node = target.ipv4_tree.root
    slash_thirty_bits = list(network_to_bits(ipaddress.ip_network("192.168.0.0/30")))
    for bit in slash_thirty_bits[:-1]:
        node = node.children[bit]
    assert len(node.children) == 1
    assert node.children[slash_thirty_bits[-1]].host == ipaddress.ip_network("192.168.0.0/30")
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/30")
    node.children.clear()
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/24")
    assert target.prune() == 5
    assert target.prune() == 0

    # dns pruning
    target = RadixTarget()
    target.insert("example.com")
    target.insert("api.test.www.example.com")
    node = target.dns_tree.root
    for segment in ("com", "example", "www", "test"):
        node = node.children[segment]
    assert len(node.children) == 1
    assert list(node.children) == ["api"]
    assert node.children["api"].host == "api.test.www.example.com"
    assert node.children["api"].data == "api.test.www.example.com"
    assert target.get("wat.hm.api.test.www.example.com") == "api.test.www.example.com"
    node.children.clear()
    assert target.get("wat.hm.api.test.www.example.com") == "example.com"
    assert target.prune() == 2
    assert target.prune() == 0


def test_delete_node():
    # delete IPs
    target = RadixTarget()
    target.insert("192.168.0.0/24")
    target.insert("192.168.0.0/26")
    target.insert("192.168.0.0/28")
    target.insert("192.168.0.0/30")
    with pytest.raises(KeyError):
        target.delete_node("192.168.1.1")
    with pytest.raises(KeyError):
        target.delete_node("192.168.0.0/31")
    with pytest.raises(KeyError):
        target.delete_node("192.168.0.0/25")
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/30")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/26"),
        ipaddress.ip_network("192.168.0.0/28"),
        ipaddress.ip_network("192.168.0.0/30"),
    }
    target.delete_node("192.168.0.0/28")
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/30")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/26"),
        ipaddress.ip_network("192.168.0.0/30"),
    }
    assert {n.host for n in target.all_nodes} == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/26"),
        ipaddress.ip_network("192.168.0.0/30"),
    }
    target.delete_node("192.168.0.0/30")
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/26")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/26"),
    }
    assert {n.host for n in target.all_nodes} == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/26"),
    }

    # delete DNS
    target = RadixTarget()
    target.insert("example.com")
    target.insert("www.example.com")
    target.insert("test.www.example.com")
    target.insert("api.test.www.example.com")
    with pytest.raises(KeyError):
        target.delete_node("asdf.api.test.www.example.com")
    with pytest.raises(KeyError):
        target.delete_node("com")
    assert target.get("asdf.api.test.www.example.com") == "api.test.www.example.com"
    assert target.hosts == {
        "example.com",
        "www.example.com",
        "test.www.example.com",
        "api.test.www.example.com",
    }
    assert {n.host for n in target.all_nodes} == {
        "example.com",
        "www.example.com",
        "test.www.example.com",
        "api.test.www.example.com",
    }
    target.delete_node("test.www.example.com")
    assert target.get("asdf.api.test.www.example.com") == "api.test.www.example.com"
    assert target.hosts == {
        "example.com",
        "www.example.com",
        "api.test.www.example.com",
    }
    assert {n.host for n in target.all_nodes} == {
        "example.com",
        "www.example.com",
        "api.test.www.example.com",
    }


def test_merge_subnets():
    # test mergeable helper
    subnet1 = ipaddress.ip_network("192.168.0.0/25")
    subnet2 = ipaddress.ip_network("192.168.0.128/25")
    assert merge_subnets(subnet1, subnet2) == ipaddress.ip_network("192.168.0.0/24")
    assert merge_subnets(subnet2, subnet1) == ipaddress.ip_network("192.168.0.0/24")
    subnet3 = ipaddress.ip_network("192.168.0.0/26")
    subnet4 = ipaddress.ip_network("192.168.0.0/24")
    with pytest.raises(ValueError):
        merge_subnets(subnet3, subnet4)
    with pytest.raises(ValueError):
        merge_subnets(subnet4, subnet3)
    with pytest.raises(ValueError):
        merge_subnets(subnet1, subnet3)
    with pytest.raises(ValueError):
        merge_subnets(subnet3, subnet1)
    with pytest.raises(ValueError):
        merge_subnets(subnet1, subnet4)
    with pytest.raises(ValueError):
        merge_subnets(subnet4, subnet1)
    ipv4 = ipaddress.ip_network("192.168.0.0/24")
    ipv6 = ipaddress.ip_network("2607:f0d0:1002:0064::/64")
    with pytest.raises(ValueError):
        merge_subnets(ipv4, ipv6)
    with pytest.raises(ValueError):
        merge_subnets(ipv6, ipv4)

    subnet1 = ipaddress.ip_network("192.168.0.0/26")
    subnet2 = ipaddress.ip_network("192.168.0.64/26")
    subnet3 = ipaddress.ip_network("192.168.0.128/26")
    subnet4 = ipaddress.ip_network("192.168.0.192/26")

    assert merge_subnets(subnet1, subnet2) == ipaddress.ip_network("192.168.0.0/25")
    assert merge_subnets(subnet2, subnet1) == ipaddress.ip_network("192.168.0.0/25")
    assert merge_subnets(subnet3, subnet4) == ipaddress.ip_network("192.168.0.128/25")
    assert merge_subnets(subnet4, subnet3) == ipaddress.ip_network("192.168.0.128/25")
    with pytest.raises(ValueError):
        merge_subnets(subnet2, subnet3)
    with pytest.raises(ValueError):
        merge_subnets(subnet3, subnet2)
    with pytest.raises(ValueError):
        merge_subnets(subnet1, subnet3)
    with pytest.raises(ValueError):
        merge_subnets(subnet3, subnet1)
    with pytest.raises(ValueError):
        merge_subnets(subnet1, subnet4)
    with pytest.raises(ValueError):
        merge_subnets(subnet4, subnet1)


def test_defrag():
    # basic duplicate removal
    target = RadixTarget()
    target.insert("192.168.0.0/28")
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/28")
    assert target.hosts == {ipaddress.ip_network("192.168.0.0/28")}
    target.insert("192.168.0.0/30")
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/30")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/28"),
        ipaddress.ip_network("192.168.0.0/30"),
    }
    cleaned_hosts, new_hosts = target.defrag()
    assert new_hosts == set()
    assert cleaned_hosts == {ipaddress.ip_network("192.168.0.0/30")}
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/28")
    assert target.hosts == {ipaddress.ip_network("192.168.0.0/28")}

    # basic duplicate removal with custom data
    target = RadixTarget()
    target.insert("192.168.0.0/28", "val1")
    assert target.get("192.168.0.0") == "val1"
    assert target.hosts == {ipaddress.ip_network("192.168.0.0/28")}
    target.insert("192.168.0.0/30", "val1")
    assert target.get("192.168.0.0") == "val1"
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/28"),
        ipaddress.ip_network("192.168.0.0/30"),
    }
    cleaned_hosts, new_hosts = target.defrag()
    assert new_hosts == set()
    assert cleaned_hosts == {ipaddress.ip_network("192.168.0.0/30")}
    assert target.get("192.168.0.0") == "val1"
    assert target.hosts == {ipaddress.ip_network("192.168.0.0/28")}

    # basic duplicate removal with different custom data
    target = RadixTarget()
    target.insert("192.168.0.0/28", "val1")
    assert target.get("192.168.0.0") == "val1"
    assert target.hosts == {ipaddress.ip_network("192.168.0.0/28")}
    target.insert("192.168.0.0/30", "val2")
    assert target.get("192.168.0.0") == "val2"
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/28"),
        ipaddress.ip_network("192.168.0.0/30"),
    }
    cleaned_hosts, new_hosts = target.defrag()
    assert new_hosts == set()
    assert cleaned_hosts == set()
    assert target.get("192.168.0.0") == "val2"
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/28"),
        ipaddress.ip_network("192.168.0.0/30"),
    }

    # multiple nested duplicates
    target = RadixTarget()
    target.insert("192.168.0.0/24", "val1")
    target.insert("192.168.0.0/26", "val1")
    target.insert("192.168.0.0/28", "val1")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/26"),
        ipaddress.ip_network("192.168.0.0/28"),
    }
    assert target.get("192.168.0.0") == "val1"
    assert target.get_host("192.168.0.0") == ipaddress.ip_network("192.168.0.0/28")
    cleaned_hosts, new_hosts = target.defrag()
    assert cleaned_hosts == {
        ipaddress.ip_network("192.168.0.0/26"),
        ipaddress.ip_network("192.168.0.0/28"),
    }
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
    }
    assert target.get("192.168.0.0") == "val1"
    assert target.get_host("192.168.0.0") == ipaddress.ip_network("192.168.0.0/24")

    # Two mergeable subnets
    target = RadixTarget()
    target.insert("192.168.0.0/25")
    target.insert("192.168.0.128/25")
    target.insert("www.evilcorp.com")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/25"),
        ipaddress.ip_network("192.168.0.128/25"),
        "www.evilcorp.com",
    }
    assert target.all_nodes == [
        target.get_node("192.168.0.0"),
        target.get_node("192.168.0.128"),
        target.get_node("test.www.evilcorp.com"),
    ]
    assert target.nodes_by_host == {
        ipaddress.ip_network("192.168.0.0/25"): target.get_node("192.168.0.0"),
        ipaddress.ip_network("192.168.0.128/25"): target.get_node("192.168.0.128"),
        "www.evilcorp.com": target.get_node("test.www.evilcorp.com"),
    }
    cleaned_hosts, new_hosts = target.defrag()
    assert cleaned_hosts == {
        ipaddress.ip_network("192.168.0.0/25"),
        ipaddress.ip_network("192.168.0.128/25"),
    }
    assert new_hosts == {ipaddress.ip_network("192.168.0.0/24")}
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
        "www.evilcorp.com",
    }
    assert target.get("192.168.0.0") == ipaddress.ip_network("192.168.0.0/24")

    # these nodes should not be merged because they have different data
    target = RadixTarget()
    target.insert("192.168.0.0/25", "val1")
    target.insert("192.168.0.128/25", "val2")
    cleaned_hosts, new_hosts = target.defrag()
    assert cleaned_hosts == set()
    assert new_hosts == set()
    assert target.get("192.168.0.0") == "val1"
    assert target.get("192.168.0.128") == "val2"

    # recursive defrag
    target = RadixTarget()
    target.insert("192.168.0.0/25")
    target.insert("192.168.0.128/27")
    target.insert("192.168.0.160/27")
    target.insert("192.168.0.192/27")
    target.insert("192.168.0.224/28")
    target.insert("192.168.0.240/29")
    target.insert("192.168.0.248/30")
    target.insert("192.168.0.252/31")
    target.insert("192.168.0.254")
    target.insert("192.168.0.255")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/25"),
        ipaddress.ip_network("192.168.0.128/27"),
        ipaddress.ip_network("192.168.0.160/27"),
        ipaddress.ip_network("192.168.0.192/27"),
        ipaddress.ip_network("192.168.0.224/28"),
        ipaddress.ip_network("192.168.0.240/29"),
        ipaddress.ip_network("192.168.0.248/30"),
        ipaddress.ip_network("192.168.0.252/31"),
        ipaddress.ip_network("192.168.0.254/32"),
        ipaddress.ip_network("192.168.0.255/32"),
    }
    cleaned_hosts, new_hosts = target.defrag()
    assert cleaned_hosts == {
        ipaddress.ip_network("192.168.0.0/25"),
        ipaddress.ip_network("192.168.0.128/27"),
        ipaddress.ip_network("192.168.0.160/27"),
        ipaddress.ip_network("192.168.0.192/27"),
        ipaddress.ip_network("192.168.0.224/28"),
        ipaddress.ip_network("192.168.0.240/29"),
        ipaddress.ip_network("192.168.0.248/30"),
        ipaddress.ip_network("192.168.0.252/31"),
        ipaddress.ip_network("192.168.0.254/32"),
        ipaddress.ip_network("192.168.0.255/32"),
    }
    assert new_hosts == {ipaddress.ip_network("192.168.0.0/24")}
    assert target.get("192.168.0.255") == ipaddress.ip_network("192.168.0.0/24")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
    }

    # same test but for IPv6
    target = RadixTarget()
    target.insert("dead:beef::/121")
    target.insert("dead:beef::80/123")
    target.insert("dead:beef::a0/123")
    target.insert("dead:beef::c0/123")
    target.insert("dead:beef::e0/124")
    target.insert("dead:beef::f0/125")
    target.insert("dead:beef::f8/126")
    target.insert("dead:beef::fc/127")
    target.insert("dead:beef::fe")
    target.insert("dead:beef::ff")
    assert target.hosts == {
        ipaddress.ip_network("dead:beef::/121"),
        ipaddress.ip_network("dead:beef::80/123"),
        ipaddress.ip_network("dead:beef::a0/123"),
        ipaddress.ip_network("dead:beef::c0/123"),
        ipaddress.ip_network("dead:beef::e0/124"),
        ipaddress.ip_network("dead:beef::f0/125"),
        ipaddress.ip_network("dead:beef::f8/126"),
        ipaddress.ip_network("dead:beef::fc/127"),
        ipaddress.ip_network("dead:beef::fe/128"),
        ipaddress.ip_network("dead:beef::ff/128"),
    }
    cleaned_hosts, new_hosts = target.defrag()
    assert cleaned_hosts == {
        ipaddress.ip_network("dead:beef::/121"),
        ipaddress.ip_network("dead:beef::80/123"),
        ipaddress.ip_network("dead:beef::a0/123"),
        ipaddress.ip_network("dead:beef::c0/123"),
        ipaddress.ip_network("dead:beef::e0/124"),
        ipaddress.ip_network("dead:beef::f0/125"),
        ipaddress.ip_network("dead:beef::f8/126"),
        ipaddress.ip_network("dead:beef::fc/127"),
        ipaddress.ip_network("dead:beef::fe/128"),
        ipaddress.ip_network("dead:beef::ff/128"),
    }
    assert new_hosts == {ipaddress.ip_network("dead:beef::/120")}
    assert target.get("dead:beef::ff") == ipaddress.ip_network("dead:beef::/120")
    assert target.hosts == {
        ipaddress.ip_network("dead:beef::/120"),
    }

    # existing parent node with unique data (should prevent defrag)
    target = RadixTarget()
    target.insert("192.168.0.0/24", "val1")
    target.insert("192.168.0.0/25", "val2")
    target.insert("192.168.0.128/25", "val2")
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/25"),
        ipaddress.ip_network("192.168.0.128/25"),
    }
    cleaned_hosts, new_hosts = target.defrag()
    assert cleaned_hosts == set()
    assert new_hosts == set()
    assert target.hosts == {
        ipaddress.ip_network("192.168.0.0/24"),
        ipaddress.ip_network("192.168.0.0/25"),
        ipaddress.ip_network("192.168.0.128/25"),
    }
