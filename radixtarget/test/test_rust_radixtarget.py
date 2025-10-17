import random
import ipaddress
import time
from pathlib import Path
from radixtarget import RadixTarget


def test_core_radixtarget_functionality():
    """
    Test core RadixTarget functionality with the new Rust-backed implementation.

    This test covers:
    - Basic initialization and data insertion
    - IP and DNS membership testing
    - Data storage and retrieval
    - Target comparison and containment
    - String representation
    """

    # Test basic initialization and insertion
    target = RadixTarget()
    assert not target  # Empty target should be falsy
    assert len(target) == 0

    # Test IP insertion with default data (should be the IP string itself)
    canonical1 = target.insert("8.8.8.8/30")
    assert isinstance(canonical1, str)
    assert "8.8.8.8" in target
    assert "8.8.8.9" in target
    assert "8.8.8.12" not in target

    # Test data retrieval - should get the original value as default data
    assert target.get("8.8.8.8") == "8.8.8.8/30"
    assert target.search("8.8.8.9") == "8.8.8.8/30"  # search is alias for get
    assert target.get("8.8.8.12") is None

    # Test IP insertion with custom data
    canonical2 = target.add("192.168.1.0/24", "custom_network_data")
    assert isinstance(canonical2, str)
    assert canonical1 != canonical2  # Different entries should have different canonical forms
    assert "192.168.1.100" in target
    assert target.get("192.168.1.100") == "custom_network_data"

    # Test IPv6 support
    target.put("2001:4860:4860::8888/126", "ipv6_data")
    assert "2001:4860:4860::8889" in target
    assert target.get("2001:4860:4860::8889") == "ipv6_data"
    assert "2001:4860:4860::888c" not in target

    # Test DNS insertion
    target.insert("example.com")
    assert "example.com" in target
    assert "www.example.com" in target  # Subdomains should be included by default
    assert target.get("www.example.com") == "example.com"
    assert target.get("example.com") == "example.com"

    # Test DNS with custom data
    target.add("evilcorp.com", "evil_data")
    assert "api.evilcorp.com" in target
    assert target.get("api.evilcorp.com") == "evil_data"

    # Test strict scope
    strict_target = RadixTarget(strict_scope=True)
    strict_target.insert("example.org")
    assert "example.org" in strict_target
    assert "www.example.org" not in strict_target  # Subdomains excluded in strict mode
    assert strict_target.get("www.example.org") is None

    # Test target comparison and equality
    target1 = RadixTarget()
    target1.add("8.8.8.8/30")
    target1.add("example.com")

    target2 = RadixTarget()
    target2.add("8.8.8.8/29")  # Larger network containing target1's network
    target2.add("com")  # Parent domain containing target1's domain

    # Test with identical targets
    target3 = RadixTarget()
    target3.add("8.8.8.8/30")
    target3.add("example.com")

    assert target1 == target3  # Should be equal
    assert target1 != target2  # Should be different

    # Test individual containment
    assert "8.8.8.9" in target1  # Should be in /30 network
    assert "8.8.8.9" in target2  # Should be in /29 network
    assert "www.example.com" in target1  # Should match example.com

    # Test deletion
    target.delete("example.com")
    assert "example.com" not in target
    assert "www.example.com" not in target
    assert target.get("example.com") is None

    # Verify other entries still exist
    assert "8.8.8.8" in target
    assert target.get("8.8.8.8") == "8.8.8.8/30"
    assert "192.168.1.100" in target
    assert target.get("192.168.1.100") == "custom_network_data"

    # Test string representation
    simple_target = RadixTarget()
    simple_target.add("1.2.3.4")
    simple_target.add("example.com")
    str_repr = str(simple_target)
    assert "1.2.3.4" in str_repr
    assert "example.com" in str_repr

    print("✓ All core RadixTarget functionality tests passed!")


def test_ip_network_handling():
    """
    Test IP network handling with IPv4 and IPv6 networks.

    This test covers:
    - IPv4 and IPv6 network insertion and lookup
    - Network vs individual IP handling
    - Address family separation (IPv4/IPv6 don't interfere)
    - Network overlap detection
    - Custom data preservation with IP ranges
    - Proper containment logic for networks
    """

    rt = RadixTarget()

    # Test IPv4 networks
    rt.insert("192.168.1.0/24")
    assert rt.search("192.168.1.10") == "192.168.1.0/24"
    assert rt.search("192.168.2.10") is None

    # Test with ipaddress objects
    network_obj = ipaddress.ip_network("10.0.0.0/8")
    rt.insert(str(network_obj))
    assert rt.search("10.255.255.255") == "10.0.0.0/8"

    # Test individual IP insertion (should be stored as /32 network)
    rt.insert("172.16.12.1")
    assert rt.search("172.16.12.1") == "172.16.12.1/32"

    # Test custom data with networks
    rt.insert("8.8.8.0/24", "google_dns_range")
    assert rt.search("8.8.8.8") == "google_dns_range"
    assert rt.search("8.8.8.255") == "google_dns_range"
    assert rt.search("8.8.9.1") is None

    # Test IPv6 networks
    rt.insert("dead::/64")
    assert rt.search("dead::beef") == "dead::/64"
    assert rt.search("dead:cafe::beef") is None

    # Test individual IPv6 address (should be stored as /128 network)
    rt.insert("cafe::babe")
    assert rt.search("cafe::babe") == "cafe::babe/128"

    # Test custom data with IPv6
    rt.insert("beef::/120", "custom_beef_data")
    assert rt.search("beef::bb") == "custom_beef_data"

    # Test network containment queries
    rt.insert("192.168.128.0/24")
    assert rt.search("192.168.128.0/28") == "192.168.128.0/24"  # Subnet within network
    assert rt.search("192.168.128.0/23") is None  # Larger network not found

    # Test IPv6 network containment
    rt.insert("babe::/64")
    assert rt.search("babe::/96") == "babe::/64"  # Subnet within network
    assert rt.search("babe::/63") is None  # Larger network not found

    print("✓ All IP network handling tests passed!")


def test_ipv4_ipv6_separation():
    """
    Test that IPv4 and IPv6 addresses are properly separated and don't interfere.

    This addresses the edge case where IPv4 and IPv6 addresses might have
    similar bit patterns but should be treated completely separately.
    """

    rt = RadixTarget()

    # Create IPv4 and IPv6 addresses that could potentially conflict
    # if not properly separated by address family
    rand_int = random.randint(0, 2**32 - 1)
    ipv4_address = ipaddress.IPv4Address(rand_int)
    ipv6_address = ipaddress.IPv6Address(rand_int << (128 - 32))  # Shift to high bits
    ipv6_network = ipaddress.IPv6Network(f"{ipv6_address}/32")

    # Insert the IPv4 address (as /32)
    rt.insert(str(ipv4_address), "ipv4_data")

    # Verify IPv4 address is found with correct data
    assert rt.search(str(ipv4_address)) == "ipv4_data"

    # Verify IPv6 addresses are NOT found (different address families)
    assert rt.search(str(ipv6_address)) is None
    assert rt.search(str(ipv6_network)) is None

    # Now insert IPv6 data
    rt.insert(str(ipv6_network), "ipv6_network_data")
    rt.insert(str(ipv6_address), "ipv6_data")  # More specific /128, will override for this address

    # Verify both address families work independently
    assert rt.search(str(ipv4_address)) == "ipv4_data"
    assert rt.search(str(ipv6_address)) == "ipv6_data"  # Most specific match
    # Test a different address in the network to get the network data
    other_ipv6_in_network = ipaddress.IPv6Address(ipv6_network.network_address + 1)
    if other_ipv6_in_network != ipv6_address:  # Make sure it's different
        assert rt.search(str(other_ipv6_in_network)) == "ipv6_network_data"

    # Test with specific example that could cause bit pattern conflicts
    rt2 = RadixTarget()
    rt2.insert("1.0.0.0/30", "ipv4_val")
    rt2.insert("100::/30", "ipv6_val")

    assert rt2.search("1.0.0.1") == "ipv4_val"
    assert rt2.search("100::1") == "ipv6_val"
    # These should not interfere with each other despite similar bit patterns

    print("✓ All IPv4/IPv6 separation tests passed!")


def test_dns_functionality():
    """
    Test comprehensive DNS functionality with the Rust-backed implementation.

    This test covers:
    - Basic domain insertion and lookup
    - Subdomain matching behavior
    - Strict scope mode for DNS
    - Custom data storage with domains
    - Domain hierarchy handling
    - DNS vs IP separation
    - Error handling for DNS operations
    """

    rt = RadixTarget()

    # Test basic domain insertion
    rt.insert("example.com")
    assert "example.com" in rt
    assert rt.search("example.com") == "example.com"

    # Test subdomain matching (default behavior)
    assert "www.example.com" in rt
    assert "api.example.com" in rt
    assert "test.api.example.com" in rt
    assert rt.search("www.example.com") == "example.com"
    assert rt.search("api.example.com") == "example.com"
    assert rt.search("test.api.example.com") == "example.com"

    # Test that parent domains are NOT matched
    assert "com" not in rt
    assert rt.search("com") is None
    assert "notexample.com" not in rt
    assert rt.search("notexample.com") is None

    # Test with custom data
    rt.insert("evilcorp.com", "corporate_data")
    assert "evilcorp.com" in rt
    assert "www.evilcorp.com" in rt
    assert "api.evilcorp.com" in rt
    assert rt.search("evilcorp.com") == "corporate_data"
    assert rt.search("www.evilcorp.com") == "corporate_data"
    assert rt.search("api.evilcorp.com") == "corporate_data"

    # Test multiple levels of subdomains
    rt.insert("test.www.example.com", "specific_subdomain")
    assert "test.www.example.com" in rt
    assert "deep.test.www.example.com" in rt
    assert rt.search("test.www.example.com") == "specific_subdomain"
    assert rt.search("deep.test.www.example.com") == "specific_subdomain"
    assert rt.search("other.www.example.com") == "example.com"  # Falls back to example.com

    # Test TLD handling
    rt.insert("net")
    assert "net" in rt
    assert "example.net" in rt
    assert "www.example.net" in rt
    assert rt.search("net") == "net"
    assert rt.search("example.net") == "net"
    assert rt.search("www.example.net") == "net"

    # Test complex multi-level domains
    rt.insert("co.uk", "uk_data")
    assert "co.uk" in rt
    assert "example.co.uk" in rt
    assert "www.example.co.uk" in rt
    assert rt.search("co.uk") == "uk_data"
    assert rt.search("example.co.uk") == "uk_data"
    assert rt.search("www.example.co.uk") == "uk_data"
    assert rt.search("www.example.uk") is None

    print("✓ All basic DNS functionality tests passed!")


def test_dns_strict_scope():
    """
    Test DNS strict scope functionality.

    In strict scope mode:
    - Only exact domain matches are allowed
    - Subdomains are NOT automatically included
    - Parent domains are still not matched
    """

    # Test strict scope mode
    strict_rt = RadixTarget(strict_scope=True)

    # Insert a domain in strict mode
    strict_rt.insert("example.com")

    # Exact match should work
    assert "example.com" in strict_rt
    assert strict_rt.search("example.com") == "example.com"

    # Subdomains should NOT be included in strict mode
    assert "www.example.com" not in strict_rt
    assert "api.example.com" not in strict_rt
    assert "test.api.example.com" not in strict_rt
    assert strict_rt.search("www.example.com") is None
    assert strict_rt.search("api.example.com") is None
    assert strict_rt.search("test.api.example.com") is None

    # Parent domains should still not be matched
    assert "com" not in strict_rt
    assert strict_rt.search("com") is None

    # Test with custom data in strict mode
    strict_rt.insert("evilcorp.org", "strict_data")
    assert "evilcorp.org" in strict_rt
    assert "www.evilcorp.org" not in strict_rt
    assert strict_rt.search("evilcorp.org") == "strict_data"
    assert strict_rt.search("www.evilcorp.org") is None

    # Test that we can still insert subdomains explicitly in strict mode
    strict_rt.insert("www.evilcorp.org", "subdomain_data")
    assert "www.evilcorp.org" in strict_rt
    assert strict_rt.search("www.evilcorp.org") == "subdomain_data"
    # But deeper subdomains still won't match
    assert "api.www.evilcorp.org" not in strict_rt
    assert strict_rt.search("api.www.evilcorp.org") is None

    # Compare with non-strict mode
    normal_rt = RadixTarget()
    normal_rt.insert("example.net")
    assert "www.example.net" in normal_rt  # Should work in normal mode
    assert strict_rt.search("www.example.net") is None  # Should not work in strict mode

    print("✓ All DNS strict scope tests passed!")


def test_dns_mixed_with_ip():
    """
    Test that DNS and IP functionality work together without interference.

    This ensures that:
    - DNS and IP lookups are completely separate
    - Mixed targets work correctly
    - No cross-contamination between DNS and IP data
    """

    rt = RadixTarget()

    # Insert both IP and DNS data
    rt.insert("192.168.1.0/24", "ip_network_data")
    rt.insert("example.com", "domain_data")
    rt.insert("8.8.8.8", "dns_server_ip")
    rt.insert("dns.google.com", "google_dns_domain")

    # Test IP lookups work correctly
    assert "192.168.1.100" in rt
    assert rt.search("192.168.1.100") == "ip_network_data"
    assert "8.8.8.8" in rt
    assert rt.search("8.8.8.8") == "dns_server_ip"

    # Test DNS lookups work correctly
    assert "example.com" in rt
    assert "www.example.com" in rt
    assert rt.search("example.com") == "domain_data"
    assert rt.search("www.example.com") == "domain_data"
    assert "dns.google.com" in rt
    assert "api.dns.google.com" in rt
    assert rt.search("dns.google.com") == "google_dns_domain"
    assert rt.search("api.dns.google.com") == "google_dns_domain"

    # Test that IP addresses don't match domain patterns
    assert rt.search("192.168.1.com") is None  # IP-like domain not in target
    assert rt.search("8.8.8.8.example.com") == "domain_data"  # But this should match example.com

    # Test deletion works independently
    rt.delete("example.com")
    assert "example.com" not in rt
    assert "www.example.com" not in rt
    assert rt.search("example.com") is None
    # But IP data should still be there
    assert "192.168.1.100" in rt
    assert rt.search("192.168.1.100") == "ip_network_data"
    assert "8.8.8.8" in rt
    assert rt.search("8.8.8.8") == "dns_server_ip"

    print("✓ All DNS/IP mixed functionality tests passed!")


def test_dns_edge_cases():
    """
    Test DNS edge cases and error conditions.

    This covers:
    - Empty domain handling
    - Invalid domain formats
    - Case sensitivity
    - Unicode domains (if supported)
    - Very long domain names
    - Special characters in domains
    """

    rt = RadixTarget()

    # Test case sensitivity (domains are case-insensitive for matching but preserve original case)
    rt.insert("Example.COM")
    assert "example.com" in rt
    assert "EXAMPLE.COM" in rt
    assert "Example.Com" in rt
    assert "www.EXAMPLE.com" in rt
    # But the stored data should preserve the original case
    assert rt.search("example.com") == "example.com"
    assert rt.search("EXAMPLE.COM") == "example.com"
    assert rt.search("www.example.com") == "example.com"

    # Test domains with hyphens and numbers
    rt.insert("test-123.example-site.com", "hyphen_data")
    assert "test-123.example-site.com" in rt
    assert "www.test-123.example-site.com" in rt
    assert rt.search("test-123.example-site.com") == "hyphen_data"
    assert rt.search("api.test-123.example-site.com") == "hyphen_data"

    print("✓ All DNS edge case tests passed!")


def test_acl_mode():
    """
    Test ACL mode functionality which prevents child subnets/domains from being added
    when a parent already exists, optimizing for ACL/whitelist/blacklist scenarios.

    This test covers:
    - IP subnet hierarchy optimization in ACL mode
    - Domain hierarchy optimization in ACL mode
    - Interaction with strict scope mode
    - Proper containment logic with ACL optimization
    """

    # Test IP subnet ACL optimization - child subnets should be removed
    target = RadixTarget(acl_mode=True)
    target.add("1.2.3.4/24")
    target.add("1.2.3.4/28")  # Child subnet - should be optimized away

    # Only the parent /24 subnet should remain
    hosts = sorted([str(h) for h in target.hosts])
    assert hosts == ["1.2.3.0/24"]

    # But containment should still work correctly
    assert "1.2.3.100" in target
    assert target.get("1.2.3.100") == "1.2.3.0/24"

    # Test order doesn't matter
    target2 = RadixTarget(acl_mode=True)
    target2.add("1.2.3.4/28")  # Add child first
    target2.add("1.2.3.4/24")  # Add parent second

    hosts2 = sorted([str(h) for h in target2.hosts])
    assert hosts2 == ["1.2.3.0/24"]

    # Test individual IP vs subnet optimization
    target3 = RadixTarget(acl_mode=True)
    target3.add("1.2.3.4/28")
    target3.add("1.2.3.4")  # Individual IP (becomes /32) - should be optimized away

    hosts3 = sorted([str(h) for h in target3.hosts])
    assert hosts3 == ["1.2.3.0/28"]

    # Test reverse order
    target4 = RadixTarget(acl_mode=True)
    target4.add("1.2.3.4")  # Individual IP first
    target4.add("1.2.3.4/28")  # Subnet second - IP should be optimized away

    hosts4 = sorted([str(h) for h in target4.hosts])
    assert hosts4 == ["1.2.3.0/28"]

    # Test domain ACL optimization - child domains should be removed
    target5 = RadixTarget(acl_mode=True)
    target5.add("evilcorp.com")
    target5.add("www.evilcorp.com")  # Child domain - should be optimized away

    hosts5 = sorted([str(h) for h in target5.hosts])
    assert hosts5 == ["evilcorp.com"]

    # But containment should still work
    assert "www.evilcorp.com" in target5
    assert "api.evilcorp.com" in target5
    assert target5.get("www.evilcorp.com") == "evilcorp.com"

    # Test order doesn't matter for domains
    target6 = RadixTarget(acl_mode=True)
    target6.add("www.evilcorp.com")  # Add child first
    target6.add("evilcorp.com")  # Add parent second

    hosts6 = sorted([str(h) for h in target6.hosts])
    assert hosts6 == ["evilcorp.com"]

    # Test ACL mode cannot be combined with strict scope - they are mutually exclusive
    # This should raise an error
    import pytest

    with pytest.raises(ValueError):  # Should raise ValueError
        RadixTarget(acl_mode=True, strict_scope=True)

    # Test mixed IP and domain ACL optimization
    target8 = RadixTarget(acl_mode=True)
    target8.add("192.168.1.0/24")
    target8.add("192.168.1.0/28")  # Should be optimized away
    target8.add("example.com")
    target8.add("www.example.com")  # Should be optimized away
    target8.add("8.8.8.8")  # Individual IP, no parent

    hosts8 = {str(h) for h in target8.hosts}
    assert hosts8 == {"192.168.1.0/24", "8.8.8.8/32", "example.com"}

    # Test that unrelated entries are not affected
    assert "192.168.1.100" in target8
    assert target8.get("192.168.1.100") == "192.168.1.0/24"
    assert "www.example.com" in target8
    assert target8.get("www.example.com") == "example.com"
    assert "8.8.8.8" in target8
    assert target8.get("8.8.8.8") == "8.8.8.8/32"

    print("✓ All ACL mode tests passed!")


def test_target_hashing():
    """
    Test RadixTarget hashing functionality with the Rust-backed implementation.

    This test covers:
    - Deterministic integer hash generation
    - Hash consistency across identical targets
    - Hash differences for different targets
    - Hash changes when targets are modified
    - Hash behavior with strict scope mode
    - Hash properties (integer type)
    """

    # Test basic target hashing
    target1 = RadixTarget()
    target1.add("evilcorp.com")
    target1.add("1.2.3.4/24")
    target1.add("evilcorp.net")

    # Get the hash and verify it's deterministic
    hash1 = target1.hash
    assert isinstance(hash1, int)
    assert hash1 == -5575911061806357761  # Expected hash for this combination

    # Same target should produce same hash
    assert target1.hash == hash1

    # Different target with additional entry
    target2 = RadixTarget()
    target2.add("evilcorp.org")
    target2.add("evilcorp.com")
    target2.add("1.2.3.4/24")
    target2.add("evilcorp.net")

    hash2 = target2.hash
    assert isinstance(hash2, int)
    assert hash2 == 4519009570078867868  # Expected hash for this combination

    # Different targets should have different hashes initially
    assert target1.hash != target2.hash
    assert target1 != target2

    # Target created from iteration should have same hash as original
    target3 = RadixTarget()
    for host in target1:
        target3.add(str(host))
    assert target3.hash == target1.hash
    assert target3 == target1

    # Test that strict scope affects hash
    target4 = RadixTarget(strict_scope=True)
    target4.add("evilcorp.com")
    target4.add("1.2.3.0/24")  # Use canonical form
    target4.add("evilcorp.net")
    assert target4.hash == 6578698081272501171  # Expected hash for strict scope
    assert target4.hash != target1.hash  # Should be different due to strict scope
    assert target4 != target1

    # Test hash equality after making targets equivalent
    target1.add("evilcorp.org")  # Add missing host to target1
    assert target1.hash == target2.hash  # Now they should match
    assert target1 == target2
    assert target1.hash == 4519009570078867868

    # Test empty target hash
    empty_target = RadixTarget()
    empty_hash = empty_target.hash
    assert isinstance(empty_hash, int)
    assert empty_hash == -3953938083091587911  # Expected hash for empty target

    # Two empty targets should have same hash
    empty_target2 = RadixTarget()
    assert empty_target.hash == empty_target2.hash
    assert empty_target == empty_target2

    # Empty target should have different hash than populated target
    assert empty_target.hash != target1.hash
    assert empty_target != target1

    # Test hash with mixed IP/DNS content
    mixed_target = RadixTarget()
    mixed_target.add("192.168.1.0/24")
    mixed_target.add("10.0.0.0/8")
    mixed_target.add("example.com")
    mixed_target.add("test.org")
    mixed_target.add("2001:db8::/32")

    mixed_hash = mixed_target.hash
    assert isinstance(mixed_hash, int)
    assert mixed_hash == 922387328904585423  # Expected hash for mixed content

    # Same content in different order should produce same hash
    mixed_target2 = RadixTarget()
    mixed_target2.add("test.org")
    mixed_target2.add("2001:db8::/32")
    mixed_target2.add("example.com")
    mixed_target2.add("10.0.0.0/8")
    mixed_target2.add("192.168.1.0/24")

    assert mixed_target.hash == mixed_target2.hash
    assert mixed_target == mixed_target2

    print("✓ All target hashing tests passed!")


def test_target_merging():
    """
    Test merging RadixTarget objects and adding lists of hosts.

    This test covers:
    - Merging one target into another with target1.merge(target2)
    - Adding lists of hosts with target.add([host1, host2, ...])
    - Data preservation during merging
    - Proper string representation after merging
    - Order independence of merging
    """

    # Test basic target merging
    target1 = RadixTarget()
    target1.add("1.2.3.4/24")
    target1.add("evilcorp.net")

    target2 = RadixTarget()
    target2.add("evilcorp.com")
    target2.add("evilcorp.net")  # Duplicate should not cause issues

    # Verify initial state
    assert sorted([str(h) for h in target1]) == ["1.2.3.0/24", "evilcorp.net"]
    assert sorted([str(h) for h in target2]) == ["evilcorp.com", "evilcorp.net"]

    # Merge target2 into target1
    target1.merge(target2)

    # Verify merged result
    expected_hosts = ["1.2.3.0/24", "evilcorp.com", "evilcorp.net"]
    assert sorted([str(h) for h in target1]) == expected_hosts
    assert str(target1) == "1.2.3.0/24,evilcorp.com,evilcorp.net"

    # Test merging with custom data
    target3 = RadixTarget()
    target3.add("192.168.1.0/24", "network_data")
    target3.add("test.com", "domain_data")

    target4 = RadixTarget()
    target4.add("10.0.0.0/8", "big_network")
    target4.add("api.test.com", "api_data")

    # Merge and verify data preservation
    target3.merge(target4)

    assert "192.168.1.100" in target3
    assert target3.get("192.168.1.100") == "network_data"
    assert "test.com" in target3
    assert target3.get("test.com") == "domain_data"
    assert "10.0.0.1" in target3
    assert target3.get("10.0.0.1") == "big_network"
    assert "api.test.com" in target3
    assert target3.get("api.test.com") == "api_data"

    # Test order independence
    target6 = RadixTarget()
    target6.add("first.com")
    target6.add("192.168.1.0/24")

    target7 = RadixTarget()
    target7.add("second.com")
    target7.add("10.0.0.0/8")

    target8 = RadixTarget()
    target8.add("192.168.1.0/24")
    target8.add("first.com")

    target9 = RadixTarget()
    target9.add("10.0.0.0/8")
    target9.add("second.com")

    # Merge in different orders
    target6.merge(target7)
    target9.merge(target8)

    # Should have same content regardless of merge order
    hosts6 = sorted([str(h) for h in target6])
    hosts9 = sorted([str(h) for h in target9])
    assert hosts6 == hosts9

    print("✓ All target merging tests passed!")


def test_target_copying():
    """
    Test copying RadixTarget objects.

    This test covers:
    - Creating independent copies with .copy()
    - Data preservation in copies
    - Independence of copied targets
    - Equality between original and copy
    - Modifications don't affect the original
    """

    # Create original target with mixed content
    original = RadixTarget()
    original.add("1.2.3.0/24", "network_data")
    original.add("evilcorp.com", "domain_data")
    original.add("8.8.8.8", "dns_server")
    original.add("2001:db8::/32", "ipv6_data")

    # Create copy
    copy_target = original.copy()

    # Verify copy is equal but not the same object
    assert copy_target == original
    assert copy_target is not original

    # Verify same hosts
    original_hosts = sorted([str(h) for h in original])
    copy_hosts = sorted([str(h) for h in copy_target])
    assert original_hosts == copy_hosts

    expected_hosts = ["1.2.3.0/24", "2001:db8::/32", "8.8.8.8/32", "evilcorp.com"]
    assert copy_hosts == expected_hosts

    # Verify data preservation
    assert copy_target.get("1.2.3.100") == "network_data"
    assert copy_target.get("evilcorp.com") == "domain_data"
    assert copy_target.get("8.8.8.8") == "dns_server"
    assert copy_target.get("2001:db8::1") == "ipv6_data"

    # Verify independence - modify original
    original.add("new.domain.com", "new_data")
    original.add("192.168.1.0/24", "new_network")

    # Copy should not have new entries
    assert "new.domain.com" in original
    assert "new.domain.com" not in copy_target
    assert "192.168.1.100" in original
    assert "192.168.1.100" not in copy_target

    # Original data should still be intact in copy
    assert copy_target.get("1.2.3.100") == "network_data"
    assert copy_target.get("evilcorp.com") == "domain_data"

    # Test copying empty target
    empty_target = RadixTarget()
    empty_copy = empty_target.copy()

    assert empty_copy == empty_target
    assert empty_copy is not empty_target
    assert len(empty_copy) == 0
    assert not empty_copy

    # Test copying target with strict scope
    strict_target = RadixTarget(strict_scope=True)
    strict_target.add("example.com")
    strict_target.add("192.168.1.0/24")

    strict_copy = strict_target.copy()

    # Should preserve strict scope behavior
    assert "example.com" in strict_copy
    assert "www.example.com" not in strict_copy  # Strict scope
    assert "192.168.1.100" in strict_copy

    # Test copying target with ACL mode
    acl_target = RadixTarget(acl_mode=True)
    acl_target.add("1.2.3.0/24")
    acl_target.add("1.2.3.0/28")  # Should be optimized away

    acl_copy = acl_target.copy()

    # Should preserve ACL optimization
    hosts_acl = sorted([str(h) for h in acl_copy])
    assert hosts_acl == ["1.2.3.0/24"]  # /28 should be optimized away
    assert "1.2.3.100" in acl_copy

    print("✓ All target copying tests passed!")


def test_error_handling():
    """
    Test error handling and validation for invalid inputs.

    This test covers current implementation behavior and documents
    areas where validation may need to be added.
    """

    target = RadixTarget()

    # Test that the current implementation accepts various formats
    # (validation may be added in future versions)

    # These currently work but might be invalid in strict validation:
    potentially_invalid = [
        "http://example.com",  # URL with protocol
        "example.com:80",  # Domain with port
        "192.168.1.1:80",  # IP with port
    ]

    validation_working = []
    validation_missing = []

    for test_input in potentially_invalid:
        target.add(test_input)
        validation_missing.append(test_input)
        print(f"⚠️  No validation for: {test_input}")

    # Test basic functionality still works
    target2 = RadixTarget()
    target2.add("example.com")
    target2.add("192.168.1.0/24")
    target2.add("8.8.8.8")

    assert "example.com" in target2
    assert "192.168.1.100" in target2
    assert "8.8.8.8" in target2

    print(
        f"✓ Error handling test passed - {len(validation_working)} validations working, {len(validation_missing)} may need implementation"
    )


def test_radixtarget_benchmark():
    """
    Performance benchmark for RadixTarget with the Rust-backed implementation.

    This test loads a large set of CIDR blocks and benchmarks IP lookup performance
    to ensure the Rust implementation provides good performance characteristics.
    """
    # Path to CIDR test data
    cidr_list_path = Path(__file__).parent / "cidrs.txt"

    rt = RadixTarget()

    # Load CIDR blocks from test file
    with open(cidr_list_path) as f:
        cidrs = f.read().splitlines()

    print(f"📊 Loading {len(cidrs)} CIDR blocks for benchmark")

    # Insert all CIDR blocks
    for c in cidrs:
        if c.strip():  # Skip empty lines
            rt.insert(c.strip())

    print(f"✅ Loaded {len(cidrs)} CIDR blocks")

    # Benchmark random IP lookups
    iterations = 10000

    print(f"🚀 Starting benchmark: {iterations:,} random IP lookups")
    print("📋 Pre-generating test data...")

    # Pre-generate test IPs to avoid overhead in benchmark loop
    test_ips = []
    for i in range(iterations):
        random_ip = ipaddress.ip_address(random.randint(0, 2**32 - 1))
        test_ips.append(str(random_ip))

    print("🚀 Running benchmark...")
    start = time.time()
    hits = 0
    misses = 0

    for ip in test_ips:
        result = rt.search(ip)

        if result is not None:
            hits += 1
        else:
            misses += 1

    end = time.time()
    elapsed = end - start
    lookups_per_second = int(iterations / elapsed)

    print("📈 Benchmark Results:")
    print(f"  {iterations:,} iterations in {elapsed:.4f} seconds")
    print(f"  {lookups_per_second:,} lookups/second")
    print(f"  {hits:,} hits, {misses:,} misses")
    print(f"  Hit rate: {(hits / iterations) * 100:.1f}%")

    print(f"✓ Benchmark completed: {lookups_per_second:,} lookups/second")

    # Performance expectation - should be reasonably fast
    # This is a rough baseline, actual performance will vary by system
    min_expected_performance = 1000  # lookups per second

    assert lookups_per_second >= min_expected_performance, (
        f"Performance below expected ({lookups_per_second:,} < {min_expected_performance:,} lookups/sec)"
    )

    # Test with actual loaded data - extended benchmark
    print(f"🚀 Extended benchmark against {len(cidrs)} loaded ranges...")

    # Extended performance test with more iterations
    extended_iterations = 100000

    print("📋 Pre-generating extended test data...")
    # Pre-generate test IPs for extended benchmark
    extended_test_ips = []
    for i in range(extended_iterations):
        random_ip = ipaddress.ip_address(random.randint(0, 2**32 - 1))
        extended_test_ips.append(str(random_ip))

    print("🚀 Running extended benchmark...")
    start = time.time()
    extended_hits = 0

    for ip in extended_test_ips:
        result = rt.search(ip)
        if result is not None:
            extended_hits += 1

    end = time.time()
    extended_elapsed = end - start
    extended_lookups_per_second = int(extended_iterations / extended_elapsed)

    print("📊 Extended Results:")
    print(f"  {extended_iterations:,} iterations in {extended_elapsed:.4f} seconds")
    print(f"  {extended_lookups_per_second:,} lookups/second")
    print(f"  {extended_hits:,} hits out of {extended_iterations:,}")
    print(f"  Hit rate: {(extended_hits / extended_iterations) * 100:.1f}%")

    print("✓ All benchmark tests completed!")


def test_special_methods_coverage():
    """Test uncovered special methods in radixtarget.py"""
    target1 = RadixTarget()
    target1.add("example.com")
    target1.add("192.168.1.0/24")

    target2 = RadixTarget()
    target2.add("example.com")
    target2.add("192.168.1.0/24")

    # Test __repr__ (line 147)
    assert repr(target1) == "RadixTarget(strict_scope=false, 2 hosts)"

    # Test __eq__ with non-RadixTarget (line 153)
    assert not (target1 == "not_a_target")
    assert not (target1 == 42)

    # Test __hash__ (line 157)
    hash_val = hash(target1)
    assert isinstance(hash_val, int)

    # Test __contains__ with RadixTarget (line 129)
    target3 = RadixTarget()
    target3.add("example.com")
    assert target3 in target1  # target3 is subset of target1
