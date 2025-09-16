#!/usr/bin/env python3

import pytest
import sys
import os

# Add the parent directory to sys.path to import radixtarget_rust
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'radixtarget-rust'))

try:
    import radixtarget_rust
except ImportError:
    pytest.skip("radixtarget_rust not available - run 'maturin develop' first", allow_module_level=True)


class TestRadixTargetRust:
    """Test the Rust implementation of RadixTarget via Python bindings."""

    def test_new_empty(self):
        """Test creating an empty RadixTarget."""
        rt = radixtarget_rust.PyRadixTarget()
        assert rt.len() == 0
        assert rt.is_empty()

    def test_new_with_strict_scope(self):
        """Test creating RadixTarget with strict scope."""
        rt = radixtarget_rust.PyRadixTarget(strict_scope=True)
        assert rt.len() == 0
        assert rt.is_empty()

    def test_new_with_hosts(self):
        """Test creating RadixTarget with initial hosts."""
        hosts = ["example.com", "8.8.8.0/24", "2001:db8::/32"]
        rt = radixtarget_rust.PyRadixTarget(strict_scope=False, hosts=hosts)
        assert rt.len() == 3
        assert not rt.is_empty()

    def test_insert_and_get_ipv4(self):
        """Test inserting and retrieving IPv4 networks."""
        rt = radixtarget_rust.PyRadixTarget()
        
        # Insert a /24 network
        hash_val = rt.insert("8.8.8.0/24")
        assert isinstance(hash_val, int)
        
        # Check that a specific IP in that network matches
        result = rt.get("8.8.8.8")
        assert result == hash_val
        
        # Check that an IP outside the network doesn't match
        assert rt.get("1.1.1.1") is None

    def test_insert_and_get_ipv6(self):
        """Test inserting and retrieving IPv6 networks."""
        rt = radixtarget_rust.PyRadixTarget()
        
        # Insert a /64 network
        hash_val = rt.insert("2001:db8::/64")
        assert isinstance(hash_val, int)
        
        # Check that a specific IP in that network matches
        result = rt.get("2001:db8::1")
        assert result == hash_val
        
        # Check that an IP outside the network doesn't match
        assert rt.get("2001:db9::1") is None

    def test_insert_and_get_dns(self):
        """Test inserting and retrieving DNS names."""
        rt = radixtarget_rust.PyRadixTarget()
        
        # Insert a domain
        hash_val = rt.insert("example.com")
        assert isinstance(hash_val, int)
        
        # Check exact match
        result = rt.get("example.com")
        assert result == hash_val
        
        # Check subdomain matching (non-strict mode)
        result_sub = rt.get("www.example.com")
        assert result_sub == hash_val
        
        # Check non-matching domain
        assert rt.get("google.com") is None

    def test_dns_strict_scope(self):
        """Test DNS matching in strict scope mode."""
        rt = radixtarget_rust.PyRadixTarget(strict_scope=True)
        
        hash_val = rt.insert("example.com")
        
        # Exact match should work
        assert rt.get("example.com") == hash_val
        
        # Subdomain should NOT match in strict mode
        assert rt.get("www.example.com") is None

    def test_contains(self):
        """Test the contains method."""
        rt = radixtarget_rust.PyRadixTarget()
        
        rt.insert("example.com")
        rt.insert("8.8.8.0/24")
        rt.insert("2001:db8::/64")
        
        # Test exact contains
        assert rt.contains("example.com")
        assert rt.contains("8.8.8.0/24")
        assert rt.contains("2001:db8::/64")
        
        # Test matching (contains checks if value matches, like get())
        assert rt.contains("www.example.com")  # subdomain matches in non-strict mode
        assert rt.contains("8.8.8.8")  # IP in network matches
        assert rt.contains("2001:db8::1")  # IP in IPv6 network matches
        
        # Test non-matching
        assert not rt.contains("google.com")
        assert not rt.contains("1.1.1.1")
        assert not rt.contains("2001:db9::1")

    def test_delete(self):
        """Test deleting entries."""
        rt = radixtarget_rust.PyRadixTarget()
        
        # Insert and verify
        rt.insert("example.com")
        assert rt.contains("example.com")
        assert rt.len() == 1
        
        # Delete and verify
        deleted = rt.delete("example.com")
        assert deleted
        assert not rt.contains("example.com")
        assert rt.len() == 0
        
        # Try to delete again (should return False)
        deleted_again = rt.delete("example.com")
        assert not deleted_again

    def test_prune(self):
        """Test the prune method."""
        rt = radixtarget_rust.PyRadixTarget()
        
        rt.insert("example.com")
        rt.insert("8.8.8.0/24")
        
        # Prune should return 0 for a clean tree
        pruned = rt.prune()
        assert pruned == 0

    def test_defrag(self):
        """Test the defrag method with mergeable subnets."""
        rt = radixtarget_rust.PyRadixTarget()
        
        # Insert two /25 networks that can be merged into a /24
        rt.insert("192.168.0.0/25")
        rt.insert("192.168.0.128/25")
        
        assert rt.len() == 2
        
        # Defrag should merge them
        cleaned, new = rt.defrag()
        
        # Should have removed the two /25s and added one /24
        assert len(cleaned) == 2
        assert "192.168.0.0/25" in cleaned
        assert "192.168.0.128/25" in cleaned
        
        assert len(new) == 1
        assert "192.168.0.0/24" in new
        
        # Length should now be 1
        assert rt.len() == 1

    def test_repr(self):
        """Test string representation."""
        rt = radixtarget_rust.PyRadixTarget()
        rt.insert("example.com")
        
        repr_str = repr(rt)
        assert "RadixTarget" in repr_str
        assert "example.com" in repr_str

    def test_equality(self):
        """Test equality comparison."""
        rt1 = radixtarget_rust.PyRadixTarget()
        rt2 = radixtarget_rust.PyRadixTarget()
        
        # Empty targets should be equal
        assert rt1 == rt2
        
        # Add same content to both
        rt1.insert("example.com")
        rt2.insert("example.com")
        assert rt1 == rt2
        
        # Add different content
        rt1.insert("google.com")
        assert rt1 != rt2

    def test_malformed_input(self):
        """Test handling of malformed input."""
        rt = radixtarget_rust.PyRadixTarget()
        
        # These should not crash and should be handled as DNS fallback
        malformed_inputs = [
            "999.999.999.999",  # invalid IPv4
            "::gggg",  # invalid IPv6
            "example..com",  # double dot
            "",  # empty string
        ]
        
        for inp in malformed_inputs:
            # Should not raise an exception
            hash_val = rt.insert(inp)
            assert isinstance(hash_val, int)
            
            # Should be retrievable via DNS lookup
            result = rt.get(inp)
            assert result == hash_val
