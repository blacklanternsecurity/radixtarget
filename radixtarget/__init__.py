"""
RadixTarget - Fast radix tree for IP addresses and DNS names

This module provides efficient storage and lookup of IP networks and DNS names
using a Rust-based radix tree implementation for optimal performance.
"""

from ._radixtarget import PyRadixTarget, py_host_size_key as host_size_key
from .radixtarget import RadixTarget

# Alias for convenience
Target = RadixTarget

__all__ = ["RadixTarget", "Target", "host_size_key"]
