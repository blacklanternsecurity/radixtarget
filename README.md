# radixtarget-rust

A high-performance radix tree implementation for fast lookups of IP addresses, IP networks, and DNS hostnames, written in Rust.

## Features

- Written in pure Rust for maximum performance and safety
- Supports IPv4, IPv6, and DNS hostnames in a unified API
- Efficient longest-prefix matching for IPs and subdomain matching for DNS
- Insert, delete, prune, and defragment operations
- Used for network scope management, firewall rules, and more

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
radixtarget_rust = { path = "radixtarget_rust" }
```

Or, if published on crates.io:

```toml
[dependencies]
radixtarget_rust = "0.1"
```

## Example Usage

```rust
use radixtarget_rust::target::RadixTarget;

fn main() {
    // Create a new RadixTarget (non-strict DNS scope)
    let mut rt = RadixTarget::new(false);

    // IPv4
    rt.insert("192.168.1.0/24");
    assert!(rt.get("192.168.1.10").is_some());
    assert!(rt.get("192.168.2.10").is_none());

    // IPv6
    rt.insert("dead::/64");
    assert!(rt.get("dead::beef").is_some());
    assert!(rt.get("dead:cafe::beef").is_none());

    // DNS
    rt.insert("net");
    rt.insert("www.example.com");
    rt.insert("test.www.example.com");
    assert!(rt.get("net").is_some());
    assert!(rt.get("evilcorp.net").is_some());
    assert!(rt.get("www.example.com").is_some());
    assert!(rt.get("asdf.test.www.example.com").is_some());
    assert!(rt.get("example.com").is_none());

    // Remove a target
    rt.delete("www.example.com");
    assert!(rt.get("www.example.com").is_none());
}
```

## API Highlights

- `RadixTarget::new(strict_scope: bool)`: Create a new tree. If `strict_scope` is true, DNS lookups require exact matches (no subdomain matching).
- `insert(&mut self, value: &str) -> u64`: Insert an IP network, address, or DNS name. Returns a hash of the canonicalized value.
- `get(&self, value: &str) -> Option<u64>`: Get the most specific match for a value.
- `delete(&mut self, value: &str) -> bool`: Remove a value from the tree.
- `prune(&mut self) -> usize`: Remove unreachable/dead nodes.
- `defrag(&mut self) -> (HashSet<String>, HashSet<String>)`: Merge adjacent/mergeable nodes and update the set of hosts.

## Use Cases

- Network scope management for security tools
- Fast IP/DNS allow/block lists
- Efficient prefix/subdomain matching
