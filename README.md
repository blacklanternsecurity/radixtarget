# RadixTarget

[![Python Version](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/radixtarget)](https://pypi.org/project/radixtarget/)
[![Rust Version](https://img.shields.io/badge/rust-1.70+-orange)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/radixtarget?color=orange)](https://crates.io/crates/radixtarget)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://github.com/blacklanternsecurity/radixtarget/blob/master/LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Rust Tests](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/rust-tests.yml/badge.svg?branch=master)](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/rust-tests.yml)
[![Python Tests](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/python-tests.yml/badge.svg?branch=master)](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/python-tests.yml)
[![Codecov](https://codecov.io/gh/blacklanternsecurity/radixtarget/graph/badge.svg?token=7IPWMYMTGZ)](https://codecov.io/gh/blacklanternsecurity/radixtarget)

RadixTarget is a performant radix implementation designed for quick lookups of IP addresses/networks and DNS hostnames. 

RadixTarget is:
- Written in Rust with Python bindings
- Capable of ~200,000 lookups per second regardless of database size
- 100% test coverage
- Available as both a Rust crate and Python package
- Used by:
    - [BBOT](https://github.com/blacklanternsecurity/bbot)
    - [cloudcheck](https://github.com/blacklanternsecurity/cloudcheck)

## Python

### Installation

```bash
pip install radixtarget
```

### Usage

```python
from radixtarget import RadixTarget

rt = RadixTarget()

# IPv4
rt.add("192.168.1.0/24")
rt.get("192.168.1.10") # IPv4Network("192.168.1.0/24")
rt.get("192.168.2.10") # None

# IPv6
rt.add("dead::/64")
rt.get("dead::beef") # IPv6Network("dead::/64")
rt.get("dead:cafe::beef") # None

# DNS
rt.add("net")
rt.add("www.example.com")
rt.add("test.www.example.com")
rt.get("net") # "net"
rt.get("evilcorp.net") # "net"
rt.get("www.example.com") # "www.example.com"
rt.get("asdf.test.www.example.com") # "test.www.example.com"
rt.get("example.com") # None

# Custom data nodes
rt.add("evilcorp.co.uk", "custom_data")
rt.get("www.evilcorp.co.uk") # "custom_data"
```

## Rust

### Installation

```bash
cargo add radixtarget
```

### Usage

```rust
use radixtarget::{RadixTarget, ScopeMode};
use std::collections::HashSet;

// Create a new RadixTarget
let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

// IPv4 networks and addresses
rt.insert("192.168.1.0/24"); 
assert_eq!(rt.get("192.168.1.100"), Some("192.168.1.0/24".to_string()));
assert_eq!(rt.get("192.168.2.100"), None);

// IPv6 networks and addresses  
rt.insert("dead::/64");
assert_eq!(rt.get("dead::beef"), Some("dead::/64".to_string()));
assert_eq!(rt.get("cafe::beef"), None);

// DNS hostnames
rt.insert("example.com");
rt.insert("api.test.www.example.com");
assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
assert_eq!(rt.get("subdomain.api.test.www.example.com"), 
           Some("api.test.www.example.com".to_string()));

// Check if target contains a value
assert!(rt.contains("192.168.1.50"));
assert!(rt.contains("dead::1234"));
assert!(rt.contains("example.com"));

// Get all hosts
let hosts: HashSet<String> = rt.hosts();
println!("All hosts: {:?}", hosts);

// Delete targets
assert!(rt.delete("192.168.1.0/24"));
assert!(!rt.delete("192.168.1.0/24")); // false - already deleted

// Utility operations
println!("Number of hosts: {}", rt.len());
println!("Is empty: {}", rt.is_empty());

// Prune dead nodes (returns number of pruned nodes)
let pruned_count = rt.prune();

// Defragment overlapping networks (returns (cleaned, new) hosts)
let (cleaned_hosts, new_hosts) = rt.defrag();
```

#### Scope Modes

RadixTarget supports different scope modes for DNS matching:

```rust
use radixtarget::{RadixTarget, ScopeMode};

// Normal mode: standard radix tree behavior (default)
let mut rt_normal = RadixTarget::new(&[], ScopeMode::Normal);
rt_normal.insert("example.com");
assert_eq!(rt_normal.get("subdomain.example.com"), Some("example.com".to_string()));

// Strict mode: exact matching only
let mut rt_strict = RadixTarget::new(&[], ScopeMode::Strict);
rt_strict.insert("example.com");
assert_eq!(rt_strict.get("example.com"), Some("example.com".to_string()));
assert_eq!(rt_strict.get("subdomain.example.com"), None); // No subdomain matching

// ACL mode: Same behavior as normal, but keeps only the highest parent subnet for efficiency
let mut rt_acl = RadixTarget::new(&[], ScopeMode::Acl);
rt_acl.insert("192.168.1.0/24");
rt_acl.insert("192.168.1.0/28");
// Least specific match is returned instead of most specific
assert_eq!(rt_acl.get("192.168.1.1"), Some("192.168.1.0/24".to_string()));
```

#### Initialization with Hosts

```rust
use radixtarget::{RadixTarget, ScopeMode};

// Initialize with existing hosts
let hosts = vec!["192.168.1.0/24", "example.com", "dead::/64"];
let rt = RadixTarget::new(&hosts, ScopeMode::Normal);

assert!(rt.contains("192.168.1.100"));
assert!(rt.contains("subdomain.example.com"));
assert!(rt.contains("dead::beef"));
```
