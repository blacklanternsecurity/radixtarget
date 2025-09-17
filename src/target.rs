use crate::dns::{DnsRadixTree, ScopeMode};
use crate::ip::IpRadixTree;
use crate::utils::normalize_dns;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct RadixTarget {
    dns: DnsRadixTree,
    ipv4: IpRadixTree,
    ipv6: IpRadixTree,
    hosts: HashSet<String>, // store canonicalized hosts for len/contains
    cached_hash: Arc<Mutex<Option<u64>>>, // cached hash value
    scope_mode: ScopeMode,  // needed for hash calculation
}

impl RadixTarget {
    pub fn new(hosts: &[&str], scope_mode: ScopeMode) -> Self {
        let dns = DnsRadixTree::new(scope_mode);
        let acl_mode = scope_mode == ScopeMode::Acl;
        let mut rt = RadixTarget {
            dns,
            ipv4: IpRadixTree::new(acl_mode),
            ipv6: IpRadixTree::new(acl_mode),
            hosts: HashSet::new(),
            cached_hash: Arc::new(Mutex::new(None)),
            scope_mode,
        };
        for &host in hosts {
            rt.insert(host);
        }
        rt
    }

    /// Insert a target (IP network, IP address, or DNS name). Returns the canonicalized value.
    pub fn insert(&mut self, value: &str) -> Option<String> {
        // Invalidate cached hash
        *self.cached_hash.lock().unwrap() = None;

        // Hosts are now tracked directly in the trees, no need to maintain separate set
        if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.insert(ipnet),
                IpNet::V6(_) => self.ipv6.insert(ipnet),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            // Convert bare IP address to /32 or /128 network for both storage and return
            match ipaddr {
                IpAddr::V4(addr) => {
                    let net = IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap());
                    self.ipv4.insert(net)
                }
                IpAddr::V6(addr) => {
                    let net = IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap());
                    self.ipv6.insert(net)
                }
            }
        } else {
            let canonical = normalize_dns(value);
            self.dns.insert(&canonical)
        }
    }

    pub fn len(&self) -> usize {
        self.hosts().len()
    }

    pub fn strict_scope(&self) -> bool {
        self.scope_mode == ScopeMode::Strict
    }

    pub fn is_empty(&self) -> bool {
        self.hosts().is_empty()
    }

    pub fn contains(&self, value: &str) -> bool {
        if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.get(&ipnet).is_some(),
                IpNet::V6(_) => self.ipv6.get(&ipnet).is_some(),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            match ipaddr {
                IpAddr::V4(addr) => self
                    .ipv4
                    .get(&IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap()))
                    .is_some(),
                IpAddr::V6(addr) => self
                    .ipv6
                    .get(&IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap()))
                    .is_some(),
            }
        } else {
            let canonical = normalize_dns(value);
            self.dns.get(&canonical).is_some()
        }
    }

    pub fn contains_target(&self, other: &Self) -> bool {
        other.hosts().iter().all(|host| self.contains(host))
    }

    /// Delete a target (IP network, IP address, or DNS name). Returns true if deleted.
    pub fn delete(&mut self, value: &str) -> bool {
        // Invalidate cached hash
        *self.cached_hash.lock().unwrap() = None;

        let deleted = if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.delete(ipnet),
                IpNet::V6(_) => self.ipv6.delete(ipnet),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            match ipaddr {
                IpAddr::V4(addr) => self
                    .ipv4
                    .delete(IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap())),
                IpAddr::V6(addr) => self
                    .ipv6
                    .delete(IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap())),
            }
        } else {
            let canonical = normalize_dns(value);
            self.dns.delete(&canonical)
        };
        // Remove the canonical form from hosts, not the original input
        if deleted && value.parse::<IpNet>().is_err() && value.parse::<IpAddr>().is_err() {
            let canonical = normalize_dns(value);
            self.hosts.remove(&canonical);
        } else {
            self.hosts.remove(value);
        }
        deleted
    }

    /// Get the most specific match for a target (IP network, IP address, or DNS name). Returns the canonical value if found.
    pub fn get(&self, value: &str) -> Option<String> {
        if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.get(&ipnet),
                IpNet::V6(_) => self.ipv6.get(&ipnet),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            match ipaddr {
                IpAddr::V4(addr) => self
                    .ipv4
                    .get(&IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap())),
                IpAddr::V6(addr) => self
                    .ipv6
                    .get(&IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap())),
            }
        } else {
            let canonical = normalize_dns(value);
            self.dns.get(&canonical)
        }
    }

    pub fn prune(&mut self) -> usize {
        // Invalidate cached hash
        *self.cached_hash.lock().unwrap() = None;
        self.dns.prune() + self.ipv4.prune() + self.ipv6.prune()
    }

    // NOTE: This is a potentially destructive operation
    // Since in the rust implementation, only the data reference is stored for each node,
    // defrag will indiscriminately merge nodes regardless of their data
    // For this reason, this method is not used by the Python implementation, which implements its own defrag logic
    pub fn defrag(&mut self) -> (HashSet<String>, HashSet<String>) {
        // Invalidate cached hash
        *self.cached_hash.lock().unwrap() = None;

        let (cleaned_v4, new_v4) = self.ipv4.defrag();
        let (cleaned_v6, new_v6) = self.ipv6.defrag();
        let mut cleaned = HashSet::new();
        let mut new = HashSet::new();
        cleaned.extend(cleaned_v4);
        cleaned.extend(cleaned_v6);
        new.extend(new_v4);
        new.extend(new_v6);

        (cleaned, new)
    }

    pub fn hosts(&self) -> HashSet<String> {
        let mut all_hosts = HashSet::new();

        // Collect hosts from all trees
        all_hosts.extend(self.ipv4.hosts());
        all_hosts.extend(self.ipv6.hosts());
        all_hosts.extend(self.dns.hosts());

        all_hosts
    }

    pub fn hash(&self) -> u64 {
        {
            let cached = self.cached_hash.lock().unwrap();
            if let Some(hash_value) = *cached {
                return hash_value;
            }
        }

        let hash_value = self.compute_hash();

        // Cache the result
        *self.cached_hash.lock().unwrap() = Some(hash_value);
        hash_value
    }

    fn compute_hash(&self) -> u64 {
        // Calculate hash using seahash
        let mut hosts: Vec<String> = self.hosts().into_iter().collect();
        hosts.sort();

        // Create a single string to hash
        let mut data = hosts.join("\n");
        if self.scope_mode == ScopeMode::Strict {
            data.push('\0');
        }

        seahash::hash(data.as_bytes())
    }

    /// Create a deep copy of this RadixTarget
    pub fn copy(&self) -> Self {
        // Clone creates a deep copy of all internal structures
        let mut cloned = self.clone();
        // Reset the cached hash since it's wrapped in Arc<Mutex<>>
        cloned.cached_hash = Arc::new(Mutex::new(None));
        cloned
    }
}

impl PartialEq for RadixTarget {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}
impl Eq for RadixTarget {}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::collections::HashSet;
    use std::hash::{Hash, Hasher};
    use std::str::FromStr;

    fn set_of_strs<I: IntoIterator<Item = String>>(vals: I) -> HashSet<String> {
        vals.into_iter().collect()
    }

    #[test]
    fn test_insert_and_get_ipv4() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        let host = rt.insert("8.8.8.0/24");
        assert_eq!(host, Some("8.8.8.0/24".to_string()));
        assert_eq!(rt.get("8.8.8.8/32"), Some("8.8.8.0/24".to_string()));
        assert_eq!(rt.get("1.1.1.1/32"), None);
    }

    #[test]
    fn test_insert_and_get_ipv6() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        let host = rt.insert("dead::/64");
        assert_eq!(host, Some("dead::/64".to_string()));
        assert_eq!(rt.get("dead::beef/128"), Some("dead::/64".to_string()));
        assert_eq!(rt.get("cafe::beef/128"), None);
    }

    #[test]
    fn test_insert_and_get_dns() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        let host = rt.insert("example.com");
        assert_eq!(host, Some("example.com".to_string()));
        assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
        assert_eq!(rt.get("notfound.com"), None);
    }

    #[test]
    fn test_dns_subdomain_matching() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        let host = rt.insert("api.test.www.example.com");
        assert_eq!(host, Some("api.test.www.example.com".to_string()));
        assert_eq!(
            rt.get("wat.hm.api.test.www.example.com"),
            Some("api.test.www.example.com".to_string())
        );
        assert_eq!(rt.get("notfound.com"), None);
    }

    #[test]
    fn test_dns_strict_scope() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Strict);
        let host = rt.insert("example.com");
        assert_eq!(host, Some("example.com".to_string()));
        assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
        assert_eq!(rt.get("www.example.com"), None);
        assert_eq!(rt.get("com"), None);
    }

    #[test]
    fn test_delete_ipv4() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        let host = rt.insert("8.8.8.0/24");
        assert_eq!(host, Some("8.8.8.0/24".to_string()));
        assert_eq!(rt.get("8.8.8.8/32"), Some("8.8.8.0/24".to_string()));
        assert!(rt.delete("8.8.8.0/24"));
        assert_eq!(rt.get("8.8.8.8/32"), None);
        assert!(!rt.delete("8.8.8.0/24"));
    }

    #[test]
    fn test_delete_dns() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        let host = rt.insert("example.com");
        assert_eq!(host, Some("example.com".to_string()));
        assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
        assert!(rt.delete("example.com"));
        assert_eq!(rt.get("example.com"), None);
        assert!(!rt.delete("example.com"));
    }

    #[test]
    fn test_prune_ip() {
        // Test IP pruning logic and fallback to less specific parent after manual mutation.

        // 1. Insert two overlapping networks: /24 and /30 (the /30 is a subnet of the /24)
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        rt.insert("192.168.0.0/24");
        rt.insert("192.168.0.0/30");

        assert_eq!(rt.get("192.168.0.1"), Some("192.168.0.0/30".to_string()));

        // 2. Walk the tree to the node representing the /30 network.
        //    This simulates finding the most specific node for 192.168.0.0/30.
        let mut node = &mut rt.ipv4.root;
        let slash_thirty = IpNet::from_str("192.168.0.0/30").unwrap();
        let bits = {
            let (addr, prefix) = match &slash_thirty {
                IpNet::V4(n) => (n.network().octets().to_vec(), slash_thirty.prefix_len()),
                IpNet::V6(n) => (n.network().octets().to_vec(), slash_thirty.prefix_len()),
            };
            let mut bits = Vec::with_capacity(prefix as usize);
            for byte in addr {
                for i in (0..8).rev() {
                    if bits.len() == prefix as usize {
                        break;
                    }
                    bits.push((byte >> i) & 1);
                }
            }
            bits
        };
        for &bit in &bits[..bits.len() - 1] {
            node = node.children.get_mut(&(bit as u64)).unwrap();
        }
        // At this point, node is the parent of the /30 leaf node.
        assert_eq!(node.children.len(), 1); // Only the /30 child should exist here.
        let last_bit = bits[bits.len() - 1] as u64;
        assert!(node.children.contains_key(&last_bit)); // The /30 node exists.

        // 3. Simulate manual removal of the /30 node's children.
        //    This mimics a situation where the most specific node is unreachable (e.g., deleted or pruned).
        node.children.clear();

        // 4. Now, querying for 192.168.0.0 should fall back to the /24 parent network.
        //    This tests the longest-prefix match/fallback logic.
        assert_eq!(rt.get("192.168.0.0"), Some("192.168.0.0/24".to_string()));

        // 5. Prune the tree. This should remove all dead nodes left by the manual mutation (5 nodes in this case).
        let pruned = rt.ipv4.prune();
        assert_eq!(pruned, 5);

        // 6. Pruning again should do nothing (idempotency check).
        let pruned2 = rt.ipv4.prune();
        assert_eq!(pruned2, 0);
    }

    #[test]
    fn test_prune_dns() {
        // dns pruning
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        rt.insert("example.com");
        rt.insert("api.test.www.example.com");
        // Walk to the "api" node
        let mut node = &mut rt.dns.root;
        use idna::domain_to_ascii;
        let segs = ["com", "example", "www", "test"];
        for seg in segs.iter() {
            let key = {
                let canonical = domain_to_ascii(seg).unwrap();
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                canonical.hash(&mut hasher);
                hasher.finish()
            };
            node = node.children.get_mut(&key).unwrap();
        }
        assert_eq!(node.children.len(), 1);
        let api_key = {
            let canonical = domain_to_ascii("api").unwrap();
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            canonical.hash(&mut hasher);
            hasher.finish()
        };
        assert!(node.children.contains_key(&api_key));
        // Simulate manual removal of the "api" node's children
        node.children.clear();
        // Now the "api" node is unreachable, fallback to "example.com"
        assert_eq!(
            rt.get("wat.hm.api.test.www.example.com"),
            Some("example.com".to_string())
        );
        // Prune should remove all dead nodes (2 in this case)
        let pruned = rt.dns.prune();
        assert_eq!(pruned, 2);
        // Pruning again should do nothing
        let pruned2 = rt.dns.prune();
        assert_eq!(pruned2, 0);
    }

    #[test]
    fn test_defrag_basic_merge() {
        // Two mergeable subnets
        let mut target = RadixTarget::new(&[], ScopeMode::Normal);
        target.insert("192.168.0.0/25");
        target.insert("192.168.0.128/25");
        target.insert("www.evilcorp.com");
        let expected_hosts: HashSet<String> =
            ["192.168.0.0/25", "192.168.0.128/25", "www.evilcorp.com"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(target.hosts(), expected_hosts);
        let (cleaned, new) = target.defrag();
        let expected_cleaned: HashSet<String> = ["192.168.0.0/25", "192.168.0.128/25"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let expected_new: HashSet<String> =
            ["192.168.0.0/24".to_string()].iter().cloned().collect();
        assert_eq!(cleaned, expected_cleaned);
        assert_eq!(new, expected_new);
        let expected_hosts_after: HashSet<String> = ["192.168.0.0/24", "www.evilcorp.com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(target.hosts(), expected_hosts_after);
    }

    #[test]
    fn test_defrag_recursive_merge_ipv4() {
        let mut target = RadixTarget::new(&[], ScopeMode::Normal);
        for net in [
            "192.168.0.0/25",
            "192.168.0.128/27",
            "192.168.0.160/27",
            "192.168.0.192/27",
            "192.168.0.224/28",
            "192.168.0.240/29",
            "192.168.0.248/30",
            "192.168.0.252/31",
            "192.168.0.254/32",
            "192.168.0.255/32",
        ]
        .iter()
        {
            target.insert(net);
        }
        let expected_hosts: HashSet<String> = [
            "192.168.0.0/25",
            "192.168.0.128/27",
            "192.168.0.160/27",
            "192.168.0.192/27",
            "192.168.0.224/28",
            "192.168.0.240/29",
            "192.168.0.248/30",
            "192.168.0.252/31",
            "192.168.0.254/32", // stored as /32
            "192.168.0.255/32", // stored as /32
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(target.hosts(), expected_hosts);
        let (cleaned, new) = target.defrag();
        let expected_cleaned: HashSet<String> = [
            "192.168.0.0/25",
            "192.168.0.128/27",
            "192.168.0.160/27",
            "192.168.0.192/27",
            "192.168.0.224/28",
            "192.168.0.240/29",
            "192.168.0.248/30",
            "192.168.0.252/31",
            "192.168.0.254/32", // defrag returns original tree form
            "192.168.0.255/32", // defrag returns original tree form
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let expected_new: HashSet<String> =
            ["192.168.0.0/24".to_string()].iter().cloned().collect();
        assert_eq!(cleaned, expected_cleaned);
        assert_eq!(new, expected_new);
        let expected_hosts_after: HashSet<String> =
            ["192.168.0.0/24".to_string()].iter().cloned().collect();
        assert_eq!(target.hosts(), expected_hosts_after);
    }

    #[test]
    fn test_defrag_recursive_merge_ipv6() {
        let mut target = RadixTarget::new(&[], ScopeMode::Normal);
        for net in [
            "dead:beef::/121",
            "dead:beef::80/123",
            "dead:beef::a0/123",
            "dead:beef::c0/123",
            "dead:beef::e0/124",
            "dead:beef::f0/125",
            "dead:beef::f8/126",
            "dead:beef::fc/127",
            "dead:beef::fe/128",
            "dead:beef::ff/128",
        ]
        .iter()
        {
            target.insert(net);
        }
        let expected_hosts: HashSet<String> = [
            "dead:beef::/121",
            "dead:beef::80/123",
            "dead:beef::a0/123",
            "dead:beef::c0/123",
            "dead:beef::e0/124",
            "dead:beef::f0/125",
            "dead:beef::f8/126",
            "dead:beef::fc/127",
            "dead:beef::fe/128", // stored as /128
            "dead:beef::ff/128", // stored as /128
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(target.hosts(), expected_hosts);
        let (cleaned, new) = target.defrag();
        let expected_cleaned: HashSet<String> = [
            "dead:beef::/121",
            "dead:beef::80/123",
            "dead:beef::a0/123",
            "dead:beef::c0/123",
            "dead:beef::e0/124",
            "dead:beef::f0/125",
            "dead:beef::f8/126",
            "dead:beef::fc/127",
            "dead:beef::fe/128", // defrag returns original tree form
            "dead:beef::ff/128", // defrag returns original tree form
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let expected_new: HashSet<String> =
            ["dead:beef::/120".to_string()].iter().cloned().collect();
        assert_eq!(cleaned, expected_cleaned);
        assert_eq!(new, expected_new);
        let expected_hosts_after: HashSet<String> =
            ["dead:beef::/120".to_string()].iter().cloned().collect();
        assert_eq!(target.hosts(), expected_hosts_after);
    }

    #[test]
    fn test_defrag_small_recursive() {
        let mut target = RadixTarget::new(&[], ScopeMode::Normal);
        // Four /26s covering 192.168.1.0/25 and 192.168.1.128/25
        target.insert("192.168.1.0/26");
        target.insert("192.168.1.64/26");
        target.insert("192.168.1.128/26");
        target.insert("192.168.1.192/26");
        target.insert("192.168.0.0/24");
        // Single defrag: should merge the /26s into /25s, then into a /24, then merge the two /24s into a /23
        let (cleaned, new) = target.defrag();
        let expected_cleaned: HashSet<String> = [
            "192.168.1.0/26",
            "192.168.1.64/26",
            "192.168.1.128/26",
            "192.168.1.192/26",
            "192.168.0.0/24",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let expected_new: HashSet<String> =
            ["192.168.0.0/23".to_string()].iter().cloned().collect();
        assert_eq!(cleaned, expected_cleaned);
        assert_eq!(new, expected_new);
    }

    #[test]
    fn test_insert_malformed_data() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
        let malformed_inputs = [
            "999.999.999.999",        // invalid IPv4
            "256.256.256.256/33",     // invalid IPv4 CIDR
            "::gggg",                 // invalid IPv6
            "dead::beef::cafe",       // invalid IPv6
            "1.2.3.4/abc",            // invalid CIDR suffix
            "-example.com",           // invalid DNS (leading hyphen)
            "example..com",           // double dot
            ".example.com",           // leading dot
            "example.com-",           // trailing hyphen
            "exa mple.com",           // space in domain
            "",                       // empty string
            "*.*.*.*",                // wildcard nonsense
            "[::1]",                  // brackets not allowed
            "1.2.3.4/",               // trailing slash
            "com..",                  // trailing double dot
            "...",                    // just dots
            "foo@bar.com",            // @ in domain
            "1.2.3.4.5",              // too many octets
            "1234:5678:9abc:defg::1", // invalid hex in IPv6
            "example_com",            // underscore in domain
        ];
        for input in malformed_inputs.iter() {
            // Should not panic, should insert as DNS fallback, or handle gracefully
            let _ = rt.insert(input);
            // Should not be retrievable as a valid IP or network
            assert_eq!(
                rt.get(input),
                rt.dns.get(input),
                "Malformed input should only be in DNS tree: {}",
                input
            );
        }
    }

    #[test]
    fn test_hash_same_hosts_different_order() {
        // Test that targets with same hosts in different order have same hash
        let mut rt1 = RadixTarget::new(&[], ScopeMode::Normal);
        let mut rt2 = RadixTarget::new(&[], ScopeMode::Normal);

        // Add hosts in different orders
        rt1.insert("example.com");
        rt1.insert("192.168.1.0/24");
        rt1.insert("test.org");
        rt1.insert("10.0.0.0/8");

        rt2.insert("10.0.0.0/8");
        rt2.insert("test.org");
        rt2.insert("192.168.1.0/24");
        rt2.insert("example.com");

        let hash1 = rt1.hash();
        let hash2 = rt2.hash();

        assert_eq!(
            hash1, hash2,
            "Targets with same hosts in different order should have same hash"
        );
        assert_eq!(rt1, rt2, "Targets with same hosts should be equal");
    }

    #[test]
    fn test_hash_strict_vs_non_strict() {
        // Test that strict and non-strict targets with same hosts have different hashes
        let mut rt_strict = RadixTarget::new(&[], ScopeMode::Strict);
        let mut rt_non_strict = RadixTarget::new(&[], ScopeMode::Normal);

        // Add same hosts to both
        rt_strict.insert("example.com");
        rt_strict.insert("192.168.1.0/24");

        rt_non_strict.insert("example.com");
        rt_non_strict.insert("192.168.1.0/24");

        let hash_strict = rt_strict.hash();
        let hash_non_strict = rt_non_strict.hash();

        assert_ne!(
            hash_strict, hash_non_strict,
            "Strict and non-strict targets should have different hashes"
        );
        assert_ne!(
            rt_strict, rt_non_strict,
            "Targets should not be equal since equality is now hash-based"
        );
    }

    #[test]
    fn test_hash_missing_host_scenario() {
        // Test hash equality before and after adding missing host
        let mut rt1 = RadixTarget::new(&[], ScopeMode::Normal);
        let mut rt2 = RadixTarget::new(&[], ScopeMode::Normal);

        // rt1 has all hosts, rt2 is missing one
        rt1.insert("example.com");
        rt1.insert("192.168.1.0/24");
        rt1.insert("test.org");

        rt2.insert("example.com");
        rt2.insert("192.168.1.0/24");

        let hash1_before = rt1.hash();
        let hash2_before = rt2.hash();

        assert_ne!(
            hash1_before, hash2_before,
            "Targets with different hosts should have different hashes"
        );
        assert_ne!(rt1, rt2, "Targets with different hosts should not be equal");

        // Add missing host to rt2
        rt2.insert("test.org");

        let hash1_after = rt1.hash();
        let hash2_after = rt2.hash();

        assert_eq!(
            hash1_after, hash2_after,
            "Targets should have same hash after adding missing host"
        );
        assert_eq!(
            rt1, rt2,
            "Targets should be equal after adding missing host"
        );

        // Verify that rt1's hash didn't change (it was cached)
        assert_eq!(
            hash1_before, hash1_after,
            "rt1 hash should remain the same (cached)"
        );
    }

    #[test]
    fn test_hash_caching_and_invalidation() {
        // Test that hash is cached and invalidated properly
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        rt.insert("example.com");
        rt.insert("192.168.1.0/24");

        // Get hash twice - should be same (cached)
        let hash1 = rt.hash();
        let hash2 = rt.hash();
        assert_eq!(
            hash1, hash2,
            "Consecutive hash calls should return same value"
        );

        // Insert new host - should invalidate cache
        rt.insert("test.org");
        let hash3 = rt.hash();
        assert_ne!(hash1, hash3, "Hash should change after inserting new host");

        // Delete host - should invalidate cache
        let hash4 = rt.hash(); // Cache the current hash
        rt.delete("test.org");
        let hash5 = rt.hash();
        assert_ne!(hash4, hash5, "Hash should change after deleting host");
        assert_eq!(
            hash1, hash5,
            "Hash should return to original after deleting added host"
        );

        // Prune - should invalidate cache
        let _hash6 = rt.hash();
        rt.prune();
        let _hash7 = rt.hash();
        // Hash might be same if no pruning occurred, but cache should still be invalidated
        // We can't easily test this without the actual cache state, but the method should work

        // Defrag - should invalidate cache
        let _hash8 = rt.hash();
        rt.defrag();
        let _hash9 = rt.hash();
        // Similar to prune, hash might be same but cache should be invalidated
    }

    #[test]
    fn test_empty_target_hash() {
        // Test hash of empty targets
        let rt1 = RadixTarget::new(&[], ScopeMode::Normal);
        let rt2 = RadixTarget::new(&[], ScopeMode::Normal);
        let rt3 = RadixTarget::new(&[], ScopeMode::Strict);

        let hash1 = rt1.hash();
        let hash2 = rt2.hash();
        let hash3 = rt3.hash();

        assert_eq!(
            hash1, hash2,
            "Empty non-strict targets should have same hash"
        );
        assert_ne!(
            hash1, hash3,
            "Empty strict and non-strict targets should have different hashes"
        );
    }

    #[test]
    fn test_hash_consistency_across_operations() {
        // Test that hash remains consistent across various operations
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        // Build up target
        rt.insert("example.com");
        rt.insert("192.168.1.0/24");
        rt.insert("test.org");
        let final_hash = rt.hash();

        // Create another target with same hosts and same strict_scope
        let mut rt2 = RadixTarget::new(&[], ScopeMode::Normal);
        rt2.insert("test.org");
        rt2.insert("example.com");
        rt2.insert("192.168.1.0/24");

        assert_eq!(
            final_hash,
            rt2.hash(),
            "Final hashes should be equal regardless of insertion order"
        );
        assert_eq!(
            rt, rt2,
            "Targets should be equal with same hosts and same strict_scope"
        );

        // Test that adding and removing the same host doesn't change hash
        let original_hash = rt.hash();
        rt.insert("temp.com");
        rt.delete("temp.com");
        let restored_hash = rt.hash();

        assert_eq!(
            original_hash, restored_hash,
            "Hash should be same after adding and removing same host"
        );
    }

    #[test]
    fn test_equality_with_same_strict_scope() {
        // Test that targets with same hosts and same strict_scope are equal
        let mut rt1_strict = RadixTarget::new(&[], ScopeMode::Strict);
        let mut rt2_strict = RadixTarget::new(&[], ScopeMode::Strict);
        let mut rt1_non_strict = RadixTarget::new(&[], ScopeMode::Normal);
        let mut rt2_non_strict = RadixTarget::new(&[], ScopeMode::Normal);

        // Add same hosts to all targets
        for rt in [
            &mut rt1_strict,
            &mut rt2_strict,
            &mut rt1_non_strict,
            &mut rt2_non_strict,
        ] {
            rt.insert("example.com");
            rt.insert("192.168.1.0/24");
        }

        // Targets with same strict_scope should be equal
        assert_eq!(
            rt1_strict, rt2_strict,
            "Strict targets with same hosts should be equal"
        );
        assert_eq!(
            rt1_non_strict, rt2_non_strict,
            "Non-strict targets with same hosts should be equal"
        );

        // Targets with different strict_scope should not be equal
        assert_ne!(
            rt1_strict, rt1_non_strict,
            "Strict and non-strict targets should not be equal"
        );
        assert_ne!(
            rt2_strict, rt2_non_strict,
            "Strict and non-strict targets should not be equal"
        );
    }

    #[test]
    fn test_ip_normalization_single_hosts() {
        // Test that single host IPs are consistently stored as /32 or /128 networks
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        // Insert individual IPv4 address
        rt.insert("192.168.1.100");
        // Should be stored as /32 network
        assert!(
            rt.hosts().contains("192.168.1.100/32"),
            "IPv4 address should be stored as /32"
        );
        assert!(
            !rt.hosts().contains("192.168.1.100"),
            "IPv4 address should not be stored without /32 suffix"
        );

        // Insert individual IPv6 address
        rt.insert("dead::beef");
        // Should be stored as /128 network
        assert!(
            rt.hosts().contains("dead::beef/128"),
            "IPv6 address should be stored as /128"
        );
        assert!(
            !rt.hosts().contains("dead::beef"),
            "IPv6 address should not be stored without /128 suffix"
        );

        // Insert /32 IPv4 network explicitly
        rt.insert("10.0.0.1/32");
        assert!(
            rt.hosts().contains("10.0.0.1/32"),
            "IPv4 /32 should be stored as /32"
        );
        assert!(
            !rt.hosts().contains("10.0.0.1"),
            "IPv4 /32 should not be stored without /32 suffix"
        );

        // Insert /128 IPv6 network explicitly
        rt.insert("cafe::1/128");
        assert!(
            rt.hosts().contains("cafe::1/128"),
            "IPv6 /128 should be stored as /128"
        );
        assert!(
            !rt.hosts().contains("cafe::1"),
            "IPv6 /128 should not be stored without /128 suffix"
        );

        // Insert IP networks with actual network bits (should remain as-is)
        rt.insert("10.0.0.0/8");
        rt.insert("cafe::/64");
        assert!(
            rt.hosts().contains("10.0.0.0/8"),
            "IPv4 network should remain as-is"
        );
        assert!(
            rt.hosts().contains("cafe::/64"),
            "IPv6 network should remain as-is"
        );

        // Insert DNS name (should remain as-is)
        rt.insert("example.com");
        assert!(
            rt.hosts().contains("example.com"),
            "DNS name should remain as-is"
        );

        // Verify that searching works correctly with normalization
        assert!(
            rt.hosts().contains("192.168.1.100/32"),
            "Should find IPv4 address"
        );
        assert!(
            rt.hosts().contains("dead::beef/128"),
            "Should find IPv6 address"
        );
        assert_eq!(
            rt.get("192.168.1.100"),
            rt.get("192.168.1.100/32"),
            "IPv4 lookups should be equivalent"
        );
        assert_eq!(
            rt.get("dead::beef"),
            rt.get("dead::beef/128"),
            "IPv6 lookups should be equivalent"
        );

        // Check final hosts set contains normalized forms
        let expected_hosts: HashSet<String> = [
            "192.168.1.100/32", // stored as /32
            "dead::beef/128",   // stored as /128
            "10.0.0.1/32",      // stored as /32
            "cafe::1/128",      // stored as /128
            "10.0.0.0/8",       // network remains as-is
            "cafe::/64",        // network remains as-is
            "example.com",      // DNS remains as-is
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            rt.hosts(),
            expected_hosts,
            "Hosts should contain consistent network forms"
        );
    }

    #[test]
    fn test_dns_case_normalization() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        // Insert with mixed case
        let host1 = rt.insert("Example.COM");

        // All case variations should find the same entry
        assert_eq!(rt.get("example.com"), host1.clone());
        assert_eq!(rt.get("EXAMPLE.COM"), host1.clone());
        assert_eq!(rt.get("Example.Com"), host1.clone());
        assert_eq!(rt.get("eXaMpLe.CoM"), host1);

        // Contains should work with all case variations
        assert!(rt.contains("example.com"));
        assert!(rt.contains("EXAMPLE.COM"));
        assert!(rt.contains("Example.Com"));
        assert!(rt.contains("eXaMpLe.CoM"));

        // Delete should work with any case variation
        assert!(rt.delete("EXAMPLE.com"));
        assert_eq!(rt.get("example.com"), None);
        assert!(!rt.contains("Example.COM"));
    }

    #[test]
    fn test_dns_idna_normalization() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        // Unicode domain that gets converted to punycode
        let unicode = "café.com";
        let punycode = "xn--caf-dma.com";

        // Insert unicode
        let host1 = rt.insert(unicode);

        assert_eq!(rt.hosts(), set_of_strs(vec!["xn--caf-dma.com".to_string()]));

        // Should be able to find with both unicode and punycode
        assert_eq!(rt.get(unicode), host1.clone());
        assert_eq!(rt.get(punycode), host1.clone());
        assert_eq!(rt.get("CAFÉ.COM"), host1.clone());
        assert_eq!(rt.get("XN--CAF-DMA.COM"), host1);

        // Contains should work with both forms
        assert!(rt.contains(unicode));
        assert!(rt.contains(punycode));
        assert!(rt.contains("CAFÉ.COM"));
        assert!(rt.contains("XN--CAF-DMA.COM"));

        // Delete with punycode should work
        assert!(rt.delete(punycode));
        assert_eq!(rt.get(unicode), None);
        assert!(!rt.contains("CAFÉ.COM"));
    }

    #[test]
    fn test_dns_mixed_case_and_idna() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        // Insert with mixed case unicode
        let host1 = rt.insert("CAFÉ.COM");

        // All variations should work
        assert_eq!(rt.get("café.com"), host1.clone());
        assert_eq!(rt.get("CAFÉ.COM"), host1.clone());
        assert_eq!(rt.get("Café.Com"), host1.clone());
        assert_eq!(rt.get("xn--caf-dma.com"), host1.clone());
        assert_eq!(rt.get("XN--CAF-DMA.COM"), host1);

        // Delete with lowercase unicode
        assert!(rt.delete("café.com"));
        assert_eq!(rt.get("CAFÉ.COM"), None);
    }

    #[test]
    fn test_contains_target() {
        // Test basic containment scenarios
        let mut superset = RadixTarget::new(&[], ScopeMode::Normal);
        let mut subset = RadixTarget::new(&[], ScopeMode::Normal);
        let mut disjoint = RadixTarget::new(&[], ScopeMode::Normal);

        // Setup superset with broad coverage
        superset.insert("example.com");
        superset.insert("192.168.0.0/16");
        superset.insert("test.org");
        superset.insert("10.0.0.0/8");
        superset.insert("dead:beef::/32");

        // Setup subset with targets covered by superset
        subset.insert("sub.example.com"); // covered by example.com
        subset.insert("192.168.1.100"); // covered by 192.168.0.0/16
        subset.insert("10.5.5.5"); // covered by 10.0.0.0/8

        // Setup disjoint set with only some overlap
        disjoint.insert("example.com");
        disjoint.insert("172.16.1.0/24");

        // Test containment relationships
        assert!(
            superset.contains_target(&subset),
            "Superset should contain subset"
        );
        assert!(
            !subset.contains_target(&superset),
            "Subset should not contain superset"
        );
        assert!(
            !superset.contains_target(&disjoint),
            "Superset should not contain disjoint set"
        );
        assert!(
            !disjoint.contains_target(&superset),
            "Disjoint set should not contain superset"
        );
        assert!(
            !subset.contains_target(&disjoint),
            "Subset should not contain disjoint set"
        );

        // Test self-containment
        assert!(
            superset.contains_target(&superset),
            "Target should contain itself"
        );
        assert!(
            subset.contains_target(&subset),
            "Target should contain itself"
        );
        assert!(
            disjoint.contains_target(&disjoint),
            "Target should contain itself"
        );

        // Test empty target containment
        let empty = RadixTarget::new(&[], ScopeMode::Normal);
        assert!(
            superset.contains_target(&empty),
            "Any target should contain empty target"
        );
        assert!(
            subset.contains_target(&empty),
            "Any target should contain empty target"
        );
        assert!(
            empty.contains_target(&empty),
            "Empty target should contain itself"
        );
        assert!(
            !empty.contains_target(&superset),
            "Empty target should not contain non-empty target"
        );
    }

    #[test]
    fn test_contains_target_ip_networks() {
        let mut broad = RadixTarget::new(&[], ScopeMode::Normal);
        let mut specific = RadixTarget::new(&[], ScopeMode::Normal);

        // Broad network coverage
        broad.insert("192.168.0.0/16");
        broad.insert("10.0.0.0/8");
        broad.insert("2001:db8::/32");

        // Specific networks within broad coverage
        specific.insert("192.168.1.0/24"); // subset of 192.168.0.0/16
        specific.insert("10.5.0.0/16"); // subset of 10.0.0.0/8
        specific.insert("2001:db8:1::/48"); // subset of 2001:db8::/32

        assert!(
            broad.contains_target(&specific),
            "Broad networks should contain specific subnets"
        );
        assert!(
            !specific.contains_target(&broad),
            "Specific networks should not contain broader networks"
        );

        // Test exact matches
        let mut exact = RadixTarget::new(&[], ScopeMode::Normal);
        exact.insert("192.168.0.0/16");
        assert!(
            broad.contains_target(&exact),
            "Should contain exact network match"
        );
        assert!(exact.contains_target(&exact), "Should contain itself");

        // Test individual IPs
        let mut single_ips = RadixTarget::new(&[], ScopeMode::Normal);
        single_ips.insert("192.168.1.100"); // covered by 192.168.0.0/16
        single_ips.insert("10.0.0.1"); // covered by 10.0.0.0/8
        single_ips.insert("2001:db8::1"); // covered by 2001:db8::/32

        assert!(
            broad.contains_target(&single_ips),
            "Broad networks should contain individual IPs within range"
        );
    }

    #[test]
    fn test_contains_target_dns_hierarchies() {
        let mut parent = RadixTarget::new(&[], ScopeMode::Normal);
        let mut child = RadixTarget::new(&[], ScopeMode::Normal);

        // Parent domain coverage (Normal mode allows subdomain matching)
        parent.insert("example.com");
        parent.insert("test.org");

        // Child domains
        child.insert("api.example.com");
        child.insert("www.example.com");
        child.insert("sub.test.org");

        assert!(
            parent.contains_target(&child),
            "Parent domains should contain subdomains in Normal mode"
        );

        // Test with exact domain matches
        let mut exact = RadixTarget::new(&[], ScopeMode::Normal);
        exact.insert("example.com");
        assert!(
            parent.contains_target(&exact),
            "Should contain exact domain match"
        );
    }

    #[test]
    fn test_contains_target_strict_scope() {
        let mut strict_parent = RadixTarget::new(&[], ScopeMode::Strict);
        let mut strict_child = RadixTarget::new(&[], ScopeMode::Strict);

        // In strict mode, subdomains are not automatically matched
        strict_parent.insert("example.com");
        strict_child.insert("www.example.com");

        assert!(
            !strict_parent.contains_target(&strict_child),
            "Parent domain should not contain subdomain in Strict mode"
        );

        // But exact matches should work
        let mut exact = RadixTarget::new(&[], ScopeMode::Strict);
        exact.insert("example.com");
        assert!(
            strict_parent.contains_target(&exact),
            "Should contain exact match in Strict mode"
        );
    }

    #[test]
    fn test_contains_target_mixed_types() {
        let mut mixed_superset = RadixTarget::new(&[], ScopeMode::Normal);
        let mut mixed_subset = RadixTarget::new(&[], ScopeMode::Normal);

        // Superset with various types
        mixed_superset.insert("example.com"); // DNS
        mixed_superset.insert("192.168.0.0/16"); // IPv4 network
        mixed_superset.insert("10.0.0.1"); // IPv4 address
        mixed_superset.insert("2001:db8::/32"); // IPv6 network

        // Subset with targets covered by superset
        mixed_subset.insert("api.example.com"); // covered by example.com
        mixed_subset.insert("192.168.1.100"); // covered by 192.168.0.0/16
        mixed_subset.insert("10.0.0.1"); // exact match
        mixed_subset.insert("2001:db8:1::1"); // covered by 2001:db8::/32

        assert!(
            mixed_superset.contains_target(&mixed_subset),
            "Mixed superset should contain mixed subset"
        );

        // Add something not covered
        mixed_subset.insert("unrelated.net");
        assert!(
            !mixed_superset.contains_target(&mixed_subset),
            "Should not contain subset with uncovered elements"
        );
    }

    #[test]
    fn test_contains_target_partial_overlap() {
        let mut target1 = RadixTarget::new(&[], ScopeMode::Normal);
        let mut target2 = RadixTarget::new(&[], ScopeMode::Normal);

        // Partially overlapping sets
        target1.insert("example.com");
        target1.insert("192.168.0.0/24");
        target1.insert("shared.net");

        target2.insert("test.org");
        target2.insert("10.0.0.0/8");
        target2.insert("shared.net");

        // Neither should contain the other
        assert!(
            !target1.contains_target(&target2),
            "Partially overlapping sets should not contain each other"
        );
        assert!(
            !target2.contains_target(&target1),
            "Partially overlapping sets should not contain each other"
        );

        // Test with just the shared element
        let mut shared_only = RadixTarget::new(&[], ScopeMode::Normal);
        shared_only.insert("shared.net");
        assert!(
            target1.contains_target(&shared_only),
            "Should contain subset with only shared elements"
        );
        assert!(
            target2.contains_target(&shared_only),
            "Should contain subset with only shared elements"
        );
    }
}

#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn load_cidrs() -> Vec<String> {
        let cidr_path = "radixtarget/test/cidrs.txt";
        fs::read_to_string(cidr_path)
            .unwrap_or_else(|_| panic!("Failed to read {}", cidr_path))
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect()
    }

    #[test]
    #[ignore] // Use `cargo test --ignored` to run benchmarks
    fn bench_insertion_performance() {
        let cidrs = load_cidrs();
        println!(
            "📊 Loading {} CIDR blocks for insertion benchmark",
            cidrs.len()
        );

        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        println!("🚀 Starting insertion benchmark...");
        let start = Instant::now();

        for cidr in &cidrs {
            rt.insert(cidr);
        }

        let elapsed = start.elapsed();
        let insertions_per_second = (cidrs.len() as f64 / elapsed.as_secs_f64()) as u64;

        println!("📈 Insertion Benchmark Results:");
        println!(
            "  {} insertions in {:.4} seconds",
            cidrs.len(),
            elapsed.as_secs_f64()
        );
        println!("  {} insertions/second", insertions_per_second);
        println!("  Target contains {} hosts", rt.len());

        // Verify some insertions worked
        assert!(rt.contains("100.20.0.0/14"));
        assert!(rt.get("100.20.1.1").is_some());

        println!(
            "✓ Insertion benchmark completed: {} insertions/second",
            insertions_per_second
        );
    }

    #[test]
    #[ignore] // Use `cargo test --ignored` to run benchmarks
    fn bench_lookup_performance() {
        let cidrs = load_cidrs();
        println!(
            "📊 Loading {} CIDR blocks for lookup benchmark",
            cidrs.len()
        );

        let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

        // Insert all CIDRs first
        for cidr in &cidrs {
            rt.insert(cidr);
        }

        println!("✅ Loaded {} CIDR blocks", cidrs.len());

        // Generate random IPv4 addresses for lookup testing
        let iterations = 100_000;
        println!("📋 Pre-generating {} test IPs...", iterations);

        let mut test_ips = Vec::with_capacity(iterations);
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for i in 0..iterations {
            // Use a simple PRNG based on index for reproducible results
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            let random_u32 = (hasher.finish() % (u32::MAX as u64)) as u32;
            let ip = Ipv4Addr::from(random_u32);
            test_ips.push(ip.to_string());
        }

        println!("🚀 Running lookup benchmark...");
        let start = Instant::now();
        let mut hits = 0;
        let mut misses = 0;

        for ip in &test_ips {
            match rt.get(ip) {
                Some(_) => hits += 1,
                None => misses += 1,
            }
        }

        let elapsed = start.elapsed();
        let lookups_per_second = (iterations as f64 / elapsed.as_secs_f64()) as u64;

        println!("📈 Lookup Benchmark Results:");
        println!(
            "  {} iterations in {:.4} seconds",
            iterations,
            elapsed.as_secs_f64()
        );
        println!("  {} lookups/second", lookups_per_second);
        println!("  {} hits, {} misses", hits, misses);
        println!(
            "  Hit rate: {:.1}%",
            (hits as f64 / iterations as f64) * 100.0
        );

        println!(
            "✓ Lookup benchmark completed: {} lookups/second",
            lookups_per_second
        );
    }
}
