use crate::dns::{DnsRadixTree, ScopeMode};
use crate::input::{ParsedInput, RadixTargetInput};
use crate::ip::IpRadixTree;
use ipnet::IpNet;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct RadixTarget {
    dns: DnsRadixTree,
    ipv4: IpRadixTree,
    ipv6: IpRadixTree,
    cached_hash: Arc<Mutex<Option<u64>>>,
    scope_mode: ScopeMode,
}

impl RadixTarget {
    pub fn new(hosts: &[&str], scope_mode: ScopeMode) -> Result<Self, String> {
        let dns = DnsRadixTree::new(scope_mode);
        let acl_mode = scope_mode == ScopeMode::Acl;
        let mut rt = RadixTarget {
            dns,
            ipv4: IpRadixTree::new(acl_mode),
            ipv6: IpRadixTree::new(acl_mode),
            cached_hash: Arc::new(Mutex::new(None)),
            scope_mode,
        };
        for &host in hosts {
            rt.insert(host)?;
        }
        Ok(rt)
    }

    /// Insert a target (IP network, IP address, or DNS name). Returns the canonicalized value.
    pub fn insert<T: RadixTargetInput>(&mut self, value: T) -> Result<Option<String>, String> {
        // Invalidate cached hash
        *self.cached_hash.lock().unwrap() = None;

        match value.into_parsed()? {
            ParsedInput::Ip(net) => match net {
                IpNet::V4(_) => Ok(self.ipv4.insert(net)),
                IpNet::V6(_) => Ok(self.ipv6.insert(net)),
            },
            ParsedInput::Dns(canonical) => Ok(self.dns.insert(&canonical)),
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

    pub fn contains<T: RadixTargetInput>(&self, value: T) -> bool {
        match value.into_parsed() {
            Ok(ParsedInput::Ip(net)) => match net {
                IpNet::V4(_) => self.ipv4.get(&net).is_some(),
                IpNet::V6(_) => self.ipv6.get(&net).is_some(),
            },
            Ok(ParsedInput::Dns(canonical)) => self.dns.get(&canonical).is_some(),
            Err(_) => false,
        }
    }

    pub fn contains_target(&self, other: &Self) -> bool {
        other.hosts().iter().all(|host| self.contains(host.as_str()))
    }

    /// Delete a target (IP network, IP address, or DNS name). Returns true if deleted.
    pub fn delete<T: RadixTargetInput>(&mut self, value: T) -> bool {
        // Invalidate cached hash
        *self.cached_hash.lock().unwrap() = None;

        match value.into_parsed() {
            Ok(ParsedInput::Ip(net)) => match net {
                IpNet::V4(_) => self.ipv4.delete(net),
                IpNet::V6(_) => self.ipv6.delete(net),
            },
            Ok(ParsedInput::Dns(canonical)) => self.dns.delete(&canonical),
            Err(_) => false,
        }
    }

    /// Get the most specific match for a target (IP network, IP address, or DNS name). Returns the canonical value if found.
    pub fn get<T: RadixTargetInput>(&self, value: T) -> Option<String> {
        match value.into_parsed().ok()? {
            ParsedInput::Ip(net) => match net {
                IpNet::V4(_) => self.ipv4.get(&net),
                IpNet::V6(_) => self.ipv6.get(&net),
            },
            ParsedInput::Dns(canonical) => self.dns.get(&canonical),
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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let host = rt.insert("8.8.8.0/24").unwrap();
        assert_eq!(host, Some("8.8.8.0/24".to_string()));
        assert_eq!(rt.get("8.8.8.8/32"), Some("8.8.8.0/24".to_string()));
        assert_eq!(rt.get("1.1.1.1/32"), None);
    }

    #[test]
    fn test_insert_and_get_ipv6() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let host = rt.insert("dead::/64").unwrap();
        assert_eq!(host, Some("dead::/64".to_string()));
        assert_eq!(rt.get("dead::beef/128"), Some("dead::/64".to_string()));
        assert_eq!(rt.get("cafe::beef/128"), None);
    }

    #[test]
    fn test_insert_and_get_dns() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let host = rt.insert("example.com").unwrap();
        assert_eq!(host, Some("example.com".to_string()));
        assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
        assert_eq!(rt.get("notfound.com"), None);
    }

    #[test]
    fn test_ipaddr_input_get_v4_and_v6() {
        use std::net::IpAddr;
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        rt.insert("8.8.8.0/24").unwrap();
        rt.insert("dead::/64").unwrap();

        let v4: IpAddr = "8.8.8.8".parse().unwrap();
        let v6: IpAddr = "dead::beef".parse().unwrap();

        assert_eq!(rt.get(v4), Some("8.8.8.0/24".to_string()));
        assert_eq!(rt.get(v6), Some("dead::/64".to_string()));
        assert_eq!(rt.get(v4), rt.get("8.8.8.8"));
        assert_eq!(rt.get(v6), rt.get("dead::beef"));
    }

    #[test]
    fn test_ipaddr_input_insert_contains_delete() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let v6 = IpAddr::V6("dead::beef".parse::<Ipv6Addr>().unwrap());

        assert_eq!(rt.insert(v4).unwrap(), Some("192.168.1.100/32".to_string()));
        assert_eq!(rt.insert(v4).unwrap(), Some("192.168.1.100/32".to_string()));
        assert_eq!(rt.insert(v6).unwrap(), Some("dead::beef/128".to_string()));
        assert!(rt.contains(v4));
        assert!(rt.contains(v6));
        assert!(rt.contains("192.168.1.100"));
        assert!(rt.delete(v4));
        assert!(!rt.contains(v4));
        assert!(!rt.delete(v4));
        assert!(rt.delete(v6));
        assert!(!rt.contains(v6));
    }

    #[test]
    fn test_ipaddr_input_acl_mode() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut rt = RadixTarget::new(&[], ScopeMode::Acl).unwrap();
        rt.insert("10.0.0.0/24").unwrap();
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(rt.get(v4), Some("10.0.0.0/24".to_string()));
        assert_eq!(rt.insert(v4).unwrap(), None);
    }

    #[test]
    fn test_dns_subdomain_matching() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let host = rt.insert("api.test.www.example.com").unwrap();
        assert_eq!(host, Some("api.test.www.example.com".to_string()));
        assert_eq!(
            rt.get("wat.hm.api.test.www.example.com"),
            Some("api.test.www.example.com".to_string())
        );
        assert_eq!(rt.get("notfound.com"), None);
    }

    #[test]
    fn test_dns_strict_scope() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Strict).unwrap();
        let host = rt.insert("example.com").unwrap();
        assert_eq!(host, Some("example.com".to_string()));
        assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
        assert_eq!(rt.get("www.example.com"), None);
        assert_eq!(rt.get("com"), None);
    }

    #[test]
    fn test_delete_ipv4() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let host = rt.insert("8.8.8.0/24").unwrap();
        assert_eq!(host, Some("8.8.8.0/24".to_string()));
        assert_eq!(rt.get("8.8.8.8/32"), Some("8.8.8.0/24".to_string()));
        assert!(rt.delete("8.8.8.0/24"));
        assert_eq!(rt.get("8.8.8.8/32"), None);
        assert!(!rt.delete("8.8.8.0/24"));
    }

    #[test]
    fn test_delete_dns() {
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let host = rt.insert("example.com").unwrap();
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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        rt.insert("192.168.0.0/24").unwrap();
        rt.insert("192.168.0.0/30").unwrap();

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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        rt.insert("example.com").unwrap();
        rt.insert("api.test.www.example.com").unwrap();
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
        let mut target = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        target.insert("192.168.0.0/25").unwrap();
        target.insert("192.168.0.128/25").unwrap();
        target.insert("www.evilcorp.com").unwrap();
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
        let mut target = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
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
            target.insert(*net).unwrap();
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
        let mut target = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
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
            target.insert(*net).unwrap();
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
        let mut target = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        // Four /26s covering 192.168.1.0/25 and 192.168.1.128/25
        target.insert("192.168.1.0/26").unwrap();
        target.insert("192.168.1.64/26").unwrap();
        target.insert("192.168.1.128/26").unwrap();
        target.insert("192.168.1.192/26").unwrap();
        target.insert("192.168.0.0/24").unwrap();
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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
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
            let _ = rt.insert(*input);
            // Should not be retrievable as a valid IP or network
            assert_eq!(
                rt.get(*input),
                rt.dns.get(input),
                "Malformed input should only be in DNS tree: {}",
                input
            );
        }
    }

    #[test]
    fn test_hash_same_hosts_different_order() {
        // Test that targets with same hosts in different order have same hash
        let mut rt1 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut rt2 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Add hosts in different orders
        let _ = rt1.insert("example.com");
        let _ = rt1.insert("192.168.1.0/24");
        let _ = rt1.insert("test.org");
        let _ = rt1.insert("10.0.0.0/8");

        let _ = rt2.insert("10.0.0.0/8");
        let _ = rt2.insert("test.org");
        let _ = rt2.insert("192.168.1.0/24");
        let _ = rt2.insert("example.com");

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
        let mut rt_strict = RadixTarget::new(&[], ScopeMode::Strict).unwrap();
        let mut rt_non_strict = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Add same hosts to both
        let _ = rt_strict.insert("example.com");
        let _ = rt_strict.insert("192.168.1.0/24");

        let _ = rt_non_strict.insert("example.com");
        let _ = rt_non_strict.insert("192.168.1.0/24");

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
        let mut rt1 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut rt2 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // rt1 has all hosts, rt2 is missing one
        let _ = rt1.insert("example.com");
        let _ = rt1.insert("192.168.1.0/24");
        let _ = rt1.insert("test.org");

        let _ = rt2.insert("example.com");
        let _ = rt2.insert("192.168.1.0/24");

        let hash1_before = rt1.hash();
        let hash2_before = rt2.hash();

        assert_ne!(
            hash1_before, hash2_before,
            "Targets with different hosts should have different hashes"
        );
        assert_ne!(rt1, rt2, "Targets with different hosts should not be equal");

        // Add missing host to rt2
        let _ = rt2.insert("test.org");

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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        let _ = rt.insert("example.com");
        let _ = rt.insert("192.168.1.0/24");

        // Get hash twice - should be same (cached)
        let hash1 = rt.hash();
        let hash2 = rt.hash();
        assert_eq!(
            hash1, hash2,
            "Consecutive hash calls should return same value"
        );

        // Insert new host - should invalidate cache
        let _ = rt.insert("test.org");
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
        let rt1 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let rt2 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let rt3 = RadixTarget::new(&[], ScopeMode::Strict).unwrap();

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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Build up target
        let _ = rt.insert("example.com");
        let _ = rt.insert("192.168.1.0/24");
        let _ = rt.insert("test.org");
        let final_hash = rt.hash();

        // Create another target with same hosts and same strict_scope
        let mut rt2 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let _ = rt2.insert("test.org");
        let _ = rt2.insert("example.com");
        let _ = rt2.insert("192.168.1.0/24");

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
        let _ = rt.insert("temp.com");
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
        let mut rt1_strict = RadixTarget::new(&[], ScopeMode::Strict).unwrap();
        let mut rt2_strict = RadixTarget::new(&[], ScopeMode::Strict).unwrap();
        let mut rt1_non_strict = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut rt2_non_strict = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Add same hosts to all targets
        for rt in [
            &mut rt1_strict,
            &mut rt2_strict,
            &mut rt1_non_strict,
            &mut rt2_non_strict,
        ] {
            let _ = rt.insert("example.com");
            let _ = rt.insert("192.168.1.0/24");
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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Insert individual IPv4 address
        let _ = rt.insert("192.168.1.100");
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
        let _ = rt.insert("dead::beef");
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
        let _ = rt.insert("10.0.0.1/32");
        assert!(
            rt.hosts().contains("10.0.0.1/32"),
            "IPv4 /32 should be stored as /32"
        );
        assert!(
            !rt.hosts().contains("10.0.0.1"),
            "IPv4 /32 should not be stored without /32 suffix"
        );

        // Insert /128 IPv6 network explicitly
        let _ = rt.insert("cafe::1/128");
        assert!(
            rt.hosts().contains("cafe::1/128"),
            "IPv6 /128 should be stored as /128"
        );
        assert!(
            !rt.hosts().contains("cafe::1"),
            "IPv6 /128 should not be stored without /128 suffix"
        );

        // Insert IP networks with actual network bits (should remain as-is)
        let _ = rt.insert("10.0.0.0/8");
        let _ = rt.insert("cafe::/64");
        assert!(
            rt.hosts().contains("10.0.0.0/8"),
            "IPv4 network should remain as-is"
        );
        assert!(
            rt.hosts().contains("cafe::/64"),
            "IPv6 network should remain as-is"
        );

        // Insert DNS name (should remain as-is)
        let _ = rt.insert("example.com");
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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Insert with mixed case
        let host1 = rt.insert("Example.COM").unwrap();

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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Unicode domain that gets converted to punycode
        let unicode = "café.com";
        let punycode = "xn--caf-dma.com";

        // Insert unicode
        let host1 = rt.insert(unicode).unwrap();

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
        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Insert with mixed case unicode
        let host1 = rt.insert("CAFÉ.COM").unwrap();

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
        let mut superset = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut subset = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut disjoint = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Setup superset with broad coverage
        let _ = superset.insert("example.com");
        let _ = superset.insert("192.168.0.0/16");
        let _ = superset.insert("test.org");
        let _ = superset.insert("10.0.0.0/8");
        let _ = superset.insert("dead:beef::/32");

        // Setup subset with targets covered by superset
        let _ = subset.insert("sub.example.com"); // covered by example.com
        let _ = subset.insert("192.168.1.100"); // covered by 192.168.0.0/16
        let _ = subset.insert("10.5.5.5"); // covered by 10.0.0.0/8

        // Setup disjoint set with only some overlap
        let _ = disjoint.insert("example.com");
        let _ = disjoint.insert("172.16.1.0/24");

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
        let empty = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
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
        let mut broad = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut specific = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Broad network coverage
        let _ = broad.insert("192.168.0.0/16");
        let _ = broad.insert("10.0.0.0/8");
        let _ = broad.insert("2001:db8::/32");

        // Specific networks within broad coverage
        let _ = specific.insert("192.168.1.0/24"); // subset of 192.168.0.0/16
        let _ = specific.insert("10.5.0.0/16"); // subset of 10.0.0.0/8
        let _ = specific.insert("2001:db8:1::/48"); // subset of 2001:db8::/32

        assert!(
            broad.contains_target(&specific),
            "Broad networks should contain specific subnets"
        );
        assert!(
            !specific.contains_target(&broad),
            "Specific networks should not contain broader networks"
        );

        // Test exact matches
        let mut exact = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let _ = exact.insert("192.168.0.0/16");
        assert!(
            broad.contains_target(&exact),
            "Should contain exact network match"
        );
        assert!(exact.contains_target(&exact), "Should contain itself");

        // Test individual IPs
        let mut single_ips = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let _ = single_ips.insert("192.168.1.100"); // covered by 192.168.0.0/16
        let _ = single_ips.insert("10.0.0.1"); // covered by 10.0.0.0/8
        let _ = single_ips.insert("2001:db8::1"); // covered by 2001:db8::/32

        assert!(
            broad.contains_target(&single_ips),
            "Broad networks should contain individual IPs within range"
        );
    }

    #[test]
    fn test_contains_target_dns_hierarchies() {
        let mut parent = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut child = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Parent domain coverage (Normal mode allows subdomain matching)
        let _ = parent.insert("example.com");
        let _ = parent.insert("test.org");

        // Child domains
        let _ = child.insert("api.example.com");
        let _ = child.insert("www.example.com");
        let _ = child.insert("sub.test.org");

        assert!(
            parent.contains_target(&child),
            "Parent domains should contain subdomains in Normal mode"
        );

        // Test with exact domain matches
        let mut exact = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let _ = exact.insert("example.com");
        assert!(
            parent.contains_target(&exact),
            "Should contain exact domain match"
        );
    }

    #[test]
    fn test_contains_target_strict_scope() {
        let mut strict_parent = RadixTarget::new(&[], ScopeMode::Strict).unwrap();
        let mut strict_child = RadixTarget::new(&[], ScopeMode::Strict).unwrap();

        // In strict mode, subdomains are not automatically matched
        let _ = strict_parent.insert("example.com");
        let _ = strict_child.insert("www.example.com");

        assert!(
            !strict_parent.contains_target(&strict_child),
            "Parent domain should not contain subdomain in Strict mode"
        );

        // But exact matches should work
        let mut exact = RadixTarget::new(&[], ScopeMode::Strict).unwrap();
        let _ = exact.insert("example.com");
        assert!(
            strict_parent.contains_target(&exact),
            "Should contain exact match in Strict mode"
        );
    }

    #[test]
    fn test_contains_target_mixed_types() {
        let mut mixed_superset = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut mixed_subset = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Superset with various types
        let _ = mixed_superset.insert("example.com"); // DNS
        let _ = mixed_superset.insert("192.168.0.0/16"); // IPv4 network
        let _ = mixed_superset.insert("10.0.0.1"); // IPv4 address
        let _ = mixed_superset.insert("2001:db8::/32"); // IPv6 network

        // Subset with targets covered by superset
        let _ = mixed_subset.insert("api.example.com"); // covered by example.com
        let _ = mixed_subset.insert("192.168.1.100"); // covered by 192.168.0.0/16
        let _ = mixed_subset.insert("10.0.0.1"); // exact match
        let _ = mixed_subset.insert("2001:db8:1::1"); // covered by 2001:db8::/32

        assert!(
            mixed_superset.contains_target(&mixed_subset),
            "Mixed superset should contain mixed subset"
        );

        // Add something not covered
        let _ = mixed_subset.insert("unrelated.net");
        assert!(
            !mixed_superset.contains_target(&mixed_subset),
            "Should not contain subset with uncovered elements"
        );
    }

    #[test]
    fn test_contains_target_partial_overlap() {
        let mut target1 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let mut target2 = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Partially overlapping sets
        let _ = target1.insert("example.com");
        let _ = target1.insert("192.168.0.0/24");
        let _ = target1.insert("shared.net");

        let _ = target2.insert("test.org");
        let _ = target2.insert("10.0.0.0/8");
        let _ = target2.insert("shared.net");

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
        let mut shared_only = RadixTarget::new(&[], ScopeMode::Normal).unwrap();
        let _ = shared_only.insert("shared.net");
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

        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        println!("🚀 Starting insertion benchmark...");
        let start = Instant::now();

        for cidr in &cidrs {
            let _ = rt.insert(cidr.as_str());
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

        let mut rt = RadixTarget::new(&[], ScopeMode::Normal).unwrap();

        // Insert all CIDRs first
        for cidr in &cidrs {
            let _ = rt.insert(cidr.as_str());
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
            match rt.get(ip.as_str()) {
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
