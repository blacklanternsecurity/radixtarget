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

        let normalized_value = if let Ok(ipnet) = value.parse::<IpNet>() {
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
        };
        // Hosts are now tracked directly in the trees, no need to maintain separate set
        normalized_value
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

        // Create normalized versions of cleaned networks for host removal
        let mut normalized_cleaned = HashSet::new();
        for cleaned_host in &cleaned {
            if let Ok(ipnet) = cleaned_host.parse::<IpNet>() {
                // Normalize to single IP if it's a /32 or /128
                let normalized = match ipnet {
                    IpNet::V4(net) if net.prefix_len() == 32 => net.network().to_string(),
                    IpNet::V6(net) if net.prefix_len() == 128 => net.network().to_string(),
                    _ => cleaned_host.clone(),
                };
                normalized_cleaned.insert(normalized);
            } else {
                normalized_cleaned.insert(cleaned_host.clone());
            }
        }

        // Update self.hosts: remove cleaned values (using normalized forms), add new values
        self.hosts
            .retain(|h| !normalized_cleaned.contains(h) && !cleaned.contains(h));

        // Add new networks, normalizing single-host networks
        for new_host in &new {
            if let Ok(ipnet) = new_host.parse::<IpNet>() {
                let normalized = match ipnet {
                    IpNet::V4(net) if net.prefix_len() == 32 => net.network().to_string(),
                    IpNet::V6(net) if net.prefix_len() == 128 => net.network().to_string(),
                    _ => new_host.clone(),
                };
                self.hosts.insert(normalized);
            } else {
                self.hosts.insert(new_host.clone());
            }
        }

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
        assert_eq!(set_of_strs(target.hosts.clone()), expected_hosts);
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
        assert_eq!(set_of_strs(target.hosts.clone()), expected_hosts_after);
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
        assert_eq!(set_of_strs(target.hosts.clone()), expected_hosts);
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
        assert_eq!(set_of_strs(target.hosts.clone()), expected_hosts_after);
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
        assert_eq!(set_of_strs(target.hosts.clone()), expected_hosts);
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
        assert_eq!(set_of_strs(target.hosts.clone()), expected_hosts_after);
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
            rt.hosts.contains("192.168.1.100/32"),
            "IPv4 address should be stored as /32"
        );
        assert!(
            !rt.hosts.contains("192.168.1.100"),
            "IPv4 address should not be stored without /32 suffix"
        );

        // Insert individual IPv6 address
        rt.insert("dead::beef");
        // Should be stored as /128 network
        assert!(
            rt.hosts.contains("dead::beef/128"),
            "IPv6 address should be stored as /128"
        );
        assert!(
            !rt.hosts.contains("dead::beef"),
            "IPv6 address should not be stored without /128 suffix"
        );

        // Insert /32 IPv4 network explicitly
        rt.insert("10.0.0.1/32");
        assert!(
            rt.hosts.contains("10.0.0.1/32"),
            "IPv4 /32 should be stored as /32"
        );
        assert!(
            !rt.hosts.contains("10.0.0.1"),
            "IPv4 /32 should not be stored without /32 suffix"
        );

        // Insert /128 IPv6 network explicitly
        rt.insert("cafe::1/128");
        assert!(
            rt.hosts.contains("cafe::1/128"),
            "IPv6 /128 should be stored as /128"
        );
        assert!(
            !rt.hosts.contains("cafe::1"),
            "IPv6 /128 should not be stored without /128 suffix"
        );

        // Insert IP networks with actual network bits (should remain as-is)
        rt.insert("10.0.0.0/8");
        rt.insert("cafe::/64");
        assert!(
            rt.hosts.contains("10.0.0.0/8"),
            "IPv4 network should remain as-is"
        );
        assert!(
            rt.hosts.contains("cafe::/64"),
            "IPv6 network should remain as-is"
        );

        // Insert DNS name (should remain as-is)
        rt.insert("example.com");
        assert!(
            rt.hosts.contains("example.com"),
            "DNS name should remain as-is"
        );

        // Verify that searching works correctly with normalization
        assert!(rt.contains("192.168.1.100"), "Should find IPv4 address");
        assert!(rt.contains("dead::beef"), "Should find IPv6 address");
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
            rt.hosts, expected_hosts,
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
}
