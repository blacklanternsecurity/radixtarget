use crate::dns::DnsRadixTree;
use crate::ip::IpRadixTree;
use ipnet::{IpNet};
use std::collections::{HashSet};
use std::fmt;
use std::net::IpAddr;

#[derive(Clone)]
pub struct RadixTarget {
    dns: DnsRadixTree,
    ipv4: IpRadixTree,
    ipv6: IpRadixTree,
    hosts: HashSet<String>, // store canonicalized hosts for len/contains
}

impl RadixTarget {
    pub fn new_with_hosts(strict_scope: bool, hosts: &[&str]) -> Self {
        let mut rt = RadixTarget {
            dns: DnsRadixTree::new(strict_scope),
            ipv4: IpRadixTree::new(),
            ipv6: IpRadixTree::new(),
            hosts: HashSet::new(),
        };
        for &host in hosts {
            rt.insert(host);
        }
        rt
    }

    pub fn new(strict_scope: bool) -> Self {
        RadixTarget {
            dns: DnsRadixTree::new(strict_scope),
            ipv4: IpRadixTree::new(),
            ipv6: IpRadixTree::new(),
            hosts: HashSet::new(),
        }
    }

    /// Insert a target (IP network, IP address, or DNS name). Returns the SipHash of the canonicalized value.
    pub fn insert(&mut self, value: &str) -> u64 {
        let hash = if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.insert(ipnet),
                IpNet::V6(_) => self.ipv6.insert(ipnet),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            // Convert bare IP address to /32 or /128 network
            match ipaddr {
                IpAddr::V4(addr) => self.ipv4.insert(IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap())),
                IpAddr::V6(addr) => self.ipv6.insert(IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap())),
            }
        } else {
            self.dns.insert(value)
        };
        self.hosts.insert(value.to_string());
        hash
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn contains(&self, value: &str) -> bool {
        if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.get(&ipnet).is_some(),
                IpNet::V6(_) => self.ipv6.get(&ipnet).is_some(),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            match ipaddr {
                IpAddr::V4(addr) => self.ipv4.get(&IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap())).is_some(),
                IpAddr::V6(addr) => self.ipv6.get(&IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap())).is_some(),
            }
        } else {
            self.dns.get(value).is_some()
        }
    }

    /// Delete a target (IP network, IP address, or DNS name). Returns true if deleted.
    pub fn delete(&mut self, value: &str) -> bool {
        use std::net::IpAddr;
        let deleted = if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.delete(ipnet),
                IpNet::V6(_) => self.ipv6.delete(ipnet),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            match ipaddr {
                IpAddr::V4(addr) => self.ipv4.delete(IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap())),
                IpAddr::V6(addr) => self.ipv6.delete(IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap())),
            }
        } else {
            self.dns.delete(value)
        };
        self.hosts.remove(value);
        deleted
    }

    /// Get the most specific match for a target (IP network, IP address, or DNS name). Returns the SipHash if found.
    pub fn get(&self, value: &str) -> Option<u64> {
        use std::net::IpAddr;
        if let Ok(ipnet) = value.parse::<IpNet>() {
            match ipnet {
                IpNet::V4(_) => self.ipv4.get(&ipnet),
                IpNet::V6(_) => self.ipv6.get(&ipnet),
            }
        } else if let Ok(ipaddr) = value.parse::<IpAddr>() {
            match ipaddr {
                IpAddr::V4(addr) => self.ipv4.get(&IpNet::V4(ipnet::Ipv4Net::new(addr, 32).unwrap())),
                IpAddr::V6(addr) => self.ipv6.get(&IpNet::V6(ipnet::Ipv6Net::new(addr, 128).unwrap())),
            }
        } else {
            self.dns.get(value)
        }
    }

    pub fn prune(&mut self) -> usize {
        self.dns.prune() + self.ipv4.prune() + self.ipv6.prune()
    }
}

impl PartialEq for RadixTarget {
    fn eq(&self, other: &Self) -> bool {
        self.hosts == other.hosts
    }
}
impl Eq for RadixTarget {}

impl fmt::Debug for RadixTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RadixTarget({:?})", self.hosts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::str::FromStr;
    use std::hash::{Hash, Hasher};

    fn hash_for_ipnet(net: &str) -> u64 {
        let ipnet = IpNet::from_str(net).unwrap();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ipnet.hash(&mut hasher);
        hasher.finish()
    }

    fn hash_for_dns(host: &str) -> u64 {
        use idna::domain_to_ascii;
        let canonical = domain_to_ascii(host).unwrap();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        canonical.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_insert_and_get_ipv4() {
        let mut rt = RadixTarget::new(false);
        let hash = rt.insert("8.8.8.0/24");
        assert_eq!(hash, hash_for_ipnet("8.8.8.0/24"));
        assert_eq!(rt.get("8.8.8.8/32"), Some(hash_for_ipnet("8.8.8.0/24")));
        assert_eq!(rt.get("1.1.1.1/32"), None);
    }

    #[test]
    fn test_insert_and_get_ipv6() {
        let mut rt = RadixTarget::new(false);
        let hash = rt.insert("dead::/64");
        assert_eq!(hash, hash_for_ipnet("dead::/64"));
        assert_eq!(rt.get("dead::beef/128"), Some(hash_for_ipnet("dead::/64")));
        assert_eq!(rt.get("cafe::beef/128"), None);
    }

    #[test]
    fn test_insert_and_get_dns() {
        let mut rt = RadixTarget::new(false);
        let hash = rt.insert("example.com");
        assert_eq!(hash, hash_for_dns("example.com"));
        assert_eq!(rt.get("example.com"), Some(hash_for_dns("example.com")));
        assert_eq!(rt.get("notfound.com"), None);
    }

    #[test]
    fn test_dns_subdomain_matching() {
        let mut rt = RadixTarget::new(false);
        let hash = rt.insert("api.test.www.example.com");
        assert_eq!(hash, hash_for_dns("api.test.www.example.com"));
        assert_eq!(rt.get("wat.hm.api.test.www.example.com"), Some(hash_for_dns("api.test.www.example.com")));
        assert_eq!(rt.get("notfound.com"), None);
    }

    #[test]
    fn test_dns_strict_scope() {
        let mut rt = RadixTarget::new(true);
        let hash = rt.insert("example.com");
        assert_eq!(hash, hash_for_dns("example.com"));
        assert_eq!(rt.get("example.com"), Some(hash_for_dns("example.com")));
        assert_eq!(rt.get("www.example.com"), None);
        assert_eq!(rt.get("com"), None);
    }

    #[test]
    fn test_delete_ipv4() {
        let mut rt = RadixTarget::new(false);
        let hash = rt.insert("8.8.8.0/24");
        assert_eq!(hash, hash_for_ipnet("8.8.8.0/24"));
        assert_eq!(rt.get("8.8.8.8/32"), Some(hash_for_ipnet("8.8.8.0/24")));
        assert!(rt.delete("8.8.8.0/24"));
        assert_eq!(rt.get("8.8.8.8/32"), None);
        assert!(!rt.delete("8.8.8.0/24"));
    }

    #[test]
    fn test_delete_dns() {
        let mut rt = RadixTarget::new(false);
        let hash = rt.insert("example.com");
        assert_eq!(hash, hash_for_dns("example.com"));
        assert_eq!(rt.get("example.com"), Some(hash_for_dns("example.com")));
        assert!(rt.delete("example.com"));
        assert_eq!(rt.get("example.com"), None);
        assert!(!rt.delete("example.com"));
    }

    #[test]
    fn test_prune_ip() {
        // Test IP pruning logic and fallback to less specific parent after manual mutation.

        // 1. Insert two overlapping networks: /24 and /30 (the /30 is a subnet of the /24)
        let mut rt = RadixTarget::new(false);
        rt.insert("192.168.0.0/24");
        rt.insert("192.168.0.0/30");

        assert_eq!(rt.get("192.168.0.1"), Some(hash_for_ipnet("192.168.0.0/30")));

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
        for &bit in &bits[..bits.len()-1] {
            node = node.children.get_mut(&(bit as u64)).unwrap();
        }
        // At this point, node is the parent of the /30 leaf node.
        assert_eq!(node.children.len(), 1); // Only the /30 child should exist here.
        let last_bit = bits[bits.len()-1] as u64;
        assert!(node.children.get(&last_bit).is_some()); // The /30 node exists.

        // 3. Simulate manual removal of the /30 node's children.
        //    This mimics a situation where the most specific node is unreachable (e.g., deleted or pruned).
        node.children.clear();

        // 4. Now, querying for 192.168.0.0 should fall back to the /24 parent network.
        //    This tests the longest-prefix match/fallback logic.
        assert_eq!(rt.get("192.168.0.0"), Some(hash_for_ipnet("192.168.0.0/24")));

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
        let mut rt = RadixTarget::new(false);
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
        assert!(node.children.get(&api_key).is_some());
        // Simulate manual removal of the "api" node's children
        node.children.clear();
        // Now the "api" node is unreachable, fallback to "example.com"
        assert_eq!(rt.get("wat.hm.api.test.www.example.com"), Some(hash_for_dns("example.com")));
        // Prune should remove all dead nodes (2 in this case)
        let pruned = rt.dns.prune();
        assert_eq!(pruned, 2);
        // Pruning again should do nothing
        let pruned2 = rt.dns.prune();
        assert_eq!(pruned2, 0);
    }
}
