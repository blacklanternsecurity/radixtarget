// Fast IP radix tree using tree-bitmap algorithm
use crate::treebitmap::FastTreeBitmap;
use crate::utils::canonicalize_ipnet;
use ipnet::IpNet;
use std::collections::HashSet;

#[derive(Debug)]
pub struct FastIpRadixTree {
    tree: FastTreeBitmap,
    acl_mode: bool,
}

impl FastIpRadixTree {
    pub fn new(acl_mode: bool) -> Self {
        Self {
            tree: FastTreeBitmap::new(),
            acl_mode,
        }
    }

    pub fn with_capacity(capacity: usize, acl_mode: bool) -> Self {
        Self {
            tree: FastTreeBitmap::with_capacity(capacity),
            acl_mode,
        }
    }

    pub fn insert(&mut self, network: IpNet) -> Option<String> {
        let canonical = canonicalize_ipnet(&network);

        // If ACL mode is enabled, check if the network is already covered by the tree
        if self.acl_mode && self.get(&canonical).is_some() {
            return None; // Skip insertion if already covered
        }

        self.tree.insert(canonical);
        Some(canonical.to_string())
    }

    pub fn get(&self, net: &IpNet) -> Option<String> {
        let canonical = canonicalize_ipnet(net);

        // For longest prefix matching, we need to find the most specific network
        // that contains the given network's base address
        self.tree.longest_match(&canonical).map(|n| n.to_string())
    }

    pub fn delete(&mut self, network: IpNet) -> bool {
        let canonical = canonicalize_ipnet(&network);
        self.tree.remove(&canonical).is_some()
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    pub fn prune(&mut self) -> usize {
        // Tree-bitmap doesn't need pruning like the old HashMap-based implementation
        0
    }

    pub fn hosts(&self) -> HashSet<String> {
        let mut hosts = HashSet::new();
        // Iterate through all stored networks in the tree
        for network in self.tree.all_networks() {
            hosts.insert(network.to_string());
        }
        hosts
    }

    pub fn defrag(&mut self) -> (HashSet<String>, HashSet<String>) {
        // Implement defragmentation by finding mergeable network pairs
        let mut cleaned = HashSet::new();
        let mut new = HashSet::new();

        loop {
            let pairs = self.find_mergeable_pairs();
            if pairs.is_empty() {
                break;
            }

            for (left_net, right_net, supernet) in pairs {
                cleaned.insert(left_net.to_string());
                cleaned.insert(right_net.to_string());
                new.insert(supernet.to_string());

                self.delete(left_net);
                self.delete(right_net);
                self.insert(supernet);
            }
        }

        // Remove any overlap between cleaned and new
        let overlap: HashSet<_> = cleaned.intersection(&new).cloned().collect();
        for k in &overlap {
            cleaned.remove(k);
            new.remove(k);
        }

        (cleaned, new)
    }

    fn find_mergeable_pairs(&self) -> Vec<(IpNet, IpNet, IpNet)> {
        use ipnet::{Ipv4Net, Ipv6Net};
        use std::collections::HashMap;

        let mut pairs = Vec::new();
        let mut networks_by_prefix: HashMap<u8, Vec<IpNet>> = HashMap::new();

        // Group networks by prefix length
        for network in self.tree.all_networks() {
            networks_by_prefix
                .entry(network.prefix_len())
                .or_default()
                .push(network);
        }

        // Check each prefix length for mergeable pairs
        for (prefix_len, networks) in networks_by_prefix {
            if prefix_len == 0 {
                continue; // Can't merge default routes
            }

            for i in 0..networks.len() {
                for j in i + 1..networks.len() {
                    let left = &networks[i];
                    let right = &networks[j];

                    // Check if they can be merged
                    let supernet = match (left, right) {
                        (IpNet::V4(l), IpNet::V4(r)) => {
                            if prefix_len > 0 && prefix_len <= 32 {
                                let mask = if prefix_len == 32 {
                                    0xffffffffu32
                                } else {
                                    !(0xffffffffu32 >> prefix_len)
                                };
                                let l_addr = u32::from(l.network());
                                let r_addr = u32::from(r.network());
                                if (l_addr ^ r_addr) == (1 << (32 - prefix_len)) {
                                    let min_addr = l_addr.min(r_addr) & mask;
                                    Some(IpNet::V4(
                                        Ipv4Net::new(min_addr.into(), prefix_len - 1).unwrap(),
                                    ))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        (IpNet::V6(l), IpNet::V6(r)) => {
                            if prefix_len > 0 && prefix_len <= 128 {
                                let mask = if prefix_len == 128 {
                                    0xffffffffffffffffffffffffffffffffu128
                                } else {
                                    !(0xffffffffffffffffffffffffffffffffu128 >> prefix_len)
                                };
                                let l_addr = u128::from(l.network());
                                let r_addr = u128::from(r.network());
                                if (l_addr ^ r_addr) == (1 << (128 - prefix_len)) {
                                    let min_addr = l_addr.min(r_addr) & mask;
                                    Some(IpNet::V6(
                                        Ipv6Net::new(min_addr.into(), prefix_len - 1).unwrap(),
                                    ))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        _ => None, // Can't merge IPv4 and IPv6
                    };

                    if let Some(supernet) = supernet {
                        pairs.push((*left, *right, supernet));
                    }
                }
            }
        }

        pairs
    }
}

impl Clone for FastIpRadixTree {
    fn clone(&self) -> Self {
        let mut new_tree = FastIpRadixTree::new(self.acl_mode);
        // Copy all networks from the original tree
        for network in self.tree.all_networks() {
            new_tree.insert(network);
        }
        new_tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_insert_and_get_ipv4() {
        let mut tree = FastIpRadixTree::new(false);
        let net = IpNet::from_str("192.168.1.0/24").unwrap();

        assert_eq!(tree.insert(net), Some(net.to_string()));
        assert_eq!(tree.len(), 1);

        // Test lookup with host IP
        let host = IpNet::from_str("192.168.1.100/32").unwrap();
        assert_eq!(tree.get(&host), Some(net.to_string()));

        // Test no match
        let no_match = IpNet::from_str("10.0.0.1/32").unwrap();
        assert_eq!(tree.get(&no_match), None);
    }

    #[test]
    fn test_insert_and_get_ipv6() {
        let mut tree = FastIpRadixTree::new(false);
        let net = IpNet::from_str("2001:db8::/64").unwrap();

        assert_eq!(tree.insert(net), Some(net.to_string()));

        let host = IpNet::from_str("2001:db8::1/128").unwrap();
        assert_eq!(tree.get(&host), Some(net.to_string()));
    }

    #[test]
    fn test_overlapping_networks() {
        let mut tree = FastIpRadixTree::new(false);
        let broad = IpNet::from_str("10.0.0.0/8").unwrap();
        let specific = IpNet::from_str("10.1.0.0/16").unwrap();
        let most_specific = IpNet::from_str("10.1.1.0/24").unwrap();

        tree.insert(broad);
        tree.insert(specific);
        tree.insert(most_specific);

        // Should match most specific
        let host1 = IpNet::from_str("10.1.1.100/32").unwrap();
        assert_eq!(tree.get(&host1), Some(most_specific.to_string()));

        // Should match intermediate
        let host2 = IpNet::from_str("10.1.2.100/32").unwrap();
        assert_eq!(tree.get(&host2), Some(specific.to_string()));

        // Should match broad
        let host3 = IpNet::from_str("10.2.0.1/32").unwrap();
        assert_eq!(tree.get(&host3), Some(broad.to_string()));
    }

    #[test]
    fn test_acl_mode() {
        let mut tree = FastIpRadixTree::new(true);
        let broad = IpNet::from_str("10.0.0.0/8").unwrap();
        let specific = IpNet::from_str("10.1.0.0/16").unwrap();

        tree.insert(broad);
        // In ACL mode, more specific networks should be skipped if already covered
        assert_eq!(tree.insert(specific), None);
        assert_eq!(tree.len(), 1);
    }
}
