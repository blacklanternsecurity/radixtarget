use crate::node::{BaseNode, IPNode};
use crate::utils::{canonicalize_ipnet, ipnet_to_bits};
use ipnet::IpNet;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct IpRadixTree {
    pub root: IPNode,
    pub acl_mode: bool,
}

impl IpRadixTree {
    pub fn new(acl_mode: bool) -> Self {
        IpRadixTree {
            root: IPNode::new(),
            acl_mode,
        }
    }
    pub fn insert(&mut self, network: IpNet) -> Option<String> {
        let canonical = canonicalize_ipnet(&network);

        // If ACL mode is enabled, check if the network is already covered by the tree
        if self.acl_mode && self.get(&canonical).is_some() {
            return None; // Skip insertion if already covered
        }

        let mut node = &mut self.root;
        let bits = ipnet_to_bits(&canonical);
        for &bit in &bits {
            node = node
                .children
                .entry(u64::from(bit))
                .or_insert_with(|| Box::new(IPNode::new()));
        }
        node.network = Some(canonical);

        // If ACL mode is enabled, clear children of the inserted node
        if self.acl_mode {
            node.clear();
        }

        Some(canonical.to_string())
    }
    pub fn get(&self, net: &IpNet) -> Option<String> {
        let canonical = canonicalize_ipnet(net);
        let mut node = &self.root;
        let bits = ipnet_to_bits(&canonical);
        let mut best: Option<&IpNet> = None;
        if let Some(n) = &node.network
            && n.contains(&canonical.network())
            && n.prefix_len() <= canonical.prefix_len()
        {
            best = Some(n);
        }
        for &bit in &bits {
            if let Some(child) = node.children.get(&u64::from(bit)) {
                node = child;
                if let Some(n) = &node.network
                    && n.contains(&canonical.network())
                    && n.prefix_len() <= canonical.prefix_len()
                {
                    best = Some(n);
                }
            } else {
                break;
            }
        }
        best.map(|n| n.to_string())
    }
    pub fn delete(&mut self, network: IpNet) -> bool {
        let canonical = canonicalize_ipnet(&network);
        Self::delete_rec(&mut self.root, &ipnet_to_bits(&canonical), 0, &canonical)
    }
    fn delete_rec(node: &mut IPNode, bits: &[u8], depth: usize, network: &IpNet) -> bool {
        if depth == bits.len() {
            if node.network.as_ref() == Some(network) {
                node.network = None;
                return true;
            }
            return false;
        }
        let bit = bits[depth];
        if let Some(child) = node.children.get_mut(&u64::from(bit)) {
            let deleted = Self::delete_rec(child, bits, depth + 1, network);
            if child.children.is_empty() && child.network.is_none() {
                node.children.remove(&u64::from(bit));
            }
            return deleted;
        }
        false
    }
    pub fn prune(&mut self) -> usize {
        self.root.prune()
    }

    /// Get all networks stored in the tree
    pub fn hosts(&self) -> HashSet<String> {
        self.root.all_hosts()
    }
    /// Defrag the entire tree, merging mergeable networks. Returns (cleaned, new) as sets of strings, with overlap removed.
    pub fn defrag(&mut self) -> (HashSet<String>, HashSet<String>) {
        let mut cleaned = HashSet::new();
        let mut new = HashSet::new();
        loop {
            let pairs = self.root.mergeable_pairs();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{canonicalize_ipnet, ipnet_to_bits};
    use ipnet::IpNet;
    use std::str::FromStr;

    /// Test basic insertion and lookup for both IPv4 and IPv6 networks.
    /// Ensures that inserted networks are found, and unrelated addresses are not.
    #[test]
    fn test_insert_and_get_ipv4_and_ipv6() {
        let mut tree = IpRadixTree::new(false);
        let net_v4 = IpNet::from_str("8.8.8.0/24").unwrap();
        let net_v6 = IpNet::from_str("dead::/64").unwrap();
        let hash_v4 = tree.insert(net_v4);
        assert_eq!(hash_v4, Some(net_v4.to_string()), "insert(8.8.8.0/24) hash");
        let hash_v6 = tree.insert(net_v6);
        assert_eq!(hash_v6, Some(net_v6.to_string()), "insert(dead::/64) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("8.8.8.8/32").unwrap()),
            Some(net_v4.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("dead::beef/128").unwrap()),
            Some(net_v6.to_string())
        );
        assert_eq!(tree.get(&IpNet::from_str("1.1.1.1/32").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("cafe::beef/128").unwrap()), None);
    }

    /// Test insertion of a network with host bits set (e.g., 192.168.1.42/24).
    /// The tree should sanitize the network to the correct base address and match all addresses in the subnet.
    #[test]
    fn test_insert_network_with_host_bits() {
        let mut tree = IpRadixTree::new(false);
        // 192.168.1.42/24 should be sanitized to 192.168.1.0/24
        let net = IpNet::from_str("192.168.1.0/24").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, Some(net.to_string()), "insert(192.168.1.0/24) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.1/32").unwrap()),
            Some(net.to_string())
        );
        assert_eq!(tree.get(&IpNet::from_str("192.168.2.1/32").unwrap()), None);
    }

    /// Test insertion and lookup of a single IP address as a /32 network.
    /// Ensures only the exact address matches.
    #[test]
    fn test_insert_single_ip() {
        let mut tree = IpRadixTree::new(false);
        let net = IpNet::from_str("10.0.0.1/32").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, Some(net.to_string()), "insert(10.0.0.1/32) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("10.0.0.1/32").unwrap()),
            Some(net.to_string())
        );
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.2/32").unwrap()), None);
    }

    /// Test overlapping networks and longest-prefix match logic.
    /// Ensures the most specific (longest prefix) network is returned for a given address.
    #[test]
    fn test_overlapping_and_longest_prefix() {
        let mut tree = IpRadixTree::new(false);
        let net1 = IpNet::from_str("10.0.0.0/8").unwrap();
        let net2 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net3 = IpNet::from_str("10.1.2.0/24").unwrap();
        let hash3 = tree.insert(net3);
        assert_eq!(hash3, Some(net3.to_string()), "insert(10.1.2.0/24) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, Some(net2.to_string()), "insert(10.1.0.0/16) hash");
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, Some(net1.to_string()), "insert(10.0.0.0/8) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.2.3/32").unwrap()),
            Some(net3.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.2.3/30").unwrap()),
            Some(net3.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.3.3/32").unwrap()),
            Some(net2.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.3.3/30").unwrap()),
            Some(net2.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.2.2.2/32").unwrap()),
            Some(net1.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.2.2.2/30").unwrap()),
            Some(net1.to_string())
        );
    }

    /// Test IPv6 longest-prefix match logic.
    /// Ensures the most specific IPv6 network is returned for a given address.
    #[test]
    fn test_ipv6_longest_prefix() {
        let mut tree = IpRadixTree::new(false);
        // Insert overlapping networks in various orders, with and without host bits
        let net1 = IpNet::from_str("2001:db8::/32").unwrap();
        let net2 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        let net3 = IpNet::from_str("2001:db8:abcd:1234::/64").unwrap();
        let net4 = IpNet::from_str("2001:db8:abcd:1234:5678::/80").unwrap();
        // Insert out of order and with host bits
        let hash4 = tree.insert(IpNet::from_str("2001:db8:abcd:1234:5678:9abc::1/80").unwrap()); // net4
        assert_eq!(
            hash4,
            Some(net4.to_string()),
            "insert(2001:db8:abcd:1234:5678::/80) hash"
        );
        let hash3 = tree.insert(IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()); // net3
        assert_eq!(
            hash3,
            Some(net3.to_string()),
            "insert(2001:db8:abcd:1234::/64) hash"
        );
        let hash2 = tree.insert(IpNet::from_str("2001:db8:abcd::/48").unwrap()); // net2
        assert_eq!(
            hash2,
            Some(net2.to_string()),
            "insert(2001:db8:abcd::/48) hash"
        );
        let hash1 = tree.insert(IpNet::from_str("2001:db8::1/32").unwrap()); // net1
        assert_eq!(hash1, Some(net1.to_string()), "insert(2001:db8::/32) hash");

        // Queries for most specific match
        // Should match net4
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234:5678:9abc::dead/128").unwrap()),
            Some(net4.to_string())
        );
        // Should match net3
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234::beef/128").unwrap()),
            Some(net3.to_string())
        );
        // Should match net2
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd::cafe/128").unwrap()),
            Some(net2.to_string())
        );
        // Should match net1
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8::1234/128").unwrap()),
            Some(net1.to_string())
        );

        // Queries with host bits and different prefix lengths
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234:5678:9abc::dead/81").unwrap()),
            Some(net4.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234::beef/65").unwrap()),
            Some(net3.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd::cafe/49").unwrap()),
            Some(net2.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8::1234/33").unwrap()),
            Some(net1.to_string())
        );

        // Query outside all networks
        assert_eq!(
            tree.get(&IpNet::from_str("2001:dead::1/128").unwrap()),
            None
        );
        assert_eq!(tree.get(&IpNet::from_str("3000::/32").unwrap()), None);
    }

    /// Test deletion combined with querying by network and host.
    /// Ensures that after deleting a network, the correct fallback (less specific) parent is returned, or None if no match remains.
    #[test]
    fn test_deletion_and_querying() {
        let mut tree = IpRadixTree::new(false);
        // Insert overlapping networks
        let net1 = IpNet::from_str("192.168.0.0/16").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let net3 = IpNet::from_str("192.168.1.128/25").unwrap();
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, Some(net1.to_string()), "insert(192.168.0.0/16) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, Some(net2.to_string()), "insert(192.168.1.0/24) hash");
        let hash3 = tree.insert(net3);
        assert_eq!(
            hash3,
            Some(net3.to_string()),
            "insert(192.168.1.128/25) hash"
        );
        // Query before deletion
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.128/25").unwrap()),
            Some(net3.to_string())
        ); // Most specific: /25
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()),
            Some(net3.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.0/24").unwrap()),
            Some(net2.to_string())
        );
        // Delete the most specific network
        assert!(tree.delete(IpNet::from_str("192.168.1.128/25").unwrap()));
        // Now queries in 192.168.1.128/25 should fall back to /24
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.128/25").unwrap()),
            Some(net2.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()),
            Some(net2.to_string())
        );
        // Delete the /24
        assert!(tree.delete(IpNet::from_str("192.168.1.0/24").unwrap()));
        // Now queries in 192.168.1.0/24 should fall back to /16
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()),
            Some(net1.to_string())
        );
        // Delete the /16
        assert!(tree.delete(IpNet::from_str("192.168.0.0/16").unwrap()));
        // Now nothing should match
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()),
            None
        );

        // IPv6 case
        let netv6_1 = IpNet::from_str("2001:db8::/32").unwrap();
        let netv6_2 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        let netv6_3 = IpNet::from_str("2001:db8:abcd:1234::/64").unwrap();
        let hashv6_1 = tree.insert(netv6_1);
        assert_eq!(
            hashv6_1,
            Some(netv6_1.to_string()),
            "insert(2001:db8::/32) hash"
        );
        let hashv6_2 = tree.insert(netv6_2);
        assert_eq!(
            hashv6_2,
            Some(netv6_2.to_string()),
            "insert(2001:db8:abcd::/48) hash"
        );
        let hashv6_3 = tree.insert(netv6_3);
        assert_eq!(
            hashv6_3,
            Some(netv6_3.to_string()),
            "insert(2001:db8:abcd:1234::/64) hash"
        );
        // Query before deletion
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()),
            Some(netv6_3.to_string())
        ); // Most specific: /64
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd::/48").unwrap()),
            Some(netv6_2.to_string())
        ); // Most specific: /48
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8::/32").unwrap()),
            Some(netv6_1.to_string())
        ); // Most specific: /32
        // Delete the most specific
        assert!(tree.delete(IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()));
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()),
            Some(netv6_2.to_string())
        );
        // Delete the /48
        assert!(tree.delete(IpNet::from_str("2001:db8:abcd::/48").unwrap()));
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()),
            Some(netv6_1.to_string())
        );
        // Delete the /32
        assert!(tree.delete(IpNet::from_str("2001:db8::/32").unwrap()));
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()),
            None
        );
    }

    /// Test insertion and lookup with custom data types as values.
    /// Ensures the tree can store and retrieve arbitrary data.
    #[test]
    fn test_insert_with_custom_data_types() {
        let mut tree = IpRadixTree::new(false);
        let net = IpNet::from_str("8.8.8.0/24").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, Some(net.to_string()), "insert(8.8.8.0/24) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("8.8.8.8/32").unwrap()),
            Some(net.to_string())
        );
    }

    /// Test insertion and lookup of a zero-prefix (default) IPv4 network.
    /// Ensures all IPv4 addresses match the default route.
    #[test]
    fn test_insert_and_get_zero_prefix() {
        let mut tree = IpRadixTree::new(false);
        let net = IpNet::from_str("0.0.0.0/0").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, Some(net.to_string()), "insert(0.0.0.0/0) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("1.2.3.4/32").unwrap()),
            Some(net.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("255.255.255.255/32").unwrap()),
            Some(net.to_string())
        );
    }

    /// Test insertion and lookup of a zero-prefix (default) IPv6 network.
    /// Ensures all IPv6 addresses match the default route.
    #[test]
    fn test_insert_and_get_ipv6_zero_prefix() {
        let mut tree = IpRadixTree::new(false);
        let net = IpNet::from_str("::/0").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, Some(net.to_string()), "insert(::/0) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("::1/128").unwrap()),
            Some(net.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap()),
            Some(net.to_string())
        );
    }

    /// Test insertion and lookup of both IPv4 and IPv6 single-address networks in the same tree.
    /// Ensures both types can coexist and be queried independently.
    #[test]
    fn test_insert_and_get_multiple_types() {
        let mut tree = IpRadixTree::new(false);
        let net4 = IpNet::from_str("1.2.3.4/32").unwrap();
        let net6 = IpNet::from_str("dead::beef/128").unwrap();
        let hash4 = tree.insert(net4);
        assert_eq!(hash4, Some(net4.to_string()), "insert(1.2.3.4/32) hash");
        let hash6 = tree.insert(net6);
        assert_eq!(hash6, Some(net6.to_string()), "insert(dead::beef/128) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("1.2.3.4/32").unwrap()),
            Some(net4.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("dead::beef/128").unwrap()),
            Some(net6.to_string())
        );
    }

    /// Test insertion of an IPv6 network with host bits set.
    /// Ensures the tree sanitizes the network and matches all addresses in the subnet, but not outside.
    #[test]
    fn test_insert_and_get_with_host_bits_ipv6() {
        let mut tree = IpRadixTree::new(false);
        // Insert with host bits set; should normalize to dead:beef::0/120
        let inserted = IpNet::from_str("dead:beef::1/120").unwrap();
        let normalized = IpNet::from_str("dead:beef::0/120").unwrap();
        let hash = tree.insert(inserted);
        assert_eq!(
            hash,
            Some(normalized.to_string()),
            "insert(dead:beef::0/120) hash"
        );
        // Query with addresses within the /120
        assert_eq!(
            tree.get(&IpNet::from_str("dead:beef::2/128").unwrap()),
            Some(normalized.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("dead:beef::ff/128").unwrap()),
            Some(normalized.to_string())
        );
        // Query with a network within the /120 (should normalize query)
        assert_eq!(
            tree.get(&IpNet::from_str("dead:beef::2/121").unwrap()),
            Some(normalized.to_string())
        );
        // Query with an address outside the /120
        assert_eq!(
            tree.get(&IpNet::from_str("dead:beef::100/128").unwrap()),
            None
        );
        // Delete with host bits set (should normalize and delete the /120)
        assert!(tree.delete(IpNet::from_str("dead:beef::ff/120").unwrap()));
        // After deletion, nothing in the /120 should match
        assert_eq!(
            tree.get(&IpNet::from_str("dead:beef::2/128").unwrap()),
            None
        );
        assert_eq!(
            tree.get(&IpNet::from_str("dead:beef::ff/128").unwrap()),
            None
        );
        assert_eq!(
            tree.get(&IpNet::from_str("dead:beef::2/121").unwrap()),
            None
        );
    }

    /// Test querying by network string for both IPv4 and IPv6.
    /// Ensures that querying by network returns the correct data, matching the Python API.
    #[test]
    fn test_query_by_network() {
        let mut tree = IpRadixTree::new(false);
        let net_v4 = IpNet::from_str("8.8.8.0/24").unwrap();
        let net_v6 = IpNet::from_str("dead::/64").unwrap();
        let hash_v4 = tree.insert(net_v4);
        assert_eq!(hash_v4, Some(net_v4.to_string()), "insert(8.8.8.0/24) hash");
        let hash_v6 = tree.insert(net_v6);
        assert_eq!(hash_v6, Some(net_v6.to_string()), "insert(dead::/64) hash");
        // Query by network string
        assert_eq!(
            tree.get(&IpNet::from_str("8.8.8.0/24").unwrap()),
            Some(net_v4.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("dead::/64").unwrap()),
            Some(net_v6.to_string())
        );
        // Query by non-existent network
        assert_eq!(tree.get(&IpNet::from_str("8.8.9.0/24").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("cafe::/64").unwrap()), None);
    }

    /// Test querying by overlapping networks, ensuring longest-prefix match for network queries.
    #[test]
    fn test_query_by_overlapping_networks() {
        let mut tree = IpRadixTree::new(false);
        let net1 = IpNet::from_str("10.0.0.0/8").unwrap();
        let net2 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net3 = IpNet::from_str("10.1.2.0/24").unwrap();
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, Some(net1.to_string()), "insert(10.0.0.0/8) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, Some(net2.to_string()), "insert(10.1.0.0/16) hash");
        let hash3 = tree.insert(net3);
        assert_eq!(hash3, Some(net3.to_string()), "insert(10.1.2.0/24) hash");
        // Query by network string
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.2.0/24").unwrap()),
            Some(net3.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.0.0/16").unwrap()),
            Some(net2.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.0.0.0/8").unwrap()),
            Some(net1.to_string())
        );
        // Query by less specific network (should match the most specific containing network)
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.2.0/26").unwrap()),
            Some(net3.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.0.0/22").unwrap()),
            Some(net2.to_string())
        );
        assert_eq!(
            tree.get(&IpNet::from_str("10.1.0.0/12").unwrap()),
            Some(net1.to_string())
        );
        // Query by a network not contained by any inserted network
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.0/7").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("11.0.0.0/8").unwrap()), None);
    }

    /// Test querying by child networks (subnets) that aren't an exact match.
    /// Ensures the most specific (longest prefix) parent is returned for overlapping networks.
    #[test]
    fn test_query_by_child_networks_longest_prefix() {
        let mut tree = IpRadixTree::new(false);
        // Insert overlapping networks
        let net1 = IpNet::from_str("192.168.0.0/16").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let net3 = IpNet::from_str("192.168.1.128/25").unwrap();
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, Some(net1.to_string()), "insert(192.168.0.0/16) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, Some(net2.to_string()), "insert(192.168.1.0/24) hash");
        let hash3 = tree.insert(net3);
        assert_eq!(
            hash3,
            Some(net3.to_string()),
            "insert(192.168.1.128/25) hash"
        );
        // Query by a child network that is a subnet of both /16 and /24, but not an exact match
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.128/26").unwrap()),
            Some(net3.to_string())
        ); // Most specific: /25
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.1.0/25").unwrap()),
            Some(net2.to_string())
        ); // Most specific: /24
        assert_eq!(
            tree.get(&IpNet::from_str("192.168.2.0/24").unwrap()),
            Some(net1.to_string())
        ); // Only /16 matches
        // Query by a network that doesn't match any
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.0/8").unwrap()), None);

        // IPv6 case
        let netv6_1 = IpNet::from_str("2001:db8::/32").unwrap();
        let netv6_2 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        let netv6_3 = IpNet::from_str("2001:db8:abcd:1234::/64").unwrap();
        let hashv6_1 = tree.insert(netv6_1);
        assert_eq!(
            hashv6_1,
            Some(netv6_1.to_string()),
            "insert(2001:db8::/32) hash"
        );
        let hashv6_2 = tree.insert(netv6_2);
        assert_eq!(
            hashv6_2,
            Some(netv6_2.to_string()),
            "insert(2001:db8:abcd::/48) hash"
        );
        let hashv6_3 = tree.insert(netv6_3);
        assert_eq!(
            hashv6_3,
            Some(netv6_3.to_string()),
            "insert(2001:db8:abcd:1234::/64) hash"
        );
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd:1234::/80").unwrap()),
            Some(netv6_3.to_string())
        ); // Most specific: /64
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8:abcd::/56").unwrap()),
            Some(netv6_2.to_string())
        ); // Most specific: /48
        assert_eq!(
            tree.get(&IpNet::from_str("2001:db8::/40").unwrap()),
            Some(netv6_1.to_string())
        ); // Most specific: /32
        assert_eq!(tree.get(&IpNet::from_str("2001:dead::/32").unwrap()), None); // No match
    }

    /// Test that IPv4 and IPv6 addresses with the same bits are treated as overlapping in a single IpNet-based tree.
    /// This is expected, as the tree does not distinguish between address families.
    #[test]
    fn test_ipv4_ipv6_same_bits_overlap() {
        let mut tree = IpRadixTree::new(false);
        // 1.0.0.0/30 (IPv4) and 100::/30 (IPv6) have the same first 30 bits
        let net4 = IpNet::from_str("1.0.0.0/30").unwrap();
        let net6 = IpNet::from_str("100::/30").unwrap();
        // Assert that the bit vectors for both networks are identical for the first 30 bits
        let expected_bits = vec![
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];
        assert_eq!(
            ipnet_to_bits(&net4),
            expected_bits,
            "net4 bits did not match expected"
        );
        assert_eq!(
            ipnet_to_bits(&net6),
            expected_bits,
            "net6 bits did not match expected"
        );

        let hash4 = tree.insert(net4);
        assert_eq!(hash4, Some(net4.to_string()), "insert(1.0.0.0/30) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("1.0.0.1/30").unwrap()),
            Some(net4.to_string())
        );

        let hash6 = tree.insert(net6);
        assert_eq!(hash6, Some(net6.to_string()), "insert(100::/30) hash");
        assert_eq!(
            tree.get(&IpNet::from_str("100::1/30").unwrap()),
            Some(net6.to_string())
        );

        // Oops, we clobbered our IPv4 network. This is expected, and the reason why we maintain 2 separate trees.
        assert_eq!(tree.get(&IpNet::from_str("1.0.0.1/30").unwrap()), None);
        assert_eq!(
            tree.get(&IpNet::from_str("100::1/30").unwrap()),
            Some(net6.to_string())
        );
    }

    #[test]
    fn test_mergeable_pairs_two_children() {
        let net1 = IpNet::from_str("192.168.0.0/24").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let supernet = IpNet::from_str("192.168.0.0/23").unwrap();
        let mut parent = IPNode::new();
        let mut child1 = Box::new(IPNode::new());
        child1.network = Some(net1);
        let mut child2 = Box::new(IPNode::new());
        child2.network = Some(net2);
        parent.children.insert(0, child1);
        parent.children.insert(1, child2);

        let pairs = parent.mergeable_pairs();
        assert_eq!(pairs.len(), 1);
        let (left, right, merged) = &pairs[0];
        // The pair should be the two /24s, and the merged should be the /23
        assert!(
            (left == &net1 && right == &net2) || (left == &net2 && right == &net1),
            "Pair should be the two /24s"
        );
        assert_eq!(merged, &supernet, "Merged should be the /23");
    }

    #[test]
    fn test_ipradix_defrag_merge() {
        let mut tree = IpRadixTree::new(false);
        let net1 = IpNet::from_str("192.168.0.0/24").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let supernet = IpNet::from_str("192.168.0.0/23").unwrap();
        tree.insert(net1);
        tree.insert(net2);
        // Before defrag, lookups should return the /24s
        let ip1 = IpNet::from_str("192.168.0.1/32").unwrap();
        let ip2 = IpNet::from_str("192.168.1.1/32").unwrap();
        assert_eq!(tree.get(&ip1), Some(net1.to_string()));
        assert_eq!(tree.get(&ip2), Some(net2.to_string()));
        // Defrag
        let (cleaned, new) = tree.defrag();
        // The cleaned set should contain the two /24s, the new set should contain the /23
        assert!(cleaned.contains(&net1.to_string()));
        assert!(cleaned.contains(&net2.to_string()));
        assert!(new.contains(&supernet.to_string()));
        // After defrag, lookups should return the /23
        assert_eq!(tree.get(&ip1), Some(supernet.to_string()));
        assert_eq!(tree.get(&ip2), Some(supernet.to_string()));
    }

    #[test]
    fn test_clear_method() {
        use crate::node::BaseNode;

        let mut tree = IpRadixTree::new(false);

        // Insert networks in random order
        let mut networks = vec![
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.1.1.0/24",
            "10.1.2.0/24",
            "10.1.1.128/25",
            "10.1.1.192/26",
            "10.1.1.224/27",
            "10.1.1.240/28",
            "192.168.0.0/16",
            "192.168.1.0/24",
        ];

        // Shuffle randomly
        use rand::seq::SliceRandom;
        use rand::thread_rng;
        networks.shuffle(&mut thread_rng());

        for net_str in &networks {
            let net = IpNet::from_str(net_str).unwrap();
            tree.insert(net);
        }

        // Verify all networks are present
        for net_str in &networks {
            let net = IpNet::from_str(net_str).unwrap();
            assert!(
                tree.get(&net).is_some(),
                "Network {} should be present",
                net_str
            );
        }

        // Find the node for "10.1.1.0/24" and clear it
        let target_net = IpNet::from_str("10.1.1.0/24").unwrap();
        let canonical = canonicalize_ipnet(&target_net);
        let mut node = &mut tree.root;
        let bits = ipnet_to_bits(&canonical);
        for &bit in &bits {
            node = node
                .children
                .get_mut(&u64::from(bit))
                .expect("Node should exist");
        }

        // Clear the 10.1.1.0/24 node (should clear its children)
        let cleared_hosts = node.clear();

        // Should have cleared: 10.1.1.128/25, 10.1.1.192/26, 10.1.1.224/27, 10.1.1.240/28
        let expected_cleared = vec![
            "10.1.1.128/25",
            "10.1.1.192/26",
            "10.1.1.224/27",
            "10.1.1.240/28",
        ];

        assert_eq!(
            cleared_hosts.len(),
            expected_cleared.len(),
            "Should have cleared {} networks, got {}: {:?}",
            expected_cleared.len(),
            cleared_hosts.len(),
            cleared_hosts
        );

        // Check that all expected networks were cleared
        for expected in &expected_cleared {
            assert!(
                cleared_hosts.contains(&expected.to_string()),
                "Should have cleared {}",
                expected
            );
        }

        // Verify the cleared networks are no longer accessible or fall back to parent
        for cleared in &expected_cleared {
            let net = IpNet::from_str(cleared).unwrap();
            let result = tree.get(&net);
            assert!(
                result.is_none() || result == Some("10.1.1.0/24".to_string()),
                "Cleared network {} should not be accessible or should fall back to parent",
                cleared
            );
        }

        // Verify that 10.1.1.0/24 itself is still accessible
        assert_eq!(tree.get(&target_net), Some("10.1.1.0/24".to_string()));

        // Verify that unrelated networks are still accessible
        let unrelated = vec![
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.1.2.0/24",
            "192.168.0.0/16",
            "192.168.1.0/24",
        ];
        for net_str in &unrelated {
            let net = IpNet::from_str(net_str).unwrap();
            assert_eq!(
                tree.get(&net),
                Some(net_str.to_string()),
                "Unrelated network {} should still be accessible",
                net_str
            );
        }
    }

    #[test]
    fn test_acl_mode_skip_existing() {
        let mut tree = IpRadixTree::new(true);

        // First insertion should succeed
        let net = IpNet::from_str("192.168.1.0/24").unwrap();
        let result1 = tree.insert(net);
        assert_eq!(result1, Some("192.168.1.0/24".to_string()));

        // Second insertion of same network should return None
        let result2 = tree.insert(net);
        assert_eq!(result2, None);

        // Different network should still work
        let other_net = IpNet::from_str("10.0.0.0/8").unwrap();
        let result3 = tree.insert(other_net);
        assert_eq!(result3, Some("10.0.0.0/8".to_string()));

        // Verify both networks are accessible
        assert_eq!(tree.get(&net), Some("192.168.1.0/24".to_string()));
        assert_eq!(tree.get(&other_net), Some("10.0.0.0/8".to_string()));
    }

    #[test]
    fn test_acl_mode_skip_children() {
        let mut tree = IpRadixTree::new(true);

        // Insert parent network first
        let parent = IpNet::from_str("192.168.0.0/16").unwrap();
        assert_eq!(tree.insert(parent), Some("192.168.0.0/16".to_string()));
        assert_eq!(tree.get(&parent), Some("192.168.0.0/16".to_string()));

        // Insert child network should return None (already covered by parent)
        let child = IpNet::from_str("192.168.1.0/24").unwrap();
        assert_eq!(tree.insert(child), None);

        // Get child network should return parent
        assert_eq!(tree.get(&child), Some("192.168.0.0/16".to_string()));

        // Test with IPv6 as well
        let parent_v6 = IpNet::from_str("2001:db8::/32").unwrap();
        assert_eq!(tree.insert(parent_v6), Some("2001:db8::/32".to_string()));

        let child_v6 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        assert_eq!(tree.insert(child_v6), None);
        assert_eq!(tree.get(&child_v6), Some("2001:db8::/32".to_string()));
    }

    #[test]
    fn test_acl_mode_clear_children() {
        let mut tree = IpRadixTree::new(true);

        // Insert child networks first
        let child1 = IpNet::from_str("192.168.1.0/24").unwrap();
        let child2 = IpNet::from_str("192.168.2.0/24").unwrap();
        let child3 = IpNet::from_str("192.168.3.0/24").unwrap();

        tree.insert(child1);
        tree.insert(child2);
        tree.insert(child3);

        // Verify children are accessible
        assert_eq!(tree.get(&child1), Some("192.168.1.0/24".to_string()));
        assert_eq!(tree.get(&child2), Some("192.168.2.0/24".to_string()));
        assert_eq!(tree.get(&child3), Some("192.168.3.0/24".to_string()));

        // Insert parent network - should clear children
        let parent = IpNet::from_str("192.168.0.0/16").unwrap();
        let result = tree.insert(parent);
        assert_eq!(result, Some("192.168.0.0/16".to_string()));

        // Parent should be accessible
        assert_eq!(tree.get(&parent), Some("192.168.0.0/16".to_string()));

        // Children should now fall back to parent
        assert_eq!(tree.get(&child1), Some("192.168.0.0/16".to_string()));
        assert_eq!(tree.get(&child2), Some("192.168.0.0/16".to_string()));
        assert_eq!(tree.get(&child3), Some("192.168.0.0/16".to_string()));

        // Test with IPv6 as well
        let child_v6_1 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        let child_v6_2 = IpNet::from_str("2001:db8:beef::/48").unwrap();

        tree.insert(child_v6_1);
        tree.insert(child_v6_2);

        assert_eq!(
            tree.get(&child_v6_1),
            Some("2001:db8:abcd::/48".to_string())
        );
        assert_eq!(
            tree.get(&child_v6_2),
            Some("2001:db8:beef::/48".to_string())
        );

        // Insert parent IPv6 network
        let parent_v6 = IpNet::from_str("2001:db8::/32").unwrap();
        let result_v6 = tree.insert(parent_v6);
        assert_eq!(result_v6, Some("2001:db8::/32".to_string()));

        // Children should fall back to parent
        assert_eq!(tree.get(&child_v6_1), Some("2001:db8::/32".to_string()));
        assert_eq!(tree.get(&child_v6_2), Some("2001:db8::/32".to_string()));
    }
}
