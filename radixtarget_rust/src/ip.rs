use std::collections::{HashMap, HashSet};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use crate::base::{BaseNode, siphash};

#[derive(Debug, Clone)]
pub struct Node {
    pub children: HashMap<u64, Box<Node>>,
    pub network: Option<IpNet>,
}

impl Node {
    pub fn new() -> Self {
        Node {
            children: HashMap::new(),
            network: None,
        }
    }
    // Recursively prune dead child nodes (no network and no children).
    pub fn prune(&mut self) -> usize {
        let mut pruned = 0;
        loop {
            let mut new_pruned = 0;
            let keys: Vec<u64> = self.children.keys().copied().collect();
            for key in keys {
                if let Some(child) = self.children.get_mut(&key) {
                    new_pruned += child.prune();
                    if child.network.is_none() && child.children.is_empty() {
                        self.children.remove(&key);
                        new_pruned += 1;
                    }
                }
            }
            if new_pruned == 0 {
                break;
            }
            pruned += new_pruned;
        }
        pruned
    }
    /// Public iterator over all mergeable pairs of child nodes and their supernet.
    /// Yields (left_net, right_net, supernet) for each mergeable pair in the subtree.
    pub fn mergeable_pairs(&self) -> Vec<(IpNet, IpNet, IpNet)> {
        let mut pairs = Vec::new();
        // Check this node
        if self.children.len() == 2 {
            let mut iter = self.children.values();
            let left = iter.next().unwrap();
            let right = iter.next().unwrap();
            if let (Some(left_net), Some(right_net)) = (&left.network, &right.network) {
                if left_net.prefix_len() == right_net.prefix_len() &&
                   (matches!(left_net, IpNet::V4(_)) && matches!(right_net, IpNet::V4(_)) ||
                    matches!(left_net, IpNet::V6(_)) && matches!(right_net, IpNet::V6(_))) {
                    let prefix = left_net.prefix_len();
                    let supernet = match (left_net, right_net) {
                        (IpNet::V4(l), IpNet::V4(r)) => {
                            if prefix > 0 && prefix <= 32 {
                                let mask = if prefix == 32 {
                                    0xffffffffu32
                                } else {
                                    !(0xffffffffu32 >> prefix)
                                };
                                let l_addr = u32::from(l.network());
                                let r_addr = u32::from(r.network());
                                if (l_addr ^ r_addr) == (1 << (32 - prefix)) {
                                    let min_addr = l_addr.min(r_addr) & mask;
                                    Some(IpNet::V4(Ipv4Net::new(min_addr.into(), prefix - 1).unwrap()))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        (IpNet::V6(l), IpNet::V6(r)) => {
                            if prefix > 0 && prefix <= 128 {
                                let mask = if prefix == 128 {
                                    0xffffffffffffffffffffffffffffffffu128
                                } else {
                                    !(0xffffffffffffffffffffffffffffffffu128 >> prefix)
                                };
                                let l_addr = u128::from(l.network());
                                let r_addr = u128::from(r.network());
                                if (l_addr ^ r_addr) == (1 << (128 - prefix)) {
                                    let min_addr = l_addr.min(r_addr) & mask;
                                    Some(IpNet::V6(Ipv6Net::new(min_addr.into(), prefix - 1).unwrap()))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    if let Some(supernet) = supernet {
                        pairs.push((left_net.clone(), right_net.clone(), supernet));
                    }
                }
            }
        }
        // Recurse into children
        for child in self.children.values() {
            pairs.extend(child.mergeable_pairs());
        }
        pairs
    }
}

#[derive(Debug, Clone)]
pub struct IpRadixTree {
    pub root: Node,
}

impl IpRadixTree {
    pub fn new() -> Self {
        IpRadixTree {
            root: Node::new(),
        }
    }
    pub fn insert(&mut self, network: IpNet) -> u64 {
        let canonical = canonicalize_ipnet(&network);
        let mut node = &mut self.root;
        let bits = ipnet_to_bits(&canonical);
        for &bit in &bits {
            node = node.children.entry(u64::from(bit)).or_insert_with(|| Box::new(Node::new()));
        }
        node.network = Some(canonical.clone());
        siphash(&canonical)
    }
    pub fn get(&self, net: &IpNet) -> Option<u64> {
        let canonical = canonicalize_ipnet(net);
        let mut node = &self.root;
        let bits = ipnet_to_bits(&canonical);
        let mut best: Option<&IpNet> = None;
        if let Some(n) = &node.network {
            if n.contains(&canonical.network()) && n.prefix_len() <= canonical.prefix_len() {
                best = Some(n);
            }
        }
        for &bit in &bits {
            if let Some(child) = node.children.get(&u64::from(bit)) {
                node = child;
                if let Some(n) = &node.network {
                    if n.contains(&canonical.network()) && n.prefix_len() <= canonical.prefix_len() {
                        best = Some(n);
                    }
                }
            } else {
                break;
            }
        }
        best.map(|n| siphash(n))
    }
    pub fn delete(&mut self, network: IpNet) -> bool {
        let canonical = canonicalize_ipnet(&network);
        Self::delete_rec(&mut self.root, &ipnet_to_bits(&canonical), 0, &canonical)
    }
    fn delete_rec(node: &mut Node, bits: &[u8], depth: usize, network: &IpNet) -> bool {
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
                self.delete(left_net.clone());
                self.delete(right_net.clone());
                self.insert(supernet.clone());
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

fn ipnet_to_bits(net: &IpNet) -> Vec<u8> {
    let (addr, prefix) = match net {
        IpNet::V4(n) => (n.network().octets().to_vec(), net.prefix_len()),
        IpNet::V6(n) => (n.network().octets().to_vec(), net.prefix_len()),
    };
    let mut bits = Vec::with_capacity(prefix as usize);
    for byte in addr {
        for i in (0..8).rev() {
            if bits.len() == prefix as usize {
                return bits;
            }
            bits.push((byte >> i) & 1);
        }
    }
    bits
}

fn canonicalize_ipnet(network: &IpNet) -> IpNet {
    match network {
        IpNet::V4(n) => IpNet::V4(Ipv4Net::new(n.network(), n.prefix_len()).unwrap()),
        IpNet::V6(n) => IpNet::V6(Ipv6Net::new(n.network(), n.prefix_len()).unwrap()),
    }
}

impl BaseNode for Node {
    fn is_dead(&self) -> bool {
        self.network.is_none() && self.children.is_empty()
    }
    fn children_mut(&mut self) -> &mut HashMap<u64, Box<Node>> {
        &mut self.children
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::str::FromStr;
    use std::hash::{Hash, Hasher};

    fn expected_hash(net: &IpNet) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        net.hash(&mut hasher);
        hasher.finish()
    }

    /// Test basic insertion and lookup for both IPv4 and IPv6 networks.
    /// Ensures that inserted networks are found, and unrelated addresses are not.
    #[test]
    fn test_insert_and_get_ipv4_and_ipv6() {
        let mut tree = IpRadixTree::new();
        let net_v4 = IpNet::from_str("8.8.8.0/24").unwrap();
        let net_v6 = IpNet::from_str("dead::/64").unwrap();
        let hash_v4 = tree.insert(net_v4);
        assert_eq!(hash_v4, expected_hash(&net_v4), "insert(8.8.8.0/24) hash");
        let hash_v6 = tree.insert(net_v6);
        assert_eq!(hash_v6, expected_hash(&net_v6), "insert(dead::/64) hash");
        assert_eq!(tree.get(&IpNet::from_str("8.8.8.8/32").unwrap()), Some(expected_hash(&net_v4)));
        assert_eq!(tree.get(&IpNet::from_str("dead::beef/128").unwrap()), Some(expected_hash(&net_v6)));
        assert_eq!(tree.get(&IpNet::from_str("1.1.1.1/32").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("cafe::beef/128").unwrap()), None);
    }

    /// Test insertion of a network with host bits set (e.g., 192.168.1.42/24).
    /// The tree should sanitize the network to the correct base address and match all addresses in the subnet.
    #[test]
    fn test_insert_network_with_host_bits() {
        let mut tree = IpRadixTree::new();
        // 192.168.1.42/24 should be sanitized to 192.168.1.0/24
        let net = IpNet::from_str("192.168.1.0/24").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, expected_hash(&net), "insert(192.168.1.0/24) hash");
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.1/32").unwrap()), Some(expected_hash(&net)));
        assert_eq!(tree.get(&IpNet::from_str("192.168.2.1/32").unwrap()), None);
    }

    /// Test insertion and lookup of a single IP address as a /32 network.
    /// Ensures only the exact address matches.
    #[test]
    fn test_insert_single_ip() {
        let mut tree = IpRadixTree::new();
        let net = IpNet::from_str("10.0.0.1/32").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, expected_hash(&net), "insert(10.0.0.1/32) hash");
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.1/32").unwrap()), Some(expected_hash(&net)));
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.2/32").unwrap()), None);
    }

    /// Test overlapping networks and longest-prefix match logic.
    /// Ensures the most specific (longest prefix) network is returned for a given address.
    #[test]
    fn test_overlapping_and_longest_prefix() {
        let mut tree = IpRadixTree::new();
        let net1 = IpNet::from_str("10.0.0.0/8").unwrap();
        let net2 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net3 = IpNet::from_str("10.1.2.0/24").unwrap();
        let hash3 = tree.insert(net3);
        assert_eq!(hash3, expected_hash(&net3), "insert(10.1.2.0/24) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, expected_hash(&net2), "insert(10.1.0.0/16) hash");
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, expected_hash(&net1), "insert(10.0.0.0/8) hash");
        assert_eq!(tree.get(&IpNet::from_str("10.1.2.3/32").unwrap()), Some(expected_hash(&net3)));
        assert_eq!(tree.get(&IpNet::from_str("10.1.2.3/30").unwrap()), Some(expected_hash(&net3)));
        assert_eq!(tree.get(&IpNet::from_str("10.1.3.3/32").unwrap()), Some(expected_hash(&net2)));
        assert_eq!(tree.get(&IpNet::from_str("10.1.3.3/30").unwrap()), Some(expected_hash(&net2)));
        assert_eq!(tree.get(&IpNet::from_str("10.2.2.2/32").unwrap()), Some(expected_hash(&net1)));
        assert_eq!(tree.get(&IpNet::from_str("10.2.2.2/30").unwrap()), Some(expected_hash(&net1)));
    }

    /// Test IPv6 longest-prefix match logic.
    /// Ensures the most specific IPv6 network is returned for a given address.
    #[test]
    fn test_ipv6_longest_prefix() {
        let mut tree = IpRadixTree::new();
        // Insert overlapping networks in various orders, with and without host bits
        let net1 = IpNet::from_str("2001:db8::/32").unwrap();
        let net2 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        let net3 = IpNet::from_str("2001:db8:abcd:1234::/64").unwrap();
        let net4 = IpNet::from_str("2001:db8:abcd:1234:5678::/80").unwrap();
        // Insert out of order and with host bits
        let hash4 = tree.insert(IpNet::from_str("2001:db8:abcd:1234:5678:9abc::1/80").unwrap()); // net4
        assert_eq!(hash4, expected_hash(&net4), "insert(2001:db8:abcd:1234:5678::/80) hash");
        let hash3 = tree.insert(IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()); // net3
        assert_eq!(hash3, expected_hash(&net3), "insert(2001:db8:abcd:1234::/64) hash");
        let hash2 = tree.insert(IpNet::from_str("2001:db8:abcd::/48").unwrap()); // net2
        assert_eq!(hash2, expected_hash(&net2), "insert(2001:db8:abcd::/48) hash");
        let hash1 = tree.insert(IpNet::from_str("2001:db8::1/32").unwrap()); // net1
        assert_eq!(hash1, expected_hash(&net1), "insert(2001:db8::/32) hash");

        // Queries for most specific match
        // Should match net4
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234:5678:9abc::dead/128").unwrap()), Some(expected_hash(&net4)));
        // Should match net3
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234::beef/128").unwrap()), Some(expected_hash(&net3)));
        // Should match net2
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd::cafe/128").unwrap()), Some(expected_hash(&net2)));
        // Should match net1
        assert_eq!(tree.get(&IpNet::from_str("2001:db8::1234/128").unwrap()), Some(expected_hash(&net1)));

        // Queries with host bits and different prefix lengths
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234:5678:9abc::dead/81").unwrap()), Some(expected_hash(&net4)));
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234::beef/65").unwrap()), Some(expected_hash(&net3)));
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd::cafe/49").unwrap()), Some(expected_hash(&net2)));
        assert_eq!(tree.get(&IpNet::from_str("2001:db8::1234/33").unwrap()), Some(expected_hash(&net1)));

        // Query outside all networks
        assert_eq!(tree.get(&IpNet::from_str("2001:dead::1/128").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("3000::/32").unwrap()), None);
    }

    /// Test deletion combined with querying by network and host.
    /// Ensures that after deleting a network, the correct fallback (less specific) parent is returned, or None if no match remains.
    #[test]
    fn test_deletion_and_querying() {
        let mut tree = IpRadixTree::new();
        // Insert overlapping networks
        let net1 = IpNet::from_str("192.168.0.0/16").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let net3 = IpNet::from_str("192.168.1.128/25").unwrap();
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, expected_hash(&net1), "insert(192.168.0.0/16) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, expected_hash(&net2), "insert(192.168.1.0/24) hash");
        let hash3 = tree.insert(net3);
        assert_eq!(hash3, expected_hash(&net3), "insert(192.168.1.128/25) hash");
        // Query before deletion
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.128/25").unwrap()), Some(expected_hash(&net3))); // Most specific: /25
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()), Some(expected_hash(&net3)));
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.0/24").unwrap()), Some(expected_hash(&net2)));
        // Delete the most specific network
        assert!(tree.delete(IpNet::from_str("192.168.1.128/25").unwrap()));
        // Now queries in 192.168.1.128/25 should fall back to /24
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.128/25").unwrap()), Some(expected_hash(&net2)));
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()), Some(expected_hash(&net2)));
        // Delete the /24
        assert!(tree.delete(IpNet::from_str("192.168.1.0/24").unwrap()));
        // Now queries in 192.168.1.0/24 should fall back to /16
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()), Some(expected_hash(&net1)));
        // Delete the /16
        assert!(tree.delete(IpNet::from_str("192.168.0.0/16").unwrap()));
        // Now nothing should match
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.129/32").unwrap()), None);

        // IPv6 case
        let netv6_1 = IpNet::from_str("2001:db8::/32").unwrap();
        let netv6_2 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        let netv6_3 = IpNet::from_str("2001:db8:abcd:1234::/64").unwrap();
        let hashv6_1 = tree.insert(netv6_1);
        assert_eq!(hashv6_1, expected_hash(&netv6_1), "insert(2001:db8::/32) hash");
        let hashv6_2 = tree.insert(netv6_2);
        assert_eq!(hashv6_2, expected_hash(&netv6_2), "insert(2001:db8:abcd::/48) hash");
        let hashv6_3 = tree.insert(netv6_3);
        assert_eq!(hashv6_3, expected_hash(&netv6_3), "insert(2001:db8:abcd:1234::/64) hash");
        // Query before deletion
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()), Some(expected_hash(&netv6_3))); // Most specific: /64
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd::/48").unwrap()), Some(expected_hash(&netv6_2)));     // Most specific: /48
        assert_eq!(tree.get(&IpNet::from_str("2001:db8::/32").unwrap()), Some(expected_hash(&netv6_1)));          // Most specific: /32
        // Delete the most specific
        assert!(tree.delete(IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()));
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()), Some(expected_hash(&netv6_2)));
        // Delete the /48
        assert!(tree.delete(IpNet::from_str("2001:db8:abcd::/48").unwrap()));
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()), Some(expected_hash(&netv6_1)));
        // Delete the /32
        assert!(tree.delete(IpNet::from_str("2001:db8::/32").unwrap()));
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234::/64").unwrap()), None);
    }

    /// Test insertion and lookup with custom data types as values.
    /// Ensures the tree can store and retrieve arbitrary data.
    #[test]
    fn test_insert_with_custom_data_types() {
        let mut tree = IpRadixTree::new();
        let net = IpNet::from_str("8.8.8.0/24").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, expected_hash(&net), "insert(8.8.8.0/24) hash");
        assert_eq!(tree.get(&IpNet::from_str("8.8.8.8/32").unwrap()), Some(expected_hash(&net)));
    }

    /// Test insertion and lookup of a zero-prefix (default) IPv4 network.
    /// Ensures all IPv4 addresses match the default route.
    #[test]
    fn test_insert_and_get_zero_prefix() {
        let mut tree = IpRadixTree::new();
        let net = IpNet::from_str("0.0.0.0/0").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, expected_hash(&net), "insert(0.0.0.0/0) hash");
        assert_eq!(tree.get(&IpNet::from_str("1.2.3.4/32").unwrap()), Some(expected_hash(&net)));
        assert_eq!(tree.get(&IpNet::from_str("255.255.255.255/32").unwrap()), Some(expected_hash(&net)));
    }

    /// Test insertion and lookup of a zero-prefix (default) IPv6 network.
    /// Ensures all IPv6 addresses match the default route.
    #[test]
    fn test_insert_and_get_ipv6_zero_prefix() {
        let mut tree = IpRadixTree::new();
        let net = IpNet::from_str("::/0").unwrap();
        let hash = tree.insert(net);
        assert_eq!(hash, expected_hash(&net), "insert(::/0) hash");
        assert_eq!(tree.get(&IpNet::from_str("::1/128").unwrap()), Some(expected_hash(&net)));
        assert_eq!(tree.get(&IpNet::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap()), Some(expected_hash(&net)));
    }

    /// Test insertion and lookup of both IPv4 and IPv6 single-address networks in the same tree.
    /// Ensures both types can coexist and be queried independently.
    #[test]
    fn test_insert_and_get_multiple_types() {
        let mut tree = IpRadixTree::new();
        let net4 = IpNet::from_str("1.2.3.4/32").unwrap();
        let net6 = IpNet::from_str("dead::beef/128").unwrap();
        let hash4 = tree.insert(net4);
        assert_eq!(hash4, expected_hash(&net4), "insert(1.2.3.4/32) hash");
        let hash6 = tree.insert(net6);
        assert_eq!(hash6, expected_hash(&net6), "insert(dead::beef/128) hash");
        assert_eq!(tree.get(&IpNet::from_str("1.2.3.4/32").unwrap()), Some(expected_hash(&net4)));
        assert_eq!(tree.get(&IpNet::from_str("dead::beef/128").unwrap()), Some(expected_hash(&net6)));
    }

    /// Test insertion of an IPv6 network with host bits set.
    /// Ensures the tree sanitizes the network and matches all addresses in the subnet, but not outside.
    #[test]
    fn test_insert_and_get_with_host_bits_ipv6() {
        let mut tree = IpRadixTree::new();
        // Insert with host bits set; should normalize to dead:beef::0/120
        let inserted = IpNet::from_str("dead:beef::1/120").unwrap();
        let normalized = IpNet::from_str("dead:beef::0/120").unwrap();
        let hash = tree.insert(inserted);
        assert_eq!(hash, expected_hash(&normalized), "insert(dead:beef::0/120) hash");
        // Query with addresses within the /120
        assert_eq!(tree.get(&IpNet::from_str("dead:beef::2/128").unwrap()), Some(expected_hash(&normalized)));
        assert_eq!(tree.get(&IpNet::from_str("dead:beef::ff/128").unwrap()), Some(expected_hash(&normalized)));
        // Query with a network within the /120 (should normalize query)
        assert_eq!(tree.get(&IpNet::from_str("dead:beef::2/121").unwrap()), Some(expected_hash(&normalized)));
        // Query with an address outside the /120
        assert_eq!(tree.get(&IpNet::from_str("dead:beef::100/128").unwrap()), None);
        // Delete with host bits set (should normalize and delete the /120)
        assert!(tree.delete(IpNet::from_str("dead:beef::ff/120").unwrap()));
        // After deletion, nothing in the /120 should match
        assert_eq!(tree.get(&IpNet::from_str("dead:beef::2/128").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("dead:beef::ff/128").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("dead:beef::2/121").unwrap()), None);
    }

    /// Test querying by network string for both IPv4 and IPv6.
    /// Ensures that querying by network returns the correct data, matching the Python API.
    #[test]
    fn test_query_by_network() {
        let mut tree = IpRadixTree::new();
        let net_v4 = IpNet::from_str("8.8.8.0/24").unwrap();
        let net_v6 = IpNet::from_str("dead::/64").unwrap();
        let hash_v4 = tree.insert(net_v4);
        assert_eq!(hash_v4, expected_hash(&net_v4), "insert(8.8.8.0/24) hash");
        let hash_v6 = tree.insert(net_v6);
        assert_eq!(hash_v6, expected_hash(&net_v6), "insert(dead::/64) hash");
        // Query by network string
        assert_eq!(tree.get(&IpNet::from_str("8.8.8.0/24").unwrap()), Some(expected_hash(&net_v4)));
        assert_eq!(tree.get(&IpNet::from_str("dead::/64").unwrap()), Some(expected_hash(&net_v6)));
        // Query by non-existent network
        assert_eq!(tree.get(&IpNet::from_str("8.8.9.0/24").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("cafe::/64").unwrap()), None);
    }

    /// Test querying by overlapping networks, ensuring longest-prefix match for network queries.
    #[test]
    fn test_query_by_overlapping_networks() {
        let mut tree = IpRadixTree::new();
        let net1 = IpNet::from_str("10.0.0.0/8").unwrap();
        let net2 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net3 = IpNet::from_str("10.1.2.0/24").unwrap();
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, expected_hash(&net1), "insert(10.0.0.0/8) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, expected_hash(&net2), "insert(10.1.0.0/16) hash");
        let hash3 = tree.insert(net3);
        assert_eq!(hash3, expected_hash(&net3), "insert(10.1.2.0/24) hash");
        // Query by network string
        assert_eq!(tree.get(&IpNet::from_str("10.1.2.0/24").unwrap()), Some(expected_hash(&net3)));
        assert_eq!(tree.get(&IpNet::from_str("10.1.0.0/16").unwrap()), Some(expected_hash(&net2)));
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.0/8").unwrap()), Some(expected_hash(&net1)));
        // Query by less specific network (should match the most specific containing network)
        assert_eq!(tree.get(&IpNet::from_str("10.1.2.0/26").unwrap()), Some(expected_hash(&net3)));
        assert_eq!(tree.get(&IpNet::from_str("10.1.0.0/22").unwrap()), Some(expected_hash(&net2)));
        assert_eq!(tree.get(&IpNet::from_str("10.1.0.0/12").unwrap()), Some(expected_hash(&net1)));
        // Query by a network not contained by any inserted network
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.0/7").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("11.0.0.0/8").unwrap()), None);
    }

    /// Test querying by child networks (subnets) that aren't an exact match.
    /// Ensures the most specific (longest prefix) parent is returned for overlapping networks.
    #[test]
    fn test_query_by_child_networks_longest_prefix() {
        let mut tree = IpRadixTree::new();
        // Insert overlapping networks
        let net1 = IpNet::from_str("192.168.0.0/16").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let net3 = IpNet::from_str("192.168.1.128/25").unwrap();
        let hash1 = tree.insert(net1);
        assert_eq!(hash1, expected_hash(&net1), "insert(192.168.0.0/16) hash");
        let hash2 = tree.insert(net2);
        assert_eq!(hash2, expected_hash(&net2), "insert(192.168.1.0/24) hash");
        let hash3 = tree.insert(net3);
        assert_eq!(hash3, expected_hash(&net3), "insert(192.168.1.128/25) hash");
        // Query by a child network that is a subnet of both /16 and /24, but not an exact match
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.128/26").unwrap()), Some(expected_hash(&net3))); // Most specific: /25
        assert_eq!(tree.get(&IpNet::from_str("192.168.1.0/25").unwrap()), Some(expected_hash(&net2)));   // Most specific: /24
        assert_eq!(tree.get(&IpNet::from_str("192.168.2.0/24").unwrap()), Some(expected_hash(&net1)));   // Only /16 matches
        // Query by a network that doesn't match any
        assert_eq!(tree.get(&IpNet::from_str("10.0.0.0/8").unwrap()), None);

        // IPv6 case
        let netv6_1 = IpNet::from_str("2001:db8::/32").unwrap();
        let netv6_2 = IpNet::from_str("2001:db8:abcd::/48").unwrap();
        let netv6_3 = IpNet::from_str("2001:db8:abcd:1234::/64").unwrap();
        let hashv6_1 = tree.insert(netv6_1);
        assert_eq!(hashv6_1, expected_hash(&netv6_1), "insert(2001:db8::/32) hash");
        let hashv6_2 = tree.insert(netv6_2);
        assert_eq!(hashv6_2, expected_hash(&netv6_2), "insert(2001:db8:abcd::/48) hash");
        let hashv6_3 = tree.insert(netv6_3);
        assert_eq!(hashv6_3, expected_hash(&netv6_3), "insert(2001:db8:abcd:1234::/64) hash");
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd:1234::/80").unwrap()), Some(expected_hash(&netv6_3))); // Most specific: /64
        assert_eq!(tree.get(&IpNet::from_str("2001:db8:abcd::/56").unwrap()), Some(expected_hash(&netv6_2)));     // Most specific: /48
        assert_eq!(tree.get(&IpNet::from_str("2001:db8::/40").unwrap()), Some(expected_hash(&netv6_1)));          // Most specific: /32
        assert_eq!(tree.get(&IpNet::from_str("2001:dead::/32").unwrap()), None);              // No match
    }

    /// Test that IPv4 and IPv6 addresses with the same bits are treated as overlapping in a single IpNet-based tree.
    /// This is expected, as the tree does not distinguish between address families.
    #[test]
    fn test_ipv4_ipv6_same_bits_overlap() {
        let mut tree = IpRadixTree::new();
        // 1.0.0.0/30 (IPv4) and 100::/30 (IPv6) have the same first 30 bits
        let net4 = IpNet::from_str("1.0.0.0/30").unwrap();
        let net6 = IpNet::from_str("100::/30").unwrap();
        // Assert that the bit vectors for both networks are identical for the first 30 bits
        let expected_bits = vec![0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0];
        assert_eq!(ipnet_to_bits(&net4), expected_bits, "net4 bits did not match expected");
        assert_eq!(ipnet_to_bits(&net6), expected_bits, "net6 bits did not match expected");

        let hash4 = tree.insert(net4);
        assert_eq!(hash4, expected_hash(&net4), "insert(1.0.0.0/30) hash");
        assert_eq!(tree.get(&IpNet::from_str("1.0.0.1/30").unwrap()), Some(expected_hash(&net4)));

        let hash6 = tree.insert(net6);
        assert_eq!(hash6, expected_hash(&net6), "insert(100::/30) hash");
        assert_eq!(tree.get(&IpNet::from_str("100::1/30").unwrap()), Some(expected_hash(&net6)));

        // Oops, we clobbered our IPv4 network. This is expected, and the reason why we maintain 2 separate trees.
        assert_eq!(tree.get(&IpNet::from_str("1.0.0.1/30").unwrap()), None);
        assert_eq!(tree.get(&IpNet::from_str("100::1/30").unwrap()), Some(expected_hash(&net6)));
    }

    #[test]
    fn test_mergeable_pairs_two_children() {
        let net1 = IpNet::from_str("192.168.0.0/24").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let supernet = IpNet::from_str("192.168.0.0/23").unwrap();
        let mut parent = Node::new();
        let mut child1 = Box::new(Node::new());
        child1.network = Some(net1.clone());
        let mut child2 = Box::new(Node::new());
        child2.network = Some(net2.clone());
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
        let mut tree = IpRadixTree::new();
        let net1 = IpNet::from_str("192.168.0.0/24").unwrap();
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        let supernet = IpNet::from_str("192.168.0.0/23").unwrap();
        tree.insert(net1.clone());
        tree.insert(net2.clone());
        // Before defrag, lookups should return the /24s
        let ip1 = IpNet::from_str("192.168.0.1/32").unwrap();
        let ip2 = IpNet::from_str("192.168.1.1/32").unwrap();
        assert_eq!(tree.get(&ip1), Some(siphash(&net1)));
        assert_eq!(tree.get(&ip2), Some(siphash(&net2)));
        // Defrag
        let (cleaned, new) = tree.defrag();
        // The cleaned set should contain the two /24s, the new set should contain the /23
        assert!(cleaned.contains(&net1.to_string()));
        assert!(cleaned.contains(&net2.to_string()));
        assert!(new.contains(&supernet.to_string()));
        // After defrag, lookups should return the /23
        assert_eq!(tree.get(&ip1), Some(siphash(&supernet)));
        assert_eq!(tree.get(&ip2), Some(siphash(&supernet)));
    }
}