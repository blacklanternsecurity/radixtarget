// Fast IP radix tree using tree-bitmap algorithm
use crate::treebitmap::FastTreeBitmap;
use crate::utils::canonicalize_ipnet;
use ipnet::IpNet;
use std::collections::HashSet;

// IPv4 and IPv6 live in separate trees: the tree is keyed on address bits only,
// so sharing one would let e.g. 7ea4:c5d8:: match 126.164.197.216.
#[derive(Debug)]
pub struct FastIpRadixTree {
    v4: FastTreeBitmap,
    v6: FastTreeBitmap,
    acl_mode: bool,
}

impl FastIpRadixTree {
    pub fn new(acl_mode: bool) -> Self {
        Self {
            v4: FastTreeBitmap::new(),
            v6: FastTreeBitmap::new(),
            acl_mode,
        }
    }

    pub fn with_capacity(capacity: usize, acl_mode: bool) -> Self {
        Self {
            v4: FastTreeBitmap::with_capacity(capacity),
            v6: FastTreeBitmap::with_capacity(capacity),
            acl_mode,
        }
    }

    fn tree(&self, net: &IpNet) -> &FastTreeBitmap {
        match net {
            IpNet::V4(_) => &self.v4,
            IpNet::V6(_) => &self.v6,
        }
    }

    fn tree_mut(&mut self, net: &IpNet) -> &mut FastTreeBitmap {
        match net {
            IpNet::V4(_) => &mut self.v4,
            IpNet::V6(_) => &mut self.v6,
        }
    }

    fn all_networks(&self) -> impl Iterator<Item = IpNet> {
        self.v4
            .all_networks()
            .into_iter()
            .chain(self.v6.all_networks())
    }

    pub fn insert(&mut self, network: IpNet) -> Option<String> {
        let canonical = canonicalize_ipnet(&network);

        if self.acl_mode {
            // Skip insertion if already covered
            if self.get(&canonical).is_some() {
                return None;
            }
            // Drop networks the new one covers
            for covered in self.tree(&canonical).covered_by(&canonical) {
                self.tree_mut(&canonical).remove(&covered);
            }
        }

        self.tree_mut(&canonical).insert(canonical);
        Some(canonical.to_string())
    }

    pub fn get(&self, net: &IpNet) -> Option<String> {
        let canonical = canonicalize_ipnet(net);
        // Most specific stored network that contains the given network
        self.tree(&canonical)
            .longest_match(&canonical)
            .map(|n| n.to_string())
    }

    pub fn delete(&mut self, network: IpNet) -> bool {
        let canonical = canonicalize_ipnet(&network);
        self.tree_mut(&canonical).remove(&canonical).is_some()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn prune(&mut self) -> usize {
        // Tree-bitmap doesn't need pruning like the old HashMap-based implementation
        0
    }

    pub fn hosts(&self) -> HashSet<String> {
        self.all_networks().map(|n| n.to_string()).collect()
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

    /// Sibling pairs that can merge into their supernet, e.g. 10.0.0.0/25 + 10.0.0.128/25.
    fn find_mergeable_pairs(&self) -> Vec<(IpNet, IpNet, IpNet)> {
        let mut pairs = Vec::new();
        for network in self.all_networks() {
            let Some(supernet) = network.supernet() else {
                continue; // Can't merge default routes
            };
            let mut halves = supernet.subnets(network.prefix_len()).unwrap();
            let (lower, upper) = (halves.next().unwrap(), halves.next().unwrap());
            // Visit each pair once, from its lower half
            if network == lower && self.tree(&upper).exact_match(&upper).is_some() {
                pairs.push((lower, upper, supernet));
            }
        }
        pairs
    }
}

impl Clone for FastIpRadixTree {
    fn clone(&self) -> Self {
        let mut new_tree = FastIpRadixTree::new(self.acl_mode);
        // Copy all networks from the original tree
        for network in self.all_networks() {
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

    /// Random networks packed into a small space so they overlap often.
    fn random_net(rng: &mut rand::rngs::StdRng) -> IpNet {
        use rand::Rng;
        if rng.gen_bool(0.5) {
            let addr = std::net::Ipv4Addr::from(0x0a00_0000 | rng.gen_range(0..=0xffffu32));
            IpNet::V4(ipnet::Ipv4Net::new(addr, rng.gen_range(12..=32)).unwrap()).trunc()
        } else {
            let addr =
                std::net::Ipv6Addr::from((0x2001_0db8u128 << 96) | rng.gen_range(0..=0xffffu128));
            IpNet::V6(ipnet::Ipv6Net::new(addr, rng.gen_range(108..=128)).unwrap()).trunc()
        }
    }

    /// Reference: the original bit-per-level tree, one per address family.
    struct Reference {
        v4: crate::ip::IpRadixTree,
        v6: crate::ip::IpRadixTree,
    }

    impl Reference {
        fn new(acl_mode: bool) -> Self {
            Self {
                v4: crate::ip::IpRadixTree::new(acl_mode),
                v6: crate::ip::IpRadixTree::new(acl_mode),
            }
        }
        fn tree(&mut self, net: &IpNet) -> &mut crate::ip::IpRadixTree {
            match net {
                IpNet::V4(_) => &mut self.v4,
                IpNet::V6(_) => &mut self.v6,
            }
        }
        fn hosts(&self) -> HashSet<String> {
            self.v4.hosts().union(&self.v6.hosts()).cloned().collect()
        }
    }

    #[test]
    fn test_matches_reference_tree() {
        use rand::{Rng, SeedableRng};
        for acl_mode in [false, true] {
            for seed in 0..20 {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
                let mut fast = FastIpRadixTree::new(acl_mode);
                let mut reference = Reference::new(acl_mode);
                for _ in 0..2000 {
                    let net = random_net(&mut rng);
                    match rng.gen_range(0..10) {
                        0..=3 => assert_eq!(
                            fast.insert(net),
                            reference.tree(&net).insert(net),
                            "insert {net} (acl={acl_mode}, seed={seed})"
                        ),
                        4 => assert_eq!(
                            fast.delete(net),
                            reference.tree(&net).delete(net),
                            "delete {net} (acl={acl_mode}, seed={seed})"
                        ),
                        _ => assert_eq!(
                            fast.get(&net),
                            reference.tree(&net).get(&net),
                            "get {net} (acl={acl_mode}, seed={seed})"
                        ),
                    }
                }
                assert_eq!(
                    fast.hosts(),
                    reference.hosts(),
                    "hosts (acl={acl_mode}, seed={seed})"
                );
                assert_eq!(fast.len(), reference.hosts().len());

                let (fast_cleaned, fast_new) = fast.defrag();
                let (v4_cleaned, v4_new) = reference.v4.defrag();
                let (v6_cleaned, v6_new) = reference.v6.defrag();
                assert_eq!(
                    fast_cleaned,
                    &v4_cleaned | &v6_cleaned,
                    "defrag cleaned (seed={seed})"
                );
                assert_eq!(fast_new, &v4_new | &v6_new, "defrag new (seed={seed})");
                assert_eq!(
                    fast.hosts(),
                    reference.hosts(),
                    "hosts after defrag (seed={seed})"
                );
            }
        }
    }
}
