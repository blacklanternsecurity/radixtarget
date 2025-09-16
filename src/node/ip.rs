use super::base::BaseNode;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct IPNode {
    pub children: HashMap<u64, Box<IPNode>>,
    pub network: Option<IpNet>,
}

impl Default for IPNode {
    fn default() -> Self {
        Self::new()
    }
}

impl IPNode {
    pub fn new() -> Self {
        IPNode {
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
            if let (Some(left_net), Some(right_net)) = (&left.network, &right.network)
                && left_net.prefix_len() == right_net.prefix_len()
                && (matches!(left_net, IpNet::V4(_)) && matches!(right_net, IpNet::V4(_))
                    || matches!(left_net, IpNet::V6(_)) && matches!(right_net, IpNet::V6(_)))
            {
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
                                Some(IpNet::V4(
                                    Ipv4Net::new(min_addr.into(), prefix - 1).unwrap(),
                                ))
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
                                Some(IpNet::V6(
                                    Ipv6Net::new(min_addr.into(), prefix - 1).unwrap(),
                                ))
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
                    pairs.push((*left_net, *right_net, supernet));
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

impl BaseNode for IPNode {
    fn is_dead(&self) -> bool {
        self.network.is_none() && self.children.is_empty()
    }
    fn children_mut(&mut self) -> &mut HashMap<u64, Box<IPNode>> {
        &mut self.children
    }
    fn children(&self) -> &HashMap<u64, Box<IPNode>> {
        &self.children
    }
    fn host_string(&self) -> Option<String> {
        self.network.as_ref().map(|n| n.to_string())
    }
}
