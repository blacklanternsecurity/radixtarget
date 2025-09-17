// base.rs: Shared base node trait for radix trees
use std::collections::{HashMap, HashSet};

/// Trait for nodes that can be pruned (base node for radix trees).
pub trait BaseNode {
    /// Returns true if the node is dead (no data, no children)
    fn is_dead(&self) -> bool;
    /// Returns mutable reference to children as a trait object
    fn children_mut(&mut self) -> &mut HashMap<u64, Box<Self>>
    where
        Self: Sized;
    /// Returns immutable reference to children
    fn children(&self) -> &HashMap<u64, Box<Self>>
    where
        Self: Sized;
    /// Returns the host as a string if present
    fn host_string(&self) -> Option<String>;
    /// Prune dead child nodes recursively, returns number pruned
    fn prune(&mut self) -> usize
    where
        Self: Sized,
    {
        let mut pruned = 0;
        let keys: Vec<u64> = self.children_mut().keys().copied().collect();
        for key in keys {
            if let Some(child) = self.children_mut().get_mut(&key) {
                pruned += child.prune();
                if child.is_dead() {
                    self.children_mut().remove(&key);
                    pruned += 1;
                }
            }
        }
        pruned
    }
    /// Clear all children recursively and return deleted hosts
    fn clear(&mut self) -> Vec<String>
    where
        Self: Sized,
    {
        let mut hosts = Vec::new();
        for (_, child) in self.children_mut().iter_mut() {
            hosts.extend(child.clear());
            if let Some(host) = child.host_string() {
                hosts.push(host);
            }
        }
        self.children_mut().clear();
        hosts
    }

    /// Get all hosts in this subtree
    fn all_hosts(&self) -> HashSet<String>
    where
        Self: Sized,
    {
        let mut hosts = HashSet::new();
        if let Some(host) = self.host_string() {
            hosts.insert(host);
        }
        for child in self.children().values() {
            hosts.extend(child.all_hosts());
        }
        hosts
    }
}
