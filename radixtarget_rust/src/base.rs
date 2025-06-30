// base.rs: Shared base node trait and helpers for radix trees
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Trait for nodes that can be pruned (base node for radix trees).
pub trait BaseNode {
    /// Returns true if the node is dead (no data, no children)
    fn is_dead(&self) -> bool;
    /// Returns mutable reference to children as a trait object
    fn children_mut(&mut self) -> &mut HashMap<u64, Box<Self>> where Self: Sized;
    /// Prune dead child nodes recursively, returns number pruned
    fn prune(&mut self) -> usize where Self: Sized {
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
}

pub fn siphash<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}
