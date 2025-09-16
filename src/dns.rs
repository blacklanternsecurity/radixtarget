// DNSRadixTree: A radix tree for efficient DNS hostname lookups.
// Hostnames are stored in reverse order (TLD to subdomain) for hierarchical matching.
// Inspired by the Python implementation in dns.py.
use crate::node::{BaseNode, DnsNode, hash_u64};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeMode {
    /// Normal mode - standard radix tree behavior
    Normal,
    /// Strict scope mode - more restrictive matching
    Strict,
    /// ACL mode - access control list behavior
    Acl,
}

#[derive(Debug, Clone)]
pub struct DnsRadixTree {
    pub root: DnsNode,
    pub scope_mode: ScopeMode,
}

impl DnsRadixTree {
    pub fn new(scope_mode: ScopeMode) -> Self {
        DnsRadixTree {
            root: DnsNode::new(),
            scope_mode,
        }
    }

    /// Insert a hostname into the tree, storing parts in reverse order for hierarchy.
    /// Returns the canonicalized hostname after insertion, or None if already exists in ACL mode.
    pub fn insert(&mut self, hostname: &str) -> Option<String> {
        // If ACL mode is enabled, check if the host is already covered by the tree
        if self.scope_mode == ScopeMode::Acl && self.get(hostname).is_some() {
            return None; // Skip insertion if already covered
        }

        let parts: Vec<&str> = hostname.split('.').collect();
        let mut node = &mut self.root;
        for part in parts.iter().rev() {
            node = node
                .children
                .entry(hash_u64(part))
                .or_insert_with(|| Box::new(DnsNode::new()));
        }
        node.host = Some(hostname.to_string());

        // If ACL mode is enabled, clear children of the inserted node
        if self.scope_mode == ScopeMode::Acl {
            node.clear();
        }

        Some(hostname.to_string())
    }

    /// Find the most specific matching entry for a given hostname.
    /// If strict_scope is true, only exact matches are allowed.
    /// Returns the canonicalized hostname if found.
    pub fn get(&self, hostname: &str) -> Option<String> {
        let parts: Vec<&str> = hostname.split('.').collect();
        let mut node = &self.root;
        let mut matched: Option<&String> = None;
        for (i, part) in parts.iter().rev().enumerate() {
            if let Some(child) = node.children.get(&hash_u64(part)) {
                node = child;
                if self.scope_mode == ScopeMode::Strict && i + 1 < parts.len() {
                    continue;
                }
                if let Some(host) = &node.host {
                    matched = Some(host);
                }
            } else {
                break;
            }
        }
        matched.cloned()
    }

    /// Delete a hostname from the tree.
    /// Returns true if the hostname was found and deleted.
    pub fn delete(&mut self, hostname: &str) -> bool {
        let parts: Vec<&str> = hostname.split('.').collect();
        Self::delete_rec(&mut self.root, &parts, 0)
    }

    /// Recursive helper for deletion.
    fn delete_rec(node: &mut DnsNode, parts: &[&str], depth: usize) -> bool {
        if depth == parts.len() {
            if node.host.is_some() {
                node.host = None;
                return true;
            }
            return false;
        }
        let part = parts[parts.len() - 1 - depth];
        if let Some(child) = node.children.get_mut(&hash_u64(part)) {
            let deleted = Self::delete_rec(child, parts, depth + 1);
            if child.children.is_empty() && child.host.is_none() {
                node.children.remove(&hash_u64(part));
            }
            return deleted;
        }
        false
    }

    pub fn prune(&mut self) -> usize {
        self.root.prune()
    }

    /// Get all hostnames stored in the tree
    pub fn hosts(&self) -> HashSet<String> {
        self.root.all_hosts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_canonical(host: &str) -> String {
        host.to_lowercase()
    }

    #[test]
    fn test_insert_and_get_basic() {
        let mut tree = DnsRadixTree::new(ScopeMode::Normal);
        let canonical1 = tree.insert("example.com").unwrap();
        assert_eq!(
            canonical1,
            expected_canonical("example.com"),
            "insert(example.com) canonical"
        );
        let canonical2 = tree.insert("api.test.www.example.com").unwrap();
        assert_eq!(
            canonical2,
            expected_canonical("api.test.www.example.com"),
            "insert(api.test.www.example.com) canonical"
        );
        assert_eq!(
            tree.get("example.com"),
            Some(expected_canonical("example.com"))
        );
        assert_eq!(
            tree.get("api.test.www.example.com"),
            Some(expected_canonical("api.test.www.example.com"))
        );
        // Subdomain matching
        assert_eq!(
            tree.get("wat.hm.api.test.www.example.com"),
            Some(expected_canonical("api.test.www.example.com"))
        );
        // No match
        assert_eq!(tree.get("notfound.com"), None);
    }

    #[test]
    fn test_strict_scope() {
        let mut tree = DnsRadixTree::new(ScopeMode::Strict);
        let canonical1 = tree.insert("example.com").unwrap();
        assert_eq!(
            canonical1,
            expected_canonical("example.com"),
            "insert(example.com) canonical"
        );
        let canonical2 = tree.insert("api.test.www.example.com").unwrap();
        assert_eq!(
            canonical2,
            expected_canonical("api.test.www.example.com"),
            "insert(api.test.www.example.com) canonical"
        );
        // Only exact matches
        assert_eq!(
            tree.get("example.com"),
            Some(expected_canonical("example.com"))
        );
        assert_eq!(
            tree.get("api.test.www.example.com"),
            Some(expected_canonical("api.test.www.example.com"))
        );
        assert_eq!(tree.get("wat.hm.api.test.www.example.com"), None);
        assert_eq!(tree.get("notfound.com"), None);
    }

    #[test]
    fn test_delete() {
        let mut tree = DnsRadixTree::new(ScopeMode::Normal);
        let canonical1 = tree.insert("example.com").unwrap();
        assert_eq!(
            canonical1,
            expected_canonical("example.com"),
            "insert(example.com) canonical"
        );
        let canonical2 = tree.insert("api.test.www.example.com").unwrap();
        assert_eq!(
            canonical2,
            expected_canonical("api.test.www.example.com"),
            "insert(api.test.www.example.com) canonical"
        );
        assert_eq!(
            tree.get("example.com"),
            Some(expected_canonical("example.com"))
        );
        assert!(tree.delete("example.com"));
        assert_eq!(tree.get("example.com"), None);
        // Deleting again should fail
        assert!(!tree.delete("example.com"));
        // Subdomain should still match the more specific
        assert_eq!(
            tree.get("wat.hm.api.test.www.example.com"),
            Some(expected_canonical("api.test.www.example.com"))
        );
        assert!(tree.delete("api.test.www.example.com"));
        assert_eq!(tree.get("wat.hm.api.test.www.example.com"), None);
    }

    #[test]
    fn test_subdomain_matching() {
        let mut tree = DnsRadixTree::new(ScopeMode::Normal);
        let canonical1 = tree.insert("evilcorp.com").unwrap();
        assert_eq!(
            canonical1,
            expected_canonical("evilcorp.com"),
            "insert(evilcorp.com) canonical"
        );
        let canonical2 = tree.insert("www.evilcorp.com").unwrap();
        assert_eq!(
            canonical2,
            expected_canonical("www.evilcorp.com"),
            "insert(www.evilcorp.com) canonical"
        );
        let canonical3 = tree.insert("test.www.evilcorp.com").unwrap();
        assert_eq!(
            canonical3,
            expected_canonical("test.www.evilcorp.com"),
            "insert(test.www.evilcorp.com) canonical"
        );
        let canonical4 = tree.insert("api.test.www.evilcorp.com").unwrap();
        assert_eq!(
            canonical4,
            expected_canonical("api.test.www.evilcorp.com"),
            "insert(api.test.www.evilcorp.com) canonical"
        );
        assert_eq!(
            tree.get("api.test.www.evilcorp.com"),
            Some(expected_canonical("api.test.www.evilcorp.com"))
        );
        assert_eq!(
            tree.get("test.www.evilcorp.com"),
            Some(expected_canonical("test.www.evilcorp.com"))
        );
        assert_eq!(
            tree.get("www.evilcorp.com"),
            Some(expected_canonical("www.evilcorp.com"))
        );
        assert_eq!(
            tree.get("evilcorp.com"),
            Some(expected_canonical("evilcorp.com"))
        );
        // Subdomain matching
        assert_eq!(
            tree.get("wat.hm.api.test.www.evilcorp.com"),
            Some(expected_canonical("api.test.www.evilcorp.com"))
        );
        assert_eq!(
            tree.get("asdf.test.www.evilcorp.com"),
            Some(expected_canonical("test.www.evilcorp.com"))
        );
        assert_eq!(
            tree.get("asdf.evilcorp.com"),
            Some(expected_canonical("evilcorp.com"))
        );
    }

    #[test]
    fn test_no_match() {
        let mut tree = DnsRadixTree::new(ScopeMode::Normal);
        let canonical = tree.insert("example.com").unwrap();
        assert_eq!(
            canonical,
            expected_canonical("example.com"),
            "insert(example.com) canonical"
        );
        assert_eq!(tree.get("notfound.com"), None);
        assert_eq!(tree.get("com"), None);
    }

    #[test]
    fn test_top_level_domain() {
        let mut tree = DnsRadixTree::new(ScopeMode::Normal);
        // insert a top level domain
        let canonical = tree.insert("com").unwrap();
        assert_eq!(
            canonical,
            expected_canonical("com"),
            "insert(com) canonical"
        );
        // get subdomains
        assert_eq!(tree.get("www.example.com"), Some(expected_canonical("com")));
        assert_eq!(tree.get("example.com"), Some(expected_canonical("com")));
        // get the top level domain
        assert_eq!(tree.get("com"), Some(expected_canonical("com")));
        // empty string should not match
        assert_eq!(tree.get(""), None);
    }

    #[test]
    fn test_clear_method() {
        use crate::node::BaseNode;

        let mut tree = DnsRadixTree::new(ScopeMode::Normal);

        // Insert hosts in random order
        let mut hosts = vec![
            "example.com",
            "www.example.com",
            "api.example.com",
            "mail.example.com",
            "secure.api.example.com",
            "dev.api.example.com",
            "test.dev.api.example.com",
            "staging.dev.api.example.com",
            "other.com",
            "sub.other.com",
        ];

        // Shuffle randomly
        use rand::seq::SliceRandom;
        use rand::thread_rng;
        hosts.shuffle(&mut thread_rng());

        for host in &hosts {
            tree.insert(host);
        }

        // Verify all hosts are present
        for host in &hosts {
            assert!(tree.get(host).is_some(), "Host {} should be present", host);
        }

        // Find the node for "api.example.com" and clear it
        let parts: Vec<&str> = "api.example.com".split('.').collect();
        let mut node = &mut tree.root;
        for part in parts.iter().rev() {
            node = node
                .children
                .get_mut(&hash_u64(part))
                .expect("Node should exist");
        }

        // Clear the api.example.com node (should clear its children)
        let cleared_hosts = node.clear();

        // Should have cleared: secure.api.example.com, dev.api.example.com,
        // test.dev.api.example.com, staging.dev.api.example.com
        let expected_cleared = vec![
            "secure.api.example.com",
            "dev.api.example.com",
            "test.dev.api.example.com",
            "staging.dev.api.example.com",
        ];

        assert_eq!(
            cleared_hosts.len(),
            expected_cleared.len(),
            "Should have cleared {} hosts, got {}: {:?}",
            expected_cleared.len(),
            cleared_hosts.len(),
            cleared_hosts
        );

        // Check that all expected hosts were cleared
        for expected in &expected_cleared {
            assert!(
                cleared_hosts.contains(&expected.to_string()),
                "Should have cleared {}",
                expected
            );
        }

        // Verify the cleared hosts are no longer accessible
        for cleared in &expected_cleared {
            assert!(
                tree.get(cleared).is_none()
                    || tree.get(cleared) == Some("api.example.com".to_string()),
                "Cleared host {} should not be accessible or should fall back to parent",
                cleared
            );
        }

        // Verify that api.example.com itself is still accessible
        assert_eq!(
            tree.get("api.example.com"),
            Some("api.example.com".to_string())
        );

        // Verify that unrelated hosts are still accessible
        assert_eq!(tree.get("example.com"), Some("example.com".to_string()));
        assert_eq!(
            tree.get("www.example.com"),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            tree.get("mail.example.com"),
            Some("mail.example.com".to_string())
        );
        assert_eq!(tree.get("other.com"), Some("other.com".to_string()));
        assert_eq!(tree.get("sub.other.com"), Some("sub.other.com".to_string()));
    }

    #[test]
    fn test_acl_mode_skip_existing() {
        let mut tree = DnsRadixTree::new(ScopeMode::Acl);

        // First insertion should succeed
        let result1 = tree.insert("example.com");
        assert_eq!(result1, Some("example.com".to_string()));

        // Second insertion of same host should return None
        let result2 = tree.insert("example.com");
        assert_eq!(result2, None);

        // Different host should still work
        let result3 = tree.insert("other.com");
        assert_eq!(result3, Some("other.com".to_string()));

        // Verify both hosts are accessible
        assert_eq!(tree.get("example.com"), Some("example.com".to_string()));
        assert_eq!(tree.get("other.com"), Some("other.com".to_string()));
    }

    #[test]
    fn test_acl_mode_skip_children() {
        let mut tree = DnsRadixTree::new(ScopeMode::Acl);

        // Insert parent domain first
        assert_eq!(tree.insert("example.com"), Some("example.com".to_string()));
        assert_eq!(tree.get("example.com"), Some("example.com".to_string()));

        // Insert child domain should return None (already covered by parent)
        assert_eq!(tree.insert("api.example.com"), None);

        // Get child domain should return parent
        assert_eq!(tree.get("api.example.com"), Some("example.com".to_string()));
    }

    #[test]
    fn test_acl_mode_clear_children() {
        let mut tree = DnsRadixTree::new(ScopeMode::Acl);

        // Insert child domains first
        tree.insert("api.example.com");
        tree.insert("www.example.com");
        tree.insert("mail.example.com");

        // Verify children are accessible
        assert_eq!(
            tree.get("api.example.com"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            tree.get("www.example.com"),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            tree.get("mail.example.com"),
            Some("mail.example.com".to_string())
        );

        // Insert parent domain - should clear children
        let result = tree.insert("example.com");
        assert_eq!(result, Some("example.com".to_string()));

        // Parent should be accessible
        assert_eq!(tree.get("example.com"), Some("example.com".to_string()));

        // Children should now fall back to parent
        assert_eq!(tree.get("api.example.com"), Some("example.com".to_string()));
        assert_eq!(tree.get("www.example.com"), Some("example.com".to_string()));
        assert_eq!(
            tree.get("mail.example.com"),
            Some("example.com".to_string())
        );
    }
}
