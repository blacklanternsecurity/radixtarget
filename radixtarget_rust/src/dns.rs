// DNSRadixTree: A radix tree for efficient DNS hostname lookups.
// Hostnames are stored in reverse order (TLD to subdomain) for hierarchical matching.
// Inspired by the Python implementation in dns.py.
use std::collections::HashMap;
use idna::domain_to_ascii;
use crate::base::{BaseNode, siphash};

#[derive(Debug, Clone)]
pub struct DnsNode {
    pub children: HashMap<u64, Box<DnsNode>>,
    pub host: Option<String>, // canonicalized (punycode) hostname
}

impl DnsNode {
    pub fn new() -> Self {
        DnsNode {
            children: HashMap::new(),
            host: None,
        }
    }
}

impl BaseNode for DnsNode {
    fn is_dead(&self) -> bool {
        self.host.is_none() && self.children.is_empty()
    }
    fn children_mut(&mut self) -> &mut HashMap<u64, Box<DnsNode>> {
        &mut self.children
    }
}

#[derive(Debug, Clone)]
pub struct DnsRadixTree {
    pub root: DnsNode,
    pub strict_scope: bool,
}

impl DnsRadixTree {
    pub fn new(strict_scope: bool) -> Self {
        DnsRadixTree {
            root: DnsNode::new(),
            strict_scope,
        }
    }

    /// Insert a hostname into the tree, storing parts in reverse order for hierarchy.
    /// Returns the SipHash of the canonicalized hostname after insertion.
    pub fn insert(&mut self, hostname: &str) -> u64 {
        let canonical = domain_to_ascii(hostname).unwrap();
        let parts: Vec<&str> = canonical.split('.').collect();
        let mut node = &mut self.root;
        for part in parts.iter().rev() {
            node = node.children.entry(siphash(part)).or_insert_with(|| Box::new(DnsNode::new()));
        }
        node.host = Some(canonical.clone());
        siphash(&canonical)
    }

    /// Find the most specific matching entry for a given hostname.
    /// If strict_scope is true, only exact matches are allowed.
    /// Returns the SipHash of the canonicalized hostname if found.
    pub fn get(&self, hostname: &str) -> Option<u64> {
        let canonical = domain_to_ascii(hostname).ok()?;
        let parts: Vec<&str> = canonical.split('.').collect();
        let mut node = &self.root;
        let mut matched: Option<&String> = None;
        for (i, part) in parts.iter().rev().enumerate() {
            if let Some(child) = node.children.get(&siphash(part)) {
                node = child;
                if self.strict_scope && i + 1 < parts.len() {
                    continue;
                }
                if let Some(host) = &node.host {
                    matched = Some(host);
                }
            } else {
                break;
            }
        }
        matched.map(|h| siphash(h))
    }

    /// Delete a hostname from the tree.
    /// Returns true if the hostname was found and deleted.
    pub fn delete(&mut self, hostname: &str) -> bool {
        let canonical = match domain_to_ascii(hostname) { Ok(c) => c, Err(_) => return false };
        let parts: Vec<&str> = canonical.split('.').collect();
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
        if let Some(child) = node.children.get_mut(&siphash(part)) {
            let deleted = Self::delete_rec(child, parts, depth + 1);
            if child.children.is_empty() && child.host.is_none() {
                node.children.remove(&siphash(part));
            }
            return deleted;
        }
        false
    }

    pub fn prune(&mut self) -> usize {
        self.root.prune()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use idna::domain_to_ascii;
    use std::hash::{Hash, Hasher};

    fn expected_hash(host: &str) -> u64 {
        let canonical = domain_to_ascii(host).unwrap();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        canonical.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_insert_and_get_basic() {
        let mut tree = DnsRadixTree::new(false);
        let hash1 = tree.insert("example.com");
        assert_eq!(hash1, expected_hash("example.com"), "insert(example.com) hash");
        let hash2 = tree.insert("api.test.www.example.com");
        assert_eq!(hash2, expected_hash("api.test.www.example.com"), "insert(api.test.www.example.com) hash");
        assert_eq!(tree.get("example.com"), Some(expected_hash("example.com")));
        assert_eq!(tree.get("api.test.www.example.com"), Some(expected_hash("api.test.www.example.com")));
        // Subdomain matching
        assert_eq!(tree.get("wat.hm.api.test.www.example.com"), Some(expected_hash("api.test.www.example.com")));
        // No match
        assert_eq!(tree.get("notfound.com"), None);
    }

    #[test]
    fn test_strict_scope() {
        let mut tree = DnsRadixTree::new(true);
        let hash1 = tree.insert("example.com");
        assert_eq!(hash1, expected_hash("example.com"), "insert(example.com) hash");
        let hash2 = tree.insert("api.test.www.example.com");
        assert_eq!(hash2, expected_hash("api.test.www.example.com"), "insert(api.test.www.example.com) hash");
        // Only exact matches
        assert_eq!(tree.get("example.com"), Some(expected_hash("example.com")));
        assert_eq!(tree.get("api.test.www.example.com"), Some(expected_hash("api.test.www.example.com")));
        assert_eq!(tree.get("wat.hm.api.test.www.example.com"), None);
        assert_eq!(tree.get("notfound.com"), None);
    }

    #[test]
    fn test_delete() {
        let mut tree = DnsRadixTree::new(false);
        let hash1 = tree.insert("example.com");
        assert_eq!(hash1, expected_hash("example.com"), "insert(example.com) hash");
        let hash2 = tree.insert("api.test.www.example.com");
        assert_eq!(hash2, expected_hash("api.test.www.example.com"), "insert(api.test.www.example.com) hash");
        assert_eq!(tree.get("example.com"), Some(expected_hash("example.com")));
        assert!(tree.delete("example.com"));
        assert_eq!(tree.get("example.com"), None);
        // Deleting again should fail
        assert!(!tree.delete("example.com"));
        // Subdomain should still match the more specific
        assert_eq!(tree.get("wat.hm.api.test.www.example.com"), Some(expected_hash("api.test.www.example.com")));
        assert!(tree.delete("api.test.www.example.com"));
        assert_eq!(tree.get("wat.hm.api.test.www.example.com"), None);
    }

    #[test]
    fn test_subdomain_matching() {
        let mut tree = DnsRadixTree::new(false);
        let hash1 = tree.insert("evilcorp.com");
        assert_eq!(hash1, expected_hash("evilcorp.com"), "insert(evilcorp.com) hash");
        let hash2 = tree.insert("www.evilcorp.com");
        assert_eq!(hash2, expected_hash("www.evilcorp.com"), "insert(www.evilcorp.com) hash");
        let hash3 = tree.insert("test.www.evilcorp.com");
        assert_eq!(hash3, expected_hash("test.www.evilcorp.com"), "insert(test.www.evilcorp.com) hash");
        let hash4 = tree.insert("api.test.www.evilcorp.com");
        assert_eq!(hash4, expected_hash("api.test.www.evilcorp.com"), "insert(api.test.www.evilcorp.com) hash");
        assert_eq!(tree.get("api.test.www.evilcorp.com"), Some(expected_hash("api.test.www.evilcorp.com")));
        assert_eq!(tree.get("test.www.evilcorp.com"), Some(expected_hash("test.www.evilcorp.com")));
        assert_eq!(tree.get("www.evilcorp.com"), Some(expected_hash("www.evilcorp.com")));
        assert_eq!(tree.get("evilcorp.com"), Some(expected_hash("evilcorp.com")));
        // Subdomain matching
        assert_eq!(tree.get("wat.hm.api.test.www.evilcorp.com"), Some(expected_hash("api.test.www.evilcorp.com")));
        assert_eq!(tree.get("asdf.test.www.evilcorp.com"), Some(expected_hash("test.www.evilcorp.com")));
        assert_eq!(tree.get("asdf.evilcorp.com"), Some(expected_hash("evilcorp.com")));
    }

    #[test]
    fn test_no_match() {
        let mut tree = DnsRadixTree::new(false);
        let hash = tree.insert("example.com");
        assert_eq!(hash, expected_hash("example.com"), "insert(example.com) hash");
        assert_eq!(tree.get("notfound.com"), None);
        assert_eq!(tree.get("com"), None);
    }

    #[test]
    fn test_top_level_domain() {
        let mut tree = DnsRadixTree::new(false);
        // insert a top level domain
        let hash = tree.insert("com");
        assert_eq!(hash, expected_hash("com"), "insert(com) hash");
        // get subdomains
        assert_eq!(tree.get("www.example.com"), Some(expected_hash("com")));
        assert_eq!(tree.get("example.com"), Some(expected_hash("com")));
        // get the top level domain
        assert_eq!(tree.get("com"), Some(expected_hash("com")));
        // empty string should not match
        assert_eq!(tree.get(""), None);
    }

    #[test]
    fn test_internationalized_domain_names() {
        let unicode = "café.com";
        let punycode = domain_to_ascii(unicode).unwrap(); // "xn--caf-dma.com"
        assert_eq!(punycode, "xn--caf-dma.com");

        // 1. Insert unicode, delete unicode
        {
            let mut tree = DnsRadixTree::new(false);
            let hash = tree.insert(unicode);
            assert_eq!(hash, expected_hash(&punycode), "insert(unicode) hash");
            assert_eq!(tree.get(unicode), Some(expected_hash(&punycode)), "get(unicode) after insert(unicode)");
            assert_eq!(tree.get(&punycode), Some(expected_hash(&punycode)), "get(punycode) after insert(unicode)");
            assert!(tree.delete(unicode), "delete(unicode) after insert(unicode)");
            assert_eq!(tree.get(unicode), None, "get(unicode) after delete(unicode) after insert(unicode)");
            assert_eq!(tree.get(&punycode), None, "get(punycode) after delete(unicode) after insert(unicode)");
        }

        // 2. Insert unicode, delete punycode
        {
            let mut tree = DnsRadixTree::new(false);
            let hash = tree.insert(unicode);
            assert_eq!(hash, expected_hash(&punycode), "insert(unicode) hash");
            assert_eq!(tree.get(unicode), Some(expected_hash(&punycode)), "get(unicode) after insert(unicode)");
            assert_eq!(tree.get(&punycode), Some(expected_hash(&punycode)), "get(punycode) after insert(unicode)");
            assert!(tree.delete(&punycode), "delete(punycode) after insert(unicode)");
            assert_eq!(tree.get(unicode), None, "get(unicode) after delete(punycode) after insert(unicode)");
            assert_eq!(tree.get(&punycode), None, "get(punycode) after delete(punycode) after insert(unicode)");
        }

        // 3. Insert punycode, delete unicode
        {
            let mut tree = DnsRadixTree::new(false);
            let hash = tree.insert(&punycode);
            assert_eq!(hash, expected_hash(&punycode), "insert(punycode) hash");
            assert_eq!(tree.get(unicode), Some(expected_hash(&punycode)), "get(unicode) after insert(punycode)");
            assert_eq!(tree.get(&punycode), Some(expected_hash(&punycode)), "get(punycode) after insert(punycode)");
            assert!(tree.delete(unicode), "delete(unicode) after insert(punycode)");
            assert_eq!(tree.get(unicode), None, "get(unicode) after delete(unicode) after insert(punycode)");
            assert_eq!(tree.get(&punycode), None, "get(punycode) after delete(unicode) after insert(punycode)");
        }

        // 4. Insert punycode, delete punycode
        {
            let mut tree = DnsRadixTree::new(false);
            let hash = tree.insert(&punycode);
            assert_eq!(hash, expected_hash(&punycode), "insert(punycode) hash");
            assert_eq!(tree.get(unicode), Some(expected_hash(&punycode)), "get(unicode) after insert(punycode)");
            assert_eq!(tree.get(&punycode), Some(expected_hash(&punycode)), "get(punycode) after insert(punycode)");
            assert!(tree.delete(&punycode), "delete(punycode) after insert(punycode)");
            assert_eq!(tree.get(unicode), None, "get(unicode) after delete(punycode) after insert(punycode)");
            assert_eq!(tree.get(&punycode), None, "get(punycode) after delete(punycode) after insert(punycode)");
        }
    }
}