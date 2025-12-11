use radixtarget::{RadixTarget, ScopeMode};
use std::collections::HashSet;

#[test]
fn test_basic_usage_examples() {
    // Create a new RadixTarget
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

    // IPv4 networks and addresses
    rt.insert("192.168.1.0/24");
    assert_eq!(rt.get("192.168.1.100"), Some("192.168.1.0/24".to_string()));
    assert_eq!(rt.get("192.168.2.100"), None);

    // IPv6 networks and addresses
    rt.insert("dead::/64");
    assert_eq!(rt.get("dead::beef"), Some("dead::/64".to_string()));
    assert_eq!(rt.get("cafe::beef"), None);

    // DNS hostnames
    rt.insert("example.com");
    rt.insert("api.test.www.example.com");
    assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
    assert_eq!(
        rt.get("subdomain.api.test.www.example.com"),
        Some("api.test.www.example.com".to_string())
    );

    // Check if target contains a value
    assert!(rt.contains("192.168.1.50"));
    assert!(rt.contains("dead::1234"));
    assert!(rt.contains("example.com"));

    // Get all hosts
    let hosts: HashSet<String> = rt.hosts();
    println!("All hosts: {:?}", hosts);
    assert!(!hosts.is_empty());

    // Delete targets
    assert!(rt.delete("192.168.1.0/24"));
    assert!(!rt.delete("192.168.1.0/24")); // false - already deleted

    // Utility operations
    println!("Number of hosts: {}", rt.len());
    println!("Is empty: {}", rt.is_empty());

    // Prune dead nodes (returns number of pruned nodes)
    let pruned_count = rt.prune();
    println!("Pruned {} nodes", pruned_count);

    // Defragment overlapping networks (returns (cleaned, new) hosts)
    let (cleaned_hosts, new_hosts) = rt.defrag();
    println!("Cleaned: {:?}, New: {:?}", cleaned_hosts, new_hosts);
}

#[test]
fn test_scope_modes() {
    // Normal mode: standard radix tree behavior (default)
    let mut rt_normal = RadixTarget::new(&[], ScopeMode::Normal);
    rt_normal.insert("example.com");
    assert_eq!(
        rt_normal.get("subdomain.example.com"),
        Some("example.com".to_string())
    );

    // Strict mode: exact matching only
    let mut rt_strict = RadixTarget::new(&[], ScopeMode::Strict);
    rt_strict.insert("example.com");
    assert_eq!(
        rt_strict.get("example.com"),
        Some("example.com".to_string())
    );
    assert_eq!(rt_strict.get("subdomain.example.com"), None); // No subdomain matching

    // ACL mode: Same behavior as normal, but keeps only the highest parent subnet for efficiency
    let mut rt_acl = RadixTarget::new(&[], ScopeMode::Acl);
    rt_acl.insert("192.168.1.0/24");
    rt_acl.insert("192.168.1.0/28");
    // Least specific match is returned instead of most specific
    assert_eq!(
        rt_acl.get("192.168.1.1"),
        Some("192.168.1.0/24".to_string())
    );
}

#[test]
fn test_initialization_with_hosts() {
    // Initialize with existing hosts
    let hosts = vec!["192.168.1.0/24", "example.com", "dead::/64"];
    let rt = RadixTarget::new(&hosts, ScopeMode::Normal);

    assert!(rt.contains("192.168.1.100"));
    assert!(rt.contains("subdomain.example.com"));
    assert!(rt.contains("dead::beef"));
}

#[test]
fn test_additional_readme_examples() {
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

    // Test the specific examples from README

    // IPv4
    rt.insert("192.168.1.0/24");
    assert_eq!(rt.get("192.168.1.10"), Some("192.168.1.0/24".to_string()));
    assert_eq!(rt.get("192.168.2.10"), None);

    // IPv6
    rt.insert("dead::/64");
    assert_eq!(rt.get("dead::beef"), Some("dead::/64".to_string()));
    assert_eq!(rt.get("dead:cafe::beef"), None);

    // DNS examples from README
    rt.insert("net");
    rt.insert("www.example.com");
    rt.insert("test.www.example.com");

    assert_eq!(rt.get("net"), Some("net".to_string()));
    assert_eq!(rt.get("evilcorp.net"), Some("net".to_string()));
    assert_eq!(
        rt.get("www.example.com"),
        Some("www.example.com".to_string())
    );
    assert_eq!(
        rt.get("asdf.test.www.example.com"),
        Some("test.www.example.com".to_string())
    );
    assert_eq!(rt.get("example.com"), None);

    // Custom data nodes example (Rust doesn't have custom data like Python, but test the hostname)
    rt.insert("evilcorp.co.uk");
    assert_eq!(
        rt.get("www.evilcorp.co.uk"),
        Some("evilcorp.co.uk".to_string())
    );
}

#[test]
fn test_utility_operations_comprehensive() {
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

    // Start empty
    assert!(rt.is_empty());
    assert_eq!(rt.len(), 0);

    // Add some hosts
    rt.insert("192.168.1.0/24");
    rt.insert("example.com");
    rt.insert("dead::/64");

    // Check state
    assert!(!rt.is_empty());
    assert_eq!(rt.len(), 3);

    // Test contains
    assert!(rt.contains("192.168.1.50"));
    assert!(rt.contains("subdomain.example.com"));
    assert!(rt.contains("dead::1234"));
    assert!(!rt.contains("172.16.1.1"));
    assert!(!rt.contains("notfound.com"));

    // Test hosts collection
    let hosts = rt.hosts();
    assert!(hosts.contains("192.168.1.0/24"));
    assert!(hosts.contains("example.com"));
    assert!(hosts.contains("dead::/64"));

    // Test deletion
    assert!(rt.delete("example.com"));
    assert!(!rt.delete("example.com")); // Already deleted
    assert_eq!(rt.len(), 2);
    assert!(!rt.contains("subdomain.example.com"));

    // Test prune (should be 0 for clean tree)
    let pruned = rt.prune();
    assert_eq!(pruned, 0);

    // Test defrag with overlapping networks
    rt.insert("192.168.1.0/25");
    rt.insert("192.168.1.128/25");
    let (cleaned, new) = rt.defrag();

    // Should merge the two /25s into the existing /24
    assert!(cleaned.contains("192.168.1.0/25"));
    assert!(cleaned.contains("192.168.1.128/25"));
    // The /24 should remain or be recreated
    assert!(rt.hosts().contains("192.168.1.0/24") || new.contains("192.168.1.0/24"));
}

#[test]
fn test_edge_cases() {
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

    // Test case sensitivity in DNS (should be case-insensitive)
    rt.insert("Example.COM");
    assert_eq!(rt.get("example.com"), Some("example.com".to_string()));
    assert_eq!(rt.get("EXAMPLE.COM"), Some("example.com".to_string()));
    assert_eq!(
        rt.get("subdomain.Example.Com"),
        Some("example.com".to_string())
    );

    // Test IDNA normalization
    rt.insert("café.com");
    // Should be stored as punycode
    assert!(rt.hosts().contains("xn--caf-dma.com"));
    assert_eq!(rt.get("café.com"), Some("xn--caf-dma.com".to_string()));
    assert_eq!(
        rt.get("xn--caf-dma.com"),
        Some("xn--caf-dma.com".to_string())
    );

    // Test IP address normalization
    rt.insert("192.168.1.1");
    assert!(rt.hosts().contains("192.168.1.1/32"));
    assert_eq!(rt.get("192.168.1.1"), Some("192.168.1.1/32".to_string()));

    rt.insert("dead::beef");
    assert!(rt.hosts().contains("dead::beef/128"));
    assert_eq!(rt.get("dead::beef"), Some("dead::beef/128".to_string()));
}

#[test]
fn test_acl_mode_behavior() {
    let mut rt = RadixTarget::new(&[], ScopeMode::Acl);

    // In ACL mode, more specific networks should not be added if a less specific one exists
    rt.insert("192.168.0.0/16");
    rt.insert("192.168.1.0/24"); // Should be ignored/not stored separately

    // Should return the less specific network
    assert_eq!(rt.get("192.168.1.100"), Some("192.168.0.0/16".to_string()));

    // Test with DNS in ACL mode
    rt.insert("example.com");
    rt.insert("subdomain.example.com"); // Should be ignored
    assert_eq!(
        rt.get("subdomain.example.com"),
        Some("example.com".to_string())
    );
}

#[test]
fn test_copy_and_equality() {
    let mut rt1 = RadixTarget::new(&[], ScopeMode::Normal);
    rt1.insert("192.168.1.0/24");
    rt1.insert("example.com");

    // Test copy
    let rt2 = rt1.copy();
    assert_eq!(rt1, rt2);
    assert_eq!(rt1.hosts(), rt2.hosts());

    // Test that modifications to copy don't affect original
    let mut rt3 = rt1.copy();
    rt3.insert("test.org");
    assert_ne!(rt1, rt3);
    assert!(rt3.contains("test.org"));
    assert!(!rt1.contains("test.org"));
}

#[test]
fn test_contains_target() {
    let mut superset = RadixTarget::new(&[], ScopeMode::Normal);
    superset.insert("192.168.0.0/16");
    superset.insert("example.com");

    let mut subset = RadixTarget::new(&[], ScopeMode::Normal);
    subset.insert("192.168.1.100");
    subset.insert("subdomain.example.com");

    // Superset should contain subset
    assert!(superset.contains_target(&subset));
    assert!(!subset.contains_target(&superset));

    // Self-containment
    assert!(superset.contains_target(&superset));
    assert!(subset.contains_target(&subset));

    // Empty target
    let empty = RadixTarget::new(&[], ScopeMode::Normal);
    assert!(superset.contains_target(&empty));
    assert!(!empty.contains_target(&superset));
}
