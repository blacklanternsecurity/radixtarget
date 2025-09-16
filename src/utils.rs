// utils.rs: Utility functions for radix trees
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// Hash a value to u64 using the default hasher
pub fn hash_u64<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Convert an IP network to a vector of bits for radix tree traversal
pub fn ipnet_to_bits(net: &IpNet) -> Vec<u8> {
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

/// Canonicalize an IP network by ensuring it uses the network address
pub fn canonicalize_ipnet(network: &IpNet) -> IpNet {
    match network {
        IpNet::V4(n) => IpNet::V4(Ipv4Net::new(n.network(), n.prefix_len()).unwrap()),
        IpNet::V6(n) => IpNet::V6(Ipv6Net::new(n.network(), n.prefix_len()).unwrap()),
    }
}

/// Normalize a DNS hostname to canonical form (IDNA + lowercase)
pub fn normalize_dns(hostname: &str) -> String {
    idna::domain_to_ascii(hostname)
        .unwrap_or_else(|_| hostname.to_string())
        .to_lowercase()
}

/// Host size key function for sorting - equivalent to Python's host_size_key
/// Returns (priority, string_repr) where priority is:
/// - For IP networks: negative number of addresses (so bigger networks come first)
/// - For DNS names: positive length (so shorter domains come first)
pub fn host_size_key(host: &str) -> (i64, String) {
    // Try to parse as IP network first
    if let Ok(ipnet) = host.parse::<IpNet>() {
        let num_addresses = match ipnet {
            IpNet::V4(net) => (32 - net.prefix_len()) as u64,
            IpNet::V6(net) => (128 - net.prefix_len()) as u64,
        };
        // Format as network address with prefix length (like Python's ipaddress module)
        (
            -(num_addresses as i64),
            format!("{}/{}", ipnet.network(), ipnet.prefix_len()),
        )
    } else if let Ok(ipaddr) = host.parse::<IpAddr>() {
        // Single IP address - use original string to avoid re-formatting
        if ipaddr.is_ipv4() {
            (-1, format!("{}/32", host))
        } else {
            (-1, format!("{}/128", host))
        }
    } else {
        // DNS name - normalize and return length
        let canonical = normalize_dns(host);
        (canonical.len() as i64, canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_size_key_single_ipv4() {
        assert_eq!(host_size_key("1.2.3.4"), (-1, "1.2.3.4/32".to_string()));
    }

    #[test]
    fn test_host_size_key_single_ipv6() {
        assert_eq!(host_size_key("::1"), (-1, "::1/128".to_string()));
    }

    #[test]
    fn test_host_size_key_ipv4_networks() {
        // /24 network = 32-24 = 8 host bits
        assert_eq!(host_size_key("1.2.3.0/24"), (-8, "1.2.3.0/24".to_string()));

        // /28 network = 32-28 = 4 host bits
        assert_eq!(host_size_key("1.2.3.0/28"), (-4, "1.2.3.0/28".to_string()));

        // /30 network = 32-30 = 2 host bits
        assert_eq!(host_size_key("1.2.3.4/30"), (-2, "1.2.3.4/30".to_string()));
    }

    #[test]
    fn test_host_size_key_ipv6_networks() {
        // /64 network = 128-64 = 64 host bits (network address is normalized)
        assert_eq!(host_size_key("::1/64"), (-64, "::/64".to_string()));

        // /120 network = 128-120 = 8 host bits (network address is normalized)
        assert_eq!(host_size_key("::1/120"), (-8, "::/120".to_string()));
    }

    #[test]
    fn test_host_size_key_dns_names() {
        assert_eq!(
            host_size_key("evilcorp.com"),
            (12, "evilcorp.com".to_string())
        );
        assert_eq!(
            host_size_key("www.evilcorp.com"),
            (16, "www.evilcorp.com".to_string())
        );
        assert_eq!(
            host_size_key("api.www.evilcorp.com"),
            (20, "api.www.evilcorp.com".to_string())
        );
    }

    #[test]
    fn test_host_size_key_dns_normalization() {
        // Test IDNA normalization and lowercasing
        assert_eq!(
            host_size_key("EXAMPLE.COM"),
            (11, "example.com".to_string())
        );
        assert_eq!(
            host_size_key("Example.Com"),
            (11, "example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_dns_case_insensitive() {
        assert_eq!(normalize_dns("EXAMPLE.COM"), "example.com");
        assert_eq!(
            normalize_dns("MiXeD.CaSe.DoMaIn.CoM"),
            "mixed.case.domain.com"
        );
    }

    #[test]
    fn test_normalize_dns_unicode_punycode() {
        assert_eq!(normalize_dns("café.com"), "xn--caf-dma.com");
        assert_eq!(normalize_dns("日本.jp"), "xn--wgv71a.jp");
    }
}
