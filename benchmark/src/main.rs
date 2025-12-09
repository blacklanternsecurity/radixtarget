use clap::Parser;
use radixtarget::{RadixTarget, ScopeMode};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use std::net::IpAddr;
use std::str::FromStr;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

#[derive(Parser)]
#[command(name = "radixtarget-benchmark")]
#[command(about = "Benchmark RadixTarget performance")]
struct Args {
    #[arg(short, long, default_value = "1000000")]
    size: usize,
    
    #[arg(short, long, default_value = "10000")]
    lookups: usize,
}

#[derive(Serialize, Deserialize)]
struct BenchmarkResult {
    library: String,
    size: usize,
    lookups: usize,
    insert_time_ms: f64,
    lookup_time_ms: f64,
    ops_per_second: f64,
    hit_rate: f64,
}

fn generate_ip_data(size: usize) -> (Vec<String>, Vec<String>) {
    let mut rng = thread_rng();
    let mut ipv4_networks = Vec::new();
    let mut ipv6_networks = Vec::new();
    
    // Generate IPv4 networks with proper network addresses
    for _ in 0..size/2 {
        let prefix = rng.gen_range(1..=32);
        
        // Generate a random IP and normalize it to the network address
        let a = rng.gen_range(1..=255);
        let b = rng.gen_range(0..=255);
        let c = rng.gen_range(0..=255);
        let d = rng.gen_range(0..=255);
        
        // Create the IP and apply the subnet mask to get the network address
        let ip = (a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | (d as u32);
        let mask = !((1u32 << (32 - prefix)) - 1);
        let network_ip = ip & mask;
        
        let na = ((network_ip >> 24) & 0xFF) as u8;
        let nb = ((network_ip >> 16) & 0xFF) as u8;
        let nc = ((network_ip >> 8) & 0xFF) as u8;
        let nd = (network_ip & 0xFF) as u8;
        
        ipv4_networks.push(format!("{}.{}.{}.{}/{}", na, nb, nc, nd, prefix));
    }
    
    // Generate IPv6 networks with proper network addresses
    for _ in 0..size/2 {
        let prefix = rng.gen_range(1..=128);
        
        // Generate random IPv6 segments
        let segments: [u16; 8] = [
            rng.gen(), rng.gen(), rng.gen(), rng.gen(),
            rng.gen(), rng.gen(), rng.gen(), rng.gen()
        ];
        
        // Apply the prefix mask to get the network address
        let mut network_segments = segments;
        let full_segments = prefix / 16;
        let remaining_bits = prefix % 16;
        
        // Zero out segments beyond the prefix
        for i in (full_segments as usize + 1)..8 {
            network_segments[i] = 0;
        }
        
        // Apply partial mask to the segment that straddles the prefix boundary
        if remaining_bits > 0 && (full_segments as usize) < 8 {
            let mask = !((1u16 << (16 - remaining_bits)) - 1);
            network_segments[full_segments as usize] &= mask;
        }
        
        let network_str = network_segments.iter()
            .map(|&seg| format!("{:x}", seg))
            .collect::<Vec<_>>()
            .join(":");
            
        ipv6_networks.push(format!("{}/{}", network_str, prefix));
    }
    
    (ipv4_networks, ipv6_networks)
}

fn generate_lookup_ips(lookup_count: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut lookup_ips = Vec::new();
    
    // Generate completely random IPv4 lookups
    for _ in 0..lookup_count/2 {
        let a = rng.gen_range(1..=255);
        let b = rng.gen_range(0..=255);
        let c = rng.gen_range(0..=255);
        let d = rng.gen_range(1..=254);
        lookup_ips.push(format!("{}.{}.{}.{}", a, b, c, d));
    }
    
    // Generate completely random IPv6 lookups
    for _ in 0..lookup_count/2 {
        let segments: Vec<String> = (0..8)
            .map(|_| format!("{:x}", rng.gen::<u16>()))
            .collect();
        lookup_ips.push(segments.join(":"));
    }
    
    lookup_ips
}

fn benchmark_radixtarget_with_ips(ipv4_networks: &[String], ipv6_networks: &[String], lookup_ips: &[String]) -> BenchmarkResult {
    
    // Benchmark insertion
    let start = Instant::now();
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
    
    for network in ipv4_networks {
        rt.insert(network);
    }
    for network in ipv6_networks {
        rt.insert(network);
    }
    
    let insert_time = start.elapsed();
    
    // Benchmark lookups
    let start = Instant::now();
    let mut hits = 0;
    
    for lookup in lookup_ips {
        if rt.get(lookup).is_some() {
            hits += 1;
        }
    }
    
    let lookup_time = start.elapsed();
    let ops_per_sec = lookup_ips.len() as f64 / lookup_time.as_secs_f64();
    let hit_rate = hits as f64 / lookup_ips.len() as f64;
    
    BenchmarkResult {
        library: "radixtarget".to_string(),
        size: ipv4_networks.len() + ipv6_networks.len(),
        lookups: lookup_ips.len(),
        insert_time_ms: insert_time.as_secs_f64() * 1000.0,
        lookup_time_ms: lookup_time.as_secs_f64() * 1000.0,
        ops_per_second: ops_per_sec,
        hit_rate,
    }
}

fn benchmark_ip_network_table_with_ips(ipv4_networks: &[String], ipv6_networks: &[String], lookup_ips: &[String]) -> BenchmarkResult {
    
    // Benchmark insertion
    let start = Instant::now();
    let mut table: IpNetworkTable<String> = IpNetworkTable::new();
    
    for network in ipv4_networks {
        if let Ok(ip_network) = IpNetwork::from_str(network) {
            table.insert(ip_network, network.clone());
        }
    }
    for network in ipv6_networks {
        if let Ok(ip_network) = IpNetwork::from_str(network) {
            table.insert(ip_network, network.clone());
        }
    }
    
    let insert_time = start.elapsed();
    
    // Convert string IPs to IpAddr for ip_network_table
    let mut parsed_lookup_ips = Vec::new();
    for ip_str in lookup_ips {
        if let Ok(ip_addr) = IpAddr::from_str(ip_str) {
            parsed_lookup_ips.push(ip_addr);
        }
    }
    
    // Benchmark lookups
    let start = Instant::now();
    let mut hits = 0;
    
    for lookup in &parsed_lookup_ips {
        if table.longest_match(*lookup).is_some() {
            hits += 1;
        }
    }
    
    let lookup_time = start.elapsed();
    let ops_per_sec = parsed_lookup_ips.len() as f64 / lookup_time.as_secs_f64();
    let hit_rate = hits as f64 / parsed_lookup_ips.len() as f64;
    
    BenchmarkResult {
        library: "ip_network_table".to_string(),
        size: ipv4_networks.len() + ipv6_networks.len(),
        lookups: parsed_lookup_ips.len(),
        insert_time_ms: insert_time.as_secs_f64() * 1000.0,
        lookup_time_ms: lookup_time.as_secs_f64() * 1000.0,
        ops_per_second: ops_per_sec,
        hit_rate,
    }
}

fn accuracy_test() -> bool {
    println!("Running accuracy test...");
    
    // Test cases: networks and expected matches
    let test_networks = vec![
        "192.168.1.0/24",
        "192.168.1.0/25",    // More specific than above
        "10.0.0.0/8",
        "10.1.0.0/16",       // More specific than above
        "10.1.1.0/24",       // Even more specific
        "2001:db8::/32",
        "2001:db8:1::/48",   // More specific than above
    ];
    
    let test_cases = vec![
        ("192.168.1.100", Some("192.168.1.0/25")),  // Should match most specific
        ("192.168.1.200", Some("192.168.1.0/24")),  // Should match less specific (outside /25)
        ("10.1.1.50", Some("10.1.1.0/24")),         // Should match most specific
        ("10.1.2.50", Some("10.1.0.0/16")),         // Should match /16, not /24 or /8
        ("10.2.0.1", Some("10.0.0.0/8")),           // Should match only /8
        ("172.16.0.1", None),                        // Should not match anything
        ("2001:db8:1::1", Some("2001:db8:1::/48")), // Should match most specific IPv6
        ("2001:db8:2::1", Some("2001:db8::/32")),   // Should match less specific IPv6
        ("2001:db9::1", None),                       // Should not match anything
    ];
    
    // Test RadixTarget
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
    for network in &test_networks {
        rt.insert(network);
    }
    
    // Test ip_network_table
    let mut table: IpNetworkTable<String> = IpNetworkTable::new();
    for network in &test_networks {
        if let Ok(ip_network) = IpNetwork::from_str(network) {
            table.insert(ip_network, network.to_string());
        }
    }
    
    let mut all_passed = true;
    
    for (test_ip, expected) in &test_cases {
        // Test RadixTarget
        let rt_result = rt.get(test_ip);
        let rt_result_str = rt_result.as_ref().map(|s| s.as_str());
        
        // Test ip_network_table
        let table_result = if let Ok(ip_addr) = IpAddr::from_str(test_ip) {
            table.longest_match(ip_addr)
        } else {
            None
        };
        let table_result_str = table_result.as_ref().map(|(_, network)| network.as_str());
        
        let passed = rt_result_str == *expected && table_result_str == *expected;
        
        if !passed {
            println!("  FAIL: {} - Expected: {:?}, RadixTarget: {:?}, ip_network_table: {:?}", 
                test_ip, expected, rt_result_str, table_result_str);
            all_passed = false;
        } else {
            println!("  PASS: {} -> {:?}", test_ip, expected);
        }
    }
    
    if all_passed {
        println!("✓ All accuracy tests passed!");
    } else {
        println!("✗ Some accuracy tests failed!");
    }
    
    all_passed
}

fn main() {
    let args = Args::parse();
    
    // Run accuracy test first
    if !accuracy_test() {
        println!("Accuracy test failed! Aborting benchmark.");
        std::process::exit(1);
    }
    println!();
    
    println!("Generating {} IP networks...", args.size);
    let (ipv4_networks, ipv6_networks) = generate_ip_data(args.size);
    
    // Generate lookup IPs once for both benchmarks
    let lookup_ips = generate_lookup_ips(args.lookups);
    
    println!("Running RadixTarget benchmark...");
    let radixtarget_result = benchmark_radixtarget_with_ips(&ipv4_networks, &ipv6_networks, &lookup_ips);
    
    println!("Running ip_network_table benchmark...");
    let ip_network_table_result = benchmark_ip_network_table_with_ips(&ipv4_networks, &ipv6_networks, &lookup_ips);
    
    println!("\n=== BENCHMARK RESULTS ===");
    println!("Networks: {} ({} IPv4, {} IPv6)", radixtarget_result.size, ipv4_networks.len(), ipv6_networks.len());
    println!("Lookups: {}", radixtarget_result.lookups);
    println!();
    
    println!("RadixTarget:");
    println!("  Insert time: {:.2}ms", radixtarget_result.insert_time_ms);
    println!("  Lookup time: {:.2}ms", radixtarget_result.lookup_time_ms);
    println!("  Operations/sec: {:.0}", radixtarget_result.ops_per_second);
    println!("  Hit rate: {:.1}%", radixtarget_result.hit_rate * 100.0);
    println!();
    
    println!("ip_network_table:");
    println!("  Insert time: {:.2}ms", ip_network_table_result.insert_time_ms);
    println!("  Lookup time: {:.2}ms", ip_network_table_result.lookup_time_ms);
    println!("  Operations/sec: {:.0}", ip_network_table_result.ops_per_second);
    println!("  Hit rate: {:.1}%", ip_network_table_result.hit_rate * 100.0);
    println!();
    
    // Performance comparison
    let insert_speedup = ip_network_table_result.insert_time_ms / radixtarget_result.insert_time_ms;
    let lookup_speedup = ip_network_table_result.lookup_time_ms / radixtarget_result.lookup_time_ms;
    let _ops_speedup = radixtarget_result.ops_per_second / ip_network_table_result.ops_per_second;
    
    println!("Performance comparison (RadixTarget vs ip_network_table):");
    if insert_speedup > 1.0 {
        println!("  Insert: RadixTarget is {:.2}x faster", insert_speedup);
    } else {
        println!("  Insert: ip_network_table is {:.2}x faster", 1.0 / insert_speedup);
    }
    
    if lookup_speedup > 1.0 {
        println!("  Lookup: RadixTarget is {:.2}x faster", lookup_speedup);
    } else {
        println!("  Lookup: ip_network_table is {:.2}x faster", 1.0 / lookup_speedup);
    }
    
    // Save results
    let results = vec![radixtarget_result, ip_network_table_result];
    if let Ok(json) = serde_json::to_string_pretty(&results) {
        std::fs::write("benchmark_results.json", json).unwrap();
        println!("\nResults saved to benchmark_results.json");
    }
}