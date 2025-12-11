use clap::Parser;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use radixtarget::{RadixTarget, ScopeMode};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "radixtarget-benchmark")]
#[command(about = "Benchmark RadixTarget performance")]
struct Args {
    #[arg(short, long, default_value = "100000")]
    size: usize,

    #[arg(short, long, default_value = "10000")]
    lookups: usize,
}

#[derive(Serialize, Deserialize)]
struct InsertBenchmarkResult {
    library: String,
    ip_version: String,
    networks_inserted: usize,
    insert_time_ms: f64,
    inserts_per_second: f64,
}

#[derive(Serialize, Deserialize)]
struct LookupBenchmarkResult {
    library: String,
    ip_version: String,
    networks_in_table: usize,
    lookups_performed: usize,
    lookup_time_ms: f64,
    lookups_per_second: f64,
    hit_rate: f64,
}

fn generate_ipv4_data(size: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut ipv4_networks = Vec::new();

    // Generate IPv4 networks with proper network addresses
    for _ in 0..size {
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

    ipv4_networks
}

fn generate_ipv6_data(size: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut ipv6_networks = Vec::new();

    // Generate IPv6 networks with proper network addresses
    for _ in 0..size {
        let prefix = rng.gen_range(1..=128);

        // Generate random IPv6 segments
        let segments: [u16; 8] = [
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
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

        let network_str = network_segments
            .iter()
            .map(|&seg| format!("{:x}", seg))
            .collect::<Vec<_>>()
            .join(":");

        ipv6_networks.push(format!("{}/{}", network_str, prefix));
    }

    ipv6_networks
}

fn generate_ipv4_lookup_ips(lookup_count: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut lookup_ips = Vec::new();

    // Generate completely random IPv4 lookups
    for _ in 0..lookup_count {
        let a = rng.gen_range(1..=255);
        let b = rng.gen_range(0..=255);
        let c = rng.gen_range(0..=255);
        let d = rng.gen_range(1..=254);
        lookup_ips.push(format!("{}.{}.{}.{}", a, b, c, d));
    }

    lookup_ips
}

fn generate_ipv6_lookup_ips(lookup_count: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut lookup_ips = Vec::new();

    // Generate completely random IPv6 lookups
    for _ in 0..lookup_count {
        let segments: Vec<String> = (0..8).map(|_| format!("{:x}", rng.gen::<u16>())).collect();
        lookup_ips.push(segments.join(":"));
    }

    lookup_ips
}

fn benchmark_radixtarget_insert(networks: &[String], ip_version: &str) -> InsertBenchmarkResult {
    let start = Instant::now();
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);

    for network in networks {
        rt.insert(network);
    }

    let insert_time = start.elapsed();
    let inserts_per_sec = networks.len() as f64 / insert_time.as_secs_f64();

    InsertBenchmarkResult {
        library: "radixtarget".to_string(),
        ip_version: ip_version.to_string(),
        networks_inserted: networks.len(),
        insert_time_ms: insert_time.as_secs_f64() * 1000.0,
        inserts_per_second: inserts_per_sec,
    }
}

fn benchmark_radixtarget_lookup(
    networks: &[String],
    lookup_ips: &[String],
    ip_version: &str,
) -> LookupBenchmarkResult {
    // First build the radix tree
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal);
    for network in networks {
        rt.insert(network);
    }

    // Benchmark lookups
    let start = Instant::now();
    let mut hits = 0;

    for lookup in lookup_ips {
        if rt.get(lookup).is_some() {
            hits += 1;
        }
    }

    let lookup_time = start.elapsed();
    let lookups_per_sec = lookup_ips.len() as f64 / lookup_time.as_secs_f64();
    let hit_rate = hits as f64 / lookup_ips.len() as f64;

    LookupBenchmarkResult {
        library: "radixtarget".to_string(),
        ip_version: ip_version.to_string(),
        networks_in_table: networks.len(),
        lookups_performed: lookup_ips.len(),
        lookup_time_ms: lookup_time.as_secs_f64() * 1000.0,
        lookups_per_second: lookups_per_sec,
        hit_rate,
    }
}

fn benchmark_ip_network_table_insert(
    networks: &[String],
    ip_version: &str,
) -> InsertBenchmarkResult {
    let start = Instant::now();
    let mut table: IpNetworkTable<String> = IpNetworkTable::new();

    for network in networks {
        if let Ok(ip_network) = IpNetwork::from_str(network) {
            table.insert(ip_network, network.clone());
        }
    }

    let insert_time = start.elapsed();
    let inserts_per_sec = networks.len() as f64 / insert_time.as_secs_f64();

    InsertBenchmarkResult {
        library: "ip_network_table".to_string(),
        ip_version: ip_version.to_string(),
        networks_inserted: networks.len(),
        insert_time_ms: insert_time.as_secs_f64() * 1000.0,
        inserts_per_second: inserts_per_sec,
    }
}

fn benchmark_ip_network_table_lookup(
    networks: &[String],
    lookup_ips: &[String],
    ip_version: &str,
) -> LookupBenchmarkResult {
    // First build the table
    let mut table: IpNetworkTable<String> = IpNetworkTable::new();
    for network in networks {
        if let Ok(ip_network) = IpNetwork::from_str(network) {
            table.insert(ip_network, network.clone());
        }
    }

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
    let lookups_per_sec = parsed_lookup_ips.len() as f64 / lookup_time.as_secs_f64();
    let hit_rate = hits as f64 / parsed_lookup_ips.len() as f64;

    LookupBenchmarkResult {
        library: "ip_network_table".to_string(),
        ip_version: ip_version.to_string(),
        networks_in_table: networks.len(),
        lookups_performed: parsed_lookup_ips.len(),
        lookup_time_ms: lookup_time.as_secs_f64() * 1000.0,
        lookups_per_second: lookups_per_sec,
        hit_rate,
    }
}

fn accuracy_test() -> bool {
    println!("Running accuracy test...");

    // Test cases: networks and expected matches
    let test_networks = vec![
        "192.168.1.0/24",
        "192.168.1.0/25", // More specific than above
        "10.0.0.0/8",
        "10.1.0.0/16", // More specific than above
        "10.1.1.0/24", // Even more specific
        "2001:db8::/32",
        "2001:db8:1::/48", // More specific than above
    ];

    let test_cases = vec![
        ("192.168.1.100", Some("192.168.1.0/25")), // Should match most specific
        ("192.168.1.200", Some("192.168.1.0/24")), // Should match less specific (outside /25)
        ("10.1.1.50", Some("10.1.1.0/24")),        // Should match most specific
        ("10.1.2.50", Some("10.1.0.0/16")),        // Should match /16, not /24 or /8
        ("10.2.0.1", Some("10.0.0.0/8")),          // Should match only /8
        ("172.16.0.1", None),                      // Should not match anything
        ("2001:db8:1::1", Some("2001:db8:1::/48")), // Should match most specific IPv6
        ("2001:db8:2::1", Some("2001:db8::/32")),  // Should match less specific IPv6
        ("2001:db9::1", None),                     // Should not match anything
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
            println!(
                "  FAIL: {} - Expected: {:?}, RadixTarget: {:?}, ip_network_table: {:?}",
                test_ip, expected, rt_result_str, table_result_str
            );
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

    println!("Generating {} IPv4 networks...", args.size);
    let ipv4_networks = generate_ipv4_data(args.size);
    let ipv4_lookup_ips = generate_ipv4_lookup_ips(args.lookups);

    println!("Generating {} IPv6 networks...", args.size);
    let ipv6_networks = generate_ipv6_data(args.size);
    let ipv6_lookup_ips = generate_ipv6_lookup_ips(args.lookups);

    println!("Running IPv4 insert benchmarks...");
    let ipv4_radixtarget_insert = benchmark_radixtarget_insert(&ipv4_networks, "IPv4");
    let ipv4_ip_network_table_insert = benchmark_ip_network_table_insert(&ipv4_networks, "IPv4");

    println!("Running IPv4 lookup benchmarks...");
    let ipv4_radixtarget_lookup =
        benchmark_radixtarget_lookup(&ipv4_networks, &ipv4_lookup_ips, "IPv4");
    let ipv4_ip_network_table_lookup =
        benchmark_ip_network_table_lookup(&ipv4_networks, &ipv4_lookup_ips, "IPv4");

    println!("Running IPv6 insert benchmarks...");
    let ipv6_radixtarget_insert = benchmark_radixtarget_insert(&ipv6_networks, "IPv6");
    let ipv6_ip_network_table_insert = benchmark_ip_network_table_insert(&ipv6_networks, "IPv6");

    println!("Running IPv6 lookup benchmarks...");
    let ipv6_radixtarget_lookup =
        benchmark_radixtarget_lookup(&ipv6_networks, &ipv6_lookup_ips, "IPv6");
    let ipv6_ip_network_table_lookup =
        benchmark_ip_network_table_lookup(&ipv6_networks, &ipv6_lookup_ips, "IPv6");

    println!("## RadixTarget Benchmark Results");
    println!();

    println!("### IPv4 Insert Performance");
    println!();
    println!("| Library | Networks | Time (ms) | Inserts/sec | Speed vs RadixTarget |");
    println!("| ------- | -------- | --------- | ----------- | -------------------- |");
    println!(
        "| RadixTarget | {} | {:.2} | {:.0} | 1.0x |",
        ipv4_radixtarget_insert.networks_inserted,
        ipv4_radixtarget_insert.insert_time_ms,
        ipv4_radixtarget_insert.inserts_per_second
    );

    let ipv4_insert_speedup = ipv4_ip_network_table_insert.inserts_per_second
        / ipv4_radixtarget_insert.inserts_per_second;
    let ipv4_insert_comparison = format!("{:.1}x", ipv4_insert_speedup);

    println!(
        "| ip_network_table | {} | {:.2} | {:.0} | {} |",
        ipv4_ip_network_table_insert.networks_inserted,
        ipv4_ip_network_table_insert.insert_time_ms,
        ipv4_ip_network_table_insert.inserts_per_second,
        ipv4_insert_comparison
    );
    println!();

    println!("### IPv4 Lookup Performance");
    println!();
    println!("| Library | Networks in Table | Lookups | Time (ms) | Lookups/sec | Hit Rate | Speed vs RadixTarget |");
    println!("| ------- | ----------------- | ------- | --------- | ----------- | -------- | -------------------- |");
    println!(
        "| RadixTarget | {} | {} | {:.2} | {:.0} | {:.1}% | 1.0x |",
        ipv4_radixtarget_lookup.networks_in_table,
        ipv4_radixtarget_lookup.lookups_performed,
        ipv4_radixtarget_lookup.lookup_time_ms,
        ipv4_radixtarget_lookup.lookups_per_second,
        ipv4_radixtarget_lookup.hit_rate * 100.0
    );

    let ipv4_lookup_speedup = ipv4_ip_network_table_lookup.lookups_per_second
        / ipv4_radixtarget_lookup.lookups_per_second;
    let ipv4_lookup_comparison = format!("{:.1}x", ipv4_lookup_speedup);

    println!(
        "| ip_network_table | {} | {} | {:.2} | {:.0} | {:.1}% | {} |",
        ipv4_ip_network_table_lookup.networks_in_table,
        ipv4_ip_network_table_lookup.lookups_performed,
        ipv4_ip_network_table_lookup.lookup_time_ms,
        ipv4_ip_network_table_lookup.lookups_per_second,
        ipv4_ip_network_table_lookup.hit_rate * 100.0,
        ipv4_lookup_comparison
    );
    println!();

    println!("### IPv6 Insert Performance");
    println!();
    println!("| Library | Networks | Time (ms) | Inserts/sec | Speed vs RadixTarget |");
    println!("| ------- | -------- | --------- | ----------- | -------------------- |");
    println!(
        "| RadixTarget | {} | {:.2} | {:.0} | 1.0x |",
        ipv6_radixtarget_insert.networks_inserted,
        ipv6_radixtarget_insert.insert_time_ms,
        ipv6_radixtarget_insert.inserts_per_second
    );

    let ipv6_insert_speedup = ipv6_ip_network_table_insert.inserts_per_second
        / ipv6_radixtarget_insert.inserts_per_second;
    let ipv6_insert_comparison = format!("{:.1}x", ipv6_insert_speedup);

    println!(
        "| ip_network_table | {} | {:.2} | {:.0} | {} |",
        ipv6_ip_network_table_insert.networks_inserted,
        ipv6_ip_network_table_insert.insert_time_ms,
        ipv6_ip_network_table_insert.inserts_per_second,
        ipv6_insert_comparison
    );
    println!();

    println!("### IPv6 Lookup Performance");
    println!();
    println!("| Library | Networks in Table | Lookups | Time (ms) | Lookups/sec | Hit Rate | Speed vs RadixTarget |");
    println!("| ------- | ----------------- | ------- | --------- | ----------- | -------- | -------------------- |");
    println!(
        "| RadixTarget | {} | {} | {:.2} | {:.0} | {:.1}% | 1.0x |",
        ipv6_radixtarget_lookup.networks_in_table,
        ipv6_radixtarget_lookup.lookups_performed,
        ipv6_radixtarget_lookup.lookup_time_ms,
        ipv6_radixtarget_lookup.lookups_per_second,
        ipv6_radixtarget_lookup.hit_rate * 100.0
    );

    let ipv6_lookup_speedup = ipv6_ip_network_table_lookup.lookups_per_second
        / ipv6_radixtarget_lookup.lookups_per_second;
    let ipv6_lookup_comparison = format!("{:.1}x", ipv6_lookup_speedup);

    println!(
        "| ip_network_table | {} | {} | {:.2} | {:.0} | {:.1}% | {} |",
        ipv6_ip_network_table_lookup.networks_in_table,
        ipv6_ip_network_table_lookup.lookups_performed,
        ipv6_ip_network_table_lookup.lookup_time_ms,
        ipv6_ip_network_table_lookup.lookups_per_second,
        ipv6_ip_network_table_lookup.hit_rate * 100.0,
        ipv6_lookup_comparison
    );
    println!();

    // Save results
    #[derive(Serialize)]
    struct AllResults {
        insert_results: Vec<InsertBenchmarkResult>,
        lookup_results: Vec<LookupBenchmarkResult>,
    }

    let all_results = AllResults {
        insert_results: vec![
            ipv4_radixtarget_insert,
            ipv4_ip_network_table_insert,
            ipv6_radixtarget_insert,
            ipv6_ip_network_table_insert,
        ],
        lookup_results: vec![
            ipv4_radixtarget_lookup,
            ipv4_ip_network_table_lookup,
            ipv6_radixtarget_lookup,
            ipv6_ip_network_table_lookup,
        ],
    };

    if let Ok(json) = serde_json::to_string_pretty(&all_results) {
        std::fs::write("benchmark_results.json", json).unwrap();
        println!("*Results saved to benchmark_results.json*");
    }
}
