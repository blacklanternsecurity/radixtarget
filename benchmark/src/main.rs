use clap::{Parser, Subcommand};
use radixtarget::{RadixTarget, ScopeMode};
use rand::prelude::*;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "radixtarget-benchmark")]
#[command(about = "Benchmark RadixTarget performance, and compare two benchmark runs")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Benchmark the radixtarget this binary was built against
    Run {
        #[arg(short, long, default_value = "100000")]
        size: usize,

        #[arg(short, long, default_value = "100000")]
        lookups: usize,

        /// Repetitions per benchmark; the median time is reported
        #[arg(short, long, default_value = "5")]
        runs: usize,

        /// Seed for the generated data, so separate runs use identical inputs
        #[arg(long, default_value = "1337")]
        seed: u64,

        #[arg(short, long, default_value = "benchmark_results.json")]
        output: PathBuf,
    },
    /// Print a markdown comparison of two `run` outputs
    Compare {
        /// Results for the target branch. If missing, only head results are shown
        #[arg(long)]
        base: Option<PathBuf>,

        #[arg(long)]
        head: PathBuf,

        #[arg(long, default_value = "base")]
        base_label: String,

        #[arg(long, default_value = "head")]
        head_label: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Measurement {
    name: String,
    operations: usize,
    median_time_ms: f64,
    hit_rate: Option<f64>,
}

#[derive(Serialize, Deserialize)]
struct Results {
    size: usize,
    lookups: usize,
    runs: usize,
    seed: u64,
    measurements: Vec<Measurement>,
}

fn generate_ipv4_data(rng: &mut StdRng, size: usize) -> Vec<String> {
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

fn generate_ipv6_data(rng: &mut StdRng, size: usize) -> Vec<String> {
    let mut ipv6_networks = Vec::new();

    // Generate IPv6 networks with proper network addresses
    for _ in 0..size {
        let prefix = rng.gen_range(1..=128);

        // Generate random IPv6 segments
        let segments: [u16; 8] = rng.gen();

        // Apply the prefix mask to get the network address
        let mut network_segments = segments;
        let full_segments = prefix / 16;
        let remaining_bits = prefix % 16;

        // Zero out segments beyond the prefix
        for segment in network_segments.iter_mut().skip(full_segments as usize + 1) {
            *segment = 0;
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

fn generate_ipv4_lookup_ips(rng: &mut StdRng, lookup_count: usize) -> Vec<String> {
    (0..lookup_count)
        .map(|_| {
            format!(
                "{}.{}.{}.{}",
                rng.gen_range(1..=255),
                rng.gen_range(0..=255),
                rng.gen_range(0..=255),
                rng.gen_range(1..=254)
            )
        })
        .collect()
}

fn generate_ipv6_lookup_ips(rng: &mut StdRng, lookup_count: usize) -> Vec<String> {
    (0..lookup_count)
        .map(|_| {
            let segments: Vec<String> = (0..8).map(|_| format!("{:x}", rng.gen::<u16>())).collect();
            segments.join(":")
        })
        .collect()
}

fn median(mut times: Vec<f64>) -> f64 {
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    times[times.len() / 2]
}

fn build_target(networks: &[String]) -> RadixTarget {
    let mut rt = RadixTarget::new(&[], ScopeMode::Normal).expect("Failed to create RadixTarget");
    for network in networks {
        let _ = rt.insert(network);
    }
    rt
}

fn benchmark_insert(name: &str, networks: &[String], runs: usize) -> Measurement {
    let times = (0..runs)
        .map(|_| {
            let start = Instant::now();
            let rt = build_target(networks);
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            // Freeing the tree isn't part of insert time
            drop(rt);
            elapsed
        })
        .collect();

    Measurement {
        name: name.to_string(),
        operations: networks.len(),
        median_time_ms: median(times),
        hit_rate: None,
    }
}

fn benchmark_lookup(
    name: &str,
    networks: &[String],
    lookup_ips: &[String],
    runs: usize,
) -> Measurement {
    let rt = build_target(networks);
    let mut hits = 0;
    let times = (0..runs)
        .map(|_| {
            hits = 0;
            let start = Instant::now();
            for lookup in lookup_ips {
                if rt.get(lookup).is_some() {
                    hits += 1;
                }
            }
            start.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    Measurement {
        name: name.to_string(),
        operations: lookup_ips.len(),
        median_time_ms: median(times),
        hit_rate: Some(hits as f64 / lookup_ips.len() as f64),
    }
}

fn accuracy_test() -> bool {
    println!("Running accuracy test...");

    // Test cases: networks and expected matches
    let test_networks = [
        "192.168.1.0/24",
        "192.168.1.0/25", // More specific than above
        "10.0.0.0/8",
        "10.1.0.0/16", // More specific than above
        "10.1.1.0/24", // Even more specific
        "2001:db8::/32",
        "2001:db8:1::/48", // More specific than above
    ];

    let test_cases = [
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

    let rt = build_target(
        &test_networks
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    );

    let mut all_passed = true;
    for (test_ip, expected) in &test_cases {
        let result = rt.get(test_ip);
        if result.as_deref() == *expected {
            println!("  PASS: {} -> {:?}", test_ip, expected);
        } else {
            println!(
                "  FAIL: {} - Expected: {:?}, got: {:?}",
                test_ip, expected, result
            );
            all_passed = false;
        }
    }

    all_passed
}

fn run(size: usize, lookups: usize, runs: usize, seed: u64, output: PathBuf) {
    if !accuracy_test() {
        eprintln!("Accuracy test failed! Aborting benchmark.");
        std::process::exit(1);
    }

    let mut rng = StdRng::seed_from_u64(seed);
    let ipv4_networks = generate_ipv4_data(&mut rng, size);
    let ipv4_lookup_ips = generate_ipv4_lookup_ips(&mut rng, lookups);
    let ipv6_networks = generate_ipv6_data(&mut rng, size);
    let ipv6_lookup_ips = generate_ipv6_lookup_ips(&mut rng, lookups);

    println!("Running benchmarks ({} runs each)...", runs);
    let measurements = vec![
        benchmark_insert("IPv4 insert", &ipv4_networks, runs),
        benchmark_lookup("IPv4 lookup", &ipv4_networks, &ipv4_lookup_ips, runs),
        benchmark_insert("IPv6 insert", &ipv6_networks, runs),
        benchmark_lookup("IPv6 lookup", &ipv6_networks, &ipv6_lookup_ips, runs),
    ];
    for m in &measurements {
        println!("  {}: {:.2} ms", m.name, m.median_time_ms);
    }

    let results = Results {
        size,
        lookups,
        runs,
        seed,
        measurements,
    };
    std::fs::write(&output, serde_json::to_string_pretty(&results).unwrap()).unwrap();
    println!("Results saved to {}", output.display());
}

fn load(path: &PathBuf) -> Results {
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parsing {}: {}", path.display(), e))
}

fn compare(base: Option<PathBuf>, head: PathBuf, base_label: String, head_label: String) {
    let head = load(&head);
    let base = base.map(|p| load(&p));

    println!("## RadixTarget Benchmark Results");
    println!();
    println!(
        "{} networks per table, {} lookups, median of {} runs (seed {}).",
        head.size, head.lookups, head.runs, head.seed
    );
    println!();

    match base {
        Some(base) => {
            println!(
                "| Benchmark | {} (ms) | {} (ms) | Change |",
                base_label, head_label
            );
            println!("| --------- | ---: | ---: | ---: |");
            for h in &head.measurements {
                match base.measurements.iter().find(|b| b.name == h.name) {
                    Some(b) => {
                        let change =
                            (h.median_time_ms - b.median_time_ms) / b.median_time_ms * 100.0;
                        // Shared CI runners are noisy; only flag changes beyond 10%
                        let marker = if change <= -10.0 {
                            "🟢 "
                        } else if change >= 10.0 {
                            "🔴 "
                        } else {
                            ""
                        };
                        println!(
                            "| {} | {:.2} | {:.2} | {}{:+.1}% |",
                            h.name, b.median_time_ms, h.median_time_ms, marker, change
                        );
                    }
                    None => println!("| {} | n/a | {:.2} | new |", h.name, h.median_time_ms),
                }
            }
            println!();
            println!("Change is in time taken: negative is faster.");
        }
        None => {
            println!(
                "> Could not benchmark `{}`, so there is nothing to compare against.",
                base_label
            );
            println!();
            println!("| Benchmark | {} (ms) |", head_label);
            println!("| --------- | ---: |");
            for h in &head.measurements {
                println!("| {} | {:.2} |", h.name, h.median_time_ms);
            }
        }
    }
}

fn main() {
    match Args::parse().command {
        Command::Run {
            size,
            lookups,
            runs,
            seed,
            output,
        } => run(size, lookups, runs, seed, output),
        Command::Compare {
            base,
            head,
            base_label,
            head_label,
        } => compare(base, head, base_label, head_label),
    }
}
