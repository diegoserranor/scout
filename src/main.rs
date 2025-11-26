use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::net::Ipv4Addr;
use tokio::time::Instant;

mod cli;
mod fingerprint;
mod limits;
mod scan;
mod subnets;

use crate::cli::Commands;

// Modest set of TCP ports commonly exposed by consumer devices/services.
const DISCOVERY_PORTS: &[u16] = &[22, 23, 53, 80, 443, 631, 8000, 8080, 8443, 139, 445];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = cli::parse_args();

    match cli.command {
        Some(Commands::Probe { target, start, end }) => run_probe(target, start, end).await?,
        Some(Commands::Networks) => run_networks()?,
        None => run_default().await?,
    }

    Ok(())
}

async fn run_probe(
    target: String,
    start: Option<u16>,
    end: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    let start = start.unwrap_or(1);
    let end = end.unwrap_or(1024);

    if start > end {
        eprintln!("start_port must be <= end_port");
        std::process::exit(1);
    }

    let concurrency = limits::compute_concurrency();
    let channel_size = limits::compute_channel_size(concurrency);

    let now = Instant::now();

    let scan_items = scan::build_target_scan_items(&target, start, end)?;
    let mut scanner = scan::spawn(scan_items, concurrency, channel_size).await?;

    let console = cli::console(scanner.total);

    let mut open_ports: Vec<scan::ScanItem> = Vec::new();
    while let Some((target, port, open)) = scanner.rx.recv().await {
        cli::progress(&console);
        if open {
            open_ports.push((target, port));
        }
    }

    if !open_ports.is_empty() {
        println!("Open ports:");
        for (target, port) in open_ports {
            let open = format!("{}:{}", target, port);
            println!("{}", open);
        }
    } else {
        println!("No ports found");
    }

    let elapsed = now.elapsed();
    println!("Elapsed time: {:?}", elapsed);

    Ok(())
}

/// Enumerate local networks.
fn run_networks() -> Result<(), Box<dyn Error>> {
    let nets = subnets::get()?;
    subnets::print(&nets);
    Ok(())
}

/// Discover and fingerprint local hosts:
/// 1) Enumerate local IPv4 subnets, build a TCP scan list over `DISCOVERY_PORTS` for every host except our own IP.
/// 2) Run a bounded TCP connect scan to find hosts with responsive ports.
/// 3) For each live host (TCP-open), fingerprint in order:
///    - TTL probe (ping) for OS family and hop-distance hint.
///    - Service probes on open ports: HTTP first (80/443/8000/8080/8443), then SSH (22); collect every banner that responds.
async fn run_default() -> Result<(), Box<dyn Error>> {
    let nets = subnets::get()?;
    subnets::print(&nets);

    let concurrency = limits::compute_concurrency();
    let channel_size = limits::compute_channel_size(concurrency);

    let mut hosts = Vec::new();
    for subnet in &nets {
        let local_ip = subnet.addr();
        for host in subnet.net().hosts() {
            if host == local_ip {
                continue;
            }
            hosts.push(host);
        }
    }

    let scan_items = scan::build_scan_items(hosts, DISCOVERY_PORTS.iter().copied());
    let mut scanner = scan::spawn(scan_items, concurrency, channel_size).await?;
    let console = cli::console_with_label(scanner.total, "Finding live hosts");

    let mut open_hosts: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    while let Some((ip, port, open)) = scanner.rx.recv().await {
        cli::progress(&console);
        if open {
            open_hosts.entry(ip).or_default().push(port);
        }
    }
    cli::finish(&console);
    println!();

    for ports in open_hosts.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }

    let hosts: BTreeMap<Ipv4Addr, Vec<u16>> = open_hosts.into_iter().collect();

    if hosts.is_empty() {
        println!("\nNo live hosts found on discovered subnets.");
        return Ok(());
    }

    let fp_console = cli::console_with_label(hosts.len() as u64, "Fingerprinting");
    let mut results: Vec<(Ipv4Addr, Vec<u16>, fingerprint::HostFingerprint)> = Vec::new();
    for (ip, ports) in hosts {
        let fp = fingerprint::host(ip, &ports).await;
        results.push((ip, ports, fp));
        cli::progress(&fp_console);
    }
    cli::finish(&fp_console);

    println!("\n\nLive hosts (open discovery ports):");
    for (ip, ports, fp) in results {
        println!("{ip} -> ports {:?}", ports);
        if let Some(ttl_guess) = fp.ttl_guess {
            println!("  ttl_fingerprint: {ttl_guess}");
        }
        if !fp.services.is_empty() {
            for service in fp.services {
                println!("  service_fingerprint: {service}");
            }
        }
    }

    Ok(())
}
