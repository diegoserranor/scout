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
const DISCOVERY_PORTS: &[u16] = &[22, 23, 53, 80, 139, 443, 445, 631, 8000, 8080, 8443];

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

/// Scan a range of ports with a TCP probe for a target.
/// The target can be an IP address (e.g. 192.168.55.42) or a CIDR block (e.g. 192.168.55.0/24).
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

    let console = cli::console_with_label(scanner.total, "Probing targets...", "targets");

    let mut open_ports: Vec<scan::ScanItem> = Vec::new();
    while let Some((target, port, open)) = scanner.rx.recv().await {
        cli::progress(&console);
        if open {
            open_ports.push((target, port));
        }
    }

    if open_ports.is_empty() {
        println!("No ports found");
        return Ok(());
    }

    let mut grouped: BTreeMap<Ipv4Addr, Vec<u16>> = BTreeMap::new();
    for (target, port) in open_ports {
        grouped.entry(target).or_default().push(port);
    }

    for ports in grouped.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }

    let mut flattened: Vec<(Ipv4Addr, Vec<u16>)> = grouped.into_iter().collect();
    flattened.sort_by_key(|(ip, _)| *ip);

    let table = cli::build_probe_table(&flattened);
    println!();
    println!("\n{table}");

    let elapsed = now.elapsed();
    println!();
    println!("Elapsed time: {:?}", elapsed);

    Ok(())
}

/// Enumerate local networks.
fn run_networks() -> Result<(), Box<dyn Error>> {
    let nets = subnets::get()?;
    subnets::print(&nets);
    Ok(())
}

/// Discover and fingerprint local hosts found in IPv4 subnets.
/// Fingerprinting is mainly done with TCP probing by checking TTL, HTTP banners, and SSH banners.
async fn run_default() -> Result<(), Box<dyn Error>> {
    let nets = subnets::get()?;
    subnets::print(&nets);
    println!();

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
    let console = cli::console_with_label(scanner.total, "Finding live hosts...", "targets");

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

    let fp_console = cli::console_with_label(hosts.len() as u64, "Fingerprinting...", "hosts");
    let mut results: Vec<(Ipv4Addr, Vec<u16>, fingerprint::HostFingerprint)> = Vec::new();
    for (ip, ports) in hosts {
        let fp = fingerprint::host(ip, &ports).await;
        results.push((ip, ports, fp));
        cli::progress(&fp_console);
    }
    cli::finish(&fp_console);

    let table = cli::build_results_table(&results);

    println!();
    println!("\n{table}");

    Ok(())
}

