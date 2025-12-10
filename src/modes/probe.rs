use std::collections::BTreeMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Instant;

use cidr::Ipv4Cidr;

use crate::cli::console;
use crate::scan::{self, scanner};

/// Scan a range of ports with a TCP probe for a target.
/// The target can be an IP address (e.g. 192.168.55.42) or a CIDR block (e.g. 192.168.55.0/24).
pub async fn probe(
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

    let ports = start..=end;

    let hosts: Vec<Ipv4Addr>;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        hosts = vec![ip];
    } else if let Ok(cidr) = target.parse::<Ipv4Cidr>() {
        hosts = cidr.iter().map(|ip| ip.address()).collect();
    } else {
        return Err("Target not supported; supply IP address or CIDR".into());
    }

    let now = Instant::now();

    let scanner = scan::scanner::Scanner::build(hosts, ports);

    let console = console::console_with_label(
        scanner.targets.len().try_into().unwrap(),
        "Probing targets...",
        "targets",
    );

    let mut rx = scanner.spawn();

    let mut open_ports: Vec<scanner::ScanTarget> = Vec::new();
    while let Some((target, port, open)) = rx.recv().await {
        console::progress(&console);
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

    let table = console::build_probe_table(&flattened);
    println!();
    println!("\n{table}");

    let elapsed = now.elapsed();
    println!();
    println!("Elapsed time: {:?}", elapsed);

    Ok(())
}
