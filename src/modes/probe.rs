use std::collections::BTreeMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::cli::console;
use crate::scan::{limits, scanner};

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

    let concurrency = limits::compute_concurrency();
    let channel_size = limits::compute_channel_size(concurrency);

    let now = Instant::now();

    let scan_items = scanner::build_target_scan_items(&target, start, end)?;
    let mut scanner = scanner::spawn(scan_items, concurrency, channel_size).await?;

    let console = console::console_with_label(scanner.total, "Probing targets...", "targets");

    let mut open_ports: Vec<scanner::ScanItem> = Vec::new();
    while let Some((target, port, open)) = scanner.rx.recv().await {
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
