use crate::cli::console::OUTPUT_WIDTH;
use crate::{cli::console, scans};
use cidr::Ipv4Cidr;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table};
use std::collections::BTreeMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Instant;

/// Scan a range of ports with a TCP probe for a target.
/// The target can be an IP address (e.g. 192.168.55.42) or a CIDR block (e.g. 192.168.55.0/24).
pub async fn probe(
    target: String,
    start: Option<u16>,
    end: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    let now = Instant::now();

    let hosts = build_hosts(target)?;
    let ports = build_port_range(start, end)?;
    let live_targets = scans::live::build_live_targets(hosts, ports)?;

    let total: u64 = live_targets.len().try_into().unwrap();
    let console = console::console_with_label(total, "Probing targets...", "targets");

    let live_scan = scans::live::LiveScan::build(live_targets);
    let mut rx = live_scan.spawn();
    let mut open_ports: Vec<(Ipv4Addr, u16)> = Vec::new();
    while let Some((target, port, open)) = rx.recv().await {
        console::progress(&console);
        if open {
            open_ports.push((target, port));
        }
    }

    print_results(now, open_ports);

    Ok(())
}

fn build_hosts(target: String) -> Result<Vec<Ipv4Addr>, Box<dyn Error>> {
    let hosts: Vec<Ipv4Addr>;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        hosts = vec![ip];
    } else if let Ok(cidr) = target.parse::<Ipv4Cidr>() {
        hosts = cidr.iter().map(|ip| ip.address()).collect();
    } else {
        return Err("Target not supported; supply IP address or CIDR".into());
    }

    Ok(hosts)
}

fn build_port_range(start: Option<u16>, end: Option<u16>) -> Result<Vec<u16>, Box<dyn Error>> {
    let start = start.unwrap_or(1);
    let end = end.unwrap_or(1024);
    if start > end {
        return Err("start port must be smaller than end poirt".into());
    }

    Ok((start..=end).collect())
}

fn print_results(start: Instant, open_ports: Vec<(Ipv4Addr, u16)>) {
    if open_ports.is_empty() {
        println!("No ports found");
        return;
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

    let table = build_table(&flattened);
    println!();
    println!("\n{table}");

    let elapsed = start.elapsed();
    println!();
    println!("Elapsed time: {:?}", elapsed);
}

fn build_table(results: &[(Ipv4Addr, Vec<u16>)]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(OUTPUT_WIDTH)
        .set_header(vec!["Host", "Open ports"]);

    for (ip, ports) in results {
        table.add_row(vec![ip.to_string(), format_open_ports(ports)]);
    }

    table
}

fn format_open_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
