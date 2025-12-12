use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table};
use getifs::Ifv4Net;

use crate::{
    cli::console::{self, OUTPUT_WIDTH},
    scans, subnets,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    net::Ipv4Addr,
};

// Modest set of TCP ports commonly exposed by consumer devices/services.
const DISCOVERY_PORTS: &[u16] = &[22, 23, 53, 80, 139, 443, 445, 631, 8000, 8080, 8443];

/// Scan and classify local hosts found in IPv4 subnets.
/// Classification is mainly done with TCP probing by checking TTL, HTTP banners, and SSH banners.
pub async fn default() -> Result<(), Box<dyn Error>> {
    let nets = subnets::get()?;
    subnets::print(&nets);
    println!();

    let hosts = build_hosts(&nets);
    let ports: Vec<u16> = DISCOVERY_PORTS.to_vec();
    let live_targets = scans::live::build_live_targets(hosts, ports)?;

    let total: u64 = live_targets.len().try_into().unwrap();
    let console = console::console_with_label(total, "Finding live hosts...", "targets");

    let live_scan = scans::live::LiveScan::build(live_targets);
    let mut live_scan_rx = live_scan.spawn();
    let mut open_ports: Vec<scans::service::ServiceTarget> = vec![];
    while let Some((ip, port, open)) = live_scan_rx.recv().await {
        console::progress(&console);
        if open {
            open_ports.push((ip, port));
        }
    }
    console::finish(&console);
    println!();

    if open_ports.is_empty() {
        println!("\nNo live hosts found on discovered subnets.");
        return Ok(());
    }

    // Deduplicate hosts before TTL probing to avoid redundant pings.
    let ttl_targets: Vec<Ipv4Addr> = open_ports
        .iter()
        .map(|(host, _)| *host)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let total: u64 = ttl_targets.len().try_into().unwrap();
    let ttl_console = console::console_with_label(total, "Pinging hosts...", "targets");

    let ttl_scan = scans::ttl::TTLScan::build(ttl_targets);
    let mut ttl_scan_rx = ttl_scan.run();
    let mut ttl_results: Vec<(Ipv4Addr, u8)> = Vec::new();
    while let Some(result) = ttl_scan_rx.recv().await {
        console::progress(&ttl_console);
        if let Some(result) = result {
            ttl_results.push(result);
        }
    }

    let service_targets = open_ports.clone();
    let total: u64 = service_targets.len().try_into().unwrap();
    let service_console = console::console_with_label(total, "Finding services...", "targets");

    let service_scan = scans::service::ServiceScan::build(service_targets);
    let mut service_scan_rx = service_scan.spawn();
    let mut service_results: Vec<(Ipv4Addr, u16, String)> = Vec::new();
    while let Some(result) = service_scan_rx.recv().await {
        console::progress(&service_console);
        if let Some(result) = result {
            service_results.push(result);
        }
    }
    console::finish(&console);
    println!();

    print_results(open_ports, ttl_results, service_results);

    Ok(())
}

fn build_hosts(nets: &[Ifv4Net]) -> Vec<Ipv4Addr> {
    let mut hosts = Vec::new();
    for subnet in nets {
        let local_ip = subnet.addr();
        for host in subnet.net().hosts() {
            if host == local_ip {
                continue;
            }
            hosts.push(host);
        }
    }
    hosts
}

fn print_results(
    open_ports: Vec<(Ipv4Addr, u16)>,
    ttl_results: Vec<(Ipv4Addr, u8)>,
    service_results: Vec<(Ipv4Addr, u16, String)>,
) {
    let mut rows_by_host: BTreeMap<Ipv4Addr, TableRow> = BTreeMap::new();

    for (host, port) in open_ports {
        let row = rows_by_host.entry(host).or_insert_with(|| TableRow {
            host,
            ttl: None,
            open_ports: Vec::new(),
            services: Vec::new(),
        });
        row.open_ports.push(port);
    }

    for (host, ttl) in ttl_results {
        let row = rows_by_host.entry(host).or_insert_with(|| TableRow {
            host,
            ttl: None,
            open_ports: Vec::new(),
            services: Vec::new(),
        });
        row.ttl = Some(ttl);
    }

    for (host, port, info) in service_results {
        let row = rows_by_host.entry(host).or_insert_with(|| TableRow {
            host,
            ttl: None,
            open_ports: Vec::new(),
            services: Vec::new(),
        });
        row.services.push(format!("{port}: {info}"));
    }

    let mut rows: Vec<TableRow> = rows_by_host.into_values().collect();
    for row in &mut rows {
        row.open_ports.sort_unstable();
        row.open_ports.dedup();
        row.services.sort();
        row.services.dedup();
    }
    rows.sort_by_key(|row| row.host);

    let table = build_table(&rows);
    println!();
    println!("\n{table}");
}

struct TableRow {
    host: Ipv4Addr,
    ttl: Option<u8>,
    open_ports: Vec<u16>,
    services: Vec<String>,
}

fn build_table(rows: &[TableRow]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(OUTPUT_WIDTH)
        .set_header(vec!["Host", "Ping TTL", "Open ports", "Services"]);

    for row in rows {
        let ttl = row
            .ttl
            .map(|ttl| ttl.to_string())
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![
            row.host.to_string(),
            ttl,
            format_open_ports(&row.open_ports),
            format_services(&row.services),
        ]);
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

fn format_services(services: &[String]) -> String {
    if services.is_empty() {
        return "-".to_string();
    }

    services.join("\n")
}
