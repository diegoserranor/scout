use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    net::Ipv4Addr,
};

use crate::{
    cli::console,
    scan::{fingerprint, limits, scanner, subnets},
};

// Modest set of TCP ports commonly exposed by consumer devices/services.
const DISCOVERY_PORTS: &[u16] = &[22, 23, 53, 80, 139, 443, 445, 631, 8000, 8080, 8443];

/// Discover and fingerprint local hosts found in IPv4 subnets.
/// Fingerprinting is mainly done with TCP probing by checking TTL, HTTP banners, and SSH banners.
pub async fn default() -> Result<(), Box<dyn Error>> {
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

    let scan_items = scanner::build_scan_items(hosts, DISCOVERY_PORTS.iter().copied());
    let mut scanner = scanner::spawn(scan_items, concurrency, channel_size).await?;
    let console = console::console_with_label(scanner.total, "Finding live hosts...", "targets");

    let mut open_hosts: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    while let Some((ip, port, open)) = scanner.rx.recv().await {
        console::progress(&console);
        if open {
            open_hosts.entry(ip).or_default().push(port);
        }
    }
    console::finish(&console);
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

    let fp_console = console::console_with_label(hosts.len() as u64, "Fingerprinting...", "hosts");
    let mut results: Vec<(Ipv4Addr, Vec<u16>, fingerprint::HostFingerprint)> = Vec::new();
    for (ip, ports) in hosts {
        let fp = fingerprint::host(ip, &ports).await;
        results.push((ip, ports, fp));
        console::progress(&fp_console);
    }
    console::finish(&fp_console);

    let table = console::build_results_table(&results);

    println!();
    println!("\n{table}");

    Ok(())
}
