//! Inspect stage: probe a scan plan for open ports, TTL, and service banners.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::net::Ipv4Addr;

use super::types::{HostReport, ScanPlan, Service};
use crate::scans;

/// Run the Inspect stage: scan the plan's host/port pairs, then enrich the live
/// hosts with a TTL ping and service banners, returning one report per host.
pub async fn inspect(plan: ScanPlan) -> Result<Vec<HostReport>, Box<dyn Error>> {
    let ScanPlan { hosts, ports } = plan;

    // Which (host, port) pairs are open.
    let live_targets = scans::live::build_live_targets(hosts, ports)?;
    let mut live_rx = scans::live::LiveScan::build(live_targets).spawn();
    let mut open_ports: Vec<(Ipv4Addr, u16)> = Vec::new();
    while let Some((ip, port, open)) = live_rx.recv().await {
        if open {
            open_ports.push((ip, port));
        }
    }

    if open_ports.is_empty() {
        return Ok(Vec::new());
    }

    // TTL fingerprint: ping each unique live host once.
    let ttl_targets: Vec<Ipv4Addr> = open_ports
        .iter()
        .map(|(ip, _)| *ip)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut ttl_rx = scans::ttl::TTLScan::build(ttl_targets).run();
    let mut ttl_results: Vec<(Ipv4Addr, u8)> = Vec::new();
    while let Some(result) = ttl_rx.recv().await {
        if let Some(result) = result {
            ttl_results.push(result);
        }
    }

    // Service banners on the open ports.
    let mut service_rx = scans::service::ServiceScan::build(open_ports.clone()).spawn();
    let mut service_results: Vec<(Ipv4Addr, u16, String)> = Vec::new();
    while let Some(result) = service_rx.recv().await {
        if let Some(result) = result {
            service_results.push(result);
        }
    }

    Ok(assemble_reports(open_ports, ttl_results, service_results))
}

/// Fold the per-scan results into one [`HostReport`] per host.
fn assemble_reports(
    open_ports: Vec<(Ipv4Addr, u16)>,
    ttl_results: Vec<(Ipv4Addr, u8)>,
    service_results: Vec<(Ipv4Addr, u16, String)>,
) -> Vec<HostReport> {
    // BTreeMap keeps reports ordered by host for stable output.
    let mut reports: BTreeMap<Ipv4Addr, HostReport> = BTreeMap::new();

    for (host, port) in open_ports {
        report_entry(&mut reports, host).open_ports.push(port);
    }
    for (host, ttl) in ttl_results {
        report_entry(&mut reports, host).ttl = Some(ttl);
    }
    for (host, port, banner) in service_results {
        report_entry(&mut reports, host)
            .services
            .push(Service { port, banner });
    }

    let mut reports: Vec<HostReport> = reports.into_values().collect();
    for report in &mut reports {
        report.open_ports.sort_unstable();
        report.open_ports.dedup();
        report
            .services
            .sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.banner.cmp(&b.banner)));
        report.services.dedup_by(|a, b| a.port == b.port && a.banner == b.banner);
    }

    reports
}

/// Get the report for `host`, creating an empty one on first sight.
fn report_entry(
    reports: &mut BTreeMap<Ipv4Addr, HostReport>,
    host: Ipv4Addr,
) -> &mut HostReport {
    reports.entry(host).or_insert_with(|| HostReport {
        host,
        ttl: None,
        open_ports: Vec::new(),
        services: Vec::new(),
    })
}
