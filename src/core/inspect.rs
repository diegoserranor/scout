//! Inspect stage: probe a scan plan and stream a report per host as it fills in.

use std::collections::BTreeMap;
use std::error::Error;
use std::net::Ipv4Addr;

use tokio::sync::mpsc;

use super::types::{HostReport, ScanPlan, Service};
use crate::scans;

/// Buffer for the stream of report snapshots handed back to the caller.
const INSPECT_BUFFER: usize = 128;

/// Run the Inspect stage: scan the plan's host/port pairs and stream a
/// [`HostReport`] snapshot for a host every time it learns something new — its
/// first open port, its TTL, a service banner. Each message is the host's full
/// current report, so consumers key by [`HostReport::host`] and keep the latest.
///
/// Setup (target expansion) is synchronous so failures surface immediately; the
/// scan runs in a background coordinator feeding the returned receiver, which
/// closes once every port has been probed and every enrichment has landed.
pub fn inspect(plan: ScanPlan) -> Result<mpsc::Receiver<HostReport>, Box<dyn Error>> {
    let ScanPlan { hosts, ports } = plan;
    let live_targets = scans::live::build_live_targets(hosts, ports)?;

    let (tx, rx) = mpsc::channel(INSPECT_BUFFER);
    tokio::spawn(coordinate(live_targets, tx));
    Ok(rx)
}

/// A result from one of the per-host/per-port enrichment probes.
enum Enrich {
    Ttl(Ipv4Addr, Option<u8>),
    Service(Ipv4Addr, u16, Option<String>),
}

/// Drive the live sweep, fan out TTL and service probes as open ports surface,
/// and emit a fresh report snapshot on every change until all work is done.
async fn coordinate(live_targets: Vec<scans::live::LiveTarget>, tx: mpsc::Sender<HostReport>) {
    let mut live_rx = scans::live::LiveScan::build(live_targets).spawn();
    let (enrich_tx, mut enrich_rx) = mpsc::channel::<Enrich>(INSPECT_BUFFER);

    let mut reports: BTreeMap<Ipv4Addr, HostReport> = BTreeMap::new();
    let mut pending: usize = 0; // enrichment probes still in flight
    let mut sweeping = true; // live sweep still running

    loop {
        // Done once the sweep has finished and no enrichment is outstanding.
        if !sweeping && pending == 0 {
            break;
        }

        tokio::select! {
            live = live_rx.recv(), if sweeping => match live {
                Some((ip, port, true)) => {
                    let first_sighting = !reports.contains_key(&ip);
                    let report = reports.entry(ip).or_insert_with(|| empty_report(ip));
                    insert_port(report, port);
                    if tx.send(report.clone()).await.is_err() {
                        return; // consumer hung up
                    }

                    // Enrich on open ports only: TTL once per host, a banner per port.
                    if first_sighting {
                        pending += 1;
                        spawn_ttl(ip, enrich_tx.clone());
                    }
                    pending += 1;
                    spawn_service(ip, port, enrich_tx.clone());
                }
                Some(_) => {} // closed port
                None => sweeping = false,
            },
            Some(result) = enrich_rx.recv() => {
                pending -= 1;
                if let Some(report) = apply_enrichment(&mut reports, result)
                    && tx.send(report).await.is_err()
                {
                    return;
                }
            }
        }
    }
}

/// Fold an enrichment result into its host's report, returning a fresh snapshot
/// when it actually changed something.
fn apply_enrichment(
    reports: &mut BTreeMap<Ipv4Addr, HostReport>,
    result: Enrich,
) -> Option<HostReport> {
    match result {
        Enrich::Ttl(ip, Some(ttl)) => {
            let report = reports.get_mut(&ip)?;
            report.ttl = Some(ttl);
            Some(report.clone())
        }
        Enrich::Service(ip, port, Some(banner)) => {
            let report = reports.get_mut(&ip)?;
            insert_service(report, port, banner);
            Some(report.clone())
        }
        // A probe that found nothing still counts toward `pending`; nothing to emit.
        Enrich::Ttl(_, None) | Enrich::Service(_, _, None) => None,
    }
}

fn spawn_ttl(ip: Ipv4Addr, enrich_tx: mpsc::Sender<Enrich>) {
    tokio::spawn(async move {
        let ttl = scans::ttl::probe(ip).await;
        let _ = enrich_tx.send(Enrich::Ttl(ip, ttl)).await;
    });
}

fn spawn_service(ip: Ipv4Addr, port: u16, enrich_tx: mpsc::Sender<Enrich>) {
    tokio::spawn(async move {
        let banner = scans::service::probe(ip, port).await;
        let _ = enrich_tx.send(Enrich::Service(ip, port, banner)).await;
    });
}

fn empty_report(host: Ipv4Addr) -> HostReport {
    HostReport {
        host,
        ttl: None,
        open_ports: Vec::new(),
        services: Vec::new(),
    }
}

/// Insert a port keeping `open_ports` sorted and deduplicated.
fn insert_port(report: &mut HostReport, port: u16) {
    if let Err(pos) = report.open_ports.binary_search(&port) {
        report.open_ports.insert(pos, port);
    }
}

/// Insert a service keeping `services` sorted by (port, banner) and deduplicated.
fn insert_service(report: &mut HostReport, port: u16, banner: String) {
    let found = report.services.binary_search_by(|s| {
        s.port
            .cmp(&port)
            .then_with(|| s.banner.as_str().cmp(&banner))
    });
    if let Err(pos) = found {
        report.services.insert(pos, Service { port, banner });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    #[test]
    fn insert_port_keeps_sorted_and_deduplicated() {
        let mut report = empty_report(ip());
        insert_port(&mut report, 443);
        insert_port(&mut report, 22);
        insert_port(&mut report, 80);
        insert_port(&mut report, 22); // duplicate is a no-op
        assert_eq!(report.open_ports, vec![22, 80, 443]);
    }

    #[test]
    fn insert_service_sorts_by_port_then_banner() {
        let mut report = empty_report(ip());
        insert_service(&mut report, 80, "nginx".to_string());
        insert_service(&mut report, 22, "OpenSSH".to_string());
        insert_service(&mut report, 80, "apache".to_string());
        let ordered: Vec<_> = report
            .services
            .iter()
            .map(|s| (s.port, s.banner.as_str()))
            .collect();
        assert_eq!(
            ordered,
            vec![(22, "OpenSSH"), (80, "apache"), (80, "nginx")]
        );
    }

    #[test]
    fn insert_service_deduplicates_identical_entries() {
        let mut report = empty_report(ip());
        insert_service(&mut report, 80, "nginx".to_string());
        insert_service(&mut report, 80, "nginx".to_string());
        assert_eq!(report.services.len(), 1);
    }

    #[test]
    fn apply_enrichment_ttl_sets_and_returns_snapshot() {
        let mut reports = BTreeMap::new();
        reports.insert(ip(), empty_report(ip()));
        let snapshot = apply_enrichment(&mut reports, Enrich::Ttl(ip(), Some(64)));
        assert_eq!(snapshot.unwrap().ttl, Some(64));
        assert_eq!(reports[&ip()].ttl, Some(64));
    }

    #[test]
    fn apply_enrichment_service_adds_and_returns_snapshot() {
        let mut reports = BTreeMap::new();
        reports.insert(ip(), empty_report(ip()));
        let snapshot = apply_enrichment(
            &mut reports,
            Enrich::Service(ip(), 22, Some("OpenSSH".to_string())),
        );
        let services = snapshot.unwrap().services;
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].port, 22);
    }

    #[test]
    fn apply_enrichment_none_results_emit_nothing() {
        let mut reports = BTreeMap::new();
        reports.insert(ip(), empty_report(ip()));
        assert!(apply_enrichment(&mut reports, Enrich::Ttl(ip(), None)).is_none());
        assert!(apply_enrichment(&mut reports, Enrich::Service(ip(), 22, None)).is_none());
    }

    #[test]
    fn apply_enrichment_unknown_ip_emits_nothing() {
        let mut reports: BTreeMap<Ipv4Addr, HostReport> = BTreeMap::new();
        assert!(apply_enrichment(&mut reports, Enrich::Ttl(ip(), Some(64))).is_none());
    }
}
