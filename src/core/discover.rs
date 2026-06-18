//! Discover stage: enumerate local subnets and find which hosts are live.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::Ipv4Addr;

use getifs::Ifv4Net;
use tokio::sync::mpsc;

use super::types::Host;
use crate::scans::live;
use crate::subnets;

/// Ports TCP-touched to decide whether a host is live. A small common set keeps
/// the sweep fast and needs no raw sockets / root (unlike ICMP); `ping` is used
/// later only as a TTL signal during Inspect.
const LIVENESS_PORTS: &[u16] = &[22, 80, 443];

/// Subnets wider than this are skipped during Discover: exhaustively TCP-touching
/// a /16 (65k hosts) is dominated by dead address space (e.g. Docker bridges) and
/// isn't what Discover is for. Skips are intentionally silent; user-targeted
/// discovery comes later. Narrow or widen to taste.
const MIN_SUBNET_PREFIX: u8 = 22; // keep /22 and narrower

/// Buffer for the stream of live hosts handed back to the caller. Generous enough
/// that the liveness sweep never blocks on a momentarily-busy consumer.
const DISCOVER_BUFFER: usize = 128;

/// Run the Discover stage: enumerate local subnets, expand them into candidate
/// hosts, and stream back each host that responds to a TCP-touch liveness sweep.
///
/// Setup (subnet enumeration, target expansion) happens synchronously so failures
/// surface immediately; the sweep itself runs in a background task feeding the
/// returned receiver. The channel closes once every candidate has been probed.
pub fn discover() -> Result<mpsc::Receiver<Host>, Box<dyn Error>> {
    let nets = subnets::get()?;
    let candidates = candidate_hosts(&nets);

    // Keep each candidate's subnet so we can rebuild its `Host` from the live
    // scan's bare (ip, port) results.
    let subnet_by_ip: HashMap<Ipv4Addr, _> =
        candidates.iter().map(|host| (host.ip, host.subnet)).collect();
    let ips: Vec<Ipv4Addr> = candidates.iter().map(|host| host.ip).collect();
    let targets = live::build_live_targets(ips, LIVENESS_PORTS.to_vec())?;

    let (tx, rx) = mpsc::channel(DISCOVER_BUFFER);
    tokio::spawn(async move {
        let mut live_rx = live::LiveScan::build(targets).spawn();
        // A host is live on its first open port; suppress the rest of its ports.
        let mut seen: HashSet<Ipv4Addr> = HashSet::new();
        while let Some((ip, _port, open)) = live_rx.recv().await {
            if open
                && seen.insert(ip)
                && let Some(&subnet) = subnet_by_ip.get(&ip)
                && tx.send(Host { ip, subnet }).await.is_err()
            {
                break; // consumer hung up
            }
        }
    });

    Ok(rx)
}

/// Expand the given subnets into candidate hosts, tagging each with the subnet
/// it belongs to and skipping our own address.
fn candidate_hosts(nets: &[Ifv4Net]) -> Vec<Host> {
    let mut hosts = Vec::<Host>::new();
    for iface in nets {
        if iface.net().prefix_len() < MIN_SUBNET_PREFIX {
            continue;
        }
        let local_ip = iface.addr();
        for host in iface.net().hosts() {
            if host == local_ip {
                continue;
            }
            hosts.push(Host {
                ip: host,
                subnet: *iface.net(),
            });
        }
    }
    hosts
}
