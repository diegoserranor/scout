//! Discover stage: enumerate local subnets and find which hosts are live.

use std::collections::HashSet;
use std::error::Error;
use std::net::Ipv4Addr;

use getifs::Ifv4Net;

use super::types::Host;
use crate::scans::live;
use crate::subnets;

/// Ports TCP-touched to decide whether a host is live. A small common set keeps
/// the sweep fast and needs no raw sockets / root (unlike ICMP); `ping` is used
/// later only as a TTL signal during Inspect.
const LIVENESS_PORTS: &[u16] = &[22, 80, 443];

/// Run the Discover stage: enumerate local subnets, expand them into candidate
/// hosts, and return those that respond to a TCP-touch liveness sweep.
pub async fn discover() -> Result<Vec<Host>, Box<dyn Error>> {
    let nets = subnets::get()?;
    let candidates = candidate_hosts(&nets);
    liveness_sweep(candidates).await
}

/// Expand the given subnets into candidate hosts, tagging each with the subnet
/// it belongs to and skipping our own address.
fn candidate_hosts(nets: &[Ifv4Net]) -> Vec<Host> {
    let mut hosts = Vec::<Host>::new();
    for iface in nets {
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

/// Keep only the live candidates: TCP-touch a small set of common ports and
/// treat a host as live if any of them accepts a connection.
async fn liveness_sweep(mut candidates: Vec<Host>) -> Result<Vec<Host>, Box<dyn Error>> {
    let ips: Vec<Ipv4Addr> = candidates.iter().map(|host| host.ip).collect();
    let targets = live::build_live_targets(ips, LIVENESS_PORTS.to_vec())?;

    let mut rx = live::LiveScan::build(targets).spawn();
    let mut alive: HashSet<Ipv4Addr> = HashSet::new();
    while let Some((ip, _port, open)) = rx.recv().await {
        if open {
            alive.insert(ip);
        }
    }

    candidates.retain(|host| alive.contains(&host.ip));
    Ok(candidates)
}
