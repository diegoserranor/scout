use super::tcp;
use crate::jobs;
use std::{error::Error, net::Ipv4Addr};
use tokio::{sync::mpsc, time::Duration};

const SCAN_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

pub type LiveResult = (Ipv4Addr, u16, bool);

pub type LiveTarget = (Ipv4Addr, u16);

pub fn build_live_targets(
    hosts: Vec<Ipv4Addr>,
    ports: Vec<u16>,
) -> Result<Vec<LiveTarget>, Box<dyn Error>> {
    let capacity = hosts
        .len()
        .checked_mul(ports.len())
        .ok_or("too many targets: host/port cartesian product overflowed")?;

    let mut live_targets: Vec<LiveTarget> = Vec::with_capacity(capacity);
    for host in &hosts {
        for port in &ports {
            live_targets.push((*host, *port));
        }
    }

    Ok(live_targets)
}

pub struct LiveScan {
    pub targets: Vec<LiveTarget>,
}

impl LiveScan {
    pub fn build(targets: Vec<LiveTarget>) -> Self {
        LiveScan { targets }
    }

    pub fn spawn(self) -> mpsc::Receiver<LiveResult> {
        let runner = jobs::Runner::<LiveTarget, LiveResult>::build(self.targets);
        runner.spawn(|(host, port)| async move { scan(host, port).await })
    }
}

async fn scan(host: Ipv4Addr, port: u16) -> LiveResult {
    let open = tcp::connect_with_timeout((host, port), SCAN_CONNECT_TIMEOUT)
        .await
        .is_some();
    (host, port, open)
}
