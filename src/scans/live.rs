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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, last)
    }

    #[test]
    fn cartesian_product_is_host_major() {
        let hosts = vec![ip(1), ip(2)];
        let ports = vec![80, 443, 8080];
        let targets = build_live_targets(hosts, ports).unwrap();
        assert_eq!(
            targets,
            vec![
                (ip(1), 80),
                (ip(1), 443),
                (ip(1), 8080),
                (ip(2), 80),
                (ip(2), 443),
                (ip(2), 8080),
            ]
        );
    }

    #[test]
    fn single_host_single_port() {
        let targets = build_live_targets(vec![ip(50)], vec![22]).unwrap();
        assert_eq!(targets, vec![(ip(50), 22)]);
    }

    #[test]
    fn empty_inputs_yield_no_targets() {
        assert!(build_live_targets(vec![], vec![80]).unwrap().is_empty());
        assert!(build_live_targets(vec![ip(1)], vec![]).unwrap().is_empty());
    }

    // NOTE: the `checked_mul` overflow guard in `build_live_targets` is
    // intentionally left uncovered — triggering it would require allocating
    // vectors large enough to overflow `usize`.
}
