use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::Duration;

use super::limits;
use super::tcp;

const SCAN_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

pub type ScanTarget = (Ipv4Addr, u16);
pub type ScanResult = (Ipv4Addr, u16, bool);

pub struct Scanner {
    pub targets: Vec<ScanTarget>,
    pub rx: mpsc::Receiver<ScanResult>,
    tx: mpsc::Sender<ScanResult>,
    sem: Arc<Semaphore>,
}

impl Scanner {
    pub fn build(
        hosts: impl IntoIterator<Item = Ipv4Addr>,
        ports: impl IntoIterator<Item = u16>,
    ) -> Self {
        let concurrency = limits::compute_concurrency();
        let channel_size = limits::compute_channel_size(concurrency);

        let sem = Arc::new(Semaphore::new(concurrency));
        let (tx, rx) = mpsc::channel(channel_size);

        let ports_vec: Vec<u16> = ports.into_iter().collect();
        let mut targets: Vec<ScanTarget> = Vec::new();
        for host in hosts {
            for &port in &ports_vec {
                targets.push((host, port));
            }
        }

        Scanner {
            targets,
            rx,
            tx,
            sem,
        }
    }

    pub fn spawn(self) -> mpsc::Receiver<ScanResult> {
        for (host, port) in self.targets {
            let sem = self.sem.clone();
            let tx = self.tx.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let open = tcp::connect_with_timeout((host, port), SCAN_CONNECT_TIMEOUT)
                    .await
                    .is_some();
                let _ = tx.send((host, port, open)).await;
                drop(_permit);
            });
        }
        drop(self.tx);
        return self.rx;
    }
}
