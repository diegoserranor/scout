use cidr::Ipv4Cidr;
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Duration, timeout};

const SCAN_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const SERVICE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(3);

pub type ScanItem = (Ipv4Addr, u16);
pub type ScanResult = (Ipv4Addr, u16, bool);

pub struct Scanner {
    pub total: u64,
    pub rx: mpsc::Receiver<ScanResult>,
}

/// Build scan items for an IP or CIDR target; domain targets are rejected.
pub fn build_target_scan_items(
    target: &str,
    start: u16,
    end: u16,
) -> Result<Vec<ScanItem>, Box<dyn Error>> {
    let ports = start..=end;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        Ok(build_scan_items(std::iter::once(ip), ports))
    } else if let Ok(cidr) = target.parse::<Ipv4Cidr>() {
        let hosts = cidr.iter().map(|ip| ip.address());
        Ok(build_scan_items(hosts, ports))
    } else {
        Err("Target not supported; supply IP address or CIDR".into())
    }
}

/// Build scan items from hosts and ports so all flows share the same construction.
pub fn build_scan_items(
    hosts: impl IntoIterator<Item = Ipv4Addr>,
    ports: impl IntoIterator<Item = u16>,
) -> Vec<ScanItem> {
    let ports_vec: Vec<u16> = ports.into_iter().collect();
    let mut scan_items: Vec<ScanItem> = Vec::new();
    for host in hosts {
        for &port in &ports_vec {
            scan_items.push((host, port));
        }
    }
    scan_items
}

pub async fn spawn(
    scan_items: Vec<ScanItem>,
    concurrency: usize,
    channel_size: usize,
) -> Result<Scanner, Box<dyn Error>> {
    let total = scan_items.len() as u64;
    if total == 0 {
        return Err("No items to scan".into());
    }

    let sem = Arc::new(Semaphore::new(concurrency));
    let (tx, rx) = mpsc::channel(channel_size);

    for (target, port) in scan_items {
        let sem = sem.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let open = scan_one(target, port).await;
            let _ = tx.send((target, port, open)).await;
            drop(_permit);
        });
    }
    drop(tx);

    let scanner = Scanner { total, rx };
    Ok(scanner)
}

async fn scan_one(host: Ipv4Addr, port: u16) -> bool {
    connect_with_deadline((host, port), SCAN_CONNECT_TIMEOUT)
        .await
        .is_some()
}

/// Shared TCP helpers for connect/read/write with bounded timeouts so all probes behave consistently.
pub async fn connect_with_timeout(addr: (Ipv4Addr, u16)) -> Option<TcpStream> {
    connect_with_deadline(addr, SERVICE_CONNECT_TIMEOUT).await
}

async fn connect_with_deadline(addr: (Ipv4Addr, u16), deadline: Duration) -> Option<TcpStream> {
    let connect = TcpStream::connect(addr);
    timeout(deadline, connect).await.ok()?.ok()
}

pub async fn write_with_timeout(stream: &mut TcpStream, buf: &[u8]) -> Option<()> {
    let write = stream.write_all(buf);
    timeout(IO_TIMEOUT, write).await.ok()?.ok()
}

pub async fn read_with_timeout(stream: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    let read = stream.read(buf);
    timeout(IO_TIMEOUT, read).await.ok()?.ok()
}

#[cfg(test)]
mod tests {
    use super::{ScanItem, build_scan_items};
    use std::net::Ipv4Addr;

    #[test]
    fn builds_cartesian_product() {
        let hosts = [
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 11),
        ];
        let ports = [22u16, 80u16];

        let items: Vec<ScanItem> = build_scan_items(hosts, ports);

        assert_eq!(
            items,
            vec![
                (Ipv4Addr::new(192, 168, 1, 10), 22),
                (Ipv4Addr::new(192, 168, 1, 10), 80),
                (Ipv4Addr::new(192, 168, 1, 11), 22),
                (Ipv4Addr::new(192, 168, 1, 11), 80),
            ]
        );
    }

    #[test]
    fn preserves_port_order_from_iter() {
        let host = [Ipv4Addr::new(10, 0, 0, 1)];
        let ports = vec![8080u16, 22u16, 443u16];

        let items = build_scan_items(host, ports);
        let extracted: Vec<u16> = items.into_iter().map(|(_h, p)| p).collect();

        assert_eq!(extracted, vec![8080, 22, 443]);
    }
}
