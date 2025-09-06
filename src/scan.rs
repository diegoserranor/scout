use cidr::Ipv4Cidr;
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

pub type ScanItem = (Ipv4Addr, u16);
pub type ScanResult = (Ipv4Addr, u16, bool);

pub struct Config {
    pub target: String,
    pub start: u16,
    pub end: u16,
    pub concurrency: usize,
    pub channel_size: usize,
}

pub struct Scanner {
    pub total: u64,
    pub rx: mpsc::Receiver<ScanResult>,
}

pub fn config(
    target: String,
    start: u16,
    end: u16,
    concurrency: usize,
    channel_size: usize,
) -> Config {
    Config {
        target,
        start,
        end,
        concurrency,
        channel_size,
    }
}

pub async fn spawn(config: Config) -> Result<Scanner, Box<dyn Error>> {
    let Config {
        target,
        start,
        end,
        concurrency,
        channel_size,
    } = config;
    let scan_items = if let Ok(ip) = target.parse::<Ipv4Addr>() {
        build_ip_scan_stack(ip, start, end)
    } else if let Ok(cidr) = target.parse::<Ipv4Cidr>() {
        build_cidr_scan_stack(cidr, start, end)
    } else {
        return Err("Domain case - not supported".into());
    };

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
            let open = scan_one(&target.to_string(), port).await;
            let _ = tx.send((target, port, open)).await;
            drop(_permit);
        });
    }
    drop(tx);

    let scanner = Scanner { total, rx };
    Ok(scanner)
}

async fn scan_one(host: &str, port: u16) -> bool {
    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => true,
        Ok(Err(_e)) => false,
        Err(_elapsed) => false,
    }
}

fn build_cidr_scan_stack(cidr: Ipv4Cidr, start: u16, end: u16) -> Vec<ScanItem> {
    let mut scan_items: Vec<ScanItem> = Vec::new();
    for ip in cidr.iter() {
        let ip_addr = ip.address();
        for port in start..=end {
            scan_items.push((ip_addr, port));
        }
    }

    scan_items
}

fn build_ip_scan_stack(ip: Ipv4Addr, start: u16, end: u16) -> Vec<ScanItem> {
    let mut scan_items: Vec<ScanItem> = Vec::new();
    for port in start..=end {
        scan_items.push((ip, port));
    }

    scan_items
}
