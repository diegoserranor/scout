use crate::jobs;
use std::net::Ipv4Addr;
use tokio::{process, sync::mpsc};

pub struct TTLScan {
    targets: Vec<Ipv4Addr>,
}

impl TTLScan {
    pub fn build(targets: Vec<Ipv4Addr>) -> Self {
        Self { targets }
    }

    pub fn run(self) -> mpsc::Receiver<Option<(Ipv4Addr, u8)>> {
        let runner = jobs::Runner::<Ipv4Addr, Option<(Ipv4Addr, u8)>>::build(self.targets);
        runner.spawn(ttl)
    }
}

async fn ttl(host: Ipv4Addr) -> Option<(Ipv4Addr, u8)> {
    let output = process::Command::new("ping")
        .args(["-c", "5", "-W", "1", &host.to_string()])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(parse_ttl_from_line)
        .map(|value| (host, value))
}

fn parse_ttl_from_line(line: &str) -> Option<u8> {
    line.split_whitespace()
        .find_map(|segment| segment.strip_prefix("ttl="))
        .and_then(|raw| raw.parse::<u8>().ok())
}
