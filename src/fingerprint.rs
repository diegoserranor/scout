use std::net::Ipv4Addr;
use tokio::process::Command;

use crate::scan::{connect_with_timeout, read_with_timeout, write_with_timeout};

pub struct HostFingerprint {
    pub ttl_guess: Option<String>,
    pub services: Vec<String>,
}

/// Fingerprint a host: TTL for OS/hop hint, plus service banners on known ports.
pub async fn host(ip: Ipv4Addr, open_ports: &[u16]) -> HostFingerprint {
    let ttl_guess = ttl(ip).await;
    let services = services(ip, open_ports).await;

    HostFingerprint {
        ttl_guess,
        services,
    }
}

/// Ping once and derive likely OS family and hop distance from TTL.
pub async fn ttl(ip: Ipv4Addr) -> Option<String> {
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "1", &ip.to_string()])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ttl = stdout.split_whitespace().find_map(|segment| {
        segment
            .strip_prefix("ttl=")
            .and_then(|v| v.parse::<u8>().ok())
    })?;

    let (base, os_guess): (u8, &str) = match ttl {
        1..=64 => (64, "likely Linux/macOS/iOS"),
        65..=128 => (128, "likely Windows"),
        _ => (255, "likely network gear/other"),
    };
    let hops = base.saturating_sub(ttl);
    let hint = if hops == 0 {
        os_guess.to_string()
    } else {
        format!("{os_guess}, {hops} hop(s) away")
    };

    Some(format!("{ttl} ({hint})"))
}

/// Attempt to grab banners from HTTP-like ports, then SSH.
pub async fn services(ip: Ipv4Addr, open_ports: &[u16]) -> Vec<String> {
    let mut results = Vec::new();

    for &port in open_ports {
        let banner = match port {
            80 | 8000 | 8080 | 8443 | 443 => http_banner(ip, port).await,
            22 => ssh_banner(ip, port).await,
            _ => None,
        };

        if let Some(banner) = banner {
            results.push(banner);
        }
    }

    results
}

pub async fn http_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut stream = connect_with_timeout((ip, port)).await?;

    let request =
        format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: scout\r\nConnection: close\r\n\r\n");
    write_with_timeout(&mut stream, request.as_bytes()).await?;

    let mut buf = [0u8; 2048];
    let read = read_with_timeout(&mut stream, &mut buf).await?;
    if read == 0 {
        return None;
    }

    let data = String::from_utf8_lossy(&buf[..read]);
    let status_line = data.lines().next().unwrap_or("").to_string();
    let server_header = data
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("server:"))
        .map(|line| line.to_string());

    Some(match server_header {
        Some(server) => format!("HTTP:{port} {status_line} | {server}"),
        None => format!("HTTP:{port} {status_line}"),
    })
}

pub async fn ssh_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut stream = connect_with_timeout((ip, port)).await?;

    let mut buf = [0u8; 512];
    let read = read_with_timeout(&mut stream, &mut buf).await?;
    if read == 0 {
        return None;
    }

    let banner = String::from_utf8_lossy(&buf[..read]).trim().to_string();
    if banner.is_empty() {
        None
    } else {
        Some(format!("SSH:{port} {banner}"))
    }
}
