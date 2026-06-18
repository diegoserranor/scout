use super::tcp;
use std::net::Ipv4Addr;
use tokio::time::Duration;

const SERVICE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Attempt to grab a banner from a known service port (HTTP-like ports, then
/// SSH); `None` for unsupported or silent ports.
pub async fn probe(ip: Ipv4Addr, port: u16) -> Option<String> {
    match port {
        80 | 8000 | 8080 | 8443 | 443 => http_banner(ip, port).await,
        22 => ssh_banner(ip, port).await,
        _ => None,
    }
}

async fn http_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut stream = tcp::connect_with_timeout((ip, port), SERVICE_CONNECT_TIMEOUT).await?;

    let request =
        format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: scout\r\nConnection: close\r\n\r\n");
    tcp::write_with_timeout(&mut stream, request.as_bytes()).await?;

    let mut buf = [0u8; 2048];
    let read = tcp::read_with_timeout(&mut stream, &mut buf).await?;
    if read == 0 {
        return None;
    }

    let data = String::from_utf8_lossy(&buf[..read]);
    let status_line = data.lines().next().unwrap_or("").to_string();
    let server_header = data
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("server:"))
        .map(|line| line.to_string());

    let service_str: String;
    if let Some(header) = server_header {
        service_str = format!("{status_line} | {header}");
    } else {
        service_str = status_line;
    }

    Some(service_str)
}

async fn ssh_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut stream = tcp::connect_with_timeout((ip, port), SERVICE_CONNECT_TIMEOUT).await?;

    let mut buf = [0u8; 512];
    let read = tcp::read_with_timeout(&mut stream, &mut buf).await?;
    if read == 0 {
        return None;
    }

    let banner = String::from_utf8_lossy(&buf[..read]).trim().to_string();
    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}
