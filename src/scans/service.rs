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

    parse_http_response(&String::from_utf8_lossy(&buf[..read]))
}

/// Extract a banner from an HTTP response: the status line, optionally joined with
/// the `Server:` header as `"{status} | {header}"`. `None` on empty input.
fn parse_http_response(data: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let status_line = data.lines().next().unwrap_or("").to_string();
    let server_header = data
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("server:"))
        .map(|line| line.to_string());

    match server_header {
        Some(header) => Some(format!("{status_line} | {header}")),
        None => Some(status_line),
    }
}

async fn ssh_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut stream = tcp::connect_with_timeout((ip, port), SERVICE_CONNECT_TIMEOUT).await?;

    let mut buf = [0u8; 512];
    let read = tcp::read_with_timeout(&mut stream, &mut buf).await?;
    if read == 0 {
        return None;
    }

    parse_ssh_banner(&buf[..read])
}

/// Decode and trim an SSH identification banner; `None` if empty after trimming.
fn parse_ssh_banner(bytes: &[u8]) -> Option<String> {
    let banner = String::from_utf8_lossy(bytes).trim().to_string();
    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_line_only_when_no_server_header() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            parse_http_response(response),
            Some("HTTP/1.1 200 OK".to_string())
        );
    }

    #[test]
    fn http_joins_server_header() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n";
        assert_eq!(
            parse_http_response(response),
            Some("HTTP/1.1 200 OK | Server: nginx/1.25".to_string())
        );
    }

    #[test]
    fn http_server_header_match_is_case_insensitive() {
        let response = "HTTP/1.1 404 Not Found\r\nSERVER: Apache\r\n\r\n";
        assert_eq!(
            parse_http_response(response),
            Some("HTTP/1.1 404 Not Found | SERVER: Apache".to_string())
        );
    }

    #[test]
    fn http_empty_input_is_none() {
        assert_eq!(parse_http_response(""), None);
    }

    #[test]
    fn ssh_typical_banner_is_trimmed() {
        assert_eq!(
            parse_ssh_banner(b"SSH-2.0-OpenSSH_9.6\r\n"),
            Some("SSH-2.0-OpenSSH_9.6".to_string())
        );
    }

    #[test]
    fn ssh_whitespace_only_is_none() {
        assert_eq!(parse_ssh_banner(b"  \r\n\t"), None);
    }

    #[test]
    fn ssh_empty_is_none() {
        assert_eq!(parse_ssh_banner(b""), None);
    }
}
