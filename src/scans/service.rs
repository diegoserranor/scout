use super::tcp;
use std::net::Ipv4Addr;
use tokio::time::Duration;

const SERVICE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Grab a raw banner from an open port. HTTP-like ports get an explicit request;
/// every other port is read as a *greeting* — many services (SSH, FTP, SMTP,
/// POP3, IMAP, …) announce themselves first, and silent ports simply yield
/// `None`. Parsing the banner into a product/version happens in `core::fingerprint`.
pub async fn probe(ip: Ipv4Addr, port: u16) -> Option<String> {
    match port {
        80 | 443 | 631 | 8000 | 8080 | 8443 | 8888 => http_banner(ip, port).await,
        _ => greeting_banner(ip, port).await,
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

/// Connect and read whatever the server volunteers, for protocols that speak
/// first. Used for SSH/FTP/SMTP/POP3/IMAP/Telnet and as the generic fallback.
async fn greeting_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let mut stream = tcp::connect_with_timeout((ip, port), SERVICE_CONNECT_TIMEOUT).await?;

    let mut buf = [0u8; 1024];
    let read = tcp::read_with_timeout(&mut stream, &mut buf).await?;
    if read == 0 {
        return None;
    }

    parse_greeting(&buf[..read])
}

/// Reduce a greeting to its first printable line: stop at the first CR/LF and
/// keep only printable ASCII, which drops Telnet IAC/control bytes. `None` if
/// nothing readable remains.
fn parse_greeting(bytes: &[u8]) -> Option<String> {
    let line: String = bytes
        .iter()
        .take_while(|&&b| b != b'\n' && b != b'\r')
        .filter(|&&b| b == b'\t' || (0x20..0x7f).contains(&b))
        .map(|&b| b as char)
        .collect();

    let banner = line.trim().to_string();
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
    fn greeting_first_line_is_trimmed() {
        assert_eq!(
            parse_greeting(b"SSH-2.0-OpenSSH_9.6\r\n"),
            Some("SSH-2.0-OpenSSH_9.6".to_string())
        );
    }

    #[test]
    fn greeting_stops_at_first_line() {
        assert_eq!(
            parse_greeting(b"220 ProFTPD Server ready\r\nmore\r\n"),
            Some("220 ProFTPD Server ready".to_string())
        );
    }

    #[test]
    fn greeting_strips_leading_telnet_iac_bytes() {
        // IAC WILL ECHO (0xFF 0xFB 0x01) then a readable prompt on the same line.
        assert_eq!(
            parse_greeting(b"\xff\xfb\x01login: "),
            Some("login:".to_string())
        );
    }

    #[test]
    fn greeting_whitespace_only_is_none() {
        assert_eq!(parse_greeting(b"  \r\n\t"), None);
    }

    #[test]
    fn greeting_empty_is_none() {
        assert_eq!(parse_greeting(b""), None);
    }
}
