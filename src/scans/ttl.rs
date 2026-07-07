use std::net::Ipv4Addr;
use tokio::process;

/// Ping a host a few times and parse the TTL from the first reply, or `None` if
/// it never answers.
pub async fn probe(host: Ipv4Addr) -> Option<u8> {
    let output = process::Command::new("ping")
        .args(["-c", "5", "-W", "1", &host.to_string()])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().find_map(parse_ttl_from_line)
}

fn parse_ttl_from_line(line: &str) -> Option<u8> {
    line.split_whitespace()
        .find_map(|segment| segment.strip_prefix("ttl="))
        .and_then(|raw| raw.parse::<u8>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ttl_from_ping_line() {
        let line = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.5 ms";
        assert_eq!(parse_ttl_from_line(line), Some(64));
    }

    #[test]
    fn boundary_values() {
        assert_eq!(parse_ttl_from_line("ttl=0"), Some(0));
        assert_eq!(parse_ttl_from_line("ttl=255"), Some(255));
    }

    #[test]
    fn no_ttl_segment_is_none() {
        assert_eq!(parse_ttl_from_line("PING 192.168.1.1 56 data bytes"), None);
    }

    #[test]
    fn out_of_range_or_non_numeric_is_none() {
        assert_eq!(parse_ttl_from_line("ttl=999"), None); // > u8::MAX
        assert_eq!(parse_ttl_from_line("ttl=abc"), None);
    }
}
