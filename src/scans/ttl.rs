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
