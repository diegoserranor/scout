//! Pure fingerprint inference: turn raw signals (a TTL, a service banner) into
//! structured guesses. No I/O and no presentation — every function here is
//! deterministic and unit-testable, and `inspect.rs` is the only caller.

use super::types::{Confidence, OsFamily, OsGuess, Service};

/// Banner substrings (lowercased) that point at a Linux/Unix host.
const LINUX_HINTS: &[&str] = &[
    "ubuntu", "debian", "linux", "unix", "centos", "fedora", "raspbian", "freebsd",
];
/// Banner substrings (lowercased) that point at a Windows host.
const WINDOWS_HINTS: &[&str] = &["windows", "microsoft", "microsoft-iis", "win32", "win64"];

/// Infer a host's OS family from its TTL and any service banners.
///
/// The TTL gives a coarse family (its initial value is decremented once per hop,
/// so we bucket by the nearest standard starting value *above* the observed one).
/// An explicit banner keyword corroborates the TTL — bumping to [`Confidence::High`]
/// when they agree, or overriding a heuristic TTL when they disagree.
pub fn guess_os(ttl: Option<u8>, services: &[Service]) -> Option<OsGuess> {
    let ttl_family = ttl.and_then(family_from_ttl);
    let service_family = family_from_services(services);

    match (ttl_family, service_family) {
        (Some((family, _)), Some(service_family)) if family == service_family => Some(OsGuess {
            family,
            confidence: Confidence::High,
        }),
        // An explicit banner beats a heuristic TTL when they disagree.
        (Some(_), Some(service_family)) => Some(OsGuess {
            family: service_family,
            confidence: Confidence::Medium,
        }),
        (Some((family, clean)), None) => Some(OsGuess {
            family,
            confidence: if clean {
                Confidence::Medium
            } else {
                Confidence::Low
            },
        }),
        (None, Some(family)) => Some(OsGuess {
            family,
            confidence: Confidence::Medium,
        }),
        (None, None) => None,
    }
}

/// Bucket a TTL into an OS family, returning whether the value is a clean,
/// undecremented baseline (64/128/255). `None` for a TTL of 0.
fn family_from_ttl(ttl: u8) -> Option<(OsFamily, bool)> {
    match ttl {
        0 => None,
        1..=64 => Some((OsFamily::Linux, ttl == 64)),
        65..=128 => Some((OsFamily::Windows, ttl == 128)),
        129..=255 => Some((OsFamily::NetworkDevice, ttl == 255)),
    }
}

/// Look for OS keywords across all banners; `None` if there is no signal or the
/// banners point at conflicting families.
fn family_from_services(services: &[Service]) -> Option<OsFamily> {
    let mut linux = false;
    let mut windows = false;
    for service in services {
        let banner = service.banner.to_ascii_lowercase();
        linux |= LINUX_HINTS.iter().any(|hint| banner.contains(hint));
        windows |= WINDOWS_HINTS.iter().any(|hint| banner.contains(hint));
    }
    match (linux, windows) {
        (true, false) => Some(OsFamily::Linux),
        (false, true) => Some(OsFamily::Windows),
        _ => None,
    }
}

/// Parse a raw banner into a structured [`Service`], preserving the original text.
///
/// Confidence reflects how much was recovered: product **and** version →
/// [`Confidence::High`], product only → [`Confidence::Medium`], nothing →
/// [`Confidence::Low`].
pub fn parse_service(port: u16, banner: &str) -> Service {
    let name = service_name(port, banner);
    let (product, version) = parse_product_version(banner);

    let confidence = match (&product, &version) {
        (Some(_), Some(_)) => Confidence::High,
        (Some(_), None) => Confidence::Medium,
        _ => Confidence::Low,
    };

    Service {
        port,
        name,
        product,
        version,
        banner: banner.to_string(),
        confidence,
    }
}

/// Identify the protocol from the banner shape first, then fall back to the port.
fn service_name(port: u16, banner: &str) -> Option<String> {
    if banner.starts_with("SSH-") {
        return Some("ssh".to_string());
    }
    if banner.starts_with("HTTP/") || banner.to_ascii_lowercase().contains("server:") {
        return Some("http".to_string());
    }
    let by_port = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        80 | 8000 | 8080 | 8888 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 8443 => "https",
        631 => "ipp",
        _ => return None,
    };
    Some(by_port.to_string())
}

/// Extract a product and version from a banner, dispatching on its shape.
fn parse_product_version(banner: &str) -> (Option<String>, Option<String>) {
    if banner.starts_with("SSH-") {
        parse_ssh(banner)
    } else if let Some(rest) = server_header_value(banner) {
        parse_slash_token(rest)
    } else {
        parse_greeting(banner)
    }
}

/// `SSH-2.0-OpenSSH_9.6p1 Debian-3` → (`OpenSSH`, `9.6p1`).
fn parse_ssh(banner: &str) -> (Option<String>, Option<String>) {
    let software = match banner.splitn(3, '-').nth(2) {
        Some(software) => software,
        None => return (None, None),
    };
    let token = match software.split_whitespace().next() {
        Some(token) => token,
        None => return (None, None),
    };
    match token.split_once('_') {
        Some((product, version)) => (clean(product), clean(version)),
        None => (clean(token), None),
    }
}

/// The text following a `Server:` header, if present (case-insensitive).
fn server_header_value(banner: &str) -> Option<&str> {
    let idx = banner.to_ascii_lowercase().find("server:")?;
    Some(banner[idx + "server:".len()..].trim())
}

/// `nginx/1.25.3 (Ubuntu)` → (`nginx`, `1.25.3`).
fn parse_slash_token(value: &str) -> (Option<String>, Option<String>) {
    let token = match value.split_whitespace().next() {
        Some(token) => token,
        None => return (None, None),
    };
    match token.split_once('/') {
        Some((product, version)) => (clean(product), clean(version)),
        None => (clean(token), None),
    }
}

/// Generic greeting parse (FTP/SMTP/POP3/IMAP): find the first version-looking
/// token and take the word before it as the product.
fn parse_greeting(banner: &str) -> (Option<String>, Option<String>) {
    let tokens: Vec<&str> = banner.split_whitespace().collect();
    for (i, token) in tokens.iter().enumerate() {
        if looks_like_version(token) && i > 0 {
            return (clean(tokens[i - 1]), clean(token));
        }
    }
    (None, None)
}

/// A token that starts with a digit and contains a dot, e.g. `1.3.5`, `9.6p1`.
/// The leading-digit rule avoids matching hostnames like `host2.example.com`.
fn looks_like_version(token: &str) -> bool {
    token.starts_with(|c: char| c.is_ascii_digit()) && token.contains('.')
}

/// Trim surrounding punctuation and drop the token if nothing usable remains.
fn clean(token: &str) -> Option<String> {
    let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(banner: &str) -> Service {
        parse_service(0, banner)
    }

    #[test]
    fn ttl_64_is_linux_medium() {
        let os = guess_os(Some(64), &[]).unwrap();
        assert_eq!(os.family, OsFamily::Linux);
        assert_eq!(os.confidence, Confidence::Medium);
    }

    #[test]
    fn decremented_ttl_lowers_confidence() {
        let os = guess_os(Some(54), &[]).unwrap();
        assert_eq!(os.family, OsFamily::Linux);
        assert_eq!(os.confidence, Confidence::Low);
    }

    #[test]
    fn ttl_128_is_windows() {
        assert_eq!(guess_os(Some(128), &[]).unwrap().family, OsFamily::Windows);
    }

    #[test]
    fn high_ttl_is_network_device() {
        assert_eq!(
            guess_os(Some(250), &[]).unwrap().family,
            OsFamily::NetworkDevice
        );
    }

    #[test]
    fn corroborating_banner_bumps_to_high() {
        let services = vec![service("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1")];
        let os = guess_os(Some(64), &services).unwrap();
        assert_eq!(os.family, OsFamily::Linux);
        assert_eq!(os.confidence, Confidence::High);
    }

    #[test]
    fn banner_overrides_conflicting_ttl() {
        // TTL says Windows, but the banner explicitly says Ubuntu.
        let services = vec![service("SSH-2.0-OpenSSH_9.6p1 Ubuntu")];
        let os = guess_os(Some(128), &services).unwrap();
        assert_eq!(os.family, OsFamily::Linux);
        assert_eq!(os.confidence, Confidence::Medium);
    }

    #[test]
    fn no_ttl_and_no_services_is_none() {
        assert!(guess_os(None, &[]).is_none());
    }

    #[test]
    fn ttl_zero_is_none() {
        assert!(guess_os(Some(0), &[]).is_none());
    }

    #[test]
    fn banner_only_infers_family() {
        let services = vec![service("SSH-2.0-OpenSSH_9.6p1 Debian")];
        let os = guess_os(None, &services).unwrap();
        assert_eq!(os.family, OsFamily::Linux);
        assert_eq!(os.confidence, Confidence::Medium);
    }

    #[test]
    fn parse_ssh_banner() {
        let s = parse_service(22, "SSH-2.0-OpenSSH_9.6p1 Debian-3ubuntu0.1");
        assert_eq!(s.name.as_deref(), Some("ssh"));
        assert_eq!(s.product.as_deref(), Some("OpenSSH"));
        assert_eq!(s.version.as_deref(), Some("9.6p1"));
        assert_eq!(s.confidence, Confidence::High);
    }

    #[test]
    fn parse_http_server_header() {
        let s = parse_service(80, "HTTP/1.1 200 OK | Server: nginx/1.25.3");
        assert_eq!(s.name.as_deref(), Some("http"));
        assert_eq!(s.product.as_deref(), Some("nginx"));
        assert_eq!(s.version.as_deref(), Some("1.25.3"));
        assert_eq!(s.confidence, Confidence::High);
    }

    #[test]
    fn parse_http_without_version_is_medium() {
        let s = parse_service(80, "HTTP/1.1 200 OK | Server: Apache");
        assert_eq!(s.product.as_deref(), Some("Apache"));
        assert_eq!(s.version, None);
        assert_eq!(s.confidence, Confidence::Medium);
    }

    #[test]
    fn parse_ftp_greeting() {
        let s = parse_service(21, "220 ProFTPD 1.3.5 Server ready");
        assert_eq!(s.name.as_deref(), Some("ftp"));
        assert_eq!(s.product.as_deref(), Some("ProFTPD"));
        assert_eq!(s.version.as_deref(), Some("1.3.5"));
        assert_eq!(s.confidence, Confidence::High);
    }

    #[test]
    fn greeting_hostname_is_not_a_version() {
        // The dotted hostname has no leading digit, so it is not mistaken for a version.
        let s = parse_service(25, "220 mail.example.com ESMTP Postfix");
        assert_eq!(s.name.as_deref(), Some("smtp"));
        assert_eq!(s.version, None);
    }

    #[test]
    fn unparseable_banner_keeps_raw_and_is_low() {
        let s = parse_service(4444, "some random chatter");
        assert_eq!(s.name, None);
        assert_eq!(s.product, None);
        assert_eq!(s.banner, "some random chatter");
        assert_eq!(s.confidence, Confidence::Low);
    }
}
