//! API of the core module.

use std::net::Ipv4Addr;

use getifs::rfc::Ipv4Net;

/// A host found during the Discover stage.
#[derive(Debug, Clone)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub subnet: Ipv4Net,
}

/// Input to the Scope stage.
#[derive(Debug, Clone)]
pub enum PortSpec {
    /// Common web ports (80, 443, 8080, 8443, 8000).
    Web,
    /// Curated set of ports consumer devices commonly expose.
    Common,
    /// Every port, 1–65535.
    All,
    Range(u16, u16),
    List(Vec<u16>),
}

/// Output of the Scope stage, used as input for the Inspect stage.
#[derive(Debug, Clone)]
pub struct ScanPlan {
    pub hosts: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
}

/// Inspect stage result per host.
#[derive(Debug, Clone)]
pub struct HostReport {
    pub host: Ipv4Addr,
    pub ttl: Option<u8>,
    /// Inferred operating system, derived from the TTL and service banners.
    pub os: Option<OsGuess>,
    pub open_ports: Vec<u16>,
    pub services: Vec<Service>,
}

/// A service found at a specific port during the Inspect stage.
#[derive(Debug, Clone)]
pub struct Service {
    pub port: u16,
    /// Protocol/service name, e.g. `"http"`, `"ssh"`, `"ftp"`.
    pub name: Option<String>,
    /// Software product behind the service, e.g. `"nginx"`, `"OpenSSH"`.
    pub product: Option<String>,
    /// Product version, e.g. `"1.25.3"`, `"9.6p1"`.
    pub version: Option<String>,
    /// Raw banner, always preserved so nothing is lost to parsing.
    pub banner: String,
    /// How much of the identification the banner actually supported.
    pub confidence: Confidence,
}

/// How strongly a fingerprint signal supports its conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    /// Canonical name for the level (domain label, not presentation).
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// Operating-system family a host most likely belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Linux,
    Windows,
    NetworkDevice,
}

impl OsFamily {
    /// Canonical name for the family (domain label, not presentation).
    pub fn label(self) -> &'static str {
        match self {
            OsFamily::Linux => "Linux/Unix",
            OsFamily::Windows => "Windows",
            OsFamily::NetworkDevice => "Network device",
        }
    }
}

/// Inferred operating system for a host, with the confidence behind the guess.
#[derive(Debug, Clone)]
pub struct OsGuess {
    pub family: OsFamily,
    pub confidence: Confidence,
}
