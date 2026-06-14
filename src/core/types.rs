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
    pub open_ports: Vec<u16>,
    pub services: Vec<Service>,
}

/// A service found at a specific port during the Inspect stage.
#[derive(Debug, Clone)]
pub struct Service {
    pub port: u16,
    pub banner: String,
}
