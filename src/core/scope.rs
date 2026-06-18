//! Scope stage: turn a port selection into a concrete plan of what to scan.

use std::error::Error;
use std::net::Ipv4Addr;
use std::str::FromStr;

use super::types::{PortSpec, ScanPlan};

/// Common web ports.
const WEB_PORTS: &[u16] = &[80, 443, 8080, 8443, 8000];
/// Curated set of ports consumer devices commonly expose.
const COMMON_PORTS: &[u16] = &[22, 23, 53, 80, 139, 443, 445, 631, 8000, 8080, 8443];

impl PortSpec {
    /// Resolve a port selection into the concrete list of ports to scan.
    pub fn resolve(&self) -> Result<Vec<u16>, Box<dyn Error>> {
        let ports = match self {
            PortSpec::Web => WEB_PORTS.to_vec(),
            PortSpec::Common => COMMON_PORTS.to_vec(),
            PortSpec::All => (1..=u16::MAX).collect(),
            PortSpec::Range(start, end) => {
                if start > end {
                    return Err("start port must be smaller than end port".into());
                }
                (*start..=*end).collect()
            }
            PortSpec::List(ports) => ports.clone(),
        };

        Ok(ports)
    }
}

impl FromStr for PortSpec {
    type Err = Box<dyn Error>;

    /// Parse a user-supplied port selection: a preset name (`web`/`common`/`all`),
    /// a `start-end` range, or a comma-separated list (a bare number is a one-item
    /// list). Range ordering is validated later, in [`PortSpec::resolve`].
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim();
        match raw.to_ascii_lowercase().as_str() {
            "web" => Ok(PortSpec::Web),
            "common" => Ok(PortSpec::Common),
            "all" => Ok(PortSpec::All),
            _ => {
                if let Some((start, end)) = raw.split_once('-') {
                    Ok(PortSpec::Range(start.trim().parse()?, end.trim().parse()?))
                } else if raw.contains(',') {
                    let list = raw
                        .split(',')
                        .map(|port| port.trim().parse::<u16>())
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(PortSpec::List(list))
                } else {
                    Ok(PortSpec::List(vec![raw.parse()?]))
                }
            }
        }
    }
}

/// Run the Scope stage: pair the chosen hosts with the resolved ports.
pub fn scope(hosts: Vec<Ipv4Addr>, spec: PortSpec) -> Result<ScanPlan, Box<dyn Error>> {
    let ports = spec.resolve()?;
    Ok(ScanPlan { hosts, ports })
}
