//! Scope stage: turn a port selection into a concrete plan of what to scan.

use std::error::Error;
use std::net::Ipv4Addr;

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

/// Run the Scope stage: pair the chosen hosts with the resolved ports.
pub fn scope(hosts: Vec<Ipv4Addr>, spec: PortSpec) -> Result<ScanPlan, Box<dyn Error>> {
    let ports = spec.resolve()?;
    Ok(ScanPlan { hosts, ports })
}
