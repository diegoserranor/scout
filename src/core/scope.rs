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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> PortSpec {
        raw.parse().expect("should parse")
    }

    #[test]
    fn from_str_presets_are_case_insensitive_and_trimmed() {
        assert!(matches!(parse("web"), PortSpec::Web));
        assert!(matches!(parse("  WEB "), PortSpec::Web));
        assert!(matches!(parse("Common"), PortSpec::Common));
        assert!(matches!(parse("ALL"), PortSpec::All));
    }

    #[test]
    fn from_str_range() {
        assert!(matches!(parse("1-100"), PortSpec::Range(1, 100)));
        // Whitespace around the bounds is trimmed.
        assert!(matches!(parse(" 20 - 25 "), PortSpec::Range(20, 25)));
    }

    #[test]
    fn from_str_list() {
        assert!(matches!(parse("22,80,443"), PortSpec::List(ref p) if p == &[22, 80, 443]));
        // Whitespace inside the list is trimmed.
        assert!(matches!(parse("22, 80 , 443"), PortSpec::List(ref p) if p == &[22, 80, 443]));
    }

    #[test]
    fn from_str_bare_number_is_single_item_list() {
        assert!(matches!(parse("8080"), PortSpec::List(ref p) if p == &[8080]));
    }

    #[test]
    fn from_str_rejects_invalid_input() {
        assert!("abc".parse::<PortSpec>().is_err());
        assert!("80-".parse::<PortSpec>().is_err());
        assert!("70000".parse::<PortSpec>().is_err()); // out of u16 range
        assert!("1,foo,3".parse::<PortSpec>().is_err());
    }

    #[test]
    fn resolve_presets() {
        assert_eq!(PortSpec::Web.resolve().unwrap(), WEB_PORTS);
        assert_eq!(PortSpec::Common.resolve().unwrap(), COMMON_PORTS);
    }

    #[test]
    fn resolve_all_is_full_port_range() {
        let ports = PortSpec::All.resolve().unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(*ports.first().unwrap(), 1);
        assert_eq!(*ports.last().unwrap(), u16::MAX);
    }

    #[test]
    fn resolve_range() {
        assert_eq!(PortSpec::Range(1, 3).resolve().unwrap(), vec![1, 2, 3]);
        // A single-port range is inclusive.
        assert_eq!(PortSpec::Range(5, 5).resolve().unwrap(), vec![5]);
    }

    #[test]
    fn resolve_rejects_reversed_range() {
        let err = PortSpec::Range(3, 1).resolve().unwrap_err();
        assert_eq!(err.to_string(), "start port must be smaller than end port");
    }

    #[test]
    fn resolve_list_is_preserved() {
        assert_eq!(
            PortSpec::List(vec![9, 1, 5]).resolve().unwrap(),
            vec![9, 1, 5]
        );
    }
}
