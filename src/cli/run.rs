//! CLI front-end: dispatch subcommands to the core stages and render the results.

use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Instant;

use cidr::Ipv4Cidr;
use clap::CommandFactory;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table};

use crate::cli::args::{Cli, Commands};
use crate::cli::console::{self, OUTPUT_WIDTH};
use crate::core::{self, Host, HostReport, PortSpec, Service};

/// Dispatch the parsed CLI to the appropriate stage.
pub async fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        None => {
            Cli::command().print_help()?;
            println!();
        }
        Some(Commands::Discover) => discover().await?,
        Some(Commands::Inspect { target, ports }) => inspect(target, ports).await?,
    }

    Ok(())
}

/// `scout discover` — list the live hosts on the local networks.
async fn discover() -> Result<(), Box<dyn Error>> {
    let bar = console::spinner("Discovering live hosts...");
    let hosts = core::discover().await?;
    bar.finish_and_clear();

    if hosts.is_empty() {
        println!("No live hosts found on local networks.");
        return Ok(());
    }

    println!("\n{}", host_table(&hosts));
    Ok(())
}

/// `scout inspect <target>` — probe a target's open ports, TTL, and services.
async fn inspect(target: String, ports: Option<String>) -> Result<(), Box<dyn Error>> {
    let now = Instant::now();

    let hosts = parse_target(&target)?;
    let spec = parse_port_spec(ports)?;
    let plan = core::scope(hosts, spec)?;

    let bar = console::spinner("Inspecting targets...");
    let reports = core::inspect(plan).await?;
    bar.finish_and_clear();

    if reports.is_empty() {
        println!("No open ports found.");
        return Ok(());
    }

    println!("\n{}", report_table(&reports));
    println!("\nElapsed time: {:?}", now.elapsed());
    Ok(())
}

/// Parse a target string into the host IPs to scan (a single IP or a CIDR block).
fn parse_target(target: &str) -> Result<Vec<Ipv4Addr>, Box<dyn Error>> {
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        Ok(vec![ip])
    } else if let Ok(cidr) = target.parse::<Ipv4Cidr>() {
        Ok(cidr.iter().map(|ip| ip.address()).collect())
    } else {
        Err("Target not supported; supply an IP address or CIDR".into())
    }
}

/// Parse the `--ports` value into a [`PortSpec`]; defaults to the common set.
fn parse_port_spec(ports: Option<String>) -> Result<PortSpec, Box<dyn Error>> {
    let Some(raw) = ports else {
        return Ok(PortSpec::Common);
    };
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

/// Render discovered hosts as a table.
fn host_table(hosts: &[Host]) -> Table {
    let mut table = base_table();
    table.set_header(vec!["Host", "Subnet"]);
    for host in hosts {
        table.add_row(vec![host.ip.to_string(), host.subnet.to_string()]);
    }
    table
}

/// Render inspection reports as a table.
fn report_table(reports: &[HostReport]) -> Table {
    let mut table = base_table();
    table.set_header(vec!["Host", "Ping TTL", "Open ports", "Services"]);
    for report in reports {
        let ttl = report
            .ttl
            .map(|ttl| ttl.to_string())
            .unwrap_or_else(|| "-".to_string());
        table.add_row(vec![
            report.host.to_string(),
            ttl,
            format_ports(&report.open_ports),
            format_services(&report.services),
        ]);
    }
    table
}

/// A table preconfigured with the shared scout styling.
fn base_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(OUTPUT_WIDTH);
    table
}

fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_services(services: &[Service]) -> String {
    if services.is_empty() {
        return "-".to_string();
    }

    services
        .iter()
        .map(|service| format!("{}: {}", service.port, service.banner))
        .collect::<Vec<_>>()
        .join("\n")
}
