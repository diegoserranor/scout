//! CLI front-end: dispatch subcommands to the core stages and render the results.

use std::collections::BTreeMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Instant;

use cidr::Ipv4Cidr;
use clap::CommandFactory;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table};

use super::args::{Cli, Commands};
use super::console::{self, OUTPUT_WIDTH};
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
    let mut rx = core::discover()?;

    let bar = console::spinner("Discovering live hosts...");
    let mut hosts: Vec<Host> = Vec::new();
    while let Some(host) = rx.recv().await {
        hosts.push(host);
        bar.set_message(format!("Discovering live hosts... {} found", hosts.len()));
    }
    bar.finish_and_clear();

    if hosts.is_empty() {
        println!("No live hosts found on local networks.");
        return Ok(());
    }

    // Hosts stream in completion order; sort for stable, readable output.
    hosts.sort_by_key(|host| host.ip);
    println!("\n{}", host_table(&hosts));
    Ok(())
}

/// `scout inspect <target>` — probe a target's open ports, TTL, and services.
async fn inspect(target: String, ports: Option<String>) -> Result<(), Box<dyn Error>> {
    let now = Instant::now();

    let hosts = parse_target(&target)?;
    let spec = parse_port_spec(ports)?;
    let plan = core::scope(hosts, spec)?;
    let mut rx = core::inspect(plan)?;

    // Each message is a host's latest snapshot; key by host so updates coalesce.
    let bar = console::spinner("Inspecting targets...");
    let mut reports: BTreeMap<Ipv4Addr, HostReport> = BTreeMap::new();
    while let Some(report) = rx.recv().await {
        reports.insert(report.host, report);
        bar.set_message(format!("Inspecting targets... {} host(s) responding", reports.len()));
    }
    bar.finish_and_clear();

    if reports.is_empty() {
        println!("No open ports found.");
        return Ok(());
    }

    let reports: Vec<HostReport> = reports.into_values().collect();
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
    match ports {
        Some(raw) => raw.parse(),
        None => Ok(PortSpec::Common),
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
