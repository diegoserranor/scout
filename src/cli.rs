use crate::fingerprint::HostFingerprint;
use clap::{Parser, Subcommand};
use comfy_table::{ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};
use indicatif::{ProgressBar, ProgressStyle};
use std::net::Ipv4Addr;

pub const OUTPUT_WIDTH: u16 = 100;

pub fn parse_args() -> Cli {
    Cli::parse()
}

/// Local host discovery and TCP probing tool
#[derive(Parser, Debug)]
#[command(name = "scout")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a TCP scan for a target host over a range of ports
    Probe {
        /// Target host IP or CIDR (e.g. 192.168.66.0/22)
        target: String,

        /// Starting port (default: 1)
        start: Option<u16>,

        /// Ending port (default: 1024)
        end: Option<u16>,
    },

    /// Get a list of potential target networks your device is part of
    Networks,
}

pub struct Console {
    bar: ProgressBar,
}

const PROGRESS_LABEL_WIDTH: usize = 21;

pub fn console_with_label(total: u64, label: &str, suffix: &str) -> Console {
    let bar = ProgressBar::new(total);
    let template = format!("{{prefix}} [{{bar:40.cyan/blue}}] {{pos}}/{{len}} {suffix}");
    let style = ProgressStyle::with_template(&template)
        .unwrap()
        .progress_chars("##-");
    bar.set_style(style);

    // Pad the prefix so different labels keep the bar aligned.
    let padded_label = format!("{label:<PROGRESS_LABEL_WIDTH$}");
    bar.set_prefix(padded_label);

    Console { bar }
}

pub fn progress(console: &Console) {
    console.bar.inc(1);
}

pub fn finish(console: &Console) {
    console.bar.finish();
}

pub fn build_probe_table(results: &[(Ipv4Addr, Vec<u16>)]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_width(OUTPUT_WIDTH);
    table.set_header(vec!["IP", "Open ports"]);

    for (ip, ports) in results {
        table.add_row(vec![ip.to_string(), format_open_ports(ports)]);
    }

    table
}

pub fn build_results_table(results: &[(Ipv4Addr, Vec<u16>, HostFingerprint)]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_width(OUTPUT_WIDTH);
    table.set_header(vec!["IP", "TTL/OS guess", "Open ports", "Info"]);

    for (ip, ports, fp) in results {
        let ttl = fp.ttl_guess.clone().unwrap_or_else(|| "-".to_string());

        let (http, ssh): (Vec<String>, Vec<String>) = fp
            .services
            .iter()
            .cloned()
            .partition(|svc| svc.starts_with("HTTP:"));

        let mut info_lines = Vec::new();
        info_lines.extend(http);
        info_lines.extend(ssh);

        let info = if info_lines.is_empty() {
            "-".to_string()
        } else {
            info_lines.join("\n")
        };

        table.add_row(vec![ip.to_string(), ttl, format_open_ports(ports), info]);
    }

    table
}

fn format_open_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| match discovery_service_name(*port) {
            Some(name) => format!("{port}({name})"),
            None => port.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn discovery_service_name(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("ssh"),
        23 => Some("telnet"),
        53 => Some("dns"),
        80 => Some("http"),
        139 => Some("netbios"),
        443 => Some("https"),
        445 => Some("smb"),
        631 => Some("ipp"),
        8000 | 8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        _ => None,
    }
}

