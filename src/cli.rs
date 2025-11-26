use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

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

pub fn console(total: u64) -> Console {
    console_with_label(total, "")
}

pub fn console_with_label(total: u64, label: &str) -> Console {
    let bar = ProgressBar::new(total);
    let style = ProgressStyle::with_template("{prefix} [{bar:40.cyan/blue}] {pos}/{len}")
        .unwrap()
        .progress_chars("##-");
    bar.set_style(style);
    bar.set_prefix(label.to_string());

    Console { bar }
}

pub fn progress(console: &Console) {
    console.bar.inc(1);
}

pub fn finish(console: &Console) {
    console.bar.finish();
}
