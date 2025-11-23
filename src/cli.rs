use clap::{Parser, Subcommand};
use indicatif::ProgressBar;

pub fn parse_args() -> Cli {
    Cli::parse()
}

/// Local host discovery and TCP probing tool
#[derive(Parser, Debug)]
#[command(name = "scout")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
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
    let bar = ProgressBar::new(total);

    Console { bar }
}

pub fn progress(console: &Console) {
    console.bar.inc(1);
}

