use clap::{Parser, Subcommand};

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
