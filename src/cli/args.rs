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
    /// Discover live hosts on your local networks
    Discover,

    /// Inspect a target's open ports, TTL, and services
    Inspect {
        /// Target host IP or CIDR (e.g. 192.168.1.0/24)
        target: String,

        /// Ports to scan: web | common | all | a range (1-1024) | a list (22,80,443).
        /// Defaults to the common set.
        #[arg(short, long)]
        ports: Option<String>,
    },
}
