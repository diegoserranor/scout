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
    Probe {
        /// Target host (IP, domain, or CIDR)
        target: String,

        /// Starting port (default: 1)
        start: Option<u16>,

        /// Ending port (default: 1024)
        end: Option<u16>,
    },
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

