use clap::Parser;
use indicatif::ProgressBar;

/// Fast network discovery tool
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Target host (IP, domain, or CIDR)
    target: String,

    /// Starting port (default: 1)
    start: Option<u16>,

    /// Ending port (default: 1024)
    end: Option<u16>,
}

pub struct Args {
    pub target: String,
    pub start: u16,
    pub end: u16,
}

pub fn parse_args() -> Args {
    let cli = Cli::parse();

    let target = cli.target;
    let start = cli.start.unwrap_or(1);
    let end = cli.end.unwrap_or(1024);

    if start > end {
        eprintln!("start_port must be <= end_port");
        std::process::exit(1);
    }

    Args { target, start, end }
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
