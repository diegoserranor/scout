use std::error::Error;

mod cli;
mod core;
mod jobs;
mod scans;
mod subnets;
mod tui;

use crate::cli::args::parse_args;
use crate::cli::run::run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_args();
    match cli.command {
        None => tui::run().await,
        Some(_) => run(cli).await,
    }
}
