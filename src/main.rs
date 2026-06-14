use std::error::Error;

mod cli;
mod core;
mod jobs;
mod scans;
mod subnets;

use crate::cli::args::parse_args;
use crate::cli::run::run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_args();
    run(cli).await
}
