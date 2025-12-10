use std::error::Error;

mod cli;
mod modes;
mod scan;

use crate::cli::{args::Commands, args::parse_args};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_args();

    match cli.command {
        Some(Commands::Probe { target, start, end }) => modes::probe(target, start, end).await?,
        Some(Commands::Networks) => modes::networks()?,
        None => modes::default().await?,
    }

    Ok(())
}
