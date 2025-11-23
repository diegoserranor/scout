use std::error::Error;
use tokio::time::Instant;

mod cli;
mod limits;
mod scan;

use crate::cli::Commands;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = cli::parse_args();

    match cli.command {
        Commands::Probe { target, start, end } => run_probe(target, start, end).await?,
        Commands::Networks => todo!(),
    }

    Ok(())
}

async fn run_probe(
    target: String,
    start: Option<u16>,
    end: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    let start = start.unwrap_or(1);
    let end = end.unwrap_or(1024);

    if start > end {
        eprintln!("start_port must be <= end_port");
        std::process::exit(1);
    }

    let concurrency = limits::compute_concurrency();
    let channel_size = limits::compute_channel_size(concurrency);

    let now = Instant::now();

    let config = scan::config(target.to_string(), start, end, concurrency, channel_size);
    let mut scanner = scan::spawn(config).await?;

    let console = cli::console(scanner.total);

    let mut open_ports: Vec<scan::ScanItem> = Vec::new();
    while let Some((target, port, open)) = scanner.rx.recv().await {
        cli::progress(&console);
        if open {
            open_ports.push((target, port));
        }
    }

    if open_ports.len() > 0 {
        println!("Open ports:");
        for (target, port) in open_ports {
            let open = format!("{}:{}", target, port);
            println!("{}", open);
        }
    } else {
        println!("No ports found");
    }

    let elapsed = now.elapsed();
    println!("Elapsed time: {:?}", elapsed);

    Ok(())
}

