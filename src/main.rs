use std::error::Error;

use tokio::time::Instant;

mod cli;
mod limits;
mod scan;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = cli::parse_args();
    let target = args.target;
    let start = args.start;
    let end = args.end;

    let concurrency = limits::compute_concurrency();
    let channel_size = limits::compute_channel_size(concurrency);

    let now = Instant::now();
    let config = scan::config(target, start, end, concurrency, channel_size);
    let scanner = scan::spawn(config).await?;

    let console = cli::console(scanner.total);
    let open_ports = consume_scanner(scanner, console).await;
    print_results(open_ports, now);

    Ok(())
}

async fn consume_scanner(mut scanner: scan::Scanner, console: cli::Console) -> Vec<scan::ScanItem> {
    let mut open_ports: Vec<scan::ScanItem> = Vec::new();
    while let Some((target, port, open)) = scanner.rx.recv().await {
        cli::progress(&console);
        if open {
            open_ports.push((target, port));
        }
    }
    open_ports
}

fn print_results(open_ports: Vec<scan::ScanItem>, now: Instant) {
    println!("Open ports:");
    for (target, port) in open_ports {
        let open = format!("{}:{}", target, port);
        println!("{}", open);
    }

    let elapsed = now.elapsed();
    println!("Elapsed time: {:?}", elapsed);
}
