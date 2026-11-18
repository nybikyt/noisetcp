use clap::{Parser, ValueEnum};
use snow::{Builder, HandshakeState, TransportState};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_FRAME: usize = 65_535;

#[derive(Parser)]
#[command(
    name = "noisetcp",
    version,
    about = "Adversarial Noise-over-TCP handshake and transport fuzzer",
    long_about = "Sends malformed Noise_XX_25519_ChaChaPoly_BLAKE2s handshake and transport frames. Connection resets and EOF are recorded as outcomes, not assumed to be kernel panics."
)]
struct Args {
    #[arg(short, long, help = "Target node IP address")]
    ip: IpAddr,

    #[arg(short, long, default_value_t = 9000, help = "Target TCP port")]
    port: u16,

    #[arg(
        short = 'n',
        long,
        default_value_t = 100,
        help = "Total number of test cases"
    )]
    iterations: u64,

    #[arg(short = 'w', long, default_value_t = 4, help = "Concurrent workers")]
    workers: usize,

    #[arg(long, value_enum, default_value_t = Mode::Both, help = "Protocol state to fuzz")]
    mode: Mode,

    #[arg(long, value_enum, default_value_t = Framing::U16be, help = "TCP framing used by the target")]
    framing: Framing,

    #[arg(long, default_value_t = 65_535, help = "Largest generated frame body")]
    max_frame: usize,

    #[arg(long, default_value_t = 8, help = "Frames sent by pipelined cases")]
    pipeline: usize,

    #[arg(
        long,
        default_value_t = 1_500,
        help = "TCP connect timeout in milliseconds"
    )]
    connect_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = 300,
        help = "Read/write timeout in milliseconds"
    )]
    io_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = 0,
        help = "Delay between cases per worker in milliseconds"
    )]
    delay_ms: u64,

    #[arg(long, default_value_t = 1, help = "Deterministic payload seed")]
    seed: u64,

    #[arg(short, long, help = "Print every test case and connection outcome")]
    verbose: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Handshake,
    Transport,
    Both,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Framing {
    U16be,
    U16le,
    Raw,
}

#[derive(Clone, Copy)]
enum HandshakeCase {
    Empty,
    OneByte,
    ShortE,
    ZeroE,
    OnesE,
    LowOrder,
    RandomE,
    EWithGarbage,
    TruncatedDeclaration,
    UnderreportedLength,
    ZeroLengthWithBody,
    Oversized,
    Pipelined,
    Fragmented,
    ThirdEmpty,
    ThirdShort,
    ThirdBadTag,
}

impl HandshakeCase {
    const ALL: [Self; 17] = [
        Self::Empty,
        Self::OneByte,
        Self::ShortE,
        Self::ZeroE,
        Self::OnesE,
        Self::LowOrder,
        Self::RandomE,
        Self::EWithGarbage,
        Self::TruncatedDeclaration,
        Self::UnderreportedLength,
        Self::ZeroLengthWithBody,
        Self::Oversized,
        Self::Pipelined,
        Self::Fragmented,
        Self::ThirdEmpty,
        Self::ThirdShort,
        Self::ThirdBadTag,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Empty => "handshake/empty",
            Self::OneByte => "handshake/one-byte",
            Self::ShortE => "handshake/short-ephemeral",
            Self::ZeroE => "handshake/zero-ephemeral",
            Self::OnesE => "handshake/ff-ephemeral",
            Self::LowOrder => "handshake/low-order-ephemeral",
            Self::RandomE => "handshake/random-ephemeral",
            Self::EWithGarbage => "handshake/ephemeral-with-garbage",
            Self::TruncatedDeclaration => "handshake/truncated-declaration",
            Self::UnderreportedLength => "handshake/underreported-length",
            Self::ZeroLengthWithBody => "handshake/zero-length-with-body",
            Self::Oversized => "handshake/oversized",
            Self::Pipelined => "handshake/pipelined",
            Self::Fragmented => "handshake/fragmented",
            Self::ThirdEmpty => "handshake/third-empty",
            Self::ThirdShort => "handshake/third-short",
            Self::ThirdBadTag => "handshake/third-bad-tag",
        }
    }
}

#[derive(Clone, Copy)]
enum TransportCase {
    Empty,
    OneByte,
    ShortTag,
    RandomCiphertext,
    InvalidMac,
    UnderreportedLength,
    Replay,
    ReplayAfterInvalid,
    TruncatedDeclaration,
    Oversized,
    Pipelined,
    Fragmented,
}

impl TransportCase {
    const ALL: [Self; 12] = [
        Self::Empty,
        Self::OneByte,
        Self::ShortTag,
        Self::RandomCiphertext,
        Self::InvalidMac,
        Self::UnderreportedLength,
        Self::Replay,
        Self::ReplayAfterInvalid,
        Self::TruncatedDeclaration,
        Self::Oversized,
        Self::Pipelined,
        Self::Fragmented,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Empty => "transport/empty",
            Self::OneByte => "transport/one-byte",
            Self::ShortTag => "transport/short-tag",
            Self::RandomCiphertext => "transport/random-ciphertext",
            Self::InvalidMac => "transport/invalid-mac",
            Self::UnderreportedLength => "transport/underreported-length",
            Self::Replay => "transport/replay",
            Self::ReplayAfterInvalid => "transport/replay-after-invalid",
            Self::TruncatedDeclaration => "transport/truncated-declaration",
            Self::Oversized => "transport/oversized",
            Self::Pipelined => "transport/pipelined",
            Self::Fragmented => "transport/fragmented",
        }
    }
}

enum TestCase {
    Handshake(HandshakeCase),
    Transport(TransportCase),
}

impl TestCase {
    fn name(&self) -> &'static str {
        match self {
            Self::Handshake(case) => case.name(),
            Self::Transport(case) => case.name(),
        }
    }
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let random = self.next().to_le_bytes();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
    }
}

#[derive(Default)]
struct Stats {
    completed: AtomicU64,
    sent: AtomicU64,
    eof: AtomicU64,
    reset: AtomicU64,
    timeout: AtomicU64,
    errors: AtomicU64,
    outcomes: Mutex<BTreeMap<String, u64>>,
}

impl Stats {
    fn record(&self, case: &str, outcome: Outcome) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        match outcome {
            Outcome::Sent => {
                self.sent.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Eof => {
                self.eof.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Reset => {
                self.reset.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Timeout => {
                self.timeout.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Error => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        let key = format!("{case} {outcome}");
        let mut outcomes = self.outcomes.lock().unwrap_or_else(|e| e.into_inner());
        *outcomes.entry(key).or_insert(0) += 1;
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Sent,
    Eof,
    Reset,
    Timeout,
    Error,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sent => "sent/open",
            Self::Eof => "eof",
            Self::Reset => "reset",
            Self::Timeout => "timeout",
            Self::Error => "error",
        })
    }
}

struct Config {
    address: SocketAddr,
    framing: Framing,
    max_frame: usize,
    pipeline: usize,
    connect_timeout: Duration,
    io_timeout: Duration,
    delay: Duration,
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    if let Err(error) = run(args) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

fn run(args: Args) -> Result<(), String> {
    if args.iterations == 0 {
        return Err("--iterations must be greater than zero".into());
    }
    if args.workers == 0 {
        return Err("--workers must be greater than zero".into());
    }
    if !(16..=MAX_NOISE_FRAME).contains(&args.max_frame) {
        return Err("--max-frame must be between 16 and 65535".into());
    }
    if args.pipeline == 0 {
        return Err("--pipeline must be greater than zero".into());
    }
    if args.connect_timeout_ms == 0 || args.io_timeout_ms == 0 {
        return Err("connect and I/O timeouts must be greater than zero".into());
    }

    let config = Arc::new(Config {
        address: SocketAddr::new(args.ip, args.port),
        framing: args.framing,
        max_frame: args.max_frame,
        pipeline: args.pipeline,
        connect_timeout: Duration::from_millis(args.connect_timeout_ms),
        io_timeout: Duration::from_millis(args.io_timeout_ms),
        delay: Duration::from_millis(args.delay_ms),
        verbose: args.verbose,
    });
    let stats = Arc::new(Stats::default());
    let next = Arc::new(AtomicU64::new(0));
    let mode = args.mode;
    let iterations = args.iterations;
    let workers = args.workers.min(iterations as usize);

    println!(
        "target={} cases={} workers={} mode={:?} framing={:?} seed={}",
        config.address, iterations, workers, mode, config.framing, args.seed
    );

    thread::scope(|scope| {
        for _ in 0..workers {
            let config = Arc::clone(&config);
            let stats = Arc::clone(&stats);
            let next = Arc::clone(&next);
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= iterations {
                    break;
                }
                let mut rng = Rng::new(args.seed ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15));
                let case = select_case(mode, index);
                let name = case.name();
                let result = execute(&case, &config, &mut rng);
                let outcome = match &result {
                    Ok(outcome) => *outcome,
                    Err(error) if is_timeout(error) => Outcome::Timeout,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Outcome::Eof,
                    Err(error) if is_disconnect(error) => Outcome::Reset,
                    Err(_) => Outcome::Error,
                };
                stats.record(name, outcome);
                let report = match &result {
                    Ok(_) => config.verbose,
                    Err(error) => {
                        config.verbose
                            || !(is_timeout(error)
                                || is_disconnect(error)
                                || error.kind() == io::ErrorKind::UnexpectedEof)
                    }
                };
                if report {
                    match result {
                        Ok(outcome) => println!("#{index:06} {name}: {outcome}"),
                        Err(error) => eprintln!("#{index:06} {name}: {error}"),
                    }
                }
                if !config.delay.is_zero() {
                    thread::sleep(config.delay);
                }
            });
        }
    });

    println!("\nresults:");
    println!("  completed: {}", stats.completed.load(Ordering::Relaxed));
    println!("  sent/open: {}", stats.sent.load(Ordering::Relaxed));
    println!("  eof:       {}", stats.eof.load(Ordering::Relaxed));
    println!("  reset:     {}", stats.reset.load(Ordering::Relaxed));
    println!("  timeout:   {}", stats.timeout.load(Ordering::Relaxed));
    println!("  errors:    {}", stats.errors.load(Ordering::Relaxed));
    println!("\nby case:");
    let outcomes = stats.outcomes.lock().unwrap_or_else(|e| e.into_inner());
    for (key, count) in outcomes.iter() {
        println!("  {count:6} {key}");
    }
    drop(outcomes);

    match TcpStream::connect_timeout(&config.address, config.connect_timeout) {
        Ok(_) => println!("\nfinal health check: TCP connect succeeded"),
        Err(error) => println!("\nfinal health check: TCP connect failed: {error}"),
    }
    Ok(())
}

fn select_case(mode: Mode, index: u64) -> TestCase {
    match mode {
        Mode::Handshake => {
            TestCase::Handshake(HandshakeCase::ALL[index as usize % HandshakeCase::ALL.len()])
        }
        Mode::Transport => {
            TestCase::Transport(TransportCase::ALL[index as usize % TransportCase::ALL.len()])
        }
        Mode::Both => {
            let slot = index as usize % (HandshakeCase::ALL.len() + TransportCase::ALL.len());
            if slot < HandshakeCase::ALL.len() {
                TestCase::Handshake(HandshakeCase::ALL[slot])
            } else {
                TestCase::Transport(TransportCase::ALL[slot - HandshakeCase::ALL.len()])
            }
        }
    }
}

fn execute(case: &TestCase, config: &Config, rng: &mut Rng) -> io::Result<Outcome> {
    let stream = TcpStream::connect_timeout(&config.address, config.connect_timeout)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(config.io_timeout))?;
    stream.set_write_timeout(Some(config.io_timeout))?;
    let mut connection = Connection {
        stream,
        framing: config.framing,
    };

    match case {
        TestCase::Handshake(case) => execute_handshake(*case, &mut connection, config, rng),
        TestCase::Transport(case) => execute_transport(*case, &mut connection, config, rng),
    }
}

struct Connection {
    stream: TcpStream,
    framing: Framing,
}

impl Connection {
    fn send(&mut self, body: &[u8]) -> io::Result<()> {
        match self.framing {
            Framing::U16be => self.send_prefixed(body, u16::to_be_bytes),
            Framing::U16le => self.send_prefixed(body, u16::to_le_bytes),
            Framing::Raw => self.stream.write_all(body),
        }
    }

    fn send_prefixed(&mut self, body: &[u8], encode: fn(u16) -> [u8; 2]) -> io::Result<()> {
        let len = u16::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds u16 length"))?;
        self.stream.write_all(&encode(len))?;
        self.stream.write_all(body)
    }

    fn send_declared(&mut self, declared: u16, body: &[u8]) -> io::Result<()> {
        match self.framing {
            Framing::U16be => self.stream.write_all(&declared.to_be_bytes())?,
            Framing::U16le => self.stream.write_all(&declared.to_le_bytes())?,
            Framing::Raw => {}
        }
        self.stream.write_all(body)
    }

    fn send_fragmented(&mut self, body: &[u8]) -> io::Result<()> {
        let mut packet = Vec::with_capacity(body.len() + 2);
        match self.framing {
            Framing::U16be => {
                let len = u16::try_from(body.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds u16 length")
                })?;
                packet.extend_from_slice(&len.to_be_bytes());
            }
            Framing::U16le => {
                let len = u16::try_from(body.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds u16 length")
                })?;
                packet.extend_from_slice(&len.to_le_bytes());
            }
            Framing::Raw => {}
        }
        packet.extend_from_slice(body);
        for byte in packet {
            self.stream.write_all(&[byte])?;
            self.stream.flush()?;
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Vec<u8>> {
        match self.framing {
            Framing::U16be => self.receive_prefixed(u16::from_be_bytes),
            Framing::U16le => self.receive_prefixed(u16::from_le_bytes),
            Framing::Raw => {
                let mut body = vec![0; 96];
                self.stream.read_exact(&mut body)?;
                Ok(body)
            }
        }
    }

    fn receive_prefixed(&mut self, decode: fn([u8; 2]) -> u16) -> io::Result<Vec<u8>> {
        let mut prefix = [0; 2];
        self.stream.read_exact(&mut prefix)?;
        let len = decode(prefix) as usize;
        let mut body = vec![0; len];
        self.stream.read_exact(&mut body)?;
        Ok(body)
    }

    fn probe(&mut self) -> Outcome {
        let mut byte = [0; 1];
        match self.stream.read(&mut byte) {
            Ok(0) => Outcome::Eof,
            Ok(_) => Outcome::Sent,
            Err(error) if is_timeout(&error) => Outcome::Sent,
            Err(error) if is_disconnect(&error) => Outcome::Reset,
            Err(_) => Outcome::Error,
        }
    }
}

fn execute_handshake(
    case: HandshakeCase,
    connection: &mut Connection,
    config: &Config,
    rng: &mut Rng,
) -> io::Result<Outcome> {
    match case {
        HandshakeCase::Empty => connection.send(&[])?,
        HandshakeCase::OneByte => connection.send(&[0])?,
        HandshakeCase::ShortE => connection.send(&[0x42; 31])?,
        HandshakeCase::ZeroE => connection.send(&[0; 32])?,
        HandshakeCase::OnesE => connection.send(&[0xff; 32])?,
        HandshakeCase::LowOrder => {
            const LOW_ORDER: [u8; 32] = [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ];
            connection.send(&LOW_ORDER)?;
        }
        HandshakeCase::RandomE => {
            let mut body = [0; 32];
            rng.fill(&mut body);
            connection.send(&body)?;
        }
        HandshakeCase::EWithGarbage => {
            let mut body = vec![0; 97];
            rng.fill(&mut body);
            connection.send(&body)?;
        }
        HandshakeCase::TruncatedDeclaration => {
            connection.send_declared(u16::MAX, &[0x41; 8])?;
            connection.stream.shutdown(Shutdown::Write)?;
        }
        HandshakeCase::UnderreportedLength => {
            let mut body = vec![0; config.max_frame];
            rng.fill(&mut body);
            connection.send_declared(1, &body)?;
        }
        HandshakeCase::ZeroLengthWithBody => {
            let mut body = [0; 64];
            rng.fill(&mut body);
            connection.send_declared(0, &body)?;
        }
        HandshakeCase::Oversized => {
            let mut body = vec![0; config.max_frame];
            rng.fill(&mut body);
            connection.send(&body)?;
        }
        HandshakeCase::Pipelined => {
            for _ in 0..config.pipeline {
                connection.send(&[0xff; 32])?;
            }
        }
        HandshakeCase::Fragmented => {
            let mut body = [0; 32];
            rng.fill(&mut body);
            connection.send_fragmented(&body)?;
        }
        HandshakeCase::ThirdEmpty => {
            xx_response(connection)?;
            connection.send(&[])?;
        }
        HandshakeCase::ThirdShort => {
            xx_response(connection)?;
            connection.send(&[0x42; 31])?;
        }
        HandshakeCase::ThirdBadTag => {
            let (mut state, _) = xx_response(connection)?;
            let mut message = vec![0; 128];
            let len = state
                .write_message(&[], &mut message)
                .map_err(noise_error)?;
            message[len - 1] ^= 1;
            connection.send(&message[..len])?;
        }
    }
    Ok(connection.probe())
}

fn execute_transport(
    case: TransportCase,
    connection: &mut Connection,
    config: &Config,
    rng: &mut Rng,
) -> io::Result<Outcome> {
    let mut transport = xx_handshake(connection)?;
    let mut valid = vec![0; 128];
    let valid_len = transport
        .write_message(b"noisetcp", &mut valid)
        .map_err(noise_error)?;
    valid.truncate(valid_len);

    match case {
        TransportCase::Empty => connection.send(&[])?,
        TransportCase::OneByte => connection.send(&[0])?,
        TransportCase::ShortTag => connection.send(&valid[..15])?,
        TransportCase::RandomCiphertext => {
            let mut body = vec![0; 64];
            rng.fill(&mut body);
            connection.send(&body)?;
        }
        TransportCase::InvalidMac => {
            let mut body = valid;
            let last = body.len() - 1;
            body[last] ^= 1;
            connection.send(&body)?;
        }
        TransportCase::UnderreportedLength => {
            connection.send_declared(1, &valid)?;
        }
        TransportCase::Replay => {
            connection.send(&valid)?;
            connection.send(&valid)?;
        }
        TransportCase::ReplayAfterInvalid => {
            connection.send(&valid)?;
            connection.send(&[0x41; 15])?;
            connection.send(&valid)?;
        }
        TransportCase::TruncatedDeclaration => {
            connection.send_declared(u16::MAX, &valid)?;
            connection.stream.shutdown(Shutdown::Write)?;
        }
        TransportCase::Oversized => {
            let mut body = vec![0; config.max_frame];
            rng.fill(&mut body);
            connection.send(&body)?;
        }
        TransportCase::Pipelined => {
            for index in 0..config.pipeline {
                let mut body = valid.clone();
                let offset = index % body.len();
                body[offset] ^= (index as u8).wrapping_add(1);
                connection.send(&body)?;
            }
        }
        TransportCase::Fragmented => {
            let mut body = valid;
            let last = body.len() - 1;
            body[last] ^= 1;
            connection.send_fragmented(&body)?;
        }
    }
    Ok(connection.probe())
}

fn xx_response(connection: &mut Connection) -> io::Result<(HandshakeState, Vec<u8>)> {
    let params = NOISE_PATTERN.parse().map_err(noise_error)?;
    let builder = Builder::new(params);
    let keypair = builder.generate_keypair().map_err(noise_error)?;
    let mut state = builder
        .local_private_key(&keypair.private)
        .build_initiator()
        .map_err(noise_error)?;
    let mut first = vec![0; 128];
    let first_len = state.write_message(&[], &mut first).map_err(noise_error)?;
    connection.send(&first[..first_len])?;
    let response = connection.receive()?;
    let mut payload = vec![0; 65_535];
    state
        .read_message(&response, &mut payload)
        .map_err(noise_error)?;
    Ok((state, payload))
}

fn xx_handshake(connection: &mut Connection) -> io::Result<TransportState> {
    let (mut state, _) = xx_response(connection)?;
    let mut third = vec![0; 128];
    let third_len = state.write_message(&[], &mut third).map_err(noise_error)?;
    connection.send(&third[..third_len])?;
    if !state.is_handshake_finished() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Noise XX handshake did not finish",
        ));
    }
    state.into_transport_mode().map_err(noise_error)
}

fn noise_error(error: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn is_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    )
}
