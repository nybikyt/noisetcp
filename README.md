# noisytcp

A userspace trigger for **CVE-2026-99288 ("NoisyTCP")**, a Linux kernel TCP
`request_sock` reuse (ABA) race in the established-socket ehash lookup that
ends in a NULL dereference and a remote kernel panic.

The tool reproduces the published packet choreography on IPv4: it calibrates
the target's SYN queue, harvests a SYN cookie, frees a hashed request socket
with an in-window RST while a fragmented lookup is in flight on another RX
context, and reallocates the same slab slot through a valid cookie ACK.

> **Lab use only.** A successful run panics the target kernel and takes down
> every container on the host. Use it only on machines you own or have
> explicit written authorization to test. The binary sends from a real,
> attributable source address; it does not scan, spread, spoof third parties,
> or evade detection.

## Status

Implemented:

* IPv4 request-queue path with `probe`, `verify`, `race` modes;
* `tw` (TIME_WAIT recycle) mode for targets with `tcp_syncookies=2`;
* automatic SYN-queue calibration, SYN-queue modelling and cookie harvest;
* fragment-based RX-context steering with a working-split probe;
* host-RST leak detection and a temporary `iptables` OUTPUT filter, or
  ARP-claimed `--spoof` source on an on-link segment;
* built-in liveness watcher (`TARGET DOWN` → exit code 3);
* offline `--selftest` (works on any OS, no root) and `--dry-run`.

Not implemented: IPv6, full child-socket ABA. `tw` covers the hardened
`tcp_syncookies=2` case, not IPv6.

## Requirements

Attacker host:

* Linux with IPv4 raw sockets and `AF_PACKET`;
* `root` or `CAP_NET_RAW` (plus `CAP_NET_ADMIN` for the automatic
  `iptables` rule and `SO_MARK`);
* a route to the target port, and a path that does not filter or reassemble
  IPv4 fragments before they reach the target.

Target:

* a Linux kernel **without** fix `4e2b3ef19e0e` ("inet: reject unhashed
  sockets during established lookups");
* any listening TCP socket (nginx, sshd, a plain `listen()`);
* `net.ipv4.tcp_syncookies = 1` for `race` (default), or `2` for `tw`;
* at least two RX queues on the ingress NIC, or RPS enabled, so a fragmented
  packet and a plain packet for the same tuple are processed concurrently.

## Build and check

```sh
cargo build --release
cargo test                 # packet builders: checksums, framing, fragments
./target/release/noisytcp --selftest
./target/release/noisytcp --dry-run
```

`--selftest` and the unit tests are pure userspace computation and run on any
platform with a Rust toolchain. The engine itself is Linux-only.

## Quick start

```sh
# everything: probe, verify, calibrate, then race until Ctrl+C
sudo ./target/release/noisytcp 192.168.1.100 22

# diagnostics only
sudo ./target/release/noisytcp 192.168.1.100 22 --mode probe
sudo ./target/release/noisytcp 192.168.1.100 22 --mode verify

# fixed queue geometry, ten minutes
sudo ./target/release/noisytcp 192.168.1.100 22 --backlog 128 --batch 128 --duration 600

# hardened target: tcp_syncookies=2 and a listener that closes on accept
sudo ./target/release/noisytcp 192.168.1.100 9000 --mode tw

# no local RSTs and no iptables: claim a free address on the segment
sudo ./target/release/noisytcp 192.168.1.100 22 --spoof --src 192.168.1.77
```

Exit codes: `0` run finished, `1` runtime/preflight error, `2` invalid
arguments, `3` the liveness watcher declared the target down.

## Documentation

The full manual (modes, every option, packet choreography, tuning,
troubleshooting, TIME_WAIT mode, debug hooks) is in
[ИНСТРУКЦИЯ.txt](ИНСТРУКЦИЯ.txt) (Russian). `--help` lists the CLI surface.

## Credits

Mechanism, disclosure and patch:

* <https://github.com/V4bel/NoisyTCP>
* <https://www.openwall.com/lists/oss-security/2026/11/15/2>
* <https://git.kernel.org/stable/c/4e2b3ef19e0e04adca38442f07dd6bc93c712bf1>

Reference proof-of-concepts this implementation borrows ideas from:

* <https://github.com/re4/noisytcp-poc> — fragment steering, out-of-window
  probe, binary-search backlog calibration, TIME_WAIT recycle, ARP claim;
* <https://github.com/nsvk13/NoisyTCP-PoC> — `sendmmsg` batching, graded
  fragment-path probe, offline selftest, lab monitor semantics;
* <https://github.com/mustafasaydam/CVE-2026-99288---NoisyTCP-Exploit> —
  in-process liveness watchdog, staged microsecond pacing.
