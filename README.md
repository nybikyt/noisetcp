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

## Usage

```sh
sudo ./target/release/noisytcp <TARGET_IP> <TARGET_PORT>
```

That is the whole public interface. Everything else is automatic:

* source address/interface selection, RST-leak detection and the temporary
  `iptables` OUTPUT rule that keeps the local kernel from resetting the
  probe's SYN-ACKs;
* `probe` (fragment path and listener), `verify` (cookie cycle) and SYN-queue
  calibration before the race;
* source-port range, fragment split, payload, gaps, jitter and SYN-ACK
  timeout;
* one tuple per round, with automatic SYN-queue fill and timings;
* the liveness watcher: when the target stops answering, the run stops with
  exit code 3;
* automatic TIME_WAIT mode when the target answers every SYN with a cookie
  (`net.ipv4.tcp_syncookies=2`). Such a target needs a listener that accepts
  and closes immediately, for example `lab/close-listener.py`.

The race runs until the target goes down or you press Ctrl+C. A real kernel
panic is the only confirmation; the tool cannot know whether the target's
kernel has the fix.

## Requirements

Attacker host:

* Linux with IPv4 raw sockets and `AF_PACKET`;
* `root` or `CAP_NET_RAW`, plus `CAP_NET_ADMIN` and `iptables` for the
  automatic RST-suppression rule and `SO_MARK`;
* a route to the target port, and a path that does not filter or reassemble
  IPv4 fragments before they reach the target.

Target:

* a Linux kernel **without** fix `4e2b3ef19e0e` ("inet: reject unhashed
  sockets during established lookups");
* any listening TCP socket (nginx, sshd, a plain `listen()`);
* `net.ipv4.tcp_syncookies = 1` (default) — or `2` with a listener that
  accepts and closes immediately (the tool switches to TIME_WAIT mode);
* at least two RX queues on the ingress NIC, or RPS enabled, so a fragmented
  packet and a plain packet for the same tuple are processed concurrently.

## Build and check

```sh
cargo build --release
cargo test
```

`cargo test` covers TCP/IP checksums, MSS framing, fragment reassembly,
the receive-filter program and CLI validation; it needs no root and no
network. The engine itself is Linux-only.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | run finished (duration/Ctrl+C) without a DOWN verdict |
| 1 | runtime/preflight error |
| 2 | invalid arguments |
| 3 | the liveness watcher declared the target down |

## Documentation

The Russian manual is [ИНСТРУКЦИЯ.txt](ИНСТРУКЦИЯ.txt). `--help` shows the
two positional arguments.

## Credits

Mechanism, disclosure and patch:

* <https://github.com/V4bel/NoisyTCP>
* <https://www.openwall.com/lists/oss-security/2026/11/15/2>
* <https://git.kernel.org/stable/c/4e2b3ef19e0e04adca38442f07dd6bc93c712bf1>

Reference proof-of-concepts this implementation borrows ideas from:

* <https://github.com/re4/noisytcp-poc> — fragment steering, out-of-window
  probe, binary-search backlog calibration, TIME_WAIT recycle, ARP claim;
* <https://github.com/nsvk13/NoisyTCP-PoC> — `sendmmsg` batching, graded
  fragment-path probe, lab monitor semantics;
* <https://github.com/mustafasaydam/CVE-2026-99288---NoisyTCP-Exploit> —
  in-process liveness watchdog, staged microsecond pacing.
