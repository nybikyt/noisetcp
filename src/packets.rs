use std::io;
use std::net::Ipv4Addr;

pub(crate) const PROBE_PAYLOAD_LEN: usize = 40;
pub(crate) const PROBE_SPLITS: [usize; 4] = [8, 24, 32, 40];
pub(crate) const DEFAULT_SPLIT: usize = 24;
pub(crate) const FLAG_FIN: u8 = 0x01;
pub(crate) const FLAG_SYN: u8 = 0x02;
pub(crate) const FLAG_RST: u8 = 0x04;
pub(crate) const FLAG_ACK: u8 = 0x10;

// The default split has to be representable in the shortest race segment.
const _: () = assert!(DEFAULT_SPLIT < 20 + PROBE_PAYLOAD_LEN);

pub(crate) struct SegmentSpec {
    pub(crate) source_port: u16,
    pub(crate) sequence: u32,
    pub(crate) acknowledgment: u32,
    pub(crate) flags: u8,
    pub(crate) mss: u16,
    pub(crate) payload_len: usize,
}

pub(crate) fn tcp_packet(
    source: Ipv4Addr,
    target: Ipv4Addr,
    target_port: u16,
    spec: SegmentSpec,
) -> Vec<u8> {
    let option_len = if spec.mss != 0 { 4 } else { 0 };
    let header_len = 20 + option_len;
    let mut tcp = vec![0u8; header_len + spec.payload_len];
    tcp[0..2].copy_from_slice(&spec.source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&target_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&spec.sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&spec.acknowledgment.to_be_bytes());
    tcp[12] = ((header_len / 4) as u8) << 4;
    tcp[13] = spec.flags;
    tcp[14..16].copy_from_slice(&65_535u16.to_be_bytes());
    if spec.mss != 0 {
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22..24].copy_from_slice(&spec.mss.to_be_bytes());
    }
    for byte in &mut tcp[header_len..] {
        *byte = 0x41;
    }
    let sum = pseudo_header_sum(source, target, tcp.len()) + checksum_sum(&tcp);
    tcp[16..18].copy_from_slice(&finish_checksum(sum).to_be_bytes());
    tcp
}

pub(crate) fn ipv4_packet(
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
    packet[9] = 6u8;
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
        + u32::from(6u16)
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

/*
 * --selftest (idea from nsvk13): build every packet type the engine uses
 * with fixed documentation addresses, verify checksums, header fields
 * and fragment framing offline, and dump them. No root, no network.
 */
pub(crate) fn selftest() -> io::Result<()> {
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let target = Ipv4Addr::new(192, 0, 2, 2);
    let port = 9000u16;
    let sport = 40000u16;
    let isn = 0xdead_beefu32;

    let check = |condition: bool, message: &str| -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(format!("selftest: {message}")))
        }
    };
    let verify_tcp = |tcp: &[u8]| -> io::Result<()> {
        let sum = pseudo_header_sum(source, target, tcp.len()) + checksum_sum(tcp);
        check(finish_checksum(sum) == 0, "TCP checksum does not verify")
    };
    let verify_ip = |packet: &[u8]| -> io::Result<()> {
        check(
            finish_checksum(checksum_sum(&packet[..20])) == 0,
            "IPv4 header checksum does not verify",
        )
    };
    let hexdump = |tag: &str, packet: &[u8]| {
        print!("{tag} ({} bytes):", packet.len());
        for byte in packet {
            print!(" {byte:02x}");
        }
        println!();
    };

    // plain SYN with MSS option
    let syn = tcp_packet(
        source,
        target,
        port,
        SegmentSpec {
            source_port: sport,
            sequence: isn,
            acknowledgment: 0,
            flags: FLAG_SYN,
            mss: 1460,
            payload_len: 0,
        },
    );
    verify_tcp(&syn)?;
    check(syn.len() == 24, "SYN length")?;
    check(syn[12] == 0x60, "SYN data offset")?;
    check(syn[13] == FLAG_SYN, "SYN flags")?;
    check(syn[20..24] == [2u8, 4, 0x05, 0xb4], "SYN MSS option")?;
    let packet = ipv4_packet(source, target, 1, 0, false, &syn);
    verify_ip(&packet)?;
    check(packet[6] & 0x20 == 0, "SYN must not set MF")?;
    hexdump("SYN", &packet);

    // in-window RST
    let rst = tcp_packet(
        source,
        target,
        port,
        SegmentSpec {
            source_port: sport,
            sequence: isn.wrapping_add(1),
            acknowledgment: 0,
            flags: FLAG_RST,
            mss: 0,
            payload_len: 0,
        },
    );
    verify_tcp(&rst)?;
    check(rst.len() == 20 && rst[13] == FLAG_RST, "RST framing")?;
    let packet = ipv4_packet(source, target, 2, 0, false, &rst);
    verify_ip(&packet)?;
    hexdump("RST", &packet);

    // cookie ACK
    let ack = tcp_packet(
        source,
        target,
        port,
        SegmentSpec {
            source_port: sport,
            sequence: isn.wrapping_add(1),
            acknowledgment: 0x1234_5679,
            flags: FLAG_ACK,
            mss: 0,
            payload_len: 0,
        },
    );
    verify_tcp(&ack)?;
    check(
        u32::from_be_bytes([ack[8], ack[9], ack[10], ack[11]]) == 0x1234_5679,
        "cookie ACK acknowledgment field",
    )?;
    let packet = ipv4_packet(source, target, 3, 0, false, &ack);
    verify_ip(&packet)?;
    hexdump("cookie ACK", &packet);

    // fragmented reader at every probe split point
    for split in PROBE_SPLITS {
        let reader = tcp_packet(
            source,
            target,
            port,
            SegmentSpec {
                source_port: sport,
                sequence: isn.wrapping_add(1),
                acknowledgment: 0,
                flags: FLAG_ACK,
                mss: 0,
                payload_len: PROBE_PAYLOAD_LEN,
            },
        );
        verify_tcp(&reader)?;
        let first = ipv4_packet(source, target, 4, 0, true, &reader[..split]);
        let second = ipv4_packet(source, target, 4, split, false, &reader[split..]);
        verify_ip(&first)?;
        verify_ip(&second)?;
        check(first[6] & 0x20 != 0, "first fragment must set MF")?;
        check(
            u16::from_be_bytes([first[6], first[7]]) & 0x1fff == 0,
            "first fragment offset must be zero",
        )?;
        check(
            u16::from_be_bytes([second[6], second[7]]) == (split / 8) as u16,
            "second fragment offset",
        )?;
        check(
            first[4..6] == second[4..6],
            "fragment pair must share the IP id",
        )?;
        let mut reassembled = first[20..].to_vec();
        reassembled.extend_from_slice(&second[20..]);
        check(
            reassembled == reader,
            "fragments must reassemble to the segment",
        )?;
        hexdump(&format!("reader split={split} frag1"), &first);
        hexdump(&format!("reader split={split} frag2"), &second);
    }

    println!("selftest ok: checksums, header fields and fragment framing verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(payload_len: usize, mss: u16) -> Vec<u8> {
        tcp_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
            9000,
            SegmentSpec {
                source_port: 40000,
                sequence: 0x1234_5678,
                acknowledgment: 0x9abc_def0,
                flags: FLAG_ACK,
                mss,
                payload_len,
            },
        )
    }

    #[test]
    fn tcp_checksum_verifies_for_every_shape() {
        for payload_len in [0usize, 1, 7, 16, 40, 256] {
            for mss in [0u16, 1460] {
                let tcp = segment(payload_len, mss);
                let sum = pseudo_header_sum(
                    Ipv4Addr::new(192, 0, 2, 1),
                    Ipv4Addr::new(192, 0, 2, 2),
                    tcp.len(),
                ) + checksum_sum(&tcp);
                assert_eq!(finish_checksum(sum), 0, "payload={payload_len} mss={mss}");
            }
        }
    }

    #[test]
    fn ip_checksum_verifies_for_every_shape() {
        for payload_len in [0usize, 1, 7, 16, 40, 256] {
            let tcp = segment(payload_len, 1460);
            let packet = ipv4_packet(
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 2),
                7,
                0,
                false,
                &tcp,
            );
            assert_eq!(finish_checksum(checksum_sum(&packet[..20])), 0);
            assert_eq!(
                usize::from(u16::from_be_bytes([packet[2], packet[3]])),
                packet.len()
            );
        }
    }

    #[test]
    fn fragments_reassemble_at_every_legal_split() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let target = Ipv4Addr::new(192, 0, 2, 2);
        for payload_len in [8usize, 16, 40] {
            let tcp = segment(payload_len, 1460);
            for split in (8..tcp.len()).step_by(8) {
                let first = ipv4_packet(source, target, 9, 0, true, &tcp[..split]);
                let second = ipv4_packet(source, target, 9, split, false, &tcp[split..]);
                assert!(first[6] & 0x20 != 0, "MF must be set on the first fragment");
                assert_eq!(
                    u16::from_be_bytes([second[6], second[7]]),
                    (split / 8) as u16,
                    "second fragment offset"
                );
                assert_eq!(first[4..6], second[4..6], "fragments must share the IP id");
                let mut joined = first[20..].to_vec();
                joined.extend_from_slice(&second[20..]);
                assert_eq!(joined, tcp, "payload={payload_len} split={split}");
            }
        }
    }

    #[test]
    fn mss_option_is_optional_and_well_formed() {
        let with = segment(0, 1460);
        assert_eq!(with[12], 0x60, "data offset covers the MSS option");
        assert_eq!(with[20..24], [2, 4, 0x05, 0xb4]);
        let without = segment(0, 0);
        assert_eq!(without[12], 0x50);
        assert_eq!(without.len(), 20);
    }

    #[test]
    fn probe_splits_fit_the_probe_segment() {
        for split in PROBE_SPLITS {
            assert!(
                split >= 8 && split % 8 == 0,
                "split {split} must be 8-byte aligned"
            );
            assert!(
                split < 20 + PROBE_PAYLOAD_LEN,
                "split {split} exceeds the probe segment"
            );
        }
    }
}
