//! Tests of the MSS clamp on SYNs behind IPv6 extension headers: which
//! headers it steps over and which it leaves alone, the ceiling it clamps
//! to, and the checksum it keeps; and, for a SYN with no extension header,
//! that it writes what rewriting the option and recomputing the checksum
//! wrote before.

use super::*;

/// The folded one's complement sum of the TCP segment at `at` in `packet`
/// with its IPv6 pseudo-header (the fixed header's addresses); 0xffff when
/// its checksum is valid.
fn tcp_sum(packet: &[u8], at: usize) -> u16 {
    let mut sum: u32 = 0;
    for pair in packet[8..40].chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    sum += (packet.len() - at) as u32 + 6;
    for pair in packet[at..].chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// A SYN from `seed`-derived addresses whose fixed header names `first`,
/// followed by `chain` and a 28-byte TCP header holding `options` (padded
/// with End of Options), with a valid checksum.
fn syn_behind(first: u8, chain: &[u8], options: &[u8], seed: u8) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[6] = first;
    p[7] = 64;
    p[8] = 0xfd;
    p[9..24].fill(seed);
    p[24] = 0xfd;
    p[25..40].fill(seed.wrapping_mul(31).wrapping_add(7));
    p.extend_from_slice(chain);
    let tcp = p.len();
    p.resize(tcp + 28, 0);
    p[tcp..tcp + 2].copy_from_slice(&40000u16.to_be_bytes());
    p[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
    p[tcp + 4..tcp + 8].copy_from_slice(&(u32::from(seed) * 0x0101_0101).to_be_bytes());
    p[tcp + 12] = 7 << 4;
    p[tcp + 13] = 0x02;
    p[tcp + 14..tcp + 16].copy_from_slice(&64240u16.to_be_bytes());
    p[tcp + 20..tcp + 20 + options.len()].copy_from_slice(options);
    let payload = (p.len() - 40) as u16;
    p[4..6].copy_from_slice(&payload.to_be_bytes());
    let sum = !tcp_sum(&p, tcp);
    p[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(
        tcp_sum(&p, tcp),
        0xffff,
        "the SYN starts with a valid checksum"
    );
    p
}

/// The MSS option alone, at the start of the options.
fn mss(value: u16) -> Vec<u8> {
    let mut o = vec![2, 4];
    o.extend_from_slice(&value.to_be_bytes());
    o
}

/// The MSS value in `packet`'s option at `at`.
fn mss_at(packet: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

/// An 8-byte options header naming `next`, holding one PadN.
fn options(next: u8) -> Vec<u8> {
    vec![next, 0, 1, 4, 0, 0, 0, 0]
}

/// A 24-byte Segment Routing header naming `next`, one segment left.
fn routing(next: u8) -> Vec<u8> {
    let mut h = vec![next, 2, 4, 1, 0, 0, 0, 0];
    h.extend_from_slice(&[0xfd; 16]);
    h
}

/// A SYN whose TCP header follows Hop-by-Hop, Destination Options or
/// Routing headers, alone or chained, is clamped to the same ceiling as one
/// with TCP straight after the fixed header, and keeps a valid TCP checksum.
/// The MSS option is the effective MTU less the fixed IPv6 and TCP headers,
/// and the sender takes its extension headers off its own segments (RFC 9293
/// Section 3.7.1), so the clamp takes nothing off for them.
#[test]
fn a_syn_behind_hop_by_hop_routing_or_destination_options_is_clamped_to_the_plain_ceiling() {
    let cases: Vec<(&str, u8, Vec<u8>)> = vec![
        ("Hop-by-Hop", 0, options(6)),
        ("Destination Options", 60, options(6)),
        ("Routing", 43, routing(6)),
        (
            "Hop-by-Hop, Destination Options, Routing",
            0,
            [options(60), options(43), routing(6)].concat(),
        ),
    ];
    for (what, first, chain) in cases {
        let mut packet = syn_behind(first, &chain, &mss(1440), 3);
        let tcp = 40 + chain.len();
        assert!(clamp_tcp_mss(&mut packet, 1200), "{what}: clamped");
        assert_eq!(
            mss_at(&packet, tcp + 22),
            1200,
            "{what}: the ceiling, with nothing taken off for {} bytes of extension headers",
            chain.len()
        );
        assert_eq!(tcp_sum(&packet, tcp), 0xffff, "{what}: valid checksum");
    }
}

/// A SYN behind an Authentication or Fragment header, behind ESP, or behind
/// a header the walk does not know is left exactly as it came: rewriting it
/// would break the authentication or a checksum over other fragments, and
/// the clamp cannot find the TCP header in the others.
#[test]
fn a_syn_behind_an_authentication_fragment_esp_or_unknown_header_is_left_alone() {
    let mut auth = vec![6, 4, 0, 0];
    auth.extend_from_slice(&[0x11; 20]);
    let cases: Vec<(&str, u8, Vec<u8>)> = vec![
        ("Authentication", 51, auth),
        ("a first Fragment", 44, vec![6, 0, 0, 1, 0, 0, 0x12, 0x34]),
        ("ESP", 0, [options(50), vec![0; 8]].concat()),
        (
            "an unknown header",
            60,
            [options(140), vec![6, 0, 0, 0, 0, 0, 0, 0]].concat(),
        ),
    ];
    for (what, first, chain) in cases {
        let mut packet = syn_behind(first, &chain, &mss(1440), 5);
        let before = packet.clone();
        assert!(!clamp_tcp_mss(&mut packet, 1200), "{what}: not clamped");
        assert_eq!(packet, before, "{what}: untouched");
    }
}

/// A SYN behind a Hop-by-Hop header whose MSS is already within the
/// ceiling, or at it, is left exactly as it came.
#[test]
fn a_syn_behind_a_hop_by_hop_header_with_an_mss_within_the_ceiling_is_left_alone() {
    for value in [1100u16, 1200] {
        let mut packet = syn_behind(0, &options(6), &mss(value), 9);
        let before = packet.clone();
        assert!(
            !clamp_tcp_mss(&mut packet, 1200),
            "MSS {value}: not clamped"
        );
        assert_eq!(packet, before, "MSS {value}: untouched");
    }
}

/// The checksum stays valid when the MSS value sits at an odd offset in the
/// segment, after a one-byte NOP, so the two bytes rewritten span two of
/// the 16-bit words the checksum sums; with and without an extension
/// header.
#[test]
fn a_clamped_syn_keeps_a_valid_checksum_with_its_mss_value_at_an_odd_offset() {
    let shifted = [vec![1], mss(1440)].concat();
    for (what, first, chain) in [
        ("no extension header", 6, vec![]),
        ("Hop-by-Hop", 0, options(6)),
    ] {
        let mut packet = syn_behind(first, &chain, &shifted, 11);
        let tcp = 40 + chain.len();
        assert!(clamp_tcp_mss(&mut packet, 1200), "{what}: clamped");
        assert_eq!(mss_at(&packet, tcp + 23), 1200, "{what}: clamped value");
        assert_eq!(tcp_sum(&packet, tcp), 0xffff, "{what}: valid checksum");
    }
}

/// For a SYN with no extension header and a valid checksum, the clamp
/// writes the same bytes as rewriting the option and recomputing the whole
/// checksum, which is what it did before it learned to step over extension
/// headers: across MSS values, ceilings, option offsets and addresses.
#[test]
fn clamping_a_syn_with_no_extension_header_writes_what_rewriting_and_recomputing_wrote() {
    let mut compared = 0;
    for seed in 0..8u8 {
        for nops in 0..2usize {
            let opts = [vec![1; nops], mss(0)].concat();
            for value in (536u16..=1460).step_by(37).chain([65535]) {
                let mut options = opts.clone();
                options[nops + 2..nops + 4].copy_from_slice(&value.to_be_bytes());
                for ceiling in (500u16..=1500).step_by(53) {
                    let original = syn_behind(6, &[], &options, seed);
                    let mut clamped = original.clone();
                    let mut expected = original.clone();
                    let wrote = clamp_tcp_mss(&mut clamped, ceiling);
                    if value > ceiling {
                        let at = 40 + 20 + nops + 2;
                        expected[at..at + 2].copy_from_slice(&ceiling.to_be_bytes());
                        recalculate_l4_checksum(&mut expected);
                    }
                    assert_eq!(wrote, value > ceiling, "MSS {value}, ceiling {ceiling}");
                    assert_eq!(
                        clamped, expected,
                        "MSS {value}, ceiling {ceiling}, {nops} NOP, seed {seed}"
                    );
                    compared += 1;
                }
            }
        }
    }
    assert!(compared > 1000, "compared {compared} SYNs");
}
