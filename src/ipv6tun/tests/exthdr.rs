//! Tests of the extension header walk: where it finds the upper-layer
//! header behind each header it steps over, where it stops, and that it
//! never reads past the packet.

use super::*;

/// An IPv6 packet whose fixed header names `first` as its next header,
/// followed by `rest`.
fn chain(first: u8, rest: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(rest.len() as u16).to_be_bytes());
    p[6] = first;
    p[7] = 64;
    p.extend_from_slice(rest);
    p
}

/// An 8-byte options header (Hop-by-Hop or Destination Options) naming
/// `next`, holding one PadN option.
fn options(next: u8) -> Vec<u8> {
    vec![next, 0, 1, 4, 0, 0, 0, 0]
}

/// A 24-byte Segment Routing header (Routing type 4) naming `next`, with one
/// segment left.
fn routing(next: u8) -> Vec<u8> {
    let mut h = vec![next, 2, 4, 1, 0, 0, 0, 0];
    h.extend_from_slice(&[0xfd; 16]);
    h
}

/// A 24-byte Authentication Header naming `next`: payload length 4, so
/// `(4 + 2) * 4` bytes, with a 12-byte ICV.
fn auth(next: u8) -> Vec<u8> {
    let mut h = vec![next, 4, 0, 0];
    h.extend_from_slice(&[0x11; 20]);
    h
}

/// A Fragment header naming `next`, at fragment offset `offset` (in 8-byte
/// units), with more fragments to follow.
fn fragment(next: u8, offset: u16) -> Vec<u8> {
    let field = (offset << 3) | 1;
    let mut h = vec![next, 0];
    h.extend_from_slice(&field.to_be_bytes());
    h.extend_from_slice(&[0, 0, 0x12, 0x34]);
    h
}

/// The upper-layer header is found behind each header the walk steps over,
/// alone and in a chain, at the offset where it starts; an Authentication or
/// first Fragment header before it marks it sealed.
#[test]
fn the_walk_finds_the_upper_layer_header_behind_each_extension_header_it_steps_over() {
    let tcp = [0u8; 20];
    let cases: Vec<(&str, Vec<u8>, Chain)> = vec![
        (
            "none",
            chain(6, &tcp),
            Chain::Upper {
                proto: 6,
                at: 40,
                sealed: false,
            },
        ),
        (
            "Hop-by-Hop",
            chain(0, &[options(6), tcp.to_vec()].concat()),
            Chain::Upper {
                proto: 6,
                at: 48,
                sealed: false,
            },
        ),
        (
            "Routing",
            chain(43, &[routing(6), tcp.to_vec()].concat()),
            Chain::Upper {
                proto: 6,
                at: 64,
                sealed: false,
            },
        ),
        (
            "Destination Options",
            chain(60, &[options(58), vec![1; 8]].concat()),
            Chain::Upper {
                proto: 58,
                at: 48,
                sealed: false,
            },
        ),
        (
            "Authentication",
            chain(51, &[auth(6), tcp.to_vec()].concat()),
            Chain::Upper {
                proto: 6,
                at: 64,
                sealed: true,
            },
        ),
        (
            "first Fragment",
            chain(44, &[fragment(6, 0), tcp.to_vec()].concat()),
            Chain::Upper {
                proto: 6,
                at: 48,
                sealed: true,
            },
        ),
        (
            "Hop-by-Hop, Destination Options, Routing",
            chain(
                0,
                &[options(60), options(43), routing(17), vec![0; 8]].concat(),
            ),
            Chain::Upper {
                proto: 17,
                at: 80,
                sealed: false,
            },
        ),
    ];
    for (what, packet, expected) in cases {
        assert_eq!(upper(&packet), expected, "{what}");
    }
}

/// ESP, No Next Header and a protocol the walk does not know end it where
/// they start: it does not look inside them.
#[test]
fn the_walk_stops_at_esp_no_next_header_and_an_unknown_header() {
    for proto in [50, 59, 140] {
        let packet = chain(60, &[options(proto), vec![0; 16]].concat());
        assert_eq!(
            upper(&packet),
            Chain::Upper {
                proto,
                at: 48,
                sealed: false
            },
            "protocol {proto}"
        );
    }
}

/// A fragment other than the first names the protocol its Fragment header
/// carries and nothing more, since it holds none of that protocol's header.
#[test]
fn a_later_fragment_names_its_protocol_and_no_header() {
    let packet = chain(0, &[options(44), fragment(58, 185), vec![1; 64]].concat());
    assert_eq!(upper(&packet), Chain::LaterFragment { proto: 58 });
}

/// A chain that runs past the packet, whether a header's length field
/// overruns it or the packet ends where an extension header should start,
/// is reported as truncated rather than read past; so are a packet shorter
/// than its fixed header and one that is not IPv6.
#[test]
fn a_chain_that_runs_past_the_packet_is_truncated() {
    let overrun = chain(60, &[vec![6, 255, 1, 4, 0, 0, 0, 0], vec![0; 20]].concat());
    assert_eq!(upper(&overrun), Chain::Truncated, "length overruns");
    let short_header = chain(0, &[options(51), vec![6, 4, 0, 0]].concat());
    assert_eq!(upper(&short_header), Chain::Truncated, "header cut short");
    let bare = chain(60, &[]);
    assert_eq!(upper(&bare), Chain::Truncated, "header missing");
    assert_eq!(upper(&[0x60; 39]), Chain::Truncated, "under 40 bytes");
    let mut ipv4 = chain(6, &[0; 20]);
    ipv4[0] = 0x45;
    assert_eq!(upper(&ipv4), Chain::Truncated, "not IPv6");
}
