//! Tests of the functions that build the ICMPv6 answers the adapter owes the
//! host: Destination Unreachable from our address, and Packet Too Big judged
//! by the per-source limiter at a time the caller gives.

use super::*;
use std::time::Duration;

/// Our address in these tests.
fn us() -> Ipv6Addr {
    "fd00::1".parse().unwrap()
}

/// An IPv6 UDP packet of `len` bytes from `src` to `dst`.
fn packet(src: Ipv6Addr, dst: Ipv6Addr, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 63;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p
}

/// Packet Too Big through one limiter: a second to the same source inside
/// the interval is held back, whether or not the first had a queue to go
/// to, and one at the end of the interval is sent.
#[test]
fn repeated_packet_too_big_to_one_source_is_held_back_for_the_interval_with_or_without_a_queue() {
    let over = packet(us(), "fd00::2".parse().unwrap(), 1100);
    let mtu = 1033;
    let mut limiter = IcmpRateLimiter::new();
    let t0 = Instant::now();
    let ms = |n| t0 + Duration::from_millis(n);
    assert_eq!(
        too_big(&over, mtu, &mut limiter, t0, false),
        None,
        "no queue"
    );
    assert_eq!(too_big(&over, mtu, &mut limiter, ms(99), true), None);
    assert_eq!(
        too_big(&over, mtu, &mut limiter, ms(100), true),
        build_packet_too_big(&over, mtu, "fd00::2".parse().unwrap())
    );
    assert_eq!(too_big(&over, mtu, &mut limiter, ms(150), true), None);
}

/// Destination Unreachable is built from our address for a packet owed an
/// ICMPv6 error, and not at all for one from a multicast source.
#[test]
fn unreachable_answers_from_our_address_and_not_a_packet_owed_no_error() {
    let outside: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let unicast = packet("fd00::2".parse().unwrap(), outside, 100);
    assert_eq!(
        unreachable(&unicast, us()),
        build_dest_unreachable(&unicast, DestUnreachableCode::NoRoute, us())
    );
    assert!(unreachable(&unicast, us()).is_some());
    let multicast = packet("ff02::1".parse().unwrap(), outside, 100);
    assert_eq!(unreachable(&multicast, us()), None);
}

/// A packet from the host to an address outside the mesh whose fixed header
/// names `first` as its next header, carrying `rest` (its extension headers
/// and upper layer), padded to 1100 bytes so it is also over a 1033-byte
/// MTU.
fn carrying(first: u8, rest: &[u8]) -> Vec<u8> {
    let mut p = packet(
        "fd00::2".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        1100,
    );
    p[6] = first;
    p[40..40 + rest.len()].copy_from_slice(rest);
    p
}

/// Whether `packet` draws Destination Unreachable, and Packet Too Big
/// through a fresh limiter.
fn answers(packet: &[u8]) -> (bool, bool) {
    let mut limiter = IcmpRateLimiter::new();
    (
        unreachable(packet, us()).is_some(),
        too_big(packet, 1033, &mut limiter, Instant::now(), true).is_some(),
    )
}

/// Each extension header chain the tests put an ICMPv6 message behind, as
/// (what, the fixed header's next header, the chain naming ICMPv6 last).
fn chains() -> Vec<(&'static str, u8, Vec<u8>)> {
    let options = |next: u8| vec![next, 0, 1, 4, 0, 0, 0, 0];
    let mut routing = vec![IPPROTO_ICMPV6, 2, 4, 1, 0, 0, 0, 0];
    routing.extend_from_slice(&[0xfd; 16]);
    let mut auth = vec![IPPROTO_ICMPV6, 4, 0, 0];
    auth.extend_from_slice(&[0x11; 20]);
    let fragment = vec![IPPROTO_ICMPV6, 0, 0, 1, 0, 0, 0x12, 0x34];
    vec![
        ("no extension header", IPPROTO_ICMPV6, vec![]),
        ("Hop-by-Hop", 0, options(IPPROTO_ICMPV6)),
        ("Destination Options", 60, options(IPPROTO_ICMPV6)),
        ("Routing", 43, routing.clone()),
        ("Authentication", 51, auth),
        ("a first Fragment", 44, fragment),
        (
            "Hop-by-Hop, Destination Options, Routing",
            0,
            [options(60), options(43), routing].concat(),
        ),
    ]
}

/// An ICMPv6 error message of each type, and a Redirect, draw neither
/// Destination Unreachable nor Packet Too Big behind any extension header
/// chain, as RFC 4443 Section 2.4 (e.1) and (e.2) require.
#[test]
fn an_icmpv6_error_or_redirect_behind_any_extension_header_chain_draws_no_icmpv6_error() {
    for (what, first, chain) in chains() {
        for kind in [1u8, 2, 3, 4, 127, 137] {
            let packet = carrying(
                first,
                &[chain.clone(), vec![kind, 0, 0, 0, 0, 0, 0, 0]].concat(),
            );
            assert_eq!(
                answers(&packet),
                (false, false),
                "(Destination Unreachable, Packet Too Big) for ICMPv6 type {kind} behind {what}"
            );
        }
    }
}

/// An Echo Request behind the same chains is not an error and still draws
/// both, so the suppression reaches only what RFC 4443 Section 2.4 (e)
/// names.
#[test]
fn an_echo_request_behind_any_extension_header_chain_still_draws_icmpv6_errors() {
    for (what, first, chain) in chains() {
        let packet = carrying(first, &[chain, vec![128, 0, 0, 0, 0, 0, 0, 0]].concat());
        assert_eq!(answers(&packet), (true, true), "Echo Request behind {what}");
    }
}

/// A later fragment of an ICMPv6 message holds no ICMPv6 header, so it
/// cannot be shown not to be an error and draws none; a later fragment of a
/// UDP datagram still draws both.
#[test]
fn a_later_fragment_of_an_icmpv6_message_draws_no_icmpv6_error_and_of_udp_does() {
    let later = |next: u8| vec![next, 0, 0x05, 0xc9, 0, 0, 0x12, 0x34];
    assert_eq!(
        answers(&carrying(44, &later(IPPROTO_ICMPV6))),
        (false, false),
        "ICMPv6"
    );
    assert_eq!(answers(&carrying(44, &later(17))), (true, true), "UDP");
}

/// A packet whose extension headers run past its end cannot be shown not to
/// carry an ICMPv6 error, and draws neither answer: RFC 4443 Section 2.4
/// puts the restrictions of (e) above any duty to originate an error.
#[test]
fn a_packet_whose_extension_headers_run_past_its_end_draws_no_icmpv6_error() {
    let mut packet = packet(
        "fd00::2".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        100,
    );
    packet[6] = 60;
    packet[40..48].copy_from_slice(&[17, 255, 1, 4, 0, 0, 0, 0]);
    assert_eq!(answers(&packet), (false, false));
}

/// Packet Too Big is never built with a source that is not a unicast
/// address (RFC 4443 Section 2.2), whatever its caller passes:
/// `too_big` takes the packet's destination as the reply's source, so a
/// packet to a multicast group is answered with nothing, and the builder
/// itself refuses a multicast or unspecified source.
#[test]
fn packet_too_big_is_never_built_with_a_multicast_or_unspecified_source() {
    let group: Ipv6Addr = "ff02::1".parse().unwrap();
    let to_group = packet(us(), group, 1100);
    let mut limiter = IcmpRateLimiter::new();
    assert_eq!(
        too_big(&to_group, 1033, &mut limiter, Instant::now(), true),
        None,
        "too_big for a packet to {group}"
    );
    let to_mesh = packet(us(), "fd00::2".parse().unwrap(), 1100);
    for source in [group, Ipv6Addr::UNSPECIFIED] {
        assert_eq!(
            build_packet_too_big(&to_mesh, 1033, source),
            None,
            "built from {source}"
        );
    }
    assert!(
        build_packet_too_big(&to_mesh, 1033, "fd00::2".parse().unwrap()).is_some(),
        "built from a unicast source"
    );
}
