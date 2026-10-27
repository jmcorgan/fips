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
