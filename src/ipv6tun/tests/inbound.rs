//! Tests of the host-side half of delivering a peer's datagram.

use super::*;
use crate::ipv6tun::ipv6_shim::compress_ipv6;
use crate::ipv6tun::link::any_key;

#[test]
fn mark_ce_marks_only_ect() {
    // ECT(0): TC low bits 0b10. Byte1 high nibble carries TC[3:0].
    let mut ect0 = [0x60, 0x20, 0, 0];
    mark_ce(&mut ect0);
    assert_eq!(ect0[1] & 0x30, 0x30, "ECN bits set to CE");

    // Not-ECT (ECN 0b00) is never marked.
    let mut not_ect = [0x60, 0x00, 0, 0];
    mark_ce(&mut not_ect);
    assert_eq!(not_ect[1] & 0x30, 0x00, "Not-ECT stays unmarked");

    // Too short → no panic, no change.
    let mut short = [0x60];
    mark_ce(&mut short);
    assert_eq!(short, [0x60]);
}

/// An ECT(0) UDP packet of `len` bytes between two placeholder addresses.
fn ect_packet(len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x60;
    p[1] = 0x20;
    p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    for (i, byte) in p[40..].iter_mut().enumerate() {
        *byte = i as u8;
    }
    p
}

#[test]
fn a_delivered_packet_is_rebuilt_between_the_sender_and_us_and_marked_only_when_the_datagram_was() {
    let source = [0xfd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let dest = [0xfd, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
    let payload = compress_ipv6(&ect_packet(100)).unwrap();
    let mut deliver = Deliver {
        peer: any_key(),
        payload,
        ce: false,
    };

    let plain = unpack(&deliver, source, dest).unwrap();
    assert_eq!(&plain[8..24], &source);
    assert_eq!(&plain[24..40], &dest);
    assert_eq!(plain[1] & 0x30, 0x20, "unmarked datagram stays ECT(0)");
    assert_eq!(&plain[40..], &ect_packet(100)[40..]);

    deliver.ce = true;
    let marked = unpack(&deliver, source, dest).unwrap();
    assert_eq!(marked[1] & 0x30, 0x30, "CE datagram is marked CE");
    assert_eq!(&marked[2..], &plain[2..]);
}

#[test]
fn a_payload_that_is_not_a_compressed_packet_is_not_delivered() {
    let deliver = Deliver {
        peer: any_key(),
        payload: vec![0x60; 3],
        ce: true,
    };
    assert_eq!(unpack(&deliver, [0xfd; 16], [0xfd; 16]), None);
}
