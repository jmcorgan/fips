use super::*;
use crate::ipv6tun::icmp_rate_limit::IcmpRateLimiter;
use crate::ipv6tun::link::{FromMesh, any_key};
use std::net::Ipv6Addr;
use std::sync::Mutex;
use std::sync::mpsc;

/// Our address in these tests.
fn us() -> Ipv6Addr {
    "fd00::1".parse().unwrap()
}

/// An IPv6 UDP packet of `len` bytes from `src` to `dst`, with a payload
/// that differs per byte so a rebuilt copy is checked byte for byte.
fn packet(src: Ipv6Addr, dst: Ipv6Addr, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x6a;
    p[1] = 0xbc;
    p[2] = 0xde;
    p[3] = 0xf1;
    p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 63;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    for (i, byte) in p[40..].iter_mut().enumerate() {
        *byte = (i * 7) as u8;
    }
    p
}

/// Everything written toward the host so far.
fn drain(rx: &mpsc::Receiver<Vec<u8>>) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// A fresh limiter.
fn limiter() -> Mutex<IcmpRateLimiter> {
    Mutex::new(IcmpRateLimiter::new())
}

/// State that knows `peer` and carries the payload limit `limit`.
fn state_with(peer: PeerKey, limit: u16) -> MeshState {
    let state = MeshState::new();
    state.apply(FromMesh::NodeMtu {
        payload_limit: limit,
    });
    state.apply(FromMesh::KnownKey { peer });
    state
}

#[test]
fn a_packet_to_a_known_key_becomes_a_datagram_carrying_the_compressed_packet() {
    let peer = any_key();
    let state = state_with(peer, 1400);
    let (tun_tx, rx) = mpsc::channel();
    let limiter = limiter();
    let mut icmp = IcmpContext::new(Some(&tun_tx), us(), &limiter);
    let sent = packet(us(), peer.address().to_ipv6(), 300);

    let datagram = outbound(&sent, &state, &mut icmp).expect("forwarded");

    assert_eq!(datagram.peer, peer);
    assert_eq!(Some(datagram.payload), compress_ipv6(&sent));
    assert!(drain(&rx).is_empty(), "nothing is answered");
}

#[test]
fn a_packet_to_a_prefix_no_key_names_is_answered_unreachable_from_the_raw_packet() {
    let state = state_with(any_key(), 1400);
    let (tun_tx, rx) = mpsc::channel();
    let limiter = limiter();
    let mut icmp = IcmpContext::new(Some(&tun_tx), us(), &limiter);
    let stranger = any_key().address().to_ipv6();
    let sent = packet(us(), stranger, 80);

    assert_eq!(outbound(&sent, &state, &mut icmp), None);

    let expected = crate::ipv6tun::icmp::build_dest_unreachable(
        &sent,
        crate::ipv6tun::icmp::DestUnreachableCode::NoRoute,
        us(),
    )
    .unwrap();
    assert_eq!(drain(&rx), vec![expected]);
}

#[test]
fn a_packet_over_the_published_limit_to_an_unknown_destination_is_answered_packet_too_big() {
    let state = state_with(any_key(), 1000);
    let (tun_tx, rx) = mpsc::channel();
    let limiter = limiter();
    let mut icmp = IcmpContext::new(Some(&tun_tx), us(), &limiter);
    let mtu = state.ipv6_mtu();
    assert_eq!(mtu, 1000 + 33);
    let stranger = any_key().address().to_ipv6();

    let over = packet(us(), stranger, usize::from(mtu) + 1);
    assert_eq!(outbound(&over, &state, &mut icmp), None);
    let fits = packet(us(), stranger, usize::from(mtu));
    assert_eq!(outbound(&fits, &state, &mut icmp), None);

    use crate::ipv6tun::icmp::{DestUnreachableCode, build_dest_unreachable, build_packet_too_big};
    assert_eq!(
        drain(&rx),
        vec![
            build_packet_too_big(&over, u32::from(mtu), stranger).unwrap(),
            build_dest_unreachable(&fits, DestUnreachableCode::NoRoute, us()).unwrap(),
        ]
    );
}

#[test]
fn a_packet_to_a_known_key_goes_to_the_node_whatever_its_size() {
    // The node holds the live limit; the adapter's copy can trail it.
    let peer = any_key();
    let state = state_with(peer, 1000);
    let (tun_tx, rx) = mpsc::channel();
    let limiter = limiter();
    let mut icmp = IcmpContext::new(Some(&tun_tx), us(), &limiter);
    let over = packet(
        us(),
        peer.address().to_ipv6(),
        usize::from(state.ipv6_mtu()) + 1,
    );
    let datagram = outbound(&over, &state, &mut icmp).expect("for the node to judge");
    assert_eq!(Some(datagram.payload), compress_ipv6(&over));
    assert!(drain(&rx).is_empty());
}

/// What today's path writes toward the host for each refusal, built from the
/// packet the host sent, against what the adapter writes from the refused
/// payload.
fn answered(refusal: Refusal) -> Vec<Vec<u8>> {
    let (tun_tx, rx) = mpsc::channel();
    let limiter = limiter();
    answer(
        refusal,
        &mut IcmpContext::new(Some(&tun_tx), us(), &limiter),
    );
    drain(&rx)
}

#[test]
fn every_refusal_of_a_packet_sent_from_our_address_is_answered_byte_for_byte_as_before() {
    let peer = any_key();
    let dst = peer.address().to_ipv6();
    for len in [40, 41, 80, 1200, 1500] {
        let sent = packet(us(), dst, len);
        let payload = compress_ipv6(&sent).unwrap();

        // Today: `too_big(packet, mtu)` and `dest_unreachable(packet)` on
        // the packet itself.
        let (tun_tx, rx) = mpsc::channel();
        let limiter = limiter();
        let mut today = IcmpContext::new(Some(&tun_tx), us(), &limiter);
        today.too_big(&sent, 1033);
        today.dest_unreachable(&sent);
        today.dest_unreachable(&sent);
        today.dest_unreachable(&sent);
        let expected = drain(&rx);
        assert_eq!(expected.len(), 4, "length {len}");

        let mut got = answered(Refusal::TooBig {
            peer,
            payload_limit: 1000,
            payload: payload.clone(),
        });
        got.extend(answered(Refusal::TableFull {
            peer,
            payload: payload.clone(),
        }));
        got.extend(answered(Refusal::NoRoute {
            peer,
            payloads: vec![payload.clone(), payload.clone()],
        }));
        assert_eq!(got, expected, "length {len}");
    }
}

#[test]
fn a_refused_packet_from_a_foreign_source_is_answered_as_if_sent_from_our_address() {
    // The one difference the payload carries: compression keeps
    // no source address, so a packet the host sent from another address is
    // rebuilt with ours, and the answer goes to us rather than to the
    // foreign source.
    let peer = any_key();
    let foreign: Ipv6Addr = "fd00::99".parse().unwrap();
    let sent = packet(foreign, peer.address().to_ipv6(), 80);
    let got = answered(Refusal::TableFull {
        peer,
        payload: compress_ipv6(&sent).unwrap(),
    });
    assert_eq!(got.len(), 1);
    assert_eq!(&got[0][24..40], &us().octets(), "sent to our address");
    assert_eq!(
        &got[0][48 + 8..48 + 24],
        &us().octets(),
        "quotes our address as source"
    );
}

#[test]
fn packet_too_big_from_a_refusal_reports_the_ipv6_mtu_of_its_payload_limit() {
    let peer = any_key();
    let sent = packet(us(), peer.address().to_ipv6(), 1300);
    let got = answered(Refusal::TooBig {
        peer,
        payload_limit: 1170,
        payload: compress_ipv6(&sent).unwrap(),
    });
    assert_eq!(got.len(), 1);
    assert_eq!(
        u32::from_be_bytes(got[0][44..48].try_into().unwrap()),
        1203,
        "1170 + 33"
    );
}

#[test]
fn a_refused_packet_to_a_non_fd_destination_or_with_a_wrong_length_field_is_quoted_as_rebuilt() {
    // Only an embedder that owns the TUN can send either: the system TUN
    // reader answers a destination outside fd00::/8 itself, and the kernel
    // does not route a packet whose length field disagrees with its length.
    // Compression keeps neither the destination's first byte nor the length
    // field, so the quote names the destination in its fd00::/8 form and
    // carries the computed length, where the TUN path quoted the packet as
    // sent. The forwarded packet already arrives that way.
    let peer = any_key();
    let mut odd = peer.address().to_ipv6().octets();
    odd[0] = 0xfe;
    let to_odd = packet(us(), Ipv6Addr::from(odd), 80);
    let mut bad_length = packet(us(), peer.address().to_ipv6(), 80);
    bad_length[4..6].copy_from_slice(&7u16.to_be_bytes());

    for (sent, field, rebuilt) in [
        (&to_odd, 24..40, peer.address().as_bytes().to_vec()),
        (&bad_length, 4..6, 40u16.to_be_bytes().to_vec()),
    ] {
        let got = answered(Refusal::TableFull {
            peer,
            payload: compress_ipv6(sent).unwrap(),
        });
        let (tun_tx, rx) = mpsc::channel();
        let limiter = limiter();
        IcmpContext::new(Some(&tun_tx), us(), &limiter).dest_unreachable(sent);
        let today = drain(&rx);
        assert_eq!(got.len(), 1);
        assert_eq!(today.len(), 1);
        // The quote starts after the 40-byte IPv6 and 8-byte ICMPv6 headers.
        let quoted = |reply: &[u8]| reply[48 + field.start..48 + field.end].to_vec();
        assert_eq!(quoted(&today[0]), sent[field.clone()].to_vec(), "as sent");
        assert_eq!(quoted(&got[0]), rebuilt, "as rebuilt");
        assert_ne!(got, today);
    }
}
