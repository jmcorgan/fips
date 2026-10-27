use super::*;
use crate::ipv6tun::icmp::{
    DestUnreachableCode, build_dest_unreachable, build_packet_too_big, too_big,
};
use crate::ipv6tun::icmp_rate_limit::IcmpRateLimiter;
use crate::ipv6tun::link::{FromMesh, any_key};
use std::net::Ipv6Addr;
use std::time::Instant;

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

/// Destination Unreachable for `packet`, from our address.
fn from_us(packet: &[u8]) -> Vec<u8> {
    build_dest_unreachable(packet, DestUnreachableCode::NoRoute, us()).unwrap()
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
    let sent = packet(us(), peer.address().to_ipv6(), 300);

    let Host::Mesh(datagram) = outbound(&sent, &state, us()) else {
        panic!("forwarded");
    };

    assert_eq!(datagram.peer, peer);
    assert_eq!(Some(datagram.payload), compress_ipv6(&sent));
}

#[test]
fn a_packet_to_a_prefix_no_key_names_is_answered_unreachable_from_the_raw_packet() {
    let state = state_with(any_key(), 1400);
    let stranger = any_key().address().to_ipv6();
    let sent = packet(us(), stranger, 80);

    assert_eq!(
        outbound(&sent, &state, us()),
        Host::Unreachable(from_us(&sent))
    );
}

#[test]
fn a_packet_over_the_published_limit_to_an_unknown_destination_is_answered_packet_too_big() {
    let state = state_with(any_key(), 1000);
    let mtu = state.ipv6_mtu();
    assert_eq!(mtu, 1000 + 33);
    let stranger = any_key().address().to_ipv6();

    let over = packet(us(), stranger, usize::from(mtu) + 1);
    assert_eq!(outbound(&over, &state, us()), Host::TooBig(u32::from(mtu)));
    let fits = packet(us(), stranger, usize::from(mtu));
    assert_eq!(
        outbound(&fits, &state, us()),
        Host::Unreachable(from_us(&fits))
    );

    let mut limiter = IcmpRateLimiter::new();
    assert_eq!(
        too_big(&over, u32::from(mtu), &mut limiter, Instant::now(), true),
        build_packet_too_big(&over, u32::from(mtu), stranger)
    );
}

#[test]
fn a_packet_to_a_known_key_goes_to_the_node_whatever_its_size() {
    // The node holds the live limit; the adapter's copy can trail it.
    let peer = any_key();
    let state = state_with(peer, 1000);
    let over = packet(
        us(),
        peer.address().to_ipv6(),
        usize::from(state.ipv6_mtu()) + 1,
    );
    let Host::Mesh(datagram) = outbound(&over, &state, us()) else {
        panic!("for the node to judge");
    };
    assert_eq!(Some(datagram.payload), compress_ipv6(&over));
}

/// What the adapter writes toward the host for a refusal, through a fresh
/// limiter: each answer it is owed, with Packet Too Big built as the
/// limiter allows it.
fn answered(refusal: Refusal) -> Vec<Vec<u8>> {
    let mut limiter = IcmpRateLimiter::new();
    answer(refusal, us())
        .into_iter()
        .filter_map(|owed| match owed {
            Owed::Unreachable(reply) => Some(reply),
            Owed::TooBig(packet, mtu) => too_big(&packet, mtu, &mut limiter, Instant::now(), true),
        })
        .collect()
}

#[test]
fn every_refusal_of_a_packet_sent_from_our_address_is_answered_byte_for_byte_as_before() {
    let peer = any_key();
    let dst = peer.address().to_ipv6();
    for len in [40, 41, 80, 1200, 1500] {
        let sent = packet(us(), dst, len);
        let payload = compress_ipv6(&sent).unwrap();

        // The answers built from the packet itself.
        let mut limiter = IcmpRateLimiter::new();
        let mut expected: Vec<Vec<u8>> = too_big(&sent, 1033, &mut limiter, Instant::now(), true)
            .into_iter()
            .collect();
        expected.extend(std::iter::repeat_n(from_us(&sent), 3));
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
        let today: Vec<Vec<u8>> = unreachable(sent, us()).into_iter().collect();
        assert_eq!(got.len(), 1);
        assert_eq!(today.len(), 1);
        // The quote starts after the 40-byte IPv6 and 8-byte ICMPv6 headers.
        let quoted = |reply: &[u8]| reply[48 + field.start..48 + field.end].to_vec();
        assert_eq!(quoted(&today[0]), sent[field.clone()].to_vec(), "as sent");
        assert_eq!(quoted(&got[0]), rebuilt, "as rebuilt");
        assert_ne!(got, today);
    }
}

/// A host packet carrying a TCP SYN with one MSS option of 1440, from
/// `src` to `dst`.
fn syn(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let mut p = vec![0u8; 64];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&24u16.to_be_bytes());
    p[6] = 6;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[52] = 6 << 4;
    p[53] = 0x02;
    p[60..64].copy_from_slice(&[2, 4, 0x05, 0xa0]);
    p
}

/// The system TUN path filters, hairpins and clamps before the shared step;
/// a packet an embedder that owns the TUN sends gets the shared step alone.
/// On one packet each: a destination outside the mesh, one addressed to us,
/// and a SYN to a known key over a narrower stored path.
#[test]
fn the_system_tun_path_filters_hairpins_and_clamps_where_the_shared_step_does_not() {
    let peer = any_key();
    let state = state_with(peer, 1400);
    let paths = PathMtuReplica::default();
    paths
        .write()
        .unwrap()
        .insert(peer.address(), crate::node::path_mtu::payload_limit(1000));

    let off: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let sent = packet(us(), off, 80);
    let mut read = sent.clone();
    assert_eq!(
        from_tun(&mut read, 1360, &paths, &state, us()),
        FromTun::OffMesh(from_us(&sent))
    );
    assert_eq!(
        outbound(&sent, &state, us()),
        Host::Unreachable(from_us(&sent))
    );

    let sent = syn(us(), us());
    let mut looped = sent.clone();
    assert_eq!(
        from_tun(&mut looped, 1360, &paths, &state, us()),
        FromTun::Hairpin
    );
    let mut checksummed = sent.clone();
    crate::ipv6tun::tcp_mss::recalculate_l4_checksum(&mut checksummed);
    assert_ne!(checksummed, sent, "the SYN's checksum was left unfinished");
    assert_eq!(looped, checksummed, "hairpinned with its checksum finished");
    assert_eq!(
        outbound(&sent, &state, us()),
        Host::Unreachable(from_us(&sent))
    );

    let sent = syn(us(), peer.address().to_ipv6());
    let mut clamped = sent.clone();
    let FromTun::Host {
        clamped: Some(863),
        host: Host::Mesh(datagram),
    } = from_tun(&mut clamped, 1360, &paths, &state, us())
    else {
        panic!("clamped to the stored path and forwarded");
    };
    assert_eq!(u16::from_be_bytes([clamped[62], clamped[63]]), 863);
    assert_eq!(Some(datagram.payload), compress_ipv6(&clamped));
    let Host::Mesh(datagram) = outbound(&sent, &state, us()) else {
        panic!("forwarded unclamped");
    };
    assert_eq!(Some(datagram.payload), compress_ipv6(&sent));
}

/// A packet that is not IPv6 gets nothing on either path, and the reader
/// leaves it as read, whether its bytes 24 to 40 read as our address or as
/// the address of a key the adapter holds.
#[test]
fn a_packet_that_is_not_ipv6_gets_nothing_on_either_path() {
    let peer = any_key();
    let state = state_with(peer, 1400);
    for dst in [us(), peer.address().to_ipv6()] {
        let mut v4 = packet(us(), dst, 60);
        v4[0] = 0x45;
        let mut read = v4.clone();
        assert_eq!(
            from_tun(&mut read, 1360, &PathMtuReplica::default(), &state, us()),
            FromTun::Nothing,
            "to {dst}"
        );
        assert_eq!(read, v4, "left as read, to {dst}");
        assert_eq!(outbound(&v4, &state, us()), Host::Nothing, "to {dst}");
    }
}

/// A refusal of several payloads is owed one answer per payload, in order.
#[test]
fn a_refusal_of_several_payloads_is_owed_one_answer_each_in_order() {
    let peer = any_key();
    let first = packet(us(), peer.address().to_ipv6(), 80);
    let second = packet(us(), peer.address().to_ipv6(), 120);
    let owed = answer(
        Refusal::NoRoute {
            peer,
            payloads: vec![
                compress_ipv6(&first).unwrap(),
                compress_ipv6(&second).unwrap(),
            ],
        },
        us(),
    );
    assert_eq!(
        owed,
        vec![
            Owed::Unreachable(from_us(&first)),
            Owed::Unreachable(from_us(&second)),
        ]
    );
    let owed = answer(
        Refusal::TooBig {
            peer,
            payload_limit: 1000,
            payload: compress_ipv6(&first).unwrap(),
        },
        us(),
    );
    assert_eq!(owed, vec![Owed::TooBig(first, 1033)]);
}
