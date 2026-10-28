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

/// A packet from the host whose source is not our address is not handed to
/// the mesh, where the receiver would rebuild it with our address as its
/// source and its checksum would fail: the host is answered with
/// Destination Unreachable code 5, source address failed ingress/egress
/// policy (RFC 4443 Section 3.1), from our address. This holds on the system
/// TUN path and on the shared step an embedder's packets take, for a source
/// outside the mesh and for another mesh address, and whether the
/// destination names a key the adapter holds or not.
#[test]
fn a_packet_from_a_source_other_than_our_address_is_answered_source_policy_and_not_forwarded() {
    let peer = any_key();
    let state = state_with(peer, 1400);
    let held = peer.address().to_ipv6();
    let stranger = any_key().address().to_ipv6();
    for src in ["2001:db8::5", "fd00::5"] {
        let src: Ipv6Addr = src.parse().unwrap();
        for dst in [held, stranger] {
            let sent = packet(src, dst, 80);
            let refused =
                build_dest_unreachable(&sent, DestUnreachableCode::SourcePolicy, us()).unwrap();
            let mut read = sent.clone();
            assert_eq!(
                from_tun(&mut read, 1360, &PathMtuReplica::default(), &state, us()),
                FromTun::Host {
                    clamped: None,
                    host: Host::Unreachable(refused.clone()),
                },
                "system TUN path, from {src} to {dst}"
            );
            assert_eq!(
                outbound(&sent, &state, us()),
                Host::Unreachable(refused),
                "shared step, from {src} to {dst}"
            );
        }
    }
}

/// A packet from the unspecified address or a multicast source is refused
/// with no answer at all, since its source names no single node to tell
/// (RFC 4443 Section 2.4 (e.6)).
#[test]
fn a_packet_from_the_unspecified_address_or_a_multicast_source_is_refused_unanswered() {
    let peer = any_key();
    let state = state_with(peer, 1400);
    for src in ["::", "ff02::1"] {
        let sent = packet(src.parse().unwrap(), peer.address().to_ipv6(), 80);
        let mut read = sent.clone();
        assert_eq!(
            from_tun(&mut read, 1360, &PathMtuReplica::default(), &state, us()),
            FromTun::Host {
                clamped: None,
                host: Host::Nothing,
            },
            "system TUN path, from {src}"
        );
        assert_eq!(
            outbound(&sent, &state, us()),
            Host::Nothing,
            "shared step, from {src}"
        );
    }
}

/// The refusal is logged at debug under the outbound module's target, with
/// the source it refused.
#[test]
fn a_refused_foreign_source_is_logged_at_debug_with_the_source() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    let state = state_with(any_key(), 1400);
    let src: Ipv6Addr = "2001:db8::5".parse().unwrap();
    outbound(
        &packet(src, any_key().address().to_ipv6(), 80),
        &state,
        us(),
    );
    let message = "Refusing a packet from the host whose source is not our address";
    assert_eq!(logs.targets(message), vec!["fips::ipv6tun::outbound"]);
    let line = logs.line(message).unwrap();
    assert!(line.starts_with("DEBUG"), "logged at debug: {line}");
    assert_eq!(
        crate::testutil::log_field(&line, "src"),
        Some("2001:db8::5")
    );
}

/// An oversized packet to a destination outside `fd00::/8`, which only an
/// embedder that owns the TUN can send, draws no Packet Too Big: the mesh
/// could not carry it at any size. One to a multicast group draws no answer
/// at all (RFC 4443 Section 2.4 (e.3)), and one to a unicast address
/// outside the mesh draws Destination Unreachable from our address, as a
/// packet to it of any size does. Each answer is followed through the
/// decisions the driver takes: the shared step, then `too_big` for a
/// Packet Too Big.
#[test]
fn an_oversized_packet_to_a_destination_outside_the_mesh_draws_no_packet_too_big() {
    let state = state_with(any_key(), 1000);
    let over = usize::from(state.ipv6_mtu()) + 1;
    let sent = |dst: Ipv6Addr| {
        let packet = packet(us(), dst, over);
        let mut limiter = IcmpRateLimiter::new();
        match outbound(&packet, &state, us()) {
            Host::TooBig(mtu) => too_big(&packet, mtu, &mut limiter, Instant::now(), true),
            Host::Unreachable(reply) => Some(reply),
            Host::Nothing => None,
            Host::Mesh(_) => panic!("{dst} is not a mesh destination"),
        }
    };
    for group in ["ff02::1", "ff0e::1:3"] {
        let group: Ipv6Addr = group.parse().unwrap();
        assert_eq!(sent(group), None, "an answer to a packet to {group}");
    }
    let outside: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        sent(outside),
        Some(from_us(&packet(us(), outside, over))),
        "the answer to a packet to {outside}"
    );
}

/// The folded one's complement sum of the TCP segment at `at` in `packet`
/// with its IPv6 pseudo-header; 0xffff when its checksum is valid.
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

/// On the system TUN path, a SYN whose TCP header follows an 8-byte
/// Hop-by-Hop Options header is clamped to the stored path as one with TCP
/// straight after the fixed header is (RFC 9293 Section 3.7.1: the MSS
/// option counts no extension header), keeps a valid TCP checksum, and is
/// handed to the mesh clamped.
#[test]
fn a_syn_behind_a_hop_by_hop_header_is_clamped_to_the_stored_path_as_a_plain_syn_is() {
    let peer = any_key();
    let state = state_with(peer, 1400);
    let paths = PathMtuReplica::default();
    paths
        .write()
        .unwrap()
        .insert(peer.address(), crate::node::path_mtu::payload_limit(1000));

    // The same SYN, clamped to 863 with no extension header, as the system
    // TUN path test above shows.
    let plain = syn(us(), peer.address().to_ipv6());
    let mut sent = plain[..40].to_vec();
    // Hop-by-Hop Options: next header TCP, length 0 (8 bytes), one PadN.
    sent.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);
    sent.extend_from_slice(&plain[40..]);
    sent[4..6].copy_from_slice(&32u16.to_be_bytes());
    sent[6] = 0;
    sent[48 + 16] = 0;
    sent[48 + 17] = 0;
    let sum = !tcp_sum(&sent, 48);
    sent[48 + 16..48 + 18].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(
        tcp_sum(&sent, 48),
        0xffff,
        "the SYN starts with a valid checksum"
    );

    let verdict = from_tun(&mut sent, 1360, &paths, &state, us());
    assert_eq!(
        u16::from_be_bytes([sent[70], sent[71]]),
        863,
        "the stored path's 863, nothing taken off for the header"
    );
    assert_eq!(
        tcp_sum(&sent, 48),
        0xffff,
        "the clamped SYN's checksum is valid"
    );
    let FromTun::Host {
        clamped: Some(_),
        host: Host::Mesh(datagram),
    } = verdict
    else {
        panic!("clamped and forwarded: {verdict:?}");
    };
    assert_eq!(Some(datagram.payload), compress_ipv6(&sent));
}
