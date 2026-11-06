//! Attribution of authentic frames (multipath v1 draft, Sections 5.3 and
//! 5.12): which path a frame counts on, the receive counts an ack reports,
//! the single-path roam, the peer's active path, the sample flag, the
//! slots kept open on release, and that `Bundle::account` and
//! `Bundle::charge` allocate nothing. Every test drives a `Bundle` in the
//! shell.

use alloc::format;
use alloc::vec::Vec;

use super::shell::*;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::link::LinkMessageType;
use crate::proto::path::{Account, Charge, Input, Output, PathRef, PathState, Roam};
use crate::testutil::{TestInstant, allocations};

/// The type byte of a session datagram.
const DATAGRAM: u8 = 0x00;
/// The type byte of a heartbeat, a link message that marks the peer's
/// active path.
const HEARTBEAT: u8 = 0x51;
/// A type byte no link message has.
const UNKNOWN: u8 = 0xEE;

#[test]
fn a_frame_is_attributed_to_the_path_of_its_transport_and_address() {
    let mut n = Node::capable(31);
    let q = live_path(&mut n, t(1), addr(2), 0xB);
    assert_eq!(q, 1);
    assert_eq!(n.account(t(1), &addr(1), 100, HEARTBEAT).path, Some(0));
    assert_eq!(n.account(t(1), &addr(2), 100, HEARTBEAT).path, Some(q));
    // The same address on another transport is another pair.
    assert_eq!(n.account(t(2), &addr(2), 100, HEARTBEAT).path, None);
}

#[test]
fn rx_frames_counts_only_that_paths_frames() {
    let mut n = Node::capable(32);
    let q = live_path(&mut n, t(1), addr(2), 0xB);
    for len in [100, 200, 300] {
        n.account(t(1), &addr(1), len, DATAGRAM);
    }
    n.now = TestInstant(40);
    for len in [50, 60] {
        n.account(t(1), &addr(2), len, DATAGRAM);
    }
    // The peer's probe on P: its frame is accounted, then it is stepped.
    n.now = TestInstant(70);
    let probe = probe_from(0xA, 1, 27);
    let frame = probe.len + FRAME_OVERHEAD;
    n.account(t(1), &addr(1), frame, LinkMessageType::PathProbe.to_byte());
    let out = n.probe(t(1), addr(1), probe);
    let [(_, ack)] = sent_acks(&out)[..] else {
        panic!("one ack: {out:?}");
    };
    assert_eq!(
        (ack.rx_frames, ack.rx_bytes),
        (4, 600 + frame as u32),
        "P's three frames and the probe's own"
    );
    let live = n.b.paths().get(0).unwrap().live();
    assert_eq!(live.heard_at(), Some(TestInstant(70)));
    let live = n.b.paths().get(q).unwrap().live();
    assert_eq!((live.frames(), live.bytes()), (2, 110));
    assert_eq!(live.heard_at(), Some(TestInstant(40)));
    // A probe on Q reports Q's counts, its own frame included.
    let probe = probe_from(0xB, 2, 27);
    n.account(t(1), &addr(2), frame, LinkMessageType::PathProbe.to_byte());
    let out = n.probe(t(1), addr(2), probe);
    let [(_, ack)] = sent_acks(&out)[..] else {
        panic!("one ack: {out:?}");
    };
    assert_eq!((ack.rx_frames, ack.rx_bytes), (3, 110 + frame as u32));
}

#[test]
fn a_frame_from_no_path_counts_nowhere_moves_nothing_and_creates_nothing() {
    let unmoved = Account {
        path: None,
        sample: false,
        roam: Roam::Unmoved,
    };
    let mut n = Node::capable(33);
    live_path(&mut n, t(1), addr(2), 0xB);
    let before = format!("{:?}", n.b.paths());
    for (transport, a) in [(t(1), addr(9)), (t(3), addr(1))] {
        for ty in [HEARTBEAT, DATAGRAM, UNKNOWN] {
            assert_eq!(n.account(transport, &a, 100, ty), unmoved);
        }
    }
    assert_eq!(format!("{:?}", n.b.paths()), before);
    // A link of one path: a frame from another transport moves nothing
    // either.
    let mut n = Node::new(33);
    let before = format!("{:?}", n.b.paths());
    let account = n.account(t(2), &addr(5), 100, HEARTBEAT);
    assert_eq!((account.path, account.roam), (None, Roam::Unmoved));
    assert_eq!(format!("{:?}", n.b.paths()), before);
}

#[test]
fn with_one_path_a_frame_roams_it_as_the_path_set_does() {
    let mut n = Node::new(34);
    let account = n.account(t(1), &addr(5), 100, DATAGRAM);
    assert_eq!(
        account,
        Account {
            path: Some(0),
            sample: true,
            roam: Roam::Roamed {
                from: (t(1), addr(1))
            },
        }
    );
    let p = n.b.paths().get(0).unwrap();
    assert_eq!((p.addr(), p.state()), (&addr(5), PathState::Live));
    assert_eq!(n.b.paths().active_index(), Some(0));
    assert_eq!(
        p.live().frames(),
        1,
        "the frame counts on the path it moved"
    );
    // From the same address again, nothing moves.
    assert_eq!(n.account(t(1), &addr(5), 100, DATAGRAM).roam, Roam::Unmoved);
}

#[test]
fn a_path_message_never_roams_and_a_probe_from_a_new_address_on_one_path_adds_a_path() {
    // A path message from a new address on the original path's transport
    // moves nothing, of whichever kind.
    let mut n = Node::new(42);
    for m in [
        LinkMessageType::PathProbe,
        LinkMessageType::PathAck,
        LinkMessageType::PathClose,
    ] {
        let account = n.account(t(1), &addr(5), 100, m.to_byte());
        assert_eq!((account.path, account.roam), (None, Roam::Unmoved), "{m:?}");
    }
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(1));
    // The end of a link with one transport, whose peer probes its second
    // path from its second address: the probe adds a path beside the
    // original (draft Section 5.1, step 2, and its note).
    let mut n = Node::capable(42);
    let probe = probe_from(0xB, 7, 1200);
    let frame = probe.len + FRAME_OVERHEAD;
    let account = n.account(t(1), &addr(2), frame, LinkMessageType::PathProbe.to_byte());
    assert_eq!(account.roam, Roam::Unmoved);
    n.probe(t(1), addr(2), probe);
    let held: Vec<_> =
        n.b.paths()
            .paths()
            .iter()
            .map(|p| (p.addr().clone(), p.peer_id(), p.state()))
            .collect();
    assert_eq!(
        held,
        [
            (addr(1), None, PathState::Live),
            (addr(2), Some(0xB), PathState::Probing),
        ]
    );
    // The peer's data on its original path, then on its second, moves no
    // path either.
    for a in [addr(1), addr(2)] {
        assert_eq!(n.account(t(1), &a, 200, DATAGRAM).roam, Roam::Unmoved);
    }
    let held: Vec<_> =
        n.b.paths()
            .paths()
            .iter()
            .map(|p| p.addr().clone())
            .collect();
    assert_eq!(held, [addr(1), addr(2)]);
}

#[test]
fn no_frame_roams_the_one_path_left_once_the_original_is_gone() {
    let mut n = Node::capable(43);
    live_path(&mut n, t(2), addr(2), 0xB);
    n.step(Input::Removed { transport: t(1) });
    assert_eq!(n.b.paths().len(), 1);
    for ty in [HEARTBEAT, DATAGRAM, UNKNOWN] {
        let account = n.account(t(2), &addr(3), 100, ty);
        assert_eq!((account.path, account.roam), (None, Roam::Unmoved));
    }
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(2));
}

#[test]
fn a_probe_naming_another_path_counts_on_the_path_it_names() {
    let mut n = Node::capable(44);
    let probe = probe_from(0xA, 1, 27);
    let frame = probe.len + FRAME_OVERHEAD;
    let ty = LinkMessageType::PathProbe.to_byte();
    n.account(t(1), &addr(1), frame, ty);
    n.probe(t(1), addr(1), probe);
    let q = live_path(&mut n, t(1), addr(2), 0xB);
    n.account(t(1), &addr(2), 100, DATAGRAM);
    let counts = |n: &Node, i: usize| {
        let live = n.b.paths().get(i).unwrap().live();
        (live.frames(), live.bytes())
    };
    let (p0, q0) = (counts(&n, 0), counts(&n, q));
    // The peer's probe of Q arrives from P's pair: it concerns Q, and P's
    // address stays (draft Section 5.1, step 2).
    n.account(t(1), &addr(1), frame, ty);
    let out = n.probe(t(1), addr(1), probe_from(0xB, 9, 27));
    let [(to, ack)] = &sent_acks(&out)[..] else {
        panic!("one ack: {out:?}");
    };
    assert_eq!((to, ack.path_id), (&pair(t(1), addr(1)), n.id(q)));
    let q1 = (q0.0 + 1, q0.1 + frame as u32);
    assert_eq!(
        (ack.rx_frames, ack.rx_bytes),
        q1,
        "Q's counts, the probe's frame included"
    );
    assert_eq!(counts(&n, q), q1);
    assert_eq!(counts(&n, 0), p0, "P's counts without the probe's frame");
}

#[test]
fn a_matched_ack_counts_on_the_path_of_its_probe_whatever_pair_it_comes_from() {
    let mut n = Node::capable(45);
    let out = n.candidate(t(3), addr(3));
    let r_pair = pair(t(3), addr(3));
    let (_, probe) = probes(&out)
        .into_iter()
        .find(|(to, _)| *to == r_pair)
        .expect("a probe on the candidate");
    let r = n.b.paths().find(t(3), &addr(3)).unwrap();
    let before = n.b.paths().get(0).unwrap().live().frames();
    // The answer comes over the original path's pair.
    let ack = ack_for(&probe, 0xC);
    let frame = ack.len + FRAME_OVERHEAD;
    n.account(t(1), &addr(1), frame, LinkMessageType::PathAck.to_byte());
    n.ack(t(1), addr(1), ack);
    let live = n.b.paths().get(r).unwrap().live();
    assert_eq!(n.b.paths().get(r).unwrap().state(), PathState::Live);
    assert_eq!((live.frames(), live.bytes()), (1, frame as u32));
    assert_eq!(n.b.paths().get(0).unwrap().live().frames(), before);
}

#[test]
fn with_two_paths_no_frame_moves_an_address() {
    let mut n = Node::capable(35);
    live_path(&mut n, t(2), addr(2), 0xB);
    for (transport, a) in [(t(1), addr(7)), (t(2), addr(8))] {
        for ty in [HEARTBEAT, DATAGRAM, UNKNOWN] {
            let account = n.account(transport, &a, 100, ty);
            assert_eq!((account.path, account.roam), (None, Roam::Unmoved));
        }
    }
    let held: Vec<_> =
        n.b.paths()
            .paths()
            .iter()
            .map(|p| (p.transport_id(), p.addr().clone()))
            .collect();
    assert_eq!(held, [(t(1), addr(1)), (t(2), addr(2))]);
}

#[test]
fn receiving_on_a_path_never_changes_the_active_path() {
    let mut n = Node::capable(36);
    let q = live_path(&mut n, t(2), addr(2), 0xB);
    assert_eq!(n.b.paths().get(q).unwrap().state(), PathState::Live);
    for ty in [
        HEARTBEAT,
        DATAGRAM,
        UNKNOWN,
        LinkMessageType::TreeAnnounce.to_byte(),
    ] {
        n.account(t(2), &addr(2), 100, ty);
        assert_eq!(n.b.paths().active_index(), Some(0));
    }
}

#[test]
fn the_peers_active_path_follows_its_last_message_that_is_not_a_datagram_or_path_message() {
    let mut n = Node::capable(37);
    live_path(&mut n, t(2), addr(2), 0xB);
    let p = (t(1), addr(1));
    let q = (t(2), addr(2));
    // Whether a datagram on `on` is sampled, which it is only on the
    // peer's active path.
    let on = |n: &mut Node, (transport, a): &(_, _)| n.account(*transport, a, 80, DATAGRAM).sample;
    assert!(!on(&mut n, &p) && !on(&mut n, &q), "no active path yet");
    // Every link message that is not a datagram or path message marks the
    // path it arrives on, a type this node does not know included.
    let marking = [
        LinkMessageType::SenderReport,
        LinkMessageType::ReceiverReport,
        LinkMessageType::TreeAnnounce,
        LinkMessageType::FilterAnnounce,
        LinkMessageType::LookupRequest,
        LinkMessageType::LookupResponse,
        LinkMessageType::Disconnect,
        LinkMessageType::Heartbeat,
    ];
    let mut types: Vec<u8> = marking.iter().map(|m| m.to_byte()).collect();
    types.push(UNKNOWN);
    for (k, ty) in types.into_iter().enumerate() {
        let (to, other) = if k % 2 == 0 { (&p, &q) } else { (&q, &p) };
        n.account(to.0, &to.1, 100, ty);
        assert!(on(&mut n, to), "type {ty:#04x} marks its path");
        assert!(!on(&mut n, other), "type {ty:#04x} unmarks the other");
    }
    // The active path is P now. Datagrams and path messages on Q leave it.
    let quiet = [
        LinkMessageType::SessionDatagram,
        LinkMessageType::PathProbe,
        LinkMessageType::PathAck,
        LinkMessageType::PathClose,
    ];
    for m in quiet {
        n.account(q.0, &q.1, 100, m.to_byte());
        assert!(on(&mut n, &p), "{m:?} leaves the peer's active path");
        assert!(!on(&mut n, &q));
    }
    // A marking frame from no path leaves the peer with no active path.
    n.account(t(1), &addr(9), 100, HEARTBEAT);
    assert!(!on(&mut n, &p) && !on(&mut n, &q));
}

#[test]
fn a_frame_is_sampled_always_on_one_path_and_otherwise_only_on_the_peers_active_path() {
    let mut n = Node::new(38);
    for ty in [DATAGRAM, HEARTBEAT, UNKNOWN] {
        assert!(n.account(t(1), &addr(1), 100, ty).sample);
    }
    assert!(
        n.account(t(2), &addr(3), 100, DATAGRAM).sample,
        "on a link of one path every frame qualifies"
    );
    let mut n = Node::capable(38);
    live_path(&mut n, t(2), addr(2), 0xB);
    assert!(!n.account(t(1), &addr(1), 100, DATAGRAM).sample);
    assert!(n.account(t(1), &addr(1), 100, HEARTBEAT).sample);
    assert!(n.account(t(1), &addr(1), 100, DATAGRAM).sample);
    assert!(!n.account(t(2), &addr(2), 100, DATAGRAM).sample);
    assert!(!n.account(t(3), &addr(3), 100, DATAGRAM).sample);
}

#[test]
fn account_and_charge_allocate_nothing() {
    let mut n = Node::capable(39);
    live_path(&mut n, t(2), addr(2), 0xB);
    let mut one = Node::new(39);
    let (a1, a2, a5, a9) = (addr(1), addr(2), addr(5), addr(9));
    let mut charges = Vec::with_capacity(100);
    let before = allocations();
    for k in 0..100u64 {
        n.now = TestInstant(k);
        n.b.account(n.now, t(1), &a1, 100, HEARTBEAT);
        n.b.account(n.now, t(2), &a2, 100, DATAGRAM);
        n.b.account(n.now, t(1), &a9, 100, DATAGRAM);
        // On a link of one path, each frame roams the path.
        let to = if k % 2 == 0 { &a5 } else { &a1 };
        one.b.account(n.now, t(1), to, 100, DATAGRAM);
    }
    // Failures past the limit on both paths, which trips each, on no path,
    // and on a link of one path, which warns.
    for _ in 0..25 {
        charges.push(n.b.charge(n.now, t(1), &a1));
        charges.push(n.b.charge(n.now, t(2), &a2));
        charges.push(n.b.charge(n.now, t(1), &a9));
        charges.push(one.b.charge(n.now, t(1), &a1));
    }
    assert_eq!(allocations(), before, "account or charge allocated");
    for c in [
        Charge::Nothing,
        Charge::Counted,
        Charge::Warn,
        Charge::Tripped,
    ] {
        assert!(charges.contains(&c), "{c:?} was reached");
    }
    assert_eq!(one.b.paths().get(0).unwrap().addr(), &a1, "the path roamed");
    // The counter sees an allocation when one happens.
    let v = core::hint::black_box(Vec::<u8>::with_capacity(1));
    assert!(allocations() > before, "the counter missed an allocation");
    drop(v);
}

#[test]
fn closing_keeps_only_the_peers_active_path_open() {
    let mut n = Node::capable(40);
    live_path(&mut n, t(2), addr(2), 0xB);
    n.candidate(t(3), addr(3));
    n.account(t(2), &addr(2), 100, HEARTBEAT);
    assert_eq!(
        keeps(&n.close()),
        [
            (pair(t(1), addr(1)), false),
            (pair(t(2), addr(2)), true),
            (pair(t(3), addr(3)), false),
        ]
    );
    // With no frame from the peer, nothing is kept.
    let mut n = Node::capable(40);
    live_path(&mut n, t(2), addr(2), 0xB);
    assert!(keeps(&n.close()).iter().all(|(_, keep)| !keep));
}

#[test]
fn a_path_evicted_while_the_peer_still_sends_on_it_is_kept_open() {
    let mut n = Node::capable(41);
    n.probe(t(1), addr(2), probe_from(0x12, 1, 27));
    n.probe(t(1), addr(3), probe_from(0x13, 1, 27));
    let i = live_path(&mut n, t(1), addr(4), 0x14);
    n.account(t(1), &addr(4), 100, HEARTBEAT);
    n.closed(t(1), addr(4), close_from(n.id(i)));
    let out = n.probe(t(1), addr(5), probe_from(0x15, 1, 27));
    assert_eq!(keeps(&out), [(pair(t(1), addr(4)), true)]);
}

/// A one-path link with multipath disabled roams its path on the frame of a
/// path message from a new address, as it does on any other frame.
#[test]
fn a_disabled_one_path_link_roams_on_a_path_messages_frame() {
    let mut n = Node::disabled(42);
    let probe = LinkMessageType::PathProbe.to_byte();
    assert_eq!(
        n.account(t(1), &addr(9), 100, probe).roam,
        Roam::Roamed {
            from: (t(1), addr(1))
        },
        "a node with multipath disabled follows the peer's address on every frame"
    );
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(9));
    assert_eq!(n.b.paths().len(), 1);
}

/// A one-path link with multipath enabled does not roam on the frame of a path
/// message from a new address, and still roams on any other frame.
#[test]
fn an_enabled_one_path_link_does_not_roam_on_a_path_messages_frame() {
    let mut n = Node::new(43);
    let probe = LinkMessageType::PathProbe.to_byte();
    assert_eq!(n.account(t(1), &addr(9), 100, probe).roam, Roam::Unmoved);
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(1));
    // A frame that is not a path message still roams it.
    assert_eq!(
        n.account(t(1), &addr(9), 100, HEARTBEAT).roam,
        Roam::Roamed {
            from: (t(1), addr(1))
        }
    );
}

/// A slot written through `driver_mut` is the one `close` hands back for that
/// path, and `driver_mut` finds no path past the last.
#[test]
fn a_slot_set_through_driver_mut_comes_back_from_close() {
    let mut n = Node::capable(44);
    let q = live_path(&mut n, t(2), addr(2), 0xB);
    *n.b.driver_mut(0).expect("the original path's slot") = Slot::default();
    let on_p = n.b.paths().get(0).unwrap().driver().serial;
    let on_q = n.b.driver_mut(q).expect("q's slot").serial;
    assert_ne!(on_p, on_q);
    assert!(n.b.driver_mut(2).is_none(), "no third path");
    let out = n.close();
    let serials: Vec<(PathRef, u64)> = out
        .iter()
        .filter_map(|o| {
            let Output::Released { to, driver, .. } = o else {
                return None;
            };
            Some((to.clone(), *driver))
        })
        .collect();
    assert_eq!(
        serials,
        [(pair(t(1), addr(1)), on_p), (pair(t(2), addr(2)), on_q)]
    );
}

/// Every path of a link whose peer is not known to be capable is kept open at
/// the close and at a discard, enabled or disabled, while a capable link's
/// paths close unless the peer sends on them.
#[test]
fn a_link_whose_peer_is_not_capable_keeps_every_path_open() {
    // Before any frame of the peer, a link whose peer is not known to be
    // capable keeps every connection, enabled or disabled.
    for n in [Node::new(45), Node::disabled(45)] {
        assert_eq!(keeps(&n.close()), [(pair(t(1), addr(1)), true)]);
    }
    // A discard on such a link keeps the connection too.
    let mut n = Node::new(46);
    assert_eq!(keeps(&step(&mut n, 10, gone(1))), [(p(), true)]);
    // A capable link's paths close unless the peer sends on them.
    let mut n = Node::capable(47);
    live_path(&mut n, t(2), addr(2), 0xB);
    assert_eq!(
        keeps(&n.close()),
        [(pair(t(1), addr(1)), false), (pair(t(2), addr(2)), false)]
    );
}
