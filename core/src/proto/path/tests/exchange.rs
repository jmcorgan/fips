//! The probe exchange that proves a path (multipath v1 draft, Section 5.1):
//! the bundle's original path, candidates, the receiver's lookup and
//! answer, ack matching, the proven MTU, `PathClose` and the address moves
//! path messages allow. Every test drives a `Bundle` through its inputs in
//! the shell.

use alloc::format;
use alloc::vec::Vec;

use super::shell::*;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::path::wire::{PATH_PROBE_MIN_SIZE, PathAck};
use crate::proto::path::{Output, PathState, Refusal, Why};
use crate::testutil::{FixedEntropy, TestInstant};
use crate::time::Duration;

/// The only ack in `out`.
fn one_ack(out: &[Out]) -> (crate::proto::path::PathRef, PathAck) {
    let sent = sent_acks(out);
    assert_eq!(sent.len(), 1, "one ack: {out:?}");
    sent[0].clone()
}

#[test]
fn a_bundle_starts_with_its_original_path_live_acked_active_and_the_peer_not_capable() {
    let n = Node::new(1);
    let set = n.b.paths();
    assert_eq!(set.len(), 1);
    let p = set.get(0).unwrap();
    assert_eq!((p.transport_id(), p.addr()), (t(1), &addr(1)));
    assert_eq!(p.state(), PathState::Live);
    assert!(p.acked(), "the original path is acked from the handshake");
    assert_eq!(set.active_index(), Some(0));
    assert_eq!(p.peer_id(), None);
    assert!(!n.b.capable());
}

#[test]
fn path_ids_come_from_the_hosts_entropy_source() {
    let n = Node::<FixedEntropy<0x11>>::make(0);
    assert_eq!(n.id(0), 0x1111_1111);
}

#[test]
fn a_candidate_of_a_peer_not_known_to_be_capable_admits_nothing_and_sends_only_a_capability_probe()
{
    let mut n = Node::new(3);
    let out = n.candidate(t(2), addr(2));
    assert!(states(&out).is_empty(), "{out:?}");
    let [Output::Send { to, .. }] = &out[..] else {
        panic!("one send: {out:?}");
    };
    assert_eq!(to, &pair(t(1), addr(1)), "on the original path");
    assert_eq!(probe_on(&out, to).len, PATH_PROBE_MIN_SIZE);
    assert_eq!(n.b.paths().len(), 1);
    assert!(!n.b.capable());
}

#[test]
fn any_authenticated_path_message_makes_the_peer_capable() {
    let inputs = [
        crate::proto::path::Input::Probe {
            transport: t(1),
            addr: addr(1),
            msg: probe_from(0xA, 1, 27),
        },
        crate::proto::path::Input::Ack {
            transport: t(1),
            addr: addr(1),
            msg: ack_for(&probe_from(0x5A5A_5A5A, 9, 27), 0xA),
        },
        crate::proto::path::Input::Close {
            transport: t(1),
            addr: addr(1),
            msg: close_from(0x5A5A_5A5A),
        },
    ];
    for input in inputs {
        let mut n = Node::new(4);
        assert_ne!(n.id(0), 0x5A5A_5A5A);
        let out = n.step(input.clone());
        assert!(n.b.capable(), "{input:?} makes the peer capable");
        assert!(
            matches!(out.first(), Some(Output::Capable)),
            "Capable comes first: {out:?}"
        );
        let capable = out.iter().filter(|o| matches!(o, Output::Capable));
        assert_eq!(capable.count(), 1);
        let again = n.step(input);
        assert!(
            !again.iter().any(|o| matches!(o, Output::Capable)),
            "Capable comes once: {again:?}"
        );
    }
}

#[test]
fn a_candidate_is_admitted_probing_and_probed_at_once_padded_to_the_link_mtu() {
    let mut n = Node::capable(5).with(Stub::default().mtu(t(2), 1400));
    let out = n.candidate(t(2), addr(2));
    let set = n.b.paths();
    assert_eq!(set.len(), 2);
    let p = set.get(1).unwrap();
    assert_eq!(p.state(), PathState::Probing);
    assert!(!p.acked());
    assert_eq!(
        states(&out),
        [(
            pair(t(2), addr(2)),
            p.path_id(),
            None,
            Some(PathState::Probing),
            Why::Candidate
        )]
    );
    let probe = probe_on(&out, &pair(t(2), addr(2)));
    assert_eq!(probe.len, 1400 - FRAME_OVERHEAD);
    assert_eq!(probe.path_id, p.path_id());
    assert!(!probe.flags.active());
    assert_eq!(p.live().outstanding(), 1);
    // A candidate for a pair already held changes nothing.
    assert!(n.candidate(t(2), addr(2)).is_empty());
}

/// The first `probe_id` of a candidate's path on a node seeded with `seed`.
fn first_probe(seed: u64) -> u32 {
    let mut n = Node::capable(seed);
    let out = n.candidate(t(2), addr(2));
    probe_on(&out, &pair(t(2), addr(2))).probe_id
}

#[test]
fn the_first_probe_id_is_random_and_each_probe_adds_one() {
    let (a, b) = (first_probe(1), first_probe(2));
    assert_ne!(a, b, "two seeds give two starts");
    assert_ne!(a, 0);
    assert_ne!(b, 0);
    // The path's next probe: answered, closed by the peer, then revived by
    // the peer's probe, which we answer with our own.
    let mut n = Node::capable(1);
    let i = live_path(&mut n, t(2), addr(2), 0xB);
    n.closed(t(2), addr(2), close_from(n.id(i)));
    let out = n.probe(t(2), addr(2), probe_from(0xB, 1, 27));
    let next = probe_on(&out, &pair(t(2), addr(2)));
    assert_eq!(next.probe_id, a.wrapping_add(1));
}

#[test]
fn the_probe_id_wraps_from_its_largest_value_to_zero() {
    // The path ids of the original and the candidate, then the first
    // probe_id of each: the original is probed first, now that the link
    // has two paths.
    script(&[0x1111_1111, 0x2222_2222, 0x3333_3333, u32::MAX]);
    let mut n = Node::<Scripted>::make(7);
    n.heard();
    let out = n.candidate(t(2), addr(2));
    assert_eq!(probe_on(&out, &pair(t(1), addr(1))).probe_id, 0x3333_3333);
    let first = probe_on(&out, &pair(t(2), addr(2)));
    assert_eq!(n.id(0), 0x1111_1111);
    assert_eq!(first.path_id, 0x2222_2222);
    assert_eq!(first.probe_id, u32::MAX);
    n.ack(t(2), addr(2), ack_for(&first, 0xB));
    n.closed(t(2), addr(2), close_from(0x2222_2222));
    let out = n.probe(t(2), addr(2), probe_from(0xB, 1, 27));
    assert_eq!(probe_on(&out, &pair(t(2), addr(2))).probe_id, 0);
}

#[test]
fn an_ack_is_matched_on_its_echoed_path_id_and_probe_id_on_any_transport() {
    let mut n = Node::capable(8);
    let probe = probe_on(&n.candidate(t(2), addr(2)), &pair(t(2), addr(2)));
    // The right path, another probe.
    let wrong_probe = PathAck {
        probe_id: probe.probe_id.wrapping_add(1),
        ..ack_for(&probe, 0xB)
    };
    let out = n.ack(t(1), addr(1), wrong_probe);
    assert_eq!(refusals(&out), [(pair(t(1), addr(1)), Refusal::Unmatched)]);
    // The right probe, another path.
    let wrong_path = PathAck {
        echo_path_id: n.id(0),
        ..ack_for(&probe, 0xB)
    };
    let out = n.ack(t(1), addr(1), wrong_path);
    assert_eq!(refusals(&out), [(pair(t(1), addr(1)), Refusal::Unmatched)]);
    assert_eq!(n.b.paths().get(1).unwrap().state(), PathState::Probing);
    // Both right, arriving on the original path's transport.
    let out = n.ack(t(1), addr(1), ack_for(&probe, 0xB));
    assert!(refusals(&out).is_empty());
    let p = n.b.paths().get(1).unwrap();
    assert_eq!(p.state(), PathState::Live);
    assert!(p.acked());
    assert_eq!(
        p.addr(),
        &addr(2),
        "an ack on another transport moves nothing"
    );
    assert_eq!(
        states(&out),
        [(
            pair(t(2), addr(2)),
            p.path_id(),
            Some(PathState::Probing),
            Some(PathState::Live),
            Why::Answered
        )]
    );
    // The same answer again matches nothing.
    let out = n.ack(t(2), addr(2), ack_for(&probe, 0xB));
    assert_eq!(refusals(&out), [(pair(t(2), addr(2)), Refusal::Unmatched)]);
}

#[test]
fn the_peers_path_id_is_learned_only_from_a_matching_ack() {
    let mut n = Node::capable(9);
    let probe = probe_on(&n.candidate(t(2), addr(2)), &pair(t(2), addr(2)));
    let unmatched = PathAck {
        probe_id: probe.probe_id.wrapping_sub(1),
        ..ack_for(&probe, 0xAAAA)
    };
    n.ack(t(2), addr(2), unmatched);
    assert_eq!(n.b.paths().get(1).unwrap().peer_id(), None);
    n.ack(t(2), addr(2), ack_for(&probe, 0xBBBB));
    assert_eq!(n.b.paths().get(1).unwrap().peer_id(), Some(0xBBBB));
}

#[test]
fn a_matching_answer_makes_a_probing_path_live_with_its_round_trip_and_proven_mtu() {
    let mut n = Node::capable(10).with(Stub::default().mtu(t(2), 1400));
    let probe = probe_on(&n.candidate(t(2), addr(2)), &pair(t(2), addr(2)));
    assert_eq!(probe.len, 1400 - FRAME_OVERHEAD);
    n.now = TestInstant(120);
    let shorter = PathAck {
        len: 600,
        ..ack_for(&probe, 0xB)
    };
    let out = n.ack(t(2), addr(2), shorter);
    let p = n.b.paths().get(1).unwrap();
    assert_eq!(p.state(), PathState::Live);
    assert!(p.acked());
    assert_eq!(p.live().rtt(), Some(Duration::from_millis(120)));
    assert_eq!(p.live().min_rtt(), Some(Duration::from_millis(120)));
    assert_eq!(p.live().samples(), 1);
    assert_eq!(p.live().mtu(), Some(600), "the smaller of probe and answer");
    assert_eq!(p.live().outstanding(), 0);
    assert_eq!(states(&out).len(), 1);
}

#[test]
fn an_ack_is_padded_to_the_smaller_of_the_probe_and_the_link_mtu() {
    let facts = Stub::default().mtu(t(1), 1000).mtu(t(2), 1280);
    let mut n = Node::capable(11).with(facts);
    let cases = [
        (t(1), addr(1), 0xA, 1200, 964),
        (t(2), addr(2), 0xB, 500, 500),
        (t(1), addr(1), 0xA, 27, 27),
    ];
    for (k, (tr, a, peer, len, want)) in cases.into_iter().enumerate() {
        let out = n.probe(tr, a.clone(), probe_from(peer, k as u32, len));
        let (to, ack) = one_ack(&out);
        assert_eq!(to, pair(tr, a));
        assert_eq!(ack.len, want, "a {len}-byte probe");
        assert!(!ack.flags.ext());
        let raw = out.iter().find_map(|o| {
            let Output::Send { bytes, .. } = o else {
                return None;
            };
            (bytes[0] == 0x53).then_some(bytes.len())
        });
        assert_eq!(raw, Some(want));
    }
}

#[test]
fn a_probe_shorter_than_27_bytes_is_never_answered() {
    let mut n = Node::new(12);
    let out = n.probe(t(1), addr(1), probe_from(0xA, 1, 26));
    assert!(n.b.capable(), "the peer is capable all the same");
    assert!(sent_acks(&out).is_empty());
    assert!(probes(&out).is_empty());
    assert_eq!(refusals(&out), [(pair(t(1), addr(1)), Refusal::Short)]);
    assert_eq!(n.b.paths().get(0).unwrap().peer_id(), None);
}

#[test]
fn a_probe_finds_its_path_by_the_peers_id_then_by_pair_then_creates_one() {
    let mut n = Node::capable(13);
    let orig = n.id(0);
    // By pair: the original path learns the peer's identifier.
    let (to, ack) = one_ack(&n.probe(t(1), addr(1), probe_from(0xA, 1, 27)));
    assert_eq!(
        (to, ack.path_id, ack.echo_path_id),
        (pair(t(1), addr(1)), orig, 0xA)
    );
    assert_eq!(n.b.paths().get(0).unwrap().peer_id(), Some(0xA));
    // Neither: a new Probing path on the arrival transport.
    let out = n.probe(t(1), addr(2), probe_from(0xB, 1, 27));
    assert_eq!(n.b.paths().len(), 2);
    let p = n.b.paths().get(1).unwrap();
    assert_eq!((p.transport_id(), p.addr()), (t(1), &addr(2)));
    assert_eq!(p.peer_id(), Some(0xB));
    assert_eq!(p.state(), PathState::Probing);
    assert_eq!(one_ack(&out).1.path_id, p.path_id());
    assert_eq!(
        states(&out),
        [(
            pair(t(1), addr(2)),
            p.path_id(),
            None,
            Some(PathState::Probing),
            Why::Probed
        )]
    );
    // By the peer's identifier first: 0xA names the original path, though
    // the pair is the second path's. The original stays where it is, since
    // the pair is held, and the answer goes to the pair the probe came from.
    let out = n.probe(t(1), addr(2), probe_from(0xA, 2, 27));
    let (to, ack) = one_ack(&out);
    assert_eq!((to, ack.path_id), (pair(t(1), addr(2)), orig));
    assert!(moved(&out).is_empty());
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(1));
    assert_eq!(n.b.paths().get(1).unwrap().peer_id(), Some(0xB));
    // By pair, an identifier not known replaces the one the path held.
    let (_, ack) = one_ack(&n.probe(t(1), addr(2), probe_from(0xC, 3, 27)));
    assert_eq!(ack.path_id, n.id(1));
    assert_eq!(n.b.paths().get(1).unwrap().peer_id(), Some(0xC));
    assert_eq!(n.b.paths().len(), 2);
}

#[test]
fn a_path_created_by_a_received_probe_stays_probing_until_its_own_probe_is_answered() {
    let mut n = Node::capable(14);
    let out = n.probe(t(2), addr(2), probe_from(0xB, 1, 27));
    let ours = probe_on(&out, &pair(t(2), addr(2)));
    let p = n.b.paths().get(1).unwrap();
    assert_eq!(p.state(), PathState::Probing);
    assert!(!p.acked());
    // The peer probing it again proves nothing in our direction.
    let out = n.probe(t(2), addr(2), probe_from(0xB, 2, 27));
    assert!(probes(&out).is_empty(), "our probe is already out");
    let p = n.b.paths().get(1).unwrap();
    assert_eq!(p.state(), PathState::Probing);
    assert!(!p.acked());
    assert_eq!(n.b.paths().active_index(), Some(0));
    n.ack(t(2), addr(2), ack_for(&ours, 0xB));
    let p = n.b.paths().get(1).unwrap();
    assert_eq!(p.state(), PathState::Live);
    assert!(p.acked());
}

#[test]
fn a_probe_beyond_the_path_limits_creates_no_path_and_gets_no_answer() {
    let mut n = Node::capable(15);
    for k in 2..=4u8 {
        n.probe(t(1), addr(k), probe_from(0x10 + u32::from(k), 1, 27));
    }
    assert_eq!(n.b.paths().len(), 4);
    let out = n.probe(t(1), addr(5), probe_from(0x15, 1, 27));
    assert!(sent_acks(&out).is_empty(), "{out:?}");
    assert!(probes(&out).is_empty());
    assert_eq!(refusals(&out), [(pair(t(1), addr(5)), Refusal::Full)]);
    assert_eq!(n.b.paths().len(), 4);
    assert_eq!(n.b.paths().find(t(1), &addr(5)), None);
}

#[test]
fn an_ack_carries_the_microseconds_since_the_bundle_began() {
    let mut n = Node::capable(16);
    n.now = TestInstant(1_234);
    let (_, ack) = one_ack(&n.probe(t(1), addr(1), probe_from(0xA, 1, 27)));
    assert_eq!(ack.rx_time_us, 1_234_000);
    // Modulo 2^32: 5000 s is 5,000,000,000 us.
    n.now = TestInstant(5_000_000);
    let (_, ack) = one_ack(&n.probe(t(1), addr(1), probe_from(0xA, 2, 27)));
    assert_eq!(ack.rx_time_us, (5_000_000_000u64 % (1 << 32)) as u32);
}

#[test]
fn path_messages_on_our_active_path_carry_active_and_no_others_do() {
    let mut n = Node::capable(17);
    let (_, ack) = one_ack(&n.probe(t(1), addr(1), probe_from(0xA, 1, 27)));
    assert!(ack.flags.active(), "the original path is our active path");
    let out = n.probe(t(2), addr(2), probe_from(0xB, 1, 27));
    assert!(!one_ack(&out).1.flags.active());
    assert!(!probe_on(&out, &pair(t(2), addr(2))).flags.active());
    assert!(probe_on(&out, &pair(t(1), addr(1))).flags.active());
    // Our active path closed by the peer and revived by its probe: our
    // probe on it carries ACTIVE too.
    let orig = n.id(0);
    n.closed(t(1), addr(1), close_from(orig));
    assert_eq!(n.b.paths().active_index(), Some(0));
    let out = n.probe(t(1), addr(1), probe_from(0xA, 2, 27));
    assert!(one_ack(&out).1.flags.active());
    assert!(probe_on(&out, &pair(t(1), addr(1))).flags.active());
}

#[test]
fn aggregation_is_never_offered() {
    let mut n = Node::capable(18);
    let mut out = n.probe(t(1), addr(1), probe_from(0xA, 1, 27));
    out.extend(n.candidate(t(2), addr(2)));
    out.extend(n.probe(t(3), addr(3), probe_from(0xC, 1, 27)));
    let sent = probes(&out);
    let answered = sent_acks(&out);
    // The candidate starts the original path's probes too.
    assert_eq!((sent.len(), answered.len()), (3, 2));
    assert!(sent.iter().all(|(_, p)| !p.caps.aggregate()));
    assert!(answered.iter().all(|(_, a)| !a.caps.aggregate()));
}

#[test]
fn an_answers_receive_counts_change_nothing_at_the_prober() {
    let run = |rx_frames: u32, rx_bytes: u32| {
        let mut n = Node::capable(19);
        let probe = probe_on(&n.candidate(t(2), addr(2)), &pair(t(2), addr(2)));
        n.now = TestInstant(50);
        let ack = PathAck {
            rx_frames,
            rx_bytes,
            ..ack_for(&probe, 0xB)
        };
        let out = n.ack(t(2), addr(2), ack);
        (format!("{:?}", n.b), format!("{out:?}"))
    };
    let quiet = run(0, 0);
    assert_eq!(quiet, run(1_000, 99_999));
    assert_eq!(quiet, run(u32::MAX, u32::MAX));
}

#[test]
fn a_path_close_names_our_id_and_marks_a_live_path_dead() {
    let mut n = Node::capable(20);
    let i = live_path(&mut n, t(2), addr(2), 0xB);
    let ours = n.id(i);
    assert_ne!(ours, 0xB);
    // The peer's own identifier for the path names nothing of ours.
    let out = n.closed(t(2), addr(2), close_from(0xB));
    assert_eq!(refusals(&out), [(pair(t(2), addr(2)), Refusal::Unknown)]);
    assert_eq!(n.b.paths().get(i).unwrap().state(), PathState::Live);
    n.now = TestInstant(300);
    let out = n.closed(t(2), addr(2), close_from(ours));
    let p = n.b.paths().get(i).unwrap();
    assert_eq!(p.state(), PathState::Dead);
    assert_eq!(p.dead_since(), Some(TestInstant(300)));
    assert_eq!(
        states(&out),
        [(
            pair(t(2), addr(2)),
            ours,
            Some(PathState::Live),
            Some(PathState::Dead),
            Why::Closed
        )]
    );
    // A close of a Dead or a Probing path changes nothing.
    assert!(states(&n.closed(t(2), addr(2), close_from(ours))).is_empty());
    n.candidate(t(3), addr(3));
    let probing = n.id(2);
    assert!(states(&n.closed(t(3), addr(3), close_from(probing))).is_empty());
    assert_eq!(n.b.paths().get(2).unwrap().state(), PathState::Probing);
}

#[test]
fn a_path_close_naming_an_id_we_do_not_hold_changes_nothing() {
    let mut n = Node::capable(21);
    live_path(&mut n, t(2), addr(2), 0xB);
    let unknown = 0x5A5A_5A5A;
    assert!(n.b.paths().paths().iter().all(|p| p.path_id() != unknown));
    let before = format!("{:?}", n.b);
    let out = n.closed(t(1), addr(1), close_from(unknown));
    assert_eq!(refusals(&out), [(pair(t(1), addr(1)), Refusal::Unknown)]);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(format!("{:?}", n.b), before);
}

#[test]
fn an_accepted_probe_brings_a_dead_path_back_to_probing_and_probes_it() {
    let mut n = Node::capable(22);
    let i = live_path(&mut n, t(2), addr(2), 0xB);
    let ours = n.id(i);
    n.closed(t(2), addr(2), close_from(ours));
    n.now = TestInstant(1_000);
    let out = n.probe(t(2), addr(2), probe_from(0xB, 9, 27));
    let p = n.b.paths().get(i).unwrap();
    assert_eq!(p.state(), PathState::Probing);
    assert_eq!(p.dead_since(), None);
    assert_eq!(
        states(&out),
        [(
            pair(t(2), addr(2)),
            ours,
            Some(PathState::Dead),
            Some(PathState::Probing),
            Why::Probed
        )]
    );
    assert_eq!(one_ack(&out).0, pair(t(2), addr(2)));
    let probe = probe_on(&out, &pair(t(2), addr(2)));
    assert_eq!(
        probe.len,
        1280 - FRAME_OVERHEAD,
        "padded: the path is unproven"
    );
}

#[test]
fn with_two_paths_a_probe_from_a_new_address_moves_its_path_and_hands_back_its_slot() {
    let mut n = Node::capable(23);
    n.probe(t(1), addr(2), probe_from(0xB, 1, 27));
    let old = n.b.paths().get(1).unwrap().driver().serial;
    let out = n.probe(t(1), addr(3), probe_from(0xB, 2, 27));
    assert_eq!(
        moved(&out),
        [(pair(t(1), addr(2)), pair(t(1), addr(3)), old)]
    );
    let p = n.b.paths().get(1).unwrap();
    assert_eq!(p.addr(), &addr(3));
    assert_ne!(p.driver().serial, old, "the path holds a fresh slot");
    let (to, ack) = one_ack(&out);
    assert_eq!((to, ack.path_id), (pair(t(1), addr(3)), n.id(1)));
    assert_eq!(n.b.paths().len(), 2);
}

#[test]
fn a_matching_ack_from_a_new_address_on_its_own_transport_moves_the_path() {
    let mut n = Node::capable(24);
    let probe = probe_on(&n.candidate(t(2), addr(2)), &pair(t(2), addr(2)));
    let old = n.b.paths().get(1).unwrap().driver().serial;
    let out = n.ack(t(2), addr(5), ack_for(&probe, 0xB));
    assert_eq!(
        moved(&out),
        [(pair(t(2), addr(2)), pair(t(2), addr(5)), old)]
    );
    let p = n.b.paths().get(1).unwrap();
    assert_eq!((p.addr(), p.state()), (&addr(5), PathState::Live));
    // On another transport the ack matches and moves nothing.
    let probe = probe_on(&n.candidate(t(3), addr(6)), &pair(t(3), addr(6)));
    let out = n.ack(t(1), addr(7), ack_for(&probe, 0xC));
    assert!(moved(&out).is_empty());
    let p = n.b.paths().get(2).unwrap();
    assert_eq!((p.addr(), p.state()), (&addr(6), PathState::Live));
}

#[test]
fn a_probe_naming_the_lone_original_path_from_a_new_address_moves_nothing_and_is_answered_there() {
    let mut n = Node::capable(27);
    // The peer names the original path 0xA from its address on it.
    n.probe(t(1), addr(1), probe_from(0xA, 1, 27));
    assert_eq!(path(&n, &p()).peer_id(), Some(0xA));
    assert_eq!(n.b.paths().len(), 1, "the original is the link's only path");
    // Then the same identifier from a new address on the same transport.
    let out = n.probe(t(1), addr(9), probe_from(0xA, 2, 27));
    assert!(
        moved(&out).is_empty(),
        "a path message moved the lone original: {out:?}"
    );
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(1));
    let (to, ack) = one_ack(&out);
    assert_eq!(
        (to, ack.path_id),
        (pair(t(1), addr(9)), n.id(0)),
        "answered where the probe came from"
    );
}

#[test]
fn an_ack_on_the_lone_suspect_original_path_from_a_new_address_counts_and_moves_nothing() {
    let mut n = Node::capable(28);
    // Carrier loss makes the lone original Suspect, which is then probed.
    let out = step(&mut n, 100, down(1));
    assert_eq!(state(&n, &p()), PathState::Suspect);
    let probe = probe_on(&out, &p());
    assert_eq!(n.b.paths().len(), 1);
    n.now = TestInstant(150);
    let out = n.ack(t(1), addr(9), ack_for(&probe, 0xA));
    assert!(
        moved(&out).is_empty(),
        "a path message moved the lone original: {out:?}"
    );
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(1));
    assert_eq!(state(&n, &p()), PathState::Live, "the answer still counts");
}

#[test]
fn a_probe_naming_the_original_path_after_the_second_path_is_discarded_moves_nothing() {
    let mut n = two(29);
    // The peer names the original path 0xA from its address on it.
    n.probe(t(1), addr(1), probe_from(0xA, 1, 27));
    assert_eq!(path(&n, &p()).peer_id(), Some(0xA));
    // The second path goes with its transport.
    step(&mut n, 10, gone(2));
    assert_eq!(n.b.paths().len(), 1, "the original is again the only path");
    let out = n.probe(t(1), addr(9), probe_from(0xA, 2, 27));
    assert!(
        moved(&out).is_empty(),
        "a path message moved the lone original: {out:?}"
    );
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(1));
    assert_eq!(one_ack(&out).0, pair(t(1), addr(9)));
}

#[test]
fn a_probe_from_a_new_address_moves_the_links_only_path_when_it_is_not_the_original() {
    let mut n = two(30);
    assert_eq!(path(&n, &q()).peer_id(), Some(peer(&q())));
    // The original path goes with its transport.
    step(&mut n, 10, gone(1));
    assert_eq!(n.b.paths().len(), 1, "the second path is the only path");
    let old = path(&n, &q()).driver().serial;
    let out = n.probe(t(2), addr(5), probe_from(peer(&q()), 1, 27));
    assert_eq!(moved(&out), [(q(), pair(t(2), addr(5)), old)]);
    assert_eq!(n.b.paths().get(0).unwrap().addr(), &addr(5));
}

#[test]
fn a_dead_path_evicted_for_a_probed_path_is_released() {
    let mut n = Node::capable(25);
    n.probe(t(1), addr(2), probe_from(0x12, 1, 27));
    n.probe(t(1), addr(3), probe_from(0x13, 1, 27));
    let i = live_path(&mut n, t(1), addr(4), 0x14);
    let dead = n.id(i);
    n.closed(t(1), addr(4), close_from(dead));
    let slot = n.b.paths().get(i).unwrap().driver().serial;
    let out = n.probe(t(1), addr(5), probe_from(0x15, 1, 27));
    assert_eq!(released(&out), [(pair(t(1), addr(4)), slot)]);
    assert_eq!(n.b.paths().len(), 4);
    assert_eq!(n.b.paths().find(t(1), &addr(4)), None);
    let new = n.b.paths().find(t(1), &addr(5)).expect("the probed path");
    assert_eq!(
        states(&out),
        [
            (
                pair(t(1), addr(4)),
                dead,
                Some(PathState::Dead),
                None,
                Why::Evicted
            ),
            (
                pair(t(1), addr(5)),
                n.id(new),
                None,
                Some(PathState::Probing),
                Why::Probed
            ),
        ]
    );
}

#[test]
fn closing_a_bundle_releases_every_path() {
    let mut n = Node::capable(26);
    n.candidate(t(2), addr(2));
    n.probe(t(3), addr(3), probe_from(0xC, 1, 27));
    let held: Vec<_> =
        n.b.paths()
            .paths()
            .iter()
            .map(|p| (pair(p.transport_id(), p.addr().clone()), p.driver().serial))
            .collect();
    assert_eq!(held.len(), 3);
    let out = n.close();
    assert_eq!(released(&out), held, "every path, in set order");
}

/// Poll `n` at each wake up to `until` ms, answering at once every probe
/// on the original path and each probe on q no longer than `fits` bytes,
/// as a receiver that drops a frame over its buffer does, and log it all.
fn run_fitting(n: &mut Node, log: &mut Log, until: u64, fits: usize) {
    while let Some(out) = n.tick(TestInstant(until)) {
        let mut queue = alloc::collections::VecDeque::from([out]);
        while let Some(out) = queue.pop_front() {
            log.add(n.now, &out);
            for (to, probe) in probes(&out) {
                if to == pair(t(1), addr(1)) || probe.len <= fits {
                    let ack = ack_for(&probe, peer(&to));
                    queue.push_back(n.ack(to.transport, to.addr.clone(), ack));
                }
            }
        }
    }
}

/// A capable node's candidate q, on transport 2 at the default link MTU of
/// 1280, its probes answered when no longer than `fits` bytes. Returns the
/// node and its log after 30 s.
fn fitting(seed: u64, fits: usize) -> (Node, Log) {
    let mut n = Node::capable(seed);
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    let q = pair(t(2), addr(2));
    log.add(n.now, &out);
    for (to, probe) in probes(&out) {
        if to != q || probe.len <= fits {
            let reply = n.ack(to.transport, to.addr.clone(), ack_for(&probe, peer(&to)));
            log.add(n.now, &reply);
        }
    }
    run_fitting(&mut n, &mut log, 30_000, fits);
    (n, log)
}

#[test]
fn after_an_unanswered_padded_probe_a_probing_path_alternates_the_smallest_size() {
    // Padding is local (Section 5.1). A receiver that drops every frame
    // over 1000 bytes never answers q's first probe, padded to the link
    // MTU; once it has timed out, q's next probe is of the smallest size,
    // which is answered and makes q Live, with no MTU proven, since only a
    // padded probe proves one.
    let padded = 1280 - FRAME_OVERHEAD;
    let q = pair(t(2), addr(2));
    let (n, log) = fitting(70, padded);
    assert_eq!(
        log.changes(&q).get(1).map(|c| (c.0, c.2)),
        Some((0, Some(PathState::Live))),
        "precondition: every size answered, q proven at once"
    );
    let path = n.b.paths().get(1).unwrap();
    assert_eq!(path.state(), PathState::Live, "precondition: proven");
    assert_eq!(path.live().mtu(), Some(padded), "precondition: MTU proven");

    let (n, log) = fitting(70, 1000);
    let sent: Vec<(u64, usize)> = log
        .probes
        .iter()
        .filter(|(at, to, _)| *to == q && *at <= 400)
        .map(|(at, _, probe)| (*at, probe.len))
        .collect();
    assert_eq!(sent, [(0, padded), (400, PATH_PROBE_MIN_SIZE)]);
    assert_eq!(
        log.changes(&q),
        [
            (0, None, Some(PathState::Probing), Why::Candidate),
            (
                400,
                Some(PathState::Probing),
                Some(PathState::Live),
                Why::Answered
            ),
        ]
    );
    let path = n.b.paths().get(1).unwrap();
    assert_eq!(path.live().mtu(), None, "a smallest probe proves no MTU");
}

#[test]
fn a_padded_probe_sent_before_a_change_of_state_does_not_shrink_the_next_one() {
    // q, acked, is closed by the peer at 100 ms: Dead. Its first Dead
    // probe, padded, goes at 1.1 s. At 1.2 s, with that probe still
    // outstanding, the peer's probe brings q back to Probing, and q is
    // probed at once, padded. The Dead probe times out at 1.5 s, in the
    // new state, but it was sent in the old one, so it is not a padded
    // probe of this state gone unanswered: when the peer clears ACTIVE
    // on q at 1.56 s, the probe that prompts at once is padded too. Only
    // once a padded probe of this state has timed out does q send one of
    // the smallest size.
    let mut n = two(71);
    let mut log = Log::default();
    let q = pair(t(2), addr(2));
    let only_p = &mut |_: u64, to: &crate::proto::path::PathRef| *to == pair(t(1), addr(1));
    let on_q = |log: &Log, from: u64| -> Vec<(u64, usize)> {
        log.probes
            .iter()
            .filter(|(at, to, _)| *at >= from && *to == q)
            .map(|(at, _, probe)| (*at, probe.len))
            .collect()
    };
    let out = shut(&mut n, 100, &q);
    log.add(n.now, &out);
    assert_eq!(state(&n, &q), PathState::Dead, "precondition: q Dead");
    run(&mut n, &mut log, 1_199, only_p);
    let padded = 1280 - FRAME_OVERHEAD;
    assert_eq!(
        on_q(&log, 101),
        [(1_100, padded)],
        "precondition: one padded Dead probe"
    );
    let back = crate::proto::path::Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: probe_from(peer(&q), 1, PATH_PROBE_MIN_SIZE),
    };
    let out = at(&mut n, &mut log, 1_200, back);
    assert_eq!(
        states(&out).first().map(|c| (c.2, c.3, c.4)),
        Some((Some(PathState::Dead), Some(PathState::Probing), Why::Probed)),
        "precondition: q revived by the peer's probe"
    );
    assert_eq!(path(&n, &q).live().outstanding(), 2, "precondition");
    run(&mut n, &mut log, 1_549, only_p);
    assert_eq!(
        path(&n, &q).live().outstanding(),
        1,
        "precondition: the Dead probe timed out, the probe at once not"
    );
    for (ms, k, active) in [(1_550, 2, true), (1_560, 3, false)] {
        let input = crate::proto::path::Input::Probe {
            transport: t(2),
            addr: addr(2),
            msg: marked(peer(&q), k, active),
        };
        at(&mut n, &mut log, ms, input);
    }
    run(&mut n, &mut log, 30_000, only_p);
    let probing = on_q(&log, 1_200);
    assert_eq!(
        probing.iter().take(2).copied().collect::<Vec<_>>(),
        [(1_200, padded), (1_560, padded)],
        "the probes at once, before a padded probe of this state timed out"
    );
    assert_eq!(
        probing.get(2).map(|p| p.1),
        Some(PATH_PROBE_MIN_SIZE),
        "the next, after one had: {probing:?}"
    );
}
