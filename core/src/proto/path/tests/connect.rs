//! Candidates on connection-oriented transports: a candidate on such a
//! transport has a connection opened, with `Output::Connect`, before its
//! first probe, and a failed connection counts as one unanswered discovery
//! probe. Every test drives a `Bundle` in the shell, which also checks
//! after every step that a connection is asked for only on a
//! connection-oriented transport, to a path held, with no probe beside it
//! on that path.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::path::wire::{PathCaps, PathFlags, PathProbe};
use crate::proto::path::{Input, PathRef, PathState, Source, Why};
use crate::testutil::TestInstant;

/// A capable node whose transport 2 is connection-oriented.
fn node(seed: u64) -> Node {
    Node::capable(seed).with(Stub::default().oriented(t(2)))
}

/// The candidate `to`.
fn found(to: &PathRef) -> Input {
    Input::Candidate {
        transport: to.transport,
        addr: to.addr.clone(),
        source: Source::Config,
    }
}

/// The connection asked for to `to` settled, opened when `ok`.
fn settled(to: &PathRef, ok: bool) -> Input {
    Input::Connected {
        transport: to.transport,
        addr: to.addr.clone(),
        ok,
    }
}

/// The connections asked for in `log`, by instant, on `to`.
fn dials(log: &Log, to: &PathRef) -> Vec<u64> {
    log.connects
        .iter()
        .filter(|(_, p)| p == to)
        .map(|(at, _)| *at)
        .collect()
}

#[test]
fn a_connection_oriented_candidate_is_connected_before_it_is_probed() {
    let mut n = node(101);
    let out = step(&mut n, 0, found(&q()));
    assert_eq!(asked(&out), [q()]);
    assert!(probes(&out).iter().all(|(to, _)| *to != q()), "{out:?}");
    let logged: Vec<_> = states(&out).into_iter().map(|c| (c.0, c.3, c.4)).collect();
    assert_eq!(logged, [(q(), Some(PathState::Probing), Why::Candidate)]);

    // Opened 50 ms on, the path is probed at once, padded to the link MTU,
    // and its answer makes it Live.
    let out = step(&mut n, 50, settled(&q(), true));
    assert!(asked(&out).is_empty(), "{out:?}");
    let probe = probe_on(&out, &q());
    assert_eq!(probe.len, 1280 - FRAME_OVERHEAD);
    n.now = TestInstant(60);
    n.ack(t(2), addr(2), ack_for(&probe, peer(&q())));
    assert_eq!(state(&n, &q()), PathState::Live);

    // A candidate on a connectionless transport is probed at once.
    let out = step(&mut n, 70, found(&r()));
    assert!(asked(&out).is_empty(), "{out:?}");
    probe_on(&out, &r());

    // Once open, the path needs no other connection, and a report of a
    // connection it did not ask for changes nothing.
    let out = step(&mut n, 80, settled(&q(), false));
    assert!(states(&out).is_empty(), "{out:?}");
    assert_eq!(path(&n, &q()).live().misses(), 0);
    let mut log = Log::default();
    run(&mut n, &mut log, 30_000, &mut all);
    assert!(log.connects.is_empty(), "{:?}", log.connects);
    assert!(!log.on(&q()).is_empty());
}

#[test]
fn a_failed_connect_counts_one_unanswered_discovery_probe() {
    let mut n = node(102);
    let mut log = Log::default();
    at(&mut n, &mut log, 0, found(&q()));
    // Each connection fails 30 ms after it is asked for. The next is asked
    // for a discovery interval on: 200 ms doubling with each failure, up
    // to the 10 s heartbeat.
    let gaps = [400, 800, 1_600, 3_200, 6_400, 10_000, 10_000];
    let mut asked_at = 0;
    let mut want = Vec::from([0]);
    for k in 1..=8u32 {
        let failed = asked_at + 30;
        let out = at(&mut n, &mut log, failed, settled(&q(), false));
        assert!(asked(&out).is_empty(), "{out:?}");
        assert!(probes(&out).iter().all(|(to, _)| *to != q()), "{out:?}");
        if k == 8 {
            let logged: Vec<_> = states(&out).into_iter().map(|c| (c.0, c.3, c.4)).collect();
            assert_eq!(logged, [(q(), Some(PathState::Dead), Why::Connect)]);
            break;
        }
        assert_eq!(state(&n, &q()), PathState::Probing);
        assert_eq!(path(&n, &q()).live().misses(), k);
        asked_at = failed + gaps[k as usize - 1];
        run(&mut n, &mut log, asked_at, &mut all);
        want.push(asked_at);
        assert_eq!(dials(&log, &q()), want);
    }
    // Never acked, the Dead path is neither connected nor probed again.
    run(&mut n, &mut log, asked_at + 120_000, &mut all);
    assert_eq!(dials(&log, &q()), want);
    assert!(log.on(&q()).is_empty());
}

#[test]
fn nothing_is_probed_while_a_connect_is_pending() {
    let mut n = node(103);
    let mut log = Log::default();
    at(&mut n, &mut log, 0, found(&q()));
    assert_eq!(dials(&log, &q()), [0]);

    // The peer's probes on the pair are answered, but its `ACTIVE` turning
    // off asks for a probe at once, which a pending connection drops.
    let flagged = |active: bool, probe_id: u32| {
        PathProbe::new(
            probe_id,
            0xE,
            PathFlags::with_active(active),
            PathCaps::default(),
        )
    };
    let out = at(&mut n, &mut log, 100, probe_in(&q(), flagged(true, 1)));
    assert_eq!(sent_acks(&out).len(), 1);
    let out = at(&mut n, &mut log, 200, probe_in(&q(), flagged(false, 2)));
    assert_eq!(sent_acks(&out).len(), 1);

    // Minutes of polls, with the active path probed and answered meanwhile.
    run(&mut n, &mut log, 180_000, &mut all);
    assert!(log.on(&q()).is_empty(), "{:?}", log.on(&q()));
    assert_eq!(dials(&log, &q()), [0]);
    assert!(!log.on(&p()).is_empty());
    assert_eq!(state(&n, &q()), PathState::Probing);
    assert_eq!(path(&n, &q()).live().outstanding(), 0);
}

#[test]
fn a_path_a_probe_created_needs_no_connect() {
    let mut n = node(104);
    let from = pair(t(2), addr(5));
    let out = n.probe(t(2), addr(5), probe_from(0xE, 1, 27));
    assert!(asked(&out).is_empty(), "{out:?}");
    assert_eq!(sent_acks(&out).len(), 1);
    let probe = probe_on(&out, &from);
    n.now = TestInstant(10);
    n.ack(t(2), addr(5), ack_for(&probe, 0xE));
    assert_eq!(state(&n, &from), PathState::Live);
}

/// The peer's probe `msg` arriving on the pair `to`.
fn probe_in(to: &PathRef, msg: PathProbe) -> Input {
    Input::Probe {
        transport: to.transport,
        addr: to.addr.clone(),
        msg,
    }
}
