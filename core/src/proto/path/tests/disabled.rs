//! A bundle with multipath disabled (multipath v1 draft, Section 8.2): it
//! sends no path message and asks for no connection, discards every path
//! message, candidate and connection report unanswered and unchanged, and
//! handles frames, authentication failures, carrier, presence and removal
//! as an enabled bundle does on a link of one path, down to reporting
//! itself orphaned. Every test drives a `Bundle` in the shell, which also
//! checks after every step that a disabled bundle sends nothing and asks
//! for no connection.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::shell::*;
use crate::proto::path::wire::PATH_PROBE_MIN_SIZE;
use crate::proto::path::{Input, Output, PathRef, PathState, Roam, Source, Why};
use crate::transport::TransportAddr;

/// The type byte of a session datagram.
const DATAGRAM: u8 = 0x00;

/// The type byte of a heartbeat.
const HEARTBEAT: u8 = 0x51;

/// The draft's `AUTH_FAIL_LIMIT`.
const LIMIT: usize = 20;

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

/// The peer's probe from its path `path_id`, `len` bytes long, on `to`.
fn probed(to: &PathRef, path_id: u32, len: usize) -> Input {
    Input::Probe {
        transport: to.transport,
        addr: to.addr.clone(),
        msg: probe_from(path_id, 1, len),
    }
}

/// The peer's ack, on `to`, of a probe on our path `ours` that we never
/// sent.
fn acked(to: &PathRef, ours: u32) -> Input {
    Input::Ack {
        transport: to.transport,
        addr: to.addr.clone(),
        msg: ack_for(&probe_from(ours, 1, 27), 0xA),
    }
}

/// The peer's close, on `to`, of our path `ours`.
fn closing(to: &PathRef, ours: u32) -> Input {
    Input::Close {
        transport: to.transport,
        addr: to.addr.clone(),
        msg: close_from(ours),
    }
}

/// The inputs only multipath brings, as a peer and a host that do
/// implement it would give them to a node whose original path is ours,
/// with transport 2 connection-oriented: the peer's probes on the original
/// pair and two new ones, candidates on both kinds of transport, an ack
/// and a close naming the original path, and both reports of a
/// connection.
fn offered(ours: u32) -> Vec<Input> {
    let far = pair(t(2), addr(6));
    Vec::from([
        probed(&p(), 0xA, 27),
        probed(&q(), 0xB, 1200),
        probed(&r(), 0xC, 27),
        found(&far),
        found(&pair(t(3), addr(7))),
        acked(&p(), ours),
        closing(&p(), ours),
        settled(&far, true),
        settled(&far, false),
    ])
}

/// Whether stepping `input` at `ms` gave an output or changed the bundle.
fn stirs(n: &mut Node, ms: u64, input: Input) -> bool {
    let before = format!("{:?}", n.b);
    let out = step(n, ms, input);
    !out.is_empty() || format!("{:?}", n.b) != before
}

#[test]
fn a_disabled_bundle_never_sends_or_connects() {
    let facts = || Stub::default().oriented(t(2));
    let mut n = Node::disabled(111).with(facts());
    let ours = n.id(0);
    for (k, input) in offered(ours).into_iter().enumerate() {
        let out = step(&mut n, 10 * k as u64, input);
        assert!(out.is_empty(), "{out:?}");
    }
    // Minutes of polls.
    for ms in (100..=180_000).step_by(100) {
        let out = step(&mut n, ms, Input::Poll);
        assert!(out.is_empty(), "{out:?}");
    }
    assert_eq!(n.b.paths().len(), 1, "no second path");
    assert_eq!(n.b.next_wake(), None);

    // The same inputs to an enabled bundle are answered, probed and
    // connected.
    let mut e = Node::new(111).with(facts());
    assert_eq!(e.id(0), ours, "the same draws");
    let mut out = Vec::new();
    for (k, input) in offered(ours).into_iter().enumerate() {
        out.extend(step(&mut e, 10 * k as u64, input));
    }
    assert!(!sent_acks(&out).is_empty(), "{out:?}");
    assert!(!probes(&out).is_empty(), "{out:?}");
    assert!(!asked(&out).is_empty(), "{out:?}");
}

#[test]
fn a_disabled_bundle_discards_path_messages_and_changes_nothing() {
    let mut n = Node::disabled(112).with(Stub::default().oriented(t(2)));
    let ours = n.id(0);
    for (k, input) in offered(ours).into_iter().enumerate() {
        let ms = 10 * k as u64;
        assert!(!stirs(&mut n, ms, input.clone()), "{input:?}");
        assert!(!n.b.capable(), "{input:?} made the peer capable");
    }
    // Each path message would make an enabled bundle's peer capable.
    for input in &offered(ours)[..3] {
        let mut e = Node::new(112);
        assert!(stirs(&mut e, 0, input.clone()), "{input:?}");
        assert!(e.b.capable(), "{input:?}");
    }

    // It holds no candidate and takes no report of a connection, where an
    // enabled bundle, once capable, connects, probes and admits.
    let far = pair(t(2), addr(6));
    let inputs = [found(&far), found(&r()), settled(&far, true)];
    let mut n = Node::disabled(113).with(Stub::default().oriented(t(2)));
    for (k, input) in inputs.iter().enumerate() {
        assert!(!stirs(&mut n, 10 * k as u64, input.clone()), "{input:?}");
    }
    assert_eq!(n.b.paths().len(), 1);
    assert_eq!(n.b.candidates().iter().count(), 0, "no candidate held");
    let mut e = Node::capable(113).with(Stub::default().oriented(t(2)));
    for (k, input) in inputs.iter().enumerate() {
        assert!(stirs(&mut e, 10 * k as u64, input.clone()), "{input:?}");
    }
    assert_eq!(e.b.paths().len(), 3);
}

/// `out` with every slot's serial set to 0, so the outputs of two nodes
/// driven alike compare equal.
fn bare(out: Vec<Out>) -> Vec<Out> {
    out.into_iter()
        .map(|o| match o {
            Output::Moved { from, to, .. } => Output::Moved {
                from,
                to,
                driver: 0,
            },
            Output::Released { to, keep, .. } => Output::Released {
                to,
                driver: 0,
                keep,
            },
            o @ (Output::Send { .. }
            | Output::State { .. }
            | Output::Capable
            | Output::NotCapable
            | Output::Refused { .. }
            | Output::Switched { .. }
            | Output::Orphaned
            | Output::Connect { .. }
            | Output::Proven { .. }) => o,
        })
        .collect()
}

/// Drive `n`, a node whose peer is not known to be capable, through the
/// calls of a link of one path: frames from its pair, from another
/// transport and from a new address on its transport (the roam), failures
/// on its pair past the limit and from a pair no path holds, an
/// unreachable send, carrier lost and back, and the interface's return;
/// then `last`, which takes the original path's transport away, and a
/// frame and a failure after it. Returns each call's result or outputs, as
/// text, with slot serials left out.
fn script(mut n: Node, last: Input) -> Vec<String> {
    let mut seen = Vec::new();
    let roamed = addr(7);
    let frames: [(u32, TransportAddr, u8); 5] = [
        (1, addr(1), HEARTBEAT),
        (1, addr(1), DATAGRAM),
        (2, addr(9), HEARTBEAT),
        (1, roamed.clone(), HEARTBEAT),
        (1, roamed.clone(), DATAGRAM),
    ];
    for (k, a, ty) in frames {
        seen.push(format!("{:?}", n.account(t(k), &a, 100, ty)));
    }
    let original = n.b.paths().get(0).expect("the original path");
    assert_eq!(original.addr(), &roamed, "the original path roamed");
    for _ in 0..LIMIT + 2 {
        seen.push(format!("{:?}", n.charge(t(1), &roamed)));
    }
    seen.push(format!("{:?}", n.charge(t(1), &addr(1))));
    seen.push(format!("{:?}", n.account(t(1), &roamed, 100, HEARTBEAT)));
    assert_eq!(path(&n, &pair(t(1), roamed.clone())).live().fails(), 0);

    let calls = [
        Input::SendFailed {
            transport: t(1),
            addr: roamed.clone(),
        },
        down(1),
        Input::Carrier {
            transport: t(1),
            up: true,
        },
        Input::Present {
            transport: t(1),
            present: true,
        },
        Input::Poll,
    ];
    for (k, input) in calls.into_iter().enumerate() {
        seen.push(format!("{:?}", bare(step(&mut n, 100 * k as u64, input))));
    }
    assert_eq!(state(&n, &pair(t(1), roamed.clone())), PathState::Suspect);

    let out = step(&mut n, 1_000, last);
    let logged: Vec<_> = states(&out).into_iter().map(|c| (c.0, c.3, c.4)).collect();
    assert_eq!(logged, [(pair(t(1), roamed.clone()), None, Why::Removed)]);
    assert_eq!(released(&out).len(), 1, "{out:?}");
    assert!(matches!(out.last(), Some(Output::Orphaned)), "{out:?}");
    seen.push(format!("{:?}", bare(out)));

    let after = n.account(t(1), &roamed, 100, HEARTBEAT);
    seen.push(format!("{after:?}"));
    assert_eq!((after.path, after.roam), (None, Roam::Unmoved));
    seen.push(format!("{:?}", n.charge(t(1), &roamed)));
    seen
}

#[test]
fn a_disabled_bundle_accounts_charges_and_is_orphaned_as_an_enabled_one() {
    let lost = Input::Present {
        transport: t(1),
        present: false,
    };
    for last in [lost, gone(1)] {
        let enabled = script(Node::new(114), last.clone());
        let disabled = script(Node::disabled(114), last.clone());
        assert_eq!(disabled, enabled, "{last:?}");
    }
}

#[test]
fn a_disabled_bundle_never_probes_or_wakes_where_an_enabled_one_would() {
    let mut e = Node::new(115);
    let mut n = Node::disabled(115);
    let ours = n.id(0);
    assert_eq!(e.id(0), ours, "the same draws");

    // A candidate: the enabled bundle, its peer not known to be capable,
    // sends a capability probe on the original path and wakes for it; the
    // disabled one holds nothing, sends nothing and has no wake.
    let out = step(&mut e, 0, found(&q()));
    let probe = probe_on(&out, &p());
    assert_eq!(probe.len, PATH_PROBE_MIN_SIZE);
    assert_eq!(probe.path_id, ours);
    assert!(e.b.next_wake().is_some());
    let out = step(&mut n, 0, found(&q()));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(n.b.next_wake(), None);

    // The same candidates, probes, acks, closes and connection reports to
    // both, then minutes of polls: the enabled bundle probes and wakes, the
    // disabled one never.
    let mut inputs = offered(ours);
    inputs.extend((1..=1_800).map(|_| Input::Poll));
    let (mut sent, mut woke) = (false, false);
    for (k, input) in inputs.into_iter().enumerate() {
        let ms = 100 * (k as u64 + 1);
        let out = step(&mut e, ms, input.clone());
        sent |= !probes(&out).is_empty();
        woke |= e.b.next_wake().is_some();
        let out = step(&mut n, ms, input.clone());
        assert!(out.is_empty(), "{input:?}: {out:?}");
        assert_eq!(n.b.next_wake(), None, "{input:?}");
        assert_eq!(n.b.candidates().iter().count(), 0, "{input:?}");
    }
    assert!(sent && woke);
    assert!(!n.b.capable());
    assert_eq!(n.b.paths().len(), 1);
}
