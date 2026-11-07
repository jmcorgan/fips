//! Closing a path (multipath v1 draft, Section 5.8): when a local
//! transport is removed, its interface leaves or it loses carrier, the
//! bundle sends the peer a `PathClose` for each path on it whose
//! identifier the peer gave, naming that identifier, on another Live path.
//! Every test drives a `Bundle` in the shell, which also checks after
//! every step that no close travels on the path it names and that nothing
//! is sent to a peer not known to be capable.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::link::LinkMessageType;
use crate::proto::path::wire::{PathClose, PathCloseReason};
use crate::proto::path::{Input, Output, PathState};
use crate::testutil::TestInstant;

/// A close naming the peer's path `path_id` for `reason`.
fn naming(path_id: u32, reason: PathCloseReason) -> PathClose {
    PathClose { path_id, reason }
}

/// The interface of `transport` leaving.
fn left(transport: u32) -> Input {
    Input::Present {
        transport: t(transport),
        present: false,
    }
}

#[test]
fn a_removed_transport_sends_a_close_for_each_of_its_paths_on_another_live_path() {
    let mut n = Node::capable(91);
    live_path(&mut n, t(2), addr(2), 0xB);
    // The peer's own probe from a second address on transport 2 gives
    // that path the peer's identifier 0xE.
    n.probe(t(2), addr(5), probe_from(0xE, 1, 27));
    let out = step(&mut n, 10, gone(2));
    let why = PathCloseReason::InterfaceGone;
    assert_eq!(
        sent_closes(&out),
        [(p(), naming(0xB, why)), (p(), naming(0xE, why))]
    );
    // The closes go before the paths are discarded.
    let close = LinkMessageType::PathClose.to_byte();
    let is_close =
        |o: &Out| matches!(o, Output::Send { bytes, .. } if bytes.first() == Some(&close));
    let last = out.iter().rposition(is_close).expect("a close");
    let first = out
        .iter()
        .position(|o| matches!(o, Output::State { .. }))
        .expect("a discard");
    assert!(last < first, "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn a_close_is_never_sent_on_the_path_it_closes() {
    for input in [down(2), gone(2), left(2)] {
        let mut n = Node::capable(92);
        live_path(&mut n, t(2), addr(2), 0xB);
        // The original path goes Dead at the peer's close, so the second
        // path is our active path and the only Live one.
        shut(&mut n, 10, &p());
        assert_eq!(active(&n), Some(q()));
        let out = step(&mut n, 20, input.clone());
        assert!(sent_closes(&out).is_empty(), "{input:?}: {out:?}");
    }
}

#[test]
fn no_close_goes_to_a_peer_not_known_to_be_capable() {
    for input in [down(1), gone(1), left(1)] {
        let mut n = Node::new(93);
        let out = step(&mut n, 10, input.clone());
        assert!(!n.b.capable());
        assert!(sent_closes(&out).is_empty(), "{input:?}: {out:?}");
    }
}

#[test]
fn a_carrier_loss_names_the_peers_id_for_each_path_on_that_transport() {
    // The original path is Live with the peer's identifier 0xA, the
    // second 0xB and the third 0xC.
    let mut n = two(94);
    live_path(&mut n, t(3), addr(3), 0xC);
    // A second path on transport 1, the peer's 0x6, made by its probe.
    n.probe(t(1), addr(6), probe_from(0x6, 1, 27));
    let ours: Vec<u32> = [p(), pair(t(1), addr(6))]
        .iter()
        .map(|to| path(&n, to).path_id())
        .collect();
    assert!(!ours.contains(&0xA) && !ours.contains(&0x6));
    let out = step(&mut n, 10, down(1));
    // Our active path is on transport 1, so the closes go on the Live
    // path of lowest index elsewhere.
    let lost = PathCloseReason::CarrierLost;
    assert_eq!(
        sent_closes(&out),
        [(q(), naming(0xA, lost)), (q(), naming(0x6, lost))]
    );
    assert_eq!(state(&n, &r()), PathState::Live);
}

#[test]
fn a_close_goes_on_our_active_path_before_a_live_path_of_lower_index() {
    let mut n = two(96);
    live_path(&mut n, t(3), addr(3), 0xC);
    // The original path goes Suspect, so the second becomes our active
    // path; the original's next answer makes it Live again, and active
    // it stays on the second.
    step(&mut n, 10, down(1));
    assert_eq!(active(&n), Some(q()));
    let probe = loop {
        let out = n.tick(TestInstant(5_000)).expect("a probe on the original");
        if let Some((_, probe)) = probes(&out).into_iter().find(|(to, _)| *to == p()) {
            break probe;
        }
    };
    n.ack(t(1), addr(1), ack_for(&probe, 0xA));
    assert_eq!(state(&n, &p()), PathState::Live);
    assert_eq!(active(&n), Some(q()));
    let later = n.now.0 + 1;
    let out = step(&mut n, later, gone(3));
    assert_eq!(
        sent_closes(&out),
        [(q(), naming(0xC, PathCloseReason::InterfaceGone))]
    );
}

#[test]
fn no_close_is_sent_for_a_path_whose_peer_id_is_unknown() {
    let mut n = Node::capable(95);
    live_path(&mut n, t(2), addr(2), 0xB);
    // A candidate on transport 2, probed and never answered.
    n.candidate(t(2), addr(5));
    let out = step(&mut n, 10, left(2));
    assert_eq!(
        sent_closes(&out),
        [(p(), naming(0xB, PathCloseReason::InterfaceGone))]
    );
    assert_eq!(n.b.paths().len(), 1);
}
