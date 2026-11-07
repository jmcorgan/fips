//! FRC-1201 Section 5.6's close clause (frc-1201:1063-1066) and the
//! `(transport, address)` each live link still needs.

use super::*;
use crate::proto::settle::model::judge::Transition;

/// One end of a crossing on `binding`, as in `crossing.rs`.
fn crossed(me: Node, peer: Node, binding: Binding) -> (Judge, Step) {
    let (mine, theirs, peer_at, peer_src) = if me < peer {
        (1, 2, 2, 12)
    } else {
        (2, 1, 1, 11)
    };
    let mut j = judge(me, peer);
    let s = last(
        &mut j,
        &[
            dial(mine, 1, at(peer_at), binding),
            msg1(theirs, theirs * 100, E1, 2, at(peer_src), binding),
            msg2(mine, E1, at(peer_at)),
        ],
    );
    (j, s)
}

#[test]
fn the_losing_handshakes_connection_is_closed_and_no_disconnect_is_sent() {
    // frc-1201:1063-1066: each end tears down the losing link, closing its
    // connection, and sends no Disconnect.
    let (_, small) = crossed(SMALL, LARGE, Binding::Connected);
    assert_eq!(small.change, Some(Transition::Move));
    assert_eq!(
        small.closes,
        alloc::vec![at(12)],
        "the inbound link at the larger node's source"
    );
    assert!(!small.disconnect);
    let (_, large) = crossed(LARGE, SMALL, Binding::Connected);
    assert_eq!(large.change, Some(Transition::Keep));
    assert_eq!(
        large.closes,
        alloc::vec![at(1)],
        "the larger node's own outbound link"
    );
    assert!(!large.disconnect);
}

#[test]
fn a_connectionless_losing_link_closes_nothing() {
    // frc-1201:1063-1065: only a connection-oriented binding has a
    // connection to close.
    let (_, s) = crossed(SMALL, LARGE, Binding::Connectionless);
    assert_eq!(s.change, Some(Transition::Move));
    assert!(s.closes.is_empty());
}

#[test]
fn a_connection_a_remaining_link_still_needs_is_kept_open() {
    // frc-1201:1064: "and no remaining link uses it". Both handshakes on
    // one connection at one address, as on a link that carries one
    // connection per pair.
    let mut j = judge(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            dial(1, 1, at(2), Binding::Connected),
            dial(3, 3, at(2), Binding::Connected),
            msg1(2, 200, E1, 2, at(2), Binding::Connected),
            msg2(1, E1, at(2)),
        ],
    );
    assert_eq!(s.change, Some(Transition::Move));
    assert!(
        s.closes.is_empty(),
        "the moved-to link and the other dial use the address"
    );
}

#[test]
fn after_a_crossing_each_end_needs_only_its_kept_links_setup_address() {
    // The close rule over setup addresses: the kept link's, nothing else.
    let (small, _) = crossed(SMALL, LARGE, Binding::Connected);
    assert_eq!(small.needs(), alloc::vec![(LinkId(1), at(2))]);
    let (large, _) = crossed(LARGE, SMALL, Binding::Connected);
    assert_eq!(large.needs(), alloc::vec![(LinkId(2), at(11))]);
}

#[test]
fn a_reaped_attempts_connection_is_closed_unless_a_live_link_needs_it() {
    // The close rule at a handshake leg that ends without completing.
    let mut j = judge(SMALL, LARGE);
    j.run(&[
        msg1(2, 200, E1, 2, at(12), Binding::Connected),
        dial(1, 1, at(2), Binding::Connected),
        dial(3, 3, at(12), Binding::Connected),
    ]);
    let reaped = j.step(Event::Timeout { hs: Hs(1) });
    assert_eq!(reaped.closes, alloc::vec![at(2)]);
    let shared = j.step(Event::Timeout { hs: Hs(3) });
    assert!(
        shared.closes.is_empty(),
        "the held peer's link is at that address"
    );
}
