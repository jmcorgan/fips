//! One peer cannot take the whole flow table.
//!
//! Every new source port a peer sends from is a new flow key, and every flow
//! accepted from a listener stays pinned by the daemon until its client writes
//! on it or the listener closes. Without a bound of its own, one peer that
//! sends one datagram from each of `max_flows` source ports fills the node's
//! table, and every native connect and every arrival from any other peer is
//! refused until the listener closes. These tests hold one peer's inbound flows
//! to a share of the table.
//!
//! The suite's limits allow eight flows, so a quarter of the table is two.

use super::tests::{arrivals, key, limits, peer, sink};
use super::*;

/// A peer's share of the flow table under the suite's limits.
const SHARE: usize = 2;

/// Deliver from `who` and accept the arrival at once, the way the listener
/// task does, so the backlog never holds more than the one being delivered.
/// `None` when the delivery did not announce a flow.
fn arrive_and_accept(registry: &mut Registry, who: u8, src: u16) -> Option<FlowKey> {
    let flow = match registry.deliver(peer(who), key(who), src, 4242, 0) {
        Delivery::Arrived(_, arrival) => arrival.flow,
        _ => return None,
    };
    let (tx, _rx) = sink();
    let (key, _, _) = registry.accept(flow, tx, 0).unwrap();
    Some(key)
}

#[test]
fn one_peer_cannot_take_the_whole_flow_table_and_a_local_connect_still_succeeds() {
    let mut registry = Registry::new(limits());
    let (arrival_tx, _arrival_rx) = arrivals();
    registry.listen(Some(4242), arrival_tx).unwrap();

    let mut accepted = 0;
    for src in 5000..5000 + limits().max_flows as u16 {
        if arrive_and_accept(&mut registry, 7, src).is_some() {
            accepted += 1;
        }
    }

    let (tx, _rx) = sink();
    let connected = registry.connect(key(1), 6000, None, tx, 0);
    assert!(
        connected.is_ok(),
        "one peer took {accepted} of {} flows and a local connect was refused: {connected:?}",
        limits().max_flows
    );
    assert!(
        matches!(
            registry.deliver(peer(8), key(8), 5000, 4242, 0),
            Delivery::Arrived(..)
        ),
        "a second peer could not reach the listener after the first took {accepted} flows"
    );
}

#[test]
fn a_pending_arrival_counts_against_its_peers_share() {
    // A backlog as large as the table, so the backlog cannot be what refuses.
    let mut registry = Registry::new(Limits {
        per_flow: 4,
        backlog: 8,
        max_flows: 8,
    });
    let (arrival_tx, _arrival_rx) = arrivals();
    registry.listen(Some(4242), arrival_tx).unwrap();

    for src in 5000..5000 + SHARE as u16 {
        assert!(matches!(
            registry.deliver(peer(7), key(7), src, 4242, 0),
            Delivery::Arrived(..)
        ));
    }
    let over = registry.deliver(peer(7), key(7), 5000 + SHARE as u16, 4242, 0);
    assert!(
        matches!(over, Delivery::Drop(DropCause::PeerShare)),
        "a peer with {SHARE} arrivals pending was not refused for its share: {over:?}"
    );
}

#[test]
fn a_peer_at_its_share_is_refused_until_one_of_its_flows_is_released() {
    let mut registry = Registry::new(limits());
    let (arrival_tx, _arrival_rx) = arrivals();
    registry.listen(Some(4242), arrival_tx).unwrap();

    let mut held = Vec::new();
    for src in 5000..5000 + SHARE as u16 {
        held.push(
            arrive_and_accept(&mut registry, 7, src).expect("under its share, a peer arrives"),
        );
    }

    let over = registry.deliver(peer(7), key(7), 6000, 4242, 0);
    assert!(
        matches!(over, Delivery::Drop(DropCause::PeerShare)),
        "a peer holding {SHARE} flows was not refused for its share: {over:?}"
    );

    assert!(registry.release(&held[0]));
    assert!(
        matches!(
            registry.deliver(peer(7), key(7), 6000, 4242, 0),
            Delivery::Arrived(..)
        ),
        "a peer that let one flow go is still refused"
    );
}

#[test]
fn flows_this_node_opened_to_a_peer_do_not_count_against_that_peers_inbound_share() {
    let mut registry = Registry::new(limits());
    let (arrival_tx, _arrival_rx) = arrivals();
    registry.listen(Some(4242), arrival_tx).unwrap();

    for _ in 0..=SHARE {
        let (tx, _rx) = sink();
        registry.connect(key(7), 5000, None, tx, 0).unwrap();
    }
    assert!(matches!(
        registry.deliver(peer(7), key(7), 5000, 4242, 0),
        Delivery::Arrived(..)
    ));
}

#[test]
fn a_peer_over_its_share_is_dropped_for_its_share_and_not_for_the_node_ceiling() {
    assert_eq!(limits().per_peer(), SHARE);
    let mut registry = Registry::new(limits());
    let (arrival_tx, _arrival_rx) = arrivals();
    registry.listen(Some(4242), arrival_tx).unwrap();

    for src in 5000..5000 + SHARE as u16 {
        arrive_and_accept(&mut registry, 7, src).expect("under its share, a peer arrives");
    }
    assert!(matches!(
        registry.deliver(peer(7), key(7), 6000, 4242, 0),
        Delivery::Drop(DropCause::PeerShare)
    ));

    // The rest of the table, filled by peers that each hold one flow.
    let mut who = 8;
    while registry.flow_count() < limits().max_flows {
        arrive_and_accept(&mut registry, who, 5000).expect("a new peer arrives");
        who += 1;
    }
    assert!(matches!(
        registry.deliver(peer(who), key(who), 5000, 4242, 0),
        Delivery::Drop(DropCause::TooManyFlows)
    ));
}

#[test]
fn a_peer_share_is_never_zero_however_small_the_table() {
    let tiny = Limits {
        per_flow: 4,
        backlog: 2,
        max_flows: 2,
    };
    assert_eq!(tiny.per_peer(), 1);
}
