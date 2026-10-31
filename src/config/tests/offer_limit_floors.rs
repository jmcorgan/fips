//! Tests for the floors on `MAX_INCOMING_OFFERS` (at least 16) and
//! `MAX_OFFERS_PER_SENDER` (at least 4), which
//! `node.rendezvous.nostr.max_concurrent_incoming_offers` and
//! `max_concurrent_offers_per_npub` hold (FRC-1601, Section 3.4). Below them
//! a node discards an offer unchecked while it handles fewer offers than the
//! protocol allows. A node given less runs at the floor; a per-sender limit
//! of 0 is raised too, not refused.

use super::*;
use crate::node::Node;

/// The two offer limits a node built with `incoming` and `per_sender`
/// configured runs with.
fn offer_limits_used(incoming: usize, per_sender: usize) -> (usize, usize) {
    let mut config = Config::default();
    config.node.rendezvous.nostr.max_concurrent_incoming_offers = incoming;
    config.node.rendezvous.nostr.max_concurrent_offers_per_npub = per_sender;
    let node = Node::new(config).expect("the node is built");
    let nostr = &node.config().node.rendezvous.nostr;
    (
        nostr.max_concurrent_incoming_offers,
        nostr.max_concurrent_offers_per_npub,
    )
}

#[test]
fn a_node_given_max_concurrent_incoming_offers_below_16_runs_with_16() {
    for incoming in [0, 1, 4, 8, 15] {
        assert_eq!(
            offer_limits_used(incoming, 4).0,
            16,
            "a node given max_concurrent_incoming_offers = {incoming} ran with it, below the floor of 16 on MAX_INCOMING_OFFERS"
        );
    }
}

#[test]
fn a_node_given_max_concurrent_offers_per_npub_below_4_runs_with_4() {
    for per_sender in [1, 2, 3, 0] {
        assert_eq!(
            offer_limits_used(16, per_sender).1,
            4,
            "a node given max_concurrent_offers_per_npub = {per_sender} ran with it, below the floor of 4 on MAX_OFFERS_PER_SENDER"
        );
    }
}

#[test]
fn a_node_given_the_offer_limits_at_or_above_their_floors_runs_with_them_unchanged() {
    assert_eq!(offer_limits_used(16, 4), (16, 4));
    assert_eq!(offer_limits_used(64, 8), (64, 8));
}
