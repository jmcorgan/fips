//! Tests for the floor on `ATTEMPT_TIMEOUT`, which
//! `node.rendezvous.nostr.attempt_timeout_secs` holds: at least 10 s
//! (FRC-1601, Section 3.4). Below it a node ends its punch attempt for want
//! of an address to adopt sooner than the floor allows. A node given less
//! runs at 10 s.

use super::*;
use crate::node::Node;

/// The punch attempt timeout a node built with `secs` configured runs with.
fn attempt_timeout_used(secs: u64) -> u64 {
    let mut config = Config::default();
    config.node.rendezvous.nostr.attempt_timeout_secs = secs;
    let node = Node::new(config).expect("the node is built");
    node.config().node.rendezvous.nostr.attempt_timeout_secs
}

#[test]
fn a_node_given_an_attempt_timeout_below_10_s_runs_with_10_s() {
    for secs in [0, 1, 5, 9] {
        assert_eq!(
            attempt_timeout_used(secs),
            10,
            "a node given attempt_timeout_secs = {secs} ran with it, below the 10 s floor on ATTEMPT_TIMEOUT"
        );
    }
}

#[test]
fn a_node_given_an_attempt_timeout_at_or_above_10_s_runs_with_it_unchanged() {
    for secs in [10, 11, 60] {
        assert_eq!(attempt_timeout_used(secs), secs);
    }
}
