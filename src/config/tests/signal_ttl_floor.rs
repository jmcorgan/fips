//! Tests for the floor on `SIGNAL_TTL`, which
//! `node.rendezvous.nostr.signal_ttl_secs` holds: at least 120 s (FRC-1601,
//! Section 3.4). Below it a node judges an offer stale, and stops waiting for
//! an answer, sooner than the floor allows. A node given less runs at 120 s,
//! and the replay-window check sees the value the node runs with.

use super::*;
use crate::node::Node;

/// The default configuration with `signal_ttl_secs` set to `secs`.
fn with_signal_ttl(secs: u64) -> Config {
    let mut config = Config::default();
    config.node.rendezvous.nostr.signal_ttl_secs = secs;
    config
}

/// The signal lifetime a node built from `config` runs with.
fn signal_ttl_used(config: Config) -> u64 {
    let node = Node::new(config).expect("the node is built");
    node.config().node.rendezvous.nostr.signal_ttl_secs
}

#[test]
fn a_node_given_a_signal_ttl_below_120_s_runs_with_120_s() {
    for secs in [0, 1, 45, 60, 119] {
        assert_eq!(
            signal_ttl_used(with_signal_ttl(secs)),
            120,
            "a node given signal_ttl_secs = {secs} ran with it, below the 120 s floor on SIGNAL_TTL"
        );
    }
}

#[test]
fn a_node_given_a_signal_ttl_at_or_above_120_s_runs_with_it_unchanged() {
    for secs in [120, 121, 179] {
        assert_eq!(signal_ttl_used(with_signal_ttl(secs)), secs);
    }
}

#[test]
fn a_signal_ttl_raised_to_its_floor_is_refused_when_the_replay_window_is_not_wider_than_240_s() {
    let mut config = with_signal_ttl(45);
    config.node.rendezvous.nostr.replay_window_secs = 200;
    match Node::new(config) {
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("signal_ttl_secs"), "got: {msg}");
            assert!(msg.contains("replay_window_secs"), "got: {msg}");
        }
        Ok(_) => panic!(
            "signal_ttl_secs = 45 with replay_window_secs = 200 was accepted, though the node \
             runs at 120 s and accepts a signal over 240 s, longer than it remembers a session id"
        ),
    }
}

#[test]
fn a_signal_ttl_raised_to_its_floor_is_accepted_when_the_replay_window_is_wider_than_240_s() {
    let mut config = with_signal_ttl(45);
    config.node.rendezvous.nostr.replay_window_secs = 300;
    assert_eq!(signal_ttl_used(config), 120);
}
