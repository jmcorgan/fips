//! Tests for the sans-IO FMP connection-lifecycle decision core.

use super::util::stale_snapshot;
use crate::proto::fmp::{ConnAction, Fmp, cross_connection_winner};
use crate::testutil::make_node_addr;
use crate::transport::LinkId;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn empty_stale_set_yields_no_actions() {
    let fmp = Fmp::new();
    assert!(fmp.poll_timeouts(Vec::new()).is_empty());
}

#[test]
fn inbound_stale_connection_is_torn_down_without_retry() {
    let fmp = Fmp::new();
    let link = LinkId::new(7);
    let actions = fmp.poll_timeouts(vec![stale_snapshot(
        link,
        false,
        Some(make_node_addr(0x22)),
    )]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConnAction::Teardown { link: l } if l == link));
}

#[test]
fn outbound_stale_with_identity_schedules_retry_then_tears_down() {
    let fmp = Fmp::new();
    let link = LinkId::new(9);
    let peer = make_node_addr(0x33);
    let actions = fmp.poll_timeouts(vec![stale_snapshot(link, true, Some(peer))]);
    assert_eq!(actions.len(), 2);
    // Retry is scheduled before teardown, matching the pre-refactor order.
    assert!(matches!(actions[0], ConnAction::ScheduleRetry { peer: p } if p == peer));
    assert!(matches!(actions[1], ConnAction::Teardown { link: l } if l == link));
}

#[test]
fn outbound_stale_without_identity_only_tears_down() {
    let fmp = Fmp::new();
    let link = LinkId::new(11);
    let actions = fmp.poll_timeouts(vec![stale_snapshot(link, true, None)]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConnAction::Teardown { link: l } if l == link));
}

#[test]
fn test_cross_connection_smaller_node_wins_outbound() {
    let node_a = make_node_addr(1); // smaller
    let node_b = make_node_addr(2); // larger

    // Node A's perspective
    assert!(cross_connection_winner(&node_a, &node_b, true)); // A's outbound wins
    assert!(!cross_connection_winner(&node_a, &node_b, false)); // A's inbound loses

    // Node B's perspective
    assert!(!cross_connection_winner(&node_b, &node_a, true)); // B's outbound loses
    assert!(cross_connection_winner(&node_b, &node_a, false)); // B's inbound wins
}

#[test]
fn test_cross_connection_symmetric() {
    let node_a = make_node_addr(1);
    let node_b = make_node_addr(2);

    // A's outbound = B's inbound
    let a_outbound_wins = cross_connection_winner(&node_a, &node_b, true);
    let b_inbound_wins = cross_connection_winner(&node_b, &node_a, false);
    assert_eq!(a_outbound_wins, b_inbound_wins);

    // A's inbound = B's outbound
    let a_inbound_wins = cross_connection_winner(&node_a, &node_b, false);
    let b_outbound_wins = cross_connection_winner(&node_b, &node_a, true);
    assert_eq!(a_inbound_wins, b_outbound_wins);

    // Exactly one survives
    assert!(a_outbound_wins != a_inbound_wins);
}

// --- rekey role gate: a pending session this node answered ---
