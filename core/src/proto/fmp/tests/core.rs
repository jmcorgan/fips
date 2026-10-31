//! Tests for the sans-IO FMP connection-lifecycle decision core.

use super::util::{establish_snapshot, resend_snapshot, stale_snapshot, wire_outcome};
use crate::proto::fmp::{
    ConnAction, Fmp, InboundDecision, InboundReject, OutboundDecision, OutboundSnapshot,
    cross_connection_winner,
};
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
fn no_resend_candidates_yields_no_actions() {
    let fmp = Fmp::new();
    assert!(fmp.poll_resends(Vec::new(), 1_000, 500, 2.0).is_empty());
}

#[test]
fn resend_emits_bytes_and_backoff_schedule() {
    let fmp = Fmp::new();
    let link = LinkId::new(5);
    let msg1 = vec![0xde, 0xad, 0xbe, 0xef];
    // now=1000, interval=500, backoff=2.0, prior_count=0 -> exponent 1 ->
    // next = 1000 + 500 * 2^1 = 2000.
    let actions = fmp.poll_resends(
        vec![resend_snapshot(link, 0, msg1.clone())],
        1_000,
        500,
        2.0,
    );
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        ConnAction::ResendMsg1 {
            link: l,
            bytes,
            next_resend_at_ms,
        } => {
            assert_eq!(*l, link);
            assert_eq!(bytes, &msg1);
            assert_eq!(*next_resend_at_ms, 2_000);
        }
        _ => panic!("expected ResendMsg1"),
    }
}

#[test]
fn resend_backoff_exponent_uses_count_plus_one() {
    let fmp = Fmp::new();
    let link = LinkId::new(6);
    // prior_count=2 -> exponent 3 -> next = 0 + 100 * 2^3 = 800.
    let actions = fmp.poll_resends(vec![resend_snapshot(link, 2, vec![1])], 0, 100, 2.0);
    match &actions[0] {
        ConnAction::ResendMsg1 {
            next_resend_at_ms, ..
        } => assert_eq!(*next_resend_at_ms, 800),
        _ => panic!("expected ResendMsg1"),
    }
}

// --- rekey decision (synthetic clock: elapsed_secs/counter fed directly) ---

// --- rekey msg1 retransmission decision ---

// ===========================================================================
// establish_inbound — inbound msg1 classification (E3)
// ===========================================================================

#[test]
fn establish_inbound_net_new_promotes() {
    let fmp = Fmp::new();
    let snap = establish_snapshot();
    let wire = wire_outcome(Some([1u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Promote
    ));
}

#[test]
fn establish_inbound_at_cap_net_new_rejects() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.at_max_peers = true;
    let wire = wire_outcome(Some([1u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Reject {
            reason: InboundReject::AtMaxPeers
        }
    ));
}

#[test]
fn establish_inbound_at_cap_existing_peer_not_capped() {
    // At cap but the identity is already a peer → the cap gate is bypassed and
    // the same-epoch msg1 goes to the peer's link machine.
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.at_max_peers = true;
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([9u8; 8]);
    let wire = wire_outcome(Some([9u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Rekey { .. }
    ));
}

#[test]
fn a_held_peers_same_epoch_msg1_goes_to_its_link_machine_until_that_machine_asks_for_a_replacement()
{
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([9u8; 8]);
    let wire = wire_outcome(Some([9u8; 8]));
    let peer = *wire.peer_identity.node_addr();
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Rekey { peer: p } if p == peer
    ));
    snap.replace = true;
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::ReplaceThenPromote { peer: p } if p == peer
    ));
}

#[test]
fn establish_inbound_epoch_mismatch_restarts() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([1u8; 8]);
    let wire = wire_outcome(Some([2u8; 8]));
    let peer = *wire.peer_identity.node_addr();
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::RestartThenPromote { peer: p } if p == peer
    ));
}

// ===========================================================================
// establish_outbound — outbound msg2 classification (E4)
// ===========================================================================

#[test]
fn establish_outbound_no_existing_peer_promotes() {
    let fmp = Fmp::new();
    // our_outbound_wins is irrelevant when there is no existing peer.
    let snap = OutboundSnapshot {
        has_existing_peer: false,
        existing_peer_epoch: None,
        our_outbound_wins: true,
        own_dial: false,
    };
    assert_eq!(
        fmp.establish_outbound(&snap, None),
        OutboundDecision::Promote
    );
}

#[test]
fn establish_outbound_cross_connection_win_swaps() {
    let fmp = Fmp::new();
    let snap = OutboundSnapshot {
        has_existing_peer: true,
        existing_peer_epoch: None,
        our_outbound_wins: true,
        own_dial: false,
    };
    assert_eq!(
        fmp.establish_outbound(&snap, None),
        OutboundDecision::CrossConnectionSwap
    );
}

#[test]
fn establish_outbound_cross_connection_loss_keeps() {
    let fmp = Fmp::new();
    let snap = OutboundSnapshot {
        has_existing_peer: true,
        existing_peer_epoch: None,
        our_outbound_wins: false,
        own_dial: false,
    };
    assert_eq!(
        fmp.establish_outbound(&snap, None),
        OutboundDecision::CrossConnectionKeep
    );
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
