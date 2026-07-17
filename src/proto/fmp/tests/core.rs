//! Tests for the sans-IO FMP connection-lifecycle decision core.

use super::util::{
    establish_snapshot, peer_snapshot, rekey_resend_snapshot, resend_snapshot, stale_snapshot,
    wire_outcome,
};
use crate::proto::fmp::{
    ConnAction, Fmp, InboundDecision, InboundReject, NegotiationPayload, NodeProfile,
    OutboundDecision, OutboundSnapshot, RekeyCfg, cross_connection_winner,
};
use crate::testutil::make_node_addr;
use crate::transport::LinkId;

/// Matching-epoch default used by `establish_snapshot`.
const SAME_EPOCH: [u8; 8] = [0x01; 8];

/// Threshold config used across the rekey decision tests: rekey at 100s of
/// session age or 1000 sent messages.
fn cfg() -> RekeyCfg {
    RekeyCfg {
        after_secs: 100,
        after_messages: 1_000,
    }
}

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

#[test]
fn rekey_no_peers_yields_no_actions() {
    let fmp = Fmp::new();
    assert!(fmp.poll_rekey(Vec::new(), &cfg()).is_empty());
}

#[test]
fn rekey_cutover_takes_precedence_over_trigger() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x10);
    p.has_pending = true;
    // Wildly over the time threshold, but cutover wins and nothing else fires.
    p.elapsed_secs = 10_000;
    p.counter = 10_000;
    let actions = fmp.poll_rekey(vec![p], &cfg());
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConnAction::Cutover { peer } if peer == make_node_addr(0x10)));
}

#[test]
fn rekey_pending_with_inflight_rekey_does_not_cut_over() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x11);
    p.has_pending = true;
    p.rekey_in_progress = true;
    p.elapsed_secs = 10_000;
    // has_pending gated by !rekey_in_progress -> no cutover; in-progress -> no
    // trigger either.
    assert!(fmp.poll_rekey(vec![p], &cfg()).is_empty());
}

#[test]
fn rekey_expired_drain_and_trigger_both_fire() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x12);
    p.is_draining = true;
    p.drain_expired = true;
    p.elapsed_secs = 150; // past 100s threshold
    let actions = fmp.poll_rekey(vec![p], &cfg());
    // Draining does not preclude re-triggering in the same tick.
    assert_eq!(actions.len(), 2);
    assert!(matches!(actions[0], ConnAction::Drain { peer } if peer == make_node_addr(0x12)));
    assert!(
        matches!(actions[1], ConnAction::InitiateRekey { peer } if peer == make_node_addr(0x12))
    );
}

#[test]
fn rekey_triggers_on_counter() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x13);
    p.counter = 1_000; // == after_messages
    let actions = fmp.poll_rekey(vec![p], &cfg());
    assert!(matches!(actions[0], ConnAction::InitiateRekey { .. }));
}

#[test]
fn rekey_negative_jitter_lowers_time_threshold() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x14);
    p.elapsed_secs = 90;
    p.jitter_secs = -15; // effective threshold 85 -> 90 >= 85 fires
    assert!(matches!(
        fmp.poll_rekey(vec![p], &cfg())[0],
        ConnAction::InitiateRekey { .. }
    ));
}

#[test]
fn rekey_positive_jitter_raises_time_threshold() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x15);
    p.elapsed_secs = 105;
    p.jitter_secs = 10; // effective threshold 110 -> 105 < 110, no time trigger
    assert!(fmp.poll_rekey(vec![p], &cfg()).is_empty());
}

#[test]
fn rekey_dampening_suppresses_trigger() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x16);
    p.elapsed_secs = 10_000;
    p.is_dampened = true;
    assert!(fmp.poll_rekey(vec![p], &cfg()).is_empty());
}

#[test]
fn rekey_msg3_pending_suppresses_trigger() {
    let fmp = Fmp::new();
    // The initiator already cut over and is still retransmitting this cycle's
    // rekey msg3; a fresh rekey must not start (it would overwrite the retained
    // payload). Mirrors the dampening-suppression case.
    let mut p = peer_snapshot(0x17);
    p.elapsed_secs = 10_000;
    p.rekey_msg3_pending = true;
    assert!(fmp.poll_rekey(vec![p], &cfg()).is_empty());
}

#[test]
fn rekey_actions_are_phase_grouped_across_peers() {
    let fmp = Fmp::new();
    // Peer A: trigger only. Peer B: cutover. Peer C: drain + trigger.
    let mut a = peer_snapshot(0x01);
    a.elapsed_secs = 200;
    let mut b = peer_snapshot(0x02);
    b.has_pending = true;
    let mut c = peer_snapshot(0x03);
    c.is_draining = true;
    c.drain_expired = true;
    c.counter = 5_000;
    let actions = fmp.poll_rekey(vec![a, b, c], &cfg());
    // Order must be: all cutovers, then all drains, then all rekeys.
    assert!(matches!(actions[0], ConnAction::Cutover { peer } if peer == make_node_addr(0x02)));
    assert!(matches!(actions[1], ConnAction::Drain { peer } if peer == make_node_addr(0x03)));
    assert!(
        matches!(actions[2], ConnAction::InitiateRekey { peer } if peer == make_node_addr(0x01))
    );
    assert!(
        matches!(actions[3], ConnAction::InitiateRekey { peer } if peer == make_node_addr(0x03))
    );
    assert_eq!(actions.len(), 4);
}

// --- rekey msg1 retransmission decision ---

#[test]
fn rekey_resend_no_candidates_yields_no_actions() {
    let fmp = Fmp::new();
    assert!(
        fmp.poll_rekey_resends(Vec::new(), 1_000, 500, 2.0, 5)
            .is_empty()
    );
}

#[test]
fn rekey_resend_over_budget_abandons() {
    let fmp = Fmp::new();
    // resend_count == max_resends -> abandon (even though it is "due").
    let c = rekey_resend_snapshot(0x40, 5, true, vec![9]);
    let actions = fmp.poll_rekey_resends(vec![c], 1_000, 500, 2.0, 5);
    assert_eq!(actions.len(), 1);
    assert!(
        matches!(actions[0], ConnAction::AbandonRekey { peer } if peer == make_node_addr(0x40))
    );
}

#[test]
fn rekey_resend_due_retransmits_with_backoff() {
    let fmp = Fmp::new();
    let msg1 = vec![0xaa, 0xbb];
    // prior_count=1 -> exponent 2 -> next = 1000 + 500 * 2^2 = 3000.
    let c = rekey_resend_snapshot(0x41, 1, true, msg1.clone());
    let actions = fmp.poll_rekey_resends(vec![c], 1_000, 500, 2.0, 5);
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        ConnAction::ResendRekeyMsg1 {
            peer,
            bytes,
            next_resend_at_ms,
        } => {
            assert_eq!(*peer, make_node_addr(0x41));
            assert_eq!(bytes, &msg1);
            assert_eq!(*next_resend_at_ms, 3_000);
        }
        _ => panic!("expected ResendRekeyMsg1"),
    }
}

#[test]
fn rekey_resend_not_due_is_skipped() {
    let fmp = Fmp::new();
    // Under budget but not due -> no action.
    let c = rekey_resend_snapshot(0x42, 1, false, vec![1]);
    assert!(
        fmp.poll_rekey_resends(vec![c], 1_000, 500, 2.0, 5)
            .is_empty()
    );
}

#[test]
fn rekey_resend_abandons_precede_retransmits() {
    let fmp = Fmp::new();
    let due = rekey_resend_snapshot(0x43, 0, true, vec![1]);
    let over = rekey_resend_snapshot(0x44, 9, true, vec![2]);
    // Input order: due-resend first, then over-budget; output must be
    // abandons-first regardless.
    let actions = fmp.poll_rekey_resends(vec![due, over], 1_000, 500, 2.0, 5);
    assert_eq!(actions.len(), 2);
    assert!(
        matches!(actions[0], ConnAction::AbandonRekey { peer } if peer == make_node_addr(0x44))
    );
    assert!(
        matches!(actions[1], ConnAction::ResendRekeyMsg1 { peer, .. } if peer == make_node_addr(0x43))
    );
}

// ===========================================================================
// XX inbound establish classification (`establish_inbound`).
//
// The 11 framed characterization tests in `node::tests::establish_xx_chartests`
// are the behavior oracle; these exercise the pure decision directly over
// hand-built snapshots, one per branch, with deterministic session ages.
// ===========================================================================

/// No existing peer for this identity -> a net-new promote.
#[test]
fn establish_net_new_promotes() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x05);
    snap.has_existing_peer = false;
    let wire = wire_outcome(0x02, SAME_EPOCH);
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Promote
    ));
}

/// An existing peer at a different startup epoch -> restart then promote.
#[test]
fn establish_epoch_mismatch_restarts() {
    let fmp = Fmp::new();
    let snap = establish_snapshot(0x05); // existing epoch [0x01; 8]
    let wire = wire_outcome(0x02, [0x02; 8]); // new epoch differs
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::RestartThenPromote { peer } => {
            assert_eq!(peer, make_node_addr(0x02));
        }
        other => panic!("expected RestartThenPromote, got {other:?}"),
    }
}

/// Same-epoch, different link, still-fresh session where we are the LARGER node:
/// our inbound wins the inline cross-connection (swap to inbound).
#[test]
fn establish_cross_connection_larger_node_inbound_wins() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x09); // our addr 0x09
    snap.different_link = true;
    snap.existing_session_age_secs = 0; // < floor
    let wire = wire_outcome(0x02, SAME_EPOCH); // peer 0x02 < our 0x09
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::CrossConnect {
            peer,
            our_inbound_wins,
        } => {
            assert_eq!(peer, make_node_addr(0x02));
            assert!(our_inbound_wins, "larger node's inbound wins");
        }
        other => panic!("expected CrossConnect, got {other:?}"),
    }
}

/// Same-epoch, different link, still-fresh session where we are the SMALLER
/// node: our inbound loses (keep the existing outbound session).
#[test]
fn establish_cross_connection_smaller_node_inbound_loses() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x02); // our addr 0x02
    snap.different_link = true;
    snap.existing_session_age_secs = 0;
    let wire = wire_outcome(0x09, SAME_EPOCH); // peer 0x09 > our 0x02
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::CrossConnect {
            our_inbound_wins, ..
        } => assert!(!our_inbound_wins, "smaller node's inbound loses"),
        other => panic!("expected CrossConnect, got {other:?}"),
    }
}

/// Same link (never a cross-connection) with a fresh session and rekey enabled:
/// neither cross-connection (same link) nor rekey (age < floor) -> duplicate.
#[test]
fn establish_same_link_fresh_is_duplicate() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x05);
    snap.different_link = false;
    snap.existing_session_age_secs = 0;
    snap.existing_msg2 = Some(vec![0xaa, 0xbb]);
    let wire = wire_outcome(0x02, SAME_EPOCH);
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::ResendMsg2 { msg2 } => assert_eq!(msg2, Some(vec![0xaa, 0xbb])),
        other => panic!("expected ResendMsg2, got {other:?}"),
    }
}

/// Aged same-epoch session, rekey disabled: not a rekey -> duplicate resend
/// (mirrors the rekey-disabled chartest).
#[test]
fn establish_aged_rekey_disabled_is_duplicate() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x05);
    snap.rekey_enabled = false;
    snap.existing_session_age_secs = 300; // >= floor, but rekey disabled
    let wire = wire_outcome(0x02, SAME_EPOCH);
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::ResendMsg2 { .. }
    ));
}

/// Aged, healthy, same-epoch session with no dual-init in flight -> rekey
/// responder, no prior abandon.
#[test]
fn establish_aged_rekey_responds_without_abandon() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x05);
    snap.existing_session_age_secs = 300; // >= floor
    let wire = wire_outcome(0x02, SAME_EPOCH);
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::RekeyRespond {
            peer,
            abandon_first,
        } => {
            assert_eq!(peer, make_node_addr(0x02));
            assert!(!abandon_first);
        }
        other => panic!("expected RekeyRespond, got {other:?}"),
    }
}

/// Dual-init in the `rekey_in_progress` state, we are the SMALLER node ->
/// tie-break win, drop their msg3.
#[test]
fn establish_dual_init_in_progress_smaller_wins() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x02); // our addr 0x02 (smaller)
    snap.existing_session_age_secs = 300;
    snap.rekey_in_progress = true;
    let wire = wire_outcome(0x09, SAME_EPOCH); // peer 0x09
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Reject {
            reason: InboundReject::DualRekeyWon
        }
    ));
}

/// Dual-init in the `rekey_in_progress` state, we are the LARGER node ->
/// tie-break loss, abandon ours then respond.
#[test]
fn establish_dual_init_in_progress_larger_loses() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x09); // our addr 0x09 (larger)
    snap.existing_session_age_secs = 300;
    snap.rekey_in_progress = true;
    let wire = wire_outcome(0x02, SAME_EPOCH); // peer 0x02
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::RekeyRespond { abandon_first, .. } => assert!(abandon_first),
        other => panic!("expected RekeyRespond{{abandon_first:true}}, got {other:?}"),
    }
}

/// XX-widened dual-init: the `pending_new_session` state (which IK never
/// reached). As the LARGER node we lose -> abandon ours then respond,
/// re-installing pending.
#[test]
fn establish_dual_init_pending_state_larger_loses() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x09); // our addr 0x09 (larger)
    snap.existing_session_age_secs = 300;
    snap.rekey_in_progress = false;
    snap.pending_new_session = true; // the widened window
    let wire = wire_outcome(0x02, SAME_EPOCH);
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::RekeyRespond { abandon_first, .. } => assert!(abandon_first),
        other => panic!("expected RekeyRespond{{abandon_first:true}}, got {other:?}"),
    }
}

/// XX-widened dual-init `pending_new_session` state as the SMALLER node ->
/// tie-break win, drop their msg3.
#[test]
fn establish_dual_init_pending_state_smaller_wins() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x02); // our addr 0x02 (smaller)
    snap.existing_session_age_secs = 300;
    snap.pending_new_session = true;
    let wire = wire_outcome(0x09, SAME_EPOCH);
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Reject {
            reason: InboundReject::DualRekeyWon
        }
    ));
}

/// The rekey floor partitions cross-connection from rekey exactly at the
/// boundary: one second below is a cross-connection, at the floor is a rekey.
#[test]
fn establish_rekey_floor_partitions_cross_connection_and_rekey() {
    let fmp = Fmp::new();
    let wire = wire_outcome(0x02, SAME_EPOCH);

    let mut below = establish_snapshot(0x09);
    below.different_link = true;
    below.rekey_age_floor_secs = 100;
    below.existing_session_age_secs = 99;
    assert!(matches!(
        fmp.establish_inbound(&below, &wire),
        InboundDecision::CrossConnect { .. }
    ));

    let mut at = establish_snapshot(0x09);
    at.different_link = true;
    at.rekey_age_floor_secs = 100;
    at.existing_session_age_secs = 100;
    assert!(matches!(
        fmp.establish_inbound(&at, &wire),
        InboundDecision::RekeyRespond { .. }
    ));
}

/// An unhealthy or session-less aged peer is not a rekey candidate -> duplicate.
#[test]
fn establish_aged_unhealthy_is_duplicate() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot(0x05);
    snap.existing_session_age_secs = 300;
    snap.is_healthy = false;
    let wire = wire_outcome(0x02, SAME_EPOCH);
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::ResendMsg2 { .. }
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
        our_outbound_wins: true,
    };
    assert_eq!(fmp.establish_outbound(&snap), OutboundDecision::Promote);
}

#[test]
fn establish_outbound_cross_connection_win_swaps() {
    let fmp = Fmp::new();
    let snap = OutboundSnapshot {
        has_existing_peer: true,
        our_outbound_wins: true,
    };
    assert_eq!(
        fmp.establish_outbound(&snap),
        OutboundDecision::CrossConnectionSwap
    );
}

#[test]
fn establish_outbound_cross_connection_loss_keeps() {
    let fmp = Fmp::new();
    let snap = OutboundSnapshot {
        has_existing_peer: true,
        our_outbound_wins: false,
    };
    assert_eq!(
        fmp.establish_outbound(&snap),
        OutboundDecision::CrossConnectionKeep
    );
}

// ===== cross_connection_winner tie-break tests =====

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

// ===== Negotiation decision tests (relocated from protocol::negotiation) =====

#[test]
fn test_version_agreement_basic() {
    let ours = NegotiationPayload::new(1, 3, 0);
    let theirs = NegotiationPayload::new(1, 2, 0);
    assert_eq!(ours.agree_version(&theirs).unwrap(), 2);
}

#[test]
fn test_version_agreement_mismatch() {
    let ours = NegotiationPayload::new(3, 5, 0);
    let theirs = NegotiationPayload::new(1, 2, 0);
    assert!(ours.agree_version(&theirs).is_err());
}

#[test]
fn test_version_agreement_asymmetric() {
    let ours = NegotiationPayload::new(2, 5, 0);
    let theirs = NegotiationPayload::new(1, 4, 0);
    assert_eq!(ours.agree_version(&theirs).unwrap(), 4);
    assert_eq!(theirs.agree_version(&ours).unwrap(), 4);
}

#[test]
fn test_fmp_payload_full_profile() {
    let p = NegotiationPayload::fmp(1, 1, NodeProfile::Full);
    assert_eq!(p.node_profile().unwrap(), NodeProfile::Full);
    assert!(p.provides_sr());
    assert!(p.provides_rr());
    assert!(p.wants_sr());
    assert!(p.wants_rr());
}

#[test]
fn test_fmp_payload_nonrouting_profile() {
    let p = NegotiationPayload::fmp(1, 1, NodeProfile::NonRouting);
    assert_eq!(p.node_profile().unwrap(), NodeProfile::NonRouting);
    assert!(p.provides_sr());
    assert!(p.provides_rr());
    assert!(!p.wants_sr());
    assert!(p.wants_rr());
}

#[test]
fn test_fmp_payload_leaf_profile() {
    let p = NegotiationPayload::fmp(1, 1, NodeProfile::Leaf);
    assert_eq!(p.node_profile().unwrap(), NodeProfile::Leaf);
    assert!(!p.provides_sr());
    assert!(p.provides_rr());
    assert!(!p.wants_sr());
    assert!(!p.wants_rr());
}

#[test]
fn test_fmp_payload_roundtrip() {
    for profile in [
        NodeProfile::Full,
        NodeProfile::NonRouting,
        NodeProfile::Leaf,
    ] {
        let original = NegotiationPayload::fmp(1, 1, profile);
        let encoded = original.encode();
        let decoded = NegotiationPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.node_profile().unwrap(), profile);
    }
}

#[test]
fn test_zero_features_is_full() {
    let p = NegotiationPayload::new(1, 1, 0);
    assert_eq!(p.node_profile().unwrap(), NodeProfile::Full);
    assert!(!p.provides_sr());
    assert!(!p.wants_sr());
}

#[test]
fn test_validate_profiles_valid() {
    assert!(NegotiationPayload::validate_profiles(NodeProfile::Full, NodeProfile::Full).is_ok());
    assert!(
        NegotiationPayload::validate_profiles(NodeProfile::Full, NodeProfile::NonRouting).is_ok()
    );
    assert!(
        NegotiationPayload::validate_profiles(NodeProfile::NonRouting, NodeProfile::Full).is_ok()
    );
    assert!(NegotiationPayload::validate_profiles(NodeProfile::Full, NodeProfile::Leaf).is_ok());
    assert!(NegotiationPayload::validate_profiles(NodeProfile::Leaf, NodeProfile::Full).is_ok());
}

#[test]
fn test_validate_profiles_invalid() {
    assert!(
        NegotiationPayload::validate_profiles(NodeProfile::NonRouting, NodeProfile::NonRouting)
            .is_err()
    );
    assert!(
        NegotiationPayload::validate_profiles(NodeProfile::NonRouting, NodeProfile::Leaf).is_err()
    );
    assert!(
        NegotiationPayload::validate_profiles(NodeProfile::Leaf, NodeProfile::NonRouting).is_err()
    );
    assert!(NegotiationPayload::validate_profiles(NodeProfile::Leaf, NodeProfile::Leaf).is_err());
}
