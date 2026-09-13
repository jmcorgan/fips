//! Tests for the sans-IO FMP connection-lifecycle decision core.

use super::util::{
    establish_snapshot, peer_snapshot, rekey_resend_snapshot, resend_snapshot, stale_snapshot,
    wire_outcome,
};
use crate::NodeAddr;
use crate::proto::fmp::{
    ConnAction, Fmp, InboundDecision, InboundReject, OutboundDecision, OutboundSnapshot, RekeyCfg,
    RekeyRole, cross_connection_winner,
};
use crate::testutil::make_node_addr;
use crate::transport::LinkId;

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
    p.pending_role = Some(RekeyRole::Initiator);
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

/// The send-counter arm of the rekey trigger, pinned at its boundary through
/// the real `poll_rekey` rather than a reimplementation of its predicate.
///
/// Firing at the threshold catches the arm being deleted, its comparison
/// narrowed to `>`, or its comparison inverted. The silence-below half is what
/// this test adds over that: it catches the arm being *widened* below its
/// configured bound. Measured rather than assumed — replacing the bound with
/// `p.counter >= 1` reds exactly one test in the whole library suite, this one,
/// while a bound removed altogether is already caught by the time arm's own
/// negative tests.
///
/// The time arm is held off in both halves — `elapsed_secs` stays 0 against a
/// 100 s threshold with no jitter — so the counter is provably what decides.
#[test]
fn rekey_counter_arm_fires_at_threshold_and_is_silent_below() {
    let fmp = Fmp::new();

    let mut below = peer_snapshot(0x13);
    below.counter = 999; // one below after_messages
    assert!(
        fmp.poll_rekey(vec![below], &cfg()).is_empty(),
        "a send counter one below the threshold must not trigger a rekey"
    );

    let mut at = peer_snapshot(0x13);
    at.counter = 1_000; // == after_messages
    let actions = fmp.poll_rekey(vec![at], &cfg());
    assert!(
        matches!(actions[0], ConnAction::InitiateRekey { .. }),
        "a send counter at the threshold must trigger a rekey"
    );
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
fn rekey_actions_are_phase_grouped_across_peers() {
    let fmp = Fmp::new();
    // Peer A: trigger only. Peer B: cutover. Peer C: drain + trigger.
    let mut a = peer_snapshot(0x01);
    a.elapsed_secs = 200;
    let mut b = peer_snapshot(0x02);
    b.has_pending = true;
    b.pending_role = Some(RekeyRole::Initiator);
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
// establish_inbound — inbound msg1 classification (E3)
// ===========================================================================

/// All-0xFF NodeAddr: strictly greater than any pubkey-derived peer addr, so a
/// tie-break with `our_node_addr` set to this makes us the larger side.
fn max_node_addr() -> NodeAddr {
    NodeAddr::from_bytes([0xFF; 16])
}

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
fn establish_inbound_at_cap_with_pending_outbound_bypasses_and_promotes() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.at_max_peers = true;
    snap.has_pending_outbound_to_peer = true;
    let wire = wire_outcome(Some([1u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Promote
    ));
}

#[test]
fn establish_inbound_at_cap_existing_peer_not_capped() {
    // At cap but the identity is already a peer → the cap gate is bypassed and
    // the same-epoch classification runs (here: a duplicate resend).
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.at_max_peers = true;
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([9u8; 8]);
    snap.existing_msg2 = Some(vec![0xAB, 0xCD]);
    let wire = wire_outcome(Some([9u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::ResendMsg2 { .. }
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

#[test]
fn establish_inbound_same_epoch_young_session_resends() {
    // Same epoch but session younger than the rekey gate → duplicate resend,
    // carrying the stored msg2 bytes verbatim.
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([7u8; 8]);
    snap.has_session = true;
    snap.existing_session_age_secs = 5;
    snap.existing_msg2 = Some(vec![0x01, 0x02, 0x03]);
    let wire = wire_outcome(Some([7u8; 8]));
    match fmp.establish_inbound(&snap, &wire) {
        InboundDecision::ResendMsg2 { msg2 } => {
            assert_eq!(msg2.as_deref(), Some(&[0x01, 0x02, 0x03][..]));
        }
        other => panic!("expected ResendMsg2, got a different variant: {other:?}"),
    }
}

#[test]
fn establish_inbound_aged_session_rekey_responds() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([7u8; 8]);
    snap.has_session = true;
    snap.existing_session_age_secs = 31;
    let wire = wire_outcome(Some([7u8; 8]));
    let peer = *wire.peer_identity.node_addr();
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::RekeyRespond { peer: p, abandon_first: false } if p == peer
    ));
}

#[test]
fn establish_inbound_rekey_gate_requires_enabled() {
    // Aged session but rekey disabled → same-epoch msg1 is a duplicate,
    // not a rekey.
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([7u8; 8]);
    snap.has_session = true;
    snap.existing_session_age_secs = 31;
    snap.rekey_enabled = false;
    let wire = wire_outcome(Some([7u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::ResendMsg2 { .. }
    ));
}

#[test]
fn establish_inbound_rekey_gate_boundary_at_30s() {
    // Exactly 30s satisfies `>= 30` → rekey; 29s does not → duplicate.
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([7u8; 8]);
    snap.has_session = true;
    let wire = wire_outcome(Some([7u8; 8]));

    snap.existing_session_age_secs = 30;
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::RekeyRespond { .. }
    ));

    snap.existing_session_age_secs = 29;
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::ResendMsg2 { .. }
    ));
}

#[test]
fn establish_inbound_pending_session_rejects() {
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([7u8; 8]);
    snap.has_session = true;
    snap.existing_session_age_secs = 31;
    snap.pending_new_session = true;
    let wire = wire_outcome(Some([7u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Reject {
            reason: InboundReject::PendingSession
        }
    ));
}

#[test]
fn establish_inbound_dual_init_we_win_rejects() {
    // rekey in progress + our addr < peer addr (our = 0x10, peer = pubkey-derived
    // non-zero) → we win, drop theirs.
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([7u8; 8]);
    snap.has_session = true;
    snap.existing_session_age_secs = 31;
    snap.rekey_in_progress = true;
    snap.our_node_addr = make_node_addr(0x00); // minimal → strictly smaller
    let wire = wire_outcome(Some([7u8; 8]));
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::Reject {
            reason: InboundReject::DualRekeyWon
        }
    ));
}

#[test]
fn establish_inbound_dual_init_we_lose_responds_with_abandon() {
    // rekey in progress + our addr > peer addr → we lose, abandon ours and
    // respond as responder.
    let fmp = Fmp::new();
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([7u8; 8]);
    snap.has_session = true;
    snap.existing_session_age_secs = 31;
    snap.rekey_in_progress = true;
    snap.our_node_addr = max_node_addr(); // strictly larger than any peer addr
    let wire = wire_outcome(Some([7u8; 8]));
    let peer = *wire.peer_identity.node_addr();
    assert!(matches!(
        fmp.establish_inbound(&snap, &wire),
        InboundDecision::RekeyRespond { peer: p, abandon_first: true } if p == peer
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

/// A pending session this node answered, held past the responder hold, is
/// retired, and the tick neither cuts it over nor starts a rekey of its own.
#[test]
fn a_responder_held_pending_past_its_hold_is_retired_and_nothing_else_fires() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x20);
    p.has_pending = true;
    p.pending_role = Some(RekeyRole::Responder);
    p.pending_expired = true;
    p.elapsed_secs = 10_000;
    p.counter = 10_000;
    let actions = fmp.poll_rekey(vec![p], &cfg());
    assert_eq!(actions.len(), 1);
    assert!(
        matches!(actions[0], ConnAction::RetirePending { peer } if peer == make_node_addr(0x20))
    );
}

/// A pending session this node answered, still inside its hold, is left
/// alone: no cutover, no retirement, and no rekey trigger even with both
/// thresholds met, since a new cycle would overwrite the held slot.
#[test]
fn a_responder_held_pending_inside_its_hold_is_neither_cut_over_nor_allowed_to_trigger() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x21);
    p.has_pending = true;
    p.pending_role = Some(RekeyRole::Responder);
    p.pending_expired = false;
    p.elapsed_secs = 10_000;
    p.counter = 10_000;
    assert!(fmp.poll_rekey(vec![p], &cfg()).is_empty());
}

/// A pending session this node initiated is cut over even when its hold
/// reads as passed: retirement never touches the initiator's pending.
#[test]
fn an_initiator_held_pending_cuts_over_even_when_its_hold_has_passed() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x22);
    p.has_pending = true;
    p.pending_role = Some(RekeyRole::Initiator);
    p.pending_expired = true;
    let actions = fmp.poll_rekey(vec![p], &cfg());
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConnAction::Cutover { peer } if peer == make_node_addr(0x22)));
}

/// A pending session with no recorded role fails safe: it is held like a
/// responder's, never cut over by the tick, and vetoes the rekey trigger.
#[test]
fn a_pending_with_no_recorded_role_is_held_and_never_cut_over_by_the_tick() {
    let fmp = Fmp::new();
    let mut p = peer_snapshot(0x23);
    p.has_pending = true;
    p.pending_role = None;
    p.pending_expired = false;
    p.elapsed_secs = 10_000;
    p.counter = 10_000;
    assert!(fmp.poll_rekey(vec![p], &cfg()).is_empty());
}

/// Retirements free an index, so they are grouped after drains (which free)
/// and before rekey initiations (which allocate): cutovers, drains,
/// retirements, rekeys.
#[test]
fn retirements_are_grouped_after_drains_and_before_rekey_initiations() {
    let fmp = Fmp::new();
    // a: trigger only. b: initiator cutover. c: drain and trigger. d: retire.
    let mut a = peer_snapshot(0x01);
    a.elapsed_secs = 200;
    let mut b = peer_snapshot(0x02);
    b.has_pending = true;
    b.pending_role = Some(RekeyRole::Initiator);
    let mut c = peer_snapshot(0x03);
    c.is_draining = true;
    c.drain_expired = true;
    c.counter = 5_000;
    let mut d = peer_snapshot(0x04);
    d.has_pending = true;
    d.pending_role = Some(RekeyRole::Responder);
    d.pending_expired = true;
    let actions = fmp.poll_rekey(vec![a, b, c, d], &cfg());
    assert_eq!(actions.len(), 5);
    assert!(matches!(actions[0], ConnAction::Cutover { peer } if peer == make_node_addr(0x02)));
    assert!(matches!(actions[1], ConnAction::Drain { peer } if peer == make_node_addr(0x03)));
    assert!(
        matches!(actions[2], ConnAction::RetirePending { peer } if peer == make_node_addr(0x04))
    );
    assert!(
        matches!(actions[3], ConnAction::InitiateRekey { peer } if peer == make_node_addr(0x01))
    );
    assert!(
        matches!(actions[4], ConnAction::InitiateRekey { peer } if peer == make_node_addr(0x03))
    );
}

#[test]
fn a_live_peer_s_msg1_is_classified_the_same_on_every_transport() {
    // Same epoch, session old enough to rekey. The transport the msg1
    // arrived on is not an input: a handshake never creates path state, so
    // a live peer dialling over a second transport is the rekey it looks
    // like, exactly as a dial over the first would be. Both ends then
    // decide from the same facts.
    let mut snap = establish_snapshot();
    snap.has_existing_peer = true;
    snap.existing_peer_epoch = Some([1u8; 8]);
    snap.has_session = true;
    snap.existing_session_age_secs = 31;
    let wire = wire_outcome(Some([1u8; 8]));
    assert!(matches!(
        Fmp::new().establish_inbound(&snap, &wire),
        InboundDecision::RekeyRespond { .. }
    ));

    // A restart is a restart, whatever transport it arrives on.
    let restarted = wire_outcome(Some([2u8; 8]));
    assert!(matches!(
        Fmp::new().establish_inbound(&snap, &restarted),
        InboundDecision::RestartThenPromote { .. }
    ));
}
