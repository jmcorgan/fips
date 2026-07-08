//! Tests for the pure FSP session-rekey + epoch-reaction decision core.

use crate::FipsAddress;
use crate::proto::fsp::core::{
    DecryptSlot, EpochReaction, Fsp, FspAction, RekeyCfg, RekeyMsg3ResendSnapshot, SessionSnapshot,
    cutover_timer_elapsed, initiation_winner, mark_ipv6_ecn_ce, push_bounded_pending,
    should_apply_path_mtu,
};
use crate::proto::fsp::limits::FSP_CUTOVER_DELAY_MS;
use crate::proto::stp::TreeCoordinate;
use crate::testutil::make_node_addr;
use std::collections::VecDeque;

fn coords(byte: u8) -> TreeCoordinate {
    TreeCoordinate::from_addrs(vec![make_node_addr(byte)]).unwrap()
}

/// A quiescent established-session snapshot: no pending cutover, no drain, no
/// dampening, zero ages/counter/jitter. Tests set only the fields they exercise.
fn session_snapshot(addr_byte: u8) -> SessionSnapshot {
    SessionSnapshot {
        addr: make_node_addr(addr_byte),
        has_pending: false,
        rekey_in_progress: false,
        is_rekey_initiator: false,
        cutover_timer_elapsed: false,
        is_draining: false,
        drain_expired: false,
        has_rekey_msg3_payload: false,
        is_dampened: false,
        elapsed_secs: 0,
        counter: 0,
        jitter_secs: 0,
    }
}

fn cfg(after_secs: u64, after_messages: u64) -> RekeyCfg {
    RekeyCfg {
        after_secs,
        after_messages,
    }
}

// ===== poll_rekey =====

#[test]
fn poll_rekey_quiescent_emits_nothing() {
    let fsp = Fsp::new();
    let snaps = vec![session_snapshot(1), session_snapshot(2)];
    assert!(fsp.poll_rekey(snaps, &cfg(100, 1000)).is_empty());
}

#[test]
fn poll_rekey_initiator_cutover_when_timer_elapsed() {
    let fsp = Fsp::new();
    let mut s = session_snapshot(1);
    s.has_pending = true;
    s.is_rekey_initiator = true;
    s.cutover_timer_elapsed = true;
    assert_eq!(
        fsp.poll_rekey(vec![s], &cfg(100, 1000)),
        vec![FspAction::CutOver {
            addr: make_node_addr(1)
        }]
    );
}

#[test]
fn poll_rekey_no_cutover_before_timer_or_when_rekey_in_progress() {
    let fsp = Fsp::new();
    // Timer not elapsed → no cutover.
    let mut s = session_snapshot(1);
    s.has_pending = true;
    s.is_rekey_initiator = true;
    s.cutover_timer_elapsed = false;
    assert!(fsp.poll_rekey(vec![s], &cfg(100, 1000)).is_empty());

    // Rekey still in progress → no cutover (and pending guards the trigger).
    let mut s = session_snapshot(1);
    s.has_pending = true;
    s.is_rekey_initiator = true;
    s.cutover_timer_elapsed = true;
    s.rekey_in_progress = true;
    assert!(fsp.poll_rekey(vec![s], &cfg(100, 1000)).is_empty());

    // Responder side (not initiator) → no cutover.
    let mut s = session_snapshot(1);
    s.has_pending = true;
    s.cutover_timer_elapsed = true;
    assert!(fsp.poll_rekey(vec![s], &cfg(100, 1000)).is_empty());
}

#[test]
fn poll_rekey_completes_expired_drain() {
    let fsp = Fsp::new();
    let mut s = session_snapshot(3);
    s.is_draining = true;
    s.drain_expired = true;
    assert_eq!(
        fsp.poll_rekey(vec![s], &cfg(100, 1000)),
        vec![FspAction::CompleteDrain {
            addr: make_node_addr(3)
        }]
    );
}

#[test]
fn poll_rekey_trigger_on_time_or_counter() {
    let fsp = Fsp::new();
    // Time threshold reached.
    let mut s = session_snapshot(4);
    s.elapsed_secs = 100;
    assert_eq!(
        fsp.poll_rekey(vec![s], &cfg(100, 1000)),
        vec![FspAction::InitiateRekey {
            addr: make_node_addr(4)
        }]
    );
    // Counter threshold reached, time not.
    let mut s = session_snapshot(4);
    s.counter = 1000;
    assert_eq!(
        fsp.poll_rekey(vec![s], &cfg(100, 1000)),
        vec![FspAction::InitiateRekey {
            addr: make_node_addr(4)
        }]
    );
    // Neither reached.
    let mut s = session_snapshot(4);
    s.elapsed_secs = 99;
    s.counter = 999;
    assert!(fsp.poll_rekey(vec![s], &cfg(100, 1000)).is_empty());
}

#[test]
fn poll_rekey_jitter_shifts_time_threshold() {
    let fsp = Fsp::new();
    // Positive jitter raises the effective threshold above the config value.
    let mut s = session_snapshot(5);
    s.elapsed_secs = 100;
    s.jitter_secs = 5;
    assert!(fsp.poll_rekey(vec![s], &cfg(100, 1000)).is_empty());
    // Negative jitter lowers it.
    let mut s = session_snapshot(5);
    s.elapsed_secs = 96;
    s.jitter_secs = -5;
    assert_eq!(
        fsp.poll_rekey(vec![s], &cfg(100, 1000)),
        vec![FspAction::InitiateRekey {
            addr: make_node_addr(5)
        }]
    );
}

#[test]
fn poll_rekey_trigger_suppressed_by_guards() {
    let fsp = Fsp::new();
    for set in [
        |s: &mut SessionSnapshot| s.rekey_in_progress = true,
        |s: &mut SessionSnapshot| s.has_pending = true,
        |s: &mut SessionSnapshot| s.has_rekey_msg3_payload = true,
        |s: &mut SessionSnapshot| s.is_dampened = true,
    ] {
        let mut s = session_snapshot(6);
        s.elapsed_secs = 1000;
        set(&mut s);
        assert!(
            fsp.poll_rekey(vec![s], &cfg(100, 1000)).is_empty(),
            "trigger must be suppressed by its guard"
        );
    }
}

#[test]
fn poll_rekey_cutover_precludes_drain_and_trigger_but_phase_grouped() {
    let fsp = Fsp::new();
    // One session eligible for cutover, another draining, another triggering.
    let mut a = session_snapshot(1);
    a.has_pending = true;
    a.is_rekey_initiator = true;
    a.cutover_timer_elapsed = true;
    let mut b = session_snapshot(2);
    b.is_draining = true;
    b.drain_expired = true;
    let mut c = session_snapshot(3);
    c.counter = 5000;
    let actions = fsp.poll_rekey(vec![a, b, c], &cfg(100, 1000));
    assert_eq!(
        actions,
        vec![
            FspAction::CutOver {
                addr: make_node_addr(1)
            },
            FspAction::CompleteDrain {
                addr: make_node_addr(2)
            },
            FspAction::InitiateRekey {
                addr: make_node_addr(3)
            },
        ],
        "phase grouped: all cutovers, then drains, then rekeys"
    );
}

// ===== poll_rekey_msg3_resends =====

fn msg3_snapshot(addr_byte: u8, resend_count: u32, resend_due: bool) -> RekeyMsg3ResendSnapshot {
    RekeyMsg3ResendSnapshot {
        addr: make_node_addr(addr_byte),
        resend_count,
        resend_due,
    }
}

#[test]
fn poll_msg3_not_due_is_noop() {
    let fsp = Fsp::new();
    assert!(
        fsp.poll_rekey_msg3_resends(vec![msg3_snapshot(1, 0, false)], 3)
            .is_empty()
    );
    // Not due even past the budget: neither abandon nor resend this tick.
    assert!(
        fsp.poll_rekey_msg3_resends(vec![msg3_snapshot(1, 99, false)], 3)
            .is_empty()
    );
}

#[test]
fn poll_msg3_resend_when_due_in_budget() {
    let fsp = Fsp::new();
    assert_eq!(
        fsp.poll_rekey_msg3_resends(vec![msg3_snapshot(2, 1, true)], 3),
        vec![FspAction::ResendSessionMsg3 {
            addr: make_node_addr(2)
        }]
    );
}

#[test]
fn poll_msg3_abandon_at_budget() {
    let fsp = Fsp::new();
    assert_eq!(
        fsp.poll_rekey_msg3_resends(vec![msg3_snapshot(3, 3, true)], 3),
        vec![FspAction::AbandonRekey {
            addr: make_node_addr(3)
        }]
    );
}

#[test]
fn poll_msg3_abandons_first() {
    let fsp = Fsp::new();
    let actions = fsp.poll_rekey_msg3_resends(
        vec![msg3_snapshot(1, 0, true), msg3_snapshot(2, 5, true)],
        3,
    );
    assert_eq!(
        actions,
        vec![
            FspAction::AbandonRekey {
                addr: make_node_addr(2)
            },
            FspAction::ResendSessionMsg3 {
                addr: make_node_addr(1)
            },
        ],
        "abandons are grouped before resends"
    );
}

// ===== classify_epoch =====

#[test]
fn classify_epoch_pending_promotes_confirming_with_retained_msg3() {
    let fsp = Fsp::new();
    assert_eq!(
        fsp.classify_epoch(DecryptSlot::Pending, true, true),
        EpochReaction::PromoteConfirming
    );
    assert_eq!(
        fsp.classify_epoch(DecryptSlot::Pending, false, true),
        EpochReaction::Promote
    );
}

#[test]
fn classify_epoch_current_confirms_responder_only_when_cut_over() {
    let fsp = Fsp::new();
    // Initiator cut over (msg3 retained, no pending) → confirm.
    assert_eq!(
        fsp.classify_epoch(DecryptSlot::Current, true, false),
        EpochReaction::ConfirmResponder
    );
    // msg3 retained but still holding pending → no confirm.
    assert_eq!(
        fsp.classify_epoch(DecryptSlot::Current, true, true),
        EpochReaction::None
    );
    // Steady state → no reaction.
    assert_eq!(
        fsp.classify_epoch(DecryptSlot::Current, false, false),
        EpochReaction::None
    );
}

#[test]
fn classify_epoch_previous_is_noop() {
    let fsp = Fsp::new();
    assert_eq!(
        fsp.classify_epoch(DecryptSlot::Previous, true, true),
        EpochReaction::None
    );
}

// ===== pure helpers =====

#[test]
fn initiation_winner_smaller_addr_wins() {
    let small = make_node_addr(1);
    let large = make_node_addr(2);
    assert!(initiation_winner(&small, &large));
    assert!(!initiation_winner(&large, &small));
}

#[test]
fn cutover_timer_boundary() {
    assert!(!cutover_timer_elapsed(
        1_000 + FSP_CUTOVER_DELAY_MS - 1,
        1_000
    ));
    assert!(cutover_timer_elapsed(1_000 + FSP_CUTOVER_DELAY_MS, 1_000));
}

// ===== coords / MTU emit-policy =====

#[test]
fn plan_cache_coords_emits_present_in_order() {
    let fsp = Fsp::new();
    let src = make_node_addr(1);
    let me = make_node_addr(2);
    // Both present: src keyed by src_addr, dest keyed by my_addr, in order.
    assert_eq!(
        fsp.plan_cache_coords(src, me, Some(coords(3)), Some(coords(4))),
        vec![
            FspAction::CacheCoords {
                addr: src,
                coords: coords(3)
            },
            FspAction::CacheCoords {
                addr: me,
                coords: coords(4)
            },
        ]
    );
    // Only source present.
    assert_eq!(
        fsp.plan_cache_coords(src, me, Some(coords(3)), None),
        vec![FspAction::CacheCoords {
            addr: src,
            coords: coords(3)
        }]
    );
    // Neither present.
    assert!(fsp.plan_cache_coords(src, me, None, None).is_empty());
}

#[test]
fn plan_coords_required_lookup_gated_on_identity() {
    let fsp = Fsp::new();
    let dest = make_node_addr(5);
    assert_eq!(
        fsp.plan_coords_required_lookup(dest, true),
        vec![FspAction::InitiateLookup { dest }]
    );
    assert!(fsp.plan_coords_required_lookup(dest, false).is_empty());
}

#[test]
fn plan_path_broken_invalidates_then_lookups() {
    let fsp = Fsp::new();
    let dest = make_node_addr(6);
    // Cached identity: invalidate, then lookup — in that order.
    assert_eq!(
        fsp.plan_path_broken(dest, true),
        vec![
            FspAction::InvalidateCoords { addr: dest },
            FspAction::InitiateLookup { dest },
        ]
    );
    // No cached identity: invalidate only (still unconditional).
    assert_eq!(
        fsp.plan_path_broken(dest, false),
        vec![FspAction::InvalidateCoords { addr: dest }]
    );
}

#[test]
fn plan_path_mtu_tighten_emits_only_when_tighter() {
    let fsp = Fsp::new();
    let fa = FipsAddress::from_node_addr(&make_node_addr(7));
    // No existing, or candidate tighter → emit.
    assert_eq!(
        fsp.plan_path_mtu_tighten(fa, None, 1400),
        vec![FspAction::TightenPathMtuLookup {
            fips_addr: fa,
            mtu: 1400
        }]
    );
    assert_eq!(
        fsp.plan_path_mtu_tighten(fa, Some(1500), 1400),
        vec![FspAction::TightenPathMtuLookup {
            fips_addr: fa,
            mtu: 1400
        }]
    );
    // Existing already tighter or equal → keep, emit nothing.
    assert!(fsp.plan_path_mtu_tighten(fa, Some(1300), 1400).is_empty());
    assert!(fsp.plan_path_mtu_tighten(fa, Some(1400), 1400).is_empty());
}

#[test]
fn should_apply_path_mtu_keeps_tighter() {
    assert!(should_apply_path_mtu(None, 1400)); // no existing → apply
    assert!(should_apply_path_mtu(Some(1500), 1400)); // candidate tighter → apply
    assert!(!should_apply_path_mtu(Some(1300), 1400)); // existing tighter → keep
    assert!(!should_apply_path_mtu(Some(1400), 1400)); // equal → keep
}

#[test]
fn push_bounded_pending_drops_oldest_at_capacity() {
    let mut q: VecDeque<Vec<u8>> = VecDeque::new();
    push_bounded_pending(&mut q, vec![1], 2);
    push_bounded_pending(&mut q, vec![2], 2);
    push_bounded_pending(&mut q, vec![3], 2); // drops [1]
    assert_eq!(q.len(), 2);
    assert_eq!(q.front(), Some(&vec![2]));
    assert_eq!(q.back(), Some(&vec![3]));
}

#[test]
fn mark_ipv6_ecn_ce_marks_only_ect() {
    // ECT(0): TC low bits 0b10. Byte1 high nibble carries TC[3:0].
    let mut ect0 = [0x60, 0x20, 0, 0];
    mark_ipv6_ecn_ce(&mut ect0);
    assert_eq!(ect0[1] & 0x30, 0x30, "ECN bits set to CE");

    // Not-ECT (ECN 0b00) is never marked.
    let mut not_ect = [0x60, 0x00, 0, 0];
    mark_ipv6_ecn_ce(&mut not_ect);
    assert_eq!(not_ect[1] & 0x30, 0x00, "Not-ECT stays unmarked");

    // Too short → no panic, no change.
    let mut short = [0x60];
    mark_ipv6_ecn_ce(&mut short);
    assert_eq!(short, [0x60]);
}
