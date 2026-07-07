//! Tests for the sans-IO MMP reporting decision core.

use crate::proto::mmp::{
    BackoffUpdate, LinkReportKind, LinkReportSnapshot, Mmp, MmpAction, MmpMode,
    PeerLivenessSnapshot, SendResult, SessionReportKind, SessionReportSnapshot,
};
use crate::testutil::make_node_addr;

/// Build a liveness snapshot for `peer` with the three pre-evaluated predicates.
fn snap(
    peer: u8,
    time_dead: bool,
    rekey_active: bool,
    heartbeat_due: bool,
) -> PeerLivenessSnapshot {
    PeerLivenessSnapshot {
        peer: make_node_addr(peer),
        time_dead,
        rekey_active,
        heartbeat_due,
    }
}

#[test]
fn empty_snapshot_set_yields_no_actions() {
    let mmp = Mmp::new();
    assert!(mmp.plan_heartbeats(&[]).is_empty());
}

#[test]
fn dead_peer_is_reaped_and_not_heartbeated() {
    let mmp = Mmp::new();
    // time_dead, no rekey, heartbeat also nominally due: reap wins, no heartbeat.
    let actions = mmp.plan_heartbeats(&[snap(0x11, true, false, true)]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], MmpAction::ReapPeer { peer } if peer == make_node_addr(0x11)));
}

#[test]
fn rekey_active_suppresses_reap_even_when_dead() {
    let mmp = Mmp::new();
    // time_dead but rekey in flight → not reaped; heartbeat still gated on due.
    let actions = mmp.plan_heartbeats(&[snap(0x22, true, true, false)]);
    assert!(actions.is_empty());
}

#[test]
fn rekey_active_and_dead_and_due_sends_heartbeat_not_reap() {
    let mmp = Mmp::new();
    // Rekey suppresses the reap; the peer is alive for scheduling and due.
    let actions = mmp.plan_heartbeats(&[snap(0x23, true, true, true)]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], MmpAction::Heartbeat { peer } if peer == make_node_addr(0x23)));
}

#[test]
fn alive_due_peer_gets_heartbeat() {
    let mmp = Mmp::new();
    let actions = mmp.plan_heartbeats(&[snap(0x33, false, false, true)]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], MmpAction::Heartbeat { peer } if peer == make_node_addr(0x33)));
}

#[test]
fn alive_peer_not_due_yields_no_action() {
    let mmp = Mmp::new();
    assert!(
        mmp.plan_heartbeats(&[snap(0x44, false, false, false)])
            .is_empty()
    );
}

#[test]
fn reaps_precede_heartbeats_in_returned_order() {
    let mmp = Mmp::new();
    // Mixed set in peer order: alive-due, dead, alive-due, dead. The returned
    // Vec must group all reaps first, then all heartbeats (the pre-refactor
    // two-loop order).
    let actions = mmp.plan_heartbeats(&[
        snap(0x01, false, false, true),
        snap(0x02, true, false, false),
        snap(0x03, false, false, true),
        snap(0x04, true, false, false),
    ]);
    assert_eq!(actions.len(), 4);
    assert!(matches!(actions[0], MmpAction::ReapPeer { peer } if peer == make_node_addr(0x02)));
    assert!(matches!(actions[1], MmpAction::ReapPeer { peer } if peer == make_node_addr(0x04)));
    assert!(matches!(actions[2], MmpAction::Heartbeat { peer } if peer == make_node_addr(0x01)));
    assert!(matches!(actions[3], MmpAction::Heartbeat { peer } if peer == make_node_addr(0x03)));
}

// ===========================================================================
// plan_link_reports — link-layer report fan-out
// ===========================================================================

/// Build a link-report snapshot for `peer` with the mode, profile flags, and
/// pre-evaluated timing gates.
#[allow(clippy::too_many_arguments)]
fn link_snap(
    peer: u8,
    mode: MmpMode,
    send_sr: bool,
    send_rr: bool,
    sr_due: bool,
    rr_due: bool,
    log_due: bool,
) -> LinkReportSnapshot {
    LinkReportSnapshot {
        peer: make_node_addr(peer),
        mode,
        send_sr,
        send_rr,
        sr_due,
        rr_due,
        log_due,
    }
}

#[test]
fn link_empty_snapshot_set_yields_no_actions() {
    let mmp = Mmp::new();
    assert!(mmp.plan_link_reports(&[]).is_empty());
}

#[test]
fn link_full_mode_emits_sender_then_receiver() {
    let mmp = Mmp::new();
    let actions = mmp.plan_link_reports(&[link_snap(
        0x11,
        MmpMode::Full,
        true,
        true,
        true,
        true,
        false,
    )]);
    assert_eq!(actions.len(), 2);
    assert!(matches!(
        actions[0],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Sender } if peer == make_node_addr(0x11)
    ));
    assert!(matches!(
        actions[1],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Receiver } if peer == make_node_addr(0x11)
    ));
}

#[test]
fn link_lightweight_mode_emits_receiver_only() {
    let mmp = Mmp::new();
    let actions = mmp.plan_link_reports(&[link_snap(
        0x22,
        MmpMode::Lightweight,
        true,
        true,
        true,
        true,
        false,
    )]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        actions[0],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Receiver } if peer == make_node_addr(0x22)
    ));
}

#[test]
fn link_minimal_mode_emits_no_reports() {
    let mmp = Mmp::new();
    let actions = mmp.plan_link_reports(&[link_snap(
        0x33,
        MmpMode::Minimal,
        true,
        true,
        true,
        true,
        false,
    )]);
    assert!(actions.is_empty());
}

#[test]
fn link_send_sr_false_suppresses_sender_report() {
    let mmp = Mmp::new();
    // Full mode, sender due, but the profile does not provide the SenderReport.
    let actions = mmp.plan_link_reports(&[link_snap(
        0x44,
        MmpMode::Full,
        false,
        true,
        true,
        true,
        false,
    )]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        actions[0],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Receiver } if peer == make_node_addr(0x44)
    ));
}

#[test]
fn link_send_rr_false_suppresses_receiver_report() {
    let mmp = Mmp::new();
    // Full mode, receiver due, but the profile does not provide the ReceiverReport.
    let actions = mmp.plan_link_reports(&[link_snap(
        0x55,
        MmpMode::Full,
        true,
        false,
        true,
        true,
        false,
    )]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        actions[0],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Sender } if peer == make_node_addr(0x55)
    ));
}

#[test]
fn link_not_due_yields_no_reports() {
    let mmp = Mmp::new();
    // Full mode, profiles provide both, but neither interval is due.
    let actions = mmp.plan_link_reports(&[link_snap(
        0x66,
        MmpMode::Full,
        true,
        true,
        false,
        false,
        false,
    )]);
    assert!(actions.is_empty());
}

#[test]
fn link_log_due_emits_log_marker() {
    let mmp = Mmp::new();
    // Minimal mode (no reports), but the operator-log interval is due.
    let actions = mmp.plan_link_reports(&[link_snap(
        0x77,
        MmpMode::Minimal,
        true,
        true,
        false,
        false,
        true,
    )]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], MmpAction::LogLink { peer } if peer == make_node_addr(0x77)));
}

#[test]
fn link_actions_are_phase_grouped_logs_senders_receivers() {
    let mmp = Mmp::new();
    // Two Full peers, both due for SR+RR+log. The returned Vec must group all
    // log markers (peer order) FIRST — they read cumulative_packets_sent, which
    // the report sends advance, so the pre-refactor handler logged before any
    // send — then all SenderReports (peer order), then all ReceiverReports.
    let actions = mmp.plan_link_reports(&[
        link_snap(0x01, MmpMode::Full, true, true, true, true, true),
        link_snap(0x02, MmpMode::Full, true, true, true, true, true),
    ]);
    assert_eq!(actions.len(), 6);
    assert!(matches!(actions[0], MmpAction::LogLink { peer } if peer == make_node_addr(0x01)));
    assert!(matches!(actions[1], MmpAction::LogLink { peer } if peer == make_node_addr(0x02)));
    assert!(matches!(
        actions[2],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Sender } if peer == make_node_addr(0x01)
    ));
    assert!(matches!(
        actions[3],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Sender } if peer == make_node_addr(0x02)
    ));
    assert!(matches!(
        actions[4],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Receiver } if peer == make_node_addr(0x01)
    ));
    assert!(matches!(
        actions[5],
        MmpAction::SendLinkReport { peer, kind: LinkReportKind::Receiver } if peer == make_node_addr(0x02)
    ));
}

// ===========================================================================
// plan_session_reports — session-layer report fan-out
// ===========================================================================

/// Build a session-report snapshot for `dest` with the mode and pre-evaluated
/// timing gates.
fn sess_snap(
    dest: u8,
    mode: MmpMode,
    sr_due: bool,
    rr_due: bool,
    mtu_due: bool,
    log_due: bool,
) -> SessionReportSnapshot {
    SessionReportSnapshot {
        dest: make_node_addr(dest),
        mode,
        sr_due,
        rr_due,
        mtu_due,
        log_due,
    }
}

#[test]
fn session_empty_snapshot_set_yields_no_actions() {
    let mmp = Mmp::new();
    assert!(mmp.plan_session_reports(&[]).is_empty());
}

#[test]
fn session_full_mode_emits_sender_receiver_mtu() {
    let mmp = Mmp::new();
    let actions =
        mmp.plan_session_reports(&[sess_snap(0x11, MmpMode::Full, true, true, true, false)]);
    assert_eq!(actions.len(), 3);
    assert!(matches!(
        actions[0],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::Sender } if dest == make_node_addr(0x11)
    ));
    assert!(matches!(
        actions[1],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::Receiver } if dest == make_node_addr(0x11)
    ));
    assert!(matches!(
        actions[2],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::PathMtu } if dest == make_node_addr(0x11)
    ));
}

#[test]
fn session_lightweight_mode_emits_receiver_and_mtu_no_sender() {
    let mmp = Mmp::new();
    let actions = mmp.plan_session_reports(&[sess_snap(
        0x22,
        MmpMode::Lightweight,
        true,
        true,
        true,
        false,
    )]);
    assert_eq!(actions.len(), 2);
    assert!(matches!(
        actions[0],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::Receiver } if dest == make_node_addr(0x22)
    ));
    assert!(matches!(
        actions[1],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::PathMtu } if dest == make_node_addr(0x22)
    ));
}

#[test]
fn session_minimal_mode_emits_only_path_mtu() {
    let mmp = Mmp::new();
    // Minimal suppresses both reports; the PathMtu gate is mode-independent.
    let actions =
        mmp.plan_session_reports(&[sess_snap(0x33, MmpMode::Minimal, true, true, true, false)]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        actions[0],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::PathMtu } if dest == make_node_addr(0x33)
    ));
}

#[test]
fn session_mtu_gate_is_mode_independent_even_when_not_due_elsewhere() {
    let mmp = Mmp::new();
    // Full mode, nothing due except the MTU notification.
    let actions =
        mmp.plan_session_reports(&[sess_snap(0x44, MmpMode::Full, false, false, true, false)]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        actions[0],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::PathMtu } if dest == make_node_addr(0x44)
    ));
}

#[test]
fn session_not_due_yields_no_reports() {
    let mmp = Mmp::new();
    let actions =
        mmp.plan_session_reports(&[sess_snap(0x55, MmpMode::Full, false, false, false, false)]);
    assert!(actions.is_empty());
}

#[test]
fn session_log_due_emits_log_marker_only() {
    let mmp = Mmp::new();
    // Minimal mode, no MTU due, but the operator log is due.
    let actions =
        mmp.plan_session_reports(&[sess_snap(0x66, MmpMode::Minimal, true, true, false, true)]);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], MmpAction::LogSession { dest } if dest == make_node_addr(0x66)));
}

#[test]
fn session_logs_precede_sends_across_sessions() {
    let mmp = Mmp::new();
    // Two Full sessions, both due for SR+RR+MTU+log. All LogSession markers (in
    // session order) must come FIRST — they read cumulative_packets_sent, which
    // the sends advance, so the pre-refactor handler logged before any send —
    // then the sends in per-session SR/RR/MTU order.
    let actions = mmp.plan_session_reports(&[
        sess_snap(0x01, MmpMode::Full, true, true, true, true),
        sess_snap(0x02, MmpMode::Full, true, true, true, true),
    ]);
    assert_eq!(actions.len(), 8);
    assert!(matches!(actions[0], MmpAction::LogSession { dest } if dest == make_node_addr(0x01)));
    assert!(matches!(actions[1], MmpAction::LogSession { dest } if dest == make_node_addr(0x02)));
    assert!(matches!(
        actions[2],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::Sender } if dest == make_node_addr(0x01)
    ));
    assert!(matches!(
        actions[3],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::Receiver } if dest == make_node_addr(0x01)
    ));
    assert!(matches!(
        actions[4],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::PathMtu } if dest == make_node_addr(0x01)
    ));
    assert!(matches!(
        actions[5],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::Sender } if dest == make_node_addr(0x02)
    ));
    assert!(matches!(
        actions[6],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::Receiver } if dest == make_node_addr(0x02)
    ));
    assert!(matches!(
        actions[7],
        MmpAction::SendSessionReport { dest, kind: SessionReportKind::PathMtu } if dest == make_node_addr(0x02)
    ));
}

// ===========================================================================
// plan_backoff — per-destination success/failure dedup reduction
// ===========================================================================

fn result(dest: u8, ok: bool) -> SendResult {
    SendResult {
        dest: make_node_addr(dest),
        ok,
    }
}

#[test]
fn backoff_empty_yields_no_updates() {
    let mmp = Mmp::new();
    assert!(mmp.plan_backoff(&[]).is_empty());
}

#[test]
fn backoff_partial_success_counts_as_success() {
    let mmp = Mmp::new();
    // One report to the dest succeeded, one failed → exactly ONE Success. This is
    // the partial-success path the real handler oracle cannot reach (its sends
    // all fail with no route).
    let updates = mmp.plan_backoff(&[result(0x11, true), result(0x11, false)]);
    assert_eq!(updates.len(), 1);
    assert!(matches!(updates[0], BackoffUpdate::Success { dest } if dest == make_node_addr(0x11)));
}

#[test]
fn backoff_all_success_counts_as_success() {
    let mmp = Mmp::new();
    // The success-side path: all reports to the dest succeeded → one Success.
    // Unreachable through the real handler (its sends all fail).
    let updates = mmp.plan_backoff(&[result(0x22, true), result(0x22, true)]);
    assert_eq!(updates.len(), 1);
    assert!(matches!(updates[0], BackoffUpdate::Success { dest } if dest == make_node_addr(0x22)));
}

#[test]
fn backoff_all_fail_counts_as_single_failure() {
    let mmp = Mmp::new();
    // Two failed reports to one dest collapse to exactly ONE Failure.
    let updates = mmp.plan_backoff(&[result(0x33, false), result(0x33, false)]);
    assert_eq!(updates.len(), 1);
    assert!(matches!(updates[0], BackoffUpdate::Failure { dest } if dest == make_node_addr(0x33)));
}

#[test]
fn backoff_multiple_dests_mixed_dedup_independently() {
    let mmp = Mmp::new();
    // dest 0x01: partial success → Success; dest 0x02: all fail → Failure;
    // dest 0x03: all success → Success. Emission is address-sorted (BTreeMap).
    let updates = mmp.plan_backoff(&[
        result(0x02, false),
        result(0x01, true),
        result(0x03, true),
        result(0x01, false),
        result(0x02, false),
    ]);
    assert_eq!(updates.len(), 3);
    assert!(matches!(updates[0], BackoffUpdate::Success { dest } if dest == make_node_addr(0x01)));
    assert!(matches!(updates[1], BackoffUpdate::Failure { dest } if dest == make_node_addr(0x02)));
    assert!(matches!(updates[2], BackoffUpdate::Success { dest } if dest == make_node_addr(0x03)));
}
