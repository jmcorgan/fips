//! The silent-session record, and where its refusal enters the inbound msg3
//! classification.

use super::util::establish_snapshot;
use crate::proto::fmp::silent::{
    ActiveBackoff, SILENT_BACKOFF_BASE_MS, SILENT_BACKOFF_CAP_MS, SILENT_SESSION_LIMIT,
};
use crate::proto::fmp::{
    EstablishSnapshot, Fmp, InboundDecision, InboundReject, Msg1Digest, RekeyClaim, SilentSessions,
    WireOutcome,
};
use crate::testutil::make_node_addr;

/// The epoch the counted sessions ran at.
const EPOCH: [u8; 8] = [7u8; 8];

/// Another epoch: a restart of the same peer.
const OTHER_EPOCH: [u8; 8] = [8u8; 8];

/// A distinct link-setup msg1 digest for session `n`.
fn setup(n: u32) -> Option<Msg1Digest> {
    Some(Msg1Digest::of(&n.to_le_bytes()))
}

/// End sessions `first..first + count` of `peer` silent at `epoch`, one
/// second apart from `start_ms`, and return the last end's result.
fn end_silent(
    record: &mut SilentSessions,
    epoch: [u8; 8],
    first: u32,
    count: u32,
    start_ms: u64,
) -> Option<ActiveBackoff> {
    let peer = make_node_addr(1);
    let mut last = None;
    for i in 0..count {
        let n = first + i;
        last = record.ended(peer, Some(epoch), setup(n), start_ms + u64::from(i) * 1000);
    }
    last.map(|start| start.backoff)
}

#[test]
fn two_silent_sessions_refuse_nothing_and_the_third_refuses_for_the_base() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    assert_eq!(end_silent(&mut record, EPOCH, 0, 2, 0), None);
    assert_eq!(record.refusing(&peer, 2_000), None);
    let third = record
        .ended(peer, Some(EPOCH), setup(2), 2_000)
        .map(|start| start.backoff);
    assert_eq!(
        third,
        Some(ActiveBackoff {
            epoch: Some(EPOCH),
            silent: SILENT_SESSION_LIMIT,
            remaining_ms: SILENT_BACKOFF_BASE_MS,
        })
    );
    assert_eq!(record.refusing(&peer, 2_000), third);
}

#[test]
fn each_further_silent_session_doubles_the_refusal_up_to_the_ten_minute_cap() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    end_silent(&mut record, EPOCH, 0, 3, 0);
    let mut now = 2_000;
    let mut lengths = Vec::new();
    for n in 3..10 {
        now += 1_000;
        let refusal = record
            .ended(peer, Some(EPOCH), setup(n), now)
            .expect("past the limit every silent session refuses");
        lengths.push(refusal.backoff.remaining_ms / 1000);
    }
    assert_eq!(lengths, vec![60, 120, 240, 480, 600, 600, 600]);
    assert_eq!(SILENT_BACKOFF_CAP_MS, 600_000);
}

#[test]
fn the_refusal_ends_when_its_time_has_run() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    end_silent(&mut record, EPOCH, 0, 3, 0);
    let ends_at = 2_000 + SILENT_BACKOFF_BASE_MS;
    assert_eq!(
        record.refusing(&peer, ends_at - 1).map(|b| b.remaining_ms),
        Some(1)
    );
    assert_eq!(record.refusing(&peer, ends_at), None);
}

#[test]
fn an_authenticated_frame_drops_the_record() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    end_silent(&mut record, EPOCH, 0, 3, 0);
    record.heard(&peer);
    assert_eq!(record.refusing(&peer, 2_000), None);
    assert_eq!(record.count(&peer), None);
    assert_eq!(end_silent(&mut record, EPOCH, 10, 2, 3_000), None);
}

#[test]
fn a_silent_session_at_another_epoch_restarts_the_count_at_one() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    end_silent(&mut record, EPOCH, 0, 3, 0);
    assert_eq!(record.ended(peer, Some(OTHER_EPOCH), setup(3), 3_000), None);
    assert_eq!(record.count(&peer), Some(1));
    assert_eq!(record.refusing(&peer, 3_000), None);
}

#[test]
fn a_record_without_an_epoch_adopts_the_first_epoch_it_sees() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    record.ended(peer, None, setup(0), 0);
    record.ended(peer, Some(EPOCH), setup(1), 1_000);
    let refusal = record.ended(peer, None, setup(2), 2_000).unwrap();
    assert_eq!(refusal.backoff.epoch, Some(EPOCH));
    assert_eq!(refusal.backoff.silent, 3);
}

#[test]
fn a_session_promoted_from_an_already_counted_msg1_is_not_counted_again() {
    // A captured msg1 replayed after each reap promotes sessions that all
    // carry the same setup digest; only the first counts.
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    for t in 0..5 {
        assert_eq!(record.ended(peer, Some(EPOCH), setup(0), t * 1000), None);
    }
    assert_eq!(record.count(&peer), Some(1));
    assert_eq!(record.refusing(&peer, 5_000), None);
}

#[test]
fn sessions_this_node_dialled_count_without_a_setup_digest() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    record.ended(peer, Some(EPOCH), None, 0);
    record.ended(peer, Some(EPOCH), None, 1_000);
    assert!(record.ended(peer, Some(EPOCH), None, 2_000).is_some());
}

#[test]
fn a_new_refusal_reports_how_many_msg1s_the_previous_refusal_refused() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    end_silent(&mut record, EPOCH, 0, 2, 0);
    let first = record
        .ended(peer, Some(EPOCH), setup(2), 2_000)
        .expect("the third silent session starts a refusal");
    assert_eq!(first.prior_refused, 0);
    for n in 1..=8 {
        assert_eq!(record.note_refused(&peer), Some(n));
    }

    let ends_at = 2_000 + SILENT_BACKOFF_BASE_MS;
    let second = record
        .ended(peer, Some(EPOCH), setup(3), ends_at + 1_000)
        .expect("a fourth silent session starts a longer refusal");
    assert_eq!(second.prior_refused, 8);
    assert_eq!(
        record.note_refused(&peer),
        Some(1),
        "the new refusal's count starts again"
    );
}

#[test]
fn clearing_a_record_returns_its_refused_count() {
    let peer = make_node_addr(1);
    let mut record = SilentSessions::new();
    assert_eq!(
        record.note_refused(&peer),
        None,
        "no record, nothing counted"
    );
    end_silent(&mut record, EPOCH, 0, 3, 0);
    for _ in 0..5 {
        record.note_refused(&peer);
    }
    assert_eq!(record.heard(&peer), 5);
    assert_eq!(record.heard(&peer), 0, "the record is gone");
}

#[test]
fn a_record_is_pruned_a_cap_after_its_refusal_ends_and_kept_before() {
    let peer = make_node_addr(1);
    let other = make_node_addr(2);
    let mut record = SilentSessions::new();
    end_silent(&mut record, EPOCH, 0, 3, 0);
    // The refusal ends at 32 s. Another identity's silent end 40 s after that
    // prunes nothing; one a cap after it prunes the first record.
    let ends_at = 2_000 + SILENT_BACKOFF_BASE_MS;
    record.ended(other, Some(EPOCH), setup(100), ends_at + 40_000);
    assert_eq!(record.count(&peer), Some(3));
    record.ended(
        other,
        Some(EPOCH),
        setup(101),
        ends_at + SILENT_BACKOFF_CAP_MS,
    );
    assert_eq!(record.count(&peer), None);
    assert_eq!(record.len(), 1);
}

#[test]
fn a_record_below_the_limit_is_pruned_a_cap_after_its_last_silent_session() {
    let peer = make_node_addr(1);
    let other = make_node_addr(2);
    let mut record = SilentSessions::new();
    record.ended(peer, Some(EPOCH), setup(0), 1_000);
    record.ended(
        other,
        Some(EPOCH),
        setup(1),
        1_000 + SILENT_BACKOFF_CAP_MS - 1,
    );
    assert_eq!(record.count(&peer), Some(1));
    record.ended(other, Some(EPOCH), setup(2), 1_000 + SILENT_BACKOFF_CAP_MS);
    assert_eq!(record.count(&peer), None);
}

/// A refusal in force for sessions at [`EPOCH`].
fn backoff() -> Option<ActiveBackoff> {
    Some(ActiveBackoff {
        epoch: Some(EPOCH),
        silent: SILENT_SESSION_LIMIT,
        remaining_ms: SILENT_BACKOFF_BASE_MS,
    })
}

/// The address of the node the snapshots belong to.
const OURS: u8 = 0x10;

/// The address of the peer whose msg3 is classified.
const PEER: u8 = 0x20;

/// No peer entry for the sender, with a refusal in force for it.
fn no_peer_snapshot() -> EstablishSnapshot {
    let mut snap = establish_snapshot(OURS);
    snap.has_existing_peer = false;
    snap.existing_peer_epoch = None;
    snap.has_session = false;
    snap.silent_backoff = backoff();
    snap
}

/// An existing peer at [`EPOCH`], with a refusal in force for it.
fn existing_snapshot() -> EstablishSnapshot {
    let mut snap = establish_snapshot(OURS);
    snap.existing_peer_epoch = Some(EPOCH);
    snap.silent_backoff = backoff();
    snap
}

/// Classify a msg3 carrying `epoch` against `snap`.
fn classify(snap: &EstablishSnapshot, epoch: Option<[u8; 8]>) -> InboundDecision {
    let wire = WireOutcome {
        peer_node_addr: make_node_addr(PEER),
        remote_epoch: epoch,
    };
    Fmp::new().establish_inbound(snap, &wire)
}

fn is_silent_reject(decision: &InboundDecision) -> bool {
    matches!(
        decision,
        InboundDecision::Reject {
            reason: InboundReject::SilentBackoff
        }
    )
}

#[test]
fn a_same_epoch_msg3_from_an_identity_with_no_peer_is_refused_during_the_back_off() {
    let decision = classify(&no_peer_snapshot(), Some(EPOCH));
    assert!(is_silent_reject(&decision), "got {decision:?}");
}

#[test]
fn a_same_epoch_msg3_from_an_identity_with_no_peer_is_promoted_with_no_back_off() {
    let mut snap = no_peer_snapshot();
    snap.silent_backoff = None;
    assert!(matches!(
        classify(&snap, Some(EPOCH)),
        InboundDecision::Promote
    ));
}

#[test]
fn a_msg3_with_no_epoch_counts_as_the_same_epoch() {
    let decision = classify(&no_peer_snapshot(), None);
    assert!(is_silent_reject(&decision), "got {decision:?}");
}

#[test]
fn a_new_epoch_msg3_is_promoted_during_the_back_off() {
    assert!(matches!(
        classify(&no_peer_snapshot(), Some(OTHER_EPOCH)),
        InboundDecision::Promote
    ));
}

#[test]
fn a_new_epoch_msg3_from_an_idle_existing_peer_restarts_it_during_the_back_off() {
    let snap = existing_snapshot();
    assert!(matches!(
        classify(&snap, Some(OTHER_EPOCH)),
        InboundDecision::RestartThenPromote { .. }
    ));
}

#[test]
fn a_duplicate_msg3_from_an_existing_peer_still_draws_the_stored_msg2_during_the_back_off() {
    let mut snap = existing_snapshot();
    snap.existing_msg2 = Some(vec![0x5E; 4]);
    assert!(matches!(
        classify(&snap, Some(EPOCH)),
        InboundDecision::ResendMsg2 { msg2: Some(_) }
    ));
}

#[test]
fn a_rekey_of_an_existing_peers_session_is_answered_during_the_back_off() {
    let mut snap = existing_snapshot();
    snap.rekey_claim = RekeyClaim::Matches;
    assert!(matches!(
        classify(&snap, Some(EPOCH)),
        InboundDecision::RekeyRespond {
            abandon_first: false,
            ..
        }
    ));
}

#[test]
fn a_crossing_dial_from_an_existing_peer_is_resolved_during_the_back_off() {
    let mut snap = existing_snapshot();
    snap.different_link = true;
    assert!(matches!(
        classify(&snap, Some(EPOCH)),
        InboundDecision::CrossConnect { .. }
    ));
}
