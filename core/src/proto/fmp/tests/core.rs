//! Tests for the sans-IO FMP connection-lifecycle decision core.

use super::util::{resend_snapshot, stale_snapshot};
use crate::proto::fmp::{
    ConnAction, DialMsg2Decision, DialMsg2Reject, DialMsg2Snapshot, Fmp, NegotiationPayload,
    NodeProfile, cross_connection_winner,
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

// ===========================================================================
// dial_outbound — initiator initial msg2 dial-identity classification
// ===========================================================================

#[test]
fn dial_outbound_matching_static_accepts() {
    let fmp = Fmp::new();
    let peer = make_node_addr(1);
    let snap = DialMsg2Snapshot {
        dialed_peer: Some(peer),
        learned_peer: peer,
    };
    assert_eq!(fmp.dial_outbound(&snap), DialMsg2Decision::Accept);
}

#[test]
fn dial_outbound_foreign_static_rejects() {
    let fmp = Fmp::new();
    let snap = DialMsg2Snapshot {
        dialed_peer: Some(make_node_addr(1)),
        learned_peer: make_node_addr(2),
    };
    assert_eq!(
        fmp.dial_outbound(&snap),
        DialMsg2Decision::Reject {
            reason: DialMsg2Reject::StaticMismatch
        }
    );
}

/// The anonymous carve-out: a dial that named nobody has no intent for the
/// answer to contradict, so any static is accepted and the ACL remains the only
/// gate. Breaking this stops shared-media discovery promoting anything.
#[test]
fn dial_outbound_anonymous_accepts_any_static() {
    let fmp = Fmp::new();
    for learned in [make_node_addr(1), make_node_addr(2), make_node_addr(200)] {
        let snap = DialMsg2Snapshot {
            dialed_peer: None,
            learned_peer: learned,
        };
        assert_eq!(fmp.dial_outbound(&snap), DialMsg2Decision::Accept);
    }
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
