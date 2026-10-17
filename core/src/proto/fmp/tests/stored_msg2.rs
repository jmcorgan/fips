//! Classification of a same-epoch msg1 on a session that cannot rekey: a
//! resend of the link-setup msg1 draws the stored msg2, a copy of an
//! answered msg1 is refused, and any other msg1 asks to replace the session.

use super::offlink::aged_snapshot;
use super::util::wire_outcome;
use crate::proto::fmp::{EstablishSnapshot, Fmp, InboundDecision, InboundReject};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The stored msg2 bytes the snapshots below carry.
const STORED: [u8; 4] = [0x5E; 4];

/// An existing peer whose session is 5 s old, with a stored msg2.
fn young_snapshot() -> EstablishSnapshot {
    let mut snap = aged_snapshot();
    snap.existing_session_age_secs = 5;
    snap.existing_msg2 = Some(STORED.to_vec());
    snap
}

/// Classify a same-epoch msg1 against `snap`.
fn classify(snap: &EstablishSnapshot) -> InboundDecision {
    Fmp::new().establish_inbound(snap, &wire_outcome(snap.existing_peer_epoch))
}

/// The three outcomes of the not-a-rekey arm, checked on snapshots built by
/// `base`: setup resend, answered copy, anything else. Returns what went
/// wrong.
fn three_rules(base: impl Fn() -> EstablishSnapshot, label: &str) -> Vec<String> {
    let mut found = Vec::new();

    let mut snap = base();
    snap.setup_match = true;
    snap.msg1_answered_before = true;
    match classify(&snap) {
        InboundDecision::ResendMsg2 { msg2 } if msg2.as_deref() == Some(&STORED[..]) => {}
        other => found.push(format!("{label}: setup resend got {other:?}")),
    }

    let mut snap = base();
    snap.msg1_answered_before = true;
    match classify(&snap) {
        InboundDecision::Reject {
            reason: InboundReject::AnsweredBefore,
        } => {}
        other => found.push(format!("{label}: answered copy got {other:?}")),
    }

    let snap = base();
    let wire = wire_outcome(snap.existing_peer_epoch);
    let expected = *wire.peer_identity.node_addr();
    match Fmp::new().establish_inbound(&snap, &wire) {
        InboundDecision::ReplaceThenPromote { peer } if peer == expected => {}
        other => found.push(format!("{label}: fresh msg1 got {other:?}")),
    }
    found
}

#[test]
fn a_resend_of_the_setup_msg1_on_a_young_session_draws_the_stored_msg2_even_though_the_record_holds_it()
 {
    let mut snap = young_snapshot();
    snap.setup_match = true;
    snap.msg1_answered_before = true;
    match classify(&snap) {
        InboundDecision::ResendMsg2 { msg2 } => assert_eq!(msg2, Some(STORED.to_vec())),
        other => panic!("expected ResendMsg2, got {other:?}"),
    }
}

#[test]
fn a_copy_of_an_answered_msg1_on_a_young_session_is_refused() {
    let mut snap = young_snapshot();
    snap.msg1_answered_before = true;
    let decision = classify(&snap);
    assert!(
        matches!(
            decision,
            InboundDecision::Reject {
                reason: InboundReject::AnsweredBefore
            }
        ),
        "got {decision:?}"
    );
}

#[test]
fn any_other_same_epoch_msg1_on_a_young_session_asks_to_replace_the_session() {
    let found = three_rules(young_snapshot, "young");
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn an_off_link_msg1_on_a_young_session_is_classified_by_digest_and_never_refused_as_off_link() {
    let off_link = || {
        let mut snap = young_snapshot();
        snap.msg1_on_link = false;
        snap.link_reachable = true;
        snap
    };
    let found = three_rules(off_link, "off link");
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn an_aged_session_classifies_as_before_whatever_the_setup_match() {
    let mut snap = young_snapshot();
    snap.existing_session_age_secs = 31;
    snap.setup_match = true;
    let decision = classify(&snap);
    assert!(
        matches!(
            decision,
            InboundDecision::RekeyRespond {
                abandon_first: false,
                ..
            }
        ),
        "an aged session's msg1 is a rekey: got {decision:?}"
    );
    snap.msg1_answered_before = true;
    let decision = classify(&snap);
    assert!(
        matches!(
            decision,
            InboundDecision::Reject {
                reason: InboundReject::AnsweredBefore
            }
        ),
        "an aged session refuses an answered msg1: got {decision:?}"
    );
}

#[test]
fn an_epoch_change_restarts_whatever_the_setup_match() {
    for setup_match in [false, true] {
        let mut snap = young_snapshot();
        snap.setup_match = setup_match;
        let wire = wire_outcome(Some([0x99; 8]));
        let decision = Fmp::new().establish_inbound(&snap, &wire);
        assert!(
            matches!(decision, InboundDecision::RestartThenPromote { .. }),
            "setup_match {setup_match}: got {decision:?}"
        );
    }
}

#[test]
fn a_link_under_30_s_old_follows_the_three_rules_even_with_a_session_over_10_s() {
    let young_link = || {
        let mut snap = young_snapshot();
        snap.existing_link_age_secs = 29;
        snap.existing_session_age_secs = 29;
        snap
    };
    let found = three_rules(young_link, "link 29 s");
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn a_session_under_10_s_on_a_link_over_30_s_follows_the_three_rules() {
    let young_session = || {
        let mut snap = young_snapshot();
        snap.existing_link_age_secs = 31;
        snap.existing_session_age_secs = 9;
        snap
    };
    let found = three_rules(young_session, "session 9 s");
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn a_link_of_30_s_with_a_session_of_10_s_is_classified_as_a_rekey() {
    let mut snap = young_snapshot();
    snap.existing_link_age_secs = 30;
    snap.existing_session_age_secs = 10;
    let decision = classify(&snap);
    assert!(
        matches!(
            decision,
            InboundDecision::RekeyRespond {
                abandon_first: false,
                ..
            }
        ),
        "got {decision:?}"
    );
}
