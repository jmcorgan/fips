use fips_core::identity::PeerIdentity;
use fips_core::utils::hash::KeyedHasher;

use super::super::election::{Election, OfferDisposition, SeenDecision};
use super::*;
use crate::nostr::BootstrapError;
use crate::nostr::machine::signal::{
    FreshnessOutcome, check_offer, create_traversal_answer, create_traversal_offer,
    validate_traversal_answer_for_offer,
};
use crate::nostr::machine::tests::ZeroEntropy;
use crate::nostr::machine::types::{TraversalAddress, TraversalAnswer};

/// FRC-1601 C.1's npubs and session id.
const NPUB_A: &str = "npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266";
const NPUB_B: &str = "npub1mlcawle2vuw97dscxundkg6phev0atsa5t0vakzrys8hk5pt5evssm7a0a";
const SESSION: &str = "1830297600000-0123456789abcdef";
const T0: u64 = 1_830_297_600_000;
const TTL_MS: u64 = 120_000;

fn udp(ip: &str, port: u16) -> TraversalAddress {
    TraversalAddress {
        protocol: "udp".to_string(),
        ip: ip.to_string(),
        port,
    }
}

/// The offer of FRC-1601 Section 5.2, from node A to node B.
fn offer() -> TraversalOffer {
    create_traversal_offer(
        SESSION.to_string(),
        T0,
        TTL_MS,
        SESSION.to_string(),
        NPUB_A.to_string(),
        NPUB_B.to_string(),
        Some(udp("198.51.100.10", 40_000)),
        Vec::new(),
        Some("stun:stun.l.google.com:19302".to_string()),
    )
}

/// Node B's answer to [`offer`], accepted or not, as Section 5.3 and C.5
/// give it.
fn answer(accepted: bool) -> TraversalAnswer {
    create_traversal_answer(
        SESSION.to_string(),
        T0 + 1_500,
        TTL_MS,
        "1830297601500-fedcba9876543210".to_string(),
        NPUB_B.to_string(),
        NPUB_A.to_string(),
        SESSION.to_string(),
        accepted,
        accepted.then(|| udp("203.0.113.20", 50_000)),
        Vec::new(),
        accepted.then(|| "stun:stun.l.google.com:19302".to_string()),
        accepted.then(|| punch_hint(T0 + 1_500, 2_000, 200, 10_000)),
        (!accepted).then(|| "no-usable-addresses".to_string()),
        Some(T0 + 800),
    )
}

/// `text` and the JSON `body` serializes to are the same document.
fn same_json<T: serde::Serialize>(body: &T, text: &str) {
    let ours = serde_json::to_value(body).unwrap();
    let frc: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(ours, frc);
}

/// An offer from A to B issued at `issued` and expiring at `expires`, both
/// relative to C.1's time.
fn stamped(issued: u64, expires: u64) -> TraversalOffer {
    TraversalOffer {
        issued_at: T0 + issued,
        expires_at: T0 + expires,
        ..offer()
    }
}

#[test]
fn the_frc_c5_offer_and_answer_bodies_and_freshness_hold() {
    same_json(
        &offer(),
        r#"{"type":"offer","sessionId":"1830297600000-0123456789abcdef",
            "issuedAt":1830297600000,"expiresAt":1830297720000,
            "nonce":"1830297600000-0123456789abcdef",
            "senderNpub":"npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266",
            "recipientNpub":"npub1mlcawle2vuw97dscxundkg6phev0atsa5t0vakzrys8hk5pt5evssm7a0a",
            "reflexiveAddress":{"protocol":"udp","ip":"198.51.100.10","port":40000},
            "localAddresses":[],"stunServer":"stun:stun.l.google.com:19302"}"#,
    );
    same_json(
        &answer(true),
        r#"{"type":"answer","sessionId":"1830297600000-0123456789abcdef",
            "issuedAt":1830297601500,"expiresAt":1830297721500,
            "nonce":"1830297601500-fedcba9876543210",
            "senderNpub":"npub1mlcawle2vuw97dscxundkg6phev0atsa5t0vakzrys8hk5pt5evssm7a0a",
            "recipientNpub":"npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266",
            "inReplyTo":"1830297600000-0123456789abcdef","accepted":true,
            "reflexiveAddress":{"protocol":"udp","ip":"203.0.113.20","port":50000},
            "localAddresses":[],"stunServer":"stun:stun.l.google.com:19302",
            "punch":{"startAtMs":1830297603500,"intervalMs":200,"durationMs":10000},
            "reason":null,"offerReceivedAt":1830297600800}"#,
    );
    same_json(
        &answer(false),
        r#"{"type":"answer","sessionId":"1830297600000-0123456789abcdef",
            "issuedAt":1830297601500,"expiresAt":1830297721500,
            "nonce":"1830297601500-fedcba9876543210",
            "senderNpub":"npub1mlcawle2vuw97dscxundkg6phev0atsa5t0vakzrys8hk5pt5evssm7a0a",
            "recipientNpub":"npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266",
            "inReplyTo":"1830297600000-0123456789abcdef","accepted":false,
            "reflexiveAddress":null,"localAddresses":[],"stunServer":null,
            "punch":null,"reason":"no-usable-addresses","offerReceivedAt":1830297600800}"#,
    );

    // Checked by node A at +2000 ms: every check of Section 5.4 passes, and
    // both are fresh by the first line of the freshness rule.
    assert_eq!(
        validate_traversal_answer_for_offer(
            &offer(),
            &answer(true),
            T0 + 2_000,
            TTL_MS,
            NPUB_B,
            NPUB_A
        ),
        Ok(FreshnessOutcome::Fresh)
    );
    assert_eq!(
        check_offer(&offer(), T0 + 2_000, TTL_MS, NPUB_A, NPUB_B),
        Ok(FreshnessOutcome::Fresh)
    );

    // The freshness table, for SIGNAL_TTL 120 s.
    let table: [(u64, u64, u64, Result<FreshnessOutcome, RejectReason>); 7] = [
        (0, 120_000, 1_000, Ok(FreshnessOutcome::Fresh)),
        (
            0,
            120_000,
            120_000,
            Ok(FreshnessOutcome::FreshWithinSkewTolerance),
        ),
        (
            0,
            120_000,
            150_000,
            Ok(FreshnessOutcome::FreshWithinSkewTolerance),
        ),
        (0, 120_000, 180_000, Err(RejectReason::Expired)),
        (0, 10_000, 70_001, Err(RejectReason::Expired)),
        (
            30_000,
            150_000,
            0,
            Ok(FreshnessOutcome::FreshWithinSkewTolerance),
        ),
        (60_001, 180_001, 0, Err(RejectReason::FutureDated)),
    ];
    for (issued, expires, now, outcome) in table {
        assert_eq!(
            check_offer(&stamped(issued, expires), T0 + now, TTL_MS, NPUB_A, NPUB_B),
            outcome,
            "issuedAt +{issued}, expiresAt +{expires}, now +{now}"
        );
    }

    // Node B's node address is the smaller: when both start a traversal at
    // once, B does not answer A's offer and A answers B's.
    let addr = |npub: &str| *PeerIdentity::from_npub(npub).unwrap().node_addr();
    let (a, b) = (addr(NPUB_A), addr(NPUB_B));
    let hex = |addr: &fips_core::identity::NodeAddr| {
        addr.as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(hex(&a), "7c79f3071e28344e8153bf6c73c294eb");
    assert_eq!(hex(&b), "4fbdbf30768ac87343fc0ebf5a5ed37c");
    let mut at_b = Election::new(300_000, 16, KeyedHasher::new::<ZeroEntropy>());
    assert!(at_b.begin_initiator(NPUB_A));
    assert_eq!(
        at_b.classify_incoming_offer(NPUB_A, &b, &a),
        OfferDisposition::Suppress
    );
    let mut at_a = Election::new(300_000, 16, KeyedHasher::new::<ZeroEntropy>());
    assert!(at_a.begin_initiator(NPUB_B));
    assert_eq!(
        at_a.classify_incoming_offer(NPUB_B, &a, &b),
        OfferDisposition::Proceed
    );

    // A copy of B's offer that B sent again is discarded at check 5.
    assert_eq!(at_a.note_session_seen(SESSION, T0), SeenDecision::Fresh);
    assert_eq!(
        at_a.note_session_seen(SESSION, T0 + 500),
        SeenDecision::Replay
    );
}

#[test]
fn an_offer_rejection_reason_renders_the_text_the_error_line_prints() {
    let cases = [
        (RejectReason::Oversized, "oversized-offer", true),
        (RejectReason::Invalid, "invalid-offer", true),
        (RejectReason::Expired, "expired-offer", false),
        (RejectReason::FutureDated, "future-dated-offer", true),
        (RejectReason::IdentityMismatch, "identity-mismatch", true),
        (RejectReason::SeenFull, "seen-sessions-full", false),
    ];
    for (reason, code, adversarial) in cases {
        let error = BootstrapError::from(Error::from(reason.clone()));
        assert_eq!(reason.to_string(), error.to_string());
        assert_eq!(
            reason.to_string(),
            BootstrapError::Protocol(code.to_string()).to_string()
        );
        assert_eq!(RejectReason::from_code(code), Some(reason.clone()));
        assert_eq!(reason.adversarial(), adversarial, "{reason:?}");
    }

    let replay = RejectReason::Replay("s1".to_string());
    assert_eq!(
        replay.to_string(),
        BootstrapError::Replay("s1".to_string()).to_string()
    );
    assert_eq!(
        BootstrapError::from(Error::from(replay.clone())).to_string(),
        replay.to_string()
    );
    assert!(!replay.adversarial());
    assert_eq!(RejectReason::from_code("relay unreachable"), None);
}
