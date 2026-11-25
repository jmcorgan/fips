//! Tests that a responder remembers a recorded `sessionId` for as long as
//! FRC-1601 Section 5.4 asks: until its wall-clock time is later than the
//! offer's `issuedAt` plus its own `SIGNAL_TTL` and
//! `FRESHNESS_SKEW_TOLERANCE`. Until then the freshness rule still accepts a
//! copy of the offer, so the memory is all that refuses it.

use super::super::FRESHNESS_SKEW_TOLERANCE_MS;
use super::super::machine::tests::ZeroEntropy;
use super::super::machine::traversal::election::{Election, SeenDecision};
use super::super::machine::traversal::gate::{
    ANSWER_RESERVE_BURST, ANSWER_RESERVE_RATE_PER_SEC, SIGNAL_BURST, SIGNAL_RATE_PER_SEC,
};
use super::super::signal::validate_offer_freshness;
use super::offer_between;
use crate::config::NostrRendezvousConfig;
use fips_core::utils::hash::KeyedHasher;

/// The offer's sender and recipient, as the freshness check is given them.
const SENDER: &str = "npub1sender";
const RESPONDER: &str = "npub1responder";

/// A responder at the defaults records an offer issued as far ahead of its
/// clock as the freshness rule accepts, then records as many other offers as
/// the signal gate admits before a copy of it arrives just ahead of
/// `issuedAt + SIGNAL_TTL + FRESHNESS_SKEW_TOLERANCE`: the rest of both of the
/// gate's bursts at once, then one offer per interval of the two allowances'
/// combined sustained rate. The copy is still fresh, and must be refused as a
/// replay.
#[test]
fn a_recorded_session_is_remembered_until_its_offer_can_no_longer_be_fresh() {
    let defaults = NostrRendezvousConfig::default();
    let ttl_ms = defaults.signal_ttl_secs * 1000;
    let mut machine = Election::new(
        defaults.replay_window_secs * 1000,
        defaults.seen_sessions_max_entries,
        KeyedHasher::new::<ZeroEntropy>(),
    );

    let t0 = 1_900_000_000_000u64;
    let mut captured = offer_between("captured", SENDER, RESPONDER);
    captured.issued_at = t0 + FRESHNESS_SKEW_TOLERANCE_MS;
    captured.expires_at = captured.issued_at + ttl_ms;
    let floor = captured.issued_at + ttl_ms + FRESHNESS_SKEW_TOLERANCE_MS;
    let at = floor - 1_000;
    assert!(
        validate_offer_freshness(&captured, t0, ttl_ms, SENDER, RESPONDER).is_ok(),
        "precondition: the captured offer is fresh when first recorded"
    );
    assert!(
        validate_offer_freshness(&captured, at, ttl_ms, SENDER, RESPONDER).is_ok(),
        "precondition: a copy of the captured offer is still fresh {} ms after it was recorded",
        at - t0
    );

    // The captured offer takes one token of the gate's bursts; the rest of
    // both bursts is spent at once, then the gate refills at its combined
    // sustained rate. At no instant does the count recorded exceed what the
    // two buckets have admitted.
    assert_ne!(
        machine.note_session_seen(&captured.session_id, t0),
        SeenDecision::Replay,
        "precondition: the captured offer is new when first recorded"
    );
    let burst_rest = (SIGNAL_BURST + ANSWER_RESERVE_BURST) as u64 - 1;
    let interval_ms = (1000.0 / (SIGNAL_RATE_PER_SEC + ANSWER_RESERVE_RATE_PER_SEC)) as u64;
    let mut recorded = 1u64;
    for i in 0..burst_rest {
        let _ = machine.note_session_seen(&format!("burst-{i}"), t0 + 1);
        recorded += 1;
    }
    let mut now = t0 + interval_ms;
    while now < at {
        let _ = machine.note_session_seen(&format!("filler-{now}"), now);
        recorded += 1;
        now += interval_ms;
    }

    assert_eq!(
        machine.note_session_seen(&captured.session_id, at),
        SeenDecision::Replay,
        "defect: the session was forgotten {} ms after it was recorded, after {recorded} \
         offers the signal gate admits, while its offer is fresh until {} ms",
        at - t0,
        floor - t0
    );
}
