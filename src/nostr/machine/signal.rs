//! Traversal signal bodies and their checks: the offer and answer a peer
//! sends inside a sealed Nostr event, their freshness against our clock, the
//! answer's match to our offer, and the clock-skew estimate a completed round
//! trip gives. Sealing and unsealing the event stay in the shell's
//! `signal.rs`; the caller passes the wall clock in as `now`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::error::Error;
use super::types::{PunchHint, TraversalAddress, TraversalAnswer, TraversalOffer};

/// Wall-clock skew tolerance applied to offer/answer freshness checks, in
/// milliseconds. Constant rather than configurable because loosening this
/// past ~minutes erodes the freshness guarantee that backstops session-id
/// replay protection. Tightening it below the size of a typical un-NTP'd
/// drift defeats the purpose. 60s sits comfortably between those.
///
/// `pub(crate)` because `Config::validate` derives the freshness window from
/// it rather than restating the number, so changing it here moves the
/// validation boundary with it.
pub const FRESHNESS_SKEW_TOLERANCE_MS: u64 = 60_000;

/// Result of a freshness check. `Fresh` means the offer/answer is within the
/// strict TTL window; `FreshWithinSkewTolerance` means it was only accepted
/// after applying `FRESHNESS_SKEW_TOLERANCE_MS` grace, which is a useful
/// signal for operators to know clock skew is in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessOutcome {
    Fresh,
    FreshWithinSkewTolerance,
}

/// Why a freshness check rejected a signal. The two classes are operationally
/// different and must not be collapsed into one reason string: one is the
/// expected consequence of relay lag, the other cannot arise from lag at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessReject {
    /// Issued too long ago: past the configured TTL plus skew tolerance.
    /// Benign; relay delivery delay produces this routinely.
    Stale,
    /// Issued further ahead of the local clock than the skew tolerance
    /// allows. Not reachable through delivery delay, so it means either a
    /// clock broken past the tolerance or a forged stamp.
    FutureDated,
}

pub fn validate_offer_freshness(
    offer: &TraversalOffer,
    now: u64,
    signal_ttl_ms: u64,
    actual_sender_npub: &str,
    local_npub: &str,
) -> Result<FreshnessOutcome, Error> {
    if offer.message_type != "offer" {
        return Err(Error::Protocol("invalid-offer".to_string()));
    }
    let outcome = match check_freshness(offer.issued_at, offer.expires_at, now, signal_ttl_ms) {
        Ok(o) => o,
        Err(FreshnessReject::Stale) => {
            return Err(Error::Protocol("expired-offer".to_string()));
        }
        Err(FreshnessReject::FutureDated) => {
            return Err(Error::Protocol("future-dated-offer".to_string()));
        }
    };
    if offer.sender_npub != actual_sender_npub || offer.recipient_npub != local_npub {
        return Err(Error::Protocol("identity-mismatch".to_string()));
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
pub fn create_traversal_offer(
    session_id: String,
    issued_at: u64,
    ttl_ms: u64,
    nonce: String,
    sender_npub: String,
    recipient_npub: String,
    reflexive_address: Option<TraversalAddress>,
    local_addresses: Vec<TraversalAddress>,
    stun_server: Option<String>,
) -> TraversalOffer {
    TraversalOffer {
        message_type: "offer".to_string(),
        session_id,
        issued_at,
        expires_at: issued_at + ttl_ms,
        nonce,
        sender_npub,
        recipient_npub,
        reflexive_address,
        local_addresses,
        stun_server,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_traversal_answer(
    session_id: String,
    issued_at: u64,
    ttl_ms: u64,
    nonce: String,
    sender_npub: String,
    recipient_npub: String,
    in_reply_to: String,
    accepted: bool,
    reflexive_address: Option<TraversalAddress>,
    local_addresses: Vec<TraversalAddress>,
    stun_server: Option<String>,
    punch: Option<PunchHint>,
    reason: Option<String>,
    offer_received_at: Option<u64>,
) -> TraversalAnswer {
    TraversalAnswer {
        message_type: "answer".to_string(),
        session_id,
        issued_at,
        expires_at: issued_at + ttl_ms,
        nonce,
        sender_npub,
        recipient_npub,
        in_reply_to,
        accepted,
        reflexive_address,
        local_addresses,
        stun_server,
        punch,
        reason,
        offer_received_at,
    }
}

pub fn validate_traversal_answer_for_offer(
    offer: &TraversalOffer,
    answer: &TraversalAnswer,
    now: u64,
    signal_ttl_ms: u64,
    actual_sender_npub: &str,
    local_npub: &str,
) -> Result<FreshnessOutcome, Error> {
    if answer.message_type != "answer" {
        return Err(Error::Protocol("invalid-answer".to_string()));
    }
    let offer_outcome = match check_freshness(offer.issued_at, offer.expires_at, now, signal_ttl_ms)
    {
        Ok(o) => o,
        Err(FreshnessReject::Stale) => {
            return Err(Error::Protocol("expired-offer-in-answer".to_string()));
        }
        Err(FreshnessReject::FutureDated) => {
            return Err(Error::Protocol("future-dated-offer-in-answer".to_string()));
        }
    };
    let answer_outcome =
        match check_freshness(answer.issued_at, answer.expires_at, now, signal_ttl_ms) {
            Ok(o) => o,
            Err(FreshnessReject::Stale) => {
                return Err(Error::Protocol("expired-answer".to_string()));
            }
            Err(FreshnessReject::FutureDated) => {
                return Err(Error::Protocol("future-dated-answer".to_string()));
            }
        };
    if offer.session_id != answer.session_id || answer.in_reply_to != offer.nonce {
        return Err(Error::Protocol("session-mismatch".to_string()));
    }
    if offer.sender_npub != local_npub
        || offer.recipient_npub != actual_sender_npub
        || answer.sender_npub != actual_sender_npub
        || answer.recipient_npub != local_npub
    {
        return Err(Error::Protocol("identity-mismatch".to_string()));
    }
    if answer.accepted && answer.reflexive_address.is_none() && answer.local_addresses.is_empty() {
        return Err(Error::Protocol("missing-addresses".to_string()));
    }
    if !answer.accepted && answer.reason.as_deref().unwrap_or_default().is_empty() {
        return Err(Error::Protocol("missing-rejection-reason".to_string()));
    }
    // Surface skew if either side was tolerated. The strict-Fresh case wins
    // when both are strict; otherwise tolerance applied somewhere.
    Ok(
        if offer_outcome == FreshnessOutcome::Fresh && answer_outcome == FreshnessOutcome::Fresh {
            FreshnessOutcome::Fresh
        } else {
            FreshnessOutcome::FreshWithinSkewTolerance
        },
    )
}

/// NTP-style clock-skew estimate from a completed offer/answer round-trip.
/// Returns the responder's apparent offset relative to the initiator in
/// milliseconds (positive = responder clock ahead). Requires the responder
/// to have populated `answer.offer_received_at`; older responders won't, in
/// which case this returns `None`.
///
/// Symmetric one-way-delay assumption (the standard NTP offset formula):
///   offset = ((T2 - T1) + (T3 - T4)) / 2
/// where T1 = offer.issued_at, T2 = answer.offer_received_at,
///       T3 = answer.issued_at, T4 = answer_received_at.
pub fn estimate_clock_skew(
    offer: &TraversalOffer,
    answer: &TraversalAnswer,
    answer_received_at: u64,
) -> Option<i64> {
    let t1 = offer.issued_at as i64;
    let t2 = answer.offer_received_at? as i64;
    let t3 = answer.issued_at as i64;
    let t4 = answer_received_at as i64;
    Some(((t2 - t1) + (t3 - t4)) / 2)
}

/// Returns Ok(outcome) if the (issued_at, expires_at) pair is acceptable
/// against `now` under the configured TTL plus `FRESHNESS_SKEW_TOLERANCE_MS`
/// of clock-skew grace on each side. Returns Err with the rejection class if
/// the message is genuinely outside the tolerated window.
///
/// Both sides are bounded. Backwards, a signal is accepted up to
/// `signal_ttl_ms + FRESHNESS_SKEW_TOLERANCE_MS` after it was issued.
/// Forwards, a signal issued ahead of the local clock is accepted only within
/// `FRESHNESS_SKEW_TOLERANCE_MS` and only as tolerated, never as strictly
/// fresh. The wire `expires_at` is chosen by the sender and is independent of
/// its `issued_at`, so it is clamped to the issuer's own stamp plus our
/// configured TTL; a sender may shorten its own expiry but cannot widen the
/// window we apply. One stamp is therefore acceptable over
/// `signal_ttl_ms + 2 * FRESHNESS_SKEW_TOLERANCE_MS` of wall clock, whatever
/// the sender declares.
fn check_freshness(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    signal_ttl_ms: u64,
) -> Result<FreshnessOutcome, FreshnessReject> {
    let effective_expiry = expires_at.min(issued_at.saturating_add(signal_ttl_ms));
    // Exactly one of these is non-zero: a saturating signed age without a
    // signed type.
    let ahead = issued_at.saturating_sub(now);
    let age = now.saturating_sub(issued_at);

    let strict_ok = ahead == 0 && effective_expiry > now && age <= signal_ttl_ms;
    if strict_ok {
        return Ok(FreshnessOutcome::Fresh);
    }
    if ahead > FRESHNESS_SKEW_TOLERANCE_MS {
        return Err(FreshnessReject::FutureDated);
    }
    let tolerated_ok = effective_expiry.saturating_add(FRESHNESS_SKEW_TOLERANCE_MS) > now
        && age <= signal_ttl_ms.saturating_add(FRESHNESS_SKEW_TOLERANCE_MS);
    if tolerated_ok {
        Ok(FreshnessOutcome::FreshWithinSkewTolerance)
    } else {
        Err(FreshnessReject::Stale)
    }
}
