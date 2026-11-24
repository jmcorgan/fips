//! The traversal's pure rules: the bound on an inbound offer's fields and
//! the reasons an offer is refused, the canonical spelling of a peer's
//! npub, which relays a signal goes to, where a peer's inbox relay list is
//! looked up and what is used when none is found, the punch hint a node
//! sends, and when an observed clock skew is worth noting.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::key::PublicKey;
use nostr::types::{RelayUrl, Timestamp};

use super::super::adverts::ingest::newest_by_author;
use super::super::error::Error;
use super::super::event::inbox::inbox_relays;
use super::super::types::{PunchHint, TraversalOffer};

/// The longest `sessionId` or `nonce`, in bytes, an inbound traversal offer
/// may carry. The seen-sessions memory keys on the session id, and the nonce
/// is copied into the answer. Ours are about 30 bytes.
pub const MAX_OFFER_FIELD_BYTES: usize = 128;

/// How far back a peer's kind 10050 inbox relay list is looked up.
pub const INBOX_LOOKBACK: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How long the lookup of a peer's inbox relay list waits for the relays.
pub const INBOX_FETCH_TIMEOUT: Duration = Duration::from_millis(1500);

/// The observed clock skew, in milliseconds, from which a traversal notes it
/// at debug rather than trace: well below the 60 s freshness tolerance, but
/// enough to show a real clock problem on either side.
pub const SIGNIFICANT_SKEW_MS: u64 = 30_000;

/// Why an inbound offer was refused before it was answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Its session id or nonce is longer than [`MAX_OFFER_FIELD_BYTES`].
    Oversized,
    /// It is not an offer.
    Invalid,
    /// It was issued longer ago than the signal lifetime and the skew
    /// tolerance allow.
    Expired,
    /// It was issued further ahead of our clock than the skew tolerance.
    FutureDated,
    /// Its named sender or recipient is not the key that sealed it or us.
    IdentityMismatch,
    /// Its session id was seen inside the replay window.
    Replay(String),
    /// The seen-sessions memory is full of live session ids.
    SeenFull,
}

impl RejectReason {
    /// The protocol reason code the error carries, for the reasons that are
    /// protocol errors.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            RejectReason::Oversized => Some("oversized-offer"),
            RejectReason::Invalid => Some("invalid-offer"),
            RejectReason::Expired => Some("expired-offer"),
            RejectReason::FutureDated => Some("future-dated-offer"),
            RejectReason::IdentityMismatch => Some("identity-mismatch"),
            RejectReason::SeenFull => Some("seen-sessions-full"),
            RejectReason::Replay(_) => None,
        }
    }

    /// The reason whose protocol reason code is `code`, if any.
    pub fn from_code(code: &str) -> Option<Self> {
        [
            RejectReason::Oversized,
            RejectReason::Invalid,
            RejectReason::Expired,
            RejectReason::FutureDated,
            RejectReason::IdentityMismatch,
            RejectReason::SeenFull,
        ]
        .into_iter()
        .find(|reason| reason.code() == Some(code))
    }

    /// Whether the refusal belongs to a class that ordinary relay delivery
    /// lag cannot explain, and so warrants a warning on a node running at
    /// the default log level. A stale offer is benign and is excluded.
    pub fn adversarial(&self) -> bool {
        matches!(
            self,
            RejectReason::Oversized
                | RejectReason::Invalid
                | RejectReason::FutureDated
                | RejectReason::IdentityMismatch
        )
    }
}

impl fmt::Display for RejectReason {
    /// The text `BootstrapError` gives the same refusal, which the
    /// "rejected traversal offer" line prints as its `error` field.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self, self.code()) {
            (RejectReason::Replay(session), _) => {
                write!(f, "replayed or duplicate session id: {session}")
            }
            (_, Some(code)) => write!(f, "protocol error: {code}"),
            (_, None) => Ok(()),
        }
    }
}

impl From<RejectReason> for Error {
    /// The machine error carrying the same text.
    fn from(reason: RejectReason) -> Self {
        match reason {
            RejectReason::Replay(session) => Error::Replay(session),
            other => Error::Protocol(other.code().unwrap_or_default().to_string()),
        }
    }
}

/// Refuse an inbound offer whose session id or nonce is longer than
/// [`MAX_OFFER_FIELD_BYTES`]. An honest peer never sends one.
pub fn check_offer_bounds(offer: &TraversalOffer) -> Result<(), RejectReason> {
    if offer.session_id.len() > MAX_OFFER_FIELD_BYTES || offer.nonce.len() > MAX_OFFER_FIELD_BYTES {
        return Err(RejectReason::Oversized);
    }
    Ok(())
}

/// The key `npub` names, and its canonical npub: the text the advert cache,
/// the failure state, the initiator set and traversal signals use for that
/// key. `npub` may be in any letter case; text that is not a NIP-19 npub is
/// refused, as `fips_core::identity::decode_npub` refuses it.
pub fn peer_key(npub: &str) -> Result<(PublicKey, String), Error> {
    let invalid = |reason: String| Error::InvalidPeerNpub {
        npub: npub.to_string(),
        reason,
    };
    let key = fips_core::identity::decode_npub(npub).map_err(|e| invalid(e.to_string()))?;
    let pubkey = PublicKey::from_slice(&key.serialize()).map_err(|e| invalid(e.to_string()))?;
    Ok((pubkey, fips_core::identity::encode_npub(&key)))
}

/// The canonical npub for `npub`, or `npub` as written when it names no key.
/// State keyed by npub is keyed by this, so every spelling of one key shares
/// one entry.
pub fn canonical_npub(npub: &str) -> String {
    peer_key(npub).map_or_else(|_| npub.to_string(), |(_, canonical)| canonical)
}

/// An npub shortened for logging: its first and last four characters.
pub fn short_npub(npub: &str) -> String {
    npub.strip_prefix("npub1")
        .filter(|s| s.len() >= 8)
        .map(|s| format!("npub1{}..{}", &s[..4], &s[s.len() - 4..]))
        .unwrap_or_else(|| npub.to_string())
}

/// Shorten a peer-supplied identifier for logging.
///
/// Truncates on a character boundary rather than a byte index. The input is a
/// session id taken straight from a remote party's JSON with no charset
/// validation, and slicing by byte offset panics when the boundary falls
/// inside a multi-byte character.
pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Retain only the candidates the client pool actually holds.
///
/// The relay client refuses the whole send if any single URL is outside the
/// pool, so a signal addressed to a peer's advertised relays fails entirely
/// on one relay we are not configured with. Filtering first turns that into a
/// send to the relays we share.
///
/// Comparison is on the normalized `RelayUrl` rather than the raw string,
/// because the pool is keyed that way: a candidate spelled
/// `wss://relay.example/` matches a configured `wss://relay.example`. Order
/// is preserved, candidates that fail to parse are dropped, and duplicates
/// that normalize alike are collapsed.
pub fn retain_pooled_relays(candidates: &[String], pool: &BTreeSet<RelayUrl>) -> Vec<String> {
    let mut seen: BTreeSet<RelayUrl> = BTreeSet::new();
    let mut usable = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let Ok(url) = RelayUrl::parse(candidate) else {
            continue;
        };
        if pool.contains(&url) && seen.insert(url.clone()) {
            usable.push(url.to_string());
        }
    }
    usable
}

/// Choose the relays a traversal signal for one peer should be sent to.
///
/// The candidates are the peer's NIP-17 inbox relays, then the relays its
/// advert nominates for signaling, then our own DM relays: remote-supplied
/// first, ours last, so a peer's preference is honored where we can act on
/// it. The result is whatever survives [`retain_pooled_relays`].
pub fn signal_relays(
    inbox: &[String],
    advert_signal: Option<&[String]>,
    dm_relays: &[String],
    pool: &BTreeSet<RelayUrl>,
) -> Vec<String> {
    let mut merged: Vec<String> = inbox.to_vec();
    for relay in advert_signal.unwrap_or_default().iter().chain(dm_relays) {
        if !merged.contains(relay) {
            merged.push(relay.clone());
        }
    }
    retain_pooled_relays(&merged, pool)
}

/// Where and how a peer's inbox relay list is looked up: on our DM relays
/// then our advert relays, each once, for lists by `target` no older than
/// [`INBOX_LOOKBACK`] at `now_ms`.
pub fn inbox_lookup(
    target: PublicKey,
    dm_relays: &[String],
    advert_relays: &[String],
    now_ms: u64,
) -> (Vec<String>, Filter) {
    let mut relays = dm_relays.to_vec();
    for relay in advert_relays {
        if !relays.contains(relay) {
            relays.push(relay.clone());
        }
    }
    let filter = Filter::new()
        .author(target)
        .kind(Kind::InboxRelays)
        .since(Timestamp::from(
            (now_ms / 1000).saturating_sub(INBOX_LOOKBACK.as_secs()),
        ));
    (relays, filter)
}

/// The relays `target`'s newest inbox relay list among `fetched` names, or
/// our `dm_relays` when the fetch failed or found no non-empty list by it.
pub fn inbox_or_fallback<E>(
    fetched: Result<&[Event], E>,
    target: PublicKey,
    dm_relays: &[String],
) -> Vec<String> {
    let Ok(events) = fetched else {
        return dm_relays.to_vec();
    };
    match newest_by_author(events.iter(), target).map(inbox_relays) {
        Some(relays) if !relays.is_empty() => relays,
        _ => dm_relays.to_vec(),
    }
}

/// The punch hint a node sends: its first probe `start_delay_ms` after
/// `now_ms`, then one every `interval_ms` for `duration_ms`.
pub fn punch_hint(
    now_ms: u64,
    start_delay_ms: u64,
    interval_ms: u64,
    duration_ms: u64,
) -> PunchHint {
    PunchHint {
        start_at_ms: now_ms + start_delay_ms,
        interval_ms,
        duration_ms,
    }
}

/// Whether an observed clock skew is large enough to note at debug.
pub fn skew_is_significant(skew_ms: i64) -> bool {
    skew_ms.unsigned_abs() >= SIGNIFICANT_SKEW_MS
}

#[cfg(test)]
#[path = "tests/rules.rs"]
mod tests;
