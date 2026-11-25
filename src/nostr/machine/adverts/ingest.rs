//! The checks every advert a relay delivers passes before it is cached.
//!
//! Three paths bring a peer's advert in: the subscription's stream, the
//! targeted fetch on a dial, and the stale-advert refetch. Each calls
//! [`check`], which runs, refusing at the first that fails:
//!
//! 1. the validity horizon, before anything else is read;
//! 2. [`screen`]: the `protocol` tag and the content bound;
//! 3. [`authentic`]: the event's id and signature. This is where the node
//!    checks a peer advert's signature itself, rather than relying on the
//!    relay client to have done so;
//! 4. [`decode`]: the JSON, the list bounds and the body rules of
//!    `adverts/mod.rs`;
//! 5. the clamp on a future `created_at`.
//!
//! The cheap refusals come before the signature check, so a flood of events
//! that are not our adverts, or are oversized, costs no signature check, and
//! a forged advert is never decoded. Every refusal is a silent discard, so
//! the order is not visible to a peer. The author test and the choice among
//! several adverts stay with each path, which take them in different orders.
//!
//! Also here: the bounds a node's own advert is cut to before it is
//! published ([`clamp_own`]), and the advert lifetime arithmetic.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use fips_core::identity::secp;
use nostr::event::Event;
use nostr::key::PublicKey;
use nostr::nips::nip19::ToBech32;
use nostr::types::Timestamp;

use super::super::error::Error;
use super::super::event::advert::protocol;
use super::super::types::OverlayAdvert;
use super::{advert_valid_until_ms, effective_created_at_secs, validate_overlay_advert};

/// How many advert lifetimes (`advert_ttl_secs`) a peer's advert may be old
/// and still be cached.
pub const ADVERT_CACHE_STALE_GRACE_MULTIPLIER: u64 = 2;

/// The largest advert event content, in bytes, that is parsed at all.
pub const MAX_ADVERT_CONTENT_BYTES: usize = 8 * 1024;

/// The most entries an advert's `endpoints`, `signalRelays` or `stunServers`
/// list may carry. The cache keeps the parsed advert, where each entry costs
/// a string header on top of its bytes, so the content bound alone would let
/// thousands of one-character entries through.
pub const MAX_ADVERT_LIST_ENTRIES: usize = 32;

/// The grace-extended maximum age of a cached advert, in ms, for an advert
/// lifetime of `ttl_secs`.
pub fn max_age_ms(ttl_secs: u64) -> u64 {
    ttl_secs * 1000 * ADVERT_CACHE_STALE_GRACE_MULTIPLIER
}

/// Why an advert event did not parse.
#[derive(Debug)]
pub enum ParseError {
    /// The advert broke a content rule.
    Invalid(Error),
    /// Its content is not the advert's JSON.
    Json(serde_json::Error),
}

impl core::fmt::Display for ParseError {
    /// The text `BootstrapError` gives the same case.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Invalid(e) => write!(f, "{e}"),
            ParseError::Json(e) => write!(f, "serde error: {e}"),
        }
    }
}

/// Refuse an advert any of whose lists has more than
/// [`MAX_ADVERT_LIST_ENTRIES`] entries. The whole advert is refused, not cut,
/// so what is cached is always what the author signed.
pub fn check_lists(advert: &OverlayAdvert) -> Result<(), Error> {
    let lists = [
        ("endpoints", Some(advert.endpoints.len())),
        ("signalRelays", advert.signal_relays.as_ref().map(Vec::len)),
        ("stunServers", advert.stun_servers.as_ref().map(Vec::len)),
    ];
    for (name, len) in lists {
        if let Some(len) = len
            && len > MAX_ADVERT_LIST_ENTRIES
        {
            return Err(Error::InvalidAdvert(format!(
                "{name} has {len} entries, over the bound of {MAX_ADVERT_LIST_ENTRIES}"
            )));
        }
    }
    Ok(())
}

/// A peer's advert body, checked: its list bounds, then the body rules.
pub fn validate(advert: OverlayAdvert) -> Result<OverlayAdvert, Error> {
    check_lists(&advert)?;
    validate_overlay_advert(advert)
}

/// Screen `event` before its signature is checked: it carries our
/// `protocol` tag for `app`, and its content is within the content bound.
pub fn screen(event: &Event, app: &str) -> Result<(), ParseError> {
    let advertised_app = protocol(event).ok_or_else(|| {
        ParseError::Invalid(Error::InvalidAdvert("missing required protocol tag".into()))
    })?;
    if advertised_app != app {
        return Err(ParseError::Invalid(Error::InvalidAdvert(format!(
            "unsupported protocol '{}'",
            advertised_app
        ))));
    }
    if event.content.len() > MAX_ADVERT_CONTENT_BYTES {
        return Err(ParseError::Invalid(Error::InvalidAdvert(format!(
            "content of {} bytes, over the bound of {MAX_ADVERT_CONTENT_BYTES}",
            event.content.len()
        ))));
    }
    Ok(())
}

/// The advert body `event` carries: its content decoded as the advert's
/// JSON, then [`validate`]d.
pub fn decode(event: &Event) -> Result<OverlayAdvert, ParseError> {
    let advert: OverlayAdvert = serde_json::from_str(&event.content).map_err(ParseError::Json)?;
    validate(advert).map_err(ParseError::Invalid)
}

/// The advert `event` carries, if it is for `app` and passes every content
/// rule: [`screen`], then [`decode`]. It does not check the signature.
#[cfg(test)]
pub fn parse(event: &Event, app: &str) -> Result<OverlayAdvert, ParseError> {
    screen(event, app)?;
    decode(event)
}

/// Whether `event`'s id is the hash of what it carries and its signature is
/// its `pubkey`'s over that id. A peer's signed event is acted on only if
/// this holds.
pub fn authentic(event: &Event) -> bool {
    event.verify_with_ctx(secp()).is_ok()
}

/// The time `event`, an advert, stops being valid at `now_ms`, or `None` if
/// it already has. Its `expiration` tag is read as the relay client reads
/// it, so the client and this agree on whether it has expired.
pub fn valid_until_ms(event: &Event, max_age_ms: u64, now_ms: u64) -> Option<u64> {
    if event.is_expired_at(Timestamp::from(now_ms / 1000)) {
        return None;
    }
    advert_valid_until_ms(
        event.created_at.as_secs(),
        event.tags.expiration().map(|timestamp| timestamp.as_secs()),
        max_age_ms,
        now_ms,
    )
}

/// Newest event in `events` whose `pubkey` field is `author`.
///
/// It reads the field only and checks no signature: a caller drops the
/// events that are not [`authentic`] first. The relay pool does not check a
/// reply against the REQ filter unless `verify_subscriptions` or
/// `ban_relay_on_mismatch` is set, and neither is. A relay may therefore
/// answer an author-filtered request with an event it signed itself, so
/// the author test happens here, before the timestamp contest, not after:
/// a future-dated foreign event must not be able to suppress the genuine
/// one by winning `created_at`.
pub fn newest_by_author<'a>(
    events: impl Iterator<Item = &'a Event>,
    author: PublicKey,
) -> Option<&'a Event> {
    events
        .filter(|event| event.pubkey == author)
        .max_by_key(|event| event.created_at.as_secs())
}

/// The npub of `event`'s author, as the cache keys it.
pub fn author_npub(event: &Event) -> String {
    event.pubkey.to_bech32().expect("infallible")
}

/// An advert that passed [`check`]: its author, its body, its clamped
/// `created_at` and the end of its validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub author_npub: String,
    pub advert: OverlayAdvert,
    pub created_at: u64,
    pub valid_until_ms: u64,
}

/// Why [`check`] refused an advert event. The callers act only on which
/// step refused it, so the reason within a step is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// It is past its validity horizon.
    Expired,
    /// Its id or signature does not verify.
    Forged,
    /// It is not our advert, or it breaks a content rule.
    Invalid,
}

/// `event` as an advert to cache at `now_ms`, if it is one: still inside its
/// validity horizon (checked first, before anything is read), passing
/// [`screen`], [`authentic`], then [`decode`], with its `created_at` clamped
/// to no more than the skew tolerance ahead of `now_ms`. Every advert a
/// relay delivers passes through here.
pub fn check(event: &Event, app: &str, max_age_ms: u64, now_ms: u64) -> Result<Checked, Refusal> {
    check_with(event, app, max_age_ms, now_ms, decode)
}

/// [`check`], decoding with `decode`, so a test can see when the decode
/// runs.
fn check_with(
    event: &Event,
    app: &str,
    max_age_ms: u64,
    now_ms: u64,
    decode: impl FnOnce(&Event) -> Result<OverlayAdvert, ParseError>,
) -> Result<Checked, Refusal> {
    let valid_until_ms = valid_until_ms(event, max_age_ms, now_ms).ok_or(Refusal::Expired)?;
    screen(event, app).map_err(|_| Refusal::Invalid)?;
    if !authentic(event) {
        return Err(Refusal::Forged);
    }
    let advert = decode(event).map_err(|_| Refusal::Invalid)?;
    Ok(Checked {
        author_npub: author_npub(event),
        advert,
        created_at: effective_created_at_secs(event.created_at.as_secs(), now_ms),
        valid_until_ms,
    })
}

/// One list of our own advert cut to [`MAX_ADVERT_LIST_ENTRIES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListCut {
    /// The list's name in the advert.
    pub list: &'static str,
    /// How many entries it was configured with.
    pub configured: usize,
}

/// Cut each of our own advert's lists to [`MAX_ADVERT_LIST_ENTRIES`],
/// keeping the configured order, so peers do not refuse it. Returns each
/// list that was cut, for the shell to warn about.
pub fn clamp_own(advert: &mut OverlayAdvert) -> Vec<ListCut> {
    fn clamp<T>(list: &mut Vec<T>, name: &'static str, cuts: &mut Vec<ListCut>) {
        if list.len() > MAX_ADVERT_LIST_ENTRIES {
            cuts.push(ListCut {
                list: name,
                configured: list.len(),
            });
            list.truncate(MAX_ADVERT_LIST_ENTRIES);
        }
    }
    let mut cuts = Vec::new();
    clamp(&mut advert.endpoints, "endpoints", &mut cuts);
    if let Some(relays) = advert.signal_relays.as_mut() {
        clamp(relays, "signalRelays", &mut cuts);
    }
    if let Some(servers) = advert.stun_servers.as_mut() {
        clamp(servers, "stunServers", &mut cuts);
    }
    cuts
}

#[cfg(test)]
#[path = "tests/ingest.rs"]
mod tests;
