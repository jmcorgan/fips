//! The overlay advert event, kind 37195 (FRC-1601 Section 4): its tags, and
//! the one tag the shell reads back from a peer's.

use alloc::string::{String, ToString};

use nostr::event::{Event, Tag};
use nostr::types::Timestamp;

use super::super::error::Error;
use super::super::types::PROTOCOL_VERSION;
use super::{NodeSigner, SignedKind, at};

/// Our advert carrying `content`, created at `unix_ms`: tagged with
/// `identifier`, `app` as its protocol, the protocol version, and an
/// expiration `ttl_secs` after `unix_ms`, in that order.
pub fn advert_event(
    signer: &NodeSigner,
    content: String,
    identifier: &str,
    app: &str,
    ttl_secs: u64,
    unix_ms: u64,
    aux: [u8; 32],
) -> Result<Event, Error> {
    let expires_at_ms = unix_ms.saturating_add(ttl_secs.saturating_mul(1000));
    let tags = alloc::vec![
        Tag::identifier(identifier.to_string()),
        Tag::custom("protocol", [app.to_string()]),
        Tag::custom("version", [PROTOCOL_VERSION.to_string()]),
        Tag::expiration(Timestamp::from((expires_at_ms / 1000).max(1))),
    ];
    signer.sign(SignedKind::Advert, at(unix_ms), tags, content, aux)
}

/// The value of an advert's first `protocol` tag, if it has one with a value.
pub fn protocol(event: &Event) -> Option<&str> {
    event
        .tags
        .iter()
        .find(|tag| tag.kind() == "protocol")
        .and_then(|tag| tag.content())
}

#[cfg(test)]
#[path = "tests/advert.rs"]
mod tests;
