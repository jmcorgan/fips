//! The NIP-42 relay authentication event, kind 22242, which a relay that
//! requires authentication asks a node for.

use alloc::string::{String, ToString};

use nostr::event::{Event, Tag};
use nostr::types::RelayUrl;

use super::super::error::Error;
use super::{NodeSigner, SignedKind, at};

/// The node's answer to `relay`'s authentication `challenge`, created at
/// `unix_ms`: tagged `challenge` then `relay`, the order nostr's own NIP-42
/// builder writes them in.
pub fn auth_event(
    signer: &NodeSigner,
    relay: &RelayUrl,
    challenge: &str,
    unix_ms: u64,
    aux: [u8; 32],
) -> Result<Event, Error> {
    let tags = alloc::vec![
        Tag::custom("challenge", [challenge.to_string()]),
        Tag::custom("relay", [relay.to_string()]),
    ];
    signer.sign(SignedKind::Auth, at(unix_ms), tags, String::new(), aux)
}

#[cfg(test)]
#[path = "tests/auth.rs"]
mod tests;
