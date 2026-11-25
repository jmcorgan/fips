//! The inbox relay list, kind 10050 (FRC-1601 Section 3.3): the list a node
//! publishes, and the relays read from a peer's.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nostr::event::{Event, Kind, Tag};
use nostr::types::RelayUrl;

use super::super::error::Error;
use super::{NodeSigner, SignedKind, at};

/// Our inbox relay list, created at `unix_ms`: one `["r", url]` tag for each
/// of `relays` that parses as a relay URL, in order, written as it parses.
pub fn inbox_list<S: AsRef<str>>(
    signer: &NodeSigner,
    relays: &[S],
    unix_ms: u64,
    aux: [u8; 32],
) -> Result<Event, Error> {
    let tags = relays
        .iter()
        .filter_map(|relay| RelayUrl::parse(relay.as_ref()).ok())
        .map(|relay| Tag::custom("r", [relay.to_string()]))
        .collect();
    signer.sign(
        SignedKind::InboxRelays,
        at(unix_ms),
        tags,
        String::new(),
        aux,
    )
}

/// The relays a kind 10050 inbox relay list names, in order, each once.
///
/// Read by the rules nostr 0.44 read it by, which every deployed node runs: a
/// tag of exactly two elements, either `["relay", url]` (NIP-17) with a
/// value other than `ALL_RELAYS`, or a bare `["r", url]` (every FIPS node
/// publishes this form) whose value starts `ws://` or `wss://`, and whose
/// value parses as a relay URL. An `r` tag with a read or write marker is a
/// NIP-65 entry and has no meaning here. nostr 0.45's per-NIP tag readers
/// accept more shapes (an extra or empty third element on a `relay` tag, a
/// leading space on an `r` value), so they are not used.
pub fn inbox_relays(event: &Event) -> Vec<String> {
    if event.kind != Kind::InboxRelays {
        return Vec::new();
    }
    let mut relays: Vec<String> = Vec::new();
    for tag in event.tags.iter() {
        let [name, value] = tag.as_slice() else {
            continue;
        };
        let readable = match name.as_str() {
            "relay" => value != "ALL_RELAYS",
            "r" => value.starts_with("ws://") || value.starts_with("wss://"),
            _ => false,
        };
        if !readable {
            continue;
        }
        let Ok(url) = RelayUrl::parse(value) else {
            continue;
        };
        let url = url.to_string();
        if !relays.contains(&url) {
            relays.push(url);
        }
    }
    relays
}

#[cfg(test)]
#[path = "tests/inbox.rs"]
mod tests;
