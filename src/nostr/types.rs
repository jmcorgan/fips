//! Shell-side Nostr rendezvous types: the error and the events the node
//! receives. The wire and payload types are the machine's, re-exported here.

use super::handoff::EstablishedTraversal;
use crate::config::PeerConfig;

pub use super::machine::types::*;

// Defined in the nostr `handoff` submodule; re-exported here so the
// existing punch sender / receiver imports remain unchanged.
pub use super::handoff::{PUNCH_ACK_MAGIC, PUNCH_MAGIC};

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("bootstrap disabled")]
    Disabled,
    #[error("peer {0} has no overlay advert")]
    MissingAdvert(String),
    #[error("peer {0} advert does not contain udp:nat endpoint")]
    MissingNatEndpoint(String),
    #[error("peer {0} has no usable traversal relays")]
    MissingRelays(String),
    #[error("invalid overlay advert: {0}")]
    InvalidAdvert(String),
    #[error("invalid npub '{npub}': {reason}")]
    InvalidPeerNpub { npub: String, reason: String },
    #[error("signal timeout waiting for answer from {0}")]
    SignalTimeout(String),
    #[error("traversal attempt timed out for {0}")]
    PunchTimeout(String),
    #[error("replayed or duplicate session id: {0}")]
    Replay(String),
    #[error("stun failed: {0}")]
    Stun(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("nostr error: {0}")]
    Nostr(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("event parse error: {0}")]
    EventParse(String),
}

#[derive(Debug)]
pub enum BootstrapEvent {
    Established {
        traversal: EstablishedTraversal,
    },
    Failed {
        peer_config: PeerConfig,
        reason: String,
    },
}
