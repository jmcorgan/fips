//! Shell-side Nostr rendezvous types: the error and the events the node
//! receives. The wire and payload types are the machine's, re-exported here.

use crate::config::PeerConfig;
use crate::node::handoff::EstablishedTraversal;

pub use super::machine::types::*;

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

impl From<super::machine::error::Error> for BootstrapError {
    /// The same variant with the same text, so every caller and every log
    /// line sees what it saw before the code that failed moved.
    fn from(e: super::machine::error::Error) -> Self {
        use super::machine::error::Error;
        match e {
            Error::Protocol(reason) => BootstrapError::Protocol(reason),
            Error::Stun(reason) => BootstrapError::Stun(reason),
            Error::InvalidAdvert(reason) => BootstrapError::InvalidAdvert(reason),
            Error::Nostr(reason) => BootstrapError::Nostr(reason),
            Error::EventParse(reason) => BootstrapError::EventParse(reason),
            Error::MissingAdvert(npub) => BootstrapError::MissingAdvert(npub),
            Error::InvalidPeerNpub { npub, reason } => {
                BootstrapError::InvalidPeerNpub { npub, reason }
            }
            Error::Replay(session) => BootstrapError::Replay(session),
            Error::Disabled => BootstrapError::Disabled,
            Error::MissingNatEndpoint(npub) => BootstrapError::MissingNatEndpoint(npub),
            Error::MissingRelays(npub) => BootstrapError::MissingRelays(npub),
            Error::SignalTimeout(npub) => BootstrapError::SignalTimeout(npub),
            Error::PunchTimeout(peer) => BootstrapError::PunchTimeout(peer),
            Error::Io(error) => BootstrapError::Io(std::io::Error::other(error)),
        }
    }
}

impl From<&crate::config::NostrRendezvousConfig> for super::machine::params::Params {
    /// The values the machine reads, each copied from its own configuration
    /// key.
    fn from(c: &crate::config::NostrRendezvousConfig) -> Self {
        Self {
            failure_streak_threshold: c.failure_streak_threshold,
            extended_cooldown_secs: c.extended_cooldown_secs,
            warn_log_interval_secs: c.warn_log_interval_secs,
            failure_state_max_entries: c.failure_state_max_entries,
            replay_window_secs: c.replay_window_secs,
            seen_sessions_max_entries: c.seen_sessions_max_entries,
            advertise: c.advertise,
            advert_cache_max_entries: c.advert_cache_max_entries,
            advert_refresh_secs: c.advert_refresh_secs,
            app: c.app.clone(),
            advert_relays: c.advert_relays.clone(),
            dm_relays: c.dm_relays.clone(),
            stun_servers: c.stun_servers.clone(),
            advert_ttl_secs: c.advert_ttl_secs,
            signal_ttl_secs: c.signal_ttl_secs,
            attempt_timeout_secs: c.attempt_timeout_secs,
            punch_start_delay_ms: c.punch_start_delay_ms,
            punch_interval_ms: c.punch_interval_ms,
            punch_duration_ms: c.punch_duration_ms,
            share_local_candidates: c.share_local_candidates,
            protocol_mismatch_cooldown_secs: c.protocol_mismatch_cooldown_secs,
            max_concurrent_incoming_offers: c.max_concurrent_incoming_offers,
            max_concurrent_offers_per_npub: c.max_concurrent_offers_per_npub,
        }
    }
}
