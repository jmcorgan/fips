use super::handoff::EstablishedTraversal;
use crate::config::PeerConfig;
use serde::{Deserialize, Serialize};

pub const ADVERT_KIND: u16 = 37195;
pub const ADVERT_IDENTIFIER: &str = "fips-overlay-v1";
pub const ADVERT_VERSION: u32 = 1;
pub const SIGNAL_KIND: u16 = 21059;
// Defined in the nostr `handoff` submodule; re-exported here so the
// existing punch sender / receiver imports remain unchanged.
pub use super::handoff::{PUNCH_ACK_MAGIC, PUNCH_MAGIC};
pub const PROTOCOL_VERSION: &str = "1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraversalAddress {
    pub protocol: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchHint {
    #[serde(rename = "startAtMs")]
    pub start_at_ms: u64,
    #[serde(rename = "intervalMs")]
    pub interval_ms: u64,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverlayTransportKind {
    Udp,
    Tcp,
    Tor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayEndpointAdvert {
    pub transport: OverlayTransportKind,
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayAdvert {
    pub identifier: String,
    pub version: u32,
    pub endpoints: Vec<OverlayEndpointAdvert>,
    #[serde(rename = "signalRelays", skip_serializing_if = "Option::is_none")]
    pub signal_relays: Option<Vec<String>>,
    #[serde(rename = "stunServers", skip_serializing_if = "Option::is_none")]
    pub stun_servers: Option<Vec<String>>,
}

impl OverlayAdvert {
    pub fn has_udp_nat_endpoint(&self) -> bool {
        self.endpoints.iter().any(|endpoint| {
            endpoint.transport == OverlayTransportKind::Udp
                && endpoint.addr.eq_ignore_ascii_case("nat")
        })
    }
}

#[derive(Debug, Clone)]
pub struct CachedOverlayAdvert {
    pub author_npub: String,
    pub advert: OverlayAdvert,
    pub created_at: u64,
    pub valid_until_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraversalOffer {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    pub nonce: String,
    #[serde(rename = "senderNpub")]
    pub sender_npub: String,
    #[serde(rename = "recipientNpub")]
    pub recipient_npub: String,
    #[serde(rename = "reflexiveAddress")]
    pub reflexive_address: Option<TraversalAddress>,
    #[serde(rename = "localAddresses")]
    pub local_addresses: Vec<TraversalAddress>,
    #[serde(rename = "stunServer")]
    pub stun_server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraversalAnswer {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    pub nonce: String,
    #[serde(rename = "senderNpub")]
    pub sender_npub: String,
    #[serde(rename = "recipientNpub")]
    pub recipient_npub: String,
    #[serde(rename = "inReplyTo")]
    pub in_reply_to: String,
    pub accepted: bool,
    #[serde(rename = "reflexiveAddress")]
    pub reflexive_address: Option<TraversalAddress>,
    #[serde(rename = "localAddresses")]
    pub local_addresses: Vec<TraversalAddress>,
    #[serde(rename = "stunServer")]
    pub stun_server: Option<String>,
    pub punch: Option<PunchHint>,
    pub reason: Option<String>,
    /// Responder's local wall-clock (Unix ms) at the moment it received the
    /// offer. Optional / non-breaking: the initiator uses this to derive an
    /// NTP-style clock-skew estimate against the offer's `issued_at`. Older
    /// responders that don't fill this in still produce valid answers.
    #[serde(
        rename = "offerReceivedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub offer_received_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchPacketKind {
    Probe,
    Ack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchPacket {
    pub kind: PunchPacketKind,
    pub sequence: u32,
    pub session_hash: [u8; 16],
}

/// Outcome of `NostrRendezvous::record_traversal_failure`.
#[derive(Debug, Clone, Copy)]
pub struct NostrFailureDecision {
    pub consecutive_failures: u32,
    /// True iff the lifecycle should log at WARN; false → DEBUG (rate-limit).
    pub should_warn: bool,
    /// Wall-clock ms before which retries should not fire, if cooldown
    /// is in effect.
    pub cooldown_until_ms: Option<u64>,
    /// True only on the streak-threshold-crossing transition. Lifecycle
    /// should run a one-shot stale-advert re-check (B6) when set.
    pub crossed_threshold: bool,
}

/// Snapshot row for `show_peers` rendering of per-npub Nostr-traversal state.
#[derive(Debug, Clone)]
pub struct NostrPeerFailureView {
    pub npub: String,
    pub consecutive_failures: u32,
    pub cooldown_until_ms: Option<u64>,
    pub last_observed_skew_ms: Option<i64>,
}

/// Outcome of `NostrRendezvous::refetch_advert_for_stale_check` (B6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NostrRefetchOutcome {
    Evicted,
    Refreshed,
    SameAdvert,
    Skipped,
}
