//! Peer configuration types.
//!
//! Known peer definitions with transport addresses and connection policies.

use serde::{Deserialize, Serialize};

/// Connection policy for a peer.
///
/// Determines when and how to establish a connection to a peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectPolicy {
    /// Connect to this peer automatically on node startup.
    /// This is the only policy supported in the initial implementation.
    #[default]
    AutoConnect,

    /// Connect only when traffic needs to be routed through this peer (future).
    OnDemand,

    /// Wait for explicit API call to connect (future).
    Manual,
}

/// A transport-specific address for reaching a peer.
///
/// Each peer can have multiple addresses across different transports,
/// allowing fallback if one transport is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAddress {
    /// Transport type (e.g., "udp", "tor", "ethernet").
    pub transport: String,

    /// Transport-specific address string.
    ///
    /// Format depends on transport type:
    /// - UDP: "host:port" (e.g., "192.168.1.1:2121")
    /// - Tor: "onion_address:port" (e.g., "xyz...abc.onion:2121")
    /// - Ethernet: "interface/mac" (future)
    pub addr: String,

    /// Priority for address selection (lower = preferred).
    /// When multiple addresses are available, lower priority addresses
    /// are tried first.
    #[serde(default = "default_priority")]
    pub priority: u8,
}

fn default_priority() -> u8 {
    100
}

fn default_auto_reconnect() -> bool {
    true
}

impl PeerAddress {
    /// Create a new peer address.
    pub fn new(transport: impl Into<String>, addr: impl Into<String>) -> Self {
        Self {
            transport: transport.into(),
            addr: addr.into(),
            priority: default_priority(),
        }
    }

    /// Create a new peer address with priority.
    pub fn with_priority(transport: impl Into<String>, addr: impl Into<String>, priority: u8) -> Self {
        Self {
            transport: transport.into(),
            addr: addr.into(),
            priority,
        }
    }
}

/// Configuration for a known peer.
///
/// Peers are identified by their Nostr public key (npub) and can have
/// multiple transport addresses for reaching them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// The peer's Nostr public key in npub (bech32) or hex format.
    pub npub: String,

    /// Human-readable alias for the peer (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// Transport addresses for reaching this peer.
    /// At least one address is required.
    pub addresses: Vec<PeerAddress>,

    /// Connection policy for this peer.
    #[serde(default)]
    pub connect_policy: ConnectPolicy,

    /// Whether to automatically reconnect after link-dead removal.
    /// When true (default), the node will retry connecting with exponential
    /// backoff after MMP removes this peer due to liveness timeout.
    #[serde(default = "default_auto_reconnect")]
    pub auto_reconnect: bool,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            npub: String::new(),
            alias: None,
            addresses: Vec::new(),
            connect_policy: ConnectPolicy::default(),
            auto_reconnect: default_auto_reconnect(),
        }
    }
}

impl PeerConfig {
    /// Create a new peer config with a single address.
    pub fn new(npub: impl Into<String>, transport: impl Into<String>, addr: impl Into<String>) -> Self {
        Self {
            npub: npub.into(),
            alias: None,
            addresses: vec![PeerAddress::new(transport, addr)],
            connect_policy: ConnectPolicy::default(),
            auto_reconnect: default_auto_reconnect(),
        }
    }

    /// Set an alias for the peer.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.alias = Some(alias.into());
        self
    }

    /// Add an additional address for the peer.
    pub fn with_address(mut self, addr: PeerAddress) -> Self {
        self.addresses.push(addr);
        self
    }

    /// Get addresses sorted by priority (lowest first).
    pub fn addresses_by_priority(&self) -> Vec<&PeerAddress> {
        let mut addrs: Vec<_> = self.addresses.iter().collect();
        addrs.sort_by_key(|a| a.priority);
        addrs
    }

    /// Check if this peer should auto-connect on startup.
    pub fn is_auto_connect(&self) -> bool {
        matches!(self.connect_policy, ConnectPolicy::AutoConnect)
    }
}
