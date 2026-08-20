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

/// The separator between a transport type and an instance name in a
/// [`PeerAddress::transport`] field (`"udp/aware"`).
///
/// `/` rather than `:` or `.`: it is already how FIPS qualifies an instance
/// inside an *address* (`"eth0/aa:bb:cc:dd:ee:ff"` for Ethernet,
/// `"hci0/AA:BB:…"` for BLE), and it cannot occur in a transport type name,
/// so the split is unambiguous.
const INSTANCE_SEPARATOR: char = '/';

/// A [`PeerAddress::transport`] field, split into a transport *type* and an
/// optional *instance name*.
///
/// A node can run several instances of one transport type
/// ([`TransportInstances::Named`](crate::config::TransportInstances::Named)) —
/// two UDP sockets, say, one pinned to infrastructure Wi-Fi and one to a Wi-Fi
/// Aware data path. Both bind wildcard sockets, so the dialer's address-family
/// test cannot tell them apart: every dial would deterministically take the
/// same instance and the other socket would never carry traffic. Qualifying
/// the transport field with the configured instance name says which one an
/// address belongs to.
///
/// Syntax: `"<type>"` or `"<type>/<instance>"`, where `<instance>` is the key
/// the transport was configured under. A bare type is *unqualified* and
/// matches any instance of that type, which is what every existing config and
/// caller produces — so this is purely additive.
///
/// ```
/// use fips::config::TransportSpec;
///
/// assert_eq!(TransportSpec::parse("udp").instance, None);
/// assert_eq!(TransportSpec::parse("udp/aware").kind, "udp");
/// assert_eq!(TransportSpec::parse("udp/aware").instance, Some("aware"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportSpec<'a> {
    /// The transport type name, as reported by `TransportType::name`.
    pub kind: &'a str,
    /// The required instance name, or `None` to match any instance.
    pub instance: Option<&'a str>,
}

impl<'a> TransportSpec<'a> {
    /// Split a transport field into type and optional instance name.
    ///
    /// A field with no separator, an empty type, or an empty instance is
    /// treated as an unqualified type — malformed input degrades to the
    /// pre-existing behaviour rather than becoming an unmatchable name.
    pub fn parse(field: &'a str) -> Self {
        match field.split_once(INSTANCE_SEPARATOR) {
            Some((kind, instance)) if !kind.is_empty() && !instance.is_empty() => Self {
                kind,
                instance: Some(instance),
            },
            _ => Self {
                kind: field,
                instance: None,
            },
        }
    }

    /// Whether a transport of type `kind` configured under `name` satisfies
    /// this spec. An unqualified spec accepts any instance; a qualified one
    /// accepts only an exact name match, and never falls back.
    pub fn matches(&self, kind: &str, name: Option<&str>) -> bool {
        self.kind == kind && self.instance.is_none_or(|want| name == Some(want))
    }
}

/// A transport-specific address for reaching a peer.
///
/// Each peer can have multiple addresses across different transports,
/// allowing fallback if one transport is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAddress {
    /// Transport type (e.g., "udp", "tor", "ethernet"), optionally qualified
    /// with a named instance (`"udp/aware"`) — see [`TransportSpec`].
    pub transport: String,

    /// Transport-specific address string.
    ///
    /// Format depends on transport type:
    /// - UDP/TCP: "host:port" — IP address or DNS hostname
    ///   (e.g., "192.168.1.1:2121" or "peer1.example.com:2121")
    /// - Ethernet: "interface/mac" (e.g., "eth0/aa:bb:cc:dd:ee:ff")
    pub addr: String,

    /// Priority for address selection (lower = preferred).
    /// When multiple addresses are available, lower priority addresses
    /// are tried first.
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Wall-clock observation timestamp (Unix ms) for ranking by recency.
    ///
    /// `None` means "no freshness signal", typically an operator-edited
    /// static config. The dialer sorts candidates by this field descending
    /// so freshly observed overlay or runtime hints can be tried before stale
    /// static addresses. This field is runtime-only and is ignored when
    /// comparing peer-address lists for config changes.
    #[serde(default, skip_serializing_if = "Option::is_none", skip_deserializing)]
    pub seen_at_ms: Option<u64>,
}

impl PartialEq for PeerAddress {
    fn eq(&self, other: &Self) -> bool {
        self.transport == other.transport
            && self.addr == other.addr
            && self.priority == other.priority
    }
}

impl Eq for PeerAddress {}

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
            seen_at_ms: None,
        }
    }

    /// Create a new peer address with priority.
    pub fn with_priority(
        transport: impl Into<String>,
        addr: impl Into<String>,
        priority: u8,
    ) -> Self {
        Self {
            transport: transport.into(),
            addr: addr.into(),
            priority,
            seen_at_ms: None,
        }
    }

    /// Tag this address with a freshness timestamp for source-agnostic
    /// candidate ranking.
    pub fn with_seen_at_ms(mut self, seen_at_ms: u64) -> Self {
        self.seen_at_ms = Some(seen_at_ms);
        self
    }

    /// The [`transport`](Self::transport) field split into type and optional
    /// instance name.
    pub fn spec(&self) -> TransportSpec<'_> {
        TransportSpec::parse(&self.transport)
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
    ///
    /// At least one address is required unless `via_nostr` is `true`,
    /// in which case the address list may be empty and endpoints are
    /// resolved from the peer's Nostr advert at dial time.
    #[serde(default)]
    pub addresses: Vec<PeerAddress>,

    /// Connection policy for this peer.
    #[serde(default)]
    pub connect_policy: ConnectPolicy,

    /// Whether to automatically reconnect after link-dead removal.
    /// When true (default), the node will retry connecting with exponential
    /// backoff after MMP removes this peer due to liveness timeout.
    #[serde(default = "default_auto_reconnect")]
    pub auto_reconnect: bool,

    /// Whether to append Nostr-advertised endpoints when dialing this peer.
    ///
    /// Static addresses are still attempted first; advert-derived endpoints are
    /// appended as fallback candidates.
    #[serde(default)]
    pub via_nostr: bool,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            npub: String::new(),
            alias: None,
            addresses: Vec::new(),
            connect_policy: ConnectPolicy::default(),
            auto_reconnect: default_auto_reconnect(),
            via_nostr: false,
        }
    }
}

impl PeerConfig {
    /// Create a new peer config with a single address.
    pub fn new(
        npub: impl Into<String>,
        transport: impl Into<String>,
        addr: impl Into<String>,
    ) -> Self {
        Self {
            npub: npub.into(),
            alias: None,
            addresses: vec![PeerAddress::new(transport, addr)],
            connect_policy: ConnectPolicy::default(),
            auto_reconnect: default_auto_reconnect(),
            via_nostr: false,
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

#[cfg(test)]
mod transport_spec_tests {
    use super::*;

    #[test]
    fn a_bare_type_is_unqualified_and_matches_any_instance() {
        let spec = TransportSpec::parse("udp");
        assert_eq!(spec.kind, "udp");
        assert_eq!(spec.instance, None);
        assert!(spec.matches("udp", None), "an unnamed Single instance");
        assert!(spec.matches("udp", Some("aware")), "a named instance");
        assert!(!spec.matches("tcp", None), "a different transport type");
    }

    #[test]
    fn a_qualified_type_matches_only_that_instance() {
        let spec = TransportSpec::parse("udp/aware");
        assert_eq!(spec.kind, "udp");
        assert_eq!(spec.instance, Some("aware"));
        assert!(spec.matches("udp", Some("aware")));
        assert!(
            !spec.matches("udp", Some("lan")),
            "a different instance must not be substituted"
        );
        assert!(
            !spec.matches("udp", None),
            "an unnamed instance cannot satisfy a named request"
        );
        assert!(!spec.matches("tcp", Some("aware")));
    }

    #[test]
    fn malformed_fields_degrade_to_an_unqualified_type() {
        // Neither half may be empty; anything else keeps the whole string as
        // the type, so a typo fails the type test rather than silently
        // matching some instance.
        for field in ["udp/", "/aware", "/"] {
            let spec = TransportSpec::parse(field);
            assert_eq!(spec.kind, field, "{field}");
            assert_eq!(spec.instance, None, "{field}");
        }
    }

    #[test]
    fn only_the_first_separator_splits() {
        let spec = TransportSpec::parse("udp/a/b");
        assert_eq!(spec.kind, "udp");
        assert_eq!(spec.instance, Some("a/b"));
    }

    #[test]
    fn peer_address_exposes_its_spec() {
        let addr = PeerAddress::new("udp/aware", "[fe80::1%7]:4872");
        assert_eq!(addr.spec().instance, Some("aware"));
        assert_eq!(
            PeerAddress::new("udp", "1.2.3.4:2121").spec().instance,
            None
        );
    }
}
