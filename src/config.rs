//! FIPS Configuration System
//!
//! Loads configuration from YAML files with a cascading priority system:
//! 1. `./fips.yaml` (current directory - highest priority)
//! 2. `~/.config/fips/fips.yaml` (user config directory)
//! 3. `/etc/fips/fips.yaml` (system - lowest priority)
//!
//! Values from higher priority files override those from lower priority files.
//!
//! # YAML Structure
//!
//! The YAML structure mirrors the sysctl-style paths in the architecture docs.
//! For example, `node.identity.nsec` in the docs corresponds to:
//!
//! ```yaml
//! node:
//!   identity:
//!     nsec: "nsec1..."
//! ```

use crate::{Identity, IdentityError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Default config filename.
const CONFIG_FILENAME: &str = "fips.yaml";

/// Errors that can occur during configuration loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config file {path}: {source}")]
    ParseYaml {
        path: PathBuf,
        source: serde_yaml::Error,
    },

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

/// Identity configuration (`node.identity.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Secret key in nsec (bech32) or hex format (`node.identity.nsec`).
    /// If not specified, a new keypair will be generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>,
}

// ============================================================================
// Node Configuration Subsections
// ============================================================================

/// Resource limits (`node.limits.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Max handshake-phase connections (`node.limits.max_connections`).
    #[serde(default = "LimitsConfig::default_max_connections")]
    pub max_connections: usize,
    /// Max authenticated peers (`node.limits.max_peers`).
    #[serde(default = "LimitsConfig::default_max_peers")]
    pub max_peers: usize,
    /// Max active links (`node.limits.max_links`).
    #[serde(default = "LimitsConfig::default_max_links")]
    pub max_links: usize,
    /// Max pending inbound handshakes (`node.limits.max_pending_inbound`).
    #[serde(default = "LimitsConfig::default_max_pending_inbound")]
    pub max_pending_inbound: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_peers: 128,
            max_links: 256,
            max_pending_inbound: 1000,
        }
    }
}

impl LimitsConfig {
    fn default_max_connections() -> usize { 256 }
    fn default_max_peers() -> usize { 128 }
    fn default_max_links() -> usize { 256 }
    fn default_max_pending_inbound() -> usize { 1000 }
}

/// Rate limiting (`node.rate_limit.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Token bucket burst capacity (`node.rate_limit.handshake_burst`).
    #[serde(default = "RateLimitConfig::default_handshake_burst")]
    pub handshake_burst: u32,
    /// Tokens/sec refill rate (`node.rate_limit.handshake_rate`).
    #[serde(default = "RateLimitConfig::default_handshake_rate")]
    pub handshake_rate: f64,
    /// Stale handshake cleanup timeout in seconds (`node.rate_limit.handshake_timeout_secs`).
    #[serde(default = "RateLimitConfig::default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            handshake_burst: 100,
            handshake_rate: 10.0,
            handshake_timeout_secs: 30,
        }
    }
}

impl RateLimitConfig {
    fn default_handshake_burst() -> u32 { 100 }
    fn default_handshake_rate() -> f64 { 10.0 }
    fn default_handshake_timeout_secs() -> u64 { 30 }
}

/// Retry/backoff configuration (`node.retry.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Max connection retry attempts (`node.retry.max_retries`).
    #[serde(default = "RetryConfig::default_max_retries")]
    pub max_retries: u32,
    /// Base backoff interval in seconds (`node.retry.base_interval_secs`).
    #[serde(default = "RetryConfig::default_base_interval_secs")]
    pub base_interval_secs: u64,
    /// Cap on exponential backoff in seconds (`node.retry.max_backoff_secs`).
    #[serde(default = "RetryConfig::default_max_backoff_secs")]
    pub max_backoff_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_interval_secs: 5,
            max_backoff_secs: 300,
        }
    }
}

impl RetryConfig {
    fn default_max_retries() -> u32 { 5 }
    fn default_base_interval_secs() -> u64 { 5 }
    fn default_max_backoff_secs() -> u64 { 300 }
}

/// Cache parameters (`node.cache.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Max entries in coord cache (`node.cache.coord_size`).
    #[serde(default = "CacheConfig::default_coord_size")]
    pub coord_size: usize,
    /// Coord cache entry TTL in seconds (`node.cache.coord_ttl_secs`).
    #[serde(default = "CacheConfig::default_coord_ttl_secs")]
    pub coord_ttl_secs: u64,
    /// Max entries in route cache (`node.cache.route_size`).
    #[serde(default = "CacheConfig::default_route_size")]
    pub route_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            coord_size: 50_000,
            coord_ttl_secs: 300,
            route_size: 10_000,
        }
    }
}

impl CacheConfig {
    fn default_coord_size() -> usize { 50_000 }
    fn default_coord_ttl_secs() -> u64 { 300 }
    fn default_route_size() -> usize { 10_000 }
}

/// Discovery protocol (`node.discovery.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Hop limit for LookupRequest flood (`node.discovery.ttl`).
    #[serde(default = "DiscoveryConfig::default_ttl")]
    pub ttl: u8,
    /// Lookup completion timeout in seconds (`node.discovery.timeout_secs`).
    #[serde(default = "DiscoveryConfig::default_timeout_secs")]
    pub timeout_secs: u64,
    /// Dedup cache expiry in seconds (`node.discovery.recent_expiry_secs`).
    #[serde(default = "DiscoveryConfig::default_recent_expiry_secs")]
    pub recent_expiry_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            ttl: 64,
            timeout_secs: 10,
            recent_expiry_secs: 10,
        }
    }
}

impl DiscoveryConfig {
    fn default_ttl() -> u8 { 64 }
    fn default_timeout_secs() -> u64 { 10 }
    fn default_recent_expiry_secs() -> u64 { 10 }
}

/// Spanning tree (`node.tree.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeConfig {
    /// Root self-announcement interval in seconds (`node.tree.root_refresh_secs`).
    #[serde(default = "TreeConfig::default_root_refresh_secs")]
    pub root_refresh_secs: u64,
    /// Per-peer TreeAnnounce rate limit in ms (`node.tree.announce_min_interval_ms`).
    #[serde(default = "TreeConfig::default_announce_min_interval_ms")]
    pub announce_min_interval_ms: u64,
    /// Min depth improvement to switch parents (`node.tree.parent_switch_threshold`).
    #[serde(default = "TreeConfig::default_parent_switch_threshold")]
    pub parent_switch_threshold: usize,
}

impl Default for TreeConfig {
    fn default() -> Self {
        Self {
            root_refresh_secs: 1800,
            announce_min_interval_ms: 500,
            parent_switch_threshold: 1,
        }
    }
}

impl TreeConfig {
    fn default_root_refresh_secs() -> u64 { 1800 }
    fn default_announce_min_interval_ms() -> u64 { 500 }
    fn default_parent_switch_threshold() -> usize { 1 }
}

/// Bloom filter (`node.bloom.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomConfig {
    /// Debounce interval for filter updates in ms (`node.bloom.update_debounce_ms`).
    #[serde(default = "BloomConfig::default_update_debounce_ms")]
    pub update_debounce_ms: u64,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self { update_debounce_ms: 500 }
    }
}

impl BloomConfig {
    fn default_update_debounce_ms() -> u64 { 500 }
}

/// Session/data plane (`node.session.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Default SessionDatagram hop limit (`node.session.default_hop_limit`).
    #[serde(default = "SessionConfig::default_hop_limit")]
    pub default_hop_limit: u8,
    /// Queue depth per dest during session establishment (`node.session.pending_packets_per_dest`).
    #[serde(default = "SessionConfig::default_pending_packets_per_dest")]
    pub pending_packets_per_dest: usize,
    /// Max destinations with pending packets (`node.session.pending_max_destinations`).
    #[serde(default = "SessionConfig::default_pending_max_destinations")]
    pub pending_max_destinations: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_hop_limit: 64,
            pending_packets_per_dest: 16,
            pending_max_destinations: 256,
        }
    }
}

impl SessionConfig {
    fn default_hop_limit() -> u8 { 64 }
    fn default_pending_packets_per_dest() -> usize { 16 }
    fn default_pending_max_destinations() -> usize { 256 }
}

/// Internal buffers (`node.buffers.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuffersConfig {
    /// Transport→Node packet channel capacity (`node.buffers.packet_channel`).
    #[serde(default = "BuffersConfig::default_packet_channel")]
    pub packet_channel: usize,
    /// TUN→Node outbound channel capacity (`node.buffers.tun_channel`).
    #[serde(default = "BuffersConfig::default_tun_channel")]
    pub tun_channel: usize,
    /// DNS→Node identity channel capacity (`node.buffers.dns_channel`).
    #[serde(default = "BuffersConfig::default_dns_channel")]
    pub dns_channel: usize,
}

impl Default for BuffersConfig {
    fn default() -> Self {
        Self {
            packet_channel: 1024,
            tun_channel: 1024,
            dns_channel: 64,
        }
    }
}

impl BuffersConfig {
    fn default_packet_channel() -> usize { 1024 }
    fn default_tun_channel() -> usize { 1024 }
    fn default_dns_channel() -> usize { 64 }
}

// ============================================================================
// Node Configuration (Root)
// ============================================================================

/// Node configuration (`node.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Identity configuration (`node.identity.*`).
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Leaf-only mode (`node.leaf_only`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub leaf_only: bool,

    /// RX loop maintenance tick period in seconds (`node.tick_interval_secs`).
    #[serde(default = "NodeConfig::default_tick_interval_secs")]
    pub tick_interval_secs: u64,

    /// Initial RTT estimate for new links in ms (`node.base_rtt_ms`).
    #[serde(default = "NodeConfig::default_base_rtt_ms")]
    pub base_rtt_ms: u64,

    /// Resource limits (`node.limits.*`).
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Rate limiting (`node.rate_limit.*`).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Retry/backoff (`node.retry.*`).
    #[serde(default)]
    pub retry: RetryConfig,

    /// Cache parameters (`node.cache.*`).
    #[serde(default)]
    pub cache: CacheConfig,

    /// Discovery protocol (`node.discovery.*`).
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    /// Spanning tree (`node.tree.*`).
    #[serde(default)]
    pub tree: TreeConfig,

    /// Bloom filter (`node.bloom.*`).
    #[serde(default)]
    pub bloom: BloomConfig,

    /// Session/data plane (`node.session.*`).
    #[serde(default)]
    pub session: SessionConfig,

    /// Internal buffers (`node.buffers.*`).
    #[serde(default)]
    pub buffers: BuffersConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            identity: IdentityConfig::default(),
            leaf_only: false,
            tick_interval_secs: 1,
            base_rtt_ms: 100,
            limits: LimitsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
            cache: CacheConfig::default(),
            discovery: DiscoveryConfig::default(),
            tree: TreeConfig::default(),
            bloom: BloomConfig::default(),
            session: SessionConfig::default(),
            buffers: BuffersConfig::default(),
        }
    }
}

impl NodeConfig {
    fn default_tick_interval_secs() -> u64 { 1 }
    fn default_base_rtt_ms() -> u64 { 100 }
}

/// Default TUN device name.
const DEFAULT_TUN_NAME: &str = "fips0";

/// Default TUN MTU (IPv6 minimum).
const DEFAULT_TUN_MTU: u16 = 1280;

/// Default DNS responder bind address.
const DEFAULT_DNS_BIND_ADDR: &str = "127.0.0.1";

/// Default DNS responder port.
const DEFAULT_DNS_PORT: u16 = 5354;

/// Default DNS record TTL in seconds (5 minutes).
const DEFAULT_DNS_TTL: u32 = 300;

/// DNS responder configuration (`dns.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Enable DNS responder (`dns.enabled`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,

    /// Bind address (`dns.bind_addr`). Defaults to "127.0.0.1".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// Listen port (`dns.port`). Defaults to 5354.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// AAAA record TTL in seconds (`dns.ttl`). Defaults to 300.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

impl DnsConfig {
    /// Get the bind address, using default if not configured.
    pub fn bind_addr(&self) -> &str {
        self.bind_addr.as_deref().unwrap_or(DEFAULT_DNS_BIND_ADDR)
    }

    /// Get the port, using default if not configured.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_DNS_PORT)
    }

    /// Get the TTL, using default if not configured.
    pub fn ttl(&self) -> u32 {
        self.ttl.unwrap_or(DEFAULT_DNS_TTL)
    }
}

/// Default UDP bind address.
const DEFAULT_UDP_BIND_ADDR: &str = "0.0.0.0:4000";

/// Default UDP MTU (IPv6 minimum).
const DEFAULT_UDP_MTU: u16 = 1280;

/// TUN interface configuration (`tun.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunConfig {
    /// Enable TUN interface (`tun.enabled`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,

    /// TUN device name (`tun.name`). Defaults to "fips0".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// TUN MTU (`tun.mtu`). Defaults to 1280 (IPv6 minimum).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

}

impl TunConfig {
    /// Get the TUN device name, using default if not configured.
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or(DEFAULT_TUN_NAME)
    }

    /// Get the TUN MTU, using default if not configured.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_TUN_MTU)
    }
}

/// UDP transport instance configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpConfig {
    /// Bind address (`bind_addr`). Defaults to "0.0.0.0:4000".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// UDP MTU (`mtu`). Defaults to 1280 (IPv6 minimum).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

impl UdpConfig {
    /// Get the bind address, using default if not configured.
    pub fn bind_addr(&self) -> &str {
        self.bind_addr.as_deref().unwrap_or(DEFAULT_UDP_BIND_ADDR)
    }

    /// Get the UDP MTU, using default if not configured.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_UDP_MTU)
    }
}

// ============================================================================
// Transport Configuration
// ============================================================================

use std::collections::HashMap;

/// Transport instances - either a single config or named instances.
///
/// Allows both simple single-instance config:
/// ```yaml
/// transports:
///   udp:
///     bind_addr: "0.0.0.0:4000"
/// ```
///
/// And multiple named instances:
/// ```yaml
/// transports:
///   udp:
///     main:
///       bind_addr: "0.0.0.0:4000"
///     backup:
///       bind_addr: "192.168.1.100:4001"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportInstances<T> {
    /// Single unnamed instance (config fields directly under transport type).
    Single(T),
    /// Multiple named instances.
    Named(HashMap<String, T>),
}

impl<T> TransportInstances<T> {
    /// Get the number of instances.
    pub fn len(&self) -> usize {
        match self {
            TransportInstances::Single(_) => 1,
            TransportInstances::Named(map) => map.len(),
        }
    }

    /// Check if there are no instances.
    pub fn is_empty(&self) -> bool {
        match self {
            TransportInstances::Single(_) => false,
            TransportInstances::Named(map) => map.is_empty(),
        }
    }

    /// Iterate over all instances as (name, config) pairs.
    ///
    /// Single instances have `None` as the name.
    /// Named instances have `Some(name)`.
    pub fn iter(&self) -> impl Iterator<Item = (Option<&str>, &T)> {
        match self {
            TransportInstances::Single(config) => {
                vec![(None, config)].into_iter()
            }
            TransportInstances::Named(map) => {
                map.iter()
                    .map(|(k, v)| (Some(k.as_str()), v))
                    .collect::<Vec<_>>()
                    .into_iter()
            }
        }
    }
}

impl<T> Default for TransportInstances<T> {
    fn default() -> Self {
        TransportInstances::Named(HashMap::new())
    }
}

/// Transports configuration section.
///
/// Each transport type can have either a single instance (config directly
/// under the type name) or multiple named instances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportsConfig {
    /// UDP transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub udp: TransportInstances<UdpConfig>,

    // Future transport types:
    // #[serde(default, skip_serializing_if = "is_transport_empty")]
    // pub tcp: TransportInstances<TcpConfig>,
    //
    // #[serde(default, skip_serializing_if = "is_transport_empty")]
    // pub tor: TransportInstances<TorConfig>,
}

/// Helper for skip_serializing_if on TransportInstances.
fn is_transport_empty<T>(instances: &TransportInstances<T>) -> bool {
    instances.is_empty()
}

impl TransportsConfig {
    /// Check if any transports are configured.
    pub fn is_empty(&self) -> bool {
        self.udp.is_empty()
        // && self.tcp.is_empty()
        // && self.tor.is_empty()
    }

    /// Merge another TransportsConfig into this one.
    ///
    /// Non-empty transport sections from `other` replace those in `self`.
    pub fn merge(&mut self, other: TransportsConfig) {
        if !other.udp.is_empty() {
            self.udp = other.udp;
        }
        // Future: same for tcp, tor, etc.
    }
}

// ============================================================================
// Peer Configuration
// ============================================================================

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
    /// - UDP: "host:port" (e.g., "192.168.1.1:4000")
    /// - Tor: "onion_address:port" (e.g., "xyz...abc.onion:4000")
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
}

impl PeerConfig {
    /// Create a new peer config with a single address.
    pub fn new(npub: impl Into<String>, transport: impl Into<String>, addr: impl Into<String>) -> Self {
        Self {
            npub: npub.into(),
            alias: None,
            addresses: vec![PeerAddress::new(transport, addr)],
            connect_policy: ConnectPolicy::default(),
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

/// Root configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Node configuration (`node.*`).
    #[serde(default)]
    pub node: NodeConfig,

    /// TUN interface configuration (`tun.*`).
    #[serde(default)]
    pub tun: TunConfig,

    /// DNS responder configuration (`dns.*`).
    #[serde(default)]
    pub dns: DnsConfig,

    /// Transport instances (`transports.*`).
    #[serde(default, skip_serializing_if = "TransportsConfig::is_empty")]
    pub transports: TransportsConfig,

    /// Static peers to connect to (`peers`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
}

impl Config {
    /// Create a new empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from the standard search paths.
    ///
    /// Files are loaded in reverse priority order and merged:
    /// 1. `/etc/fips/fips.yaml` (loaded first, lowest priority)
    /// 2. `~/.config/fips/fips.yaml` (user config)
    /// 3. `./fips.yaml` (loaded last, highest priority)
    ///
    /// Returns a tuple of (config, paths_loaded) where paths_loaded contains
    /// the paths that were successfully loaded.
    pub fn load() -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let search_paths = Self::search_paths();
        Self::load_from_paths(&search_paths)
    }

    /// Load configuration from specific paths.
    ///
    /// Paths are processed in order, with later paths overriding earlier ones.
    pub fn load_from_paths(paths: &[PathBuf]) -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let mut config = Config::default();
        let mut loaded_paths = Vec::new();

        for path in paths {
            if path.exists() {
                let file_config = Self::load_file(path)?;
                config.merge(file_config);
                loaded_paths.push(path.clone());
            }
        }

        Ok((config, loaded_paths))
    }

    /// Load configuration from a single file.
    pub fn load_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
            path: path.to_path_buf(),
            source: e,
        })?;

        serde_yaml::from_str(&contents).map_err(|e| ConfigError::ParseYaml {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Get the standard search paths in priority order (lowest to highest).
    pub fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // System config (lowest priority)
        paths.push(PathBuf::from("/etc/fips").join(CONFIG_FILENAME));

        // User config directory
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("fips").join(CONFIG_FILENAME));
        }

        // Home directory (legacy location)
        if let Some(home_dir) = dirs::home_dir() {
            paths.push(home_dir.join(".fips.yaml"));
        }

        // Current directory (highest priority)
        paths.push(PathBuf::from(".").join(CONFIG_FILENAME));

        paths
    }

    /// Merge another configuration into this one.
    ///
    /// Values from `other` override values in `self` when present.
    pub fn merge(&mut self, other: Config) {
        // Merge node.identity section
        if other.node.identity.nsec.is_some() {
            self.node.identity.nsec = other.node.identity.nsec;
        }
        // Merge node.leaf_only
        if other.node.leaf_only {
            self.node.leaf_only = true;
        }
        // Merge tun section
        if other.tun.enabled {
            self.tun.enabled = true;
        }
        if other.tun.name.is_some() {
            self.tun.name = other.tun.name;
        }
        if other.tun.mtu.is_some() {
            self.tun.mtu = other.tun.mtu;
        }
        // Merge dns section
        if other.dns.enabled {
            self.dns.enabled = true;
        }
        if other.dns.bind_addr.is_some() {
            self.dns.bind_addr = other.dns.bind_addr;
        }
        if other.dns.port.is_some() {
            self.dns.port = other.dns.port;
        }
        if other.dns.ttl.is_some() {
            self.dns.ttl = other.dns.ttl;
        }
        // Merge transports section
        self.transports.merge(other.transports);
        // Merge peers (replace if non-empty)
        if !other.peers.is_empty() {
            self.peers = other.peers;
        }
    }

    /// Create an Identity from this configuration.
    ///
    /// If an nsec is configured, uses that to create the identity.
    /// Otherwise, generates a new random identity.
    pub fn create_identity(&self) -> Result<Identity, ConfigError> {
        match &self.node.identity.nsec {
            Some(nsec) => Ok(Identity::from_secret_str(nsec)?),
            None => Ok(Identity::generate()),
        }
    }

    /// Check if an identity is configured (vs. will be generated).
    pub fn has_identity(&self) -> bool {
        self.node.identity.nsec.is_some()
    }

    /// Check if leaf-only mode is configured.
    pub fn is_leaf_only(&self) -> bool {
        self.node.leaf_only
    }

    /// Get the configured peers.
    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    /// Get peers that should auto-connect on startup.
    pub fn auto_connect_peers(&self) -> impl Iterator<Item = &PeerConfig> {
        self.peers.iter().filter(|p| p.is_auto_connect())
    }

    /// Serialize this configuration to YAML.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_empty_config() {
        let config = Config::new();
        assert!(config.node.identity.nsec.is_none());
        assert!(!config.has_identity());
    }

    #[test]
    fn test_parse_yaml_with_nsec() {
        let yaml = r#"
node:
  identity:
    nsec: nsec1qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxfnm5g9
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_some());
        assert!(config.has_identity());
    }

    #[test]
    fn test_parse_yaml_with_hex() {
        let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_some());

        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_parse_yaml_empty() {
        let yaml = "";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_none());
    }

    #[test]
    fn test_parse_yaml_partial() {
        let yaml = r#"
node:
  identity: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_none());
    }

    #[test]
    fn test_merge_configs() {
        let mut base = Config::new();
        base.node.identity.nsec = Some("base_nsec".to_string());

        let mut override_config = Config::new();
        override_config.node.identity.nsec = Some("override_nsec".to_string());

        base.merge(override_config);
        assert_eq!(
            base.node.identity.nsec,
            Some("override_nsec".to_string())
        );
    }

    #[test]
    fn test_merge_preserves_base_when_override_empty() {
        let mut base = Config::new();
        base.node.identity.nsec = Some("base_nsec".to_string());

        let override_config = Config::new();

        base.merge(override_config);
        assert_eq!(base.node.identity.nsec, Some("base_nsec".to_string()));
    }

    #[test]
    fn test_create_identity_from_nsec() {
        let mut config = Config::new();
        config.node.identity.nsec = Some(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
        );

        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_create_identity_generates_new() {
        let config = Config::new();
        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
        fs::write(&config_path, yaml).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        assert!(config.node.identity.nsec.is_some());
    }

    #[test]
    fn test_load_from_paths_merges() {
        let temp_dir = TempDir::new().unwrap();

        // Create two config files
        let low_priority = temp_dir.path().join("low.yaml");
        let high_priority = temp_dir.path().join("high.yaml");

        fs::write(
            &low_priority,
            r#"
node:
  identity:
    nsec: "low_priority_nsec"
"#,
        )
        .unwrap();

        fs::write(
            &high_priority,
            r#"
node:
  identity:
    nsec: "high_priority_nsec"
"#,
        )
        .unwrap();

        let paths = vec![low_priority.clone(), high_priority.clone()];
        let (config, loaded) = Config::load_from_paths(&paths).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(
            config.node.identity.nsec,
            Some("high_priority_nsec".to_string())
        );
    }

    #[test]
    fn test_load_skips_missing_files() {
        let temp_dir = TempDir::new().unwrap();
        let existing = temp_dir.path().join("exists.yaml");
        let missing = temp_dir.path().join("missing.yaml");

        fs::write(
            &existing,
            r#"
node:
  identity:
    nsec: "existing_nsec"
"#,
        )
        .unwrap();

        let paths = vec![missing, existing.clone()];
        let (config, loaded) = Config::load_from_paths(&paths).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], existing);
        assert_eq!(config.node.identity.nsec, Some("existing_nsec".to_string()));
    }

    #[test]
    fn test_search_paths_includes_expected() {
        let paths = Config::search_paths();

        // Should include current directory
        assert!(paths.iter().any(|p| p.ends_with("fips.yaml")));

        // Should include /etc/fips
        assert!(paths
            .iter()
            .any(|p| p.starts_with("/etc/fips") && p.ends_with("fips.yaml")));
    }

    #[test]
    fn test_to_yaml() {
        let mut config = Config::new();
        config.node.identity.nsec = Some("test_nsec".to_string());

        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("node:"));
        assert!(yaml.contains("identity:"));
        assert!(yaml.contains("nsec:"));
        assert!(yaml.contains("test_nsec"));
    }

    #[test]
    fn test_to_yaml_empty_nsec_omitted() {
        let config = Config::new();
        let yaml = config.to_yaml().unwrap();

        // Empty nsec should not be serialized
        assert!(!yaml.contains("nsec:"));
    }

    #[test]
    fn test_parse_transport_single_instance() {
        let yaml = r#"
transports:
  udp:
    bind_addr: "0.0.0.0:4000"
    mtu: 1400
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.transports.udp.len(), 1);
        let instances: Vec<_> = config.transports.udp.iter().collect();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].0, None); // Single instance has no name
        assert_eq!(instances[0].1.bind_addr(), "0.0.0.0:4000");
        assert_eq!(instances[0].1.mtu(), 1400);
    }

    #[test]
    fn test_parse_transport_named_instances() {
        let yaml = r#"
transports:
  udp:
    main:
      bind_addr: "0.0.0.0:4000"
    backup:
      bind_addr: "192.168.1.100:4001"
      mtu: 1280
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.transports.udp.len(), 2);

        let instances: std::collections::HashMap<_, _> =
            config.transports.udp.iter().collect();

        // Named instances have Some(name)
        assert!(instances.contains_key(&Some("main")));
        assert!(instances.contains_key(&Some("backup")));
        assert_eq!(instances[&Some("main")].bind_addr(), "0.0.0.0:4000");
        assert_eq!(instances[&Some("backup")].bind_addr(), "192.168.1.100:4001");
        assert_eq!(instances[&Some("backup")].mtu(), 1280);
    }

    #[test]
    fn test_parse_transport_empty() {
        let yaml = r#"
transports: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.transports.udp.is_empty());
        assert!(config.transports.is_empty());
    }

    #[test]
    fn test_transport_instances_iter() {
        // Single instance - no name
        let single = TransportInstances::Single(UdpConfig {
            bind_addr: Some("0.0.0.0:4000".to_string()),
            mtu: None,
        });
        let items: Vec<_> = single.iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, None);

        // Named instances - have names
        let mut map = HashMap::new();
        map.insert("a".to_string(), UdpConfig::default());
        map.insert("b".to_string(), UdpConfig::default());
        let named = TransportInstances::Named(map);
        let items: Vec<_> = named.iter().collect();
        assert_eq!(items.len(), 2);
        // All named instances should have Some(name)
        assert!(items.iter().all(|(name, _)| name.is_some()));
    }

    #[test]
    fn test_parse_peer_config() {
        let yaml = r#"
peers:
  - npub: "npub1abc123"
    alias: "gateway"
    addresses:
      - transport: udp
        addr: "192.168.1.1:4000"
        priority: 1
      - transport: tor
        addr: "xyz.onion:4000"
        priority: 2
    connect_policy: auto_connect
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.npub, "npub1abc123");
        assert_eq!(peer.alias, Some("gateway".to_string()));
        assert_eq!(peer.addresses.len(), 2);
        assert!(peer.is_auto_connect());

        // Check addresses are sorted by priority
        let sorted = peer.addresses_by_priority();
        assert_eq!(sorted[0].transport, "udp");
        assert_eq!(sorted[0].priority, 1);
        assert_eq!(sorted[1].transport, "tor");
        assert_eq!(sorted[1].priority, 2);
    }

    #[test]
    fn test_parse_peer_minimal() {
        let yaml = r#"
peers:
  - npub: "npub1xyz"
    addresses:
      - transport: udp
        addr: "10.0.0.1:4000"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.npub, "npub1xyz");
        assert!(peer.alias.is_none());
        // Default connect_policy is auto_connect
        assert!(peer.is_auto_connect());
        // Default priority is 100
        assert_eq!(peer.addresses[0].priority, 100);
    }

    #[test]
    fn test_parse_multiple_peers() {
        let yaml = r#"
peers:
  - npub: "npub1peer1"
    addresses:
      - transport: udp
        addr: "10.0.0.1:4000"
  - npub: "npub1peer2"
    addresses:
      - transport: udp
        addr: "10.0.0.2:4000"
    connect_policy: on_demand
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.auto_connect_peers().count(), 1);
    }

    #[test]
    fn test_peer_config_builder() {
        let peer = PeerConfig::new("npub1test", "udp", "192.168.1.1:4000")
            .with_alias("test-peer")
            .with_address(PeerAddress::with_priority("tor", "xyz.onion:4000", 50));

        assert_eq!(peer.npub, "npub1test");
        assert_eq!(peer.alias, Some("test-peer".to_string()));
        assert_eq!(peer.addresses.len(), 2);
        assert!(peer.is_auto_connect());
    }
}
