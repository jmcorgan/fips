//! Node configuration subsections.
//!
//! All the `node.*` configuration parameters: resource limits, rate limiting,
//! retry/backoff, cache sizing, discovery, spanning tree, bloom filters,
//! session management, and internal buffers.

use serde::{Deserialize, Serialize};

use super::IdentityConfig;

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
