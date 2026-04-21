//! Node configuration subsections.
//!
//! All the `node.*` configuration parameters: resource limits, rate limiting,
//! retry/backoff, cache sizing, discovery, spanning tree, bloom filters,
//! session management, and internal buffers.

use serde::{Deserialize, Serialize};

use super::IdentityConfig;
use crate::mmp::{DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MmpConfig, MmpMode};

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
    fn default_max_connections() -> usize {
        256
    }
    fn default_max_peers() -> usize {
        128
    }
    fn default_max_links() -> usize {
        256
    }
    fn default_max_pending_inbound() -> usize {
        1000
    }
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
    /// Initial handshake resend interval in ms (`node.rate_limit.handshake_resend_interval_ms`).
    /// Handshake messages are resent with exponential backoff within the timeout window.
    #[serde(default = "RateLimitConfig::default_handshake_resend_interval_ms")]
    pub handshake_resend_interval_ms: u64,
    /// Handshake resend backoff multiplier (`node.rate_limit.handshake_resend_backoff`).
    #[serde(default = "RateLimitConfig::default_handshake_resend_backoff")]
    pub handshake_resend_backoff: f64,
    /// Max handshake resends per attempt (`node.rate_limit.handshake_max_resends`).
    #[serde(default = "RateLimitConfig::default_handshake_max_resends")]
    pub handshake_max_resends: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            handshake_burst: 100,
            handshake_rate: 10.0,
            handshake_timeout_secs: 30,
            handshake_resend_interval_ms: 1000,
            handshake_resend_backoff: 2.0,
            handshake_max_resends: 5,
        }
    }
}

impl RateLimitConfig {
    fn default_handshake_burst() -> u32 {
        100
    }
    fn default_handshake_rate() -> f64 {
        10.0
    }
    fn default_handshake_timeout_secs() -> u64 {
        30
    }
    fn default_handshake_resend_interval_ms() -> u64 {
        1000
    }
    fn default_handshake_resend_backoff() -> f64 {
        2.0
    }
    fn default_handshake_max_resends() -> u32 {
        5
    }
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
    fn default_max_retries() -> u32 {
        5
    }
    fn default_base_interval_secs() -> u64 {
        5
    }
    fn default_max_backoff_secs() -> u64 {
        300
    }
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
    /// Max entries in identity cache (`node.cache.identity_size`).
    #[serde(default = "CacheConfig::default_identity_size")]
    pub identity_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            coord_size: 50_000,
            coord_ttl_secs: 300,
            identity_size: 10_000,
        }
    }
}

impl CacheConfig {
    fn default_coord_size() -> usize {
        50_000
    }
    fn default_coord_ttl_secs() -> u64 {
        300
    }
    fn default_identity_size() -> usize {
        10_000
    }
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
    /// Base backoff after first lookup failure in seconds (`node.discovery.backoff_base_secs`).
    /// Doubles per consecutive failure up to `backoff_max_secs`.
    #[serde(default = "DiscoveryConfig::default_backoff_base_secs")]
    pub backoff_base_secs: u64,
    /// Maximum backoff cap in seconds (`node.discovery.backoff_max_secs`).
    #[serde(default = "DiscoveryConfig::default_backoff_max_secs")]
    pub backoff_max_secs: u64,
    /// Minimum interval between forwarded lookups for the same target in seconds
    /// (`node.discovery.forward_min_interval_secs`).
    /// Defense-in-depth against misbehaving nodes.
    #[serde(default = "DiscoveryConfig::default_forward_min_interval_secs")]
    pub forward_min_interval_secs: u64,
    /// Retry interval within the timeout window in seconds
    /// (`node.discovery.retry_interval_secs`).
    /// After this interval without a response, resend the lookup.
    #[serde(default = "DiscoveryConfig::default_retry_interval_secs")]
    pub retry_interval_secs: u64,
    /// Maximum attempts per lookup (`node.discovery.max_attempts`).
    /// 1 = no retry, 2 = one retry, etc.
    #[serde(default = "DiscoveryConfig::default_max_attempts")]
    pub max_attempts: u8,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            ttl: 64,
            timeout_secs: 10,
            recent_expiry_secs: 10,
            backoff_base_secs: 30,
            backoff_max_secs: 300,
            forward_min_interval_secs: 2,
            retry_interval_secs: 5,
            max_attempts: 2,
        }
    }
}

impl DiscoveryConfig {
    fn default_ttl() -> u8 {
        64
    }
    fn default_timeout_secs() -> u64 {
        10
    }
    fn default_recent_expiry_secs() -> u64 {
        10
    }
    fn default_backoff_base_secs() -> u64 {
        30
    }
    fn default_backoff_max_secs() -> u64 {
        300
    }
    fn default_forward_min_interval_secs() -> u64 {
        2
    }
    fn default_retry_interval_secs() -> u64 {
        5
    }
    fn default_max_attempts() -> u8 {
        2
    }
}

/// Spanning tree (`node.tree.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeConfig {
    /// Per-peer TreeAnnounce rate limit in ms (`node.tree.announce_min_interval_ms`).
    #[serde(default = "TreeConfig::default_announce_min_interval_ms")]
    pub announce_min_interval_ms: u64,
    /// Hysteresis factor for cost-based parent re-selection (`node.tree.parent_hysteresis`).
    ///
    /// Only switch parents when the candidate's effective_depth is better than
    /// `current_effective_depth * (1.0 - parent_hysteresis)`. Range: 0.0-1.0.
    /// Set to 0.0 to disable hysteresis (switch on any improvement).
    #[serde(default = "TreeConfig::default_parent_hysteresis")]
    pub parent_hysteresis: f64,
    /// Hold-down period after parent switch in seconds (`node.tree.hold_down_secs`).
    ///
    /// After switching parents, suppress re-evaluation for this duration to allow
    /// MMP metrics to stabilize on the new link. Set to 0 to disable.
    #[serde(default = "TreeConfig::default_hold_down_secs")]
    pub hold_down_secs: u64,
    /// Periodic parent re-evaluation interval in seconds (`node.tree.reeval_interval_secs`).
    ///
    /// How often to re-evaluate parent selection based on current MMP link costs,
    /// independent of TreeAnnounce traffic. Catches link degradation after the
    /// tree has stabilized. Set to 0 to disable.
    #[serde(default = "TreeConfig::default_reeval_interval_secs")]
    pub reeval_interval_secs: u64,
    /// Flap dampening: max parent switches before extended hold-down (`node.tree.flap_threshold`).
    #[serde(default = "TreeConfig::default_flap_threshold")]
    pub flap_threshold: u32,
    /// Flap dampening: window in seconds for counting switches (`node.tree.flap_window_secs`).
    #[serde(default = "TreeConfig::default_flap_window_secs")]
    pub flap_window_secs: u64,
    /// Flap dampening: extended hold-down duration in seconds (`node.tree.flap_dampening_secs`).
    #[serde(default = "TreeConfig::default_flap_dampening_secs")]
    pub flap_dampening_secs: u64,
}

impl Default for TreeConfig {
    fn default() -> Self {
        Self {
            announce_min_interval_ms: 500,
            parent_hysteresis: 0.2,
            hold_down_secs: 30,
            reeval_interval_secs: 60,
            flap_threshold: 4,
            flap_window_secs: 60,
            flap_dampening_secs: 120,
        }
    }
}

impl TreeConfig {
    fn default_announce_min_interval_ms() -> u64 {
        500
    }
    fn default_parent_hysteresis() -> f64 {
        0.2
    }
    fn default_hold_down_secs() -> u64 {
        30
    }
    fn default_reeval_interval_secs() -> u64 {
        60
    }
    fn default_flap_threshold() -> u32 {
        4
    }
    fn default_flap_window_secs() -> u64 {
        60
    }
    fn default_flap_dampening_secs() -> u64 {
        120
    }
}

/// Bloom filter (`node.bloom.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomConfig {
    /// Debounce interval for filter updates in ms (`node.bloom.update_debounce_ms`).
    #[serde(default = "BloomConfig::default_update_debounce_ms")]
    pub update_debounce_ms: u64,
    /// Antipoison cap: reject inbound FilterAnnounce whose FPR exceeds
    /// this value (`node.bloom.max_inbound_fpr`). Valid range `(0.0, 1.0)`.
    /// Default `0.05` ≈ fill 0.549 at k=5 ≈ ~3,200 entries on the 1KB
    /// filter. Conceptually distinct from future autoscaling hysteresis
    /// setpoints — same unit, different knobs.
    #[serde(default = "BloomConfig::default_max_inbound_fpr")]
    pub max_inbound_fpr: f64,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            update_debounce_ms: 500,
            max_inbound_fpr: 0.05,
        }
    }
}

impl BloomConfig {
    fn default_update_debounce_ms() -> u64 {
        500
    }
    fn default_max_inbound_fpr() -> f64 {
        0.05
    }
}

/// Session/data plane (`node.session.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Default SessionDatagram TTL (`node.session.default_ttl`).
    #[serde(default = "SessionConfig::default_ttl")]
    pub default_ttl: u8,
    /// Queue depth per dest during session establishment (`node.session.pending_packets_per_dest`).
    #[serde(default = "SessionConfig::default_pending_packets_per_dest")]
    pub pending_packets_per_dest: usize,
    /// Max destinations with pending packets (`node.session.pending_max_destinations`).
    #[serde(default = "SessionConfig::default_pending_max_destinations")]
    pub pending_max_destinations: usize,
    /// Idle session timeout in seconds (`node.session.idle_timeout_secs`).
    /// Established sessions with no application data for this duration are
    /// removed. MMP reports do not count as activity for this timer.
    #[serde(default = "SessionConfig::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Number of initial data packets per session that include COORDS_PRESENT
    /// for transit cache warmup (`node.session.coords_warmup_packets`).
    /// Also used as the reset count on CoordsRequired receipt.
    #[serde(default = "SessionConfig::default_coords_warmup_packets")]
    pub coords_warmup_packets: u8,
    /// Minimum interval (ms) between standalone CoordsWarmup responses to
    /// CoordsRequired/PathBroken signals, per destination
    /// (`node.session.coords_response_interval_ms`).
    #[serde(default = "SessionConfig::default_coords_response_interval_ms")]
    pub coords_response_interval_ms: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_ttl: 64,
            pending_packets_per_dest: 16,
            pending_max_destinations: 256,
            idle_timeout_secs: 90,
            coords_warmup_packets: 5,
            coords_response_interval_ms: 2000,
        }
    }
}

impl SessionConfig {
    fn default_ttl() -> u8 {
        64
    }
    fn default_pending_packets_per_dest() -> usize {
        16
    }
    fn default_pending_max_destinations() -> usize {
        256
    }
    fn default_idle_timeout_secs() -> u64 {
        90
    }
    fn default_coords_warmup_packets() -> u8 {
        5
    }
    fn default_coords_response_interval_ms() -> u64 {
        2000
    }
}

/// Session-layer Metrics Measurement Protocol (`node.session_mmp.*`).
///
/// Separate from link-layer `node.mmp.*` to allow independent mode/interval
/// configuration per layer. Session reports consume bandwidth on every transit
/// link, so operators may want a lighter mode (e.g., Lightweight) for sessions
/// while running Full mode on links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMmpConfig {
    /// Operating mode (`node.session_mmp.mode`).
    #[serde(default)]
    pub mode: MmpMode,

    /// Periodic operator log interval in seconds (`node.session_mmp.log_interval_secs`).
    #[serde(default = "SessionMmpConfig::default_log_interval_secs")]
    pub log_interval_secs: u64,

    /// OWD trend ring buffer size (`node.session_mmp.owd_window_size`).
    #[serde(default = "SessionMmpConfig::default_owd_window_size")]
    pub owd_window_size: usize,
}

impl Default for SessionMmpConfig {
    fn default() -> Self {
        Self {
            mode: MmpMode::default(),
            log_interval_secs: DEFAULT_LOG_INTERVAL_SECS,
            owd_window_size: DEFAULT_OWD_WINDOW_SIZE,
        }
    }
}

impl SessionMmpConfig {
    fn default_log_interval_secs() -> u64 {
        DEFAULT_LOG_INTERVAL_SECS
    }
    fn default_owd_window_size() -> usize {
        DEFAULT_OWD_WINDOW_SIZE
    }
}

/// Control socket configuration (`node.control.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Enable the control socket (`node.control.enabled`).
    #[serde(default = "ControlConfig::default_enabled")]
    pub enabled: bool,
    /// Unix socket path (`node.control.socket_path`).
    #[serde(default = "ControlConfig::default_socket_path")]
    pub socket_path: String,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: Self::default_socket_path(),
        }
    }
}

impl ControlConfig {
    fn default_enabled() -> bool {
        true
    }

    /// Default control socket path.
    ///
    /// On Unix, returns a Unix domain socket path (XDG_RUNTIME_DIR, /run/fips,
    /// or /tmp fallback). On Windows, returns a TCP port number as a string
    /// since Windows does not support Unix domain sockets; the control socket
    /// listens on localhost at this port.
    fn default_socket_path() -> String {
        #[cfg(unix)]
        {
            if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                format!("{runtime_dir}/fips/control.sock")
            } else if std::fs::create_dir_all("/run/fips").is_ok() {
                "/run/fips/control.sock".to_string()
            } else {
                "/tmp/fips-control.sock".to_string()
            }
        }
        #[cfg(windows)]
        {
            "21210".to_string()
        }
    }
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
    fn default_packet_channel() -> usize {
        1024
    }
    fn default_tun_channel() -> usize {
        1024
    }
    fn default_dns_channel() -> usize {
        64
    }
}

// ============================================================================
// ECN Congestion Signaling
// ============================================================================

/// Rekey / session rekeying configuration (`node.rekey.*`).
///
/// Controls periodic full rekey for both FMP (link layer) and FSP
/// (session layer) Noise sessions. Rekeying provides true forward secrecy
/// with fresh DH randomness, nonce reset, and session index rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyConfig {
    /// Enable periodic rekey (`node.rekey.enabled`).
    #[serde(default = "RekeyConfig::default_enabled")]
    pub enabled: bool,

    /// Initiate rekey after this many seconds (`node.rekey.after_secs`).
    #[serde(default = "RekeyConfig::default_after_secs")]
    pub after_secs: u64,

    /// Initiate rekey after this many messages sent (`node.rekey.after_messages`).
    #[serde(default = "RekeyConfig::default_after_messages")]
    pub after_messages: u64,
}

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            after_secs: 120,
            after_messages: 1 << 16, // 65536
        }
    }
}

impl RekeyConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_after_secs() -> u64 {
        120
    }
    fn default_after_messages() -> u64 {
        1 << 16
    }
}

/// ECN congestion signaling configuration (`node.ecn.*`).
///
/// Controls the FMP CE relay chain: transit nodes detect congestion on outgoing
/// links and set the CE flag in forwarded datagrams. The destination marks
/// IPv6 ECN-CE on ECN-capable packets before TUN delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcnConfig {
    /// Enable ECN congestion signaling (`node.ecn.enabled`).
    #[serde(default = "EcnConfig::default_enabled")]
    pub enabled: bool,

    /// Loss rate threshold for marking CE (`node.ecn.loss_threshold`).
    /// When the outgoing link's loss rate meets or exceeds this value,
    /// the transit node sets CE on forwarded datagrams.
    #[serde(default = "EcnConfig::default_loss_threshold")]
    pub loss_threshold: f64,

    /// ETX threshold for marking CE (`node.ecn.etx_threshold`).
    /// When the outgoing link's ETX meets or exceeds this value,
    /// the transit node sets CE on forwarded datagrams.
    #[serde(default = "EcnConfig::default_etx_threshold")]
    pub etx_threshold: f64,
}

impl Default for EcnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            loss_threshold: 0.05,
            etx_threshold: 3.0,
        }
    }
}

impl EcnConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_loss_threshold() -> f64 {
        0.05
    }
    fn default_etx_threshold() -> f64 {
        3.0
    }
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

    /// Non-routing mode (`node.disable_routing`).
    ///
    /// Tree participation and one-way bloom receipt, but no transit
    /// forwarding or bloom combination/propagation. Overridden by
    /// `leaf_only` (leaf implies non-routing).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_routing: bool,

    /// Leaf-only mode (`node.leaf_only`).
    ///
    /// Single upstream peer, no tree/bloom/transit. Implies
    /// `disable_routing`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub leaf_only: bool,

    /// RX loop maintenance tick period in seconds (`node.tick_interval_secs`).
    #[serde(default = "NodeConfig::default_tick_interval_secs")]
    pub tick_interval_secs: u64,

    /// Initial RTT estimate for new links in ms (`node.base_rtt_ms`).
    #[serde(default = "NodeConfig::default_base_rtt_ms")]
    pub base_rtt_ms: u64,

    /// Link heartbeat send interval in seconds (`node.heartbeat_interval_secs`).
    #[serde(default = "NodeConfig::default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Link dead timeout in seconds (`node.link_dead_timeout_secs`).
    /// Peers silent for this duration are removed.
    #[serde(default = "NodeConfig::default_link_dead_timeout_secs")]
    pub link_dead_timeout_secs: u64,

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

    /// Control socket (`node.control.*`).
    #[serde(default)]
    pub control: ControlConfig,

    /// Metrics Measurement Protocol — link layer (`node.mmp.*`).
    #[serde(default)]
    pub mmp: MmpConfig,

    /// Metrics Measurement Protocol — session layer (`node.session_mmp.*`).
    #[serde(default)]
    pub session_mmp: SessionMmpConfig,

    /// ECN congestion signaling (`node.ecn.*`).
    #[serde(default)]
    pub ecn: EcnConfig,

    /// Rekey / session rekeying (`node.rekey.*`).
    #[serde(default)]
    pub rekey: RekeyConfig,

    /// Log level (`node.log_level`). Case-insensitive.
    /// Valid values: trace, debug, info, warn, error. Default: info.
    #[serde(default)]
    pub log_level: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            identity: IdentityConfig::default(),
            disable_routing: false,
            leaf_only: false,
            tick_interval_secs: 1,
            base_rtt_ms: 100,
            heartbeat_interval_secs: 10,
            link_dead_timeout_secs: 30,
            limits: LimitsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
            cache: CacheConfig::default(),
            discovery: DiscoveryConfig::default(),
            tree: TreeConfig::default(),
            bloom: BloomConfig::default(),
            session: SessionConfig::default(),
            buffers: BuffersConfig::default(),
            control: ControlConfig::default(),
            mmp: MmpConfig::default(),
            session_mmp: SessionMmpConfig::default(),
            ecn: EcnConfig::default(),
            rekey: RekeyConfig::default(),
            log_level: None,
        }
    }
}

impl NodeConfig {
    /// Get the log level as a tracing Level. Default: INFO.
    pub fn log_level(&self) -> tracing::Level {
        match self
            .log_level
            .as_deref()
            .map(|s| s.to_lowercase())
            .as_deref()
        {
            Some("trace") => tracing::Level::TRACE,
            Some("debug") => tracing::Level::DEBUG,
            Some("warn") | Some("warning") => tracing::Level::WARN,
            Some("error") => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        }
    }

    fn default_tick_interval_secs() -> u64 {
        1
    }
    fn default_base_rtt_ms() -> u64 {
        100
    }
    fn default_heartbeat_interval_secs() -> u64 {
        10
    }
    fn default_link_dead_timeout_secs() -> u64 {
        30
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecn_config_defaults() {
        let c = EcnConfig::default();
        assert!(c.enabled);
        assert!((c.loss_threshold - 0.05).abs() < 1e-9);
        assert!((c.etx_threshold - 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_ecn_config_yaml_roundtrip() {
        let yaml = "loss_threshold: 0.10\netx_threshold: 2.5\nenabled: false\n";
        let c: EcnConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!c.enabled);
        assert!((c.loss_threshold - 0.10).abs() < 1e-9);
        assert!((c.etx_threshold - 2.5).abs() < 1e-9);
    }

    #[test]
    fn test_ecn_config_partial_yaml() {
        // Only specify loss_threshold — others should get defaults
        let yaml = "loss_threshold: 0.02\n";
        let c: EcnConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(c.enabled); // default
        assert!((c.loss_threshold - 0.02).abs() < 1e-9);
        assert!((c.etx_threshold - 3.0).abs() < 1e-9); // default
    }

    #[cfg(windows)]
    #[test]
    fn test_default_socket_path_windows() {
        let config = ControlConfig::default();
        // On Windows, socket_path is a TCP port number
        let port: u16 = config
            .socket_path
            .parse()
            .expect("should be a valid port number");
        assert_eq!(port, 21210);
    }
}
