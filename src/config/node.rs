//! Node configuration subsections.
//!
//! All the `node.*` configuration parameters: resource limits, rate limiting,
//! retry/backoff, cache sizing, discovery, spanning tree, bloom filters,
//! session management, and internal buffers.

use serde::{Deserialize, Serialize};

use super::IdentityConfig;
use crate::proto::mmp::{DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MmpMode};

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
    /// Max end-to-end sessions (`node.limits.max_sessions`), `0` = unlimited.
    ///
    /// The session table is the only remotely-grown map with no bound: an
    /// inbound SessionSetup from an address nobody has seen inserts an
    /// entry, and the idle purge only reaches entries a peer stops using.
    /// The default of 1024 is four times the adjacent
    /// `node.session.pending_max_destinations`. One entry measures 6608
    /// bytes of inline state plus heap, so the table holds to roughly 7 MB
    /// and a test pins the per-entry figure the default rests on. Raising it
    /// raises the memory an attacker can make this node hold; lowering it
    /// refuses new sessions sooner on a node that legitimately talks
    /// end-to-end to many others, such as a gateway.
    #[serde(default = "LimitsConfig::default_max_sessions")]
    pub max_sessions: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_peers: 128,
            max_links: 256,
            max_pending_inbound: 1000,
            max_sessions: 1024,
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
    fn default_max_sessions() -> usize {
        1024
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
    /// Burst capacity of the established-link msg1 bucket
    /// (`node.rate_limit.established_handshake_burst`).
    ///
    /// Absent (the normal case) derives it from `node.limits.max_peers`.
    #[serde(default)]
    pub established_handshake_burst: Option<u32>,
    /// Tokens/sec refill rate of the established-link msg1 bucket
    /// (`node.rate_limit.established_handshake_rate`).
    ///
    /// Absent (the normal case) derives it from `node.limits.max_peers`,
    /// `node.rekey.after_secs` and `handshake_max_resends`.
    #[serde(default)]
    pub established_handshake_rate: Option<f64>,
    /// Per-link-peer burst capacity for inbound FSP SessionSetup messages
    /// that would open a new session (`node.rate_limit.session_setup_burst`).
    ///
    /// 64 absorbs a legitimate reconnect burst arriving behind one
    /// neighbour. It bounds nothing on its own; `session_setup_rate` is what
    /// bounds the sustained cost.
    #[serde(default = "RateLimitConfig::default_session_setup_burst")]
    pub session_setup_burst: u32,
    /// Per-link-peer refill rate for those messages, in tokens per second
    /// (`node.rate_limit.session_setup_rate`).
    ///
    /// 16/s caps one neighbour's forced half-open occupancy at
    /// `rate * handshake_timeout_secs` (480 entries at defaults) and its ack
    /// amplification at `rate * (1 + handshake_max_resends)` (96 acks/s).
    ///
    /// Setup messages naming a peer this node is already established with
    /// are metered on a separate per-link bucket, derived from
    /// `node.limits.max_peers` exactly as `established_handshake_*` is, so a
    /// stranger flood cannot suppress rekey traffic sharing the link.
    #[serde(default = "RateLimitConfig::default_session_setup_rate")]
    pub session_setup_rate: f64,
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
            established_handshake_burst: None,
            established_handshake_rate: None,
            session_setup_burst: 64,
            session_setup_rate: 16.0,
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
    fn default_session_setup_burst() -> u32 {
        64
    }
    fn default_session_setup_rate() -> f64 {
        16.0
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

/// Mesh-lookup protocol (`node.lookup.*`): the overlay coordinate-lookup
/// engine (address → coordinates). The peer-rendezvous keys that used to
/// share this table (`nostr`/`lan`) now live under [`RendezvousConfig`]
/// (`node.rendezvous.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupConfig {
    /// Hop limit for LookupRequest flood (`node.lookup.ttl`).
    #[serde(default = "LookupConfig::default_ttl")]
    pub ttl: u8,
    /// Per-attempt timeouts in seconds (`node.lookup.attempt_timeouts_secs`).
    /// Each entry is the time to wait for a response before sending the next
    /// LookupRequest (with a fresh request_id). Sequence length determines the
    /// total number of attempts before declaring the destination unreachable.
    /// Default `[1, 2, 4, 8]` gives 4 attempts and a 15s total budget.
    #[serde(default = "LookupConfig::default_attempt_timeouts_secs")]
    pub attempt_timeouts_secs: Vec<u64>,
    /// Dedup cache expiry in seconds (`node.lookup.recent_expiry_secs`).
    #[serde(default = "LookupConfig::default_recent_expiry_secs")]
    pub recent_expiry_secs: u64,
    /// Base backoff after lookup failure in seconds (`node.lookup.backoff_base_secs`).
    /// Doubles per consecutive failure up to `backoff_max_secs`. Defaults to 0
    /// (no post-failure suppression); the per-attempt sequence in
    /// `attempt_timeouts_secs` provides the only retry pacing.
    #[serde(default = "LookupConfig::default_backoff_base_secs")]
    pub backoff_base_secs: u64,
    /// Maximum backoff cap in seconds (`node.lookup.backoff_max_secs`).
    #[serde(default = "LookupConfig::default_backoff_max_secs")]
    pub backoff_max_secs: u64,
    /// Minimum interval between forwarded lookups for the same target in seconds
    /// (`node.lookup.forward_min_interval_secs`).
    /// Defense-in-depth against misbehaving nodes.
    #[serde(default = "LookupConfig::default_forward_min_interval_secs")]
    pub forward_min_interval_secs: u64,
}

impl Default for LookupConfig {
    fn default() -> Self {
        Self {
            ttl: 64,
            attempt_timeouts_secs: vec![1, 2, 4, 8],
            recent_expiry_secs: 10,
            backoff_base_secs: 0,
            backoff_max_secs: 0,
            forward_min_interval_secs: 2,
        }
    }
}

impl LookupConfig {
    fn default_ttl() -> u8 {
        64
    }
    fn default_attempt_timeouts_secs() -> Vec<u64> {
        vec![1, 2, 4, 8]
    }
    fn default_recent_expiry_secs() -> u64 {
        10
    }
    fn default_backoff_base_secs() -> u64 {
        0
    }
    fn default_backoff_max_secs() -> u64 {
        0
    }
    fn default_forward_min_interval_secs() -> u64 {
        2
    }
}

/// Peer rendezvous (`node.rendezvous.*`): how the node finds peers to connect
/// to at all — Nostr-mediated overlay endpoints and mDNS/DNS-SD on the local
/// link. Distinct from mesh lookup ([`LookupConfig`]), which finds coordinates
/// for an already-known mesh address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RendezvousConfig {
    /// Nostr-mediated overlay endpoint rendezvous (`node.rendezvous.nostr.*`).
    #[serde(default)]
    pub nostr: NostrRendezvousConfig,
    /// mDNS / DNS-SD peer rendezvous on the local link (`node.rendezvous.lan.*`).
    /// Identity surface is a strict subset of what `nostr.advertise` already
    /// publishes publicly, so there's no marginal privacy cost; the latency
    /// win for same-LAN peers is large (sub-second pairing, no relay).
    #[serde(default)]
    pub lan: crate::mdns::LanRendezvousConfig,
}

/// COMPAT (drop at the v2 cutover): a deprecated legacy `node.discovery:` block.
///
/// The `node.discovery.*` table was split into `node.lookup.*` (mesh-lookup
/// scalars) and `node.rendezvous.*` (nostr/LAN peer rendezvous). Because
/// `NodeConfig` does not deny unknown fields, a still-deployed `node.discovery:`
/// block would otherwise deserialize into nothing and silently revert every
/// lookup/rendezvous setting to its default. This all-`Option` mirror captures
/// it so [`Config::normalize_deprecated_keys`] can fold it into the new tables
/// with a one-time deprecation warning; unset legacy keys stay `None` and leave
/// the new-table defaults intact.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DiscoveryConfigCompat {
    pub ttl: Option<u8>,
    pub attempt_timeouts_secs: Option<Vec<u64>>,
    pub recent_expiry_secs: Option<u64>,
    pub backoff_base_secs: Option<u64>,
    pub backoff_max_secs: Option<u64>,
    pub forward_min_interval_secs: Option<u64>,
    pub nostr: Option<NostrRendezvousConfig>,
    pub lan: Option<crate::mdns::LanRendezvousConfig>,
}

/// Nostr advert discovery policy.
///
/// Controls how overlay endpoint adverts are consumed:
/// - `disabled`: ignore advert-derived endpoints for all peers
/// - `configured_only`: allow advert fallback only for configured peers with
///   `peers[].via_nostr = true`
/// - `open`: also consider adverts for non-configured peers
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NostrRendezvousPolicy {
    Disabled,
    #[default]
    ConfiguredOnly,
    Open,
}

/// Nostr-mediated overlay endpoint discovery (`node.rendezvous.nostr.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NostrRendezvousConfig {
    /// Enable Nostr-signaled traversal bootstrap.
    #[serde(default)]
    pub enabled: bool,
    /// Publish service advertisements so remote peers can bootstrap inbound.
    #[serde(default = "NostrRendezvousConfig::default_advertise")]
    pub advertise: bool,
    /// Relay URLs used for service advertisements.
    #[serde(default = "NostrRendezvousConfig::default_advert_relays")]
    pub advert_relays: Vec<String>,
    /// Relay URLs used for encrypted signaling events.
    #[serde(default = "NostrRendezvousConfig::default_dm_relays")]
    pub dm_relays: Vec<String>,
    /// STUN servers used for local reflexive address discovery.
    /// Outbound observation uses only this local list; peer-advertised STUN
    /// values are informational and are not treated as egress targets.
    #[serde(default = "NostrRendezvousConfig::default_stun_servers")]
    pub stun_servers: Vec<String>,
    /// Whether to advertise local (RFC 1918 / ULA) interface addresses as
    /// host candidates in the traversal offer.
    ///
    /// Off by default: in most deployments the relevant peers are not on the
    /// same broadcast domain, and sharing private host candidates causes
    /// misleading punch successes when an asymmetric L3 path (corporate VPN,
    /// Tailscale subnet route, overlapping address space, etc.) makes a
    /// peer's private IP one-way reachable from this node. Enable only when
    /// peers are on the same physical LAN and same-LAN punching is wanted.
    #[serde(default)]
    pub share_local_candidates: bool,
    /// Traversal application namespace and advert identifier suffix.
    #[serde(default = "NostrRendezvousConfig::default_app")]
    pub app: String,
    /// Signaling TTL in seconds.
    #[serde(default = "NostrRendezvousConfig::default_signal_ttl_secs")]
    pub signal_ttl_secs: u64,
    /// Policy for advert-derived endpoint discovery.
    #[serde(default)]
    pub policy: NostrRendezvousPolicy,
    /// Max number of open-discovery peers queued for outbound retry/connection
    /// at once. Prevents unbounded queue growth from ambient advert traffic.
    #[serde(default = "NostrRendezvousConfig::default_open_discovery_max_pending")]
    pub open_discovery_max_pending: usize,
    /// Max concurrent inbound traversal offers processed at once.
    /// Acts as a rate limit against offer spam from relays.
    #[serde(default = "NostrRendezvousConfig::default_max_concurrent_incoming_offers")]
    pub max_concurrent_incoming_offers: usize,
    /// Max concurrent inbound traversal offers accepted from any one sender
    /// npub. Sits inside `max_concurrent_incoming_offers`, which remains the
    /// outer bound.
    #[serde(default = "NostrRendezvousConfig::default_max_concurrent_offers_per_npub")]
    pub max_concurrent_offers_per_npub: usize,
    /// Max cached overlay adverts retained from relay traffic.
    /// Bounds memory under ambient advert volume.
    #[serde(default = "NostrRendezvousConfig::default_advert_cache_max_entries")]
    pub advert_cache_max_entries: usize,
    /// Max seen-session IDs retained for replay detection.
    /// Oldest entries are evicted when the cap is exceeded.
    #[serde(default = "NostrRendezvousConfig::default_seen_sessions_max_entries")]
    pub seen_sessions_max_entries: usize,
    /// Overall punch attempt timeout in seconds.
    #[serde(default = "NostrRendezvousConfig::default_attempt_timeout_secs")]
    pub attempt_timeout_secs: u64,
    /// Replay tracking retention window in seconds.
    #[serde(default = "NostrRendezvousConfig::default_replay_window_secs")]
    pub replay_window_secs: u64,
    /// Delay before punch traffic starts.
    #[serde(default = "NostrRendezvousConfig::default_punch_start_delay_ms")]
    pub punch_start_delay_ms: u64,
    /// Interval between punch packets.
    #[serde(default = "NostrRendezvousConfig::default_punch_interval_ms")]
    pub punch_interval_ms: u64,
    /// How long to keep punching before failure.
    #[serde(default = "NostrRendezvousConfig::default_punch_duration_ms")]
    pub punch_duration_ms: u64,
    /// Advert TTL in seconds.
    #[serde(default = "NostrRendezvousConfig::default_advert_ttl_secs")]
    pub advert_ttl_secs: u64,
    /// How often adverts are refreshed in seconds.
    #[serde(default = "NostrRendezvousConfig::default_advert_refresh_secs")]
    pub advert_refresh_secs: u64,
    /// Settle delay in seconds after Nostr discovery starts before the
    /// one-shot startup sweep of cached adverts runs. Allows the relay
    /// subscription backlog to populate the in-memory advert cache.
    /// Only used under `policy: open`. Default: 5.
    #[serde(default = "NostrRendezvousConfig::default_startup_sweep_delay_secs")]
    pub startup_sweep_delay_secs: u64,
    /// Maximum age in seconds for cached adverts considered by the
    /// one-shot startup sweep. Adverts whose `created_at` is older than
    /// `now - startup_sweep_max_age_secs` are skipped. Only used under
    /// `policy: open`. Default: 3600 (1 hour).
    #[serde(default = "NostrRendezvousConfig::default_startup_sweep_max_age_secs")]
    pub startup_sweep_max_age_secs: u64,
    /// Number of consecutive NAT-traversal failures against a peer before
    /// an extended cooldown is applied to throttle further offer publishes.
    /// At this threshold the daemon also actively re-fetches the peer's
    /// advert from `advert_relays` to evict cache entries for peers that
    /// have gone away. Default: 5.
    #[serde(default = "NostrRendezvousConfig::default_failure_streak_threshold")]
    pub failure_streak_threshold: u32,
    /// Cooldown applied to a peer once `failure_streak_threshold` is hit.
    /// Suppresses both open-discovery sweep enqueues and per-attempt
    /// retry firings until elapsed. Default: 1800 (30 minutes).
    #[serde(default = "NostrRendezvousConfig::default_extended_cooldown_secs")]
    pub extended_cooldown_secs: u64,
    /// Minimum interval between `NAT traversal failed` WARN log lines for
    /// the same peer. Subsequent failures inside the window log at DEBUG.
    /// Reduces log spam on public-test nodes with many cache-learned
    /// peers. Default: 300 (5 minutes).
    #[serde(default = "NostrRendezvousConfig::default_warn_log_interval_secs")]
    pub warn_log_interval_secs: u64,
    /// Maximum entries retained in the per-npub failure-state map.
    /// Bounds memory under high cache turnover. Oldest entries (by last
    /// failure time) evicted when the cap is exceeded. Default: 4096.
    #[serde(default = "NostrRendezvousConfig::default_failure_state_max_entries")]
    pub failure_state_max_entries: usize,
    /// Cooldown applied after observing a fatal protocol mismatch on a
    /// Nostr-adopted bootstrap transport (e.g. `Unknown FMP version`
    /// from a peer running a different FMP-protocol version). Independent
    /// of `extended_cooldown_secs` and much longer because the mismatch
    /// is structural — re-traversing the peer is wasted effort until one
    /// side upgrades. Default: 86400 (24 hours).
    #[serde(default = "NostrRendezvousConfig::default_protocol_mismatch_cooldown_secs")]
    pub protocol_mismatch_cooldown_secs: u64,
}

impl Default for NostrRendezvousConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            advertise: Self::default_advertise(),
            advert_relays: Self::default_advert_relays(),
            dm_relays: Self::default_dm_relays(),
            stun_servers: Self::default_stun_servers(),
            share_local_candidates: false,
            app: Self::default_app(),
            signal_ttl_secs: Self::default_signal_ttl_secs(),
            policy: NostrRendezvousPolicy::default(),
            open_discovery_max_pending: Self::default_open_discovery_max_pending(),
            max_concurrent_incoming_offers: Self::default_max_concurrent_incoming_offers(),
            max_concurrent_offers_per_npub: Self::default_max_concurrent_offers_per_npub(),
            advert_cache_max_entries: Self::default_advert_cache_max_entries(),
            seen_sessions_max_entries: Self::default_seen_sessions_max_entries(),
            attempt_timeout_secs: Self::default_attempt_timeout_secs(),
            replay_window_secs: Self::default_replay_window_secs(),
            punch_start_delay_ms: Self::default_punch_start_delay_ms(),
            punch_interval_ms: Self::default_punch_interval_ms(),
            punch_duration_ms: Self::default_punch_duration_ms(),
            advert_ttl_secs: Self::default_advert_ttl_secs(),
            advert_refresh_secs: Self::default_advert_refresh_secs(),
            startup_sweep_delay_secs: Self::default_startup_sweep_delay_secs(),
            startup_sweep_max_age_secs: Self::default_startup_sweep_max_age_secs(),
            failure_streak_threshold: Self::default_failure_streak_threshold(),
            extended_cooldown_secs: Self::default_extended_cooldown_secs(),
            warn_log_interval_secs: Self::default_warn_log_interval_secs(),
            failure_state_max_entries: Self::default_failure_state_max_entries(),
            protocol_mismatch_cooldown_secs: Self::default_protocol_mismatch_cooldown_secs(),
        }
    }
}

impl NostrRendezvousConfig {
    fn default_advertise() -> bool {
        true
    }

    fn default_advert_relays() -> Vec<String> {
        vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string(),
            "wss://offchain.pub".to_string(),
        ]
    }

    fn default_dm_relays() -> Vec<String> {
        vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string(),
            "wss://offchain.pub".to_string(),
        ]
    }

    fn default_stun_servers() -> Vec<String> {
        vec![
            "stun:stun.l.google.com:19302".to_string(),
            "stun:stun.cloudflare.com:3478".to_string(),
            "stun:global.stun.twilio.com:3478".to_string(),
        ]
    }

    fn default_app() -> String {
        // Branch-specific default. `next` runs FMP-v1 which is wire-
        // incompatible with `master`'s FMP-v0, so the two namespaces
        // separate the discovery overlays by default — operators who
        // want cross-branch discovery can override here.
        "fips-overlay-v1-next".to_string()
    }

    fn default_signal_ttl_secs() -> u64 {
        120
    }

    fn default_open_discovery_max_pending() -> usize {
        64
    }

    fn default_max_concurrent_incoming_offers() -> usize {
        16
    }

    /// Four, derived rather than picked. The initiator side already admits at
    /// most one in-flight traversal per peer npub, so one concurrent offer per
    /// peer is the honest steady state. An offer is published to and consumed
    /// from the whole DM relay set, three URLs by default, and whether the
    /// notification stream deduplicates one event delivered by three relays is
    /// not established here — if it does not, one honest offer can present as
    /// three near-simultaneous admissions before the replay check rejects the
    /// duplicates. Four is that worst-case fan-out plus one, so a retry
    /// overlapping a still-timing-out attempt is still admitted, and it is a
    /// quarter of the default global bound.
    fn default_max_concurrent_offers_per_npub() -> usize {
        4
    }

    fn default_advert_cache_max_entries() -> usize {
        2048
    }

    fn default_seen_sessions_max_entries() -> usize {
        2048
    }

    fn default_attempt_timeout_secs() -> u64 {
        10
    }

    fn default_replay_window_secs() -> u64 {
        300
    }

    fn default_punch_start_delay_ms() -> u64 {
        2_000
    }

    fn default_punch_interval_ms() -> u64 {
        200
    }

    fn default_punch_duration_ms() -> u64 {
        10_000
    }

    fn default_advert_ttl_secs() -> u64 {
        3_600
    }

    fn default_advert_refresh_secs() -> u64 {
        1_800
    }

    fn default_startup_sweep_delay_secs() -> u64 {
        5
    }

    fn default_startup_sweep_max_age_secs() -> u64 {
        3_600
    }

    fn default_failure_streak_threshold() -> u32 {
        5
    }

    fn default_extended_cooldown_secs() -> u64 {
        1_800
    }

    fn default_warn_log_interval_secs() -> u64 {
        300
    }

    fn default_failure_state_max_entries() -> usize {
        4_096
    }

    fn default_protocol_mismatch_cooldown_secs() -> u64 {
        86_400
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
    /// Default `0.20` ≈ fill 0.7248 at k=5 ≈ ~2,114 entries on the 1 KB
    /// filter (Swamidass–Baldi). Raised from 0.10 so aggregates that are
    /// legitimately near their operating ceiling are not rejected before
    /// the network reaches the fixed-filter capacity limit; conceptually
    /// distinct from future autoscaling hysteresis setpoints — same unit,
    /// different knobs.
    #[serde(default = "BloomConfig::default_max_inbound_fpr")]
    pub max_inbound_fpr: f64,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            update_debounce_ms: Self::default_update_debounce_ms(),
            max_inbound_fpr: Self::default_max_inbound_fpr(),
        }
    }
}

impl BloomConfig {
    fn default_update_debounce_ms() -> u64 {
        500
    }
    fn default_max_inbound_fpr() -> f64 {
        0.20
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

/// MMP configuration (`node.mmp.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmpConfig {
    /// Operating mode (`node.mmp.mode`).
    #[serde(default)]
    pub mode: MmpMode,

    /// Periodic operator log interval in seconds (`node.mmp.log_interval_secs`).
    #[serde(default = "MmpConfig::default_log_interval_secs")]
    pub log_interval_secs: u64,

    /// OWD trend ring buffer size (`node.mmp.owd_window_size`).
    #[serde(default = "MmpConfig::default_owd_window_size")]
    pub owd_window_size: usize,
}

impl Default for MmpConfig {
    fn default() -> Self {
        Self {
            mode: MmpMode::default(),
            log_interval_secs: DEFAULT_LOG_INTERVAL_SECS,
            owd_window_size: DEFAULT_OWD_WINDOW_SIZE,
        }
    }
}

impl MmpConfig {
    fn default_log_interval_secs() -> u64 {
        DEFAULT_LOG_INTERVAL_SECS
    }
    fn default_owd_window_size() -> usize {
        DEFAULT_OWD_WINDOW_SIZE
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
    /// On Unix, delegates to [`super::resolve_default_socket`] for the shared
    /// platform runtime-directory → `XDG_RUNTIME_DIR` → `/tmp` order. On
    /// Windows, returns a TCP port number as a string since Windows does not
    /// support Unix domain sockets; the control socket listens on localhost at
    /// this port.
    fn default_socket_path() -> String {
        #[cfg(unix)]
        {
            super::resolve_default_socket("control.sock")
        }
        #[cfg(windows)]
        {
            "21210".to_string()
        }
    }
}

/// Native datagram API socket (`node.native_api.*`).
///
/// **Experimental, and built on Linux, FreeBSD and macOS only.** The API hands a
/// client a file descriptor over `SCM_RIGHTS`, which Windows has no equivalent
/// of, and does it over an `AF_UNIX` `SOCK_SEQPACKET` socket, which macOS does
/// not implement. No listener is built on either, and this section is ignored
/// there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeApiConfig {
    /// Enable the native API socket (`node.native_api.enabled`).
    ///
    /// Disabled by default. Any process that can open the socket can send as
    /// this node's identity, and can receive mesh traffic on a port it chooses,
    /// so enabling it is an explicit operator decision rather than a default.
    #[serde(default = "NativeApiConfig::default_enabled")]
    pub enabled: bool,

    /// Unix socket path (`node.native_api.socket_path`).
    #[serde(default = "NativeApiConfig::default_socket_path")]
    pub socket_path: String,

    /// Datagrams held for one flow (`node.native_api.pending_per_flow`).
    ///
    /// Applies while a flow waits to be accepted and while an established
    /// flow's client is slow to read. Mirrors
    /// [`SessionConfig::pending_packets_per_dest`], which bounds the same shape
    /// of problem on the session layer.
    ///
    /// Bounded above by [`NativeApiConfig::MAX_PENDING_PER_FLOW`] at config
    /// load. The whole batch is written onto a socket pair no process can read
    /// yet, so a value large enough to exceed the send buffer would leave the
    /// listener's task with a write it cannot complete.
    ///
    /// Bounded below by 1 at the same place. Zero announces an arrival and then
    /// refuses the datagram that caused it, losing a peer's opening message
    /// with no refusal a client or an operator can see.
    #[serde(default = "NativeApiConfig::default_pending_per_flow")]
    pub pending_per_flow: usize,

    /// Flows awaiting accept on one listener (`node.native_api.backlog`).
    ///
    /// A client that announces interest and never answers cannot make the node
    /// hold more than this, whatever a peer does.
    ///
    /// Bounded below by 1 at config load. Zero would admit no flow at all: the
    /// registry compares a listener's pending depth against this before it
    /// announces anything, so every arrival would be dropped.
    #[serde(default = "NativeApiConfig::default_backlog")]
    pub backlog: usize,

    /// Flows this node holds at once (`node.native_api.max_flows`).
    #[serde(default = "NativeApiConfig::default_max_flows")]
    pub max_flows: usize,

    /// Answer the debug commands (`node.native_api.debug_commands`).
    ///
    /// **Off by default, and not a supported interface.** The three commands
    /// it admits (`inject`, `stats`, `arrive`) exist so the test harness can
    /// drive the receive and dispatch paths without a wire. `inject` makes
    /// the daemon write bytes the client chose into one of that client's own
    /// flows, and `arrive` makes it dispatch a datagram as though a peer had
    /// sent it, which reaches any listener this node holds. None of the three
    /// belongs in a packaged node, so this key is what the test harness turns
    /// on and nothing else does.
    #[serde(default = "NativeApiConfig::default_debug_commands")]
    pub debug_commands: bool,
}

impl Default for NativeApiConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            socket_path: Self::default_socket_path(),
            pending_per_flow: Self::default_pending_per_flow(),
            backlog: Self::default_backlog(),
            max_flows: Self::default_max_flows(),
            debug_commands: Self::default_debug_commands(),
        }
    }
}

impl NativeApiConfig {
    /// Largest `pending_per_flow` a node will start with.
    ///
    /// The held batch is at most this many datagrams of at most `max_payload`
    /// bytes each, written without waiting onto a socket pair whose other half
    /// is still on its way to the client. At 64 and a 1362-byte payload that is
    /// about 87 KB, which an ordinary `AF_UNIX` send buffer takes. The bound is
    /// checked at config load so a value that would wedge a listener's task is
    /// refused at startup rather than at the first arrival.
    pub const MAX_PENDING_PER_FLOW: usize = 64;

    fn default_enabled() -> bool {
        false
    }

    fn default_pending_per_flow() -> usize {
        16
    }

    fn default_backlog() -> usize {
        16
    }

    fn default_max_flows() -> usize {
        256
    }

    fn default_debug_commands() -> bool {
        false
    }

    /// Default native API socket path, resolved beside the control socket.
    ///
    /// On Windows the path is empty: the API is not built there, so no value
    /// would be meaningful.
    fn default_socket_path() -> String {
        #[cfg(unix)]
        {
            super::resolve_default_socket("api.sock")
        }
        #[cfg(windows)]
        {
            String::new()
        }
    }

    /// Whether this section carries nothing but its defaults.
    ///
    /// Drives `skip_serializing_if` so a config file that never named the
    /// section does not gain one when the config is serialized back out.
    fn is_default(&self) -> bool {
        *self == Self::default()
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

    /// Graceful-shutdown drain deadline in seconds (`node.drain_timeout_secs`).
    /// The bounded `Draining` phase broadcasts a shutdown `Disconnect` and then
    /// waits up to this long for peers to clear before tearing down, early-
    /// exiting as soon as all peers are gone. `None` selects the 2-second
    /// default (see [`NodeConfig::drain_timeout`]).
    ///
    /// Kept `Option` deliberately: `NodeConfig` has no `deny_unknown_fields`, so
    /// a naive non-`Option` add with a `default` fn would silently rewrite the
    /// value into deployed configs on the next serialize. The `Option` +
    /// `skip_serializing_if` keeps absent configs absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_timeout_secs: Option<u64>,

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

    /// Mesh-lookup protocol (`node.lookup.*`).
    #[serde(default)]
    pub lookup: LookupConfig,

    /// Peer rendezvous (`node.rendezvous.*`).
    #[serde(default)]
    pub rendezvous: RendezvousConfig,

    /// COMPAT (drop at the v2 cutover): a deprecated legacy `node.discovery:`
    /// block, folded into `lookup`/`rendezvous` by
    /// [`Config::normalize_deprecated_keys`]. Never re-serialized.
    #[serde(default, skip_serializing)]
    pub(crate) discovery: Option<DiscoveryConfigCompat>,

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

    /// Native datagram API (`node.native_api.*`). Experimental; the listener
    /// is built on Linux, FreeBSD and macOS only.
    #[serde(default, skip_serializing_if = "NativeApiConfig::is_default")]
    pub native_api: NativeApiConfig,

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
            drain_timeout_secs: None,
            limits: LimitsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
            cache: CacheConfig::default(),
            lookup: LookupConfig::default(),
            rendezvous: RendezvousConfig::default(),
            discovery: None,
            tree: TreeConfig::default(),
            bloom: BloomConfig::default(),
            session: SessionConfig::default(),
            buffers: BuffersConfig::default(),
            control: ControlConfig::default(),
            native_api: NativeApiConfig::default(),
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

    /// Graceful-shutdown drain deadline as a `Duration`.
    ///
    /// Returns the configured `drain_timeout_secs`, or the 2-second default
    /// when unset. Used by the daemon's bounded `Draining` phase.
    pub fn drain_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.drain_timeout_secs.unwrap_or(2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = MmpConfig::default();
        assert_eq!(config.mode, MmpMode::Full);
        assert_eq!(config.log_interval_secs, 30);
        assert_eq!(config.owd_window_size, 32);
    }

    #[test]
    fn test_config_yaml_parse() {
        let yaml = r#"
mode: lightweight
log_interval_secs: 60
owd_window_size: 48
"#;
        let config: MmpConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, MmpMode::Lightweight);
        assert_eq!(config.log_interval_secs, 60);
        assert_eq!(config.owd_window_size, 48);
    }

    #[test]
    fn test_config_yaml_partial() {
        let yaml = "mode: minimal";
        let config: MmpConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, MmpMode::Minimal);
        assert_eq!(config.log_interval_secs, DEFAULT_LOG_INTERVAL_SECS);
        assert_eq!(config.owd_window_size, DEFAULT_OWD_WINDOW_SIZE);
    }

    #[test]
    fn test_drain_timeout_default_and_override() {
        // Unset → the 2-second default.
        let c = NodeConfig::default();
        assert_eq!(c.drain_timeout_secs, None);
        assert_eq!(c.drain_timeout(), std::time::Duration::from_secs(2));

        // Explicit override is honored.
        let c2 = NodeConfig {
            drain_timeout_secs: Some(10),
            ..NodeConfig::default()
        };
        assert_eq!(c2.drain_timeout(), std::time::Duration::from_secs(10));

        // A zero override is a valid (immediate) drain, not the default.
        let c3 = NodeConfig {
            drain_timeout_secs: Some(0),
            ..NodeConfig::default()
        };
        assert_eq!(c3.drain_timeout(), std::time::Duration::from_secs(0));
    }

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

    #[test]
    fn test_nostr_rendezvous_startup_sweep_defaults() {
        let c = NostrRendezvousConfig::default();
        assert_eq!(c.startup_sweep_delay_secs, 5);
        assert_eq!(c.startup_sweep_max_age_secs, 3_600);
    }

    #[test]
    fn test_nostr_rendezvous_startup_sweep_yaml_override() {
        let yaml = "enabled: true\npolicy: open\nstartup_sweep_delay_secs: 10\nstartup_sweep_max_age_secs: 1800\n";
        let c: NostrRendezvousConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(c.enabled);
        assert_eq!(c.policy, NostrRendezvousPolicy::Open);
        assert_eq!(c.startup_sweep_delay_secs, 10);
        assert_eq!(c.startup_sweep_max_age_secs, 1_800);
    }

    #[test]
    fn test_nostr_rendezvous_startup_sweep_partial_yaml_uses_defaults() {
        // Only override delay; max_age should fall back to default.
        let yaml = "enabled: true\nstartup_sweep_delay_secs: 30\n";
        let c: NostrRendezvousConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(c.startup_sweep_delay_secs, 30);
        assert_eq!(c.startup_sweep_max_age_secs, 3_600);
    }

    #[test]
    fn test_log_level_parser() {
        // Pin the observed behavior of NodeConfig::log_level():
        // - 5 explicit lowercased match arms (trace/debug/warn|warning/error)
        // - INFO is the default (no explicit "info" arm; falls through default)
        // - Case-insensitive via .to_lowercase()
        // - Unknown strings and None both fall through to INFO
        let cases: &[(Option<&str>, tracing::Level)] = &[
            // Explicit arms (lowercase canonical form)
            (Some("trace"), tracing::Level::TRACE),
            (Some("debug"), tracing::Level::DEBUG),
            (Some("warn"), tracing::Level::WARN),
            (Some("warning"), tracing::Level::WARN),
            (Some("error"), tracing::Level::ERROR),
            // "info" has no explicit arm — falls through default
            (Some("info"), tracing::Level::INFO),
            // None → default INFO
            (None, tracing::Level::INFO),
            // Case-insensitivity (parser lowercases via .to_lowercase())
            (Some("TRACE"), tracing::Level::TRACE),
            (Some("Debug"), tracing::Level::DEBUG),
            (Some("Warning"), tracing::Level::WARN),
            (Some("WARN"), tracing::Level::WARN),
            (Some("ERROR"), tracing::Level::ERROR),
            (Some("INFO"), tracing::Level::INFO),
            // Unknown strings → INFO default (no error path)
            (Some("verbose"), tracing::Level::INFO),
            (Some("nonsense"), tracing::Level::INFO),
            (Some(""), tracing::Level::INFO),
        ];

        for (input, expected) in cases {
            let cfg = NodeConfig {
                log_level: input.map(|s| s.to_string()),
                ..NodeConfig::default()
            };
            assert_eq!(
                cfg.log_level(),
                *expected,
                "input {:?} should map to {:?}",
                input,
                expected
            );
        }
    }

    #[test]
    fn test_native_api_is_off_and_undebuggable_by_default() {
        // Both gates default closed, and neither has any other guard in the
        // library: the harness case that leaves `debug_commands` out of its
        // YAML proves the serde path, not the value it lands on.
        let config = NativeApiConfig::default();
        assert!(!config.enabled);
        assert!(!config.debug_commands);

        // Enabling the API must not drag the debug commands in with it, which
        // is the shape a real operator config takes.
        let yaml = "enabled: true\n";
        let parsed: NativeApiConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(parsed.enabled);
        assert!(!parsed.debug_commands);
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
