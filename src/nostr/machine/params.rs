//! The machine's settings. The shell converts them from the node's
//! `node.rendezvous.nostr.*` configuration, which this module cannot name,
//! and the fixed waits the machine's relay operations and schedules use.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

/// How long a subscribe, and an inbox relay list publish, may take.
pub const STARTUP_OP_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an advert publish may take.
pub const ADVERT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a fetch of a peer's advert waits for the relays.
pub const ADVERT_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// How often our own inbox relay list is republished, well inside the
/// 30 days peers look back for one, so peers always find a current one.
pub const INBOX_REPUBLISH: Duration = Duration::from_secs(24 * 60 * 60);

/// The wait before the first retry of a failed subscribe; each later retry
/// waits twice as long, up to [`SUBSCRIBE_RETRY_MAX`].
pub const SUBSCRIBE_RETRY_FIRST: Duration = Duration::from_secs(2);

/// The longest wait between subscribe retries.
pub const SUBSCRIBE_RETRY_MAX: Duration = Duration::from_secs(60);

/// How long each STUN server has to answer a traversal's observation, from
/// its first send. Tight, so a misbehaving server does not stretch every
/// traversal.
pub const TRAVERSAL_STUN_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a failed public-address observation is remembered. Held briefly
/// so that a transient flake at start-up is retried within about a minute
/// and the advert gains its UDP endpoint as soon as STUN works, rather than
/// after a whole advert refresh interval. A success is remembered for
/// `max(advert_refresh_secs, 60)` seconds.
pub const PUBLIC_ADDR_FAILURE_TTL: Duration = Duration::from_secs(60);

/// The configuration values the machine's pieces read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// Consecutive failures before a peer enters its extended cooldown.
    pub failure_streak_threshold: u32,
    /// The extended cooldown, in seconds.
    pub extended_cooldown_secs: u64,
    /// The minimum interval between repeated failure warnings for one peer,
    /// in seconds.
    pub warn_log_interval_secs: u64,
    /// The bound on the failure-state table.
    pub failure_state_max_entries: usize,
    /// How long a seen offer's session id is remembered, in seconds.
    pub replay_window_secs: u64,
    /// The bound on the seen-sessions memory.
    pub seen_sessions_max_entries: usize,
    /// Whether this node publishes an advert at all.
    pub advertise: bool,
    /// The bound on the peer advert cache, protected authors aside.
    pub advert_cache_max_entries: usize,
    /// This node's advert republish interval, in seconds; a cached entry
    /// keeps its slot for one such interval past its horizon.
    pub advert_refresh_secs: u64,
    /// The application name adverts carry in their `protocol` tag.
    pub app: String,
    /// The relays adverts are published to and read from.
    pub advert_relays: Vec<String>,
    /// The relays this node reads traversal signals on, which its advert
    /// and inbox relay list name.
    pub dm_relays: Vec<String>,
    /// The STUN servers this node uses, which its advert names.
    pub stun_servers: Vec<String>,
    /// This node's advert lifetime, in seconds.
    pub advert_ttl_secs: u64,
    /// How long a traversal signal is valid, and how long an initiator
    /// waits for the answer, in seconds.
    pub signal_ttl_secs: u64,
    /// How long a punch attempt may run before it adopts nothing, in
    /// seconds.
    pub attempt_timeout_secs: u64,
    /// How long after a punch hint is made its first probe goes out, in
    /// milliseconds.
    pub punch_start_delay_ms: u64,
    /// The interval between probe rounds, in milliseconds.
    pub punch_interval_ms: u64,
    /// How long probe rounds go on, in milliseconds.
    pub punch_duration_ms: u64,
    /// Whether a traversal offers this host's own addresses as same-LAN
    /// candidates.
    pub share_local_candidates: bool,
    /// How long a peer whose datagrams carry another FMP version is not
    /// traversed again, in seconds.
    pub protocol_mismatch_cooldown_secs: u64,
    /// The bound on inbound offers handled at once, across all senders.
    pub max_concurrent_incoming_offers: usize,
    /// The bound on inbound offers handled at once from one sender.
    pub max_concurrent_offers_per_npub: usize,
}
