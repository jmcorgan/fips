//! The machine's settings. The shell converts them from the node's
//! `node.rendezvous.nostr.*` configuration, which this module cannot name.

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
}
