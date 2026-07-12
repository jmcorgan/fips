//! Connection retry logic for auto-connect peers.
//!
//! When an outbound handshake fails (timeout or send error), the node can
//! automatically retry with exponential backoff. Retry state lives on Node
//! (not PeerConnection) because each retry creates a fresh connection.

use super::{Node, NodeError};
use crate::PeerIdentity;
use crate::config::PeerConfig;
use crate::identity::NodeAddr;
use crate::proto::fmp::backoff_ms;
use tracing::{debug, info, warn};

// MAX_BACKOFF_MS is now derived from config: node.retry.max_backoff_secs * 1000
const MAX_RETRY_CONNECTIONS_PER_TICK: usize = 16;

/// Tracks retry state for a peer across connection attempts.
pub struct RetryState {
    /// The peer config to use for initiating retries.
    pub peer_config: PeerConfig,

    /// Number of retries attempted so far.
    pub retry_count: u32,

    /// Timestamp (Unix ms) when the next retry should be attempted.
    pub retry_after_ms: u64,

    /// Whether this is an auto-reconnect (unlimited retries, ignores max_retries).
    pub reconnect: bool,

    /// Optional absolute expiry for this retry entry (Unix ms).
    ///
    /// When set, retries are dropped after this point even if reconnect logic
    /// would otherwise continue.
    pub expires_at_ms: Option<u64>,
}

impl RetryState {
    /// Create a new retry state for a peer.
    pub fn new(peer_config: PeerConfig) -> Self {
        Self {
            peer_config,
            retry_count: 0,
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        }
    }
}

impl Node {
    /// Schedule a retry for a failed outbound connection, if applicable.
    ///
    /// Only schedules if the peer is an auto-connect peer and max retries
    /// have not been exhausted (unless `reconnect` is true, which retries
    /// indefinitely). Does nothing if the peer is already connected or has
    /// a connection in progress.
    pub(super) fn schedule_retry(&mut self, node_addr: NodeAddr, now_ms: u64) {
        let retry_cfg = &self.config().node.retry;
        let max_retries = retry_cfg.max_retries;
        if max_retries == 0 {
            return;
        }

        // Don't retry if peer is already connected
        if self.peers.contains_key(&node_addr) {
            return;
        }

        let base_interval_ms = retry_cfg.base_interval_secs * 1000;
        let max_backoff_ms = retry_cfg.max_backoff_secs * 1000;
        let peer_name = self.peer_display_name(&node_addr);

        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
            // Already tracking — increment
            state.retry_count += 1;
            if !state.reconnect && state.retry_count > max_retries {
                info!(
                    peer = %peer_name,
                    attempts = state.retry_count,
                    "Max retries exhausted, giving up on peer"
                );
                self.retry_pending.remove(&node_addr);
                return;
            }
            let delay = backoff_ms(state.retry_count, base_interval_ms, max_backoff_ms);
            state.retry_after_ms = now_ms + delay;
            debug!(
                peer = %peer_name,
                retry = state.retry_count,
                reconnect = state.reconnect,
                delay_secs = delay / 1000,
                "Scheduling connection retry"
            );
        } else {
            // First failure — find the matching PeerConfig
            let peer_config = self
                .config()
                .auto_connect_peers()
                .find(|pc| {
                    PeerIdentity::from_npub(&pc.npub)
                        .map(|id| *id.node_addr() == node_addr)
                        .unwrap_or(false)
                })
                .cloned();

            if let Some(pc) = peer_config {
                let mut state = RetryState::new(pc);
                state.retry_count = 1;
                state.reconnect = true;
                let delay = backoff_ms(state.retry_count, base_interval_ms, max_backoff_ms);
                state.retry_after_ms = now_ms + delay;
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    delay_secs = delay / 1000,
                    "First connection attempt failed, scheduling retry"
                );
                self.retry_pending.insert(node_addr, state);
            }
            // If not found in auto_connect_peers, no retry (one-shot connection)
        }
    }

    /// Schedule auto-reconnect for a peer removed by MMP dead timeout.
    ///
    /// Looks up the peer in auto-connect config and checks `auto_reconnect`.
    /// If enabled, feeds the peer into the retry system with unlimited retries.
    ///
    /// If a retry entry already exists (e.g. from a previous failed handshake
    /// attempt during an earlier reconnect cycle), the existing retry count is
    /// preserved and incremented rather than reset to zero. This ensures
    /// exponential backoff accumulates across repeated link-dead events instead
    /// of resetting to the base interval on every peer removal.
    pub(super) fn schedule_reconnect(&mut self, node_addr: NodeAddr, now_ms: u64) {
        // Find peer in auto-connect config
        let peer_config = self
            .config()
            .auto_connect_peers()
            .find(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .map(|id| *id.node_addr() == node_addr)
                    .unwrap_or(false)
            })
            .cloned();

        let Some(pc) = peer_config else {
            return; // Not an auto-connect peer, no reconnect
        };

        if !pc.auto_reconnect {
            debug!(
                peer = %self.peer_display_name(&node_addr),
                "Auto-reconnect disabled for peer, skipping"
            );
            return;
        }

        let base_interval_ms = self.config().node.retry.base_interval_secs * 1000;
        let max_backoff_ms = self.config().node.retry.max_backoff_secs * 1000;
        let peer_name = self.peer_display_name(&node_addr);

        // If we already have accumulated backoff from previous failed attempts,
        // preserve and bump it rather than resetting to zero. This prevents the
        // exponential backoff from being discarded on each link-dead cycle.
        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
            state.reconnect = true;
            state.retry_count += 1;
            let delay = backoff_ms(state.retry_count, base_interval_ms, max_backoff_ms);
            state.retry_after_ms = now_ms + delay;
            debug!(
                peer = %peer_name,
                retry = state.retry_count,
                delay_secs = delay / 1000,
                "Scheduling auto-reconnect after link-dead removal (backoff preserved)"
            );
            return;
        }

        let mut state = RetryState::new(pc);
        state.reconnect = true;
        let delay = backoff_ms(state.retry_count, base_interval_ms, max_backoff_ms);
        state.retry_after_ms = now_ms + delay;

        debug!(
            peer = %peer_name,
            delay_secs = delay / 1000,
            "Scheduling auto-reconnect after link-dead removal"
        );

        self.retry_pending.insert(node_addr, state);
    }

    /// Process pending retries whose time has arrived.
    ///
    /// For each due retry, initiates a fresh connection attempt. The retry
    /// entry stays in `retry_pending` until the connection succeeds (cleared
    /// in `promote_connection`) or max retries are exhausted (cleared in
    /// `schedule_retry`).
    pub(super) async fn process_pending_retries(&mut self, now_ms: u64) {
        if self.retry_pending.is_empty() {
            return;
        }

        let expired: Vec<NodeAddr> = self
            .retry_pending
            .iter()
            .filter_map(|(addr, state)| {
                state
                    .expires_at_ms
                    .filter(|expires_at_ms| now_ms >= *expires_at_ms)
                    .map(|_| *addr)
            })
            .collect();
        for node_addr in expired {
            self.retry_pending.remove(&node_addr);
            info!(
                peer = %self.peer_display_name(&node_addr),
                "Retry window expired, dropping pending retry state"
            );
        }
        if self.retry_pending.is_empty() {
            return;
        }

        if !self.outbound_admission_check() {
            debug!(
                peers = self.peers.len(),
                max_peers = self.max_peers(),
                retry_pending = self.retry_pending.len(),
                "Suppressing auto-reconnect retries: at capacity"
            );
            return;
        }

        // Collect retries that are due
        let due: Vec<NodeAddr> = self
            .retry_pending
            .iter()
            .filter(|(_, state)| now_ms >= state.retry_after_ms)
            .map(|(addr, _)| *addr)
            .collect();
        let deferred = due.len().saturating_sub(MAX_RETRY_CONNECTIONS_PER_TICK);
        if deferred > 0 {
            debug!(
                due = due.len(),
                processing = MAX_RETRY_CONNECTIONS_PER_TICK,
                deferred,
                "Retry processing budget exhausted; deferring remaining peers"
            );
        }

        for node_addr in due.into_iter().take(MAX_RETRY_CONNECTIONS_PER_TICK) {
            // Peer may have connected inbound while we waited
            if self.peers.contains_key(&node_addr) {
                self.retry_pending.remove(&node_addr);
                continue;
            }

            let state = match self.retry_pending.get(&node_addr) {
                Some(s) => s,
                None => continue,
            };

            debug!(
                peer = %self.peer_display_name(&node_addr),
                retry = state.retry_count,
                "Attempting connection retry"
            );

            let peer_config = state.peer_config.clone();

            // Refresh the peer's overlay advert before retrying. The cache is
            // read-only on hit (see fetch_advert), so every retry without a
            // refetch dials the same cached endpoint — and the most common
            // reason a peer ended up in retry_pending is that the cached
            // endpoint just stopped working (NAT rebind, port change, peer
            // restart on a different port). Without this refresh the retry
            // loop dials the same dead address forever.
            //
            // refetch_advert_for_stale_check uses the relay's advert as
            // ground truth: replaces the cache if there's a newer one,
            // evicts if the relay has nothing, otherwise leaves it. Cheap
            // (one Filter fetch with 2s timeout) and bounded by the retry
            // backoff cadence.
            if let Some(bootstrap) = self.supervisor.nostr_rendezvous.engine_arc() {
                let _ = bootstrap
                    .refetch_advert_for_stale_check(&peer_config.npub)
                    .await;
            }

            match self.initiate_peer_connection(&peer_config).await {
                Ok(()) => {
                    // Push retry_after_ms past the handshake timeout window so
                    // we don't re-fire on the next tick. If the handshake
                    // succeeds, promote_connection() clears retry_pending. If
                    // it times out, check_timeouts() calls schedule_retry()
                    // which bumps the counter and applies proper backoff.
                    let hs_timeout_ms = self.config().node.rate_limit.handshake_timeout_secs * 1000;
                    if let Some(state) = self.retry_pending.get_mut(&node_addr) {
                        state.retry_after_ms = now_ms + hs_timeout_ms;
                    }
                    debug!(
                        peer = %self.peer_display_name(&node_addr),
                        "Retry connection initiated, suppressing re-fire for {}s",
                        self.config().node.rate_limit.handshake_timeout_secs,
                    );
                }
                Err(e) => {
                    warn!(
                        peer = %self.peer_display_name(&node_addr),
                        error = %e,
                        "Retry connection initiation failed"
                    );
                    // No-transport failures usually mean the cached overlay
                    // advert is stale (peer rebound NAT, switched relay, etc.).
                    // The advert cache is read-only inside fetch_advert, so
                    // every retry returns the same dead address until the
                    // entry expires. Force a re-fetch so the next retry tick
                    // picks up fresh endpoints.
                    if matches!(e, NodeError::NoTransportForType(_))
                        && let Some(bootstrap) = self.supervisor.nostr_rendezvous.engine_arc()
                    {
                        let npub = peer_config.npub.clone();
                        tokio::spawn(async move {
                            let _ = bootstrap.refetch_advert_for_stale_check(&npub).await;
                        });
                    }
                    // Immediate failure counts as an attempt — schedule next retry
                    // (reconnect flag is preserved on existing retry_pending entry)
                    self.schedule_retry(node_addr, now_ms);
                }
            }
        }
    }
}
