//! Connection retry logic for auto-connect peers.
//!
//! When an outbound handshake fails (timeout or send error), the node can
//! automatically retry with exponential backoff. Retry state lives on Node
//! (not PeerConnection) because each retry creates a fresh connection.

use super::Node;
use crate::config::PeerConfig;
use crate::identity::NodeAddr;
use crate::PeerIdentity;
use tracing::{debug, info, warn};

// MAX_BACKOFF_MS is now derived from config: node.retry.max_backoff_secs * 1000

/// Tracks retry state for a peer across connection attempts.
pub struct RetryState {
    /// The peer config to use for initiating retries.
    pub peer_config: PeerConfig,

    /// Number of retries attempted so far.
    pub retry_count: u32,

    /// Timestamp (Unix ms) when the next retry should be attempted.
    pub retry_after_ms: u64,
}

impl RetryState {
    /// Create a new retry state for a peer.
    pub fn new(peer_config: PeerConfig) -> Self {
        Self {
            peer_config,
            retry_count: 0,
            retry_after_ms: 0,
        }
    }

    /// Calculate the backoff delay in milliseconds for the current retry count.
    ///
    /// Uses exponential backoff: `base_interval_ms * 2^retry_count`,
    /// capped at `MAX_BACKOFF_MS`.
    pub fn backoff_ms(&self, base_interval_ms: u64, max_backoff_ms: u64) -> u64 {
        let multiplier = 1u64.checked_shl(self.retry_count).unwrap_or(u64::MAX);
        base_interval_ms.saturating_mul(multiplier).min(max_backoff_ms)
    }
}

impl Node {
    /// Schedule a retry for a failed outbound connection, if applicable.
    ///
    /// Only schedules if the peer is an auto-connect peer and max retries
    /// have not been exhausted. Does nothing if the peer is already connected
    /// or has a connection in progress.
    pub(super) fn schedule_retry(&mut self, node_addr: NodeAddr, now_ms: u64) {
        let retry_cfg = &self.config.node.retry;
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

        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
            // Already tracking — increment
            state.retry_count += 1;
            if state.retry_count > max_retries {
                info!(
                    node_addr = %node_addr,
                    attempts = state.retry_count,
                    "Max retries exhausted, giving up on peer"
                );
                self.retry_pending.remove(&node_addr);
                return;
            }
            let delay = state.backoff_ms(base_interval_ms, max_backoff_ms);
            state.retry_after_ms = now_ms + delay;
            debug!(
                node_addr = %node_addr,
                retry = state.retry_count,
                delay_secs = delay / 1000,
                "Scheduling connection retry"
            );
        } else {
            // First failure — find the matching PeerConfig
            let peer_config = self
                .config
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
                let delay = state.backoff_ms(base_interval_ms, max_backoff_ms);
                state.retry_after_ms = now_ms + delay;
                debug!(
                    node_addr = %node_addr,
                    delay_secs = delay / 1000,
                    "First connection attempt failed, scheduling retry"
                );
                self.retry_pending.insert(node_addr, state);
            }
            // If not found in auto_connect_peers, no retry (one-shot connection)
        }
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

        // Collect retries that are due
        let due: Vec<NodeAddr> = self
            .retry_pending
            .iter()
            .filter(|(_, state)| now_ms >= state.retry_after_ms)
            .map(|(addr, _)| *addr)
            .collect();

        for node_addr in due {
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
                node_addr = %node_addr,
                retry = state.retry_count,
                "Attempting connection retry"
            );

            let peer_config = state.peer_config.clone();

            match self.initiate_peer_connection(&peer_config).await {
                Ok(()) => {
                    debug!(
                        node_addr = %node_addr,
                        "Retry connection initiated"
                    );
                    // Don't remove from retry_pending — wait for promotion
                    // (success) or next timeout (failure triggers schedule_retry again)
                }
                Err(e) => {
                    warn!(
                        node_addr = %node_addr,
                        error = %e,
                        "Retry connection initiation failed"
                    );
                    // Immediate failure counts as an attempt — schedule next retry
                    self.schedule_retry(node_addr, now_ms);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;

    const TEST_MAX_BACKOFF_MS: u64 = 300_000;

    #[test]
    fn test_backoff_exponential() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 0,
            retry_after_ms: 0,
        };
        // base = 5000ms
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 5000); // 5s * 2^0

        let state = RetryState {
            retry_count: 1,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 10_000); // 5s * 2^1

        let state = RetryState {
            retry_count: 2,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 20_000); // 5s * 2^2

        let state = RetryState {
            retry_count: 3,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 40_000); // 5s * 2^3

        let state = RetryState {
            retry_count: 4,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 80_000); // 5s * 2^4
    }

    #[test]
    fn test_backoff_cap() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 20, // 2^20 * 5000 would be huge
            retry_after_ms: 0,
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), TEST_MAX_BACKOFF_MS);
    }

    #[test]
    fn test_backoff_zero_base() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 3,
            retry_after_ms: 0,
        };
        assert_eq!(state.backoff_ms(0, TEST_MAX_BACKOFF_MS), 0);
    }
}
