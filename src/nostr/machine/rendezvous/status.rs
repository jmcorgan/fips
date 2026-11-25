//! What the node reads of rendezvous without waiting: the per-peer failure
//! state, as of the last change to it. The shell keeps the latest
//! [`Status`] where the node's synchronous queries (the open-discovery
//! sweep's cooldown check, `show peers`) read it.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::traversal::failures::{FailureState, NpubFailureRecord};
use super::super::types::NostrPeerFailureView;

/// The rendezvous state the node reads synchronously.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// Each peer's failure record, by canonical npub.
    pub failures: BTreeMap<String, NpubFailureRecord>,
}

impl Status {
    /// The status `failures` gives.
    pub fn of(failures: &FailureState) -> Self {
        Self {
            failures: failures.snapshot().into_iter().collect(),
        }
    }

    /// When `npub`'s extended cooldown ends, if it is in one at `now_ms`.
    pub fn cooldown_until(&self, npub: &str, now_ms: u64) -> Option<u64> {
        self.failures
            .get(npub)
            .and_then(|record| record.cooldown_until_ms)
            .filter(|&until| until > now_ms)
    }

    /// One row per peer for `show peers`.
    pub fn failure_views(&self) -> Vec<NostrPeerFailureView> {
        self.failures
            .iter()
            .map(|(npub, record)| NostrPeerFailureView {
                npub: npub.clone(),
                consecutive_failures: record.consecutive_failures,
                cooldown_until_ms: record.cooldown_until_ms,
                last_observed_skew_ms: record.last_observed_skew_ms,
            })
            .collect()
    }
}
