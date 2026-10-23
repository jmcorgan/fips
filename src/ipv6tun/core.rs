//! The adapter's own copy of what the node tells it over the link.
//!
//! The node publishes payload limits: the largest FSP payload it sends to any
//! peer, and per peer where it has learned a narrower path. The adapter turns
//! them into IPv6 terms with its own shim arithmetic and keeps the results
//! where its TUN threads read them per packet. Nothing here reads node state;
//! it changes only when a [`FromMesh`] message is applied.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, RwLock};

use super::icmp::effective_ipv6_mtu;
use super::ipv6_shim::HEADER_SAVING;
use super::link::{FromMesh, MeshLink};
use super::tun::{IPV6_MIN_MTU, MssCeiling};
use crate::Ipv6Address;

/// Per-peer payload limits keyed by the peer's IPv6 address, as the TUN
/// threads look them up from a packet's address bytes.
pub(crate) type PathMtuReplica = Arc<RwLock<HashMap<Ipv6Address, u16>>>;

/// The largest IPv6 packet a payload limit admits: the shim compresses a
/// 40-byte IPv6 header to [`HEADER_SAVING`] bytes fewer.
pub(crate) fn ipv6_mtu(payload_limit: u16) -> u16 {
    payload_limit.saturating_add(HEADER_SAVING)
}

/// The largest TCP segment a payload limit admits: its IPv6 MTU less the
/// 40-byte IPv6 and 20-byte TCP headers. Zero when not one payload byte fits.
pub(crate) fn tcp_mss(payload_limit: u16) -> u16 {
    ipv6_mtu(payload_limit)
        .saturating_sub(40)
        .saturating_sub(20)
}

/// What applying a message leaves for the caller to act on.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// The node attached us; this is our own IPv6 address.
    Attached(Ipv6Addr),
    /// The replay that followed the attach is complete.
    Synced,
    /// A state push was applied; nothing else to do.
    State,
}

/// The adapter's copy of the node's payload limits, shared between the task
/// that applies the node's messages and the TUN threads that read them per
/// packet. Cloning shares the same state.
#[derive(Clone)]
pub(crate) struct MeshState {
    /// The node-wide payload limit last applied.
    node_limit: Arc<AtomicU16>,
    /// The TCP MSS ceiling derived from `node_limit`.
    ceiling: MssCeiling,
    /// Per-peer payload limits.
    paths: PathMtuReplica,
}

impl MeshState {
    /// State before any attach: no per-peer limits, and the limit of the
    /// IPv6 minimum MTU, which is where the clamp starts before any
    /// transport has bound.
    pub(crate) fn new() -> Self {
        let seed = effective_ipv6_mtu(IPV6_MIN_MTU).saturating_sub(HEADER_SAVING);
        Self {
            node_limit: Arc::new(AtomicU16::new(seed)),
            ceiling: Arc::new(AtomicU16::new(tcp_mss(seed))),
            paths: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Apply one message from the node.
    pub(crate) fn apply(&self, message: FromMesh) -> Applied {
        match message {
            FromMesh::Attached {
                node,
                payload_limit,
            } => {
                // An attach replays the per-peer limits in full, so anything
                // held from an earlier attach is dropped first.
                if let Ok(mut paths) = self.paths.write() {
                    paths.clear();
                }
                self.set_limit(payload_limit);
                return Applied::Attached(node.address().to_ipv6());
            }
            FromMesh::Synced => return Applied::Synced,
            FromMesh::NodeMtu { payload_limit } => self.set_limit(payload_limit),
            FromMesh::PathMtu {
                peer,
                payload_limit,
            } => {
                let addr = peer.address();
                // A poisoned lock means a TUN thread panicked holding it; the
                // TUN is then down and nothing reads the map.
                if let Ok(mut paths) = self.paths.write() {
                    match payload_limit {
                        Some(limit) => paths.insert(addr, limit),
                        None => paths.remove(&addr),
                    };
                }
            }
        }
        Applied::State
    }

    /// Record the node-wide limit and the ceiling derived from it.
    fn set_limit(&self, payload_limit: u16) {
        self.node_limit.store(payload_limit, Ordering::Relaxed);
        self.ceiling
            .store(tcp_mss(payload_limit), Ordering::Relaxed);
    }

    /// The node-wide IPv6 MTU last applied.
    pub(crate) fn ipv6_mtu(&self) -> u16 {
        ipv6_mtu(self.node_limit.load(Ordering::Relaxed))
    }

    /// The shared TCP MSS ceiling, for the TUN threads.
    pub(crate) fn ceiling(&self) -> MssCeiling {
        self.ceiling.clone()
    }

    /// The shared per-peer limits, for the TUN threads.
    pub(crate) fn paths(&self) -> PathMtuReplica {
        self.paths.clone()
    }
}

/// Apply the node's messages until the link closes, which is how the node
/// ends it.
pub(crate) async fn run_link(mut link: MeshLink, state: MeshState) {
    while let Some(message) = link.from_mesh.recv().await {
        state.apply(message);
    }
}

#[cfg(test)]
#[path = "tests/core.rs"]
mod tests;
