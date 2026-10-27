//! The adapter's own copy of what the node tells it over the link.
//!
//! The node publishes payload limits: the largest FSP payload it sends to any
//! peer, and per peer where it has learned a narrower path. The adapter turns
//! them into IPv6 terms with the shim arithmetic in `mtu.rs` and keeps the
//! results where its TUN threads read them per packet. It also keeps the keys
//! the node can route to, by the address prefix a host packet names them
//! with, together with the keys its own DNS responder handed out, and the
//! address of each such key, which names the source of what that peer
//! delivers. Nothing here reads node state; it changes only when a
//! [`FromMesh`] message is applied or the DNS responder learns a key.

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, RwLock};

use super::link::{FromMesh, Learned, PeerKey};
use super::mss::{IPV6_MIN_MTU, MssCeiling};
use super::mtu::{ipv6_mtu, tcp_mss};
use crate::Ipv6Address;
use crate::proto::framing::payload_limit;
use fips_core::identity::NodePrefix;

/// Per-peer payload limits keyed by the peer's IPv6 address, as the TUN
/// threads look them up from a packet's address bytes.
pub(crate) type PathMtuReplica = Arc<RwLock<HashMap<Ipv6Address, u16>>>;

/// A key the adapter can name a destination by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Known {
    /// The destination's key.
    peer: PeerKey,
    /// The number of the last report of this key the DNS responder made,
    /// or 0 if it made none.
    learned: u64,
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
    /// The keys destinations are named by, by prefix.
    keys: Arc<RwLock<HashMap<NodePrefix, Known>>>,
    /// The address of each key in `keys`, so a delivery from a peer the
    /// adapter knows names its source without hashing the key again.
    addresses: Arc<RwLock<HashMap<PeerKey, Ipv6Address>>>,
    /// The number of the last key the DNS responder learned.
    learned: Arc<AtomicU64>,
}

impl MeshState {
    /// State before any attach: no per-peer limits, and the payload limit of
    /// the IPv6 minimum MTU, which is where the clamp starts before any
    /// transport has bound and where the node's record of what it has
    /// published starts too.
    pub(crate) fn new() -> Self {
        let seed = payload_limit(IPV6_MIN_MTU);
        Self {
            node_limit: Arc::new(AtomicU16::new(seed)),
            ceiling: Arc::new(AtomicU16::new(tcp_mss(seed))),
            paths: Arc::new(RwLock::new(HashMap::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
            addresses: Arc::new(RwLock::new(HashMap::new())),
            learned: Arc::new(AtomicU64::new(0)),
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
                if let Ok(mut keys) = self.keys.write() {
                    keys.clear();
                }
                if let Ok(mut addresses) = self.addresses.write() {
                    addresses.clear();
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
            FromMesh::KnownKey { peer } => {
                // A poisoned lock means a thread panicked holding it; the
                // adapter is then going down.
                if let Ok(mut keys) = self.keys.write() {
                    let learned = keys
                        .get(&peer.addr().prefix())
                        .filter(|known| known.peer == peer)
                        .map_or(0, |known| known.learned);
                    let old = keys.insert(peer.addr().prefix(), Known { peer, learned });
                    self.addressed(peer, old.map(|known| known.peer));
                }
            }
            FromMesh::ForgotKey { peer, learned } => {
                if let Ok(mut keys) = self.keys.write() {
                    let prefix = peer.addr().prefix();
                    // A key the DNS responder handed out after the node
                    // decided this is the host's to use, and stays.
                    if keys
                        .get(&prefix)
                        .is_some_and(|known| known.peer == peer && known.learned <= learned)
                    {
                        keys.remove(&prefix);
                        if let Ok(mut addresses) = self.addresses.write() {
                            addresses.remove(&peer);
                        }
                    }
                }
            }
        }
        Applied::State
    }

    /// Record that the DNS responder handed `peer`'s address to the host,
    /// so the host's packets to it are forwarded from now on, and return
    /// the report for the node.
    pub(crate) fn learn(&self, peer: PeerKey) -> Learned {
        let seq = self.learned.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut keys) = self.keys.write() {
            let old = keys.insert(peer.addr().prefix(), Known { peer, learned: seq });
            self.addressed(peer, old.map(|known| known.peer));
        }
        Learned { peer, seq }
    }

    /// Record `peer`'s address, now that it names the prefix `replaced`
    /// held, and drop the address of `replaced` if that was another key.
    fn addressed(&self, peer: PeerKey, replaced: Option<PeerKey>) {
        if let Ok(mut addresses) = self.addresses.write() {
            if let Some(old) = replaced.filter(|old| *old != peer) {
                addresses.remove(&old);
            }
            addresses.entry(peer).or_insert_with(|| peer.address());
        }
    }

    /// The address of `peer`: from the map for a key the adapter holds,
    /// hashed from the key otherwise.
    pub(crate) fn address(&self, peer: &PeerKey) -> Ipv6Address {
        self.addresses
            .read()
            .ok()
            .and_then(|addresses| addresses.get(peer).copied())
            .unwrap_or_else(|| peer.address())
    }

    /// Number a report of `peer` for the node without recording it, for an
    /// adapter that holds no key map (no identity feed).
    pub(crate) fn report(&self, peer: PeerKey) -> Learned {
        let seq = self.learned.fetch_add(1, Ordering::Relaxed) + 1;
        Learned { peer, seq }
    }

    /// The key a destination with address prefix `prefix` is named by.
    pub(crate) fn key(&self, prefix: &NodePrefix) -> Option<PeerKey> {
        self.keys.read().ok()?.get(prefix).map(|known| known.peer)
    }

    /// Every key the adapter holds, for tests.
    #[cfg(test)]
    pub(crate) fn keys(&self) -> Vec<PeerKey> {
        self.keys
            .read()
            .map(|keys| keys.values().map(|known| known.peer).collect())
            .unwrap_or_default()
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

#[cfg(test)]
#[path = "tests/core.rs"]
mod tests;
