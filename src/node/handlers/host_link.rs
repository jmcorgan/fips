//! The node's end of the link to the IPv6 adapter.
//!
//! The adapter attaches once per start, before its device opens, and the
//! node answers in line: who it is, the payload limit it last published, the
//! replay of every per-peer limit the adapter asked for, and the end of the
//! replay. From then on the node pushes the node-wide limit whenever it moves
//! and each per-peer change as the path MTU map makes it. The link ends at
//! the teardown step that drops the packet channels.

use std::sync::atomic::{AtomicU16, Ordering};

use crate::ipv6tun::icmp::mss_ceiling;
use crate::ipv6tun::link::{self, Attach, FromMesh, PeerKey};
use crate::ipv6tun::tun::IPV6_MIN_MTU;
use crate::node::Node;
use crate::node::path_mtu::payload_limit;

/// What the node has published of its node-wide limit, and the ceiling it
/// last logged at a transport change.
pub(crate) struct NodeMtuFeed {
    /// The payload limit last pushed, or the one `Attached` will carry.
    published: AtomicU16,
    /// The TCP MSS ceiling last logged at a transport change.
    logged: AtomicU16,
}

impl NodeMtuFeed {
    /// Both values at the IPv6 minimum, which is what `transport_mtu()`
    /// falls back to when nothing is bound.
    pub(crate) fn new() -> Self {
        Self {
            published: AtomicU16::new(payload_limit(IPV6_MIN_MTU)),
            logged: AtomicU16::new(mss_ceiling(IPV6_MIN_MTU)),
        }
    }

    /// Swap in the TCP MSS ceiling `ceiling`, returning the one last logged.
    pub(crate) fn swap_logged(&self, ceiling: u16) -> u16 {
        self.logged.swap(ceiling, Ordering::Relaxed)
    }

    /// The TCP MSS ceiling last logged.
    #[cfg(test)]
    pub(crate) fn logged(&self) -> u16 {
        self.logged.load(Ordering::Relaxed)
    }
}

impl Node {
    /// Attach the IPv6 adapter: take its request, answer it, and hand it its
    /// end of the link with the answer already queued.
    ///
    /// Runs inside `start()`, where the receive loop is not yet running, so
    /// the adapter has the whole reply before its device opens.
    pub(in crate::node) fn attach_host(&mut self) {
        let Attach { port, feeds } = self.supervisor.ipv6tun.attach_request();
        // Port 256 is the adapter's by construction; nothing else can ask.
        debug_assert!(port.is_none_or(|p| p == link::IPV6_PORT));
        let (mesh_link, host_link) = link::pair();
        host_link.send(FromMesh::Attached {
            node: PeerKey::new(self.identity().pubkey()),
            payload_limit: self.node_mtu.published.load(Ordering::Relaxed),
        });
        if feeds.path_mtu
            && let Ok(mut map) = self.path_mtu_lookup.write()
        {
            map.attach(host_link.clone());
        }
        host_link.send(FromMesh::Synced);
        self.supervisor.host_link = Some(host_link);
        self.supervisor.ipv6tun.attached(mesh_link);
    }

    /// End the link and wait for the adapter to apply what was still queued
    /// on it: its receiver closes once both senders go.
    pub(in crate::node) async fn detach_host(&mut self) {
        self.supervisor.host_link = None;
        // The map's sender must go even if a writer panicked holding the
        // lock, or the adapter's task would never see the link close.
        self.path_mtu_lookup
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .detach();
        self.supervisor.ipv6tun.detached().await;
    }

    /// Push the node-wide payload limit if it differs from the last one
    /// published.
    ///
    /// Called on every tick as well as at each transport change, so the
    /// adapter's copy is at most one tick behind even where no transport
    /// change was seen.
    pub(in crate::node) fn publish_mtu(&self) {
        let limit = self.native_max_payload();
        if self.node_mtu.published.swap(limit, Ordering::Relaxed) != limit
            && let Some(host_link) = &self.supervisor.host_link
        {
            host_link.send(FromMesh::NodeMtu {
                payload_limit: limit,
            });
        }
    }
}
