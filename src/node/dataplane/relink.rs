//! Telling the transports which link carries an active peer, which BLE
//! reads to decide which of its connections a node's claimed key was proven
//! on.

use crate::identity::NodeAddr;
use crate::node::Node;
use crate::transport::{TransportAddr, TransportId};

impl Node {
    /// The transport and address the active peer `node` sends over.
    pub(in crate::node) fn peer_link(
        &self,
        node: &NodeAddr,
    ) -> Option<(TransportId, TransportAddr)> {
        let peer = self.peers.get(node)?;
        Some((peer.transport_id()?, peer.current_addr()?.clone()))
    }

    /// Tell the transports that the active peer `node` moved from `old` to
    /// `new`: the old connection no longer carries it, the new one does. With
    /// no `new`, the peer was removed.
    ///
    /// BLE uses this to decide which of its connections a node's claimed key
    /// was proven on; every other transport ignores it.
    ///
    /// The new link is marked before the old one is cleared. Each is a
    /// separate turn of the transport's lock, and a newcomer waiting on that
    /// lock in between must not find the peer with no verified link: it
    /// would be admitted as the peer, or could evict the link the peer is
    /// moving onto. Within one transport the mark already demotes the old
    /// link; across transports the two links are in different pools.
    pub(in crate::node) async fn relink(
        &self,
        node: &NodeAddr,
        old: Option<(TransportId, TransportAddr)>,
        new: Option<(TransportId, TransportAddr)>,
    ) {
        // The mutation lane's break: the old link is cleared first.
        if node_fault!(RelinkClearsFirst) {
            if let Some((tid, addr)) = &old
                && old != new
                && let Some(transport) = self.transports.get(tid)
            {
                transport.clear_verified(addr, node, new.is_none()).await;
            }
            if let Some((tid, addr)) = &new
                && let Some(transport) = self.transports.get(tid)
            {
                transport.mark_verified(addr, node).await;
            }
            return;
        }
        if let Some((tid, addr)) = &new
            && let Some(transport) = self.transports.get(tid)
        {
            transport.mark_verified(addr, node).await;
        }
        if let Some((tid, addr)) = &old
            && old != new
            && let Some(transport) = self.transports.get(tid)
        {
            transport.clear_verified(addr, node, new.is_none()).await;
        }
    }

    /// Whether `transport` needs to hear of every authenticated frame's link.
    pub(in crate::node) fn tracks_peers(&self, transport: TransportId) -> bool {
        self.transports
            .get(&transport)
            .is_some_and(|t| t.tracks_peers())
    }
}
