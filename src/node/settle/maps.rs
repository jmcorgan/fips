//! The per-peer maps other than the link table: the handshakes in flight,
//! the active peers and the session-index map. The handshake legs are the
//! settlement core's (`Node.core`'s legs).

use std::collections::HashMap;

use crate::NodeAddr;
use crate::peer::ActivePeer;
use crate::peer::handshake::Handshake;
use crate::transport::LinkId;
use crate::utils::index::SessionIndex;

/// The node's entries for the handshakes in flight, keyed by the `LinkId` of
/// each handshake's link: what the settlement core's leg for the link does
/// not hold (the Noise crypto, the bookkeeping the promotion and the control
/// API read, the dial's origin).
///
/// An entry is added at a dial or at the answer of a msg1, and dropped when
/// its handshake is promoted, given up or reaped. Entries are reached by
/// `Deref` for reads, and by `get_mut` for a change to an entry that leaves
/// the map as it is.
#[derive(Default)]
pub(in crate::node) struct HandshakeMap {
    entries: HashMap<LinkId, Handshake>,
    #[cfg(test)]
    planted: bool,
}

reads!(HandshakeMap, entries, HashMap<LinkId, Handshake>);

impl HandshakeMap {
    /// A handshake begun at a dial or an answered msg1, replacing any entry
    /// the link had.
    pub(in crate::node) fn add(&mut self, link: LinkId, entry: Handshake) {
        self.entries.insert(link, entry);
    }

    /// The link's entry, made by `make` if the link has none.
    pub(in crate::node) fn ensure(
        &mut self,
        link: LinkId,
        make: impl FnOnce() -> Handshake,
    ) -> &mut Handshake {
        self.entries.entry(link).or_insert_with(make)
    }

    /// Drop the link's entry.
    pub(in crate::node) fn drop(&mut self, link: LinkId) {
        self.entries.remove(&link);
    }

    /// The link's entry, to update.
    pub(in crate::node) fn get_mut(&mut self, link: &LinkId) -> Option<&mut Handshake> {
        self.entries.get_mut(link)
    }
}

/// The authenticated peers, keyed by their verified address.
///
/// Read by `Deref`; a change to a peer that leaves the map as it is goes
/// through `get_mut`, `values_mut` or `iter_mut`.
#[derive(Default)]
pub(in crate::node) struct PeerMap {
    peers: HashMap<NodeAddr, ActivePeer>,
    #[cfg(test)]
    planted: bool,
}

reads!(PeerMap, peers, HashMap<NodeAddr, ActivePeer>);

impl PeerMap {
    /// A promotion's new peer, replacing any peer held at `addr`.
    pub(in crate::node) fn install(&mut self, addr: NodeAddr, peer: ActivePeer) {
        self.peers.insert(addr, peer);
    }

    /// The peer at `addr`, taken out of the map.
    pub(in crate::node) fn take(&mut self, addr: &NodeAddr) -> Option<ActivePeer> {
        self.peers.remove(addr)
    }

    /// The peer at `addr`, to update.
    pub(in crate::node) fn get_mut(&mut self, addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.peers.get_mut(addr)
    }

    /// Every peer, to update in place.
    pub(in crate::node) fn values_mut(
        &mut self,
    ) -> std::collections::hash_map::ValuesMut<'_, NodeAddr, ActivePeer> {
        self.peers.values_mut()
    }

    /// Every peer with its address, to update in place.
    pub(in crate::node) fn iter_mut(
        &mut self,
    ) -> std::collections::hash_map::IterMut<'_, NodeAddr, ActivePeer> {
        self.peers.iter_mut()
    }
}

/// Our session indices, each naming the peer whose session uses it. Keyed by
/// the index alone: indices come from one allocator, so a frame naming a
/// bound index finds its peer whichever transport delivered it.
#[derive(Default)]
pub(in crate::node) struct BindMap {
    indices: HashMap<u32, NodeAddr>,
    #[cfg(test)]
    planted: bool,
}

reads!(BindMap, indices, HashMap<u32, NodeAddr>);

impl BindMap {
    /// A link output bound `index` to the peer at `addr`.
    pub(in crate::node) fn bind(&mut self, index: u32, addr: NodeAddr) {
        self.indices.insert(index, addr);
    }

    /// `index` names no peer any more: a link output unbound it, or its peer
    /// is gone.
    pub(in crate::node) fn unbind(&mut self, index: &u32) {
        self.indices.remove(index);
    }
}

/// One pending redial: the inbound link its leg runs on, and the index the
/// leg's msg2 named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) struct Redial {
    pub(in crate::node) link: LinkId,
    pub(in crate::node) index: SessionIndex,
}

/// The pending redials, at most one per held identity: a cache of the
/// settlement core's, by the node's link and the index each leg's msg2
/// named, rebuilt after every step of the core.
///
/// A redial is a fresh same-epoch msg1 that arrived off a held peer's
/// established link. It is answered by a leg on its own inbound link,
/// beside the held peering, and replaces the peering only when the peer's
/// first frame authenticates under the leg's session. The core marks the
/// redial when its answer is built and forgets it when the leg is promoted,
/// reaped or replaced; the audit's `redial-leg` clause holds each of the
/// core's marks to a leg.
///
/// The memory of the ephemerals that armed a redial is the restart gates'
/// (`Node.core`'s): per identity, the ephemerals of the last 15 s, so a
/// capture is answered once per interval, kept apart from the replay memory
/// of unheard promotions, which a frame forgets, and forgotten only at the
/// identity's swap.
#[derive(Debug, Default)]
pub(in crate::node) struct RedialMap {
    by_peer: HashMap<NodeAddr, Redial>,
}

impl RedialMap {
    /// Rebuild the cache from the core's pending redials, `pending`, each
    /// an identity and its leg's link, where the node names that link
    /// `id`, and the leg there holds a lease of index `index`. A mark whose
    /// link or leg is gone is left out.
    pub(in crate::node) fn rebuild(
        &mut self,
        pending: impl Iterator<Item = (NodeAddr, Option<LinkId>, Option<u32>)>,
    ) {
        self.by_peer = pending
            .filter_map(|(peer, link, index)| {
                Some((
                    peer,
                    Redial {
                        link: link?,
                        index: SessionIndex::new(index?),
                    },
                ))
            })
            .collect();
    }

    /// The pending redial of `peer`.
    pub(in crate::node) fn of(&self, peer: &NodeAddr) -> Option<Redial> {
        self.by_peer.get(peer).copied()
    }

    /// The identity and redial whose leg's msg2 named `index`.
    pub(in crate::node) fn by_index(&self, index: u32) -> Option<(NodeAddr, Redial)> {
        self.by_peer
            .iter()
            .find(|(_, r)| r.index.as_u32() == index)
            .map(|(peer, r)| (*peer, *r))
    }

    /// Every pending redial.
    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &Redial)> {
        self.by_peer.iter()
    }
}
