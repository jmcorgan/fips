//! The per-peer maps other than the link table: the handshake machines with
//! their timers, the pending dials, the active peers and the session-index
//! map.

use std::collections::HashMap;

use crate::NodeAddr;
use crate::peer::ActivePeer;
use crate::peer::machine::{PeerMachine, TimerKind};
use crate::transport::{LinkId, TransportId};

/// The per-peer control machines, keyed by the `LinkId` that spans a peer's
/// handshake and active life, with each machine's timer store.
///
/// The two share a lifetime: a machine's timers are dropped with it, so no
/// armed timer outlives its machine. The machines are reached by `Deref` for
/// reads, and by `get_mut` for a change to a machine that leaves the map as it
/// is.
#[derive(Default)]
pub(in crate::node) struct MachineMap {
    machines: HashMap<LinkId, PeerMachine>,
    timers: HashMap<LinkId, HashMap<TimerKind, u64>>,
    #[cfg(test)]
    planted: bool,
}

reads!(MachineMap, machines, HashMap<LinkId, PeerMachine>);

impl MachineMap {
    /// A machine born at a dial or an inbound msg1, replacing any machine
    /// the link had.
    pub(in crate::node) fn add(&mut self, link: LinkId, machine: PeerMachine) {
        self.machines.insert(link, machine);
    }

    /// The link's machine, made by `make` if the link has none.
    pub(in crate::node) fn ensure(
        &mut self,
        link: LinkId,
        make: impl FnOnce() -> PeerMachine,
    ) -> &mut PeerMachine {
        self.machines.entry(link).or_insert_with(make)
    }

    /// The machine of the link `from` now controls the link `to`, onto which
    /// its peer moved: the machine and its timers are keyed under `to`.
    pub(in crate::node) fn rekey(&mut self, from: LinkId, to: LinkId) {
        if let Some(mut machine) = self.machines.remove(&from) {
            machine.relink(to);
            self.machines.insert(to, machine);
        }
        if let Some(timers) = self.timers.remove(&from) {
            self.timers.insert(to, timers);
        }
    }

    /// Drop the link's machine and its timers.
    pub(in crate::node) fn drop(&mut self, link: LinkId) {
        self.machines.remove(&link);
        self.timers.remove(&link);
    }

    /// The link's machine, to step or update.
    pub(in crate::node) fn get_mut(&mut self, link: &LinkId) -> Option<&mut PeerMachine> {
        self.machines.get_mut(link)
    }

    /// The timer store: each link's armed timers and their deadlines (ms).
    pub(in crate::node) fn timers(&self) -> &HashMap<LinkId, HashMap<TimerKind, u64>> {
        &self.timers
    }

    /// Arm the link's timer of `kind` for `at` (ms), replacing its deadline
    /// if it was armed.
    pub(in crate::node) fn arm(&mut self, link: LinkId, kind: TimerKind, at: u64) {
        self.timers.entry(link).or_default().insert(kind, at);
    }

    /// Disarm the link's timer of `kind`. The link keeps its store, empty or
    /// not.
    pub(in crate::node) fn cancel(&mut self, link: LinkId, kind: TimerKind) {
        if let Some(timers) = self.timers.get_mut(&link) {
            timers.remove(&kind);
        }
    }

    /// The timer store, for a test that writes it itself. Marks the map
    /// planted.
    #[cfg(test)]
    pub(in crate::node) fn raw_timers(&mut self) -> &mut HashMap<LinkId, HashMap<TimerKind, u64>> {
        self.planted = true;
        &mut self.timers
    }
}

/// The dials waiting for their msg2, keyed by the transport and the session
/// index our msg1 carried, naming the dial's link.
#[derive(Default)]
pub(in crate::node) struct DialMap {
    dials: HashMap<(TransportId, u32), LinkId>,
    #[cfg(test)]
    planted: bool,
}

reads!(DialMap, dials, HashMap<(TransportId, u32), LinkId>);

impl DialMap {
    /// A msg1 sent for the dial on `link`: its msg2 is looked up at `key`.
    pub(in crate::node) fn note(&mut self, key: (TransportId, u32), link: LinkId) {
        self.dials.insert(key, link);
    }

    /// The dial at `key` is over, or its entry stale.
    pub(in crate::node) fn forget(&mut self, key: &(TransportId, u32)) {
        self.dials.remove(key);
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
