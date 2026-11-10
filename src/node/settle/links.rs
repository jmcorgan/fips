//! The link table: the node's links and the address index over them.

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(any(test, debug_assertions))]
use std::collections::HashSet;

use crate::NodeAddr;
use crate::node::AddrKey;
use crate::proto::settle::input::Input;
use crate::proto::settle::links::{Dir, Holder, LinkNo, Links, Pair};
use crate::transport::{Link, LinkDirection, LinkId};

/// Why a link is let off the live audit's `held-entry` clause: a state the
/// node makes today that the clause would otherwise call a breach. Each is
/// recorded by the code that makes the state, at the event, on the link it
/// concerns, and dropped with the link. In test and debug builds only.
#[cfg(any(test, debug_assertions))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(in crate::node) enum Waiver {
    /// After crossed dials the node moved to its own outbound session but
    /// kept the inbound link it promoted the peer on, and the move's renewal
    /// of the link's paths released that link's only index entry. Removed
    /// when a crossing moves the node onto the link it dialed.
    CrossedInbound,
    /// The node's own later dial to a held peer completed and moved the
    /// session onto it, keeping the link the peer was promoted on, whose
    /// only index entry the move's renewal released. Removed when that move
    /// re-keys the peer's link record to the dial's link.
    MovedOwnDial,
    /// A later dial to the held link's own pair overwrote the link's entry,
    /// and closing or abandoning the dial's link took the entry with it.
    /// Removed when retiring the dial's link leaves the held link's entry in
    /// place.
    HeldLinkEntry,
}

/// The node's links, keyed by `LinkId`, and the index from a
/// `(transport, address)` pair to the link at it.
///
/// The index is a reverse lookup from `(transport, address)` to link. It is
/// **not** a packet-dispatch path: `find_link_by_addr` has no callers outside
/// its own tests, and encrypted frames are dispatched by session index. Its
/// live readers are the `should_admit_msg1` fast path and the
/// duplicate-inbound-handshake check in `handle_msg1`.
///
/// **Do not key a peer-identity question on it.** The address form is not
/// canonical: an outbound dial registers the literal configured string, which
/// may be a hostname (`"node-b:2121"`), while an inbound packet carries the
/// resolved form (`"10.128.2.4:2121"`). `TransportAddr` compares byte-wise, so
/// those never match, and a lookup keyed on an inbound address silently returns
/// "no such link" for every hostname-configured peer rather than failing. The
/// entry is also single-valued per key, so an inbound handshake overwrites an
/// outbound dial's entry for the same address. The readers above tolerate this
/// because each compares a key written in the same form it reads; a new reader
/// that does not will be quietly wrong.
///
/// The links are reached by `Deref` for reads, and by `get_mut` for a change
/// to a link that leaves the table as it is; the index by `index`. Every
/// write to either goes through a writer named for its event, and each writer
/// is the statements its sites wrote, so the index keeps its single-valued
/// keys and its gaps.
///
/// Beside them the table keeps the settlement core's link records
/// ([`Links`]), one for each link, under the core's number for it: opened
/// with the link, retired with it, held by the peer a promotion installs, and
/// fed what each link's bundle reports through the core's join. Nothing reads
/// the records to decide anything yet: the index and the close rule stay the
/// node's own, and the live audit holds the records to each held link's
/// bundle.
#[derive(Default)]
pub(in crate::node) struct LinkTable {
    links: HashMap<LinkId, Link>,
    index: HashMap<AddrKey, LinkId>,
    /// The settlement core's record of each link.
    core: Links,
    /// The core's number for each link.
    nos: HashMap<LinkId, LinkNo>,
    /// The waivers each link carries.
    #[cfg(any(test, debug_assertions))]
    waivers: HashMap<LinkId, HashSet<Waiver>>,
    #[cfg(test)]
    planted: bool,
    /// How many times the live audit has checked the node this table is in.
    #[cfg(test)]
    audits: Cell<u64>,
}

reads!(LinkTable, links, HashMap<LinkId, Link>);

impl LinkTable {
    /// A new link: the link is added, and its own pair in the index names
    /// it, whatever link the pair named before.
    /// The core records the link, set up at its pair, held by its
    /// handshake leg.
    pub(in crate::node) fn open(&mut self, link: Link) {
        let id = link.link_id();
        let key = (link.transport_id(), link.remote_addr().clone());
        let dir = match link.direction() {
            LinkDirection::Inbound => Dir::Inbound,
            LinkDirection::Outbound => Dir::Outbound,
        };
        let no = self.core.open(pair(&key), dir, Holder::Leg);
        self.nos.insert(id, no);
        self.links.insert(id, link);
        self.index.insert(key, id);
    }

    /// The link is closed: it is taken out, with every index entry that
    /// names it. Entries another link has claimed are left alone. The core's
    /// record of it is retired.
    pub(in crate::node) fn close(&mut self, id: &LinkId) -> Option<Link> {
        let link = self.links.remove(id)?;
        self.retire(id);
        #[cfg(any(test, debug_assertions))]
        let taken: Vec<AddrKey> = self
            .index
            .iter()
            .filter(|(_, mapped)| **mapped == *id)
            .map(|(key, _)| key.clone())
            .collect();
        self.index.retain(|_, mapped| *mapped != *id);
        #[cfg(any(test, debug_assertions))]
        {
            self.waivers.remove(id);
            for key in &taken {
                self.shadowed(key);
            }
        }
        Some(link)
    }

    /// A dial is abandoned: its link is dropped, and so is the index entry
    /// at `key`, whichever link that entry names. The core's record of the
    /// link is retired.
    pub(in crate::node) fn forget(&mut self, id: &LinkId, key: &AddrKey) {
        self.links.remove(id);
        self.retire(id);
        let taken = self.index.remove(key).is_some();
        #[cfg(any(test, debug_assertions))]
        {
            self.waivers.remove(id);
            if taken {
                self.shadowed(key);
            }
        }
        #[cfg(not(any(test, debug_assertions)))]
        let _ = taken;
    }

    /// The link's path moved from `from` to `to`. Only if `from` names the
    /// link is its entry dropped, and then `to` names the link unless
    /// another link holds it.
    pub(in crate::node) fn follow(&mut self, id: LinkId, from: &AddrKey, to: AddrKey) {
        if self.index.get(from) == Some(&id) {
            if !node_fault!(MovedLeavesEntry) {
                self.index.remove(from);
            }
            self.index.entry(to).or_insert(id);
        }
    }

    /// The link switched to a path at `to`, which names the link unless
    /// another link holds it.
    pub(in crate::node) fn claim(&mut self, id: LinkId, to: AddrKey) {
        self.index.entry(to).or_insert(id);
    }

    /// The link released its path at `key`, whose entry goes only if it
    /// names the link.
    pub(in crate::node) fn unclaim(&mut self, id: LinkId, key: &AddrKey) {
        if self.index.get(key) == Some(&id) {
            self.index.remove(key);
        }
    }

    /// Retire the core's record of the link `id`. The connections the core
    /// would close are the node's to close, by its own rule, until the core
    /// decides them.
    fn retire(&mut self, id: &LinkId) {
        if let Some(no) = self.nos.remove(id) {
            let _closes = self.core.retire(no);
        }
    }

    /// The core's number for the link `id`, while the link is open.
    pub(in crate::node) fn no(&self, id: &LinkId) -> Option<LinkNo> {
        self.nos.get(id).copied()
    }

    /// The core's link records.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn core(&self) -> &Links {
        &self.core
    }

    /// The link `id` is now held by the peer at `peer`.
    pub(in crate::node) fn hold(&mut self, id: &LinkId, peer: NodeAddr) {
        if let Some(no) = self.no(id) {
            self.core.hold(no, Holder::Peer(peer));
        }
    }

    /// Apply what a link's bundle reported, `input`, to the core's record of
    /// the link. The connections a released path leaves to close are the
    /// node's to close, by its own rule, until the core decides them.
    pub(in crate::node) fn mirror(&mut self, input: &Input) {
        let _closes = self.core.mirror(input);
    }

    /// The link, to update.
    pub(in crate::node) fn get_mut(&mut self, id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(id)
    }

    /// The index: each `(transport, address)` pair and the link it names.
    pub(in crate::node) fn index(&self) -> &HashMap<AddrKey, LinkId> {
        &self.index
    }

    /// The index, for a test that writes it itself. Marks the table
    /// planted.
    #[cfg(test)]
    pub(in crate::node) fn raw_index(&mut self) -> &mut HashMap<AddrKey, LinkId> {
        self.planted = true;
        &mut self.index
    }

    /// Record `waiver` on the link `id`.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn waive(&mut self, id: LinkId, waiver: Waiver) {
        self.waivers.entry(id).or_default().insert(waiver);
    }

    /// Whether the link `id` carries any waiver.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn waived(&self, id: &LinkId) -> bool {
        self.waivers.contains_key(id)
    }

    /// Whether the link `id` carries `waiver`.
    #[cfg(test)]
    pub(in crate::node) fn carries(&self, id: &LinkId, waiver: Waiver) -> bool {
        self.waivers
            .get(id)
            .is_some_and(|set| set.contains(&waiver))
    }

    /// The entry at `key` has just been taken from the index: every other
    /// live link set up at `key` was shadowed by it and is left with no
    /// entry at its own pair.
    #[cfg(any(test, debug_assertions))]
    fn shadowed(&mut self, key: &AddrKey) {
        let at: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.transport_id() == key.0 && link.remote_addr() == &key.1)
            .map(|(id, _)| *id)
            .collect();
        for id in at {
            self.waive(id, Waiver::HeldLinkEntry);
        }
    }

    /// Mark the table planted: the node it is in was built past its
    /// writers.
    #[cfg(test)]
    pub(in crate::node) fn plant(&mut self) {
        self.planted = true;
    }

    /// Put `key` in the index naming `id`, past the writers and without
    /// marking the table: the shape of a write that bypasses the table, for
    /// the test that the live audit catches one.
    #[cfg(test)]
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(in crate::node) fn plant_entry(&mut self, key: AddrKey, id: LinkId) {
        self.index.insert(key, id);
    }

    /// Write the core's record of the link `id` as holding a path at `key`
    /// in state `state`, past the feed and without marking the table: the
    /// shape of a record that differs from its bundle, for the test that the
    /// live audit catches one.
    #[cfg(test)]
    pub(in crate::node) fn plant_path(
        &mut self,
        id: &LinkId,
        key: &AddrKey,
        state: crate::proto::settle::links::Proven,
    ) {
        if let Some(no) = self.no(id) {
            self.core.path(no, pair(key), state);
        }
    }

    /// Count one live audit of the node this table is in.
    #[cfg(test)]
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(in crate::node) fn count_audit(&self) {
        self.audits.set(self.audits.get() + 1);
    }

    /// How many times the live audit has checked the node this table is in.
    #[cfg(test)]
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(in crate::node) fn audits(&self) -> u64 {
        self.audits.get()
    }
}

/// The core's pair for the index key `key`.
pub(in crate::node) fn pair(key: &AddrKey) -> Pair {
    Pair {
        transport: key.0,
        addr: key.1.clone(),
    }
}
