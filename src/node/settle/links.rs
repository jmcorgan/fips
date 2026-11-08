//! The link table: the node's links and the address index over them.

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(any(test, debug_assertions))]
use std::collections::HashSet;

use crate::node::AddrKey;
use crate::transport::{Link, LinkId};

/// Why a link is let off a clause of the audit: a state the node makes today
/// that the clause would otherwise call a breach. Each is recorded by the code
/// that makes the state, at the event, on the link it concerns, and dropped
/// with the link. In test and debug builds only.
#[cfg(any(test, debug_assertions))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(in crate::node) enum Waiver {
    /// After crossed dials the node moved to its own outbound session but
    /// kept the inbound link it promoted the peer on, off the pair it moved
    /// to. The link keeps its entry, so this waives no live clause: it answers
    /// the quiescent audit's check that a passed exemption was recorded.
    /// Removed when a crossing moves the node onto the link it dialed.
    CrossedInbound,
    /// The node's own later dial to a held peer completed and moved the
    /// session onto it, keeping the link the peer was promoted on, off the
    /// pair it moved to. As with `CrossedInbound`, it waives no live clause.
    /// Removed when that move re-keys the peer's link record to the dial's
    /// link.
    MovedOwnDial,
    /// The live audit's `held-entry` clause lets this one off. A later dial to the held link's own pair overwrote the link's entry,
    /// and closing or abandoning the dial's link took the entry with it.
    /// Removed when retiring the dial's link leaves the held link's entry in
    /// place.
    HeldLinkEntry,
    /// Crossed dials settled at msg3 moved the larger node's session onto the
    /// msg3's pair and kept the link it dialed as the peer's record, off that
    /// pair. Waives no live clause: it answers the quiescent audit's check
    /// that a passed exemption was recorded. Removed when that move re-keys
    /// the record.
    SettledAtMsg3,
}

/// The node's links, keyed by `LinkId`, and the index from a
/// `(transport, address)` pair to the link at it.
///
/// The index is a reverse lookup from `(transport, address)` to link. It is
/// **not** a packet-dispatch path: `find_link_by_addr` has no callers outside
/// its own tests, and encrypted frames are dispatched by session index. Its
/// live readers are the `should_admit_msg1` fast path, the
/// duplicate-inbound-handshake check in `handle_msg1`, and the
/// anonymous-beacon dial dedup in `poll_transport_discovery`.
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
/// An inbound handshake that overwrites a key records the link it displaced,
/// and the key returns to that link, if it is still live, when the handshake's
/// leg is closed.
#[derive(Default)]
pub(in crate::node) struct LinkTable {
    links: HashMap<LinkId, Link>,
    index: HashMap<AddrKey, LinkId>,
    /// For an inbound handshake leg that took over a key at msg1, the key and
    /// the link it named before. `close` hands the key back to that link, if
    /// it is still live, when the leg goes.
    displaced: HashMap<LinkId, (AddrKey, LinkId)>,
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
    pub(in crate::node) fn open(&mut self, link: Link) {
        let id = link.link_id();
        let key = (link.transport_id(), link.remote_addr().clone());
        self.links.insert(id, link);
        self.index.insert(key, id);
    }

    /// An inbound handshake's msg1: the leg's link is added and its pair names
    /// it, as `open` does, and the link the pair named before is recorded for
    /// `close` to hand the pair back to.
    pub(in crate::node) fn open_leg(&mut self, link: Link) {
        let id = link.link_id();
        let key = (link.transport_id(), link.remote_addr().clone());
        self.links.insert(id, link);
        if let Some(prior) = self.index.insert(key.clone(), id) {
            self.displaced.insert(id, (key, prior));
        }
    }

    /// A crossing's loser has been closed: `key` names the winner, whatever
    /// it named before.
    pub(in crate::node) fn award(&mut self, key: AddrKey, winner: LinkId) {
        self.index.insert(key, winner);
    }

    /// The link is closed: it is taken out, with every index entry that
    /// names it. Entries another link has claimed are left alone. A leg that
    /// took a key at msg1 hands it back to the link it displaced, if that link
    /// is still live and nothing has claimed the key since, and a newer leg
    /// that displaced this one now displaces that link instead.
    pub(in crate::node) fn close(&mut self, id: &LinkId) -> Option<Link> {
        let displaced = self.displaced.remove(id);
        let link = self.links.remove(id)?;
        #[cfg(any(test, debug_assertions))]
        let taken: Vec<AddrKey> = self
            .index
            .iter()
            .filter(|(_, mapped)| **mapped == *id)
            .map(|(key, _)| key.clone())
            .collect();
        self.index.retain(|_, mapped| *mapped != *id);
        if let Some((key, prior)) = displaced {
            // A newer leg at the same address displaced this one; it now
            // displaces what this one did, or its disposal would find a dead
            // link and drop the key from a link that is still live.
            for (newer_key, newer_prior) in self.displaced.values_mut() {
                if *newer_prior == *id && *newer_key == key {
                    *newer_prior = prior;
                }
            }
            if self.links.contains_key(&prior) {
                self.index.entry(key).or_insert(prior);
            }
        }
        #[cfg(any(test, debug_assertions))]
        {
            self.waivers.remove(id);
            for key in &taken {
                if !self.index.contains_key(key) {
                    self.shadowed(key);
                }
            }
        }
        Some(link)
    }

    /// A dial is abandoned: its link is dropped, and so is the index entry
    /// at `key`, whichever link that entry names.
    pub(in crate::node) fn forget(&mut self, id: &LinkId, key: &AddrKey) {
        self.links.remove(id);
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

    /// The link, to update.
    pub(in crate::node) fn get_mut(&mut self, id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(id)
    }

    /// The legs that hold a record of the link they displaced.
    #[cfg(debug_assertions)]
    pub(in crate::node) fn displaced(&self) -> impl Iterator<Item = &LinkId> {
        self.displaced.keys()
    }

    /// The link `leg` displaced at msg1 and would hand its key back to.
    #[cfg(test)]
    pub(in crate::node) fn prior(&self, leg: &LinkId) -> Option<LinkId> {
        self.displaced.get(leg).map(|(_, prior)| *prior)
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

    /// Whether the link `id` is let off `held-entry`.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn waived(&self, id: &LinkId) -> bool {
        self.carries(id, Waiver::HeldLinkEntry)
    }

    /// Whether the link `id` carries `waiver`.
    #[cfg(any(test, debug_assertions))]
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
