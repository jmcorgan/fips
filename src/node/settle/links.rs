//! The link table: the node's links and the address index over them.

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::collections::HashSet;
use std::collections::{BTreeSet, HashMap};

use crate::NodeAddr;
use crate::node::AddrKey;
use crate::proto::settle::input::Input;
use crate::proto::settle::links::{Dir, Holder, LinkNo, Links, Pair, Proven};
use crate::transport::{Link, LinkDirection, LinkId};

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
/// readers tolerate this because each compares a key written in the same form
/// it reads; a new reader that does not will be quietly wrong.
///
/// The index is derived from the settlement core's link records ([`Links`]),
/// one for each link, under the core's number for it: opened with the link,
/// retired with it, held by the peer a promotion installs, and fed what each
/// link's bundle reports through the core's join. It names each live link at
/// its setup pair and at each of its Live or acknowledged paths; a pair
/// several links use names the link with the newest number. Unlike the
/// core's own index, the setup pair stays named after the bundle releases
/// the path there: the link record's own pair names the link while it
/// lives, which the anonymous-beacon dedup reads. So an inbound leg that
/// takes a pair at msg1 names it while it lives, and the pair goes back to
/// the link it was named before once the leg is closed. The table keeps that as a cache, rebuilt by every
/// writer, since every change to the records goes through one: the records
/// are private to the table, and the feed reaches them through
/// [`LinkTable::mirror`] and [`LinkTable::hold`]. The live audit's
/// `index-cache` clause holds the cache to the records.
///
/// The links are reached by `Deref` for reads, and by `get_mut` for a change
/// to a link that leaves the table as it is; the index by `index`. Every
/// write to either goes through a writer named for its event.
#[derive(Default)]
pub(in crate::node) struct LinkTable {
    links: HashMap<LinkId, Link>,
    /// The index the records give, rebuilt at every writer.
    index: HashMap<AddrKey, LinkId>,
    /// The settlement core's record of each link.
    core: Links,
    /// The core's number for each link.
    nos: HashMap<LinkId, LinkNo>,
    #[cfg(test)]
    planted: bool,
    /// Entries a test wrote past the writers, put back at every rebuild.
    #[cfg(test)]
    overlay: HashMap<AddrKey, LinkId>,
    /// Pairs a mutation-lane switch took from the index, left empty until a
    /// writer names them again.
    #[cfg(test)]
    taken: HashSet<AddrKey>,
    /// How many times the live audit has checked the node this table is in.
    #[cfg(test)]
    audits: Cell<u64>,
}

reads!(LinkTable, links, HashMap<LinkId, Link>);

impl LinkTable {
    /// A new link: the link is added, and the core records it, set up at
    /// its pair and held by its handshake leg.
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
        #[cfg(test)]
        {
            self.taken.remove(&key);
            self.overlay.remove(&key);
        }
        self.rebuild();
    }

    /// The link is closed: it is taken out, and the core's record of it is
    /// retired, so the index names it nowhere.
    pub(in crate::node) fn close(&mut self, id: &LinkId) -> Option<Link> {
        let link = self.links.remove(id)?;
        #[cfg(test)]
        let named = self.named(id);
        self.retire(id);
        self.rebuild();
        // The mutation lane's break: the link's own pair and every pair it
        // was named at are taken from whichever link the index names there.
        #[cfg(test)]
        if node_fault!(ShadowLosesEntry) {
            self.taken
                .insert((link.transport_id(), link.remote_addr().clone()));
            self.taken.extend(named);
            self.rebuild();
        }
        Some(link)
    }

    /// A dial is abandoned: its link is dropped and the core's record of it
    /// retired, as at a close. `key` is the dial's pair, which another
    /// link may still name.
    pub(in crate::node) fn forget(&mut self, id: &LinkId, key: &AddrKey) {
        self.links.remove(id);
        self.retire(id);
        self.rebuild();
        // The mutation lane's break: the dial's pair is taken from whichever
        // link it named.
        #[cfg(test)]
        if node_fault!(ForgetTakesKey) {
            self.taken.insert(key.clone());
            self.rebuild();
        }
        #[cfg(not(test))]
        let _ = key;
    }

    /// The link's path moved. The core's record follows when the feed
    /// applies the move, so this only rebuilds the index.
    pub(in crate::node) fn follow(&mut self) {
        self.rebuild();
    }

    /// The link switched to a path at `to`, which its record holds Live.
    pub(in crate::node) fn claim(&mut self, id: LinkId, to: AddrKey) {
        if let Some(no) = self.no(&id) {
            self.core.path(no, pair(&to), Proven::Live);
        }
        #[cfg(test)]
        self.taken.remove(&to);
        self.rebuild();
    }

    /// The link released its path at `key`, which its record no longer
    /// holds. A released setup pair stays in the index while the link lives.
    pub(in crate::node) fn unclaim(&mut self, id: LinkId, key: &AddrKey) {
        if let Some(no) = self.no(&id) {
            let _closes = self.core.release(no, &pair(key), true);
        }
        #[cfg(test)]
        if self.overlay.get(key) == Some(&id) {
            self.overlay.remove(key);
        }
        self.rebuild();
    }

    /// Whether a live link other than `except` uses the connection at
    /// `key`. A link a peer holds uses each pair its bundle has proven,
    /// which `held` answers for it with `Some`; a link no peer holds, for
    /// which `held` answers `None`, uses its own setup pair. That counts a
    /// handshake leg still in flight, whose connection another leg's close
    /// must not take.
    pub(in crate::node) fn used(
        &self,
        key: &AddrKey,
        except: LinkId,
        held: impl Fn(LinkId) -> Option<bool>,
    ) -> bool {
        self.links
            .iter()
            .filter(|(id, _)| **id != except)
            .any(|(id, link)| {
                let setup = link.transport_id() == key.0 && link.remote_addr() == &key.1;
                match held(*id) {
                    Some(_) if node_fault!(CloseBySetupAddress) => setup,
                    Some(proven) => proven,
                    None => setup,
                }
            })
    }

    /// Retire the core's record of the link `id`, and drop any entry a test
    /// wrote naming it. The connections the core would close are the node's
    /// to close, by its own rule, until the core decides them.
    fn retire(&mut self, id: &LinkId) {
        if let Some(no) = self.nos.remove(id) {
            let _closes = self.core.retire(no);
        }
        #[cfg(test)]
        self.overlay.retain(|_, named| named != id);
    }

    /// The pairs the index names the link `id` at.
    #[cfg(test)]
    fn named(&self, id: &LinkId) -> Vec<AddrKey> {
        self.index
            .iter()
            .filter(|(_, named)| *named == id)
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Rebuild the index from the core's records.
    fn rebuild(&mut self) {
        self.index = reduce(&self.with_setups(self.core.index()), &self.nos);
        #[cfg(test)]
        {
            for key in &self.taken {
                self.index.remove(key);
            }
            for (key, id) in &self.overlay {
                self.index.insert(key.clone(), *id);
            }
        }
    }

    /// The core's number for the link `id`, while the link is open.
    pub(in crate::node) fn no(&self, id: &LinkId) -> Option<LinkNo> {
        self.nos.get(id).copied()
    }

    /// Who holds the link `id`, by the core's record of it: its handshake
    /// leg, or the peer a promotion installed.
    pub(in crate::node) fn holder(&self, id: &LinkId) -> Option<Holder> {
        self.no(id)
            .and_then(|no| self.core.get(no))
            .map(|rec| rec.holder)
    }

    /// The core's link records.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn core(&self) -> &Links {
        &self.core
    }

    /// The index the core's records give now, computed afresh rather than
    /// read from the cache.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn derived(&self) -> HashMap<AddrKey, LinkId> {
        reduce(&self.with_setups(&self.core.derived()), &self.nos)
    }

    /// `set` with each open link's setup pair added: the core leaves a
    /// setup pair whose path its bundle released out of the index, and this
    /// line keeps the link record's own pair named while the link lives.
    fn with_setups(&self, set: &BTreeSet<(Pair, LinkNo)>) -> BTreeSet<(Pair, LinkNo)> {
        let mut out = set.clone();
        for no in self.nos.values() {
            if let Some(rec) = self.core.get(*no) {
                out.insert((rec.setup.clone(), *no));
            }
        }
        out
    }

    /// The link `id` is now held by the peer at `peer`.
    pub(in crate::node) fn hold(&mut self, id: &LinkId, peer: NodeAddr) {
        if let Some(no) = self.no(id) {
            self.core.hold(no, Holder::Peer(peer));
        }
        self.rebuild();
    }

    /// Apply what a link's bundle reported, `input`, to the core's record of
    /// the link, and rebuild the index. The connections a released path
    /// leaves to close are the node's to close, by its own rule, until the
    /// core decides them.
    pub(in crate::node) fn mirror(&mut self, input: &Input) {
        match input {
            // The mutation lane's break: a moved path's old pair stays in
            // the record, and so in the index.
            Input::Moved { link, to, .. } if node_fault!(MovedLeavesEntry) => {
                self.core.path(*link, to.clone(), Proven::Live);
            }
            _ => {
                let _closes = self.core.mirror(input);
            }
        }
        if node_fault!(IndexNotRebuilt) {
            return;
        }
        self.rebuild();
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
    /// planted. What the test writes is put back at every rebuild.
    #[cfg(test)]
    pub(in crate::node) fn raw_index(&mut self) -> Planting<'_> {
        self.planted = true;
        Planting { table: self }
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
        self.overlay.insert(key.clone(), id);
        self.index.insert(key, id);
    }

    /// Take `key` out of the index past the writers and without marking the
    /// table, until a writer names it again: the shape of a write that
    /// bypasses the table, for the tests that the live audit catches one.
    #[cfg(test)]
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(in crate::node) fn take_entry(&mut self, key: &AddrKey) {
        self.overlay.remove(key);
        self.taken.insert(key.clone());
        self.index.remove(key);
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
        self.rebuild();
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

/// A test's write to the index past the writers: each entry goes in the
/// index and is put back at every rebuild, until its link closes or a writer
/// writes its pair as the written index did: a link opened there, or the
/// link it names releasing it. An entry taken out stays out the same way.
#[cfg(test)]
pub(in crate::node) struct Planting<'a> {
    table: &'a mut LinkTable,
}

#[cfg(test)]
impl Planting<'_> {
    /// Name `id` at `key`, returning the link the index named there.
    pub(in crate::node) fn insert(&mut self, key: AddrKey, id: LinkId) -> Option<LinkId> {
        self.table.overlay.insert(key.clone(), id);
        self.table.index.insert(key, id)
    }

    /// Take `key` out of the index, returning the link it named there. It
    /// stays out at every rebuild until a writer names it again.
    pub(in crate::node) fn remove(&mut self, key: &AddrKey) -> Option<LinkId> {
        self.table.overlay.remove(key);
        self.table.taken.insert(key.clone());
        self.table.index.remove(key)
    }
}

/// The index `set` gives, by link id: each pair it names, naming the link
/// with the newest number there, the one opened last. A number with no id
/// names nothing.
fn reduce(
    set: &BTreeSet<(Pair, LinkNo)>,
    nos: &HashMap<LinkId, LinkNo>,
) -> HashMap<AddrKey, LinkId> {
    let ids: HashMap<LinkNo, LinkId> = nos.iter().map(|(id, no)| (*no, *id)).collect();
    let mut index = HashMap::new();
    for (at, no) in set {
        let Some(id) = ids.get(no) else {
            continue;
        };
        let key = (at.transport, at.addr.clone());
        if node_fault!(IndexOldestWins) {
            index.entry(key).or_insert(*id);
        } else {
            index.insert(key, *id);
        }
    }
    index
}

/// The core's pair for the index key `key`.
pub(in crate::node) fn pair(key: &AddrKey) -> Pair {
    Pair {
        transport: key.0,
        addr: key.1.clone(),
    }
}
