//! The link table: the node's links and the address index over them.

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::collections::HashSet;
use std::collections::{BTreeSet, HashMap};

use crate::NodeAddr;
use crate::node::AddrKey;
#[cfg(test)]
use crate::peer::ActivePeer;
#[cfg(test)]
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
/// or by the core at a dial's connect or an anonymous msg1 and taken under
/// its number ([`LinkTable::bind`]), retired with it, held by the peer a
/// promotion installs, and fed what each link's bundle reports through the
/// core's join. It names each live link at
/// its setup pair and at each of its Live or acknowledged paths; a pair
/// several links use names the link with the newest number. Unlike the
/// core's own index, the setup pair stays named after the bundle releases
/// the path there: the link record's own pair names the link while it
/// lives, which the anonymous-beacon dedup reads. So an inbound leg that
/// takes a pair at msg1 names it while it lives, and the pair goes back to
/// the link it was named before once the leg is closed. The records are the
/// node's settlement core's (`Node.core`), the one copy in any build; the
/// table holds the numbers and the index, and each writer takes the records.
/// The table keeps the index as a cache, rebuilt by every writer and after
/// every step of the core ([`LinkTable::stepped`]), since every change to
/// the records goes through one or the other: the feed of a link's bundle
/// steps the core. The live audit's `index-cache` clause holds the cache to
/// the records.
///
/// The links are reached by `Deref` for reads, and by `get_mut` for a change
/// to a link that leaves the table as it is; the index by `index`. Every
/// write to either goes through a writer named for its event.
#[derive(Default)]
pub(in crate::node) struct LinkTable {
    links: HashMap<LinkId, Link>,
    /// The index the records give, rebuilt at every writer.
    index: HashMap<AddrKey, LinkId>,
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
    /// Links whose record the resync opened from an index entry a test
    /// wrote, while the map lacked the link: the record is opened again
    /// from the link once a test puts it in the map.
    #[cfg(test)]
    orphans: HashSet<LinkId>,
    /// The record the settlement core's resync opened for each link a test
    /// put in the map past the writers, which the table does not number:
    /// the core decides on it, and the index does not name it. The table
    /// takes the record over if it numbers the link later.
    #[cfg(test)]
    spare: HashMap<LinkId, LinkNo>,
    /// How many times the live audit has checked the node this table is in.
    #[cfg(test)]
    audits: Cell<u64>,
}

reads!(LinkTable, links, HashMap<LinkId, Link>);

impl LinkTable {
    /// A new link: the link is added, and the core records it, set up at
    /// its pair and held by its handshake leg.
    pub(in crate::node) fn open(&mut self, core: &mut Links, link: Link) {
        let id = link.link_id();
        let key = (link.transport_id(), link.remote_addr().clone());
        let dir = match link.direction() {
            LinkDirection::Inbound => Dir::Inbound,
            LinkDirection::Outbound => Dir::Outbound,
        };
        // A link the resync gave a record from a test's index entry, before
        // the link was opened, is recorded afresh from the link.
        #[cfg(test)]
        if self.orphans.remove(&id) {
            self.retire(core, &id);
        }
        // A record the core's resync opened for the link while a test held
        // it in the map past the writers is taken over.
        #[cfg(test)]
        let no = self
            .take_spare(core, id, &pair(&key), dir)
            .unwrap_or_else(|| core.open(pair(&key), dir, Holder::Leg));
        #[cfg(not(test))]
        let no = core.open(pair(&key), dir, Holder::Leg);
        self.nos.insert(id, no);
        self.links.insert(id, link);
        #[cfg(test)]
        {
            self.taken.remove(&key);
            self.overlay.remove(&key);
        }
        self.rebuild(core);
    }

    /// A new link, which the settlement core opened a record for and
    /// numbered `no`, at a dial's connect or an anonymous msg1: the link is
    /// added under that number.
    pub(in crate::node) fn bind(&mut self, core: &mut Links, link: Link, no: LinkNo) {
        let id = link.link_id();
        #[cfg(test)]
        {
            let key = (link.transport_id(), link.remote_addr().clone());
            self.taken.remove(&key);
            self.overlay.remove(&key);
            self.orphans.remove(&id);
            if let Some(old) = self.spare.remove(&id) {
                let _closes = core.retire(old);
            }
        }
        self.nos.insert(id, no);
        self.links.insert(id, link);
        self.rebuild(core);
    }

    /// The core stepped: its records may have changed, so the index is
    /// rebuilt from them.
    pub(in crate::node) fn stepped(&mut self, core: &mut Links) {
        self.rebuild(core);
    }

    /// The link is closed: it is taken out, and the core's record of it is
    /// retired, so the index names it nowhere.
    pub(in crate::node) fn close(&mut self, core: &mut Links, id: &LinkId) -> Option<Link> {
        let link = self.links.remove(id)?;
        #[cfg(test)]
        let named = self.named(id);
        self.retire(core, id);
        self.rebuild(core);
        // The mutation lane's break: the link's own pair and every pair it
        // was named at are taken from whichever link the index names there.
        #[cfg(test)]
        if node_fault!(ShadowLosesEntry) {
            self.taken
                .insert((link.transport_id(), link.remote_addr().clone()));
            self.taken.extend(named);
            self.rebuild(core);
        }
        Some(link)
    }

    /// A dial is abandoned: its link is dropped and the core's record of it
    /// retired, as at a close. `key` is the dial's pair, which another
    /// link may still name.
    pub(in crate::node) fn forget(&mut self, core: &mut Links, id: &LinkId, key: &AddrKey) {
        self.links.remove(id);
        self.retire(core, id);
        self.rebuild(core);
        // The mutation lane's break: the dial's pair is taken from whichever
        // link it named.
        #[cfg(test)]
        if node_fault!(ForgetTakesKey) {
            self.taken.insert(key.clone());
            self.rebuild(core);
        }
        #[cfg(not(test))]
        let _ = key;
    }

    /// The link's path moved. The core's record follows when the feed
    /// applies the move, so this only rebuilds the index.
    pub(in crate::node) fn follow(&mut self, core: &mut Links) {
        self.rebuild(core);
    }

    /// The link switched to a path at `to`, which its record holds Live.
    pub(in crate::node) fn claim(&mut self, core: &mut Links, id: LinkId, to: AddrKey) {
        if let Some(no) = self.no(&id) {
            core.path(no, pair(&to), Proven::Live);
        }
        #[cfg(test)]
        self.taken.remove(&to);
        self.rebuild(core);
    }

    /// The link released its path at `key`, which its record no longer
    /// holds. A released setup pair stays in the index while the link lives.
    pub(in crate::node) fn unclaim(&mut self, core: &mut Links, id: LinkId, key: &AddrKey) {
        if let Some(no) = self.no(&id) {
            let _closes = core.release(no, &pair(key), true);
        }
        #[cfg(test)]
        if self.overlay.get(key) == Some(&id) {
            self.overlay.remove(key);
        }
        self.rebuild(core);
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
    fn retire(&mut self, core: &mut Links, id: &LinkId) {
        if let Some(no) = self.nos.remove(id) {
            let _closes = core.retire(no);
        }
        #[cfg(test)]
        {
            self.overlay.retain(|_, named| named != id);
            self.orphans.remove(id);
            if let Some(no) = self.spare.remove(id) {
                let _closes = core.retire(no);
            }
        }
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

    /// Rebuild the index from the core's records. In a test build the
    /// records first name each link at the pairs a test wrote in the index
    /// for it past the writers ([`Links::name`]), so the records answer
    /// for the index the test wrote.
    fn rebuild(&mut self, core: &mut Links) {
        #[cfg(test)]
        {
            let named = self
                .overlay
                .iter()
                .filter_map(|(key, id)| Some((pair(key), self.no(id)?)))
                .collect();
            core.name(named);
        }
        self.index = reduce(&self.with_setups(core, core.index()), &self.nos);
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

    /// The core's number for the link `id` as the core decides on it: the
    /// table's, or in a test build the record the core's resync opened for
    /// a link a test put in the map past the writers.
    pub(in crate::node) fn core_no(&self, id: &LinkId) -> Option<LinkNo> {
        #[cfg(test)]
        if let Some(no) = self.spare.get(id) {
            return Some(*no);
        }
        self.no(id)
    }

    /// The link the core numbers `no` ([`LinkTable::core_no`]'s inverse).
    pub(in crate::node) fn id(&self, no: LinkNo) -> Option<LinkId> {
        #[cfg(test)]
        if let Some(id) = self
            .spare
            .iter()
            .find_map(|(id, n)| (*n == no).then_some(*id))
        {
            return Some(id);
        }
        self.nos
            .iter()
            .find_map(|(id, n)| (*n == no).then_some(*id))
    }

    /// Open a record in the core for the link `id`, which a test put in the
    /// map past the writers and the table does not number, set up at `at`
    /// by the end `dir` says and held as a leg; the index does not name it
    /// (test builds only).
    #[cfg(test)]
    pub(in crate::node) fn plant_spare(
        &mut self,
        core: &mut Links,
        id: LinkId,
        at: Pair,
        dir: Dir,
    ) {
        if self.nos.contains_key(&id) || self.spare.contains_key(&id) {
            return;
        }
        let no = core.open(at, dir, Holder::Leg);
        self.spare.insert(id, no);
    }

    /// Take over the core's spare record of the link `id` when the table
    /// numbers it, if the record was set up as the link is; one set up
    /// otherwise is retired (test builds only).
    #[cfg(test)]
    fn take_spare(&mut self, core: &mut Links, id: LinkId, at: &Pair, dir: Dir) -> Option<LinkNo> {
        let no = self.spare.remove(&id)?;
        if core.get(no).is_some_and(|r| r.setup == *at && r.dir == dir) {
            return Some(no);
        }
        let _closes = core.retire(no);
        None
    }

    /// Who holds the link `id`, by the core's record of it: its handshake
    /// leg, or the peer a promotion installed.
    pub(in crate::node) fn holder(&self, core: &Links, id: &LinkId) -> Option<Holder> {
        self.no(id)
            .and_then(|no| core.get(no))
            .map(|rec| rec.holder)
    }

    /// The link the index names at `key`, with the end that set it up and
    /// who holds it, by the core's record of it. A link with no record is
    /// no link of the node's.
    pub(in crate::node) fn placed(
        &self,
        core: &Links,
        key: &AddrKey,
    ) -> Option<(LinkId, Dir, Holder)> {
        let id = *self.index.get(key)?;
        let rec = core.get(self.no(&id)?)?;
        Some((id, rec.dir, rec.holder))
    }

    /// The peer holding the link the index names at `key`, by the core's
    /// record of the link.
    pub(in crate::node) fn held_at(&self, core: &Links, key: &AddrKey) -> Option<NodeAddr> {
        match self.placed(core, key)? {
            (_, _, Holder::Peer(peer)) => Some(peer),
            (_, _, Holder::Leg) => None,
        }
    }

    /// The index the core's records give now, computed afresh rather than
    /// read from the cache.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn derived(&self, core: &Links) -> HashMap<AddrKey, LinkId> {
        reduce(&self.with_setups(core, &core.derived()), &self.nos)
    }

    /// `set` with each open link's setup pair added: the core leaves a
    /// setup pair whose path its bundle released out of the index, and this
    /// line keeps the link record's own pair named while the link lives.
    fn with_setups(
        &self,
        core: &Links,
        set: &BTreeSet<(Pair, LinkNo)>,
    ) -> BTreeSet<(Pair, LinkNo)> {
        let mut out = set.clone();
        for no in self.nos.values() {
            if let Some(rec) = core.get(*no) {
                out.insert((rec.setup.clone(), *no));
            }
        }
        out
    }

    /// The bundle of the link `id` was renewed on a new session and has not
    /// found the peer capable: the core's record forgets that it had.
    pub(in crate::node) fn renewed(&mut self, core: &mut Links, id: &LinkId) {
        if let Some(no) = self.no(id) {
            core.renewed(no);
        }
    }

    /// The link `id` is now held by the peer at `peer`.
    pub(in crate::node) fn hold(&mut self, core: &mut Links, id: &LinkId, peer: NodeAddr) {
        if let Some(no) = self.no(id) {
            core.hold(no, Holder::Peer(peer));
        }
        self.rebuild(core);
    }

    /// Apply what a link's bundle reported, `input`, to the core's record of
    /// the link, and rebuild the index. The connections a released path
    /// leaves to close are the node's to close, by its own rule, until the
    /// core decides them.
    #[cfg(test)]
    pub(in crate::node) fn mirror(&mut self, core: &mut Links, input: &Input) {
        match input {
            // The mutation lane's break: a moved path's old pair stays in
            // the record, and so in the index.
            Input::Moved { link, to, .. } if node_fault!(MovedLeavesEntry) => {
                core.path(*link, to.clone(), Proven::Live);
            }
            _ => {
                let _closes = core.mirror(input);
            }
        }
        if node_fault!(IndexNotRebuilt) {
            return;
        }
        self.rebuild(core);
    }

    /// Write into the core's records what a test changed past the writers,
    /// for the node's resync before it next reads them. Each link a test put
    /// in the map itself gets a record, as a leg at its setup pair; each
    /// entry a test wrote in the index naming a link with no record opens
    /// one there, as a leg the node did not dial for; and each peer in
    /// `unrecorded`, held on a link the map lacks and no record has, by its
    /// link, address and the pair it is at, gets a record set up at that
    /// pair and held by it. A record opened here is held by the peer
    /// `holders` puts on its link, if any; one opened from an index entry
    /// is opened again from its link once a test puts the link in the map.
    /// Each entry a test wrote in the index for a link the records have
    /// names the link there through the records ([`LinkTable::rebuild`]).
    /// Nothing a writer set is overwritten (test builds only).
    #[cfg(test)]
    pub(in crate::node) fn resync(
        &mut self,
        core: &mut Links,
        unrecorded: Vec<(LinkId, NodeAddr, Pair)>,
        holders: &HashMap<LinkId, NodeAddr>,
    ) {
        let planted: Vec<(LinkId, Pair, Dir)> = self
            .links
            .iter()
            .filter(|(id, _)| !self.nos.contains_key(id) || self.orphans.contains(id))
            .map(|(id, link)| {
                let at = pair(&(link.transport_id(), link.remote_addr().clone()));
                let dir = match link.direction() {
                    LinkDirection::Inbound => Dir::Inbound,
                    LinkDirection::Outbound => Dir::Outbound,
                };
                (*id, at, dir)
            })
            .collect();
        // Whether the records gain anything here, or a test's index entries
        // are to be named through them: with neither, the index the records
        // give is the one the last writer built, and is left as it is.
        let mut wrote = !planted.is_empty() || !self.overlay.is_empty();
        for (id, at, dir) in planted {
            if self.orphans.remove(&id)
                && let Some(no) = self.nos.remove(&id)
            {
                let _closes = core.retire(no);
            }
            self.adopt(core, id, at, dir, holders);
        }
        let mut entries: Vec<(AddrKey, LinkId)> = self
            .overlay
            .iter()
            .map(|(key, id)| (key.clone(), *id))
            .collect();
        entries.sort_by(|(a, _), (b, _)| pair(a).cmp(&pair(b)));
        for (key, id) in entries {
            let at = pair(&key);
            if self.no(&id).is_some() || core.at(&at).next().is_some() {
                continue;
            }
            // An entry naming a link with no record names a link the map
            // lacks, whose direction nothing gives. It is no inbound link
            // of the node's, so no duplicate msg1 is answered on it, until
            // a test puts the link in the map.
            self.adopt(core, id, at, Dir::Outbound, holders);
            self.orphans.insert(id);
        }
        for (id, peer, at) in unrecorded {
            if self.no(&id).is_none() {
                wrote = true;
                self.adopt(core, id, at, Dir::Inbound, holders);
                if let Some(no) = self.no(&id) {
                    core.hold(no, Holder::Peer(peer));
                }
            }
        }
        if wrote {
            self.rebuild(core);
        }
    }

    /// Open a record for the link `id`, which has none, as a leg at `at`,
    /// held by the peer `holders` puts on the link, if any (test builds
    /// only).
    #[cfg(test)]
    fn adopt(
        &mut self,
        core: &mut Links,
        id: LinkId,
        at: Pair,
        dir: Dir,
        holders: &HashMap<LinkId, NodeAddr>,
    ) {
        let no = self
            .take_spare(core, id, &at, dir)
            .unwrap_or_else(|| core.open(at, dir, Holder::Leg));
        self.nos.insert(id, no);
        if let Some(peer) = holders.get(&id) {
            core.hold(no, Holder::Peer(*peer));
        }
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
        core: &mut Links,
        id: &LinkId,
        key: &AddrKey,
        state: crate::proto::settle::links::Proven,
    ) {
        if let Some(no) = self.no(id) {
            core.path(no, pair(key), state);
        }
        self.rebuild(core);
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

/// The pair `peer` is at, as its link's transport and current address give
/// it, or an empty address on transport 0 for a peer that has neither
/// (test builds only).
#[cfg(test)]
pub(in crate::node) fn current(peer: &ActivePeer) -> Pair {
    Pair {
        transport: peer
            .transport_id()
            .unwrap_or_else(|| crate::transport::TransportId::new(0)),
        addr: peer
            .current_addr()
            .cloned()
            .unwrap_or_else(|| crate::transport::TransportAddr::new(Vec::new())),
    }
}
