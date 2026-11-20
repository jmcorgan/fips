//! The link table: the node's links and the address index over them.

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::collections::HashSet;
use std::collections::{BTreeSet, HashMap};

#[cfg(test)]
use fips_core::proto::path::PathRef;

use crate::NodeAddr;
use crate::node::AddrKey;
#[cfg(test)]
use crate::peer::ActivePeer;
use crate::peer::PeerInstant;
use crate::proto::settle::input::Input;
#[cfg(test)]
use crate::proto::settle::join;
use crate::proto::settle::legs::{LegOut, Legs};
use crate::proto::settle::links::{Dir, Holder, LinkNo, Links, Pair, Placement, Proven};
use crate::transport::{Link, LinkDirection, LinkId};

/// The node's links, keyed by `LinkId`, and the index from a
/// `(transport, address)` pair to the link at it.
///
/// The index is a reverse lookup from `(transport, address)` to link. It is
/// **not** a packet-dispatch path: `find_link_by_addr` has no callers outside
/// its own tests, and encrypted frames are dispatched by session index. Its
/// live readers are the duplicate-inbound-handshake check in `handle_msg1`
/// and the sweep of unproven BLE channels; the attribution questions a msg1
/// or a rekey msg2 asks of its source read the core's records the cache is
/// built from ([`LinkTable::placement`]).
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
/// its setup pair, unless the bundle released the path there, and at each of
/// its Live or acknowledged paths; a pair several links use names the link
/// with the newest number. The table keeps that as a cache, rebuilt by every
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
    /// Links whose record the resync opened from an index entry a test
    /// wrote, while the map lacked the link: the record is opened again
    /// from the link once a test puts it in the map.
    #[cfg(test)]
    orphans: HashSet<LinkId>,
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

    /// The link switched to a path at `to`. A record that lacks the path
    /// gains it acknowledged, the least a switch's target holds; a path it
    /// holds keeps its state, which the feed of the switch that follows in
    /// the same step sets to the bundle's.
    pub(in crate::node) fn claim(&mut self, id: LinkId, to: AddrKey) {
        if let Some(no) = self.no(&id) {
            let at = pair(&to);
            let held = self
                .core
                .get(no)
                .is_some_and(|r| r.paths.iter().any(|(p, _)| *p == at));
            if !held {
                self.core.path(no, at, Proven::Acked);
            }
        }
        #[cfg(test)]
        self.taken.remove(&to);
        self.rebuild();
    }

    /// The link released its path at `key`, which its record no longer
    /// holds. A released setup pair leaves the index.
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

    /// The close rule, the settlement core's over its records: whether a
    /// live link other than `except` uses the connection at `key`, a held
    /// link by each Live or acknowledged path of its record, and a
    /// handshake leg, or a link whose record holds no path, by its setup
    /// pair ([`Links::in_use`]). A leg in flight thus keeps its connection
    /// from another leg's close.
    pub(in crate::node) fn used(&self, key: &AddrKey, except: LinkId) -> bool {
        // A link with no number has no record to except.
        let except = self.no(&except).unwrap_or(LinkNo(u64::MAX));
        self.core.in_use(&pair(key), except)
    }

    /// Retire the core's record of the link `id`, and drop any entry a test
    /// wrote naming it. The connections the core would close are the node's
    /// to close, by its own rule, until the core decides them.
    fn retire(&mut self, id: &LinkId) {
        if let Some(no) = self.nos.remove(id) {
            let _closes = self.core.retire(no);
        }
        #[cfg(test)]
        {
            self.overlay.retain(|_, named| named != id);
            self.orphans.remove(id);
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
    fn rebuild(&mut self) {
        #[cfg(test)]
        {
            let named = self
                .overlay
                .iter()
                .filter_map(|(key, id)| Some((pair(key), self.no(id)?)))
                .collect();
            self.core.name(named);
        }
        self.index = reduce(self.core.index(), &self.nos);
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

    /// The link the core numbers `no`, while it is open.
    pub(in crate::node) fn id(&self, no: LinkNo) -> Option<LinkId> {
        self.nos
            .iter()
            .find_map(|(id, n)| (*n == no).then_some(*id))
    }

    /// Where a msg1 from `key` stands among the core's link records
    /// ([`Links::placement`]); `leg` gives the identity the handshake leg on
    /// one of the node's links expects.
    pub(in crate::node) fn placement(
        &self,
        key: &AddrKey,
        leg: impl Fn(LinkId) -> Option<NodeAddr>,
    ) -> Placement {
        self.core
            .placement(&pair(key), |no| self.id(no).and_then(&leg))
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
        reduce(&self.core.derived(), &self.nos)
    }

    /// Run the handshake legs' timers at `now`: the resends due, and the
    /// legs past their deadline, each reaped leg's record retired from the
    /// core's records by the close rule, which names the connections its
    /// retirement closes. The index is rebuilt after, as at every writer.
    pub(in crate::node) fn poll(
        &mut self,
        legs: &mut Legs<PeerInstant>,
        now: PeerInstant,
    ) -> Vec<LegOut> {
        let out = legs.poll(now, &mut self.core);
        if node_fault!(IndexNotRebuilt) {
            return out;
        }
        self.rebuild();
        out
    }

    /// [`LinkTable::poll`]'s reap of the leg on the core's link `no` alone,
    /// if it is past its deadline at `now`, its record retired by the close
    /// rule and the index rebuilt after.
    pub(in crate::node) fn reap(
        &mut self,
        legs: &mut Legs<PeerInstant>,
        no: LinkNo,
        now: PeerInstant,
    ) -> Vec<LegOut> {
        let out = legs.reap_one(no, now, &mut self.core);
        if node_fault!(IndexNotRebuilt) {
            return out;
        }
        self.rebuild();
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

    /// Write into the core's records what a test changed past the writers,
    /// for the node's resync before it next reads them. Each link a test put
    /// in the map itself gets a record, as a leg at its setup pair; each
    /// entry a test wrote in the index naming a link with no record opens
    /// one there, as a leg; each peer in `unrecorded`, held on a link the
    /// map lacks and no record has, by its link, address, pair, bundle
    /// paths and whether its bundle found it capable, gets a record set up
    /// at that pair and held by it, holding those paths; and each peer
    /// named in `held`, the same facts but its pair, has its record hold
    /// exactly those paths and that flag and be held by it. A record
    /// opened here is held by the peer `holders` puts on its link, if any;
    /// one opened from an index entry is opened again from its link once a
    /// test puts the link in the map. Each entry a test wrote in the index
    /// for a link the records have names the link there through the
    /// records ([`LinkTable::rebuild`]), not as a path its bundle does not
    /// hold. Nothing a writer set is overwritten but `held`'s paths and
    /// holders.
    #[cfg(test)]
    pub(in crate::node) fn resync(
        &mut self,
        held: Vec<(LinkId, NodeAddr, Paths, bool)>,
        unrecorded: Vec<(LinkId, NodeAddr, Pair, Paths, bool)>,
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
        for (id, at, dir) in planted {
            if self.orphans.remove(&id)
                && let Some(no) = self.nos.remove(&id)
            {
                let _closes = self.core.retire(no);
            }
            self.adopt(id, at, dir, holders);
        }
        let mut entries: Vec<(AddrKey, LinkId)> = self
            .overlay
            .iter()
            .map(|(key, id)| (key.clone(), *id))
            .collect();
        entries.sort_by(|(a, _), (b, _)| pair(a).cmp(&pair(b)));
        for (key, id) in entries {
            let at = pair(&key);
            if self.no(&id).is_some() || self.core.at(&at).next().is_some() {
                continue;
            }
            // An entry naming a link with no record names a link the map
            // lacks, whose direction nothing gives. It is no inbound
            // link of the node's, so no duplicate msg1 is answered on it,
            // until a test puts the link in the map.
            self.adopt(id, at, Dir::Outbound, holders);
            self.orphans.insert(id);
        }
        for (id, peer, at, paths, capable) in unrecorded {
            if self.no(&id).is_none() {
                self.adopt(id, at, Dir::Inbound, holders);
                if let Some(no) = self.no(&id) {
                    self.core.hold(no, Holder::Peer(peer));
                    self.core.resync(no, paths, capable);
                }
            }
        }
        for (id, peer, paths, capable) in held {
            if let Some(no) = self.no(&id) {
                self.core.resync(no, paths, capable);
                if self.core.get(no).map(|r| r.holder) != Some(Holder::Peer(peer)) {
                    self.core.hold(no, Holder::Peer(peer));
                }
            }
        }
        self.rebuild();
    }

    /// Open a record for the link `id`, which has none, as a leg at `at`,
    /// held by the peer `holders` puts on the link, if any.
    #[cfg(test)]
    fn adopt(&mut self, id: LinkId, at: Pair, dir: Dir, holders: &HashMap<LinkId, NodeAddr>) {
        let no = self.core.open(at, dir, Holder::Leg);
        self.nos.insert(id, no);
        if let Some(peer) = holders.get(&id) {
            self.core.hold(no, Holder::Peer(*peer));
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
/// link it names releasing it.
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

/// A link's paths, each with its state, as the core's record holds them.
#[cfg(test)]
pub(in crate::node) type Paths = Vec<(Pair, Proven)>;

/// The paths `peer`'s bundle holds, each in the state the core is told of
/// it: Live for a Live path, acknowledged for another acknowledged one,
/// probing otherwise; none for a peer with no bundle. What its link's record
/// holds when the feed has told it everything.
#[cfg(test)]
pub(in crate::node) fn recorded(peer: &ActivePeer) -> Paths {
    peer.bundle()
        .map(|b| {
            b.paths()
                .paths()
                .iter()
                .map(|p| {
                    let at = PathRef {
                        transport: p.transport_id(),
                        addr: p.addr().clone(),
                    };
                    (join::pair(&at), join::proven(b, &at))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The core's pair for the index key `key`.
pub(in crate::node) fn pair(key: &AddrKey) -> Pair {
    Pair {
        transport: key.0,
        addr: key.1.clone(),
    }
}
