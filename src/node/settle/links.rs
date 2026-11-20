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
#[cfg(test)]
use crate::proto::settle::input::Input;
#[cfg(test)]
use crate::proto::settle::join;
#[cfg(test)]
use crate::proto::settle::links::Holder;
#[cfg(test)]
use crate::proto::settle::links::Proven;
use crate::proto::settle::links::{Dir, LinkNo, Links, Pair, Placement};

use super::Core;
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
/// with the newest number. The records are the node's settlement core's
/// (`Node.core`), the one copy in any build; the table holds the numbers
/// and the index, and each writer takes the records. The table keeps the
/// index as a cache, rebuilt by every writer and after every step of the
/// core over the records, since every change to them goes through one: the
/// feed reaches them through [`LinkTable::mirror`] and [`LinkTable::hold`],
/// and the legs' resends and reaps through [`LinkTable::poll`] and
/// [`LinkTable::reap`]. The live audit's `index-cache` clause holds the
/// cache to the records.
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
    /// How many times the live audit has checked the node this table is in.
    #[cfg(test)]
    audits: Cell<u64>,
}

reads!(LinkTable, links, HashMap<LinkId, Link>);

impl LinkTable {
    /// A new link outside any handshake: the link is added, and the core
    /// records it, set up at its pair and held by its handshake leg.
    pub(in crate::node) fn open(&mut self, core: &mut Core, link: Link) {
        let id = link.link_id();
        let key = (link.transport_id(), link.remote_addr().clone());
        let dir = match link.direction() {
            LinkDirection::Inbound => Dir::Inbound,
            LinkDirection::Outbound => Dir::Outbound,
        };
        let no = core.open_link(pair(&key), dir);
        self.nos.insert(id, no);
        self.links.insert(id, link);
        #[cfg(test)]
        {
            self.taken.remove(&key);
            self.overlay.remove(&key);
        }
        self.rebuild(core);
    }

    /// A new link, which the core opened a record for and numbered `no`,
    /// at a dial or an admitted msg1: the link is added under that number.
    pub(in crate::node) fn bind(&mut self, core: &mut Core, link: Link, no: LinkNo) {
        let id = link.link_id();
        #[cfg(test)]
        {
            let key = (link.transport_id(), link.remote_addr().clone());
            self.taken.remove(&key);
            self.overlay.remove(&key);
        }
        self.nos.insert(id, no);
        self.links.insert(id, link);
        self.rebuild(core);
    }

    /// The link is closed: it is taken out, and the index, rebuilt from the
    /// core's records, which retired it, names it nowhere.
    pub(in crate::node) fn close(&mut self, core: &mut Core, id: &LinkId) -> Option<Link> {
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

    /// A dial is abandoned: its link is dropped, as at a close, once the
    /// core gave it up. `key` is the dial's pair, which another link may
    /// still name.
    pub(in crate::node) fn forget(&mut self, core: &mut Core, id: &LinkId, key: &AddrKey) {
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
    pub(in crate::node) fn follow(&mut self, core: &mut Core) {
        self.rebuild(core);
    }

    /// The link switched to a path at `to`, which the core's record gains
    /// when the feed steps it with the switch: the index is rebuilt from
    /// the records.
    pub(in crate::node) fn claimed(&mut self, core: &mut Core, id: LinkId, to: AddrKey) {
        debug_assert!(
            self.no(&id).is_none_or(|no| core
                .links()
                .get(no)
                .is_some_and(|r| r.paths.iter().any(|(p, _)| *p == pair(&to)))),
            "the core's record of link {id} lacks the pair it switched to"
        );
        #[cfg(test)]
        self.taken.remove(&to);
        #[cfg(not(test))]
        let _ = to;
        self.rebuild(core);
    }

    /// The link released its path at `key`, which the core's record no
    /// longer holds once it stepped with the release: a released setup pair
    /// leaves the index.
    pub(in crate::node) fn unclaimed(&mut self, core: &mut Core, id: LinkId, key: &AddrKey) {
        #[cfg(test)]
        if self.overlay.get(key) == Some(&id) {
            self.overlay.remove(key);
        }
        #[cfg(not(test))]
        let _ = (id, key);
        self.rebuild(core);
    }

    /// The link switched to a path at `to`, for a test that drives the
    /// table alone: a record that lacks the path gains it acknowledged,
    /// the least a switch's target holds, as the core's switch does
    /// (test builds only).
    #[cfg(test)]
    pub(in crate::node) fn claim(&mut self, core: &mut Core, id: LinkId, to: AddrKey) {
        if let Some(no) = self.no(&id) {
            let at = pair(&to);
            let links = core.records();
            let held = links
                .get(no)
                .is_some_and(|r| r.paths.iter().any(|(p, _)| *p == at));
            if !held {
                links.path(no, at, Proven::Acked);
            }
        }
        self.claimed(core, id, to);
    }

    /// The link released its path at `key`, for a test that drives the
    /// table alone: the record lets it go, as the core's release does
    /// (test builds only).
    #[cfg(test)]
    pub(in crate::node) fn unclaim(&mut self, core: &mut Core, id: LinkId, key: &AddrKey) {
        if let Some(no) = self.no(&id) {
            let _closes = core.records().release(no, &pair(key), true);
        }
        self.unclaimed(core, id, key);
    }

    /// The close rule, the settlement core's over its records: whether a
    /// live link other than `except` uses the connection at `key`, a held
    /// link by each Live or acknowledged path of its record, and a
    /// handshake leg, or a link whose record holds no path, by its setup
    /// pair ([`Links::in_use`]). A leg in flight thus keeps its connection
    /// from another leg's close.
    pub(in crate::node) fn used(&self, core: &Links, key: &AddrKey, except: LinkId) -> bool {
        // A link with no number has no record to except.
        let except = self.no(&except).unwrap_or(LinkNo(u64::MAX));
        core.in_use(&pair(key), except)
    }

    /// Drop the link `id`'s number, whose record the core retired at the
    /// removal, crossing or given-up dial that closes the link, and any
    /// entry a test wrote naming it. In a test build a record still open
    /// is retired here: a link a test closes past the core's decisions,
    /// after its own removal of the peer.
    fn retire(&mut self, core: &mut Core, id: &LinkId) {
        if let Some(no) = self.nos.remove(id) {
            #[cfg(test)]
            {
                let _closes = core.records().retire(no);
            }
            #[cfg(not(test))]
            debug_assert!(
                core.links().get(no).is_none(),
                "a link closed while the core still holds its record"
            );
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
    fn rebuild(&mut self, core: &mut Core) {
        #[cfg(test)]
        self.rebuild_records(core.records());
        #[cfg(not(test))]
        {
            self.index = reduce(core.links().index(), &self.nos);
        }
    }

    /// [`LinkTable::rebuild`] over the records themselves (test builds
    /// only).
    #[cfg(test)]
    fn rebuild_records(&mut self, core: &mut Links) {
        let named = self
            .overlay
            .iter()
            .filter_map(|(key, id)| Some((pair(key), self.no(id)?)))
            .collect();
        core.name(named);
        self.index = reduce(core.index(), &self.nos);
        for key in &self.taken {
            self.index.remove(key);
        }
        for (key, id) in &self.overlay {
            self.index.insert(key.clone(), *id);
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
        core: &Links,
        key: &AddrKey,
        leg: impl Fn(LinkId) -> Option<NodeAddr>,
    ) -> Placement {
        core.placement(&pair(key), |no| self.id(no).and_then(&leg))
    }

    /// The index the core's records give now, computed afresh rather than
    /// read from the cache.
    #[cfg(any(test, debug_assertions))]
    pub(in crate::node) fn derived(&self, core: &Links) -> HashMap<AddrKey, LinkId> {
        reduce(&core.derived(), &self.nos)
    }

    /// The link `id` is now held by the peer at `peer`, as the core's
    /// install or move that the caller runs holds its record: the index is
    /// rebuilt from the records.
    ///
    /// A test that promotes a peer past the core, by a direct call of the
    /// promotion, has the record held as the core's install would hold it,
    /// as the resync does for a peer planted past the writers (test builds
    /// only).
    pub(in crate::node) fn held(&mut self, core: &mut Core, id: &LinkId, peer: NodeAddr) {
        #[cfg(test)]
        if core.held(&peer).is_none() {
            self.hold(core, id, peer);
            return;
        }
        debug_assert!(
            self.no(id)
                .is_none_or(|no| core.links().get(no).map(|r| r.holder)
                    == Some(crate::proto::settle::links::Holder::Peer(peer))),
            "the core holds the link {id} for another than the peer installed on it"
        );
        self.rebuild(core);
    }

    /// The link `id` is now held by the peer at `peer`, for a test that
    /// drives the table alone, as the core's install holds it (test builds
    /// only).
    #[cfg(test)]
    pub(in crate::node) fn hold(&mut self, core: &mut Core, id: &LinkId, peer: NodeAddr) {
        if let Some(no) = self.no(id) {
            core.records().hold(no, Holder::Peer(peer));
        }
        self.rebuild(core);
    }

    /// Apply what a link's bundle reported, `input`, to the core's record of
    /// the link, and rebuild the index, as a test drives the table alone
    /// (the node steps the core with it, [`Node::feed`]).
    #[cfg(test)]
    pub(in crate::node) fn mirror(&mut self, core: &mut Core, input: &Input) {
        let _closes = core.records().mirror(input);
        self.stepped(core);
    }

    /// Rebuild the index after a step of the core changed its records: an
    /// install or a move that holds a link for its peer, a bundle's report
    /// applied to them, or a leg's resends and reaps run over them.
    pub(in crate::node) fn stepped(&mut self, core: &mut Core) {
        // The mutation lane's break: the index is left as it was, whatever
        // the step changed.
        if node_fault!(IndexNotRebuilt) {
            return;
        }
        self.rebuild(core);
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
        core: &mut Core,
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
        // Whether the records gain anything here, or a test's index entries
        // are to be named through them: with neither, the index the records
        // give is the one the last writer built, and is left as it is.
        let mut wrote = !planted.is_empty() || !self.overlay.is_empty();
        let core = core.records();
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
            // lacks, whose direction nothing gives. It is no inbound
            // link of the node's, so no duplicate msg1 is answered on it,
            // until a test puts the link in the map.
            self.adopt(core, id, at, Dir::Outbound, holders);
            self.orphans.insert(id);
        }
        for (id, peer, at, paths, capable) in unrecorded {
            if self.no(&id).is_none() {
                wrote = true;
                self.adopt(core, id, at, Dir::Inbound, holders);
                if let Some(no) = self.no(&id) {
                    core.hold(no, Holder::Peer(peer));
                    core.resync(no, paths, capable);
                }
            }
        }
        for (id, peer, paths, capable) in held {
            if let Some(no) = self.no(&id) {
                wrote = true;
                core.resync(no, paths, capable);
                if core.get(no).map(|r| r.holder) != Some(Holder::Peer(peer)) {
                    core.hold(no, Holder::Peer(peer));
                }
            }
        }
        if wrote {
            self.rebuild_records(core);
        }
    }

    /// Open a record for the link `id`, which has none, as a leg at `at`,
    /// held by the peer `holders` puts on the link, if any.
    #[cfg(test)]
    fn adopt(
        &mut self,
        core: &mut Links,
        id: LinkId,
        at: Pair,
        dir: Dir,
        holders: &HashMap<LinkId, NodeAddr>,
    ) {
        let no = core.open(at, dir, Holder::Leg);
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

    /// Write the core's record of the link `id` as holding a path at `key`
    /// in state `state`, past the feed and without marking the table: the
    /// shape of a record that differs from its bundle, for the test that the
    /// live audit catches one.
    #[cfg(test)]
    pub(in crate::node) fn plant_path(
        &mut self,
        core: &mut Core,
        id: &LinkId,
        key: &AddrKey,
        state: crate::proto::settle::links::Proven,
    ) {
        if let Some(no) = self.no(id) {
            core.records().path(no, pair(key), state);
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
