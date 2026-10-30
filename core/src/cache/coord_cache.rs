//! Coordinate cache for routing decisions.
//!
//! Maps node addresses to their tree coordinates, enabling data packets
//! to be routed without carrying coordinates in every packet. Populated
//! by SessionSetup packets.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::entropy::EntropySource;
use crate::utils::hash::{HashMap, KeyedHasher};

use super::CacheStats;
use super::entry::CacheEntry;
use crate::identity::NodeAddr;
use crate::proto::stp::TreeCoordinate;

/// Default maximum entries in coordinate cache.
pub const DEFAULT_COORD_CACHE_SIZE: usize = 50_000;

/// Default TTL for coordinate cache entries (5 minutes in milliseconds).
pub const DEFAULT_COORD_CACHE_TTL_MS: u64 = 300_000;

/// Coordinate addresses the cache may store per entry of its configured
/// capacity, and the least weight any one entry is charged.
///
/// Bounds the main segment's coordinate storage at
/// `max_entries * ADDRS_PER_ENTRY` addresses in total (800,000 at the default
/// capacity, about 26 MB of coordinate entries) whatever depth the hints
/// claim; a frame can carry a coordinate of about seventy addresses, which
/// unbounded would be about 116 MB. It is a total, not a per-entry cap: one
/// entry deeper than this is stored and charged its depth, and one deeper than
/// the whole bound is stored alone. The probation segment is bounded by count
/// instead ([`PROBATION_SHARE_DIVISOR`]) and adds up to that many entries of
/// any depth. Honest depth follows the mesh's hop diameter, so an honest cache
/// fills by entry count first. Deep coordinates still cache and route; they
/// shrink how many entries fit. The floor makes a shallow entry cost as much as a depth-fifteen one, so
/// shallow keys do not buy faster entry turnover. No measured basis.
pub const ADDRS_PER_ENTRY: usize = 16;

/// The weight an entry holding `coords` is charged against the address bound.
fn weight_of(coords: &TreeCoordinate) -> u64 {
    coords.entries().len().max(ADDRS_PER_ENTRY) as u64
}

/// The probation segment holds `max(1, max_entries / PROBATION_SHARE_DIVISOR)`
/// entries on top of the main segment's bound (1,562 at the default capacity).
///
/// Probation is where a hint goes when its writer cannot pay for it: the frame
/// that carried it still routes, and the entry survives until this many further
/// unpaid writes arrive without a frame using it. Larger keeps an honest new
/// destination behind a drained neighbour longer; smaller lets an unpaid flood
/// displace it sooner. It is bounded by count, not weight, so its memory is at
/// most this many entries times the deepest coordinate a frame can carry. No
/// measured basis.
pub const PROBATION_SHARE_DIVISOR: usize = 32;

/// What the writer of a hint can pay toward the cache space it takes, in units
/// of weight (coordinate addresses, at least [`ADDRS_PER_ENTRY`] per entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Funding {
    /// The writer can pay at most this much. A write is paid only if its whole
    /// charge fits.
    Upto(u64),
    /// The write is not charged: it is paid for by other means, such as a
    /// handshake this node started.
    Uncharged,
}

impl Funding {
    /// Whether this funding pays a charge of `weight` in full.
    fn covers(self, weight: u64) -> bool {
        match self {
            Funding::Upto(available) => weight <= available,
            Funding::Uncharged => true,
        }
    }
}

/// The part of the cache an entry is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment {
    /// The configured bound, where paid and verified entries live.
    Main,
    /// The allowance for unpaid new keys; it evicts only its own entries.
    Probation,
}

/// What a funded hint write did, and what it cost.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placed {
    /// The write's outcome, as for [`CoordCache::insert`].
    pub outcome: HintOutcome,
    /// The weight the write added to the main segment, which is what the
    /// writer pays. Never more than an `Upto` funding allowed.
    pub added_weight: u64,
    /// The segment the key is in after the write.
    pub segment: Segment,
    /// The funding could not pay for the write, so it did less than a paid
    /// write would: a new key went to probation, or a growing update of a main
    /// entry kept the old coordinates.
    pub unfunded: bool,
}

/// What a hint write did, which is the only place the precedence rule is
/// observable.
///
/// `#[must_use]` on purpose. A hint write can be refused, and a caller that
/// drops the outcome cannot tell a stored coordinate from a rejected one. It
/// also makes the compiler, rather than review, the thing that notices when a
/// write site is left on the hint path that should have been verified.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintOutcome {
    /// No entry existed; the hint was stored.
    Inserted,
    /// An entry existed and the hint replaced it with a different value.
    ///
    /// This is the security-interesting outcome. A destination's coordinates
    /// changing is ordinary when it moves in the tree and is also exactly what
    /// a poisoning looks like, so the two are not distinguishable here and the
    /// counter is a rate to watch rather than an alarm.
    Changed,
    /// An entry existed and the hint carried the same value.
    Unchanged,
    /// The hint was refused and the cache left as it was: the entry was
    /// verified and still within its verification window (for
    /// [`CoordCache::insert_stated`], only when the coordinates are the same
    /// or do not name the key), or no room could be made in main because only
    /// live-verified entries remain (a new key from
    /// [`CoordCache::insert_funded`] goes to probation instead, and an update
    /// from [`CoordCache::insert_stated`] is stored regardless), or (from
    /// [`CoordCache::insert_funded`]) the writer could not pay for an update
    /// that deepens a main entry.
    Rejected,
}

/// Which eviction index holds a slot's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// In `by_use`, keyed `(stamp, seq)`: a candidate victim.
    ByUse,
    /// In `parked`, keyed `(verified_until, seq)`: live-verified when filed,
    /// so eviction skips it until its verification lapses.
    Parked,
    /// In `probation`, keyed `(stamp, seq)` like `ByUse`.
    Probation,
}

impl Place {
    /// The segment this place belongs to.
    fn segment(self) -> Segment {
        match self {
            Place::ByUse | Place::Parked => Segment::Main,
            Place::Probation => Segment::Probation,
        }
    }
}

/// One cached entry and where the eviction index files it.
#[derive(Clone, Debug)]
struct Slot {
    entry: CacheEntry,
    /// The slot's key in the index `place` names. For `ByUse` the first half
    /// is the entry's `last_used` when it was filed; the entry may have been
    /// touched since, which eviction notices and corrects lazily.
    key: (u64, u64),
    place: Place,
    /// What the entry counts against the address bound; see [`weight_of`].
    /// This is the most the entry has weighed since it entered its segment:
    /// an update that makes it shallower does not lower it, so it is never
    /// below the weight the entry holds. In main it is what the entry has
    /// been charged, so making it deep again is not charged twice; in
    /// probation it is the least a promotion pays, so a shallow rewrite
    /// cannot make a deep destination cheap to promote.
    weight: u64,
}

/// Coordinate cache for routing decisions.
///
/// Maps node addresses to their tree coordinates, enabling data packets
/// to be routed without carrying coordinates in every packet. Populated
/// by SessionSetup packets.
///
/// Eviction takes the least recently used entry that is not live-verified,
/// found through an ordered index rather than a scan of the map, so an insert
/// at capacity costs O(log n) amortised. Touching an entry does no index
/// work: the index is corrected when eviction reaches a stale key. Ties are
/// broken by a per-cache insertion sequence, never by address, because peers
/// choose addresses.
///
/// The main segment is bounded by entries and by the coordinate addresses it
/// stores ([`ADDRS_PER_ENTRY`]); a write that would exceed either evicts until
/// it fits. A hint whose writer cannot pay for it goes to a probation segment
/// on top ([`PROBATION_SHARE_DIVISOR`]), which evicts only its own entries, so
/// an unpaid write never displaces a paid one and the cache can hold
/// `max_entries + max(1, max_entries / PROBATION_SHARE_DIVISOR)` entries.
///
/// `E` is the host's random source, which keys the map's hasher.
#[derive(Clone, Debug)]
pub struct CoordCache<E> {
    /// NodeAddr -> coordinates mapping.
    entries: HashMap<NodeAddr, Slot>,
    /// Entries eviction may take, oldest stamp first.
    by_use: BTreeMap<(u64, u64), NodeAddr>,
    /// Entries that were live-verified when eviction reached them, by the
    /// time their verification lapses.
    parked: BTreeMap<(u64, u64), NodeAddr>,
    /// The probation segment's entries, oldest stamp first.
    probation: BTreeMap<(u64, u64), NodeAddr>,
    /// Insertion sequence for index keys.
    seq: u64,
    /// Sum of the main segment's entry weights.
    stored_weight: u64,
    /// Maximum number of entries.
    max_entries: usize,
    /// Default TTL for entries (milliseconds).
    default_ttl_ms: u64,
    entropy: PhantomData<fn() -> E>,
    /// Entries visited by eviction scans, so tests can measure eviction work
    /// without timing it.
    #[cfg(any(test, feature = "test-hooks"))]
    eviction_examined: u64,
}

impl<E: EntropySource> CoordCache<E> {
    /// Create a new coordinate cache.
    pub fn new(max_entries: usize, default_ttl_ms: u64) -> Self {
        Self {
            entries: HashMap::with_capacity_and_hasher(
                max_entries.min(1000),
                KeyedHasher::new::<E>(),
            ),
            by_use: BTreeMap::new(),
            parked: BTreeMap::new(),
            probation: BTreeMap::new(),
            seq: 0,
            stored_weight: 0,
            max_entries,
            default_ttl_ms,
            entropy: PhantomData,
            #[cfg(any(test, feature = "test-hooks"))]
            eviction_examined: 0,
        }
    }

    /// Create a cache with default parameters.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_COORD_CACHE_SIZE, DEFAULT_COORD_CACHE_TTL_MS)
    }

    /// Get the maximum capacity.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Get the default TTL.
    pub fn default_ttl_ms(&self) -> u64 {
        self.default_ttl_ms
    }

    /// Set the default TTL.
    pub fn set_default_ttl_ms(&mut self, ttl_ms: u64) {
        self.default_ttl_ms = ttl_ms;
    }

    /// Insert or update a cache entry from an unauthenticated hint.
    ///
    /// **This, [`CoordCache::insert_funded`] and [`CoordCache::insert_stated`]
    /// are the only ways to write a coordinate learned off the wire, and this
    /// is deliberately the obvious name.** A hint never displaces an entry
    /// that a verified lookup established and whose verification has not yet
    /// aged out (see [`CacheEntry::is_verified`]), except a node's statement
    /// of its own coordinates through [`CoordCache::insert_stated`].
    /// Conferring trust requires asking for it by name, with
    /// [`CoordCache::insert_verified`].
    ///
    /// The write is not charged ([`Funding::Uncharged`]); a write a link peer
    /// must pay for goes through [`CoordCache::insert_funded`].
    pub fn insert(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) -> HintOutcome {
        let ttl_ms = self.default_ttl_ms;
        self.place_hint(
            addr,
            coords,
            current_time_ms,
            ttl_ms,
            Funding::Uncharged,
            false,
        )
        .outcome
    }

    /// Insert or update a cache entry from a hint its writer pays for.
    ///
    /// The charge is the weight the write adds to the main segment: a new
    /// key's weight, or what an update adds above the most the entry has been
    /// charged (nothing for an update no deeper than that). So an update that
    /// makes an entry shallower costs nothing and leaves its charge where it
    /// was, and a later update back to the old depth is free: a forged shallow
    /// rewrite cannot make the honest correction cost its writer anything. A
    /// write is paid only if `funding` covers the whole charge. Placement:
    ///
    /// - a paid new key goes to main, evicting by the main rule, or to
    ///   probation, charged nothing, if only live-verified entries remain;
    /// - an unpaid new key goes to probation, evicting only probation entries;
    /// - a paid write of a probation key promotes it to main, charged the
    ///   larger of the new weight and the most probation held, and nothing
    ///   else does (using an entry is no evidence: the first use of a new key
    ///   is the inserting frame's own routing);
    /// - a write of an expired key is placed as a new key's would be;
    /// - an unpaid update of a main entry beyond its charge keeps the old
    ///   coordinates;
    /// - an update of a probation entry is applied in place.
    ///
    /// The caller spends [`Placed::added_weight`] from the writer's budget.
    pub fn insert_funded(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        funding: Funding,
    ) -> Placed {
        let ttl_ms = self.default_ttl_ms;
        self.place_hint(addr, coords, current_time_ms, ttl_ms, funding, false)
    }

    /// Write the coordinates a node states for itself, filed under its
    /// address, from an authenticated message of a session with this node.
    ///
    /// Placed as [`CoordCache::insert_funded`] places a hint, with two
    /// differences, both for a node that has moved in the tree, where its
    /// own statement is newer than this node's lookup:
    ///
    /// - it replaces a live verified entry whose coordinates differ, making
    ///   it a hint and ending its verification window; equal coordinates
    ///   leave a verified entry as it is;
    /// - an update that deepens a main entry is stored even when the only
    ///   entries left to evict are live-verified, so the cache can then hold
    ///   more weight than its address bound, by at most one entry per
    ///   session.
    ///
    /// Coordinates that do not begin with `addr` are not the node's statement
    /// about itself, and are written as an ordinary hint, which yields to a
    /// verified entry.
    pub fn insert_stated(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        funding: Funding,
    ) -> Placed {
        let ttl_ms = self.default_ttl_ms;
        let stated = *coords.node_addr() == addr;
        self.place_hint(addr, coords, current_time_ms, ttl_ms, funding, stated)
    }

    /// Place a hint with an explicit TTL; see [`CoordCache::insert_funded`].
    /// `stated` places it as [`CoordCache::insert_stated`] describes.
    fn place_hint(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
        funding: Funding,
        stated: bool,
    ) -> Placed {
        let weight = weight_of(&coords);
        let placed = |outcome, added_weight, segment, unfunded| Placed {
            outcome,
            added_weight,
            segment,
            unfunded,
        };
        // An expired entry is no route, so a write of its key is placed as a
        // new key's would be. Updating it instead would let an unpaid deeper
        // write keep the expired entry, which the frame's own next-hop lookup
        // then removes, leaving the frame no route.
        if self
            .entries
            .get(&addr)
            .is_some_and(|slot| slot.entry.is_expired(current_time_ms))
        {
            self.remove_slot(&addr);
        }
        let Some(slot) = self.entries.get(&addr) else {
            if !funding.covers(weight) {
                self.make_probation_room();
                let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
                self.file_new(addr, entry, weight, Segment::Probation);
                return placed(HintOutcome::Inserted, 0, Segment::Probation, true);
            }
            // Eviction can decline to free a slot when every entry is a live
            // verified one, which is the case the hint must not be allowed to
            // force. A link peer's write then goes to probation, as an unpaid
            // one would, because the budget decides placement and never
            // whether the frame routes. An uncharged write is refused.
            if !self.make_room(weight, current_time_ms) {
                if let Funding::Upto(_) = funding {
                    self.make_probation_room();
                    let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
                    self.file_new(addr, entry, weight, Segment::Probation);
                    return placed(HintOutcome::Inserted, 0, Segment::Probation, false);
                }
                return placed(HintOutcome::Rejected, 0, Segment::Main, false);
            }
            let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
            self.file_new(addr, entry, weight, Segment::Main);
            return placed(HintOutcome::Inserted, weight, Segment::Main, false);
        };

        let differs = slot.entry.coords() != &coords;
        if slot.entry.is_verified(current_time_ms) && !(stated && differs) {
            return placed(HintOutcome::Rejected, 0, slot.place.segment(), false);
        }
        let outcome = if differs {
            HintOutcome::Changed
        } else {
            HintOutcome::Unchanged
        };
        let (segment, old_weight) = (slot.place.segment(), slot.weight);

        match segment {
            Segment::Probation if funding.covers(weight.max(old_weight)) => {
                // Promotion: the key moves to main and pays its whole weight,
                // or stays where it is, updated, if main has no room. It is
                // charged at least the most probation held for it, so a
                // shallow rewrite cannot promote a deep destination cheaply
                // and leave its honest coordinates an unpaid growth.
                let charge = weight.max(old_weight);
                let Some(mut slot) = self.remove_slot(&addr) else {
                    return placed(HintOutcome::Rejected, 0, segment, false);
                };
                slot.entry.update(coords, current_time_ms, ttl_ms);
                if self.make_room(charge, current_time_ms) {
                    self.file_new(addr, slot.entry, charge, Segment::Main);
                    placed(outcome, charge, Segment::Main, false)
                } else {
                    self.file_new(addr, slot.entry, charge, Segment::Probation);
                    placed(outcome, 0, Segment::Probation, false)
                }
            }
            Segment::Probation => {
                self.update_in_place(addr, coords, current_time_ms, ttl_ms, weight);
                placed(outcome, 0, Segment::Probation, false)
            }
            Segment::Main if weight <= old_weight => {
                self.update_in_place(addr, coords, current_time_ms, ttl_ms, weight);
                placed(outcome, 0, Segment::Main, false)
            }
            Segment::Main if !funding.covers(weight - old_weight) => {
                placed(HintOutcome::Rejected, 0, Segment::Main, true)
            }
            Segment::Main => {
                // A growing update makes room like a new key does. The entry
                // is taken out first so it cannot be its own victim, and goes
                // back unchanged if no room can be made, unless it is a
                // node's statement of its own coordinates, which is stored
                // regardless.
                let Some(mut slot) = self.remove_slot(&addr) else {
                    return placed(HintOutcome::Rejected, 0, segment, false);
                };
                if !self.make_room(weight, current_time_ms) && !stated {
                    self.file_new(addr, slot.entry, old_weight, Segment::Main);
                    return placed(HintOutcome::Rejected, 0, Segment::Main, false);
                }
                slot.entry.update(coords, current_time_ms, ttl_ms);
                self.file_new(addr, slot.entry, weight, Segment::Main);
                placed(outcome, weight - old_weight, Segment::Main, false)
            }
        }
    }

    /// Rewrite an existing entry's coordinates where it is, for an update
    /// that adds no weight to its segment's bound. The entry keeps the larger
    /// of its weight and the new one.
    fn update_in_place(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
        weight: u64,
    ) {
        let Some(slot) = self.entries.get_mut(&addr) else {
            return;
        };
        slot.entry.update(coords, current_time_ms, ttl_ms);
        let charged = slot.weight.max(weight);
        if slot.place.segment() == Segment::Main {
            self.stored_weight = self.stored_weight - slot.weight + charged;
        }
        slot.weight = charged;
        self.refile(addr);
    }

    /// Insert or update a cache entry from a lookup whose proof was verified.
    ///
    /// Unconditional: a verified value displaces whatever was there, which is
    /// the point — it is how a poisoned entry gets corrected. It makes room
    /// within the cache's bounds if it can, and is stored even if it cannot
    /// (only this node's own lookups write here, so the excess is bounded by
    /// them).
    pub fn insert_verified(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) {
        let weight = weight_of(&coords);
        let ttl_ms = self.default_ttl_ms;
        let entry = match self.remove_slot(&addr) {
            Some(mut slot) => {
                slot.entry.update_verified(coords, current_time_ms, ttl_ms);
                slot.entry
            }
            None => CacheEntry::new_verified(coords, current_time_ms, ttl_ms),
        };
        let _ = self.make_room(weight, current_time_ms);
        self.file_new(addr, entry, weight, Segment::Main);
    }

    /// Insert or update a verified cache entry with path MTU information.
    ///
    /// Used by discovery response handling to store the discovered path MTU
    /// alongside the target's coordinates. Verified for the same reason
    /// [`CoordCache::insert_verified`] is: the caller checked the proof.
    pub fn insert_verified_with_path_mtu(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        path_mtu: u16,
    ) {
        self.insert_verified(addr, coords, current_time_ms);
        if let Some(slot) = self.entries.get_mut(&addr) {
            slot.entry.set_path_mtu(path_mtu);
        }
    }

    /// Insert with a custom TTL.
    ///
    /// Eviction orders entries by last use, not by expiry, so an entry with a
    /// short TTL is not evicted ahead of an older one with a long TTL.
    pub fn insert_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) -> HintOutcome {
        self.place_hint(
            addr,
            coords,
            current_time_ms,
            ttl_ms,
            Funding::Uncharged,
            false,
        )
        .outcome
    }

    /// Look up coordinates for an address (without touching).
    pub fn get(&self, addr: &NodeAddr, current_time_ms: u64) -> Option<&TreeCoordinate> {
        self.entries.get(addr).and_then(|slot| {
            if slot.entry.is_expired(current_time_ms) {
                None
            } else {
                Some(slot.entry.coords())
            }
        })
    }

    /// Look up coordinates and refresh (update last_used and extend TTL).
    ///
    /// Does no index work when it only touches, so the forwarding path pays
    /// nothing for the eviction index.
    pub fn get_and_touch(
        &mut self,
        addr: &NodeAddr,
        current_time_ms: u64,
    ) -> Option<&TreeCoordinate> {
        // Check and remove if expired
        if self
            .entries
            .get(addr)
            .is_some_and(|slot| slot.entry.is_expired(current_time_ms))
        {
            self.remove_slot(addr);
            return None;
        }

        // Refresh TTL and return
        let ttl_ms = self.default_ttl_ms;
        let slot = self.entries.get_mut(addr)?;
        slot.entry.refresh(current_time_ms, ttl_ms);
        Some(slot.entry.coords())
    }

    /// Get the full cache entry.
    pub fn get_entry(&self, addr: &NodeAddr) -> Option<&CacheEntry> {
        self.entries.get(addr).map(|slot| &slot.entry)
    }

    /// Remove an entry.
    pub fn remove(&mut self, addr: &NodeAddr) -> Option<CacheEntry> {
        self.remove_slot(addr).map(|slot| slot.entry)
    }

    /// Demote an entry to an unverified hint, keeping its coordinates and TTL.
    ///
    /// The entry goes on routing, but a hint may now replace it. Returns
    /// whether an entry existed.
    pub fn demote(&mut self, addr: &NodeAddr) -> bool {
        match self.entries.get_mut(addr) {
            Some(slot) => {
                slot.entry.mark_hint();
                if slot.place == Place::Parked {
                    self.refile(*addr);
                }
                true
            }
            None => false,
        }
    }

    /// Forget the path MTU stored with an entry, keeping the entry.
    pub fn clear_path_mtu(&mut self, addr: &NodeAddr) {
        if let Some(slot) = self.entries.get_mut(addr) {
            slot.entry.clear_path_mtu();
        }
    }

    /// Check if an address is cached (and not expired).
    pub fn contains(&self, addr: &NodeAddr, current_time_ms: u64) -> bool {
        self.get(addr, current_time_ms).is_some()
    }

    /// Number of entries (including expired).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over non-expired entries.
    pub fn iter(&self, current_time_ms: u64) -> impl Iterator<Item = (&NodeAddr, &CacheEntry)> {
        self.entries
            .iter()
            .map(|(addr, slot)| (addr, &slot.entry))
            .filter(move |(_, entry)| !entry.is_expired(current_time_ms))
    }

    /// Remove all expired entries.
    pub fn purge_expired(&mut self, current_time_ms: u64) -> usize {
        self.retain_entries(|entry| !entry.is_expired(current_time_ms))
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_use.clear();
        self.parked.clear();
        self.probation.clear();
        self.stored_weight = 0;
    }

    /// Drop entries whose cached destination ancestry contains the given
    /// `NodeAddr`.
    ///
    /// Used at parent-position-change sites: when our own position in the
    /// tree changes, destinations downstream of us (whose cached coordinates
    /// embed our previous prefix) have stale path information and must be
    /// re-learned. Entries whose ancestry does not include `node_addr` are
    /// unaffected by the local position change and are retained.
    ///
    /// Returns the count of entries removed.
    pub fn invalidate_via_node(&mut self, node_addr: &NodeAddr) -> usize {
        self.retain_entries(|entry| !entry.coords().contains(node_addr))
    }

    /// Drop entries whose cached destination `root_id` differs from
    /// `current_root`.
    ///
    /// Used at root-change sites (become_root, root handover via
    /// TreeAnnounce). `find_next_hop` returns `None` for any destination
    /// whose root does not match the local root, so entries from a stale
    /// root cannot route and would otherwise occupy cache slots until
    /// TTL expiry.
    ///
    /// Returns the count of entries removed.
    pub fn invalidate_other_roots(&mut self, current_root: &NodeAddr) -> usize {
        self.retain_entries(|entry| entry.coords().root_id() == current_root)
    }

    /// Keep only the entries `keep` accepts, dropping the others' index keys.
    /// Returns the count removed.
    fn retain_entries(&mut self, mut keep: impl FnMut(&CacheEntry) -> bool) -> usize {
        let len_before = self.entries.len();
        let by_use = &mut self.by_use;
        let parked = &mut self.parked;
        let probation = &mut self.probation;
        let stored_weight = &mut self.stored_weight;
        self.entries.retain(|_, slot| {
            if keep(&slot.entry) {
                return true;
            }
            match slot.place {
                Place::ByUse => by_use.remove(&slot.key),
                Place::Parked => parked.remove(&slot.key),
                Place::Probation => probation.remove(&slot.key),
            };
            if slot.place.segment() == Segment::Main {
                *stored_weight -= slot.weight;
            }
            false
        });
        len_before - self.entries.len()
    }

    /// Next index key with the given first half.
    fn next_key(&mut self, first: u64) -> (u64, u64) {
        self.seq += 1;
        (first, self.seq)
    }

    /// Add a slot for a key not in the map, filed in `segment` for eviction by
    /// last use.
    fn file_new(&mut self, addr: NodeAddr, entry: CacheEntry, weight: u64, segment: Segment) {
        let key = self.next_key(entry.last_used());
        let place = match segment {
            Segment::Main => {
                self.stored_weight += weight;
                self.by_use.insert(key, addr);
                Place::ByUse
            }
            Segment::Probation => {
                self.probation.insert(key, addr);
                Place::Probation
            }
        };
        self.entries.insert(
            addr,
            Slot {
                entry,
                key,
                place,
                weight,
            },
        );
    }

    /// Entries in the main segment.
    fn main_len(&self) -> usize {
        self.by_use.len() + self.parked.len()
    }

    /// The most entries the probation segment holds.
    fn probation_bound(&self) -> usize {
        (self.max_entries / PROBATION_SHARE_DIVISOR).max(1)
    }

    /// Evict probation entries until one more fits. Probation holds no
    /// verified entries, so this always succeeds.
    fn make_probation_room(&mut self) {
        let bound = 2 * self.probation.len() + 1;
        let mut visited = 0;
        while self.probation.len() >= self.probation_bound() {
            let Some((stamp, addr)) = self.probation.pop_first() else {
                return;
            };
            self.note_examined();
            visited += 1;
            debug_assert!(
                visited <= bound,
                "probation eviction visited a key twice over"
            );
            let used = self.entries.get(&addr).map(|slot| slot.entry.last_used());
            match used {
                // Used by a frame since it was filed: restamp, as main does.
                Some(used) if used != stamp.0 => {
                    let key = self.next_key(used);
                    self.probation.insert(key, addr);
                    if let Some(slot) = self.entries.get_mut(&addr) {
                        slot.key = key;
                    }
                }
                _ => {
                    self.entries.remove(&addr);
                }
            }
        }
    }

    /// The most weight the cache may store.
    fn weight_bound(&self) -> u64 {
        (self.max_entries as u64).saturating_mul(ADDRS_PER_ENTRY as u64)
    }

    /// Evict until one more entry of `weight` fits both bounds. Returns
    /// whether it fits; it does not when only live-verified entries remain,
    /// and then nothing is evicted: the victims found are put back, so a
    /// refused write leaves every entry where it was.
    ///
    /// An entry heavier than the whole address bound fits once main is
    /// otherwise empty, so any depth a frame can carry can still be stored.
    fn make_room(&mut self, weight: u64, current_time_ms: u64) -> bool {
        let weight = weight.min(self.weight_bound());
        let (mut len, mut stored) = (self.main_len(), self.stored_weight);
        let mut victims = Vec::new();
        while len >= self.max_entries || stored + weight > self.weight_bound() {
            let Some(addr) = self.next_victim(current_time_ms) else {
                for addr in victims {
                    if let Some(slot) = self.entries.get(&addr) {
                        self.by_use.insert(slot.key, addr);
                    }
                }
                return false;
            };
            len -= 1;
            stored -= self.entries.get(&addr).map_or(0, |slot| slot.weight);
            victims.push(addr);
        }
        for addr in victims {
            if let Some(slot) = self.entries.remove(&addr) {
                self.stored_weight -= slot.weight;
            }
        }
        true
    }

    /// Re-file an existing slot in `by_use` at its entry's current last use,
    /// after a write changed it.
    fn refile(&mut self, addr: NodeAddr) {
        let Some(slot) = self.entries.get(&addr) else {
            return;
        };
        let (old, place, used) = (slot.key, slot.place, slot.entry.last_used());
        let key = self.next_key(used);
        let place = match place {
            Place::ByUse | Place::Parked => {
                if place == Place::Parked {
                    self.parked.remove(&old);
                } else {
                    self.by_use.remove(&old);
                }
                self.by_use.insert(key, addr);
                Place::ByUse
            }
            Place::Probation => {
                self.probation.remove(&old);
                self.probation.insert(key, addr);
                Place::Probation
            }
        };
        if let Some(slot) = self.entries.get_mut(&addr) {
            slot.key = key;
            slot.place = place;
        }
    }

    /// Remove a slot and its index key.
    fn remove_slot(&mut self, addr: &NodeAddr) -> Option<Slot> {
        let slot = self.entries.remove(addr)?;
        match slot.place {
            Place::ByUse => self.by_use.remove(&slot.key),
            Place::Parked => self.parked.remove(&slot.key),
            Place::Probation => self.probation.remove(&slot.key),
        };
        if slot.place.segment() == Segment::Main {
            self.stored_weight -= slot.weight;
        }
        Some(slot)
    }

    /// Find the least recently used entry that is not live-verified, and take
    /// its key out of `by_use`; the caller removes the entry, or files the key
    /// back under `slot.key`. Returns `None` when there is none.
    ///
    /// Restricting the victim pool is what stops a hint flood from
    /// manufacturing the empty slot the precedence rule depends on: without
    /// it, an attacker fills the cache with hints until a verified entry
    /// becomes the LRU, evicts it, and then plants into a slot that is now
    /// empty and so accepts an ordinary first write. Declining to evict is
    /// the correct outcome when every entry is live-verified; the caller
    /// refuses the hint rather than growing past the cap.
    ///
    /// Each key popped is either the victim, an entry touched since it was
    /// filed (restamped at its last use, which the touch paid for), or a
    /// live-verified entry (parked until its verification lapses). So the
    /// work is amortised over the touches and verified writes that caused it.
    fn next_victim(&mut self, current_time_ms: u64) -> Option<NodeAddr> {
        // Entries whose verification has lapsed are victims again.
        while let Some((&(until, _), _)) = self.parked.first_key_value() {
            if until >= current_time_ms {
                break;
            }
            let Some((_, addr)) = self.parked.pop_first() else {
                break;
            };
            self.note_examined();
            let used = self.entries.get(&addr).map(|s| s.entry.last_used());
            let key = self.next_key(used.unwrap_or(0));
            self.by_use.insert(key, addr);
            if let Some(slot) = self.entries.get_mut(&addr) {
                slot.key = key;
                slot.place = Place::ByUse;
            }
        }

        let bound = 2 * self.by_use.len() + 1;
        let mut visited = 0;
        while let Some((stamp, addr)) = self.by_use.pop_first() {
            self.note_examined();
            visited += 1;
            debug_assert!(visited <= bound, "eviction visited a key twice over");
            let Some(slot) = self.entries.get(&addr) else {
                debug_assert!(false, "an index key outlived its entry");
                continue;
            };
            let (used, verified, until) = (
                slot.entry.last_used(),
                slot.entry.is_verified(current_time_ms),
                slot.entry.verified_until(),
            );
            if used != stamp.0 {
                let key = self.next_key(used);
                self.by_use.insert(key, addr);
                if let Some(slot) = self.entries.get_mut(&addr) {
                    slot.key = key;
                }
                continue;
            }
            if verified {
                let key = self.next_key(until);
                self.parked.insert(key, addr);
                if let Some(slot) = self.entries.get_mut(&addr) {
                    slot.key = key;
                    slot.place = Place::Parked;
                }
                continue;
            }
            return Some(addr);
        }
        None
    }

    /// Count one entry visited by an eviction scan; a no-op outside tests.
    #[inline(always)]
    fn note_examined(&mut self) {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            self.eviction_examined += 1;
        }
    }

    /// Total entries eviction has visited since the cache was created.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn eviction_examined(&self) -> u64 {
        self.eviction_examined
    }

    /// The segment `addr` is in, if it is cached.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn segment_of(&self, addr: &NodeAddr) -> Option<Segment> {
        self.entries.get(addr).map(|slot| slot.place.segment())
    }

    /// Entries in the probation segment.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn probation_len(&self) -> usize {
        self.probation.len()
    }

    /// Total coordinate addresses stored across all entries, expired or not.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn stored_addrs(&self) -> usize {
        self.entries
            .values()
            .map(|s| s.entry.coords().entries().len())
            .sum()
    }

    /// Get cache statistics.
    pub fn stats(&self, current_time_ms: u64) -> CacheStats {
        let mut expired = 0;
        let mut total_age = 0u64;

        for entry in self.entries.values().map(|slot| &slot.entry) {
            if entry.is_expired(current_time_ms) {
                expired += 1;
            }
            total_age += entry.age(current_time_ms);
        }

        CacheStats {
            entries: self.entries.len(),
            max_entries: self.max_entries,
            expired,
            avg_age_ms: if self.entries.is_empty() {
                0
            } else {
                total_age / self.entries.len() as u64
            },
        }
    }
}

impl<E: EntropySource> Default for CoordCache<E> {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
#[path = "tests/coord_cache.rs"]
mod tests;
