//! Coordinate cache for routing decisions.
//!
//! Maps node addresses to their tree coordinates, enabling data packets
//! to be routed without carrying coordinates in every packet. Populated
//! by SessionSetup packets.

use std::collections::HashMap;

use super::CacheStats;
use super::entry::CacheEntry;
use crate::NodeAddr;
use crate::proto::stp::TreeCoordinate;

/// Default maximum entries in coordinate cache.
pub const DEFAULT_COORD_CACHE_SIZE: usize = 50_000;

/// Default TTL for coordinate cache entries (5 minutes in milliseconds).
pub const DEFAULT_COORD_CACHE_TTL_MS: u64 = 300_000;

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
    /// An entry existed, was verified and still within its verification
    /// window, so the hint was refused.
    Rejected,
}

/// Coordinate cache for routing decisions.
///
/// Maps node addresses to their tree coordinates, enabling data packets
/// to be routed without carrying coordinates in every packet. Populated
/// by SessionSetup packets.
#[derive(Clone, Debug)]
pub struct CoordCache {
    /// NodeAddr -> coordinates mapping.
    entries: HashMap<NodeAddr, CacheEntry>,
    /// Maximum number of entries.
    max_entries: usize,
    /// Default TTL for entries (milliseconds).
    default_ttl_ms: u64,
}

impl CoordCache {
    /// Create a new coordinate cache.
    pub fn new(max_entries: usize, default_ttl_ms: u64) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(1000)),
            max_entries,
            default_ttl_ms,
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
    /// **This is the only way to write a coordinate learned off the wire, and
    /// it is deliberately the obvious name.** A hint never displaces an entry
    /// that a verified lookup established and whose verification has not yet
    /// aged out; see [`CacheEntry::is_verified`]. Conferring trust requires
    /// asking for it by name, with [`CoordCache::insert_verified`].
    pub fn insert(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) -> HintOutcome {
        self.insert_hint_with_ttl(addr, coords, current_time_ms, self.default_ttl_ms)
    }

    /// Insert or update a cache entry from a hint, with an explicit TTL.
    fn insert_hint_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) -> HintOutcome {
        if let Some(entry) = self.entries.get_mut(&addr) {
            if entry.is_verified(current_time_ms) {
                return HintOutcome::Rejected;
            }
            let changed = entry.coords() != &coords;
            entry.update(coords, current_time_ms, ttl_ms);
            return if changed {
                HintOutcome::Changed
            } else {
                HintOutcome::Unchanged
            };
        }

        // Evict if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_one(current_time_ms);
        }

        // Eviction can decline to free a slot when every entry is a live
        // verified one, which is the case the hint must not be allowed to
        // force. Refuse rather than grow past the cap.
        if self.entries.len() >= self.max_entries {
            return HintOutcome::Rejected;
        }

        let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
        self.entries.insert(addr, entry);
        HintOutcome::Inserted
    }

    /// Insert or update a cache entry from a lookup whose proof was verified.
    ///
    /// Unconditional: a verified value displaces whatever was there, which is
    /// the point — it is how a poisoned entry gets corrected.
    pub fn insert_verified(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
    ) {
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.update_verified(coords, current_time_ms, self.default_ttl_ms);
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_one(current_time_ms);
        }

        let entry = CacheEntry::new_verified(coords, current_time_ms, self.default_ttl_ms);
        self.entries.insert(addr, entry);
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
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.update_verified(coords, current_time_ms, self.default_ttl_ms);
            entry.set_path_mtu(path_mtu);
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_one(current_time_ms);
        }

        let mut entry = CacheEntry::new_verified(coords, current_time_ms, self.default_ttl_ms);
        entry.set_path_mtu(path_mtu);
        self.entries.insert(addr, entry);
    }

    /// Insert with a custom TTL.
    pub fn insert_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) -> HintOutcome {
        self.insert_hint_with_ttl(addr, coords, current_time_ms, ttl_ms)
    }

    /// Look up coordinates for an address (without touching).
    pub fn get(&self, addr: &NodeAddr, current_time_ms: u64) -> Option<&TreeCoordinate> {
        self.entries.get(addr).and_then(|entry| {
            if entry.is_expired(current_time_ms) {
                None
            } else {
                Some(entry.coords())
            }
        })
    }

    /// Look up coordinates and refresh (update last_used and extend TTL).
    pub fn get_and_touch(
        &mut self,
        addr: &NodeAddr,
        current_time_ms: u64,
    ) -> Option<&TreeCoordinate> {
        // Check and remove if expired
        if let Some(entry) = self.entries.get(addr)
            && entry.is_expired(current_time_ms)
        {
            self.entries.remove(addr);
            return None;
        }

        // Refresh TTL and return
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.refresh(current_time_ms, self.default_ttl_ms);
            Some(entry.coords())
        } else {
            None
        }
    }

    /// Get the full cache entry.
    pub fn get_entry(&self, addr: &NodeAddr) -> Option<&CacheEntry> {
        self.entries.get(addr)
    }

    /// Remove an entry.
    pub fn remove(&mut self, addr: &NodeAddr) -> Option<CacheEntry> {
        self.entries.remove(addr)
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
            .filter(move |(_, entry)| !entry.is_expired(current_time_ms))
    }

    /// Remove all expired entries.
    pub fn purge_expired(&mut self, current_time_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| !entry.is_expired(current_time_ms));
        before - self.entries.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
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
        let len_before = self.entries.len();
        self.entries
            .retain(|_, entry| !entry.coords().contains(node_addr));
        len_before - self.entries.len()
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
        let len_before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.coords().root_id() == current_root);
        len_before - self.entries.len()
    }

    /// Evict one entry (expired first, then LRU).
    fn evict_one(&mut self, current_time_ms: u64) {
        // First try to evict an expired entry
        let expired_key = self
            .entries
            .iter()
            .find(|(_, e)| e.is_expired(current_time_ms))
            .map(|(k, _)| *k);

        if let Some(key) = expired_key {
            self.entries.remove(&key);
            return;
        }

        // Otherwise evict the LRU among entries that are not live-verified.
        //
        // Restricting the victim pool is what stops a hint flood from
        // manufacturing the empty slot the precedence rule depends on: without
        // it, an attacker fills the cache with hints until a verified entry
        // becomes the LRU, evicts it, and then plants into a slot that is now
        // empty and so accepts an ordinary first write. Declining to evict is
        // the correct outcome when every entry is live-verified; the caller
        // refuses the hint rather than growing past the cap.
        let lru_key = self
            .entries
            .iter()
            .filter(|(_, e)| !e.is_verified(current_time_ms))
            .max_by_key(|(_, e)| e.idle_time(current_time_ms))
            .map(|(k, _)| *k);

        if let Some(key) = lru_key {
            self.entries.remove(&key);
        }
    }

    /// Get cache statistics.
    pub fn stats(&self, current_time_ms: u64) -> CacheStats {
        let mut expired = 0;
        let mut total_age = 0u64;

        for entry in self.entries.values() {
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

impl Default for CoordCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::entry::VERIFIED_TTL_MS;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

    #[test]
    fn test_coord_cache_basic() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        let _ = cache.insert(addr, coords.clone(), 0);

        assert!(cache.contains(&addr, 0));
        assert_eq!(cache.get(&addr, 0), Some(&coords));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_coord_cache_expiry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        let _ = cache.insert(addr, coords, 0);

        assert!(cache.contains(&addr, 500));
        assert!(!cache.contains(&addr, 1500));
    }

    #[test]
    fn test_coord_cache_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        let _ = cache.insert(addr, make_coords(&[1, 2, 0]), 500);

        assert_eq!(cache.len(), 1);
        let coords = cache.get(&addr, 500).unwrap();
        assert_eq!(coords.depth(), 2);
    }

    #[test]
    fn test_coord_cache_eviction() {
        let mut cache = CoordCache::new(2, 10000);

        let addr1 = make_node_addr(1);
        let addr2 = make_node_addr(2);
        let addr3 = make_node_addr(3);

        let _ = cache.insert(addr1, make_coords(&[1, 0]), 0);
        let _ = cache.insert(addr2, make_coords(&[2, 0]), 100);

        // Touch addr2 to make it more recent
        let _ = cache.get_and_touch(&addr2, 200);

        // Insert addr3, should evict addr1 (LRU)
        let _ = cache.insert(addr3, make_coords(&[3, 0]), 300);

        assert!(!cache.contains(&addr1, 300));
        assert!(cache.contains(&addr2, 300));
        assert!(cache.contains(&addr3, 300));
    }

    #[test]
    fn test_coord_cache_evict_expired_first() {
        let mut cache = CoordCache::new(2, 100);

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

        // At time 150, addr1 is expired, addr2 is not
        let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 150);

        // addr1 should be evicted (expired), not addr2 (LRU but not expired)
        assert!(!cache.contains(&make_node_addr(1), 150));
        assert!(cache.contains(&make_node_addr(2), 150));
        assert!(cache.contains(&make_node_addr(3), 150));
    }

    #[test]
    fn test_coord_cache_purge_expired() {
        let mut cache = CoordCache::new(100, 100);

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0); // expires at 100
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50); // expires at 150
        let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 200); // expires at 300

        assert_eq!(cache.len(), 3);

        let purged = cache.purge_expired(151); // both addr1 and addr2 expired

        // Entry 1 and 2 expired, entry 3 still valid
        assert_eq!(purged, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&make_node_addr(3), 151));
    }

    #[test]
    fn test_coord_cache_stats() {
        let mut cache = CoordCache::new(100, 100);

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

        let stats = cache.stats(150);

        assert_eq!(stats.entries, 2);
        assert_eq!(stats.max_entries, 100);
        assert_eq!(stats.expired, 1); // addr1 expired
        assert!(stats.avg_age_ms > 0);
    }

    #[test]
    fn test_coord_cache_insert_with_ttl() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);

        // Should expire at 200, not the default 1000
        assert!(cache.contains(&addr, 100));
        assert!(!cache.contains(&addr, 201));
    }

    #[test]
    fn test_coord_cache_insert_with_ttl_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);
        let _ = cache.insert_with_ttl(addr, make_coords(&[1, 2, 0]), 100, 300);

        assert_eq!(cache.len(), 1);
        let coords = cache.get(&addr, 100).unwrap();
        assert_eq!(coords.depth(), 2);
        // New TTL: 100 + 300 = 400
        assert!(cache.contains(&addr, 399));
        assert!(!cache.contains(&addr, 401));
    }

    #[test]
    fn test_coord_cache_get_and_touch_removes_expired() {
        let mut cache = CoordCache::new(100, 100);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        // Entry expired at time 200
        let result = cache.get_and_touch(&addr, 200);
        assert!(result.is_none());
        // Entry should be removed from the map
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_coord_cache_get_entry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 500);

        let entry = cache.get_entry(&addr).unwrap();
        assert_eq!(entry.created_at(), 500);
        assert_eq!(entry.expires_at(), 1500);

        assert!(cache.get_entry(&make_node_addr(99)).is_none());
    }

    #[test]
    fn test_coord_cache_remove() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        let removed = cache.remove(&addr);
        assert!(removed.is_some());
        assert_eq!(cache.len(), 0);

        // Removing again returns None
        assert!(cache.remove(&addr).is_none());
    }

    #[test]
    fn test_coord_cache_clear_and_is_empty() {
        let mut cache = CoordCache::new(100, 1000);

        assert!(cache.is_empty());

        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_coord_cache_default() {
        let cache = CoordCache::default();

        assert_eq!(cache.max_entries(), DEFAULT_COORD_CACHE_SIZE);
        assert_eq!(cache.default_ttl_ms(), DEFAULT_COORD_CACHE_TTL_MS);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_coord_cache_set_default_ttl() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.set_default_ttl_ms(200);
        assert_eq!(cache.default_ttl_ms(), 200);

        let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
        // New TTL applies: expires at 200
        assert!(cache.contains(&addr, 100));
        assert!(!cache.contains(&addr, 201));
    }

    #[test]
    fn test_coord_cache_stats_empty() {
        let cache = CoordCache::new(100, 1000);
        let stats = cache.stats(0);

        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, 100);
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.avg_age_ms, 0);
    }

    // ===== Surgical invalidation tests =====

    #[test]
    fn test_invalidate_via_node_at_self_depth() {
        // Entry whose own NodeAddr (depth 0) is the invalidation target.
        let mut cache = CoordCache::new(100, 1000);
        let target = make_node_addr(1);

        let _ = cache.insert(target, make_coords(&[1, 0]), 0);
        assert_eq!(cache.len(), 1);

        let removed = cache.invalidate_via_node(&target);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_invalidate_via_node_interior() {
        // Entry whose ancestry contains the target in the interior of the path.
        let mut cache = CoordCache::new(100, 1000);
        let dest = make_node_addr(5);
        // Path: 5 -> 3 -> 1 -> 0 (root). Target 3 appears at depth 1.
        let _ = cache.insert(dest, make_coords(&[5, 3, 1, 0]), 0);

        let removed = cache.invalidate_via_node(&make_node_addr(3));
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_invalidate_via_node_absent() {
        // Entry whose ancestry does NOT contain the target must be retained.
        let mut cache = CoordCache::new(100, 1000);
        let dest = make_node_addr(5);
        let _ = cache.insert(dest, make_coords(&[5, 3, 1, 0]), 0);

        let removed = cache.invalidate_via_node(&make_node_addr(99));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&dest, 0));
    }

    #[test]
    fn test_invalidate_via_node_empty_cache() {
        let mut cache = CoordCache::new(100, 1000);
        let removed = cache.invalidate_via_node(&make_node_addr(1));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_invalidate_other_roots_current_root_kept() {
        let mut cache = CoordCache::new(100, 1000);
        // Entries rooted at addr(0)
        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_invalidate_other_roots_different_root_dropped() {
        let mut cache = CoordCache::new(100, 1000);
        // Three entries rooted at addr(0), one rooted at addr(9)
        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);
        let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 0);
        let _ = cache.insert(make_node_addr(4), make_coords(&[4, 9]), 0);

        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 3);
        assert!(!cache.contains(&make_node_addr(4), 0));
        assert!(cache.contains(&make_node_addr(1), 0));
    }

    #[test]
    fn test_invalidate_other_roots_all_match() {
        let mut cache = CoordCache::new(100, 1000);
        let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_invalidate_other_roots_empty_cache() {
        let mut cache = CoordCache::new(100, 1000);
        let removed = cache.invalidate_other_roots(&make_node_addr(0));
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_hint_does_not_displace_a_live_verified_entry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let good = make_coords(&[1, 0]);
        let forged = make_coords(&[1, 2, 0]);

        cache.insert_verified(addr, good.clone(), 0);
        assert_eq!(cache.insert(addr, forged, 10), HintOutcome::Rejected);
        assert_eq!(
            cache.get(&addr, 10),
            Some(&good),
            "the verified value must survive the hint"
        );
    }

    #[test]
    fn a_verified_write_displaces_a_hint() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let hint = make_coords(&[1, 2, 0]);
        let good = make_coords(&[1, 0]);

        assert_eq!(cache.insert(addr, hint, 0), HintOutcome::Inserted);
        cache.insert_verified(addr, good.clone(), 10);
        assert_eq!(
            cache.get(&addr, 10),
            Some(&good),
            "a proof must be able to correct a poisoned entry"
        );
    }

    #[test]
    fn verification_ages_out_so_a_stale_verified_entry_stops_refusing_hints() {
        let mut cache = CoordCache::new(100, u64::MAX / 4);
        let addr = make_node_addr(1);
        cache.insert_verified(addr, make_coords(&[1, 0]), 0);

        // Inside the window: refused.
        assert_eq!(
            cache.insert(addr, make_coords(&[1, 2, 0]), VERIFIED_TTL_MS),
            HintOutcome::Rejected
        );
        // One millisecond past it: accepted, so a destination that genuinely
        // moved is not locked out forever by a verification nobody renews.
        let moved = make_coords(&[1, 3, 0]);
        assert_eq!(
            cache.insert(addr, moved.clone(), VERIFIED_TTL_MS + 1),
            HintOutcome::Changed
        );
        assert_eq!(cache.get(&addr, VERIFIED_TTL_MS + 1), Some(&moved));
    }

    #[test]
    fn ordinary_traffic_does_not_extend_the_verification_window() {
        // The entry TTL has to be long enough that the touches below keep the
        // entry alive; the test is about the verification clock, not expiry.
        let mut cache = CoordCache::new(100, VERIFIED_TTL_MS);
        let addr = make_node_addr(1);
        cache.insert_verified(addr, make_coords(&[1, 0]), 0);

        // Touch it repeatedly the way forwarding does, right up to the edge.
        for t in [100, 1000, 100_000, VERIFIED_TTL_MS] {
            let _ = cache.get_and_touch(&addr, t);
        }

        // The entry is alive but its verification has aged out on its own
        // clock, which is the whole point of keeping the two clocks separate.
        assert_eq!(
            cache.insert(addr, make_coords(&[1, 2, 0]), VERIFIED_TTL_MS + 1),
            HintOutcome::Changed,
            "refresh must not carry the verification forward"
        );
    }

    #[test]
    fn eviction_prefers_an_unverified_victim_over_a_verified_one() {
        let mut cache = CoordCache::new(2, 1_000_000);
        let verified = make_node_addr(1);
        let hint = make_node_addr(2);
        let newcomer = make_node_addr(3);

        // The verified entry is the least recently used, so an unrestricted
        // LRU would take it. That is exactly the eviction an attacker would
        // drive to manufacture an empty slot.
        cache.insert_verified(verified, make_coords(&[1, 0]), 0);
        assert_eq!(
            cache.insert(hint, make_coords(&[2, 0]), 100),
            HintOutcome::Inserted
        );
        assert_eq!(
            cache.insert(newcomer, make_coords(&[3, 0]), 200),
            HintOutcome::Inserted
        );

        assert!(
            cache.contains(&verified, 200),
            "the verified entry must not be the eviction victim"
        );
        assert!(
            !cache.contains(&hint, 200),
            "the unverified entry should have been evicted instead"
        );
    }

    #[test]
    fn a_cache_full_of_verified_entries_refuses_a_hint_rather_than_evicting_one() {
        let mut cache = CoordCache::new(2, 1_000_000);
        cache.insert_verified(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert_verified(make_node_addr(2), make_coords(&[2, 0]), 0);

        assert_eq!(
            cache.insert(make_node_addr(3), make_coords(&[3, 0]), 10),
            HintOutcome::Rejected
        );
        assert!(cache.contains(&make_node_addr(1), 10));
        assert!(cache.contains(&make_node_addr(2), 10));
    }
}
