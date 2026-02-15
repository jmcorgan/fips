//! Coordinate cache for routing decisions.
//!
//! Maps node addresses to their tree coordinates, enabling data packets
//! to be routed without carrying coordinates in every packet. Populated
//! by SessionSetup packets.

use std::collections::HashMap;

use super::entry::CacheEntry;
use super::CacheStats;
use crate::tree::TreeCoordinate;
use crate::NodeAddr;

/// Default maximum entries in coordinate cache.
pub const DEFAULT_COORD_CACHE_SIZE: usize = 50_000;

/// Default TTL for coordinate cache entries (5 minutes in milliseconds).
pub const DEFAULT_COORD_CACHE_TTL_MS: u64 = 300_000;

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

    /// Insert or update a cache entry.
    pub fn insert(&mut self, addr: NodeAddr, coords: TreeCoordinate, current_time_ms: u64) {
        // Update existing entry if present
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.update(coords, current_time_ms, self.default_ttl_ms);
            return;
        }

        // Evict if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_one(current_time_ms);
        }

        let entry = CacheEntry::new(coords, current_time_ms, self.default_ttl_ms);
        self.entries.insert(addr, entry);
    }

    /// Insert with a custom TTL.
    pub fn insert_with_ttl(
        &mut self,
        addr: NodeAddr,
        coords: TreeCoordinate,
        current_time_ms: u64,
        ttl_ms: u64,
    ) {
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.update(coords, current_time_ms, ttl_ms);
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_one(current_time_ms);
        }

        let entry = CacheEntry::new(coords, current_time_ms, ttl_ms);
        self.entries.insert(addr, entry);
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

    /// Look up coordinates and touch (update last_used).
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

        // Touch and return
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.touch(current_time_ms);
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

        // Otherwise evict LRU (oldest last_used)
        let lru_key = self
            .entries
            .iter()
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

        cache.insert(addr, coords.clone(), 0);

        assert!(cache.contains(&addr, 0));
        assert_eq!(cache.get(&addr, 0), Some(&coords));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_coord_cache_expiry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(addr, coords, 0);

        assert!(cache.contains(&addr, 500));
        assert!(!cache.contains(&addr, 1500));
    }

    #[test]
    fn test_coord_cache_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert(addr, make_coords(&[1, 0]), 0);
        cache.insert(addr, make_coords(&[1, 2, 0]), 500);

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

        cache.insert(addr1, make_coords(&[1, 0]), 0);
        cache.insert(addr2, make_coords(&[2, 0]), 100);

        // Touch addr2 to make it more recent
        let _ = cache.get_and_touch(&addr2, 200);

        // Insert addr3, should evict addr1 (LRU)
        cache.insert(addr3, make_coords(&[3, 0]), 300);

        assert!(!cache.contains(&addr1, 300));
        assert!(cache.contains(&addr2, 300));
        assert!(cache.contains(&addr3, 300));
    }

    #[test]
    fn test_coord_cache_evict_expired_first() {
        let mut cache = CoordCache::new(2, 100);

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

        // At time 150, addr1 is expired, addr2 is not
        cache.insert(make_node_addr(3), make_coords(&[3, 0]), 150);

        // addr1 should be evicted (expired), not addr2 (LRU but not expired)
        assert!(!cache.contains(&make_node_addr(1), 150));
        assert!(cache.contains(&make_node_addr(2), 150));
        assert!(cache.contains(&make_node_addr(3), 150));
    }

    #[test]
    fn test_coord_cache_purge_expired() {
        let mut cache = CoordCache::new(100, 100);

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0); // expires at 100
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50); // expires at 150
        cache.insert(make_node_addr(3), make_coords(&[3, 0]), 200); // expires at 300

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

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

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

        cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);

        // Should expire at 200, not the default 1000
        assert!(cache.contains(&addr, 100));
        assert!(!cache.contains(&addr, 201));
    }

    #[test]
    fn test_coord_cache_insert_with_ttl_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);
        cache.insert_with_ttl(addr, make_coords(&[1, 2, 0]), 100, 300);

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

        cache.insert(addr, make_coords(&[1, 0]), 0);
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

        cache.insert(addr, make_coords(&[1, 0]), 500);

        let entry = cache.get_entry(&addr).unwrap();
        assert_eq!(entry.created_at(), 500);
        assert_eq!(entry.expires_at(), 1500);

        assert!(cache.get_entry(&make_node_addr(99)).is_none());
    }

    #[test]
    fn test_coord_cache_remove() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_node_addr(1);

        cache.insert(addr, make_coords(&[1, 0]), 0);
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

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

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

        cache.insert(addr, make_coords(&[1, 0]), 0);
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
}
