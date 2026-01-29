//! Caching Entities
//!
//! Coordinate and route caching for FIPS routing. The CoordCache stores
//! address-to-coordinate mappings populated by session setup, while
//! RouteCache stores coordinates learned from discovery queries.

use crate::tree::TreeCoordinate;
use crate::{FipsAddress, NodeId};
use std::collections::HashMap;
use thiserror::Error;

/// Default maximum entries in coordinate cache.
pub const DEFAULT_COORD_CACHE_SIZE: usize = 50_000;

/// Default TTL for coordinate cache entries (5 minutes in milliseconds).
pub const DEFAULT_COORD_CACHE_TTL_MS: u64 = 300_000;

/// Default maximum entries in route cache.
pub const DEFAULT_ROUTE_CACHE_SIZE: usize = 10_000;

/// Errors related to cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache full: max {max} entries")]
    CacheFull { max: usize },

    #[error("entry not found")]
    NotFound,

    #[error("entry expired")]
    Expired,
}

/// A cached coordinate entry.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// The cached coordinates.
    coords: TreeCoordinate,
    /// When this entry was created (Unix milliseconds).
    created_at: u64,
    /// When this entry was last used (Unix milliseconds).
    last_used: u64,
    /// When this entry expires (Unix milliseconds).
    expires_at: u64,
}

impl CacheEntry {
    /// Create a new cache entry.
    pub fn new(coords: TreeCoordinate, current_time_ms: u64, ttl_ms: u64) -> Self {
        Self {
            coords,
            created_at: current_time_ms,
            last_used: current_time_ms,
            expires_at: current_time_ms.saturating_add(ttl_ms),
        }
    }

    /// Get the cached coordinates.
    pub fn coords(&self) -> &TreeCoordinate {
        &self.coords
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the last used timestamp.
    pub fn last_used(&self) -> u64 {
        self.last_used
    }

    /// Get the expiry timestamp.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Check if this entry has expired.
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms > self.expires_at
    }

    /// Touch the entry to update last_used time.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_used = current_time_ms;
    }

    /// Refresh the expiry time.
    pub fn refresh(&mut self, current_time_ms: u64, ttl_ms: u64) {
        self.expires_at = current_time_ms.saturating_add(ttl_ms);
        self.last_used = current_time_ms;
    }

    /// Update the coordinates and refresh timestamps.
    pub fn update(&mut self, coords: TreeCoordinate, current_time_ms: u64, ttl_ms: u64) {
        self.coords = coords;
        self.last_used = current_time_ms;
        self.expires_at = current_time_ms.saturating_add(ttl_ms);
    }

    /// Time since last use (for LRU eviction).
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_used)
    }

    /// Age of the entry.
    pub fn age(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.created_at)
    }

    /// Time until expiry (0 if already expired).
    pub fn time_to_expiry(&self, current_time_ms: u64) -> u64 {
        self.expires_at.saturating_sub(current_time_ms)
    }
}

/// Coordinate cache for routing decisions.
///
/// Maps FIPS addresses to their tree coordinates, enabling data packets
/// to be routed without carrying coordinates in every packet. Populated
/// by SessionSetup packets.
#[derive(Clone, Debug)]
pub struct CoordCache {
    /// Address -> coordinates mapping.
    entries: HashMap<FipsAddress, CacheEntry>,
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
    pub fn insert(&mut self, addr: FipsAddress, coords: TreeCoordinate, current_time_ms: u64) {
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
        addr: FipsAddress,
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
    pub fn get(&self, addr: &FipsAddress, current_time_ms: u64) -> Option<&TreeCoordinate> {
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
        addr: &FipsAddress,
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
    pub fn get_entry(&self, addr: &FipsAddress) -> Option<&CacheEntry> {
        self.entries.get(addr)
    }

    /// Remove an entry.
    pub fn remove(&mut self, addr: &FipsAddress) -> Option<CacheEntry> {
        self.entries.remove(addr)
    }

    /// Check if an address is cached (and not expired).
    pub fn contains(&self, addr: &FipsAddress, current_time_ms: u64) -> bool {
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

/// Cache statistics.
#[derive(Clone, Debug)]
pub struct CacheStats {
    /// Current number of entries.
    pub entries: usize,
    /// Maximum capacity.
    pub max_entries: usize,
    /// Number of expired entries.
    pub expired: usize,
    /// Average entry age in milliseconds.
    pub avg_age_ms: u64,
}

impl CacheStats {
    /// Fill ratio (entries / max_entries).
    pub fn fill_ratio(&self) -> f64 {
        if self.max_entries == 0 {
            0.0
        } else {
            self.entries as f64 / self.max_entries as f64
        }
    }
}

/// A cached route from discovery.
#[derive(Clone, Debug)]
pub struct CachedCoords {
    /// The coordinates discovered.
    coords: TreeCoordinate,
    /// When this was discovered (Unix milliseconds).
    discovered_at: u64,
    /// Last time we used this route (Unix milliseconds).
    last_used: u64,
}

impl CachedCoords {
    /// Create a new cached route.
    pub fn new(coords: TreeCoordinate, discovered_at: u64) -> Self {
        Self {
            coords,
            discovered_at,
            last_used: discovered_at,
        }
    }

    /// Get the coordinates.
    pub fn coords(&self) -> &TreeCoordinate {
        &self.coords
    }

    /// Get the discovery timestamp.
    pub fn discovered_at(&self) -> u64 {
        self.discovered_at
    }

    /// Get the last used timestamp.
    pub fn last_used(&self) -> u64 {
        self.last_used
    }

    /// Touch (update last_used).
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_used = current_time_ms;
    }

    /// Age since discovery.
    pub fn age(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.discovered_at)
    }

    /// Idle time since last use.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_used)
    }

    /// Update coordinates (re-discovered).
    pub fn update(&mut self, coords: TreeCoordinate, current_time_ms: u64) {
        self.coords = coords;
        self.discovered_at = current_time_ms;
        self.last_used = current_time_ms;
    }
}

/// Route cache for discovered destinations.
///
/// Separate from CoordCache, this stores routes learned from the discovery
/// protocol (LookupRequest/LookupResponse) rather than session establishment.
/// Keyed by NodeId rather than FipsAddress.
#[derive(Clone, Debug)]
pub struct RouteCache {
    /// NodeId -> discovered coordinates.
    entries: HashMap<NodeId, CachedCoords>,
    /// Maximum entries.
    max_entries: usize,
}

impl RouteCache {
    /// Create a new route cache.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(1000)),
            max_entries,
        }
    }

    /// Create with default capacity.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_ROUTE_CACHE_SIZE)
    }

    /// Get the maximum capacity.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Insert a discovered route.
    pub fn insert(&mut self, node_id: NodeId, coords: TreeCoordinate, current_time_ms: u64) {
        // Update existing
        if let Some(entry) = self.entries.get_mut(&node_id) {
            entry.update(coords, current_time_ms);
            return;
        }

        // Evict if full
        if self.entries.len() >= self.max_entries {
            self.evict_lru(current_time_ms);
        }

        self.entries
            .insert(node_id, CachedCoords::new(coords, current_time_ms));
    }

    /// Look up a route (without touching).
    pub fn get(&self, node_id: &NodeId) -> Option<&CachedCoords> {
        self.entries.get(node_id)
    }

    /// Look up and touch.
    pub fn get_and_touch(
        &mut self,
        node_id: &NodeId,
        current_time_ms: u64,
    ) -> Option<&TreeCoordinate> {
        if let Some(entry) = self.entries.get_mut(node_id) {
            entry.touch(current_time_ms);
            Some(entry.coords())
        } else {
            None
        }
    }

    /// Remove a route (e.g., after route failure).
    pub fn invalidate(&mut self, node_id: &NodeId) -> Option<CachedCoords> {
        self.entries.remove(node_id)
    }

    /// Check if a node is cached.
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.entries.contains_key(node_id)
    }

    /// Number of cached routes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all routes.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Evict routes older than a threshold.
    pub fn evict_older_than(&mut self, max_age_ms: u64, current_time_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.age(current_time_ms) < max_age_ms);
        before - self.entries.len()
    }

    fn evict_lru(&mut self, current_time_ms: u64) {
        let lru_id = self
            .entries
            .iter()
            .max_by_key(|(_, e)| e.idle_time(current_time_ms))
            .map(|(k, _)| *k);

        if let Some(id) = lru_id {
            self.entries.remove(&id);
        }
    }
}

impl Default for RouteCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    fn make_address(val: u8) -> FipsAddress {
        let mut bytes = [0xfdu8; 16];
        bytes[1] = val;
        FipsAddress::from_bytes(bytes).unwrap()
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::new(ids.iter().map(|&v| make_node_id(v)).collect()).unwrap()
    }

    // ===== CacheEntry Tests =====

    #[test]
    fn test_cache_entry_expiry() {
        let coords = make_coords(&[1, 0]);
        let entry = CacheEntry::new(coords, 1000, 500);

        assert!(!entry.is_expired(1000));
        assert!(!entry.is_expired(1500)); // expires_at = 1500, not yet expired
        assert!(entry.is_expired(1501)); // one ms after expiry
        assert!(entry.is_expired(2000));
    }

    #[test]
    fn test_cache_entry_refresh() {
        let coords = make_coords(&[1, 0]);
        let mut entry = CacheEntry::new(coords, 1000, 500);

        assert!(entry.is_expired(1501)); // expires_at = 1500

        entry.refresh(1400, 500); // new expires_at = 1900

        assert!(!entry.is_expired(1600));
        assert!(!entry.is_expired(1900)); // at exactly expiry, not expired
        assert!(entry.is_expired(1901)); // one ms after expiry
    }

    #[test]
    fn test_cache_entry_times() {
        let coords = make_coords(&[1, 0]);
        let entry = CacheEntry::new(coords, 1000, 500);

        assert_eq!(entry.created_at(), 1000);
        assert_eq!(entry.last_used(), 1000);
        assert_eq!(entry.expires_at(), 1500);
        assert_eq!(entry.age(1200), 200);
        assert_eq!(entry.idle_time(1200), 200);
        assert_eq!(entry.time_to_expiry(1200), 300);
        assert_eq!(entry.time_to_expiry(1600), 0);
    }

    // ===== CoordCache Tests =====

    #[test]
    fn test_coord_cache_basic() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_address(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(addr, coords.clone(), 0);

        assert!(cache.contains(&addr, 0));
        assert_eq!(cache.get(&addr, 0), Some(&coords));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_coord_cache_expiry() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_address(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(addr, coords, 0);

        assert!(cache.contains(&addr, 500));
        assert!(!cache.contains(&addr, 1500));
    }

    #[test]
    fn test_coord_cache_update() {
        let mut cache = CoordCache::new(100, 1000);
        let addr = make_address(1);

        cache.insert(addr, make_coords(&[1, 0]), 0);
        cache.insert(addr, make_coords(&[1, 2, 0]), 500);

        assert_eq!(cache.len(), 1);
        let coords = cache.get(&addr, 500).unwrap();
        assert_eq!(coords.depth(), 2);
    }

    #[test]
    fn test_coord_cache_eviction() {
        let mut cache = CoordCache::new(2, 10000);

        let addr1 = make_address(1);
        let addr2 = make_address(2);
        let addr3 = make_address(3);

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

        cache.insert(make_address(1), make_coords(&[1, 0]), 0);
        cache.insert(make_address(2), make_coords(&[2, 0]), 50);

        // At time 150, addr1 is expired, addr2 is not
        cache.insert(make_address(3), make_coords(&[3, 0]), 150);

        // addr1 should be evicted (expired), not addr2 (LRU but not expired)
        assert!(!cache.contains(&make_address(1), 150));
        assert!(cache.contains(&make_address(2), 150));
        assert!(cache.contains(&make_address(3), 150));
    }

    #[test]
    fn test_coord_cache_purge_expired() {
        let mut cache = CoordCache::new(100, 100);

        cache.insert(make_address(1), make_coords(&[1, 0]), 0); // expires at 100
        cache.insert(make_address(2), make_coords(&[2, 0]), 50); // expires at 150
        cache.insert(make_address(3), make_coords(&[3, 0]), 200); // expires at 300

        assert_eq!(cache.len(), 3);

        let purged = cache.purge_expired(151); // both addr1 and addr2 expired

        // Entry 1 and 2 expired, entry 3 still valid
        assert_eq!(purged, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&make_address(3), 151));
    }

    #[test]
    fn test_coord_cache_stats() {
        let mut cache = CoordCache::new(100, 100);

        cache.insert(make_address(1), make_coords(&[1, 0]), 0);
        cache.insert(make_address(2), make_coords(&[2, 0]), 50);

        let stats = cache.stats(150);

        assert_eq!(stats.entries, 2);
        assert_eq!(stats.max_entries, 100);
        assert_eq!(stats.expired, 1); // addr1 expired
        assert!(stats.avg_age_ms > 0);
    }

    // ===== CachedCoords Tests =====

    #[test]
    fn test_cached_coords() {
        let coords = make_coords(&[1, 0]);
        let mut cached = CachedCoords::new(coords.clone(), 1000);

        assert_eq!(cached.coords(), &coords);
        assert_eq!(cached.discovered_at(), 1000);
        assert_eq!(cached.last_used(), 1000);

        cached.touch(1500);
        assert_eq!(cached.last_used(), 1500);
        assert_eq!(cached.idle_time(1600), 100);
        assert_eq!(cached.age(1600), 600);
    }

    // ===== RouteCache Tests =====

    #[test]
    fn test_route_cache_basic() {
        let mut cache = RouteCache::new(100);
        let node = make_node_id(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(node, coords.clone(), 0);

        assert!(cache.contains(&node));
        assert_eq!(cache.get(&node).unwrap().coords(), &coords);
    }

    #[test]
    fn test_route_cache_invalidate() {
        let mut cache = RouteCache::new(100);
        let node = make_node_id(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(node, coords, 0);
        assert!(cache.contains(&node));

        cache.invalidate(&node);
        assert!(!cache.contains(&node));
    }

    #[test]
    fn test_route_cache_lru_eviction() {
        let mut cache = RouteCache::new(2);

        let node1 = make_node_id(1);
        let node2 = make_node_id(2);
        let node3 = make_node_id(3);

        cache.insert(node1, make_coords(&[1, 0]), 0);
        cache.insert(node2, make_coords(&[2, 0]), 100);

        // Touch node2
        let _ = cache.get_and_touch(&node2, 200);

        // Insert node3
        cache.insert(node3, make_coords(&[3, 0]), 300);

        // node1 should be evicted
        assert!(!cache.contains(&node1));
        assert!(cache.contains(&node2));
        assert!(cache.contains(&node3));
    }

    #[test]
    fn test_route_cache_evict_older_than() {
        let mut cache = RouteCache::new(100);

        cache.insert(make_node_id(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_id(2), make_coords(&[2, 0]), 500);
        cache.insert(make_node_id(3), make_coords(&[3, 0]), 1000);

        let evicted = cache.evict_older_than(600, 1000);

        assert_eq!(evicted, 1); // node1 is > 600ms old
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_route_cache_update() {
        let mut cache = RouteCache::new(100);
        let node = make_node_id(1);

        cache.insert(node, make_coords(&[1, 0]), 0);
        cache.insert(node, make_coords(&[1, 2, 0]), 500);

        assert_eq!(cache.len(), 1);
        let cached = cache.get(&node).unwrap();
        assert_eq!(cached.coords().depth(), 2);
        assert_eq!(cached.discovered_at(), 500);
    }
}
