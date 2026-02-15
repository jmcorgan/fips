//! Route cache for discovered destinations.
//!
//! Separate from CoordCache, this stores routes learned from the discovery
//! protocol (LookupRequest/LookupResponse) rather than session establishment.

use std::collections::HashMap;

use crate::tree::TreeCoordinate;
use crate::NodeAddr;

/// Default maximum entries in route cache.
pub const DEFAULT_ROUTE_CACHE_SIZE: usize = 10_000;

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
/// Keyed by NodeAddr.
#[derive(Clone, Debug)]
pub struct RouteCache {
    /// NodeAddr -> discovered coordinates.
    entries: HashMap<NodeAddr, CachedCoords>,
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
    pub fn insert(&mut self, node_addr: NodeAddr, coords: TreeCoordinate, current_time_ms: u64) {
        // Update existing
        if let Some(entry) = self.entries.get_mut(&node_addr) {
            entry.update(coords, current_time_ms);
            return;
        }

        // Evict if full
        if self.entries.len() >= self.max_entries {
            self.evict_lru(current_time_ms);
        }

        self.entries
            .insert(node_addr, CachedCoords::new(coords, current_time_ms));
    }

    /// Look up a route (without touching).
    pub fn get(&self, node_addr: &NodeAddr) -> Option<&CachedCoords> {
        self.entries.get(node_addr)
    }

    /// Look up and touch.
    pub fn get_and_touch(
        &mut self,
        node_addr: &NodeAddr,
        current_time_ms: u64,
    ) -> Option<&TreeCoordinate> {
        if let Some(entry) = self.entries.get_mut(node_addr) {
            entry.touch(current_time_ms);
            Some(entry.coords())
        } else {
            None
        }
    }

    /// Remove a route (e.g., after route failure).
    pub fn invalidate(&mut self, node_addr: &NodeAddr) -> Option<CachedCoords> {
        self.entries.remove(node_addr)
    }

    /// Check if a node is cached.
    pub fn contains(&self, node_addr: &NodeAddr) -> bool {
        self.entries.contains_key(node_addr)
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

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

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

    #[test]
    fn test_route_cache_basic() {
        let mut cache = RouteCache::new(100);
        let node = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(node, coords.clone(), 0);

        assert!(cache.contains(&node));
        assert_eq!(cache.get(&node).unwrap().coords(), &coords);
    }

    #[test]
    fn test_route_cache_invalidate() {
        let mut cache = RouteCache::new(100);
        let node = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(node, coords, 0);
        assert!(cache.contains(&node));

        cache.invalidate(&node);
        assert!(!cache.contains(&node));
    }

    #[test]
    fn test_route_cache_lru_eviction() {
        let mut cache = RouteCache::new(2);

        let node1 = make_node_addr(1);
        let node2 = make_node_addr(2);
        let node3 = make_node_addr(3);

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

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 500);
        cache.insert(make_node_addr(3), make_coords(&[3, 0]), 1000);

        let evicted = cache.evict_older_than(600, 1000);

        assert_eq!(evicted, 1); // node1 is > 600ms old
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_route_cache_update() {
        let mut cache = RouteCache::new(100);
        let node = make_node_addr(1);

        cache.insert(node, make_coords(&[1, 0]), 0);
        cache.insert(node, make_coords(&[1, 2, 0]), 500);

        assert_eq!(cache.len(), 1);
        let cached = cache.get(&node).unwrap();
        assert_eq!(cached.coords().depth(), 2);
        assert_eq!(cached.discovered_at(), 500);
    }

    #[test]
    fn test_cached_coords_update() {
        let mut cached = CachedCoords::new(make_coords(&[1, 0]), 1000);

        let new_coords = make_coords(&[1, 2, 0]);
        cached.update(new_coords.clone(), 2000);

        assert_eq!(cached.coords(), &new_coords);
        assert_eq!(cached.discovered_at(), 2000);
        assert_eq!(cached.last_used(), 2000);
    }

    #[test]
    fn test_route_cache_get_and_touch() {
        let mut cache = RouteCache::new(100);
        let node = make_node_addr(1);
        let coords = make_coords(&[1, 0]);

        cache.insert(node, coords.clone(), 0);

        let result = cache.get_and_touch(&node, 500);
        assert_eq!(result, Some(&coords));

        // Verify last_used was updated
        let entry = cache.get(&node).unwrap();
        assert_eq!(entry.last_used(), 500);
    }

    #[test]
    fn test_route_cache_get_and_touch_missing() {
        let mut cache = RouteCache::new(100);
        let result = cache.get_and_touch(&make_node_addr(99), 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_route_cache_clear_and_is_empty() {
        let mut cache = RouteCache::new(100);

        assert!(cache.is_empty());

        cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
        cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_route_cache_default() {
        let cache = RouteCache::default();

        assert_eq!(cache.max_entries(), DEFAULT_ROUTE_CACHE_SIZE);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_route_cache_invalidate_missing() {
        let mut cache = RouteCache::new(100);
        let result = cache.invalidate(&make_node_addr(99));
        assert!(result.is_none());
    }
}
