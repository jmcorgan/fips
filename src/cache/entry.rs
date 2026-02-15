//! Cache entry with TTL and LRU tracking.

use crate::tree::TreeCoordinate;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeAddr;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

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

    #[test]
    fn test_cache_entry_touch() {
        let coords = make_coords(&[1, 0]);
        let mut entry = CacheEntry::new(coords, 1000, 500);

        assert_eq!(entry.last_used(), 1000);
        entry.touch(1300);
        assert_eq!(entry.last_used(), 1300);
        // Touch doesn't affect expiry
        assert_eq!(entry.expires_at(), 1500);
    }

    #[test]
    fn test_cache_entry_update() {
        let mut entry = CacheEntry::new(make_coords(&[1, 0]), 1000, 500);

        let new_coords = make_coords(&[1, 2, 0]);
        entry.update(new_coords.clone(), 2000, 600);

        assert_eq!(entry.coords(), &new_coords);
        assert_eq!(entry.last_used(), 2000);
        assert_eq!(entry.expires_at(), 2600);
        // created_at is unchanged
        assert_eq!(entry.created_at(), 1000);
    }

    #[test]
    fn test_cache_entry_saturating_add() {
        let coords = make_coords(&[1, 0]);
        let entry = CacheEntry::new(coords, u64::MAX - 10, 100);

        // Should saturate to u64::MAX rather than overflow
        assert_eq!(entry.expires_at(), u64::MAX);
    }
}
