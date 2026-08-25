//! Cache entry with TTL and LRU tracking.

use crate::proto::stp::TreeCoordinate;

/// How long a verification outranks a hint, in milliseconds.
///
/// Deliberately independent of the entry's own TTL. An entry carrying live
/// traffic is refreshed on every use and so never expires, and if verification
/// rode that same clock a once-verified entry would outrank every hint forever
/// — including the hints that would carry a destination's genuine move. This
/// clock is never refreshed: verification ages out on its own, and the entry
/// stays usable afterwards, it just stops winning.
pub const VERIFIED_TTL_MS: u64 = 300_000;

/// Where a cached coordinate came from, which is what decides whether it may
/// be overwritten.
///
/// The distinction is the whole of the defence: `Verified` values arrive with
/// a proof this node checked, `Hint` values are copied off a passing packet
/// and are attacker-supplied in the general case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordSource {
    /// Established by a lookup whose response proof this node verified.
    Verified,
    /// Copied from a packet in transit. Unauthenticated.
    Hint,
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
    /// Path MTU discovered during lookup (if available).
    ///
    /// Set from the `LookupResponse.path_mtu` field when a discovery
    /// response is cached. `None` when populated from SessionSetup or
    /// other sources that don't carry path MTU information.
    path_mtu: Option<u16>,
    /// Where the current coordinates came from.
    source: CoordSource,
    /// Until when a `Verified` source outranks a hint (Unix milliseconds).
    ///
    /// Zero for a hint. Never extended by `refresh` or `touch`; see
    /// [`VERIFIED_TTL_MS`].
    verified_until: u64,
}

impl CacheEntry {
    /// Create a new cache entry, carrying a hint.
    ///
    /// Hint is the safe default: a caller that means to confer trust has to say
    /// so with [`CacheEntry::new_verified`], rather than trust being what you
    /// get by reaching for the obvious constructor.
    pub fn new(coords: TreeCoordinate, current_time_ms: u64, ttl_ms: u64) -> Self {
        Self {
            coords,
            created_at: current_time_ms,
            last_used: current_time_ms,
            expires_at: current_time_ms.saturating_add(ttl_ms),
            path_mtu: None,
            source: CoordSource::Hint,
            verified_until: 0,
        }
    }

    /// Create a new cache entry from a verified lookup.
    pub fn new_verified(coords: TreeCoordinate, current_time_ms: u64, ttl_ms: u64) -> Self {
        let mut entry = Self::new(coords, current_time_ms, ttl_ms);
        entry.mark_verified(current_time_ms);
        entry
    }

    /// Where the current coordinates came from.
    pub fn source(&self) -> CoordSource {
        self.source
    }

    /// Whether this entry's verification still outranks a hint at this time.
    ///
    /// A `Verified` entry whose `verified_until` has passed answers `false`:
    /// the coordinates remain usable, they just no longer refuse an update.
    pub fn is_verified(&self, current_time_ms: u64) -> bool {
        self.source == CoordSource::Verified && current_time_ms <= self.verified_until
    }

    /// Mark the current coordinates as verified, starting the verification
    /// clock at `current_time_ms`.
    pub fn mark_verified(&mut self, current_time_ms: u64) {
        self.source = CoordSource::Verified;
        self.verified_until = current_time_ms.saturating_add(VERIFIED_TTL_MS);
    }

    /// Mark the current coordinates as an unauthenticated hint.
    pub fn mark_hint(&mut self) {
        self.source = CoordSource::Hint;
        self.verified_until = 0;
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

    /// Get the path MTU discovered during lookup, if available.
    pub fn path_mtu(&self) -> Option<u16> {
        self.path_mtu
    }

    /// Set the path MTU discovered during lookup.
    pub fn set_path_mtu(&mut self, mtu: u16) {
        self.path_mtu = Some(mtu);
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

    /// Update the coordinates and refresh timestamps, as a hint.
    ///
    /// New coordinates are new provenance: whatever the entry held before, the
    /// value now present came from this caller, so an update by the hint path
    /// demotes the entry rather than inheriting the old verification.
    pub fn update(&mut self, coords: TreeCoordinate, current_time_ms: u64, ttl_ms: u64) {
        self.coords = coords;
        self.last_used = current_time_ms;
        self.expires_at = current_time_ms.saturating_add(ttl_ms);
        self.mark_hint();
    }

    /// Update the coordinates from a verified lookup and restart the
    /// verification clock.
    pub fn update_verified(&mut self, coords: TreeCoordinate, current_time_ms: u64, ttl_ms: u64) {
        self.update(coords, current_time_ms, ttl_ms);
        self.mark_verified(current_time_ms);
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
