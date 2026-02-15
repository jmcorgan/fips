//! Caching Entities
//!
//! Coordinate and route caching for FIPS routing. The CoordCache stores
//! address-to-coordinate mappings populated by session setup, while
//! RouteCache stores coordinates learned from discovery queries.

mod coord_cache;
mod entry;
mod route_cache;

use thiserror::Error;

pub use coord_cache::{CoordCache, DEFAULT_COORD_CACHE_SIZE, DEFAULT_COORD_CACHE_TTL_MS};
pub use entry::CacheEntry;
pub use route_cache::{CachedCoords, RouteCache, DEFAULT_ROUTE_CACHE_SIZE};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_stats_fill_ratio() {
        let stats = CacheStats {
            entries: 50,
            max_entries: 100,
            expired: 0,
            avg_age_ms: 0,
        };
        assert!((stats.fill_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_stats_fill_ratio_zero_max() {
        let stats = CacheStats {
            entries: 0,
            max_entries: 0,
            expired: 0,
            avg_age_ms: 0,
        };
        assert!((stats.fill_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_stats_fill_ratio_full() {
        let stats = CacheStats {
            entries: 100,
            max_entries: 100,
            expired: 10,
            avg_age_ms: 500,
        };
        assert!((stats.fill_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_error_display() {
        let full = CacheError::CacheFull { max: 1000 };
        assert_eq!(full.to_string(), "cache full: max 1000 entries");

        let not_found = CacheError::NotFound;
        assert_eq!(not_found.to_string(), "entry not found");

        let expired = CacheError::Expired;
        assert_eq!(expired.to_string(), "entry expired");
    }
}
