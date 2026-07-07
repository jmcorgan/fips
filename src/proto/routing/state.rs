//! Routing-subsystem state owned by [`Node`](crate::node::Node).
//!
//! Groups the routing error-signal rate limiter behind a single struct so
//! the forwarding handlers can evolve toward a sans-IO core without
//! threading the limiter field through `Node`.

use super::limits::RoutingErrorRateLimiter;

/// Routing-subsystem state.
pub(crate) struct Router {
    /// Rate limiter for routing error signals (CoordsRequired / PathBroken).
    pub(crate) error_limiter: RoutingErrorRateLimiter,
}

impl Router {
    /// Create routing state with a default error-signal rate limiter,
    /// matching the pre-refactor initialization exactly.
    pub(crate) fn new() -> Self {
        Self {
            error_limiter: RoutingErrorRateLimiter::new(),
        }
    }
}
