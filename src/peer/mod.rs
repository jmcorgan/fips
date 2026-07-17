//! Peer Management
//!
//! Two-phase peer lifecycle:
//! 1. **PeerConnection** - Handshake phase, before identity is verified
//! 2. **ActivePeer** - Authenticated phase, after successful Noise handshake

mod active;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod connected_udp;
mod connection;
pub(crate) mod machine;

pub use active::{ActivePeer, ConnectivityState};
pub use connection::{HandshakeState, PeerConnection};

use crate::NodeAddr;
use crate::transport::LinkId;
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

/// Errors related to peer operations.
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("peer not authenticated")]
    NotAuthenticated,

    #[error("peer not found: {0:?}")]
    NotFound(NodeAddr),

    #[error("connection not found: {0}")]
    ConnectionNotFound(LinkId),

    #[error("peer already exists: {0:?}")]
    AlreadyExists(NodeAddr),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("identity mismatch: expected {expected:?}, got {actual:?}")]
    IdentityMismatch {
        expected: NodeAddr,
        actual: NodeAddr,
    },

    #[error("peer disconnected")]
    Disconnected,

    #[error("max connections exceeded: {max}")]
    MaxConnectionsExceeded { max: usize },

    #[error("max peers exceeded: {max}")]
    MaxPeersExceeded { max: usize },
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use crate::proto::fmp::PromotionResult;
    use crate::transport::LinkId;
    use crate::{Identity, PeerIdentity};

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    #[test]
    fn test_promotion_result_promoted() {
        let identity = make_peer_identity();
        let node_addr = *identity.node_addr();
        let result = PromotionResult::Promoted(node_addr);

        assert!(result.node_addr().is_some());
        assert_eq!(result.node_addr(), Some(node_addr));
        assert!(!result.should_close_this_connection());
        assert!(result.link_to_close().is_none());
    }

    #[test]
    fn test_promotion_result_cross_lost() {
        let result = PromotionResult::CrossConnectionLost {
            winner_link_id: LinkId::new(1),
        };

        assert!(result.node_addr().is_none());
        assert!(result.should_close_this_connection());
        assert!(result.link_to_close().is_none()); // Caller closes their own
    }

    #[test]
    fn test_promotion_result_cross_won() {
        let identity = make_peer_identity();
        let node_addr = *identity.node_addr();
        let result = PromotionResult::CrossConnectionWon {
            loser_link_id: LinkId::new(1),
            node_addr,
        };

        assert!(result.node_addr().is_some());
        assert_eq!(result.node_addr(), Some(node_addr));
        assert!(!result.should_close_this_connection());
        assert_eq!(result.link_to_close(), Some(LinkId::new(1)));
    }
}
