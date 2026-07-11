//! Peer Management
//!
//! Two-phase peer lifecycle:
//! 1. **PeerConnection** - Handshake phase, before identity is verified
//! 2. **ActivePeer** - Authenticated phase, after successful Noise handshake
//!
//! The PeerSlot enum represents either phase, enabling unified storage
//! while maintaining type safety for phase-specific operations.

mod active;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod connected_udp;
mod connection;

pub use active::{ActivePeer, ConnectivityState};
pub use connection::{HandshakeState, PeerConnection};

use crate::NodeAddr;
use crate::transport::LinkId;
use std::fmt;
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
// PeerSlot
// ============================================================================

/// A slot in the peer table, representing either connection or active phase.
#[derive(Debug)]
pub enum PeerSlot {
    /// Connection in handshake phase.
    Connecting(Box<PeerConnection>),
    /// Authenticated peer.
    Active(Box<ActivePeer>),
}

impl PeerSlot {
    /// Create a new connecting slot (outbound).
    pub fn outbound(conn: PeerConnection) -> Self {
        PeerSlot::Connecting(Box::new(conn))
    }

    /// Create a new connecting slot (inbound).
    pub fn inbound(conn: PeerConnection) -> Self {
        PeerSlot::Connecting(Box::new(conn))
    }

    /// Create a new active slot.
    pub fn active(peer: ActivePeer) -> Self {
        PeerSlot::Active(Box::new(peer))
    }

    /// Check if this is a connecting slot.
    pub fn is_connecting(&self) -> bool {
        matches!(self, PeerSlot::Connecting(_))
    }

    /// Check if this is an active slot.
    pub fn is_active(&self) -> bool {
        matches!(self, PeerSlot::Active(_))
    }

    /// Get the link ID for this slot.
    pub fn link_id(&self) -> LinkId {
        match self {
            PeerSlot::Connecting(conn) => conn.link_id(),
            PeerSlot::Active(peer) => peer.link_id(),
        }
    }

    /// Get as connection reference, if connecting.
    pub fn as_connection(&self) -> Option<&PeerConnection> {
        match self {
            PeerSlot::Connecting(conn) => Some(conn),
            PeerSlot::Active(_) => None,
        }
    }

    /// Get as mutable connection reference, if connecting.
    pub fn as_connection_mut(&mut self) -> Option<&mut PeerConnection> {
        match self {
            PeerSlot::Connecting(conn) => Some(conn),
            PeerSlot::Active(_) => None,
        }
    }

    /// Get as active peer reference, if active.
    pub fn as_active(&self) -> Option<&ActivePeer> {
        match self {
            PeerSlot::Active(peer) => Some(peer),
            PeerSlot::Connecting(_) => None,
        }
    }

    /// Get as mutable active peer reference, if active.
    pub fn as_active_mut(&mut self) -> Option<&mut ActivePeer> {
        match self {
            PeerSlot::Active(peer) => Some(peer),
            PeerSlot::Connecting(_) => None,
        }
    }

    /// Get the known node_addr, if any.
    ///
    /// For connections, this is the expected identity (may be None for inbound).
    /// For active peers, this is always known.
    pub fn node_addr(&self) -> Option<&NodeAddr> {
        match self {
            PeerSlot::Connecting(conn) => conn.expected_identity().map(|id| id.node_addr()),
            PeerSlot::Active(peer) => Some(peer.node_addr()),
        }
    }
}

impl fmt::Display for PeerSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerSlot::Connecting(conn) => {
                write!(
                    f,
                    "connecting(link={}, state={})",
                    conn.link_id(),
                    conn.handshake_state()
                )
            }
            PeerSlot::Active(peer) => {
                write!(
                    f,
                    "active(node={:?}, link={})",
                    peer.node_addr(),
                    peer.link_id()
                )
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::fmp::PromotionResult;
    use crate::transport::LinkId;
    use crate::{Identity, PeerIdentity};

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    #[test]
    fn test_peer_slot_connecting() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);
        let slot = PeerSlot::Connecting(Box::new(conn));

        assert!(slot.is_connecting());
        assert!(!slot.is_active());
        assert!(slot.as_connection().is_some());
        assert!(slot.as_active().is_none());
        assert_eq!(slot.link_id(), LinkId::new(1));
    }

    #[test]
    fn test_peer_slot_active() {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(2), 2000);
        let slot = PeerSlot::Active(Box::new(peer));

        assert!(!slot.is_connecting());
        assert!(slot.is_active());
        assert!(slot.as_connection().is_none());
        assert!(slot.as_active().is_some());
        assert_eq!(slot.link_id(), LinkId::new(2));
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

    #[test]
    fn test_peer_slot_node_addr() {
        // Outbound connection knows expected identity
        let identity = make_peer_identity();
        let expected_node_addr = *identity.node_addr();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);
        let slot = PeerSlot::Connecting(Box::new(conn));
        assert_eq!(slot.node_addr(), Some(&expected_node_addr));

        // Inbound connection doesn't know identity yet
        let conn_inbound = PeerConnection::inbound(LinkId::new(2), 2000);
        let slot_inbound = PeerSlot::Connecting(Box::new(conn_inbound));
        assert!(slot_inbound.node_addr().is_none());

        // Active peer always knows identity
        let identity2 = make_peer_identity();
        let active_node_addr = *identity2.node_addr();
        let peer = ActivePeer::new(identity2, LinkId::new(3), 3000);
        let slot_active = PeerSlot::Active(Box::new(peer));
        assert_eq!(slot_active.node_addr(), Some(&active_node_addr));
    }
}
