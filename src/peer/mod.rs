//! Peer Management
//!
//! Two-phase peer lifecycle:
//! 1. **PeerConnection** - Handshake phase, before identity is verified
//! 2. **ActivePeer** - Authenticated phase, after successful Noise handshake
//!
//! The PeerSlot enum represents either phase, enabling unified storage
//! while maintaining type safety for phase-specific operations.

mod active;
mod connection;

pub use active::{ActivePeer, ConnectivityState};
pub use connection::{HandshakeState, PeerConnection};

use crate::transport::LinkId;
use crate::NodeId;
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
    NotFound(NodeId),

    #[error("connection not found: {0}")]
    ConnectionNotFound(LinkId),

    #[error("peer already exists: {0:?}")]
    AlreadyExists(NodeId),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("identity mismatch: expected {expected:?}, got {actual:?}")]
    IdentityMismatch { expected: NodeId, actual: NodeId },

    #[error("peer disconnected")]
    Disconnected,

    #[error("max connections exceeded: {max}")]
    MaxConnectionsExceeded { max: usize },

    #[error("max peers exceeded: {max}")]
    MaxPeersExceeded { max: usize },
}

// ============================================================================
// Cross-Connection Handling
// ============================================================================

/// Result of attempting to promote a connection to active peer.
///
/// When a handshake completes, we may discover that we already have a
/// connection to this peer (cross-connection). The tie-breaker rule
/// determines which connection survives.
///
/// Note: Returns NodeId instead of ActivePeer because ActivePeer cannot
/// be cloned (it contains NoiseSession which has cryptographic state).
/// Callers can look up the peer from the peers map using the NodeId.
#[derive(Debug, Clone, Copy)]
pub enum PromotionResult {
    /// New peer created successfully.
    Promoted(NodeId),

    /// Cross-connection detected. This connection lost the tie-breaker
    /// and should be closed.
    CrossConnectionLost {
        /// The link that won (existing connection).
        winner_link_id: LinkId,
    },

    /// Cross-connection detected. This connection won the tie-breaker.
    /// The existing connection was replaced.
    CrossConnectionWon {
        /// The link that lost (previous connection, now closed).
        loser_link_id: LinkId,
        /// The node ID of the peer.
        node_id: NodeId,
    },
}

impl PromotionResult {
    /// Get the node ID if promotion succeeded.
    pub fn node_id(&self) -> Option<NodeId> {
        match self {
            PromotionResult::Promoted(node_id) => Some(*node_id),
            PromotionResult::CrossConnectionWon { node_id, .. } => Some(*node_id),
            PromotionResult::CrossConnectionLost { .. } => None,
        }
    }

    /// Check if this connection should be closed.
    pub fn should_close_this_connection(&self) -> bool {
        matches!(self, PromotionResult::CrossConnectionLost { .. })
    }

    /// Get the link that should be closed, if any.
    pub fn link_to_close(&self) -> Option<LinkId> {
        match self {
            PromotionResult::CrossConnectionLost { .. } => None, // Caller's link
            PromotionResult::CrossConnectionWon { loser_link_id, .. } => Some(*loser_link_id),
            PromotionResult::Promoted(_) => None,
        }
    }
}

/// Determine winner of cross-connection tie-breaker.
///
/// Rule: The node with the smaller node_id prefers its OUTBOUND connection.
/// This is deterministic and symmetric: both nodes will reach the same conclusion.
///
/// # Arguments
/// * `our_node_id` - Our node's ID
/// * `their_node_id` - The peer's node ID
/// * `this_is_outbound` - Whether the connection being evaluated is our outbound
///
/// # Returns
/// `true` if this connection should win (survive), `false` if it should close.
pub fn cross_connection_winner(
    our_node_id: &NodeId,
    their_node_id: &NodeId,
    this_is_outbound: bool,
) -> bool {
    let we_are_smaller = our_node_id < their_node_id;

    // Smaller node's outbound wins
    // If we're smaller: our outbound wins, our inbound loses
    // If they're smaller: our outbound loses, our inbound wins
    if we_are_smaller {
        this_is_outbound
    } else {
        !this_is_outbound
    }
}

// ============================================================================
// PeerSlot
// ============================================================================

/// A slot in the peer table, representing either connection or active phase.
#[derive(Debug)]
pub enum PeerSlot {
    /// Connection in handshake phase.
    Connecting(PeerConnection),
    /// Authenticated peer.
    Active(ActivePeer),
}

impl PeerSlot {
    /// Create a new connecting slot (outbound).
    pub fn outbound(conn: PeerConnection) -> Self {
        PeerSlot::Connecting(conn)
    }

    /// Create a new connecting slot (inbound).
    pub fn inbound(conn: PeerConnection) -> Self {
        PeerSlot::Connecting(conn)
    }

    /// Create a new active slot.
    pub fn active(peer: ActivePeer) -> Self {
        PeerSlot::Active(peer)
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

    /// Get the known node_id, if any.
    ///
    /// For connections, this is the expected identity (may be None for inbound).
    /// For active peers, this is always known.
    pub fn node_id(&self) -> Option<&NodeId> {
        match self {
            PeerSlot::Connecting(conn) => conn.expected_identity().map(|id| id.node_id()),
            PeerSlot::Active(peer) => Some(peer.node_id()),
        }
    }
}

impl fmt::Display for PeerSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerSlot::Connecting(conn) => {
                write!(f, "connecting(link={}, state={})", conn.link_id(), conn.handshake_state())
            }
            PeerSlot::Active(peer) => {
                write!(f, "active(node={:?}, link={})", peer.node_id(), peer.link_id())
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
    use crate::transport::LinkId;
    use crate::{Identity, PeerIdentity};

    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    #[test]
    fn test_cross_connection_smaller_node_wins_outbound() {
        let node_a = make_node_id(1); // smaller
        let node_b = make_node_id(2); // larger

        // Node A's perspective
        assert!(cross_connection_winner(&node_a, &node_b, true)); // A's outbound wins
        assert!(!cross_connection_winner(&node_a, &node_b, false)); // A's inbound loses

        // Node B's perspective
        assert!(!cross_connection_winner(&node_b, &node_a, true)); // B's outbound loses
        assert!(cross_connection_winner(&node_b, &node_a, false)); // B's inbound wins
    }

    #[test]
    fn test_cross_connection_symmetric() {
        let node_a = make_node_id(1);
        let node_b = make_node_id(2);

        // A's outbound = B's inbound
        let a_outbound_wins = cross_connection_winner(&node_a, &node_b, true);
        let b_inbound_wins = cross_connection_winner(&node_b, &node_a, false);
        assert_eq!(a_outbound_wins, b_inbound_wins);

        // A's inbound = B's outbound
        let a_inbound_wins = cross_connection_winner(&node_a, &node_b, false);
        let b_outbound_wins = cross_connection_winner(&node_b, &node_a, true);
        assert_eq!(a_inbound_wins, b_outbound_wins);

        // Exactly one survives
        assert!(a_outbound_wins != a_inbound_wins);
    }

    #[test]
    fn test_peer_slot_connecting() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);
        let slot = PeerSlot::Connecting(conn);

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
        let slot = PeerSlot::Active(peer);

        assert!(!slot.is_connecting());
        assert!(slot.is_active());
        assert!(slot.as_connection().is_none());
        assert!(slot.as_active().is_some());
        assert_eq!(slot.link_id(), LinkId::new(2));
    }

    #[test]
    fn test_promotion_result_promoted() {
        let identity = make_peer_identity();
        let node_id = *identity.node_id();
        let result = PromotionResult::Promoted(node_id);

        assert!(result.node_id().is_some());
        assert_eq!(result.node_id(), Some(node_id));
        assert!(!result.should_close_this_connection());
        assert!(result.link_to_close().is_none());
    }

    #[test]
    fn test_promotion_result_cross_lost() {
        let result = PromotionResult::CrossConnectionLost {
            winner_link_id: LinkId::new(1),
        };

        assert!(result.node_id().is_none());
        assert!(result.should_close_this_connection());
        assert!(result.link_to_close().is_none()); // Caller closes their own
    }

    #[test]
    fn test_promotion_result_cross_won() {
        let identity = make_peer_identity();
        let node_id = *identity.node_id();
        let result = PromotionResult::CrossConnectionWon {
            loser_link_id: LinkId::new(1),
            node_id,
        };

        assert!(result.node_id().is_some());
        assert_eq!(result.node_id(), Some(node_id));
        assert!(!result.should_close_this_connection());
        assert_eq!(result.link_to_close(), Some(LinkId::new(1)));
    }

    #[test]
    fn test_peer_slot_node_id() {
        // Outbound connection knows expected identity
        let identity = make_peer_identity();
        let expected_node_id = *identity.node_id();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);
        let slot = PeerSlot::Connecting(conn);
        assert_eq!(slot.node_id(), Some(&expected_node_id));

        // Inbound connection doesn't know identity yet
        let conn_inbound = PeerConnection::inbound(LinkId::new(2), 2000);
        let slot_inbound = PeerSlot::Connecting(conn_inbound);
        assert!(slot_inbound.node_id().is_none());

        // Active peer always knows identity
        let identity2 = make_peer_identity();
        let active_node_id = *identity2.node_id();
        let peer = ActivePeer::new(identity2, LinkId::new(3), 3000);
        let slot_active = PeerSlot::Active(peer);
        assert_eq!(slot_active.node_id(), Some(&active_node_id));
    }
}
