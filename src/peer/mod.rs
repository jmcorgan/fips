//! Peer Management
//!
//! Two-phase peer lifecycle:
//! 1. **PeerMachine** with a handshake carrier attached - handshake phase,
//!    before identity is verified
//! 2. **ActivePeer** - Authenticated phase, after successful Noise handshake

mod active;
pub(crate) mod machine;

pub(crate) use active::RekeyMsg2Step;
pub use active::{ActivePeer, ConnectivityState};

use crate::NodeAddr;
use crate::identity::OsEntropy;
use crate::transport::LinkId;
use crate::utils::index::IndexAllocator;
use fips_core::proto::fmp::rekey::FmpProfile;
use fips_core::proto::rekey::{Config, NodeKeys, Output, Outputs, Params, Record, Rekey};
use fips_core::time::{Clock, Instant};
use std::time::Duration;
use thiserror::Error;

/// The clock an active peer measures its rekey timers on: the host's
/// monotonic clock, so a step of the system clock neither fires nor holds a
/// rekey timer, and a test moves them all with `crate::time::advance`.
pub(crate) type PeerClock = crate::time::HostClock;

/// An instant on [`PeerClock`].
pub(crate) type PeerInstant = <PeerClock as Clock>::Instant;

/// Now on [`PeerClock`].
pub(crate) fn peer_now() -> PeerInstant {
    PeerClock::default().now()
}

/// Time from `earlier` to now on [`PeerClock`], zero when `earlier` is the
/// later one.
pub(crate) fn since(earlier: PeerInstant) -> Duration {
    peer_now().saturating_duration_since(earlier)
}

/// The rekey profile of a link: the pattern this line's links speak.
pub(crate) type LinkProfile = FmpProfile<OsEntropy>;

/// The rekey machine of one active peer's link: its current, pending and
/// previous epochs with their keys, indices and key-epoch bits, its own
/// rekey handshake in flight, the drain, the peer's startup epoch,
/// dampening and the replay record. It decides every link rekey: it starts
/// and resends this node's rekeys, answers the peer's, and cuts over.
pub(crate) type LinkRekey = Rekey<LinkProfile, PeerClock>;

/// What one call to a link's rekey machine asks the node to do.
pub(crate) type LinkOutputs = Outputs<LinkProfile>;

/// One thing a link's rekey machine asks the node to do.
pub(crate) type LinkOutput = Output<LinkProfile>;

// The link machines draw their rekey jitter over the range, and keep the
// drain window and the dampening, the deployed link shell has always used.
const _: () = {
    assert!(Config::fmp().jitter as i64 == crate::node::REKEY_JITTER_SECS);
    assert!(Config::fmp().drain.as_secs() == 10);
    assert!(Config::fmp().dampening.as_secs() == 30);
};

/// The parameters a test's link machine runs with: the link defaults, as a
/// node with the default configuration runs them.
#[cfg(test)]
pub(crate) fn test_link_params() -> Params {
    Params::fmp()
}

/// What building a link's rekey machine borrows from the node: its index
/// allocator, its static keys, its address, the parameters a new link's
/// machine is built with, the replay record it starts from and whether a
/// decrypt-worker pool runs.
pub(crate) struct LinkCaps<'a> {
    /// The node's session-index allocator.
    pub(crate) indices: &'a mut IndexAllocator,
    /// The node's static keypair and startup epoch.
    pub(crate) local: &'a NodeKeys,
    /// The node's address, for the tie-break.
    pub(crate) me: NodeAddr,
    /// The parameters a new link's machine is built with.
    pub(crate) params: Params,
    /// The record a closed link with the same peer at the same startup
    /// epoch left, empty when there was none; the machine takes it. A
    /// cross-connection move does not read it: the moved machine takes the
    /// record of the machine it replaces.
    pub(crate) record: Record,
    /// Whether a decrypt-worker pool runs, to which the new machine offers
    /// its first session at once. False at a promotion, which offers it once
    /// the peer is in the node's table.
    pub(crate) workers: bool,
}

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
