//! Sans-IO FMP connection-lifecycle decision core.
//!
//! Pure, runtime-agnostic maintain/teardown decisions for the FMP peer
//! connection lifecycle: handshake-connection timeout/teardown and outbound
//! msg1 resend scheduling. Link rekeys are decided by each link's rekey
//! machine (`proto::rekey`), not here. The async I/O adapters in
//! `node::handlers::timeout` build a [`LifecycleView`] over live node state (pre-computing every clock
//! read into plain `u64`/`bool` snapshot fields), call the `poll_*` decisions,
//! and drive the returned [`ConnAction`]s — the actual sends, registry
//! mutations, metrics, and logging. No I/O, no clock, no metrics, no logging
//! here.
//!
//! The establish leaf's Noise wire construction and the promotion's effects
//! stay shell-side; handshake message bytes are carried as opaque blobs only.
//! Each handshake is classified by the settlement core (`proto::settle`);
//! this module keeps the msg1 outcome the shell's Noise step yields
//! ([`WireOutcome`]), the refusals it counts ([`InboundReject`]) and the
//! cross-connection tie-break.

use super::state::Fmp;
use crate::identity::{NodeAddr, PeerIdentity};
use crate::transport::LinkId;
use crate::utils::index::SessionIndex;
use alloc::vec::Vec;

/// Determine winner of cross-connection tie-breaker.
///
/// Rule: The node with the smaller node_addr prefers its OUTBOUND connection.
/// This is deterministic and symmetric: both nodes will reach the same conclusion.
///
/// # Arguments
/// * `our_node_addr` - Our node's ID
/// * `their_node_addr` - The peer's node ID
/// * `this_is_outbound` - Whether the connection being evaluated is our outbound
///
/// # Returns
/// `true` if this connection should win (survive), `false` if it should close.
pub fn cross_connection_winner(
    our_node_addr: &NodeAddr,
    their_node_addr: &NodeAddr,
    this_is_outbound: bool,
) -> bool {
    let we_are_smaller = our_node_addr < their_node_addr;

    // Smaller node's outbound wins
    // If we're smaller: our outbound wins, our inbound loses
    // If they're smaller: our outbound loses, our inbound wins
    if we_are_smaller {
        this_is_outbound
    } else {
        !this_is_outbound
    }
}

/// Result of attempting to promote a connection to active peer.
///
/// When a handshake completes, we may discover that we already have a
/// connection to this peer (cross-connection). The tie-breaker rule
/// determines which connection survives.
///
/// Note: Returns NodeAddr instead of ActivePeer because ActivePeer cannot
/// be cloned (it contains NoiseSession which has cryptographic state).
/// Callers can look up the peer from the peers map using the NodeAddr.
#[derive(Debug, Clone, Copy)]
pub enum PromotionResult {
    /// New peer created successfully.
    Promoted(NodeAddr),

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
        node_addr: NodeAddr,
    },
}

impl PromotionResult {
    /// Get the node ID if promotion succeeded.
    pub fn node_addr(&self) -> Option<NodeAddr> {
        match self {
            PromotionResult::Promoted(node_addr) => Some(*node_addr),
            PromotionResult::CrossConnectionWon { node_addr, .. } => Some(*node_addr),
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

/// A snapshot of one handshake connection's lifecycle-relevant state, taken by
/// the shell so the core decides without touching live `Node` state or reading
/// a clock.
///
/// Produced by the [`LifecycleView`] read-seam for the teardown decision,
/// [`Fmp::poll_timeouts`].
pub struct ConnSnapshot {
    /// The connection's link identifier (the teardown target).
    pub link: LinkId,
    /// Teardown path: is this an outbound connection? Drives retry scheduling
    /// (only outbound auto-connect peers are retried).
    pub is_outbound: bool,
    /// Teardown path: the retry target learned from the connection's expected
    /// identity, if any. `None` when no identity is known.
    pub retry_addr: Option<NodeAddr>,
}

/// A digest of one link handshake msg1 exactly as it arrived, header included.
///
/// The initiator's resend ladder retransmits its stored msg1 bytes unchanged,
/// so a resend digests equal to the original and any other msg1 does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msg1Digest([u8; 32]);

impl Msg1Digest {
    /// Digest the wire bytes of one msg1.
    pub fn of(wire_msg1: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::digest(wire_msg1).into())
    }

    /// The first four bytes of the digest, the part the log lines carry.
    pub fn prefix(&self) -> [u8; 4] {
        [self.0[0], self.0[1], self.0[2], self.0[3]]
    }
}

/// The same SHA-256 value as the digest a link's rekey machine records.
impl From<Msg1Digest> for crate::proto::rekey::Digest {
    fn from(d: Msg1Digest) -> Self {
        Self(d.0)
    }
}

/// The digest a link's rekey machine recorded, as the msg1 digest it is.
impl From<crate::proto::rekey::Digest> for Msg1Digest {
    fn from(d: crate::proto::rekey::Digest) -> Self {
        Self(d.0)
    }
}

/// A digest of the initiator ephemeral a link handshake msg1 carries.
///
/// The ephemeral is authenticated by the msg1's own AEAD (it is mixed into
/// the handshake hash before the encrypted static), so a copy with a changed
/// header still carries the same ephemeral, while the whole-message
/// [`Msg1Digest`] that recognises resends does not match it. The records
/// that must count one captured msg1 once, however its header is rewritten,
/// key on this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EphemeralDigest([u8; 32]);

impl EphemeralDigest {
    /// Digest the ephemeral at the start of a Noise IK msg1, or `None` if the
    /// message is too short to carry one.
    pub fn of_noise_msg1(noise_msg1: &[u8]) -> Option<Self> {
        use sha2::{Digest, Sha256};
        let ephemeral = noise_msg1.get(..crate::noise::PUBKEY_SIZE)?;
        Some(Self(Sha256::digest(ephemeral).into()))
    }
}

/// The result of the shell-side Noise wire step (Phase B) for one inbound
/// handshake msg1.
///
/// The Noise step (`receive_handshake_init`) runs on the handshake's entry:
/// it reads **no** `Node` registry state — the essential invariant of this
/// decomposition — and yields the learned peer identity, the
/// remote startup epoch, the sender's session index, and the opaque msg2 noise
/// payload to frame and send. The core never parses or builds Noise bytes; the
/// payload is an opaque blob.
pub struct WireOutcome {
    /// Peer identity learned from the handshake (msg1 static key).
    pub peer_identity: PeerIdentity,
    /// The peer's startup epoch captured from msg1, if present.
    pub remote_epoch: Option<[u8; 8]>,
    /// The sender's session index from the msg1 header (becomes our
    /// `receiver_idx`/`their_index` in the msg2 response and the promotion).
    pub their_index: SessionIndex,
    /// The opaque Noise msg2 payload the responder produced (empty only if no
    /// msg2 is to be sent).
    pub msg2_payload: Vec<u8>,
    /// Digest of the msg1 as it arrived, which the promotion records as the
    /// link-setup msg1.
    pub msg1_digest: Msg1Digest,
}

/// A registry/transport effect the async shell performs on the core's behalf.
///
/// The maintain/teardown subset (`Teardown`, `ScheduleRetry`) covers the
/// tick-poll half of the lifecycle.
pub enum ConnAction {
    /// Tear down and free the handshake connection on `link`
    /// (`cleanup_stale_connection`): frees the session index, removes the
    /// `pending_outbound` entry, and cleans up the link + address mapping.
    Teardown { link: LinkId },
    /// Schedule an auto-connect retry toward `peer` (`schedule_retry`) before
    /// its failed/stale outbound connection is torn down.
    ScheduleRetry { peer: NodeAddr },
}

/// Read-only view of FMP connection/peer state the lifecycle core needs.
///
/// The core defines this interface; the async shell (`node`) implements it over
/// the live handshake and peer maps — handshake-phase state is read off the
/// entries still carrying a pending handshake, active-peer state off
/// `peers`. It is a **snapshot-iterator** seam: each method returns owned
/// snapshot vectors with all clock reads already resolved shell-side, so the
/// pure decisions never borrow `Node` and never
/// read a clock. Keeping it a trait keeps `proto` free of a `node` dependency
/// and lets the decisions be unit-tested against hand-built snapshots.
pub trait LifecycleView {
    /// Snapshot every handshake connection that is stale (idle past
    /// `timeout_ms`) or failed, as of `now_ms`. The shell resolves the
    /// timeout/failed predicate; the core decides retry-then-teardown.
    fn stale_connections(&self, now_ms: u64, timeout_ms: u64) -> Vec<ConnSnapshot>;
}

/// Why an inbound msg1 was rejected. Every variant rejects identically
/// (rate-limiter complete, the local not-yet-registered connection dropped),
/// and the shell counts each variant under a handshake reject reason of its
/// own, so no two of them share a counter.
#[derive(Debug)]
pub enum InboundReject {
    /// At `max_peers` and the sender is not a held peer: silent-drop before any
    /// msg2 build/send, whatever dials of this node's own are in flight.
    AtMaxPeers,
    /// The identity's last sessions at this msg1's epoch, at least
    /// `SILENT_SESSION_LIMIT` in a
    /// row, ended without one authenticated frame, and the back-off they
    /// started is still running. Checked only where the msg1 would promote a
    /// new session.
    SilentBackoff,
}

impl Fmp {
    /// Decide the teardown choreography for the stale/failed connections the
    /// shell snapshotted. For each connection, an outbound one with a known
    /// identity first gets an auto-connect retry scheduled, then every
    /// connection is torn down. Pure over the snapshots.
    ///
    /// Preserves the pre-refactor per-connection order (retry before teardown).
    pub fn poll_timeouts(&self, stale: Vec<ConnSnapshot>) -> Vec<ConnAction> {
        let mut actions = Vec::new();
        for snap in stale {
            if snap.is_outbound
                && let Some(peer) = snap.retry_addr
            {
                actions.push(ConnAction::ScheduleRetry { peer });
            }
            actions.push(ConnAction::Teardown { link: snap.link });
        }
        actions
    }
}
