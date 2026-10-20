//! Sans-IO FMP connection-lifecycle state.
//!
//! The pure, runtime-agnostic bookkeeping for an in-progress FMP peer
//! connection — link/direction identity, learned peer identity and epoch,
//! index/transport/address tracking, handshake-resend scheduling, and link
//! statistics — extracted out of the async node shell. The handshake phase
//! itself lives solely on the per-peer control machine
//! (`PeerMachine`), not here.
//!
//! [`ConnectionState`] owns every **pure** field of the handshake-phase
//! connection. The Noise crypto handles (`noise::HandshakeState`,
//! `NoiseSession`) stay shell-owned in the per-peer control machine's
//! handshake carrier, which the machine drives alongside its own
//! `ConnectionState`. The machine's transition methods drive the Noise
//! objects, then write learned results back through the pure setters here
//! (`set_expected_identity`,
//! `set_remote_epoch`, `touch`).
//!
//! This state is `no_std`+`alloc`-clean: the identifier/address/statistics
//! value types are the plain-data `transport` primitives, and
//! [`PeerIdentity`] and [`SessionIndex`] are this crate's `identity` and
//! `utils::index` types. They are named here as data only (never driving
//! crypto). This node's index for the handshake is held as an
//! [`IndexLease`], minted by the rekey machine's `lease::allocate`, so the
//! promotion can hand it to the link's rekey machine as the index of its
//! first epoch.
//!
//! [`Fmp`] is the separate, stateless lifecycle anchor owned by
//! `Node`; see its doc below.

use super::core::Msg1Digest;
use crate::identity::PeerIdentity;
use crate::proto::rekey::IndexLease;
use crate::transport::{LinkDirection, LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use alloc::vec::Vec;

/// Pure, runtime-agnostic bookkeeping for a connection in the handshake phase.
///
/// Owns every non-crypto field of the handshake-phase connection. The Noise
/// crypto handles live beside it on the per-peer control machine; this struct
/// is written only as plain data — the machine extracts learned identity and
/// epoch out of the crypto objects and sets them here through the setters.
#[derive(Debug)]
pub struct ConnectionState {
    // === Link Reference ===
    /// The link carrying this connection.
    link_id: LinkId,

    /// Connection direction (we initiated or they initiated).
    direction: LinkDirection,

    /// Expected peer identity (known for outbound, learned for inbound).
    /// Updated after receiving their static key in the handshake.
    expected_identity: Option<PeerIdentity>,

    // === Timing ===
    /// When the connection attempt started (Unix milliseconds).
    started_at: u64,

    /// When the last handshake message was sent/received.
    last_activity: u64,

    // === Statistics ===
    /// Link statistics during handshake.
    link_stats: LinkStats,

    // === Wire Protocol Index Tracking ===
    /// Our sender_idx for this handshake (chosen by us), as the lease that
    /// holds it in the node's allocator.
    /// For outbound: included in msg1, used as receiver_idx in msg2 echo.
    /// For inbound: chosen after processing msg1, included in msg2.
    our_index: Option<IndexLease>,

    /// Their sender_idx (learned from their messages).
    /// For outbound: learned from msg2.
    /// For inbound: learned from msg1.
    their_index: Option<SessionIndex>,

    /// Transport ID (for index namespace).
    transport_id: Option<TransportId>,

    /// Current source address (updated on packet receipt).
    source_addr: Option<TransportAddr>,

    // === Epoch (Restart Detection) ===
    /// Remote peer's startup epoch (learned from handshake).
    remote_epoch: Option<[u8; 8]>,

    // === Handshake Resend ===
    /// Wire-format msg1 bytes for resend (initiator only).
    handshake_msg1: Option<Vec<u8>>,

    /// Wire-format msg2 bytes for resend (responder only).
    handshake_msg2: Option<Vec<u8>>,

    /// Digest of the msg1 this connection was opened by (responder only),
    /// carried to the promotion line so both ends' logs join on it.
    msg1_digest: Option<Msg1Digest>,

    /// Number of resends performed so far.
    resend_count: u32,
}

impl ConnectionState {
    /// Create the pure state for a new outbound connection (we initiate).
    ///
    /// For outbound, we know who we're trying to reach from configuration.
    pub fn outbound(
        link_id: LinkId,
        expected_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Outbound,
            expected_identity: Some(expected_identity),
            started_at: current_time_ms,
            last_activity: current_time_ms,
            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: None,
            source_addr: None,
            remote_epoch: None,
            handshake_msg1: None,
            handshake_msg2: None,
            msg1_digest: None,
            resend_count: 0,
        }
    }

    /// Create the pure state for a new inbound connection (they initiate).
    ///
    /// For inbound, we don't know who they are until we decrypt their identity
    /// from Noise message 1.
    pub fn inbound(link_id: LinkId, current_time_ms: u64) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Inbound,
            expected_identity: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,
            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: None,
            source_addr: None,
            remote_epoch: None,
            handshake_msg1: None,
            handshake_msg2: None,
            msg1_digest: None,
            resend_count: 0,
        }
    }

    /// Create the pure state for a new inbound connection with transport info.
    ///
    /// Used when processing msg1 where we know the transport and source address.
    #[cfg(test)]
    pub fn inbound_with_transport(
        link_id: LinkId,
        transport_id: TransportId,
        source_addr: TransportAddr,
        current_time_ms: u64,
    ) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Inbound,
            expected_identity: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,
            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: Some(transport_id),
            source_addr: Some(source_addr),
            remote_epoch: None,
            handshake_msg1: None,
            handshake_msg2: None,
            msg1_digest: None,
            resend_count: 0,
        }
    }

    // === Accessors ===

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// Get the connection direction.
    pub fn direction(&self) -> LinkDirection {
        self.direction
    }

    /// Get the expected/learned peer identity, if known.
    pub fn expected_identity(&self) -> Option<&PeerIdentity> {
        self.expected_identity.as_ref()
    }

    /// Check if this is an outbound connection.
    pub fn is_outbound(&self) -> bool {
        self.direction == LinkDirection::Outbound
    }

    /// Check if this is an inbound connection.
    pub fn is_inbound(&self) -> bool {
        self.direction == LinkDirection::Inbound
    }

    /// When the connection started.
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// When the last activity occurred.
    pub fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Connection duration so far.
    #[cfg(test)]
    pub fn duration(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.started_at)
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_activity)
    }

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        &self.link_stats
    }

    // === Index Accessors ===

    /// Get our session index (if set).
    pub fn our_index(&self) -> Option<SessionIndex> {
        self.our_index
            .as_ref()
            .map(|lease| SessionIndex::new(lease.index()))
    }

    /// Hold `lease` as our session index. A lease already held is handed
    /// back, for the caller to release.
    pub fn set_our_index(&mut self, lease: IndexLease) -> Option<IndexLease> {
        self.our_index.replace(lease)
    }

    /// Take our session index's lease (back to unset), for the caller to
    /// release or to hand on.
    pub fn take_our_index(&mut self) -> Option<IndexLease> {
        self.our_index.take()
    }

    /// Get their session index (if known).
    pub fn their_index(&self) -> Option<SessionIndex> {
        self.their_index
    }

    /// Set their session index.
    pub fn set_their_index(&mut self, index: SessionIndex) {
        self.their_index = Some(index);
    }

    /// Get the transport ID (if set).
    pub fn transport_id(&self) -> Option<TransportId> {
        self.transport_id
    }

    /// Set the transport ID.
    pub fn set_transport_id(&mut self, id: TransportId) {
        self.transport_id = Some(id);
    }

    /// Get the source address (if known).
    pub fn source_addr(&self) -> Option<&TransportAddr> {
        self.source_addr.as_ref()
    }

    /// Set the source address.
    pub fn set_source_addr(&mut self, addr: TransportAddr) {
        self.source_addr = Some(addr);
    }

    // === Epoch Accessors ===

    /// Get the remote peer's startup epoch (available after handshake).
    pub fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.remote_epoch
    }

    /// Record the remote peer's startup epoch, as extracted from the crypto
    /// handshake by the shell.
    pub fn set_remote_epoch(&mut self, epoch: Option<[u8; 8]>) {
        self.remote_epoch = epoch;
    }

    // === Learned Identity ===

    /// Record the learned/confirmed peer identity, as extracted from the crypto
    /// handshake by the shell.
    pub fn set_expected_identity(&mut self, identity: PeerIdentity) {
        self.expected_identity = Some(identity);
    }

    // === Handshake Resend ===

    /// Store the wire-format msg1 bytes for resend and reset the resend counter.
    /// The first-resend deadline is scheduled by the shell timer driver, not
    /// tracked here.
    pub fn set_handshake_msg1(&mut self, msg1: Vec<u8>, _first_resend_at_ms: u64) {
        self.handshake_msg1 = Some(msg1);
        self.resend_count = 0;
    }

    /// Store the wire-format msg2 bytes for resend on duplicate msg1.
    pub fn set_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.handshake_msg2 = Some(msg2);
    }

    /// Record the digest of the msg1 that opened this inbound connection.
    pub fn set_msg1_digest(&mut self, digest: Msg1Digest) {
        self.msg1_digest = Some(digest);
    }

    /// The digest of the msg1 that opened this inbound connection, if
    /// recorded.
    pub fn msg1_digest(&self) -> Option<Msg1Digest> {
        self.msg1_digest
    }

    /// Get the stored msg1 bytes (if any).
    pub fn handshake_msg1(&self) -> Option<&[u8]> {
        self.handshake_msg1.as_deref()
    }

    /// Get the stored msg2 bytes (if any).
    pub fn handshake_msg2(&self) -> Option<&[u8]> {
        self.handshake_msg2.as_deref()
    }

    /// Number of resends performed.
    pub fn resend_count(&self) -> u32 {
        self.resend_count
    }

    /// Record a resend. The next-resend deadline is scheduled by the shell
    /// timer driver, not tracked here.
    pub fn record_resend(&mut self, _next_resend_at_ms: u64) {
        self.resend_count += 1;
    }

    // === Activity / Timeout ===

    /// Overwrite the connection-start timestamp. Used when the surviving
    /// control-machine carrier adopts the leg's start provenance instead of the
    /// machine-construction default.
    pub fn set_started_at(&mut self, started_at_ms: u64) {
        self.started_at = started_at_ms;
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_activity = current_time_ms;
    }

    /// Check if the connection has timed out.
    pub fn is_timed_out(&self, current_time_ms: u64, timeout_ms: u64) -> bool {
        self.idle_time(current_time_ms) > timeout_ms
    }
}

/// FMP connection-lifecycle subsystem anchor owned by
/// `Node`.
///
/// Unlike [`Router`](crate::proto::routing::Router), the FMP lifecycle core
/// owns **no** mutable state: every registry mutation (index allocation,
/// `peers_by_index`/`addr_to_link`/`connections` insertion and removal,
/// decrypt-worker register/unregister) stays shell-side, driven by the
/// [`ConnAction`](super::ConnAction)s the pure `poll_*` decisions emit. `Fmp`
/// is therefore an empty namespace anchor: it exists so the maintain/teardown
/// decisions can hang off a `Node` field (`self.fmp`) in the same shape the
/// other migrated subsystems use, not to hold data.
pub struct Fmp;

/// The same as `Fmp::new`.
impl Default for Fmp {
    fn default() -> Self {
        Self::new()
    }
}

impl Fmp {
    /// Create the (stateless) FMP lifecycle anchor.
    pub fn new() -> Self {
        Self
    }
}
