//! Sans-IO FMP connection-lifecycle state.
//!
//! The pure, runtime-agnostic bookkeeping for an in-progress FMP peer
//! connection — link/direction identity, the handshake-phase enum, learned
//! peer identity and epoch, index/transport/address tracking, handshake-resend
//! scheduling, and link statistics — extracted out of the async node shell.
//!
//! [`ConnectionState`] owns every **pure** field of the handshake-phase
//! connection. The Noise crypto handles (`noise::HandshakeState`,
//! `NoiseSession`) stay shell-owned in
//! [`PeerConnection`](crate::peer::PeerConnection), which holds a
//! `ConnectionState` alongside them and drives the two halves side by side. The
//! shell's XX transition methods validate against the pure phase, drive the
//! Noise objects, then write learned results back through the pure setters here
//! (`set_handshake_state`, `set_expected_identity`, `set_remote_epoch`,
//! `touch`).
//!
//! This state is `no_std`+`alloc`-clean with respect to transport: the
//! identifier/address/statistics value types are the plain-data `transport`
//! primitives (defined in the `no_std` `transport::types` module, named here
//! via their `crate::transport` re-export). Two `std`-tethers remain —
//! [`PeerIdentity`] and [`SessionIndex`] — plain-data types whose defining
//! modules are not yet `no_std`. They are named here as data only (never
//! driving crypto) and mirror the tether already carried by the sibling
//! decision [`core`](super::core).
//!
//! [`Fmp`] is the separate, stateless lifecycle anchor owned by
//! [`Node`](crate::node::Node); see its doc below.

use super::wire::NodeProfile;
use crate::PeerIdentity;
use crate::transport::{LinkDirection, LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use core::fmt;

/// Handshake protocol state machine.
///
/// For Noise XX pattern:
/// - Initiator: Initial → SentMsg1 → Complete (after processing msg2 + sending msg3)
/// - Responder: Initial → ReceivedMsg1 → Complete (after processing msg3)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state, ready to start handshake.
    Initial,
    /// Initiator: Sent message 1, awaiting message 2.
    SentMsg1,
    /// Responder: Received message 1, ready to send message 2.
    ReceivedMsg1,
    /// Handshake completed successfully.
    Complete,
    /// Handshake failed.
    Failed,
}

impl HandshakeState {
    /// Check if handshake is still in progress.
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            HandshakeState::Initial | HandshakeState::SentMsg1 | HandshakeState::ReceivedMsg1
        )
    }

    /// Check if handshake completed successfully.
    pub fn is_complete(&self) -> bool {
        matches!(self, HandshakeState::Complete)
    }

    /// Check if handshake failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, HandshakeState::Failed)
    }
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HandshakeState::Initial => "initial",
            HandshakeState::SentMsg1 => "sent_msg1",
            HandshakeState::ReceivedMsg1 => "received_msg1",
            HandshakeState::Complete => "complete",
            HandshakeState::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

/// Pure, runtime-agnostic bookkeeping for a connection in the handshake phase.
///
/// Owns every non-crypto field of the handshake-phase connection. The Noise
/// crypto handles live beside it in the shell
/// [`PeerConnection`](crate::peer::PeerConnection); this struct is written only
/// as plain data — the shell extracts learned identity/epoch out of the crypto
/// objects and sets them here through the setters.
#[derive(Debug)]
pub struct ConnectionState {
    // === Link Reference ===
    /// The link carrying this connection.
    link_id: LinkId,

    /// Connection direction (we initiated or they initiated).
    direction: LinkDirection,

    // === Handshake State ===
    /// Current handshake state.
    handshake_state: HandshakeState,

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
    /// Our sender_idx for this handshake (chosen by us).
    /// For outbound: included in msg1, used as receiver_idx in msg2 echo.
    /// For inbound: chosen after processing msg1, included in msg2.
    our_index: Option<SessionIndex>,

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

    // === Negotiation Results ===
    /// Peer's node profile (learned from negotiation payload).
    peer_profile: Option<NodeProfile>,

    // === Handshake Resend ===
    /// Wire-format msg1 bytes for resend (initiator only).
    handshake_msg1: Option<Vec<u8>>,

    /// Wire-format msg2 bytes for resend (responder only).
    handshake_msg2: Option<Vec<u8>>,

    /// Number of resends performed so far.
    resend_count: u32,

    /// When the next resend should fire (Unix ms). 0 = no resend scheduled.
    next_resend_at_ms: u64,
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
            handshake_state: HandshakeState::Initial,
            expected_identity: Some(expected_identity),
            started_at: current_time_ms,
            last_activity: current_time_ms,
            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: None,
            source_addr: None,
            remote_epoch: None,
            peer_profile: None,
            handshake_msg1: None,
            handshake_msg2: None,
            resend_count: 0,
            next_resend_at_ms: 0,
        }
    }

    /// Create the pure state for a new outbound connection without a pre-known
    /// identity.
    ///
    /// Used for anonymous discovery on shared-media transports (Ethernet, BLE)
    /// where the beacon doesn't carry identity. The peer's identity is learned
    /// from XX msg2 during the handshake.
    pub fn outbound_anonymous(link_id: LinkId, current_time_ms: u64) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Outbound,
            handshake_state: HandshakeState::Initial,
            expected_identity: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,
            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: None,
            source_addr: None,
            remote_epoch: None,
            peer_profile: None,
            handshake_msg1: None,
            handshake_msg2: None,
            resend_count: 0,
            next_resend_at_ms: 0,
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
            handshake_state: HandshakeState::Initial,
            expected_identity: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,
            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: None,
            source_addr: None,
            remote_epoch: None,
            peer_profile: None,
            handshake_msg1: None,
            handshake_msg2: None,
            resend_count: 0,
            next_resend_at_ms: 0,
        }
    }

    /// Create the pure state for a new inbound connection with transport info.
    ///
    /// Used when processing msg1 where we know the transport and source address.
    pub fn inbound_with_transport(
        link_id: LinkId,
        transport_id: TransportId,
        source_addr: TransportAddr,
        current_time_ms: u64,
    ) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Inbound,
            handshake_state: HandshakeState::Initial,
            expected_identity: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,
            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: Some(transport_id),
            source_addr: Some(source_addr),
            remote_epoch: None,
            peer_profile: None,
            handshake_msg1: None,
            handshake_msg2: None,
            resend_count: 0,
            next_resend_at_ms: 0,
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

    /// Get the handshake state.
    pub fn handshake_state(&self) -> HandshakeState {
        self.handshake_state
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

    /// Check if handshake is in progress.
    pub fn is_in_progress(&self) -> bool {
        self.handshake_state.is_in_progress()
    }

    /// Check if handshake completed.
    pub fn is_complete(&self) -> bool {
        self.handshake_state.is_complete()
    }

    /// Check if handshake failed.
    pub fn is_failed(&self) -> bool {
        self.handshake_state.is_failed()
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

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.link_stats
    }

    // === Index Accessors ===

    /// Get our session index (if set).
    pub fn our_index(&self) -> Option<SessionIndex> {
        self.our_index
    }

    /// Set our session index.
    pub fn set_our_index(&mut self, index: SessionIndex) {
        self.our_index = Some(index);
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

    // === Negotiation Results ===

    /// Get the peer's negotiated node profile, if learned.
    pub fn peer_profile(&self) -> Option<NodeProfile> {
        self.peer_profile
    }

    /// Record the peer's node profile learned during FMP negotiation.
    pub fn set_negotiation_results(&mut self, peer_profile: NodeProfile) {
        self.peer_profile = Some(peer_profile);
    }

    // === Handshake Phase Advance ===

    /// Advance the pure handshake phase. Driven by the shell after it has
    /// stepped the Noise objects.
    pub fn set_handshake_state(&mut self, state: HandshakeState) {
        self.handshake_state = state;
    }

    /// Mark the pure handshake phase failed. The shell drops the crypto handle
    /// separately.
    pub fn mark_failed(&mut self) {
        self.handshake_state = HandshakeState::Failed;
    }

    // === Handshake Resend ===

    /// Store the wire-format msg1 bytes for resend and schedule the first resend.
    pub fn set_handshake_msg1(&mut self, msg1: Vec<u8>, first_resend_at_ms: u64) {
        self.handshake_msg1 = Some(msg1);
        self.resend_count = 0;
        self.next_resend_at_ms = first_resend_at_ms;
    }

    /// Store the wire-format msg2 bytes for resend on duplicate msg1.
    pub fn set_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.handshake_msg2 = Some(msg2);
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

    /// When the next resend is scheduled (Unix ms).
    pub fn next_resend_at_ms(&self) -> u64 {
        self.next_resend_at_ms
    }

    /// Record a resend and schedule the next one.
    pub fn record_resend(&mut self, next_resend_at_ms: u64) {
        self.resend_count += 1;
        self.next_resend_at_ms = next_resend_at_ms;
    }

    // === Activity / Timeout ===

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
/// [`Node`](crate::node::Node).
///
/// Unlike [`Router`](crate::proto::routing::Router), the FMP lifecycle core
/// owns **no** mutable state: every registry mutation (index allocation,
/// `peers_by_index`/`addr_to_link`/`connections` insertion and removal,
/// decrypt-worker register/unregister) stays shell-side, driven by the
/// [`ConnAction`](super::ConnAction)s the pure `poll_*` decisions emit. `Fmp`
/// is therefore an empty namespace anchor: it exists so the maintain/teardown
/// decisions can hang off a `Node` field (`self.fmp`) in the same shape the
/// other migrated subsystems use, not to hold data.
pub(crate) struct Fmp;

impl Fmp {
    /// Create the (stateless) FMP lifecycle anchor.
    pub(crate) fn new() -> Self {
        Self
    }
}
