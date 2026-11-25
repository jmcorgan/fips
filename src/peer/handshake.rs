//! One handshake in flight, as the node holds it beside the settlement
//! core's leg: its Noise crypto, its bookkeeping, and where its dial came
//! from.
//!
//! The settlement core decides every handshake and holds its leg (the msg1,
//! the resends, the deadline and the lease). What the core does not hold
//! lives here, in the node's handshake map entry for the link: the Noise
//! handshake and the session it completes, the pair, indices, epoch and wall
//! stamps the promotion and the control API read, the stored msg1 and msg2,
//! the dial's origin, and whether the handshake failed past recovery. An
//! entry is made at a dial or an answered msg1, and goes when the handshake
//! is promoted, given up or reaped.

use crate::PeerIdentity;
use crate::identity::ErasingKeypair;
use crate::noise::{self, NoiseError, NoiseSession};
use crate::proto::fmp::{ConnectionState, LegStamp, Msg1Digest};
use crate::transport::{LinkDirection, LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use fips_core::proto::rekey::IndexLease;
use secp256k1::Keypair;

/// The handshake operations are only reachable while a pending connection is
/// attached; every path that drives the crypto attaches it first.
fn no_pending_connection() -> NoiseError {
    NoiseError::WrongState {
        expected: "attached connection".to_string(),
        got: "no connection".to_string(),
    }
}

/// The handshake-phase Noise crypto, held by the handshake's entry.
///
/// PRESENCE OF THIS STRUCT (`Handshake::leg().is_some()`) IS THE
/// HANDSHAKE-PHASE CARRIER SIGNAL — it is what `Node::connections()`,
/// `connection_count()`, the stale-connection sweep, the transport-in-use
/// check, and the peering budget all key on. It is attached and detached at
/// exactly the points the pending connection was, and its presence is NOT a
/// function of whether either handle is populated.
///
/// A present-but-empty value is legal and required: `fail` drops
/// the initiation handle while deliberately retaining the carrier so the
/// sweep can reclaim it, and `take_session` empties the other. Deriving
/// presence from handle presence would make every failed handshake invisible
/// to the sweep — a permanent leak.
pub(crate) struct HandshakeCrypto {
    /// Noise handshake state (consumed on completion).
    pub(crate) noise_handshake: Option<noise::HandshakeState>,
    /// Completed Noise session (available once the handshake completes).
    pub(crate) noise_session: Option<NoiseSession>,
}

impl HandshakeCrypto {
    /// A fresh carrier holding neither handle, as every handshake begins.
    pub(crate) fn new() -> Self {
        Self {
            noise_handshake: None,
            noise_session: None,
        }
    }
}

impl std::fmt::Debug for HandshakeCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeCrypto")
            .field("has_noise_handshake", &self.noise_handshake.is_some())
            .field("has_noise_session", &self.noise_session.is_some())
            .finish()
    }
}

/// Where an outbound dial's expectation of its peer came from.
///
/// A transport neighbour's key claim (a BLE or Ethernet beacon naming a key)
/// is unproven until the handshake completes, and anyone in radio or link
/// range can make one. The per-node gates count a claim leg only against
/// other claims, so claims cannot hold back the node's configured address,
/// LAN advert or redial. Set at the dial site and carried by the handshake's
/// entry for the whole dial, across the pending-connect to handshake-leg
/// hand-off.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DialOrigin {
    /// The address was held for the peer: configuration, a LAN advert for a
    /// configured peer, an overlay advert, a retry, a traversal handoff.
    /// Also every inbound handshake.
    #[default]
    Addressed,
    /// An mDNS advert named the address, for a node this node is not
    /// configured to dial. Counted as addressed by the claim gates; its msg1
    /// is resent at most [`DISCOVERY_RESENDS`] times.
    MdnsAdvert,
    /// A transport neighbour claimed the peer's key.
    NeighbourClaim,
}

/// The most msg1 resends of a handshake an mDNS advert directs at a node
/// this node is not configured to dial: six msg1 in all with the first
/// (FRC-1201 Section 3.1). An advert can name any address, so this bounds
/// what one advert can make the node send there.
pub(crate) const DISCOVERY_RESENDS: u32 = 5;

/// The node's entry for one handshake: its crypto while the handshake is in
/// flight, its bookkeeping, and the facts about it the settlement core's leg
/// does not hold.
pub(crate) struct Handshake {
    /// The handshake-phase Noise crypto. `None` before the handshake begins
    /// (a dial waiting for its transport to connect) and after the promotion
    /// takes it. Its presence, not the state of the handles inside it, is
    /// what marks this entry as carrying a pending handshake; see
    /// [`HandshakeCrypto`].
    leg: Option<HandshakeCrypto>,
    /// The handshake's bookkeeping: link, direction, indices, transport,
    /// stored handshake bytes, epoch and stamps.
    conn: ConnectionState,
    /// The handshake failed past recovery: a stored msg1 could not be sent,
    /// or a msg2 read left no handshake to complete. The stale-connection
    /// sweep reclaims it, and the control API shows it `"failed"`.
    failed: bool,
    /// The handshake has begun: this node's msg1 is written, or the peer's
    /// msg1 is read and answered.
    begun: bool,
    /// The framed msg1 an inbound handshake was set up by, kept until the
    /// work that follows its promotion records it on the peer.
    held_msg1: Option<Vec<u8>>,
    /// Where this handshake's dial came from; see [`DialOrigin`].
    origin: DialOrigin,
}

impl Handshake {
    /// A dial of this node's to `identity` on `link`, begun at `at`.
    pub(crate) fn new_outbound(link: LinkId, identity: PeerIdentity, at: LegStamp) -> Self {
        Self::with(ConnectionState::outbound(link, identity, at))
    }

    /// The peer's handshake on `link`, its msg1 arriving at `at`.
    pub(crate) fn new_inbound(link: LinkId, at: LegStamp) -> Self {
        Self::with(ConnectionState::inbound(link, at))
    }

    fn with(conn: ConnectionState) -> Self {
        Self {
            leg: None,
            conn,
            failed: false,
            begun: false,
            held_msg1: None,
            origin: DialOrigin::Addressed,
        }
    }

    /// Record a failure past recovery: the Noise handshake handle is
    /// dropped, so a later `complete_handshake` reports `WrongState`, and
    /// the crypto carrier is kept, so the stale-connection sweep, which
    /// reads [`is_failed`](Self::is_failed), reclaims the handshake.
    pub(crate) fn fail(&mut self) {
        if let Some(leg) = self.leg.as_mut() {
            leg.noise_handshake = None;
        }
        self.failed = true;
    }

    /// Whether this handshake failed past recovery.
    pub(crate) fn is_failed(&self) -> bool {
        self.failed
    }

    /// The handshake state the control API shows for this handshake:
    /// `"failed"` once it failed, `"sent_msg1"` once this node's msg1 is
    /// written, `"received_msg1"` once the peer's msg1 is read and answered,
    /// and `"initial"` before either.
    pub(crate) fn shown_state(&self) -> &'static str {
        if self.failed {
            "failed"
        } else if !self.begun {
            "initial"
        } else if self.conn.is_outbound() {
            "sent_msg1"
        } else {
            "received_msg1"
        }
    }

    /// Keep `msg1`, the framed msg1 this inbound leg is being set up by, for
    /// the work that follows its promotion.
    pub(crate) fn hold_msg1(&mut self, msg1: Vec<u8>) {
        self.held_msg1 = Some(msg1);
    }

    /// Take the framed msg1 this inbound leg was set up by, if one is held.
    pub(crate) fn take_msg1(&mut self) -> Option<Vec<u8>> {
        self.held_msg1.take()
    }

    /// The handshake crypto carrier, if this handshake is still in
    /// flight. Presence answers "is there a pending handshake
    /// here", independently of whether either handle is populated.
    pub(crate) fn leg(&self) -> Option<&HandshakeCrypto> {
        self.leg.as_ref()
    }

    /// Take the handshake crypto carrier off the entry (promotion and
    /// teardown consume it by value).
    pub(crate) fn take_leg(&mut self) -> Option<HandshakeCrypto> {
        // The entry outlives the promotion until its work is done, so the
        // slot is cleared as the leg leaves, or it would keep the session's
        // traffic keys. Callers unwrap the result at once, which `take_cleared`
        // warns may leave a second stack copy; clearing here still covers every
        // caller's heap slot, and a stack copy is a move like any other.
        noise::take_cleared(&mut self.leg)
    }

    /// Attach a handshake crypto carrier to the entry.
    pub(crate) fn set_leg(&mut self, leg: HandshakeCrypto) {
        self.leg = Some(leg);
    }

    // === Noise handshake operations ===
    //
    // Mechanism, not decision: these are called by the shell, are never
    // reached from `step()`, and no event triggers them. Each drives the
    // Noise crypto on the pending connection and records the results on both
    // the entry's bookkeeping, so a reader of either sees
    // the same value at the same point.

    /// Start the handshake as initiator and generate message 1.
    ///
    /// For outbound connections only. Returns the handshake message to send.
    /// The epoch is our startup epoch, encrypted into msg1 for restart detection.
    pub(crate) fn start_handshake(
        &mut self,
        mut our_keypair: Keypair,
        epoch: [u8; 8],
        at: LegStamp,
    ) -> Result<Vec<u8>, NoiseError> {
        // The parameter is this frame's own copy of the node's long-term
        // private key, and the state checks below return before it is used.
        // The guard clears it in place on every exit path, and makes no copy
        // of its own for an early return to leave behind.
        let our_keypair = ErasingKeypair::new(&mut our_keypair);

        let msg1 = {
            let direction = self.conn.direction();
            let expected_identity = self.conn.expected_identity().copied();
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            if direction != LinkDirection::Outbound {
                return Err(NoiseError::WrongState {
                    expected: "outbound connection".to_string(),
                    got: "inbound connection".to_string(),
                });
            }

            let remote_static = expected_identity
                .expect("outbound must have expected identity")
                .pubkey_full();

            let mut kp = *our_keypair.get();
            let mut hs = noise::HandshakeState::new_initiator(kp, remote_static);
            kp.non_secure_erase();
            hs.set_local_epoch(epoch);
            let msg1 = hs.write_message_1()?;

            leg.noise_handshake = Some(hs);

            msg1
        };
        self.conn.touch(at);
        self.begun = true;

        Ok(msg1)
    }

    /// Initialize responder and process incoming message 1.
    ///
    /// For inbound connections only. Returns the handshake message 2 to send.
    /// The epoch is our startup epoch, encrypted into msg2 for restart detection.
    pub(crate) fn receive_handshake_init(
        &mut self,
        mut our_keypair: Keypair,
        epoch: [u8; 8],
        message: &[u8],
        at: LegStamp,
    ) -> Result<Vec<u8>, NoiseError> {
        // Same as `start_handshake`: the parameter copy outlives two early
        // returns, so the guard clears it in place rather than an erase per
        // exit path.
        let our_keypair = ErasingKeypair::new(&mut our_keypair);

        let (msg2, learned_identity, remote_epoch) = {
            let direction = self.conn.direction();
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            if direction != LinkDirection::Inbound {
                return Err(NoiseError::WrongState {
                    expected: "inbound connection".to_string(),
                    got: "outbound connection".to_string(),
                });
            }

            let mut kp = *our_keypair.get();
            let mut hs = noise::HandshakeState::new_responder(kp);
            kp.non_secure_erase();
            hs.set_local_epoch(epoch);

            // Process message 1 (this reveals the initiator's identity and epoch)
            hs.read_message_1(message)?;

            // Extract the discovered identity from the crypto and record it as
            // pure data on the state.
            let remote_static = *hs
                .remote_static()
                .expect("remote static available after msg1");
            let learned_identity = PeerIdentity::from_pubkey_full(remote_static);

            // Capture remote epoch from msg1
            let remote_epoch = hs.remote_epoch();

            // Generate message 2
            let msg2 = hs.write_message_2()?;

            // Handshake is complete for responder
            let session = hs.into_session()?;
            leg.noise_session = Some(session);

            (msg2, learned_identity, remote_epoch)
        };
        self.conn.set_expected_identity(learned_identity);
        self.conn.set_remote_epoch(remote_epoch);
        self.conn.touch(at);
        self.begun = true;

        Ok(msg2)
    }

    /// Complete the handshake by processing message 2.
    ///
    /// For outbound connections only (initiator completing handshake).
    ///
    /// Nothing authenticates a msg2 before it is read, and the index it names
    /// travels in cleartext in our msg1, so a msg2 that fails to read may be a
    /// forgery rather than the responder's answer. The read runs on a fork of
    /// the handshake, which stays in the leg untouched, so the genuine msg2
    /// can still complete it. The two kinds of error are told apart by the
    /// leg:
    ///
    /// - an error with the handle still in the leg means the msg2 did not
    ///   authenticate and nothing on the entry changed;
    /// - an error with the handle gone (no handshake in progress, or a failure
    ///   to make the session after a successful read) means the leg cannot
    ///   continue.
    pub(crate) fn complete_handshake(
        &mut self,
        message: &[u8],
        at: LegStamp,
    ) -> Result<(), NoiseError> {
        let remote_epoch = {
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            // The connection is at `SentMsg1` iff its Noise handshake handle is
            // present (set by `start_handshake`, taken here on completion).
            // Gating on the handle directly is byte-equivalent to the old
            // `!= SentMsg1` guard for every reachable transition.
            let Some(pending) = leg.noise_handshake.as_ref() else {
                return Err(NoiseError::WrongState {
                    expected: "sent_msg1 state".to_string(),
                    got: "no active handshake".to_string(),
                });
            };

            // The read runs on a fork, so a msg2 that fails it leaves the
            // handshake in its slot exactly as it was.
            let hs = pending.fork_msg2(message)?;

            // The read authenticated, so the fork replaces the handshake in
            // the slot. The slot is heap memory that outlives this call;
            // clearing it drops the handshake in place, which erases both of
            // its private keys there, and zeroes what is left.
            noise::clear_slot(&mut leg.noise_handshake);

            // Capture remote epoch from msg2
            let remote_epoch = hs.remote_epoch();

            let session = hs.into_session()?;
            leg.noise_session = Some(session);

            remote_epoch
        };
        self.conn.set_remote_epoch(remote_epoch);
        self.conn.touch(at);

        Ok(())
    }

    /// Take the completed Noise session.
    ///
    /// Returns the NoiseSession for use in ActivePeer. Can only be called
    /// once after the handshake completes.
    #[cfg(test)]
    pub(crate) fn take_session(&mut self) -> Option<NoiseSession> {
        // The session exists iff the handshake reached `Complete`, so taking it
        // unconditionally is byte-equivalent to the old `== Complete` gate.
        // The slot is cleared as the session leaves, so its two traffic keys
        // do not stay behind in the entry.
        self.leg
            .as_mut()
            .and_then(|leg| noise::take_cleared(&mut leg.noise_session))
    }

    /// Check if we have a completed session ready to take.
    #[cfg(test)]
    pub(crate) fn has_session(&self) -> bool {
        self.leg
            .as_ref()
            .is_some_and(|leg| leg.noise_session.is_some())
    }

    /// The session index we allocated for this peer, read from the surviving
    /// carrier. The shell draws it and the handshake's leg in the settlement
    /// core holds it; the carrier takes it when a dial's msg2 completes the
    /// dial, or when an answer is promoted. `None` before then (and after a
    /// rejected/unauthorized msg1).
    pub(crate) fn our_index(&self) -> Option<SessionIndex> {
        self.conn.our_index()
    }

    /// Take the lease holding our session index off the handshake:
    /// the promotion hands it to the active peer's link rekey machine, a
    /// cross-connection hands it to the promoted peer's, and the
    /// stale-connection reaper frees it.
    pub(crate) fn take_our_index(&mut self) -> Option<IndexLease> {
        self.conn.take_our_index()
    }

    /// Connection-start timestamp of the handshake — the home for the
    /// operator-visible `started_at_ms` now that the leg no longer projects it.
    pub(crate) fn conn_started_at(&self) -> u64 {
        self.conn.started_at()
    }

    /// Last-activity timestamp of the handshake, on the wall clock —
    /// the home for the operator-visible `last_activity_ms`/`idle_ms`.
    pub(crate) fn conn_last_activity(&self) -> u64 {
        self.conn.last_activity()
    }

    /// Last activity of the handshake on the interval clock, which
    /// the idle-timeout check reads.
    #[cfg(test)]
    pub(crate) fn conn_active_at(&self) -> u64 {
        self.conn.active_at()
    }

    /// Whether the carrier has been idle past `timeout_ms` at
    /// `interval_now`, a reading of the interval clock.
    pub(crate) fn conn_is_timed_out(&self, interval_now: u64, timeout_ms: u64) -> bool {
        self.conn.is_timed_out(interval_now, timeout_ms)
    }

    /// Expected peer identity of the handshake — the home for the
    /// operator-visible `expected_peer` now that the leg no longer projects it.
    /// Outbound carries the dial identity from construction; inbound records
    /// the identity discovered in msg1, written here by `receive_handshake_init`
    /// at the same point it reaches the pending connection. Everything that
    /// names a peer mid-handshake reads this, including the stale-connection
    /// sweep's retry address.
    pub(crate) fn conn_expected_identity(&self) -> Option<&PeerIdentity> {
        self.conn.expected_identity()
    }

    /// Where this handshake's dial came from.
    pub(crate) fn dial_origin(&self) -> DialOrigin {
        self.origin
    }

    /// Record where this handshake's dial came from. Called once, at the
    /// dial site.
    pub(crate) fn set_dial_origin(&mut self, origin: DialOrigin) {
        self.origin = origin;
    }

    /// Remote startup epoch of the handshake, recorded by the
    /// handshake operations at the message that reveals it (msg1 inbound,
    /// msg2 outbound). Promotion reads it to seed the active peer and to
    /// detect a peer restart across a reconnect.
    pub(crate) fn conn_remote_epoch(&self) -> Option<[u8; 8]> {
        self.conn.remote_epoch()
    }

    /// Stored wire-format msg1 of the handshake — the resend source for
    /// the outbound handshake retransmit, now that the leg no longer carries it.
    pub(crate) fn conn_handshake_msg1(&self) -> Option<&[u8]> {
        self.conn.handshake_msg1()
    }

    /// Stored wire-format msg2 of the handshake — the resend source for a
    /// duplicate msg1 while the inbound handshake is still pending.
    pub(crate) fn conn_handshake_msg2(&self) -> Option<&[u8]> {
        self.conn.handshake_msg2()
    }

    /// Store on the handshake the wire-format msg1 this node's dial
    /// sent, which its handshake leg held until the msg2 completed it, for
    /// the promotion that follows. The carrier schedules no resend.
    pub(crate) fn set_conn_handshake_msg1(&mut self, msg1: Vec<u8>) {
        self.conn.set_handshake_msg1(msg1);
    }

    /// Store the wire-format msg2 for duplicate-msg1 resend on the surviving
    /// carrier, mirroring the leg's responder write.
    pub(crate) fn set_conn_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.conn.set_handshake_msg2(msg2);
    }

    /// Record on the handshake the digest of the msg1 that opened
    /// this inbound connection, for the promotion line.
    pub(crate) fn set_conn_msg1_digest(&mut self, digest: Msg1Digest) {
        self.conn.set_msg1_digest(digest);
    }

    /// The digest of the msg1 that opened this inbound connection, if
    /// recorded on the handshake.
    pub(crate) fn conn_msg1_digest(&self) -> Option<Msg1Digest> {
        self.conn.msg1_digest()
    }

    /// Which side opened this connection, read from the handshake.
    /// Seeded at construction: a dial carries an outbound connection state
    /// and the peer's handshake an inbound one.
    pub(crate) fn conn_direction(&self) -> LinkDirection {
        self.conn.direction()
    }

    /// Whether we opened this connection.
    pub(crate) fn conn_is_outbound(&self) -> bool {
        self.conn.is_outbound()
    }

    /// Whether the peer opened this connection.
    pub(crate) fn conn_is_inbound(&self) -> bool {
        self.conn.is_inbound()
    }

    /// The peer's address on this link, read from the handshake.
    /// Written at the same three points the connection's own copy was: the
    /// inbound seed, the outbound dial, and message-2 completion.
    pub(crate) fn conn_source_addr(&self) -> Option<&TransportAddr> {
        self.conn.source_addr()
    }

    pub(crate) fn set_conn_source_addr(&mut self, addr: TransportAddr) {
        self.conn.set_source_addr(addr);
    }

    /// Peer session index of the handshake — the source for the
    /// promotion hand-off now that the leg no longer projects it.
    pub(crate) fn conn_their_index(&self) -> Option<SessionIndex> {
        self.conn.their_index()
    }

    /// Transport ID of the handshake — the source for the promotion
    /// hand-off, the stale-connection cleanup, and the msg1 resend send.
    pub(crate) fn conn_transport_id(&self) -> Option<TransportId> {
        self.conn.transport_id()
    }

    /// Link statistics of the handshake — the seed copied into the
    /// active peer at promotion.
    pub(crate) fn conn_link_stats(&self) -> &LinkStats {
        self.conn.link_stats()
    }

    /// Record the peer session index on the handshake, so the
    /// promotion hand-off reads it from the entry.
    pub(crate) fn set_conn_their_index(&mut self, index: SessionIndex) {
        self.conn.set_their_index(index);
    }

    /// Record the transport ID on the handshake. Written on the
    /// inbound establish path at msg1 and on the outbound dial.
    pub(crate) fn set_conn_transport_id(&mut self, id: TransportId) {
        self.conn.set_transport_id(id);
    }

    /// Record our session index on the handshake, as the lease that
    /// holds it. The outbound establish path takes the lease shell-side and
    /// writes it here, the single index home once the leg dissolves (the
    /// inbound path writes the carrier directly at authorize). A lease the
    /// carrier already held is handed back, for the caller to release.
    pub(crate) fn set_conn_our_index(&mut self, index: IndexLease) -> Option<IndexLease> {
        self.conn.set_our_index(index)
    }

    /// Adopt an explicit connection-start timestamp on the carrier, so the
    /// surviving state keeps the leg's start provenance rather than the
    /// dial-time construction default.
    pub(crate) fn set_conn_started_at(&mut self, started_at_ms: u64) {
        self.conn.set_started_at(started_at_ms);
    }

    /// Advance the carrier's last-activity timestamp — the paired
    /// write for the leg's handshake `touch`.
    pub(crate) fn touch_conn(&mut self, at: LegStamp) {
        self.conn.touch(at);
    }
}

#[cfg(test)]
#[path = "tests/handshake.rs"]
mod tests;
