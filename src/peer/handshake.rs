//! A pending handshake's node-side state.
//!
//! The settlement core decides every handshake and holds its leg
//! (`src/node/settle/decide.rs`). What the core's leg does not hold stays in
//! the node, in one [`Handshake`] per link, held in the node's handshake map
//! (`src/node/settle/maps.rs`): the XX Noise crypto ([`HandshakeCrypto`],
//! with an answer's msg3 read, [`LinkFinal`], until the core decides it), the
//! `ConnectionState` bookkeeping (direction, expected peer, indices, pair,
//! epoch, stored msg1 and msg2 and the `LegStamp` stamps), where a dial came
//! from ([`DialOrigin`]), and the handshake's [`Phase`], which the pending
//! connection view shows and the msg1 resend and the stale-connection sweep
//! read.
//!
//! An entry is made at a dial or an answered msg1. A promoted entry stays as
//! the peer's, with no crypto, until the peer is removed; every other end of
//! the handshake drops it. The entry decides nothing: the handshake handlers
//! carry out the core's decisions and write the entry as they go.

use crate::identity::ErasingKeypair;
use crate::identity::OsEntropy;
use crate::noise::{self, NoiseError, NoiseSession};
use crate::proto::fmp::{ConnectionState, DialMsg2Decision, DialMsg2Reject, LegStamp, NodeProfile};
use crate::transport::{LinkDirection, LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{NodeAddr, PeerIdentity};
use fips_core::proto::fmp::rekey::{Unread, read_final};
use fips_core::proto::rekey::IndexLease;
use secp256k1::Keypair;

/// A peer's msg3 as an inbound leg read it: the session it completed, the
/// initiator's identity, startup epoch and negotiation payload, and the lease
/// on the leg's index.
pub(crate) type LinkFinal = fips_core::proto::fmp::rekey::Final<OsEntropy>;

/// Why [`Handshake::read_final`] did not complete the leg.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Msg3Error {
    /// The msg3 or its negotiation payload did not authenticate. The leg is
    /// unchanged: the read ran on a fork, and its handshake and the lease on
    /// its index are kept for the genuine msg3.
    #[error("unreadable msg3")]
    Unreadable,
    /// The leg had no handshake to read with, or a step after a successful
    /// read failed. The leg's handshake is consumed.
    #[error(transparent)]
    Failed(#[from] NoiseError),
}

/// How an initiator's initial msg2 ended, when the dial attempt can continue.
///
/// Only [`Completed`](Self::Completed) consumes the leg's handshake. The other
/// two leave the leg exactly as it was before the msg2 was read, so the
/// genuine msg2 can still complete the attempt.
#[derive(Debug)]
pub(crate) enum DialMsg2Step {
    /// The dial-identity decision accepted the msg2: msg3 is written, the
    /// handshake has become the leg's session, and the learned identity and
    /// epoch are on the carrier. Carries the msg3 bytes and the decrypted
    /// negotiation payload from msg2, if it had one.
    Completed(Vec<u8>, Option<Vec<u8>>),
    /// The msg2 read, and the dial-identity decision rejected the static it
    /// carries. `learned_peer` is the address that static derives to.
    Rejected {
        reason: DialMsg2Reject,
        learned_peer: NodeAddr,
    },
    /// The msg2 did not read or its negotiation payload did not decrypt.
    Unreadable(NoiseError),
}

/// A timer the node arms for a handshake, kept in the handshake map's timer
/// store beside the entry.
///
/// `Hash` lets it key the store; `Ord` lets a reader collect due kinds
/// deterministically. The timeout reaper fires `HandshakeTimeout` before
/// `HandshakeRetransmit` on a same-tick coincidence (a reaped leg must not be
/// resent), which is the reverse of this declaration order, so it orders
/// explicitly rather than relying on the derived `Ord`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TimerKind {
    HandshakeRetransmit,
    HandshakeTimeout,
    /// Armed by no production path: tests plant it to mark a promoted
    /// entry's store, which a move or removal of the peer carries or drops.
    #[cfg_attr(not(test), allow(dead_code))]
    Liveness,
}

/// The milliseconds after a dial's msg1 at which its first resend is due,
/// for a dial whose leg the settlement core does not hold.
pub(crate) const RETRANSMIT_MS: u64 = 1_000;

/// The milliseconds after a dial's msg1 at which its timeout timer is armed.
/// The reaper keys on the timer's presence and reads its threshold from the
/// node's configuration.
pub(crate) const TIMEOUT_MS: u64 = 30_000;

/// Where a handshake stands, as far as the node reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// An outbound entry before its dial is carried out, and an anonymous
    /// dial's entry, whose msg1 its handshake start sends inline.
    Dialing,
    /// A connection-oriented dial whose connect is in flight.
    Connecting,
    /// An identified dial whose msg1 has been sent: its msg1 resends are due
    /// only here.
    SentMsg1,
    /// An answer before its msg1 is answered.
    Answering,
    /// An answer whose msg2 is sent, awaiting msg3.
    SentMsg2,
    /// The handshake promoted: the entry is the peer's.
    Established,
    /// The peer the entry was promoted for was found dead.
    Closed,
}

impl Phase {
    /// The handshake state the pending connection view shows: the strings
    /// the view showed before the entry replaced the per-peer control
    /// machine. An anonymous dial's entry stays at `Dialing` while its msg1
    /// is out, so `Dialing` shows `"sent_msg1"`.
    pub(crate) fn shown(self) -> &'static str {
        match self {
            Phase::Answering | Phase::Connecting | Phase::Closed => "initial",
            Phase::SentMsg1 | Phase::Dialing => "sent_msg1",
            Phase::SentMsg2 => "received_msg1",
            Phase::Established => "complete",
        }
    }
}

/// The handshake operations are only reachable while a pending connection is
/// attached; every path that drives the crypto attaches it first.
fn no_pending_connection() -> NoiseError {
    NoiseError::WrongState {
        expected: "attached connection".to_string(),
        got: "no connection".to_string(),
    }
}

/// The handshake-phase Noise crypto, owned by the handshake entry.
///
/// PRESENCE OF THIS STRUCT (`Handshake::leg().is_some()`) IS THE
/// HANDSHAKE-PHASE CARRIER SIGNAL — it is what `Node::connections()`,
/// `connection_count()`, the stale-connection sweep, the transport-in-use
/// check, and the peering budget all key on. It is attached and detached at
/// exactly the points the pending connection was, and its presence is NOT a
/// function of whether either handle is populated.
///
/// A present-but-empty value is legal and load-bearing: `mark_failed` drops
/// the initiation handle while deliberately retaining the carrier so the
/// sweep can reclaim it, and `take_session` empties the other. Deriving
/// presence from handle presence would make every failed handshake invisible
/// to the sweep — a permanent leak. See the presence tests in this module.
pub(crate) struct HandshakeCrypto {
    /// Noise handshake state (consumed on completion).
    pub(crate) noise_handshake: Option<noise::HandshakeState>,
    /// Completed Noise session (available once the handshake completes).
    pub(crate) noise_session: Option<NoiseSession>,
    /// An inbound leg's msg3 read, held until the establish decision says
    /// whether it is a link setup (its session and lease settle onto the
    /// leg) or a rekey of a peer's link (it goes to that peer's link rekey
    /// machine).
    pub(crate) fin: Option<LinkFinal>,
}

impl HandshakeCrypto {
    /// A fresh carrier holding neither handle, as every handshake begins.
    pub(crate) fn new() -> Self {
        Self {
            noise_handshake: None,
            noise_session: None,
            fin: None,
        }
    }
}

impl std::fmt::Debug for HandshakeCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeCrypto")
            .field("has_noise_handshake", &self.noise_handshake.is_some())
            .field("has_noise_session", &self.noise_session.is_some())
            .field("has_fin", &self.fin.is_some())
            .finish()
    }
}

/// Where an outbound dial's expectation of its peer came from.
///
/// A transport neighbour's key claim (a BLE or Ethernet beacon naming a key)
/// is unproven until the handshake completes, and anyone in radio or link
/// range can make one. The per-node gates count a claim leg only against
/// other claims, so claims cannot hold back the node's configured address,
/// LAN advert or redial. Set at the dial site and carried by the entry for
/// the whole dial, across the pending-connect to handshake-leg hand-off.
///
/// On this line no transport beacon names a key: every transport neighbour
/// is dialled anonymously and is marked `NeighbourClaim` for where it came
/// from, though it claims no identity until its msg2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DialOrigin {
    /// The address was held for the peer: configuration, a LAN advert for a
    /// configured peer, an overlay advert, a retry, a traversal handoff.
    /// Also every inbound entry.
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

impl DialOrigin {
    /// The msg1 resends a dial of this origin may make when the node is
    /// configured for `configured`: capped at [`DISCOVERY_RESENDS`] for a
    /// dial an mDNS advert directs at an unconfigured node, `configured`
    /// for every other dial.
    pub(crate) fn resend_limit(self, configured: u32) -> u32 {
        match self {
            Self::MdnsAdvert => configured.min(DISCOVERY_RESENDS),
            Self::Addressed | Self::NeighbourClaim => configured,
        }
    }
}

/// One link's pending handshake, or the promoted peer's entry. See the
/// module documentation.
pub(crate) struct Handshake {
    phase: Phase,
    link: LinkId,
    identity: Option<PeerIdentity>,
    /// The Noise crypto while the handshake is pending. `None` before the
    /// handshake begins (the dial window) and after the promotion takes it.
    /// Its presence, not the state of the handles inside it, marks the entry
    /// as carrying a pending handshake; see [`HandshakeCrypto`].
    leg: Option<HandshakeCrypto>,
    /// Handshake bookkeeping (link, direction, indices, transport, stored
    /// handshake bytes, epoch), from the FMP state core.
    conn: ConnectionState,
    /// A send or completion failure was seen on this handshake. Carried as a
    /// flag beside the phase, so msg1 resend eligibility survives until the
    /// stale-connection sweep reclaims the handshake. It drives
    /// [`is_failed`](Self::is_failed) and the shown state `"failed"`.
    send_failed: bool,
    /// Where this entry's dial came from; see [`DialOrigin`].
    origin: DialOrigin,
}

impl Handshake {
    /// A new outbound entry (we dial), at [`Phase::Dialing`]. `identity` is
    /// `None` for an anonymous-discovery dial (a shared-media beacon carries no
    /// identity): [`crystallize_identity`](Self::crystallize_identity) fills it
    /// in when the XX msg2 reveals who answered.
    pub(crate) fn new_outbound(link: LinkId, identity: Option<PeerIdentity>, at: LegStamp) -> Self {
        Self {
            phase: Phase::Dialing,
            link,
            identity,
            leg: None,
            conn: match identity {
                Some(id) => ConnectionState::outbound(link, id, at),
                None => ConnectionState::outbound_anonymous(link, at),
            },
            send_failed: false,
            origin: DialOrigin::Addressed,
        }
    }

    /// A new inbound entry (they dialed us), at [`Phase::Answering`].
    pub(crate) fn new_inbound(link: LinkId, at: LegStamp) -> Self {
        Self {
            phase: Phase::Answering,
            link,
            identity: None,
            leg: None,
            conn: ConnectionState::inbound(link, at),
            send_failed: false,
            origin: DialOrigin::Addressed,
        }
    }

    /// Park an inbound entry at [`Phase::SentMsg2`], holding the lease on the
    /// index it allocated once its msg1 is answered. An inbound leg is parked
    /// once, before it holds a lease. No timer is armed for an answer: the
    /// stale-connection reaper owns its timeout.
    pub(crate) fn park_inbound_msg2_sent(&mut self, our_index: IndexLease) {
        let held = self.conn.set_our_index(our_index);
        debug_assert!(held.is_none(), "an inbound leg is parked once");
        self.phase = Phase::SentMsg2;
    }

    /// Where the handshake stands.
    #[cfg(test)]
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }

    /// The handshake crypto carrier, if this entry is still in the
    /// handshake window. Presence answers "is there a pending handshake
    /// here", independently of whether either handle is populated.
    pub(crate) fn leg(&self) -> Option<&HandshakeCrypto> {
        self.leg.as_ref()
    }

    /// Take the handshake crypto carrier off the entry (promotion and
    /// teardown consume it by value).
    pub(crate) fn take_leg(&mut self) -> Option<HandshakeCrypto> {
        // On promotion the entry lives on as the peer's handshake entry, so
        // the slot is cleared as the leg leaves, or it would keep the session's
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
    // that connection and the surviving carrier, so a reader of either sees
    // the same value at the same point.

    /// Start the handshake as initiator and generate message 1.
    ///
    /// For outbound connections only. Returns the Noise XX msg1 bytes.
    /// XX msg1 is ephemeral-only (33 bytes) — no identity or epoch.
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
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            if direction != LinkDirection::Outbound {
                return Err(NoiseError::WrongState {
                    expected: "outbound connection".to_string(),
                    got: "inbound connection".to_string(),
                });
            }

            // XX initiator: no remote static needed upfront, so an anonymous
            // dial (no expected identity) is a first-class case rather than an
            // error. The old `!= Initial` phase guard is dropped — this method
            // creates the Noise handshake handle, so there is no
            // `take().expect()` to protect, and its Err path was unreachable in
            // production (one call per fresh outbound handshake).
            let mut kp = *our_keypair.get();
            let mut hs = noise::HandshakeState::new_initiator(kp);
            kp.non_secure_erase();
            hs.set_local_epoch(epoch);
            let msg1 = hs.write_message_1()?;

            leg.noise_handshake = Some(hs);

            msg1
        };
        self.conn.touch(at);

        Ok(msg1)
    }

    /// Initialize responder and process incoming message 1.
    ///
    /// For inbound connections only. Returns the Noise XX msg2 bytes.
    /// XX: identity is NOT learned from msg1 (only ephemeral exchange).
    /// The responder learns the initiator's identity from msg3.
    ///
    /// If `negotiation_payload` is provided, it is encrypted and appended
    /// to the returned msg2 bytes.
    pub(crate) fn receive_handshake_init(
        &mut self,
        mut our_keypair: Keypair,
        epoch: [u8; 8],
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        at: LegStamp,
    ) -> Result<Vec<u8>, NoiseError> {
        // Same as `start_handshake`: the parameter copy outlives two early
        // returns, so the guard clears it in place rather than an erase per
        // exit path.
        let our_keypair = ErasingKeypair::new(&mut our_keypair);

        let msg2 = {
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

            // Process XX message 1 (ephemeral only — no identity learned)
            hs.read_message_1(message)?;

            // Generate XX message 2 (sends our static + epoch)
            let mut msg2 = hs.write_message_2()?;

            // Append encrypted negotiation payload if provided
            if let Some(payload) = negotiation_payload {
                let encrypted = hs.encrypt_payload(payload)?;
                msg2.extend_from_slice(&encrypted);
            }

            // XX: handshake NOT complete yet — need msg3. Keep the Noise
            // handshake handle for `complete_handshake_msg3()`; the phase
            // (formerly `ReceivedMsg1`) lives on this entry, so no phase is
            // set here. The handle's presence is the crypto-local
            // `ReceivedMsg1` signal.
            leg.noise_handshake = Some(hs);

            msg2
        };
        self.conn.touch(at);

        Ok(msg2)
    }

    /// Complete the handshake by processing message 2 and generating message 3.
    ///
    /// For outbound connections only (initiator). Reads the responder's msg2
    /// (learning their identity and epoch), decrypts its negotiation payload if
    /// present, and asks `decide` whether the identity that answered may
    /// complete this dial. Only on [`Accept`](DialMsg2Decision::Accept) is the
    /// handshake taken: msg3 is written (with `negotiation_payload` encrypted
    /// and appended, if given), the handshake becomes the leg's session, and
    /// the learned identity and epoch land on the carrier.
    ///
    /// Nothing authenticates a msg2 before this read, and the index it names
    /// travels in cleartext in our msg1, so the message may be a forgery.
    /// Under XX it may also read correctly and still not be from the peer we
    /// dialed: any keyed node that saw the msg1 can answer it under its own
    /// static. A msg2 that does not read, whose payload does not decrypt, or
    /// whose static `decide` rejects puts the handshake back in its pre-read
    /// state and returns [`Unreadable`](DialMsg2Step::Unreadable) or
    /// [`Rejected`](DialMsg2Step::Rejected). The carrier is not touched: its
    /// expected identity stays the dialed one, and neither the epoch nor the
    /// last activity moves, so the attempt keeps its resend schedule and its
    /// deadline. `Err` means the leg cannot continue: it had no handshake to
    /// read with, or completing an accepted msg2 failed after the handshake
    /// was taken.
    ///
    /// The entry does not decide whether the identity that answered may be
    /// admitted as the one dialed; the caller supplies that decision, taken
    /// against the FMP core, and this runs it before anything is consumed. On
    /// an anonymous leg the decision accepts any answer, and the learned
    /// identity written here is the only way the carrier gets one. The dial
    /// intent sits untouched in `conn_dialed_identity`.
    pub(crate) fn complete_handshake(
        &mut self,
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        at: LegStamp,
        decide: impl FnOnce(NodeAddr) -> DialMsg2Decision,
    ) -> Result<DialMsg2Step, NoiseError> {
        let (msg3, received_negotiation, learned_identity, remote_epoch) = {
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            // The connection is at `SentMsg1` iff its Noise handshake handle is
            // present (set by `start_handshake`, taken here on completion).
            let Some(hs) = leg.noise_handshake.as_ref() else {
                return Err(NoiseError::WrongState {
                    expected: "sent_msg1 state".to_string(),
                    got: "no active handshake".to_string(),
                });
            };

            // Read XX msg2 (learning the responder's identity and epoch) and
            // any negotiation payload after it on a fork. A read that fails,
            // and an answer `decide` refuses, drop the fork and leave the
            // handshake as it was for the genuine msg2.
            let (fork, received_negotiation) = match hs.fork_msg2(message) {
                Ok(read) => read,
                Err(e) => return Ok(DialMsg2Step::Unreadable(e)),
            };

            // Learn responder identity from msg2
            let Some(remote_static) = fork.remote_static().copied() else {
                return Ok(DialMsg2Step::Unreadable(NoiseError::WrongState {
                    expected: "remote static learned from msg2".to_string(),
                    got: "no remote static".to_string(),
                }));
            };
            let learned_identity = PeerIdentity::from_pubkey_full(remote_static);
            let learned_peer = *learned_identity.node_addr();

            if let DialMsg2Decision::Reject { reason } = decide(learned_peer) {
                return Ok(DialMsg2Step::Rejected {
                    reason,
                    learned_peer,
                });
            }

            // Capture remote epoch from msg2
            let remote_epoch = fork.remote_epoch();

            // Commit to the fork. The slot is heap memory that outlives this
            // call; clearing it once the handshake has left keeps both private
            // keys from staying there.
            drop(leg.noise_handshake.take());
            noise::clear_slot(&mut leg.noise_handshake);
            let mut hs = fork;

            // Generate XX msg3
            let mut msg3 = hs.write_message_3()?;

            // Append encrypted negotiation payload if provided
            if let Some(payload) = negotiation_payload {
                let encrypted = hs.encrypt_payload(payload)?;
                msg3.extend_from_slice(&encrypted);
            }

            // Handshake complete for initiator
            let session = hs.into_session()?;
            leg.noise_session = Some(session);

            (msg3, received_negotiation, learned_identity, remote_epoch)
        };
        self.conn.set_expected_identity(learned_identity);
        self.conn.set_remote_epoch(remote_epoch);
        self.conn.touch(at);

        Ok(DialMsg2Step::Completed(msg3, received_negotiation))
    }

    /// [`complete_handshake`](Self::complete_handshake) with a decision that
    /// accepts whoever answered, for tests that drive a genuine handshake by
    /// hand. `Completed` maps to `Ok`; a msg2 that does not complete the
    /// handshake maps to `Err`.
    #[cfg(test)]
    pub(crate) fn complete_handshake_accepting(
        &mut self,
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        at: LegStamp,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), NoiseError> {
        match self.complete_handshake(message, negotiation_payload, at, |_| {
            DialMsg2Decision::Accept
        })? {
            DialMsg2Step::Completed(msg3, negotiation) => Ok((msg3, negotiation)),
            DialMsg2Step::Unreadable(e) => Err(e),
            DialMsg2Step::Rejected { learned_peer, .. } => Err(NoiseError::WrongState {
                expected: "an accepted msg2".to_string(),
                got: format!("a msg2 from {learned_peer} rejected"),
            }),
        }
    }

    /// Read the initiator's framed `msg3` on this inbound leg.
    ///
    /// The read runs on a fork of the leg's responder handshake
    /// (`fmp::rekey::read_final`), so a msg3 that does not authenticate, or
    /// whose negotiation payload does not decrypt, returns
    /// [`Msg3Error::Unreadable`] and leaves the leg exactly as it was: its
    /// handshake and the lease on its index are kept for the genuine msg3,
    /// and its carrier is not touched, so a spray cannot push out its reap
    /// deadline. Nothing ties a msg3 to the leg before the read except the
    /// receiver index, which travels in cleartext in msg2's header.
    ///
    /// On success the handshake is consumed and the read, holding the
    /// session, the initiator's identity, epoch and payload and the leg's
    /// lease, stays on the leg ([`final_read`](Self::final_read)) until the
    /// establish decision settles it; the learned identity and epoch land on
    /// the carrier.
    pub(crate) fn read_final(&mut self, msg3: &[u8], at: LegStamp) -> Result<(), Msg3Error> {
        let (learned_identity, remote_epoch) = {
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;
            // The responder holds its handshake from msg1 until msg3.
            let Some(hs) = leg.noise_handshake.as_ref() else {
                return Err(NoiseError::WrongState {
                    expected: "received_msg1 state".to_string(),
                    got: "no active handshake".to_string(),
                }
                .into());
            };
            let lease = self.conn.take_our_index();
            let fin = match read_final(hs, msg3, lease) {
                Ok(fin) => fin,
                Err(Unread(lease)) => {
                    if let Some(lease) = lease {
                        let _ = self.conn.set_our_index(lease);
                    }
                    return Err(Msg3Error::Unreadable);
                }
            };
            // Cleared as on the initiator's msg2 path: under XX the responder
            // holds its handshake in this heap slot until msg3.
            drop(leg.noise_handshake.take());
            noise::clear_slot(&mut leg.noise_handshake);
            let learned_identity = PeerIdentity::from_pubkey_full(*fin.remote());
            let remote_epoch = fin.epoch();
            leg.fin = Some(fin);
            (learned_identity, remote_epoch)
        };
        self.conn.set_expected_identity(learned_identity);
        self.conn.set_remote_epoch(Some(remote_epoch));
        self.conn.touch(at);
        Ok(())
    }

    /// The leg's msg3 read, while the establish decision has not settled it.
    pub(crate) fn final_read(&self) -> Option<&LinkFinal> {
        self.leg.as_ref()?.fin.as_ref()
    }

    /// Take the leg's msg3 read off it, for a rekey of a peer's link: the
    /// read and the lease it carries go to that peer's link rekey machine.
    pub(crate) fn take_final(&mut self) -> Option<LinkFinal> {
        self.leg.as_mut()?.fin.take()
    }

    /// Settle the leg's msg3 read as a link setup: its session becomes the
    /// leg's completed session and its lease the carrier's index, as the
    /// promotion and the cross-connection move read them. A no-op without a
    /// read.
    pub(crate) fn settle_setup(&mut self) {
        let Some(fin) = self.leg.as_mut().and_then(|leg| leg.fin.take()) else {
            return;
        };
        let (session, lease) = fin.into_setup();
        if let Some(leg) = self.leg.as_mut() {
            leg.noise_session = Some(session);
        }
        if let Some(lease) = lease {
            let held = self.conn.set_our_index(lease);
            debug_assert!(
                held.is_none(),
                "a leg's lease is on its read or its carrier"
            );
        }
    }

    /// Complete the responder handshake by reading the bare Noise `msg3`
    /// (no link header) and settling it as a link setup, returning the
    /// decrypted negotiation payload. For tests that drive a genuine
    /// handshake by hand: the msg3 is framed with zero indices and read as
    /// [`read_final`](Self::read_final) reads a framed one.
    #[cfg(test)]
    pub(crate) fn complete_handshake_msg3(
        &mut self,
        message: &[u8],
        at: LegStamp,
    ) -> Result<Option<Vec<u8>>, Msg3Error> {
        let zero = SessionIndex::new(0);
        let framed = crate::proto::fmp::wire::build_msg3(zero, zero, message);
        self.read_final(&framed, at)?;
        let payload = self
            .final_read()
            .and_then(|fin| fin.payload().map(<[u8]>::to_vec));
        self.settle_setup();
        Ok(payload)
    }

    /// Take the completed Noise session.
    ///
    /// Returns the NoiseSession for use in ActivePeer. Can only be called
    /// once after the handshake completes.
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

    /// Drop the crypto handshake handle. The failure *state* lives on this
    /// entry; this only releases the Noise handle at the identical point it
    /// was released before, so a subsequent `complete_handshake` still reports
    /// `WrongState`.
    pub(crate) fn mark_failed(&mut self) {
        if let Some(leg) = self.leg.as_mut() {
            leg.noise_handshake = None;
        }
    }

    /// The session index we allocated for this peer, read from the surviving
    /// carrier. Populated once the index is allocated on either establish path
    /// (inbound at msg1, outbound at msg1 preparation). `None` before
    /// allocation (and after a rejected/unauthorized msg1). The inbound cutover
    /// reads this to perform the shell registry surgery.
    pub(crate) fn our_index(&self) -> Option<SessionIndex> {
        self.conn.our_index()
    }

    /// The peer identity this entry was born with (outbound identified dial)
    /// or crystallized onto it (anonymous discovery at msg2, inbound at msg3
    /// promote). `None` while the peer is still anonymous.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> Option<&PeerIdentity> {
        self.identity.as_ref()
    }

    /// Crystallize a learned identity onto an anonymous entry: XX msg2 is
    /// where an anonymous-discovery leg first learns who answered its dial.
    /// Sets the identity, the node address, and the conn's expected identity —
    /// control-tier fields only; no action is emitted and no state transition
    /// runs. A no-op when the identity is already known (identified dials fix
    /// it at birth), so callers on shared paths need not distinguish the two.
    pub(crate) fn crystallize_identity(&mut self, identity: PeerIdentity) {
        if self.identity.is_some() {
            return;
        }
        self.identity = Some(identity);
        self.conn.set_expected_identity(identity);
    }

    /// Hand back the lease on the leg's session index that the settlement
    /// core held while the handshake was in flight: onto the leg's msg3
    /// read while one is unsettled, as the read would have taken it, and
    /// onto the surviving carrier otherwise. Returns a lease the caller is
    /// to release: `lease` itself if the read holds one already, or the
    /// lease the carrier held before.
    pub(crate) fn give_lease(&mut self, lease: IndexLease) -> Option<IndexLease> {
        match self.leg.as_mut().and_then(|leg| leg.fin.as_mut()) {
            Some(fin) => fin.give(lease),
            None => self.conn.set_our_index(lease),
        }
    }

    /// Take the lease holding our session index off the surviving carrier:
    /// the promotion hands it to the active peer's link rekey machine, a
    /// cross-connection hands it to the promoted peer's, and the
    /// stale-connection reaper frees it. A leg whose msg3 read is still
    /// unsettled gives up the read with the lease it holds.
    pub(crate) fn take_our_index(&mut self) -> Option<IndexLease> {
        let held = self.conn.take_our_index();
        let read = self
            .leg
            .as_mut()
            .and_then(|leg| leg.fin.take())
            .and_then(LinkFinal::into_lease);
        debug_assert!(
            held.is_none() || read.is_none(),
            "a leg's lease is on its read or its carrier"
        );
        held.or(read)
    }

    /// The msg1 resend count for this outbound handshake leg. The entry is
    /// the home for this counter — the timer driver advances it via
    /// [`record_resend`](Self::record_resend) on each successful resend, and the
    /// control-socket connection snapshot reads it here so the operator-visible
    /// count follows the entry rather than the (now inert) shell connection.
    pub(crate) fn resend_count(&self) -> u32 {
        self.conn.resend_count()
    }

    /// Record a successful msg1 resend: advance the count and store the next
    /// backoff deadline. The driver calls this only after the resend actually
    /// went out (record-on-success — a failed send neither advances the count
    /// nor reschedules), matching the pre-fold shell semantics.
    pub(crate) fn record_resend(&mut self, next_resend_at_ms: u64) {
        self.conn.record_resend(next_resend_at_ms);
    }

    /// Connection-start timestamp of the surviving carrier — the home for the
    /// operator-visible `started_at_ms` now that the leg no longer projects it.
    pub(crate) fn conn_started_at(&self) -> u64 {
        self.conn.started_at()
    }

    /// Last-activity timestamp of the surviving carrier, on the wall clock —
    /// the home for the operator-visible `last_activity_ms`/`idle_ms`.
    pub(crate) fn conn_last_activity(&self) -> u64 {
        self.conn.last_activity()
    }

    /// Last activity of the surviving carrier on the interval clock, which
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

    /// Expected peer identity of the surviving carrier — the home for the
    /// operator-visible `expected_peer` now that the leg no longer projects it.
    /// Outbound carries the dial identity from construction; inbound records
    /// the identity discovered in msg1, written here by `receive_handshake_init`
    /// at the same point it reaches the pending connection. Everything that
    /// names a peer mid-handshake reads this, including the stale-connection
    /// sweep's retry address.
    pub(crate) fn conn_expected_identity(&self) -> Option<&PeerIdentity> {
        self.conn.expected_identity()
    }

    /// The identity this leg was *dialed at*, as opposed to the one that
    /// answered. `Some` only on an identified outbound dial; `None` on an
    /// anonymous shared-media dial and on every inbound leg. Fixed when the
    /// carrier is built and untouched by the handshake, so `handle_msg2` can
    /// hold the msg2-learned identity up against the dial intent instead of
    /// finding the intent already overwritten by it.
    pub(crate) fn conn_dialed_identity(&self) -> Option<&PeerIdentity> {
        self.conn.dialed_identity()
    }

    /// Where this entry's dial came from.
    pub(crate) fn dial_origin(&self) -> DialOrigin {
        self.origin
    }

    /// Record where this entry's dial came from. Called once, at the dial
    /// site, before the entry is first driven.
    pub(crate) fn set_dial_origin(&mut self, origin: DialOrigin) {
        self.origin = origin;
    }

    /// Remote startup epoch of the surviving carrier, recorded by the
    /// handshake operations at the message that reveals it (msg1 inbound,
    /// msg2 outbound). Promotion reads it to seed the active peer and to
    /// detect a peer restart across a reconnect.
    pub(crate) fn conn_remote_epoch(&self) -> Option<[u8; 8]> {
        self.conn.remote_epoch()
    }

    /// Stored wire-format msg1 of the surviving carrier — the resend source for
    /// the outbound handshake retransmit, now that the leg no longer carries it.
    /// On an inbound leg, the msg1 the leg answered.
    pub(crate) fn conn_handshake_msg1(&self) -> Option<&[u8]> {
        self.conn.handshake_msg1()
    }

    /// Stored wire-format msg2 of the surviving carrier — the resend source for a
    /// duplicate msg1 while the inbound handshake is still pending.
    pub(crate) fn conn_handshake_msg2(&self) -> Option<&[u8]> {
        self.conn.handshake_msg2()
    }

    /// Store the wire-format msg1 on the surviving carrier, mirroring the
    /// leg's start-of-handshake write. The carrier schedules no resend. An
    /// inbound leg stores the msg1 it answered here; it never resends it.
    pub(crate) fn set_conn_handshake_msg1(&mut self, msg1: Vec<u8>) {
        self.conn.set_handshake_msg1(msg1);
    }

    /// Store the wire-format msg2 for duplicate-msg1 resend on the surviving
    /// carrier, mirroring the leg's responder write.
    pub(crate) fn set_conn_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.conn.set_handshake_msg2(msg2);
    }

    /// The link this entry belongs to.
    pub(crate) fn link_id(&self) -> LinkId {
        self.link
    }

    /// The peer this entry belongs to moved onto `link`. The connection the
    /// entry carries keeps the handshake's link id: no reader looks at it
    /// once the leg is promoted.
    pub(crate) fn relink(&mut self, link: LinkId) {
        self.link = link;
    }

    /// Which side opened this connection, read from the surviving carrier.
    /// Seeded at construction: an outbound entry carries an outbound
    /// connection state and an inbound entry an inbound one.
    pub(crate) fn conn_direction(&self) -> LinkDirection {
        self.conn.direction()
    }

    /// Whether we opened this connection.
    pub(crate) fn conn_is_outbound(&self) -> bool {
        self.conn.is_outbound()
    }

    /// Whether the peer opened this connection.
    #[cfg(test)]
    pub(crate) fn conn_is_inbound(&self) -> bool {
        self.conn.is_inbound()
    }

    /// The peer's address on this link, read from the surviving carrier.
    /// Written at the same three points the connection's own copy was: the
    /// inbound seed, the outbound dial, and message-2 completion.
    pub(crate) fn conn_source_addr(&self) -> Option<&TransportAddr> {
        self.conn.source_addr()
    }

    pub(crate) fn set_conn_source_addr(&mut self, addr: TransportAddr) {
        self.conn.set_source_addr(addr);
    }

    /// Peer session index of the surviving carrier — the source for the
    /// promotion hand-off now that the leg no longer projects it.
    pub(crate) fn conn_their_index(&self) -> Option<SessionIndex> {
        self.conn.their_index()
    }

    /// Transport ID of the surviving carrier — the source for the promotion
    /// hand-off, the stale-connection cleanup, and the msg1 resend send.
    pub(crate) fn conn_transport_id(&self) -> Option<TransportId> {
        self.conn.transport_id()
    }

    /// Link statistics of the surviving carrier — the seed copied into the
    /// active peer at promotion.
    pub(crate) fn conn_link_stats(&self) -> &LinkStats {
        self.conn.link_stats()
    }

    /// Negotiated peer profile of the surviving carrier — the source for the
    /// promotion hand-off now that the leg no longer projects it.
    pub(crate) fn conn_peer_profile(&self) -> Option<NodeProfile> {
        self.conn.peer_profile()
    }

    /// Record the negotiated peer profile on the surviving carrier.
    pub(crate) fn set_conn_peer_profile(&mut self, profile: NodeProfile) {
        self.conn.set_negotiation_results(profile);
    }

    /// Record the peer session index on the surviving carrier, so the
    /// promotion hand-off reads it from the entry.
    pub(crate) fn set_conn_their_index(&mut self, index: SessionIndex) {
        self.conn.set_their_index(index);
    }

    /// Record the transport ID on the surviving carrier. Written on the
    /// inbound establish path at msg1 and on the outbound dial.
    pub(crate) fn set_conn_transport_id(&mut self, id: TransportId) {
        self.conn.set_transport_id(id);
    }

    /// Record our session index on the surviving carrier, as the lease that
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

    /// Advance the carrier's last-activity timestamp — the entry-tier paired
    /// write for the leg's handshake `touch`.
    pub(crate) fn touch_conn(&mut self, at: LegStamp) {
        self.conn.touch(at);
    }

    /// Whether this is an identified dial at [`Phase::SentMsg1`], the only
    /// phase in which a msg1 resend is due.
    pub(crate) fn is_handshaking_sent_msg1(&self) -> bool {
        self.phase == Phase::SentMsg1
    }

    /// Whether this handshake has failed: a send or completion failure was
    /// seen on it, which leaves its phase. The stale-connection sweep reads
    /// this to reclaim the handshake.
    pub(crate) fn is_failed(&self) -> bool {
        self.send_failed
    }

    /// The operator-visible handshake-state string for the pending-connection
    /// view, from the entry's phase ([`Phase::shown`]). A failed handshake
    /// shows `"failed"` whatever its phase.
    pub(crate) fn displayed_handshake_state(&self) -> &'static str {
        if self.send_failed {
            return "failed";
        }
        self.phase.shown()
    }

    /// Record a handshake failure that the shell observed on the leg (e.g. a
    /// `complete_handshake` that rejected msg2), WITHOUT leaving the current
    /// handshake phase: the failure is carried as `send_failed`, so the phase
    /// is unchanged while `is_failed` and the shown state report the failure.
    /// The stale-connection sweep reclaims the leg via
    /// [`is_failed`](Self::is_failed) at the next tick, before any projection or
    /// resend.
    pub(crate) fn mark_send_failed(&mut self) {
        self.send_failed = true;
    }

    /// A connection-oriented dial begins its connect: from
    /// [`Phase::Dialing`] to [`Phase::Connecting`]. False, with nothing
    /// changed, for an entry past its dial.
    pub(crate) fn connecting(&mut self) -> bool {
        if self.phase != Phase::Dialing {
            return false;
        }
        self.phase = Phase::Connecting;
        true
    }

    /// An identified dial's msg1 is about to go out: from [`Phase::Dialing`]
    /// for a connectionless dial, or from [`Phase::Connecting`] once its
    /// connect has resolved, to [`Phase::SentMsg1`]. False, with nothing
    /// changed, for an entry in any other phase.
    pub(crate) fn sending_msg1(&mut self, connected: bool) -> bool {
        let from = if connected {
            Phase::Connecting
        } else {
            Phase::Dialing
        };
        if self.phase != from {
            return false;
        }
        self.phase = Phase::SentMsg1;
        true
    }

    /// The handshake promoted: the entry is the peer's from here.
    pub(crate) fn established(&mut self) {
        self.phase = Phase::Established;
    }

    /// Whether the entry is a promoted peer's that has not been found dead.
    pub(crate) fn is_established(&self) -> bool {
        self.phase == Phase::Established
    }

    /// The promoted peer this entry belongs to was found dead.
    pub(crate) fn closed(&mut self) {
        self.phase = Phase::Closed;
    }

    /// The handshake's msg1 send failed: drop the Noise handle and mark the
    /// entry failed, leaving its phase, so msg1 resends stay due until the
    /// stale-connection sweep reclaims it.
    pub(crate) fn send_failed(&mut self) {
        self.mark_failed();
        self.send_failed = true;
    }
}

#[cfg(test)]
#[path = "tests/handshake.rs"]
mod tests;
