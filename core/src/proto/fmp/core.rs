//! Sans-IO FMP connection-lifecycle decision core.
//!
//! Pure, runtime-agnostic maintain/teardown decisions for the FMP peer
//! connection lifecycle: handshake-connection timeout/teardown and outbound
//! msg1 resend scheduling. Link rekeys are decided by each link's rekey
//! machine (`proto::rekey`), not here. The `poll_*` decisions take plain
//! snapshots with every clock read pre-computed into `u64`/`bool` fields,
//! and return [`ConnAction`]s for the caller to drive. The root crate's node
//! no longer calls them: it times and reaps its handshakes in the
//! settlement core's legs (`proto::settle::legs`). No I/O, no clock, no
//! metrics, no logging here.
//!
//! The establish leaf's Noise wire construction and `install_handshake`
//! effects stay shell-side; handshake message bytes are carried as opaque blobs
//! only. The XX handshake's establish decisions are the settlement core's XX
//! flow's (`flow/`). This file keeps the initiator's dial-identity decision
//! ([`Fmp::dial_outbound`]), the crossing tie-break and the negotiation
//! decisions.

use super::state::Fmp;
use super::wire::{
    FMP_FEAT_PROFILE_MASK, FMP_FEAT_PROVIDES_RR, FMP_FEAT_PROVIDES_SR, FMP_FEAT_WANTS_RR,
    FMP_FEAT_WANTS_SR, NegotiationPayload, NodeProfile,
};
use crate::identity::NodeAddr;
use crate::proto::Error;
use crate::transport::LinkId;
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
/// Produced by the [`LifecycleView`] read-seam. Each `poll_*` decision only
/// reads the subset of fields relevant to it; the producing view method leaves
/// the rest at their defaults.
pub struct ConnSnapshot {
    /// The connection's link identifier (teardown/resend target).
    pub link: LinkId,
    /// Teardown path: is this an outbound connection? Drives retry scheduling
    /// (only outbound auto-connect peers are retried).
    pub is_outbound: bool,
    /// Teardown path: the retry target learned from the connection's expected
    /// identity, if any. `None` when no identity is known.
    pub retry_addr: Option<NodeAddr>,
    /// Resend path: prior msg1 resend count. Drives the backoff exponent.
    pub resend_count: u32,
    /// Resend path: the stored outbound handshake msg1 wire bytes (an opaque
    /// blob — the core never parses or constructs a Noise message). Empty on
    /// the teardown path, which never reads it.
    pub msg1: Vec<u8>,
}

/// A digest of one link handshake msg1 exactly as it arrived, header included.
///
/// Both ends of a link hold the same msg1 bytes, the initiator the msg1 it
/// sent and the responder the msg1 it answered, so the digest joins their
/// log lines for one handshake.
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
/// An XX msg1 is the bare initiator ephemeral, with nothing authenticated
/// in it. A copy whose frame header (`sender_idx`) is rewritten still
/// carries the same ephemeral, while the whole-message [`Msg1Digest`] does
/// not match it, so a record that must count one captured msg1 once,
/// however its header is rewritten, keys on this.
///
/// On XX a responder promotes a session only at msg3, which is bound to
/// the fresh msg2 this node sent, so a replayed msg1 promotes nothing and
/// this line passes the silent-session record no setup digest. The type is
/// kept so that record's code stays the same as on the IK line, where a
/// msg1 promotes the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EphemeralDigest([u8; 32]);

impl EphemeralDigest {
    /// Digest the ephemeral at the start of a Noise msg1, or `None` if the
    /// message is too short to carry one.
    pub fn of_noise_msg1(noise_msg1: &[u8]) -> Option<Self> {
        use sha2::{Digest, Sha256};
        let ephemeral = noise_msg1.get(..crate::noise::PUBKEY_SIZE)?;
        Some(Self(Sha256::digest(ephemeral).into()))
    }
}

/// Minimum interval between accepted epoch changes for one peer identity,
/// and the recency threshold at which the peering an epoch change would
/// destroy still counts as live.
///
/// An epoch-mismatch msg1 is authentic but replayable: a captured one stays
/// valid indefinitely, and accepting it tears down a working peering. Both
/// conditions are receiver-local. The liveness half is the one that closes
/// the replay, since a peering under attack is by construction still
/// heartbeating; the interval half bounds the churn a peer can drive on its
/// own.
///
/// Sized against the peer's own recovery rather than against a round number:
/// a genuinely restarting peer's msg1 resends fire at roughly t+1, t+3, t+7
/// and t+15 seconds and its attempt is reaped at `handshake_timeout_secs`
/// (30), so 15 is the largest value at which a real restart still re-peers
/// inside its first handshake window with no reconnect backoff. It also sits
/// below `link_dead_timeout_secs` (30), so the liveness gate can never
/// outlive the reaper that would have removed the peering anyway.
///
/// Raising it lengthens the outage an attacker's accepted replay causes,
/// because the genuine peer's recovery msg1 hits the same arm. Lowering it
/// weakens both halves and, below the resend ladder, buys nothing.
pub const EPOCH_RESTART_MIN_INTERVAL_SECS: u64 = 15;

/// What an inbound `msg3` declares about replacing a session we already hold.
///
/// The sender knows whether it is rekeying; the responder cannot infer it, since
/// a rekey and a fresh dial both arrive as a new `msg1` on a new link. The msg3
/// negotiation TLV carries the sender's answer and the shell resolves it into
/// this three-valued input — resolved shell-side because matching the declared
/// index against the session we hold is a registry read, and because it must be
/// matched only against the peer the handshake authenticated as, never resolved
/// through a global index map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyClaim {
    /// No marker: the sender says this handshake is not a rekey.
    None,
    /// The marker names the session we hold for this peer.
    Matches,
    /// The marker names a session that is not the one we hold.
    Mismatch,
}

/// A snapshot of the two identities the *initial outbound* `msg2` completion
/// decision compares, taken by the shell once the Noise step has run.
///
/// XX *learns* the responder's static from `msg2` instead of pinning it a
/// priori as IK did, so a cryptographically valid `msg2` proves only that
/// *someone* answered the dial, never that the peer we meant to reach answered
/// it. A link rekey's `msg2` gets the same check from the link's rekey machine
/// (`Bond::check`); this one protects the link being formed. No Noise material
/// reaches the core.
pub struct DialMsg2Snapshot {
    /// The node address this leg was dialed at, or `None` if the dial named no
    /// peer.
    ///
    /// `None` is an *anonymous* leg — a shared-media beacon dial, whose beacon
    /// asserts no identity for anyone to substitute — and it is decided locally
    /// when the leg is built, never from anything on the wire, so no peer can
    /// steer an identified dial into the `None` branch.
    pub dialed_peer: Option<NodeAddr>,
    /// The node address derived from the static key learned in this `msg2`,
    /// i.e. the identity this leg would actually be promoted under.
    pub learned_peer: NodeAddr,
}

/// A registry/transport effect the async shell performs on the core's behalf.
///
/// The scaffold subset covers the maintain/teardown half of the lifecycle. The
/// establish-leaf variants (`SendMsg2`, `PromoteToActive`) are deferred to the
/// born-on-next handshake component and are intentionally absent.
pub enum ConnAction {
    /// Tear down and free the handshake connection on `link`
    /// (`cleanup_stale_connection`): frees the session index, removes the
    /// `pending_outbound` entry, and cleans up the link + address mapping.
    Teardown { link: LinkId },
    /// Schedule an auto-connect retry toward `peer` (`schedule_retry`) before
    /// its failed/stale outbound connection is torn down.
    ScheduleRetry { peer: NodeAddr },
    /// Resend the stored handshake msg1 `bytes` on `link`, then (on a
    /// successful send) record the resend and reschedule the next one at
    /// `next_resend_at_ms`. The shell resolves the transport + remote address
    /// from the live connection and performs the send; `bytes` is an opaque
    /// blob the core neither parses nor builds.
    ResendMsg1 {
        link: LinkId,
        bytes: Vec<u8>,
        next_resend_at_ms: u64,
    },
}

/// Read-only view of FMP connection/peer state the lifecycle core needs.
///
/// The core defines this interface; the async shell (`node`) implements it over
/// the live `peer_machines`/`peers` maps — handshake-phase state is read off
/// the machines still carrying a pending handshake, active-peer state off
/// `peers`. It is a **snapshot-iterator** seam: each method returns owned
/// snapshot vectors with all clock reads already resolved shell-side, so the
/// pure decisions never borrow `Node` and never
/// read a clock. Keeping it a trait keeps `proto` free of a `node` dependency
/// and lets the decisions be unit-tested against hand-built snapshots.
pub trait LifecycleView {
    /// Snapshot every handshake connection that is stale (idle past
    /// `timeout_ms`) or failed, as of `now_ms`. The shell resolves the
    /// timeout/failed predicate; the core decides retry-then-teardown. The
    /// root crate's node no longer implements it.
    fn stale_connections(&self, now_ms: u64, timeout_ms: u64) -> Vec<ConnSnapshot>;
}

/// The classification outcome for one initiator-side *initial* `msg2`
/// completion, decided purely from the [`DialMsg2Snapshot`]. The shell matches
/// on this and drives the effects; the core consumes nothing and touches no
/// live state.
///
/// The responder gets the equivalent guarantee structurally — an inbound leg is
/// promoted under the node address derived from the authenticated static, so
/// there is no prior expectation for a foreign static to contradict. Only the
/// initiator holds an intent that the wire can disagree with, so only here does
/// it have to be stated as an explicit decision.
#[derive(Debug, PartialEq, Eq)]
pub enum DialMsg2Decision {
    /// Either the dial named no peer (an anonymous leg, where any answer is a
    /// legitimate first contact) or it named the peer that answered. Carry on
    /// into the ACL gate and promotion, the unchanged pre-existing behaviour.
    Accept,
    /// The dial named a peer and someone else answered: drop this `msg2` with a
    /// handshake reject and promote nothing. `reason` selects only the
    /// diagnostic log line.
    Reject { reason: DialMsg2Reject },
}

/// Why an initiator-side initial `msg2` was dropped by the core classification.
#[derive(Debug, PartialEq, Eq)]
pub enum DialMsg2Reject {
    /// The static learned in `msg2` derives to a different node address than the
    /// one dialed — an on-path party observed the outbound `msg1` and raced a
    /// valid XX `msg2` under its own static, or the address we dialed is no
    /// longer the peer we recorded there. Either way this leg never promotes.
    StaticMismatch,
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

    /// Decide the msg1 resend schedule for the outbound handshake connections
    /// the shell snapshotted as due. Each candidate yields one
    /// [`ConnAction::ResendMsg1`] carrying the opaque msg1 bytes and the
    /// next-resend deadline computed from the exponential backoff
    /// (`interval_ms * backoff^(count+1)`). Pure over the snapshots.
    ///
    /// The shell performs the send and only commits the resend (count++ and
    /// reschedule) when it succeeds, preserving the pre-refactor behavior where
    /// a failed send neither advances the count nor reschedules.
    pub fn poll_resends(
        &self,
        candidates: Vec<ConnSnapshot>,
        now_ms: u64,
        interval_ms: u64,
        backoff: f64,
    ) -> Vec<ConnAction> {
        candidates
            .into_iter()
            .map(|snap| ConnAction::ResendMsg1 {
                link: snap.link,
                next_resend_at_ms: next_resend_at_ms(
                    now_ms,
                    interval_ms,
                    backoff,
                    snap.resend_count,
                ),
                bytes: snap.msg1,
            })
            .collect()
    }

    /// Classify one initiator-side *initial* `msg2` completion: the dial-time
    /// identity gate. Pure: reads only `snap`, mutates nothing.
    ///
    /// A dial that named a peer may only be completed by that peer, so the
    /// identity learned from `msg2` must derive to the dialed node address.
    /// Anything else is [`Reject`](DialMsg2Decision::Reject) and the shell
    /// promotes nothing.
    ///
    /// A dial that named nobody has nothing to contradict: an anonymous
    /// shared-media beacon asserts no identity, so answering one and being
    /// admitted is peering rather than substitution, and the ACL — which runs
    /// against the learned identity either way — stays the correct and only gate
    /// there. That carve-out cannot be reached as an exemption, because whether
    /// `dialed_peer` is `Some` is settled when the leg is built and never by the
    /// wire.
    pub fn dial_outbound(&self, snap: &DialMsg2Snapshot) -> DialMsg2Decision {
        if let Some(dialed) = snap.dialed_peer
            && dialed != snap.learned_peer
        {
            return DialMsg2Decision::Reject {
                reason: DialMsg2Reject::StaticMismatch,
            };
        }
        DialMsg2Decision::Accept
    }
}

/// Exponential-backoff schedule for the next handshake/rekey msg1 resend:
/// `now_ms + interval_ms * backoff^(prior_count + 1)`. Matches the pre-refactor
/// arithmetic (the exponent is the resend count *after* this attempt).
fn next_resend_at_ms(now_ms: u64, interval_ms: u64, backoff: f64, prior_count: u32) -> u64 {
    let count = prior_count + 1;
    now_ms + (interval_ms as f64 * crate::proto::math::powi(backoff, count)) as u64
}

// ============================================================================
// FMP negotiation decision logic
// ============================================================================
//
// The version-agreement, profile-extraction, and profile-pairing decisions
// relocated from `protocol::negotiation` (the payload *codec* stays in
// `wire.rs`). These are pure decisions over an already-decoded
// `NegotiationPayload`, so they belong beside the other FMP core decisions.

impl NegotiationPayload {
    /// Agree on a protocol version with a peer's negotiation payload.
    ///
    /// Returns `min(our_max, their_max)`, rejecting if the agreed version
    /// is below either side's minimum.
    pub fn agree_version(&self, other: &Self) -> Result<u8, Error> {
        let agreed = self.version_max.min(other.version_max);
        if agreed < self.version_min || agreed < other.version_min {
            return Err(Error::Malformed("version mismatch"));
        }
        Ok(agreed)
    }

    /// Build an FMP negotiation payload for the given node profile.
    ///
    /// Sets the profile bits and MMP wants/provides defaults for the profile.
    pub fn fmp(version_min: u8, version_max: u8, profile: NodeProfile) -> Self {
        let (provides_sr, provides_rr, wants_sr, wants_rr) = match profile {
            NodeProfile::Full => (true, true, true, true),
            NodeProfile::NonRouting => (true, true, false, true),
            NodeProfile::Leaf => (false, true, false, false),
        };

        let mut features = (profile as u8 as u64) & FMP_FEAT_PROFILE_MASK;
        if provides_sr {
            features |= FMP_FEAT_PROVIDES_SR;
        }
        if provides_rr {
            features |= FMP_FEAT_PROVIDES_RR;
        }
        if wants_sr {
            features |= FMP_FEAT_WANTS_SR;
        }
        if wants_rr {
            features |= FMP_FEAT_WANTS_RR;
        }

        Self::new(version_min, version_max, features)
    }

    /// Extract the node profile from the FMP feature bitfield.
    pub fn node_profile(&self) -> Result<NodeProfile, Error> {
        let raw = (self.features & FMP_FEAT_PROFILE_MASK) as u8;
        NodeProfile::try_from(raw)
    }

    /// Whether this peer can provide MMP sender reports.
    pub fn provides_sr(&self) -> bool {
        self.features & FMP_FEAT_PROVIDES_SR != 0
    }

    /// Whether this peer can provide MMP receiver reports.
    pub fn provides_rr(&self) -> bool {
        self.features & FMP_FEAT_PROVIDES_RR != 0
    }

    /// Whether this peer wants MMP sender reports.
    pub fn wants_sr(&self) -> bool {
        self.features & FMP_FEAT_WANTS_SR != 0
    }

    /// Whether this peer wants MMP receiver reports.
    pub fn wants_rr(&self) -> bool {
        self.features & FMP_FEAT_WANTS_RR != 0
    }

    /// Validate that two profiles form a valid link pairing.
    ///
    /// At least one side must be `Full` or the link is rejected.
    pub fn validate_profiles(ours: NodeProfile, theirs: NodeProfile) -> Result<(), Error> {
        if ours != NodeProfile::Full && theirs != NodeProfile::Full {
            return Err(Error::Malformed(
                "invalid profile pairing (at least one must be full)",
            ));
        }
        Ok(())
    }
}

/// Decode, validate, and extract the peer's node profile from an FMP
/// negotiation payload.
///
/// The pure decode -> validate -> profile decision lifted out of the async
/// `process_fmp_negotiation` shell adapter. The shell applies the returned
/// profile to the connection (`set_negotiation_results`) and logs.
pub fn decide_fmp_negotiation(
    our_profile: NodeProfile,
    neg_bytes: &[u8],
) -> Result<NodeProfile, Error> {
    let their_payload = NegotiationPayload::decode(neg_bytes)?;
    let their_profile = their_payload.node_profile()?;
    NegotiationPayload::validate_profiles(our_profile, their_profile)?;
    Ok(their_profile)
}
