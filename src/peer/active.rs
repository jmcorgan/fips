//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use super::{
    LinkCaps, LinkOutput, LinkOutputs, LinkProfile, LinkRekey, PeerInstant, peer_now, since,
};
use crate::config::MmpConfig;
use crate::node::diag::HsLineCounts;
use crate::node::session::{ThreadJitter, with_tags};
use crate::noise::NoiseSession;
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::{NegotiationPayload, NodeProfile, RekeyMsg2Decision, RekeyMsg2Reject};
use crate::proto::mmp::MmpPeerState;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Ipv6Address, NodeAddr, PeerIdentity};
use fips_core::proto::fmp::rekey::ik::{LinkKeys, setup_record};
use fips_core::proto::rekey::{
    Bond, Close, Completed, CycleView, Env, Identity, Ids, IndexLease, Input, PeerKey, Record,
    Role, SealRefusal, Sealed, SendCopy, SetupFacts, Slot,
};
use secp256k1::XOnlyPublicKey;
use std::fmt;
use std::time::{Duration, Instant};

/// Connectivity of an active peer, as the control socket reports it.
///
/// Not stored on the peer: the node derives it from how long the peer has
/// been silent, compared with the configured heartbeat interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectivityState {
    /// Heard from within the heartbeat interval.
    Connected,
    /// Silent for longer than the heartbeat interval.
    Stale,
}

impl ConnectivityState {
    /// Check if this is a terminal state requiring cleanup.
    ///
    /// Always false: neither derived state is terminal.
    pub fn is_terminal(&self) -> bool {
        false
    }
}

impl fmt::Display for ConnectivityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ConnectivityState::Connected => "connected",
            ConnectivityState::Stale => "stale",
        };
        write!(f, "{}", s)
    }
}

/// The rekey machine of a link whose session is `session`, bonded to
/// `bond`: its first epoch is `session` under this node's `ours` and the
/// peer's `theirs`, bound on `transport`, with the key-epoch bit, starts and
/// record `facts` gives, offered to the decrypt workers at once when
/// `caps` says a pool runs. Returns the machine and the binding of `ours`. Hands the lease back,
/// building nothing, when `session` authenticated another key than `bond`.
fn link_machine(
    bond: PeerKey,
    session: NoiseSession,
    ours: IndexLease,
    theirs: SessionIndex,
    transport: TransportId,
    facts: SetupFacts<PeerInstant>,
    caps: &mut LinkCaps<'_>,
) -> Result<(LinkRekey, LinkOutputs), IndexLease> {
    let bond = Bond::Key(bond);
    let epoch = facts.peer_epoch.unwrap_or_default();
    let Ok(first) = bond.check(completed(session, epoch, theirs)) else {
        return Err(ours);
    };
    let ids = Ids::new(ours, theirs.as_u32(), transport);
    let mut scratch = Vec::new();
    Ok(with_tags(|tags| {
        let mut env = Env {
            indices: &mut *caps.indices,
            transport,
            tags,
            workers: caps.workers,
            jitter: &mut ThreadJitter,
            local: caps.local,
            scratch: &mut scratch,
        };
        LinkRekey::established(
            caps.params,
            bond,
            caps.me,
            first,
            ids,
            facts,
            peer_now(),
            &mut env,
        )
    }))
}

/// What link setup tells a new link's rekey machine: key-epoch bit 0, the
/// session and the link starting now, nothing seen from the peer yet, the
/// peer's startup epoch `peer_epoch`, if the setup carried one, and the
/// replay record `record` an earlier link with the peer at that epoch left.
fn setup_facts(peer_epoch: Option<[u8; 8]>, record: Record) -> SetupFacts<PeerInstant> {
    let now = peer_now();
    SetupFacts {
        peer_epoch,
        k: false,
        link_since: now,
        started: now,
        peer_k: None,
        record,
    }
}

/// A completed handshake's `session` as a link's rekey machine takes it: the
/// key it authenticated, the peer's startup `epoch` it carried (zero when
/// unknown) and the peer's index `theirs`.
fn completed(
    session: NoiseSession,
    epoch: [u8; 8],
    theirs: SessionIndex,
) -> Completed<LinkProfile> {
    Completed {
        remote: PeerKey::from_xonly(&session.remote_static_xonly()),
        session: Box::new(LinkKeys::new(session)),
        epoch,
        theirs: Some(theirs.as_u32()),
    }
}

/// What a link's rekey machine keeps across a cross-connection move, as a
/// test reads it (test builds only).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LinkAnchors {
    /// The current session's key-epoch bit.
    pub(crate) k: bool,
    /// When the current session started.
    pub(crate) started: PeerInstant,
    /// The current session's inner-header timestamp base.
    pub(crate) base: Option<PeerInstant>,
    /// When the link came up.
    pub(crate) link_since: PeerInstant,
    /// The peer's startup epoch.
    pub(crate) peer_epoch: Option<[u8; 8]>,
    /// The key-epoch bit last seen on the peer's frames.
    pub(crate) peer_k: Option<bool>,
    /// The replay record.
    pub(crate) record: Record,
}

/// Published active-send-state for a peer (the two-tier boundary).
///
/// This is the send-critical subset of an `ActivePeer` that the data plane
/// reads (and, on roam, writes) directly by plain borrow with no FSM
/// dispatch: the transport target, the connected-UDP handles, and the hot
/// per-packet counters. The epochs, their keys, indices and key-epoch bits
/// and the session-relative time base live in the peer's link rekey machine.
///
/// Co-located, not behind `Arc`/`ArcSwap` — the data plane is not sharded, so
/// the hot path reads this by plain borrow. Publishing behind `Arc`/`ArcSwap`
/// is later-increment plumbing for a sharded data plane.
#[derive(Debug)]
struct PeerSendState {
    // === Transport target ===
    /// Transport ID for this peer's link.
    transport_id: Option<TransportId>,
    /// Current transport address (for roaming support).
    current_addr: Option<TransportAddr>,
    /// Link used to reach this peer.
    link_id: LinkId,

    // === Connected-UDP handles ===
    /// Unix UDP fast-path: per-peer `connect()`-ed socket (paired with
    /// the listen socket via `SO_REUSEPORT`). The kernel demux prefers
    /// the connected 5-tuple, so inbound packets land here; the
    /// encrypt-worker send path sends with `msg_name = NULL`, skipping
    /// per-packet sockaddr handling + route lookup. Behind an `Arc` so
    /// in-flight worker jobs survive rekey/address-change rotations.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_udp: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,

    /// Per-peer recv drain thread. Always paired with `connected_udp`:
    /// the kernel routes inbound packets from this peer to the
    /// connected socket, so it *must* be drained or the kernel recv
    /// buffer fills. Drop signals shutdown via self-pipe.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    peer_recv_drain: Option<crate::transport::udp::PeerRecvDrain>,

    // === Hot counters ===
    /// Link statistics.
    link_stats: LinkStats,
    /// When this peer was last seen (any activity, Unix milliseconds).
    last_seen: u64,
    /// Whether an authenticated frame from this peer has arrived since it was
    /// promoted. Kept beside `last_seen` because `touch` writes both.
    heard: bool,
    /// Number of replay detections suppressed since last session reset.
    replay_suppressed_count: u32,
    /// Consecutive decryption failures (reset on any successful decrypt).
    consecutive_decrypt_failures: u32,
    /// Frames authenticated on the previous session since the last cutover.
    prev_frames: u64,
    /// The receiver index of the last frame that failed to decrypt.
    failed_idx: Option<SessionIndex>,
    /// Per-peer MMP state (None for legacy peers without Noise sessions).
    mmp: Option<MmpPeerState>,
}

impl PeerSendState {
    /// Empty send-state for a peer with no Noise session yet. Mirrors the
    /// send-critical portion of `ActivePeer::new`.
    fn new(link_id: LinkId, last_seen: u64) -> Self {
        Self {
            transport_id: None,
            current_addr: None,
            link_id,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_udp: None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            peer_recv_drain: None,
            link_stats: LinkStats::new(),
            last_seen,
            heard: false,
            replay_suppressed_count: 0,
            consecutive_decrypt_failures: 0,
            prev_frames: 0,
            failed_idx: None,
            mmp: None,
        }
    }
}

/// A fully authenticated remote FIPS node.
///
/// Created only after successful Noise IK handshake. The identity is
/// cryptographically verified at this point.
///
/// Note: ActivePeer intentionally does not implement Clone because its link
/// rekey machine holds Noise sessions, which cannot be safely cloned
/// (cloning would risk nonce reuse, a catastrophic security failure).
#[derive(Debug)]
pub struct ActivePeer {
    // === Identity (Verified) ===
    /// Cryptographic identity (verified via handshake).
    identity: PeerIdentity,
    /// Bech32 npub, derived once at construction.
    ///
    /// The npub is a pure function of `identity`'s public key, and
    /// `identity` is never mutated after construction, so this can never
    /// go stale. Deriving it costs a bech32 encode, which the per-tick
    /// stats snapshot was paying once per peer per tick.
    npub: String,
    /// Shortened npub for log/UI display, derived once at construction.
    /// Immutable for the same reason as [`ActivePeer::npub`].
    short_npub: String,

    // === Spanning Tree ===
    /// Their latest parent declaration.
    declaration: Option<ParentDeclaration>,
    /// Their path to root.
    ancestry: Option<TreeCoordinate>,

    // === Tree Announce Rate Limiting ===
    /// Minimum interval between TreeAnnounce messages (milliseconds).
    tree_announce_min_interval_ms: u64,
    /// Last time we sent a TreeAnnounce to this peer (Unix milliseconds).
    last_tree_announce_sent_ms: u64,
    /// Whether a tree announce is pending (deferred due to rate limit).
    pending_tree_announce: bool,

    // === Bloom Filter ===
    /// What's reachable through them (inbound filter).
    inbound_filter: Option<BloomFilter>,
    /// Their filter's sequence number.
    filter_sequence: u64,
    /// When we received their last filter (Unix milliseconds).
    filter_received_at: u64,
    /// Whether we owe them a filter update.
    pending_filter_update: bool,

    // === Statistics ===
    /// When this peer was authenticated (Unix milliseconds).
    authenticated_at: u64,

    // === Negotiated Profile ===
    /// Peer's node profile (Full, NonRouting, Leaf).
    peer_profile: NodeProfile,
    /// Whether to send sender reports to this peer (our provides_sr AND peer wants_sr).
    send_sr: bool,
    /// Whether to send receiver reports to this peer (our provides_rr AND peer wants_rr).
    send_rr: bool,

    // === Heartbeat ===
    /// When a heartbeat to this peer last *succeeded*. A send that failed does
    /// not move this: it told the peer nothing, and treating it as if it had
    /// would leave the peer un-heartbeated for a full interval on the strength
    /// of a send that never landed.
    last_heartbeat_sent: Option<Instant>,
    /// When a heartbeat to this peer was last *attempted*, whatever came of it.
    /// Paired with the above so a peer whose send failed is retried sooner than
    /// the heartbeat interval without being retried on every tick — see
    /// `HEARTBEAT_RETRY_INTERVAL`.
    last_heartbeat_attempt: Option<Instant>,

    // === Handshake Resend ===
    /// Wire-format msg2 for resend on duplicate msg1 (responder only).
    /// Kept for the life of the peering: nothing clears it.
    handshake_msg2: Option<Vec<u8>>,
    /// Digest of the ephemeral in the link-setup msg1 the peering was
    /// promoted from, by which the silent-session record counts a session
    /// once however a copy's header was rewritten.
    setup_ephemeral: Option<EphemeralDigest>,

    // === Rekey (Key Rotation) ===
    /// The link's rekey machine: its epochs and their keys, indices and
    /// key-epoch bits, this node's own rekey handshake in flight, the
    /// drain, the pending session with the role that made it and its
    /// install time, the peer's startup epoch, dampening, the link's age,
    /// the rekey jitter and the record of answered msg1s. `None` for a peer
    /// built without a Noise session.
    rekey: Option<LinkRekey>,
    /// Repeated handshake lines logged for this peer, by kind, so a peer
    /// repeating one handshake outcome logs it a bounded number of times.
    hs_lines: HsLineCounts,
    /// Whether this peering has given any evidence that its peer is present
    /// now: an authenticated frame on its session, or, for a peering this
    /// node initiated, the msg2 that answered our fresh ephemeral. A
    /// responder promotion is not such evidence, because the msg1 it was
    /// promoted from carries nothing fresh and may be a replayed capture.
    heard: bool,

    // === Published active-send-state (two-tier boundary) ===
    /// The send-critical subset read (and, on roam/responder-cutover, written)
    /// directly by the data plane. See `PeerSendState`.
    send: PeerSendState,
}

impl ActivePeer {
    /// Create a new active peer from verified identity.
    ///
    /// Called after successful authentication handshake.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn new(identity: PeerIdentity, link_id: LinkId, authenticated_at: u64) -> Self {
        Self {
            npub: identity.npub(),
            short_npub: identity.short_npub(),
            identity,
            declaration: None,
            ancestry: None,
            tree_announce_min_interval_ms: 500,
            last_tree_announce_sent_ms: 0,
            pending_tree_announce: false,
            inbound_filter: None,
            filter_sequence: 0,
            filter_received_at: 0,
            pending_filter_update: true, // Send filter on new connection
            authenticated_at,
            peer_profile: NodeProfile::Full,
            send_sr: true,
            send_rr: true,
            last_heartbeat_sent: None,
            last_heartbeat_attempt: None,
            handshake_msg2: None,
            setup_ephemeral: None,
            rekey: None,
            hs_lines: HsLineCounts::default(),
            heard: true,
            send: PeerSendState::new(link_id, authenticated_at),
        }
    }

    /// Create from verified identity with existing link stats.
    ///
    /// Used when promoting a completed handshake, preserving its link stats.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn with_stats(
        identity: PeerIdentity,
        link_id: LinkId,
        authenticated_at: u64,
        link_stats: LinkStats,
    ) -> Self {
        let mut peer = Self::new(identity, link_id, authenticated_at);
        peer.send.link_stats = link_stats;
        peer
    }

    /// Create from verified identity with Noise session and index tracking.
    ///
    /// This is the primary constructor for the wire protocol path. The
    /// session becomes the first epoch of the peer's link rekey machine,
    /// under `our_index`, the lease link setup took, and the peer's
    /// `their_index`, bound on `transport_id`; the machine is bonded to the
    /// identity's key. Returns the outputs the node executes, the binding of
    /// `our_index` among them. Hands the lease back, building nothing, when
    /// the session authenticated another key than `identity`'s, which a
    /// completed handshake never does.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_session(
        identity: PeerIdentity,
        link_id: LinkId,
        authenticated_at: u64,
        noise_session: NoiseSession,
        our_index: IndexLease,
        their_index: SessionIndex,
        transport_id: TransportId,
        current_addr: TransportAddr,
        link_stats: LinkStats,
        _is_initiator: bool,
        mmp_config: &MmpConfig,
        remote_epoch: Option<[u8; 8]>,
        our_profile: NodeProfile,
        peer_profile: NodeProfile,
        caps: &mut LinkCaps<'_>,
    ) -> Result<(Self, LinkOutputs), IndexLease> {
        // Compute MMP report gating: A sends to B iff A.provides AND B.wants
        let our_neg = NegotiationPayload::fmp(0, 0, our_profile);
        let their_neg = NegotiationPayload::fmp(0, 0, peer_profile);
        let send_sr = our_neg.provides_sr() && their_neg.wants_sr();
        let send_rr = our_neg.provides_rr() && their_neg.wants_rr();

        let bond = PeerKey::from_xonly(&identity.pubkey());
        let facts = setup_facts(remote_epoch, std::mem::take(&mut caps.record));
        let (rekey, out) = link_machine(
            bond,
            noise_session,
            our_index,
            their_index,
            transport_id,
            facts,
            caps,
        )?;
        let mut send = PeerSendState::new(link_id, authenticated_at);
        send.transport_id = Some(transport_id);
        send.current_addr = Some(current_addr);
        send.link_stats = link_stats;
        send.mmp = Some(MmpPeerState::new(
            mmp_config.mode,
            mmp_config.log_interval_secs,
            mmp_config.owd_window_size,
        ));
        let peer = Self {
            npub: identity.npub(),
            short_npub: identity.short_npub(),
            identity,
            declaration: None,
            ancestry: None,
            tree_announce_min_interval_ms: 500,
            last_tree_announce_sent_ms: 0,
            pending_tree_announce: false,
            inbound_filter: None,
            filter_sequence: 0,
            filter_received_at: 0,
            pending_filter_update: true,
            authenticated_at,
            peer_profile,
            send_sr,
            send_rr,
            last_heartbeat_sent: None,
            last_heartbeat_attempt: None,
            handshake_msg2: None,
            setup_ephemeral: None,
            rekey: Some(rekey),
            hs_lines: HsLineCounts::default(),
            heard: is_initiator,
            send,
        };
        Ok((peer, out))
    }

    /// [`with_session`](Self::with_session) for a test that needs a keyed
    /// peer without running link setup: `our_index` is leased outside any
    /// allocator, and the machine is bonded to the key the session
    /// authenticated, which a test's `identity` need not be. The outputs (the
    /// index binding) are dropped, as the test has no node.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_test_session(
        identity: PeerIdentity,
        link_id: LinkId,
        authenticated_at: u64,
        noise_session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
        transport_id: TransportId,
        current_addr: TransportAddr,
        link_stats: LinkStats,
        is_initiator: bool,
        mmp_config: &MmpConfig,
        remote_epoch: Option<[u8; 8]>,
    ) -> Self {
        let local =
            fips_core::proto::rekey::NodeKeys::new(crate::Identity::generate().keypair(), [0; 8]);
        let mut indices = crate::utils::index::IndexAllocator::new();
        let mut caps = LinkCaps {
            indices: &mut indices,
            local: &local,
            me: *identity.node_addr(),
            params: super::test_link_params(),
            record: Record::new(),
            workers: false,
        };
        let bond = PeerKey::from_xonly(&noise_session.remote_static_xonly());
        let (rekey, _) = link_machine(
            bond,
            noise_session,
            IndexLease::for_test(our_index.as_u32()),
            their_index,
            transport_id,
            setup_facts(remote_epoch, Record::new()),
            &mut caps,
        )
        .unwrap_or_else(|_| unreachable!("a machine bonds to its own session's key"));
        let mut peer = Self::with_stats(identity, link_id, authenticated_at, link_stats);
        peer.send.transport_id = Some(transport_id);
        peer.send.current_addr = Some(current_addr);
        peer.send.mmp = Some(MmpPeerState::new(
            mmp_config.mode,
            mmp_config.log_interval_secs,
            mmp_config.owd_window_size,
            is_initiator,
        ));
        peer.heard = is_initiator;
        peer.rekey = Some(rekey);
        peer
    }

    // === Connected-UDP fast path ===

    /// Refcount the per-peer `connect()`-ed UDP socket if installed.
    /// Encrypt-worker send path uses this to bypass the wildcard
    /// listen socket's per-packet sockaddr handling.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn connected_udp(
        &self,
    ) -> Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>> {
        self.send.connected_udp.clone()
    }

    /// Install a per-peer `connect()`-ed UDP socket with its paired
    /// recv drain thread. The two own each other's lifetime: the drain
    /// is the only consumer of packets on this socket.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn set_connected_udp(
        &mut self,
        socket: std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>,
        drain: crate::transport::udp::PeerRecvDrain,
    ) {
        // Drop the old drain BEFORE the old socket so its last fd
        // reference is released cleanly.
        self.send.peer_recv_drain = None;
        self.send.connected_udp = None;
        self.send.connected_udp = Some(socket);
        self.send.peer_recv_drain = Some(drain);
    }

    /// Clear the per-peer connected UDP socket + drain. The drain
    /// exits via self-pipe signal; the kernel fd closes on last `Arc`
    /// drop (any in-flight worker jobs holding the old `Arc` stay
    /// valid until they complete).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(dead_code)] // called from session-deregister + rekey follow-up
    pub(crate) fn clear_connected_udp(&mut self) {
        self.send.peer_recv_drain = None;
        self.send.connected_udp = None;
    }

    // === Identity Accessors ===

    /// Get the peer's verified identity.
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Get the peer's NodeAddr.
    pub fn node_addr(&self) -> &NodeAddr {
        self.identity.node_addr()
    }

    /// Get the peer's IPv6 address.
    pub fn address(&self) -> &Ipv6Address {
        self.identity.address()
    }

    /// Get the peer's public key.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.identity.pubkey()
    }

    /// Get the peer's npub string.
    ///
    /// Returns a clone of the value cached at construction; the bech32
    /// encode is not repeated.
    pub fn npub(&self) -> String {
        self.npub.clone()
    }

    /// Borrow the peer's cached npub without allocating.
    pub fn npub_str(&self) -> &str {
        &self.npub
    }

    /// Borrow the peer's cached shortened npub (e.g. `npub1abcd...wxyz`).
    pub fn short_npub(&self) -> &str {
        &self.short_npub
    }

    // === Connection Accessors ===

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.send.link_id
    }

    /// Check if peer is disconnected.
    ///
    /// Always false: the peer stores no connectivity state, and a peer that
    /// goes away is removed from the node rather than marked.
    pub fn is_disconnected(&self) -> bool {
        false
    }

    // === Session Accessors ===

    /// Check if this peer has a Noise session.
    pub(crate) fn has_session(&self) -> bool {
        self.rekey.is_some()
    }

    /// The Noise session of the epoch in `slot`, read-only.
    fn keys(&self, slot: Slot) -> Option<&NoiseSession> {
        self.rekey
            .as_ref()?
            .keys(slot)
            .map(fips_core::proto::rekey::NoiseKeys::session)
    }

    /// Our session index of the epoch in `slot`.
    fn index(&self, slot: Slot) -> Option<SessionIndex> {
        self.rekey.as_ref()?.ours(slot).map(SessionIndex::new)
    }

    /// The tag of the epoch in `slot`, by which the link's rekey machine
    /// is told of a frame a decrypt worker opened under it.
    pub(crate) fn epoch_tag(&self, slot: Slot) -> Option<fips_core::proto::rekey::EpochTag> {
        self.rekey.as_ref()?.tag(slot)
    }

    /// The transport this peer's indices are bound on: the one it is
    /// reached over. A peer with a session always has one.
    fn bound_transport(&self) -> TransportId {
        self.send.transport_id.unwrap_or(TransportId::new(0))
    }

    /// Get the Noise session, if present.
    pub(crate) fn noise_session(&self) -> Option<&NoiseSession> {
        self.keys(Slot::Current)
    }

    /// Reserve a counter under the current session at `now` for one
    /// frame, with the send key, the peer's index, the key-epoch bit and
    /// the inner-header timestamp that session fixes.
    pub(crate) fn seal(&mut self, now: PeerInstant) -> Result<Sealed<SendCopy>, SealRefusal> {
        match self.rekey.as_mut() {
            Some(rekey) => rekey.seal(now),
            None => Err(SealRefusal::NotEstablished),
        }
    }

    /// Get our session index (they use this to send TO us).
    pub(crate) fn our_index(&self) -> Option<SessionIndex> {
        self.index(Slot::Current)
    }

    /// Get their session index (we use this to send TO them).
    pub(crate) fn their_index(&self) -> Option<SessionIndex> {
        self.rekey
            .as_ref()?
            .theirs(Slot::Current)
            .map(SessionIndex::new)
    }

    /// Move this peer onto `session`, the winning handshake of a crossed
    /// dial, under this node's `ours` and the peer's `theirs`.
    ///
    /// When both nodes dial each other at once, each promotes the handshake
    /// the other started; the smaller node's outbound handshake wins, and it
    /// moves to that session when the peer's msg2 arrives. The link's rekey
    /// machine is closed, which abandons its own rekey in flight, ends a
    /// responder pending and the drain of the previous session, and releases
    /// every index they held, and a new one is built on `session` from what
    /// the closed one hands back: the moved session keeps the replaced one's
    /// key-epoch bit and start (so its rekey age and inner-header timestamps
    /// carry on), the link's age, the key-epoch bit last seen from the peer
    /// and the replay record. `caps` lends the index allocator and keys, the
    /// parameters the new machine is built with and whether a decrypt-worker
    /// pool runs, to which the new session is offered at once; its record is
    /// not read.
    ///
    /// Returns the outputs that unbind, revoke and release what the closed
    /// machine held and bind (and offer) the new session. Hands `ours` back
    /// in a release, changing nothing, when `session` authenticated another
    /// key than the peer's. Also resets the replay suppression counter and
    /// the repeated handshake line counts since the session changed.
    pub(crate) fn move_session(
        &mut self,
        session: NoiseSession,
        ours: IndexLease,
        theirs: SessionIndex,
        caps: &mut LinkCaps<'_>,
    ) -> LinkOutputs {
        self.reset_replay_suppressed();
        self.hs_lines.roll();
        let transport = self.bound_transport();
        let Some(old) = self.rekey.take() else {
            return vec![LinkOutput::Release(ours)];
        };
        let remote = PeerKey::from_xonly(&session.remote_static_xonly());
        let view = old.view();
        let held = match view.identity {
            Identity::Proven(key) if key == remote => Some(key),
            Identity::Proven(_) | Identity::Claimed(_) => None,
        };
        let Some(bond) = held else {
            self.rekey = Some(old);
            return vec![LinkOutput::Release(ours)];
        };
        let (mut out, carry) = old.close(Close::CrossConnectionMove);
        let Some(carry) = carry else {
            out.push(LinkOutput::Release(ours));
            return out;
        };
        match link_machine(bond, session, ours, theirs, transport, carry.into(), caps) {
            Ok((rekey, built)) => {
                out.extend(built);
                self.rekey = Some(rekey);
            }
            Err(lease) => out.push(LinkOutput::Release(lease)),
        }
        out
    }

    /// Get the transport ID for this peer.
    pub fn transport_id(&self) -> Option<TransportId> {
        self.send.transport_id
    }

    /// Get the current transport address.
    pub fn current_addr(&self) -> Option<&TransportAddr> {
        self.send.current_addr.as_ref()
    }

    /// Update the current address (for roaming support).
    ///
    /// Called when we receive a valid authenticated packet from a new address.
    /// Returns `true` if `(transport_id, addr)` actually changed — callers
    /// use this to invalidate per-peer `connect(2)`-ed UDP sockets whose
    /// 5-tuple just went stale.
    pub fn set_current_addr(&mut self, transport_id: TransportId, addr: TransportAddr) -> bool {
        let changed = self.send.transport_id != Some(transport_id)
            || self.send.current_addr.as_ref() != Some(&addr);
        self.send.transport_id = Some(transport_id);
        self.send.current_addr = Some(addr);
        changed
    }

    // === Handshake Resend ===

    /// Store wire-format msg2 for resend on duplicate msg1.
    pub(crate) fn set_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.handshake_msg2 = Some(msg2);
    }

    /// Get stored msg2 bytes for resend.
    pub(crate) fn handshake_msg2(&self) -> Option<&[u8]> {
        self.handshake_msg2.as_deref()
    }

    // === Replay Detection Suppression ===

    /// Increment replay suppression counter. Returns the new count.
    pub fn increment_replay_suppressed(&mut self) -> u32 {
        self.send.replay_suppressed_count += 1;
        self.send.replay_suppressed_count
    }

    /// Reset replay suppression counter, returning previous count.
    pub fn reset_replay_suppressed(&mut self) -> u32 {
        let count = self.send.replay_suppressed_count;
        self.send.replay_suppressed_count = 0;
        count
    }

    /// Current replay suppression count.
    pub fn replay_suppressed_count(&self) -> u32 {
        self.send.replay_suppressed_count
    }

    // === Repeated Handshake Lines ===

    /// This peer's repeated handshake line counts.
    pub(crate) fn hs_lines(&self) -> &HsLineCounts {
        &self.hs_lines
    }

    /// This peer's repeated handshake line counts, to count a line.
    pub(crate) fn hs_lines_mut(&mut self) -> &mut HsLineCounts {
        &mut self.hs_lines
    }

    // === Decryption Failure Tracking ===

    /// Increment consecutive decryption failure counter, returning new count.
    /// Saturates at `u32::MAX`, since only an authenticated frame resets it.
    pub fn increment_decrypt_failures(&mut self) -> u32 {
        self.send.consecutive_decrypt_failures =
            self.send.consecutive_decrypt_failures.saturating_add(1);
        self.send.consecutive_decrypt_failures
    }

    /// Reset consecutive decryption failure counter.
    pub fn reset_decrypt_failures(&mut self) {
        self.send.consecutive_decrypt_failures = 0;
    }

    /// Current consecutive decryption failure count.
    pub fn consecutive_decrypt_failures(&self) -> u32 {
        self.send.consecutive_decrypt_failures
    }

    /// Record the receiver index of a frame that failed to decrypt.
    pub(crate) fn record_failed(&mut self, idx: SessionIndex) {
        self.send.failed_idx = Some(idx);
    }

    /// The receiver index of the last frame that failed to decrypt.
    pub(crate) fn last_failed(&self) -> Option<SessionIndex> {
        self.send.failed_idx
    }

    /// Count one frame authenticated on the previous session.
    pub(crate) fn count_previous(&mut self) {
        self.send.prev_frames = self.send.prev_frames.saturating_add(1);
    }

    /// Frames authenticated on the previous session since the last cutover.
    pub(crate) fn prev_frames(&self) -> u64 {
        self.send.prev_frames
    }

    // === Epoch Accessors ===

    /// Get the remote peer's startup epoch (from handshake).
    pub(crate) fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.rekey.as_ref()?.view().peer_epoch
    }

    /// Update the remote peer's startup epoch after a successful in-place
    /// rekey. Initial handshakes set this through `with_session`, but recovery
    /// rekeys also exchange epochs and must keep restart detection current.
    #[cfg(test)]
    pub(crate) fn set_remote_epoch(&mut self, remote_epoch: Option<[u8; 8]>) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.force_peer_epoch(remote_epoch);
        }
    }

    // === Negotiated Profile ===

    /// Get peer's node profile.
    pub fn peer_profile(&self) -> NodeProfile {
        self.peer_profile
    }

    /// Whether to send sender reports to this peer.
    pub fn send_sr(&self) -> bool {
        self.send_sr
    }

    /// Whether to send receiver reports to this peer.
    pub fn send_rr(&self) -> bool {
        self.send_rr
    }

    // === Tree Accessors ===

    /// Get the peer's tree coordinates, if known.
    pub fn coords(&self) -> Option<&TreeCoordinate> {
        self.ancestry.as_ref()
    }

    /// Get the peer's parent declaration, if known.
    pub fn declaration(&self) -> Option<&ParentDeclaration> {
        self.declaration.as_ref()
    }

    /// Check if this peer has a known tree position.
    pub fn has_tree_position(&self) -> bool {
        self.declaration.is_some() && self.ancestry.is_some()
    }

    // === Filter Accessors ===

    /// Get the peer's inbound filter, if known.
    pub fn inbound_filter(&self) -> Option<&BloomFilter> {
        self.inbound_filter.as_ref()
    }

    /// Get the filter sequence number.
    pub fn filter_sequence(&self) -> u64 {
        self.filter_sequence
    }

    /// Check if this peer's filter is stale.
    pub fn filter_is_stale(&self, current_time_ms: u64, stale_threshold_ms: u64) -> bool {
        if self.filter_received_at == 0 {
            return true;
        }
        current_time_ms.saturating_sub(self.filter_received_at) > stale_threshold_ms
    }

    /// Check if a destination might be reachable through this peer.
    pub fn may_reach(&self, node_addr: &NodeAddr) -> bool {
        match &self.inbound_filter {
            Some(filter) => filter.contains(node_addr),
            None => false,
        }
    }

    /// Check if we need to send this peer a filter update.
    pub fn needs_filter_update(&self) -> bool {
        self.pending_filter_update
    }

    // === Statistics Accessors ===

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        &self.send.link_stats
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.send.link_stats
    }

    // === MMP Accessors ===

    /// Get MMP state (None for legacy peers without sessions).
    pub fn mmp(&self) -> Option<&MmpPeerState> {
        self.send.mmp.as_ref()
    }

    /// Get mutable MMP state.
    pub fn mmp_mut(&mut self) -> Option<&mut MmpPeerState> {
        self.send.mmp.as_mut()
    }

    /// Link cost for routing decisions.
    ///
    /// Returns a scalar cost where lower is better (1.0 = ideal).
    /// Computed as RTT-weighted ETX: `etx * (1.0 + srtt_ms / 100.0)`.
    ///
    /// Returns 1.0 (optimistic default) when MMP metrics are not yet
    /// available, matching depth-only parent selection behavior.
    pub fn link_cost(&self) -> f64 {
        match self.mmp() {
            Some(mmp) => {
                let etx = mmp.metrics.etx;
                match mmp.metrics.srtt_ms() {
                    Some(srtt_ms) => etx * (1.0 + srtt_ms / 100.0),
                    None => 1.0,
                }
            }
            None => 1.0,
        }
    }

    /// Whether this peer has at least one MMP RTT measurement.
    pub fn has_srtt(&self) -> bool {
        self.mmp()
            .is_some_and(|mmp| mmp.metrics.srtt_ms().is_some())
    }

    /// When this peer was authenticated.
    pub fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    /// When this peer was last seen.
    pub fn last_seen(&self) -> u64 {
        self.send.last_seen
    }

    /// Whether an authenticated frame from this peer has arrived since it was
    /// promoted.
    pub(crate) fn heard(&self) -> bool {
        self.send.heard
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.send.last_seen)
    }

    /// Connection duration since authentication.
    pub fn connection_duration(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.authenticated_at)
    }

    /// Session-relative elapsed time in milliseconds (for inner header timestamp).
    ///
    /// Returns milliseconds since the current session's timestamp base, its
    /// cutover, truncated to u32. Wraps at ~49.7 days which is acceptable
    /// for session-relative timing. Zero for a peer without a session.
    pub(crate) fn session_elapsed_ms(&self) -> u32 {
        self.rekey
            .as_ref()
            .and_then(LinkRekey::base)
            .map_or(0, |base| since(base).as_millis() as u32)
    }

    /// When the link's rekey machine last heard the peer: the last frame
    /// that authenticated under any session the link holds, the previous
    /// one during a drain included. `None` before the first.
    pub(crate) fn last_heard(&self) -> Option<PeerInstant> {
        self.rekey.as_ref()?.view().last_rx
    }

    /// How long ago this peer's current session started (for link-dead
    /// fallback timing): the time since the current session's timestamp
    /// base on the peer clock, the clock the link's MMP receiver reads, or
    /// zero for a peer without a session.
    pub(crate) fn session_age(&self) -> Duration {
        self.rekey
            .as_ref()
            .and_then(LinkRekey::base)
            .map_or(Duration::ZERO, since)
    }

    // === Heartbeat ===

    /// When a heartbeat to this peer last succeeded.
    pub fn last_heartbeat_sent(&self) -> Option<Instant> {
        self.last_heartbeat_sent
    }

    /// Record that a heartbeat reached the transport without error.
    ///
    /// Call this *after* the send, and only when it returned cleanly. Marking
    /// before the send makes a failed heartbeat indistinguishable from a
    /// delivered one, which then suppresses the next attempt for a full
    /// `heartbeat_interval_secs` although the peer has heard nothing.
    pub fn mark_heartbeat_sent(&mut self, now: Instant) {
        self.last_heartbeat_sent = Some(now);
        self.last_heartbeat_attempt = Some(now);
    }

    /// When a heartbeat to this peer was last attempted, whatever came of it.
    pub(crate) fn last_heartbeat_attempt(&self) -> Option<Instant> {
        self.last_heartbeat_attempt
    }

    /// Record that a heartbeat send was attempted.
    ///
    /// Call this *before* the send, so an attempt that fails, or one that never
    /// returns, still spaces the next one out.
    pub(crate) fn mark_heartbeat_attempt(&mut self, now: Instant) {
        self.last_heartbeat_attempt = Some(now);
    }

    // === State Updates ===

    /// Record an authenticated frame from this peer: refresh the last-seen
    /// time and mark the peer as heard.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.send.last_seen = current_time_ms;
        self.send.heard = true;
    }

    /// Update the link ID (e.g., on reconnect).
    pub fn set_link_id(&mut self, link_id: LinkId) {
        self.send.link_id = link_id;
    }

    // === Tree Updates ===

    /// Update peer's tree position.
    pub fn update_tree_position(
        &mut self,
        declaration: ParentDeclaration,
        ancestry: TreeCoordinate,
        current_time_ms: u64,
    ) {
        self.declaration = Some(declaration);
        self.ancestry = Some(ancestry);
        self.send.last_seen = current_time_ms;
    }

    /// Clear peer's tree position.
    pub fn clear_tree_position(&mut self) {
        self.declaration = None;
        self.ancestry = None;
    }

    // === Tree Announce Rate Limiting ===

    /// Set the minimum interval between TreeAnnounce messages (milliseconds).
    pub fn set_tree_announce_min_interval_ms(&mut self, ms: u64) {
        self.tree_announce_min_interval_ms = ms;
    }

    /// Get the last tree announce send timestamp (for carrying across reconnection).
    pub fn last_tree_announce_sent_ms(&self) -> u64 {
        self.last_tree_announce_sent_ms
    }

    /// Set the last tree announce send timestamp (to preserve rate limit across reconnection).
    pub fn set_last_tree_announce_sent_ms(&mut self, ms: u64) {
        self.last_tree_announce_sent_ms = ms;
    }

    /// Check if we can send a TreeAnnounce now (rate limiting).
    pub fn can_send_tree_announce(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_tree_announce_sent_ms) >= self.tree_announce_min_interval_ms
    }

    /// Record that we sent a TreeAnnounce to this peer.
    pub fn record_tree_announce_sent(&mut self, now_ms: u64) {
        self.last_tree_announce_sent_ms = now_ms;
        self.pending_tree_announce = false;
    }

    /// Mark that a tree announce is pending (deferred by the rate limit or by
    /// a failed link send).
    pub fn mark_tree_announce_pending(&mut self) {
        self.pending_tree_announce = true;
    }

    /// Check if a deferred tree announce is waiting to be sent.
    pub fn has_pending_tree_announce(&self) -> bool {
        self.pending_tree_announce
    }

    // === Filter Updates ===

    /// Update peer's inbound filter.
    pub fn update_filter(&mut self, filter: BloomFilter, sequence: u64, current_time_ms: u64) {
        self.inbound_filter = Some(filter);
        self.filter_sequence = sequence;
        self.filter_received_at = current_time_ms;
        self.send.last_seen = current_time_ms;
    }

    /// Clear peer's inbound filter.
    pub fn clear_filter(&mut self) {
        self.inbound_filter = None;
        self.filter_sequence = 0;
        self.filter_received_at = 0;
    }

    /// Mark that we need to send this peer a filter update.
    pub fn mark_filter_update_needed(&mut self) {
        self.pending_filter_update = true;
    }

    /// Clear the pending filter update flag.
    pub fn clear_filter_update_needed(&mut self) {
        self.pending_filter_update = false;
    }

    // === Rekey (Key Rotation) ===

    /// When the current Noise session was established; `None` without a
    /// session.
    pub(crate) fn session_established_at(&self) -> Option<PeerInstant> {
        self.rekey.as_ref()?.started(Slot::Current)
    }

    /// Test-only seam: install link-layer MMP state with a chosen operating
    /// mode on a peer that was constructed without a Noise session (the bare
    /// `new` constructor leaves `mmp` as `None`). This only attaches the same
    /// `MmpPeerState::new` the session path installs; it changes no decision
    /// logic and no threshold, and is compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_init_mmp(&mut self, mode: crate::proto::mmp::MmpMode) {
        let config = MmpConfig {
            mode,
            ..MmpConfig::default()
        };
        self.send.mmp = Some(MmpPeerState::new(
            config.mode,
            config.log_interval_secs,
            config.owd_window_size,
        ));
    }

    /// When this peering's link came up: at promotion, or when a pending
    /// session that revealed a peer restart left the slot. Unlike
    /// [`session_established_at`](Self::session_established_at), a rekey
    /// cutover does not move it. `None` without a session.
    #[cfg(test)]
    pub(crate) fn link_established_at(&self) -> Option<PeerInstant> {
        Some(self.rekey.as_ref()?.view().link_since)
    }

    /// Test-only seam: backdate the session-established instant so a test can
    /// construct a session that reads as `age`-old. The link instant is moved
    /// back with it when it would otherwise be the younger of the two, since
    /// a link is never younger than its session. This only shifts the
    /// machine's stamps; it changes no decision logic, no threshold, and is
    /// compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_session_established(&mut self, age: std::time::Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_started(age);
        }
    }

    /// Test-only seam: backdate the drain-start instant so a test can make
    /// `drain_expired()` read true without waiting out the drain window. Only
    /// shifts the private timestamp field, and is a no-op when no drain is in
    /// progress, so it cannot manufacture a drain that did not happen. It changes
    /// no decision logic, no threshold, and is compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_drain_started(&mut self, age: Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_drain(age);
        }
    }

    /// Test-only seam: backdate the pending session's install time so a test
    /// can make the responder hold read as passed. Shifts only the machine's
    /// stamp; compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn backdate_pending(&mut self, age: Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_pending(age);
        }
    }

    /// Test-only seam: backdate the last peer-initiated rekey so a test can
    /// move past the rekey dampening window without waiting it out. Shifts
    /// only the machine's stamp; compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn backdate_dampener(&mut self, age: Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_dampening(age);
        }
    }

    /// Test-only seam: set the K-bit this node sends with, to stand up the
    /// out-of-step K-bits that a peer restart or a cross-connection swap
    /// leaves behind. Compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn force_kbit(&mut self, kbit: bool) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.force_k(kbit);
        }
    }

    /// Test-only seam: seal `plaintext` under this peer's session in `slot`
    /// for `receiver_idx` with header flags `flags`, as the inline send path
    /// seals a frame, and return the framed wire bytes. A test forges with it
    /// what the peer holding the other half of that session would send.
    #[cfg(test)]
    pub(crate) fn seal_test_frame(
        &mut self,
        slot: Slot,
        receiver_idx: SessionIndex,
        flags: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        use crate::proto::fmp::wire::{build_encrypted, build_established_header};
        let (counter, key) = self
            .rekey
            .as_mut()
            .and_then(|rekey| rekey.reserve_slot(slot))
            .expect("the peer holds a session in the slot");
        let header = build_established_header(receiver_idx, counter, flags, plaintext.len() as u16);
        let ciphertext = fips_core::noise::seal(key.key(), counter, &header, plaintext)
            .expect("the session seals");
        build_encrypted(&header, &ciphertext)
    }

    /// Test-only: what this peer's link rekey machine would hand a
    /// successor: the key-epoch bits of its current session and of the
    /// peer's last frame, its current session's start and timestamp base,
    /// the link's age, the peer's startup epoch and the replay record.
    #[cfg(test)]
    pub(crate) fn link_anchors(&self) -> Option<LinkAnchors> {
        let rekey = self.rekey.as_ref()?;
        let view = rekey.view();
        let cur = view.current.as_ref()?;
        let (peer_k, record) = rekey.memory();
        Some(LinkAnchors {
            k: cur.k,
            started: cur.started,
            base: cur.base,
            link_since: view.link_since,
            peer_epoch: view.peer_epoch,
            peer_k,
            record: record.clone(),
        })
    }

    /// Test-only: every index this peer's link rekey machine binds, with
    /// the transport recorded at the binding and whether a decrypt worker
    /// holds that session's receive half, for the audit of the node's index
    /// map and worker table against the machine.
    #[cfg(test)]
    pub(crate) fn link_bindings(&self) -> Vec<((TransportId, u32), bool)> {
        use fips_core::proto::rekey::{Purpose, RecvHome};
        let Some(rekey) = self.rekey.as_ref() else {
            return Vec::new();
        };
        let view = rekey.view();
        rekey
            .bindings()
            .into_iter()
            .map(|b| {
                let ep = match b.purpose {
                    Purpose::Current => view.current.as_ref(),
                    Purpose::Previous => view.previous.as_ref(),
                    Purpose::Pending => view.pending.as_ref(),
                    Purpose::Attempt => None,
                };
                let on_worker = ep.is_some_and(|e| e.recv == RecvHome::Delegated);
                ((b.transport, b.index), on_worker)
            })
            .collect()
    }

    /// Test-only seam: backdate the session's timestamp base so a test can
    /// make `session_elapsed_ms()` read as `age`-old (needed to synthesize a
    /// positive RTT sample from a crafted ReceiverReport). This only shifts the
    /// machine's stamp; it changes no decision logic, no threshold, and is
    /// compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_session_start(&mut self, age: std::time::Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_base(age);
        }
    }

    /// Per-session symmetric rekey-timer jitter offset (seconds).
    ///
    /// Drawn at session construction and at each rekey cutover; uniform
    /// over `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`. Callers add this
    /// to the configured `node.rekey.after_secs` to obtain the effective
    /// trigger interval for this session. Zero without a session.
    #[cfg(test)]
    pub(crate) fn rekey_jitter_secs(&self) -> i64 {
        self.rekey
            .as_ref()
            .map_or(0, |rekey| i64::from(rekey.jitter_secs()))
    }

    /// Current K-bit epoch value.
    pub(crate) fn current_k_bit(&self) -> bool {
        self.rekey.as_ref().is_some_and(LinkRekey::k)
    }

    /// Whether this node's own rekey handshake is in flight: its msg1 sent
    /// and the peer's msg2 not yet read.
    pub(crate) fn rekey_in_progress(&self) -> bool {
        self.rekey
            .as_ref()
            .is_some_and(|rekey| rekey.view().cycle == CycleView::Init)
    }

    /// Whether dampening, opened when this node last answered the peer's
    /// rekey, still holds back this node's own.
    #[cfg(test)]
    pub(crate) fn dampened(&self) -> bool {
        self.rekey
            .as_ref()
            .is_some_and(|rekey| rekey.dampened(peer_now()))
    }

    /// Get the pending new session's our_index.
    pub(crate) fn pending_our_index(&self) -> Option<SessionIndex> {
        self.index(Slot::Pending)
    }

    /// Get the pending new session's their_index.
    #[cfg(test)]
    pub(crate) fn pending_their_index(&self) -> Option<SessionIndex> {
        self.rekey
            .as_ref()?
            .theirs(Slot::Pending)
            .map(SessionIndex::new)
    }

    /// Get the previous session's our_index (during drain).
    pub(crate) fn previous_our_index(&self) -> Option<SessionIndex> {
        self.index(Slot::Previous)
    }

    /// Get the previous session for decryption fallback.
    pub(crate) fn previous_session(&self) -> Option<&NoiseSession> {
        self.keys(Slot::Previous)
    }

    /// Get the pending new session (completed rekey, not yet cut over).
    pub(crate) fn pending_new_session(&self) -> Option<&NoiseSession> {
        self.keys(Slot::Pending)
    }

    /// Which side of the rekey handshake produced the pending session; `None`
    /// when no pending session is held.
    pub(crate) fn pending_role(&self) -> Option<Role> {
        match self.rekey.as_ref()?.view().cycle {
            CycleView::PendI(_) => Some(Role::Initiator),
            CycleView::PendR => Some(Role::Responder),
            CycleView::Idle | CycleView::Init => None,
        }
    }

    /// The digest of the msg1 whose answer armed the pending session, and
    /// the msg2 that answered it, when this node holds it as the rekey
    /// responder; `None` otherwise.
    pub(crate) fn rekey_answer(&self) -> Option<(Msg1Digest, Vec<u8>)> {
        let (msg1, msg2) = self.rekey.as_ref()?.rekey_answer()?;
        Some((msg1.into(), msg2.clone()))
    }

    /// Record `msg1`, the framed link-setup msg1 this peering was promoted
    /// from, and `msg2`, the msg2 that answered it: a resend of the msg1
    /// draws the msg2 again while the session is too young to rekey, and a
    /// copy of it, under any header, is refused once the session is old
    /// enough. Nothing is recorded for a msg1 too short to frame one.
    pub(crate) fn note_setup(&mut self, msg1: &[u8], msg2: &[u8]) {
        if let Some(rekey) = self.rekey.as_mut()
            && let Some(record) = setup_record(msg1, Some(msg2))
        {
            rekey.note_setup(record);
        }
    }

    /// Record the ephemeral digest of the link-setup msg1 this peering was
    /// promoted from (`None` if the msg1 was too short to carry one).
    pub(crate) fn note_setup_ephemeral(&mut self, ephemeral: Option<EphemeralDigest>) {
        self.setup_ephemeral = ephemeral;
    }

    /// The ephemeral digest of the link-setup msg1 this peering was promoted
    /// from, or `None` for a peering this node dialled.
    pub(crate) fn setup_ephemeral(&self) -> Option<EphemeralDigest> {
        self.setup_ephemeral
    }

    /// How long the pending session has been held since it was installed;
    /// `None` when no pending session is held.
    pub(crate) fn pending_age(&self) -> Option<Duration> {
        self.rekey.as_ref()?.started(Slot::Pending).map(since)
    }

    /// Step this peer's link rekey machine with `input` at `now`, lending
    /// it the node's index allocator `indices`, its keys `local` and
    /// whether a decrypt-worker pool exists, and return what the node must
    /// carry out, front to back. Empty for a peer without a session. Its
    /// index bindings are made on the transport the peer is reached over
    /// now.
    pub(crate) fn step_link(
        &mut self,
        now: PeerInstant,
        input: Input<'_, LinkProfile>,
        indices: &mut crate::utils::index::IndexAllocator,
        local: &fips_core::proto::rekey::NodeKeys,
        workers: bool,
    ) -> LinkOutputs {
        let transport = self.bound_transport();
        let Some(rekey) = self.rekey.as_mut() else {
            return LinkOutputs::new();
        };
        let mut scratch = Vec::new();
        with_tags(|tags| {
            let mut env = Env {
                indices,
                transport,
                tags,
                workers,
                jitter: &mut ThreadJitter,
                local,
                scratch: &mut scratch,
            };
            rekey.step(now, input, &mut env)
        })
    }

    /// Test-only: start this node's own rekey at `now` as a trigger that has
    /// come would, whatever the link's age, lending the machine `indices`
    /// and `local`. Returns the outputs (the attempt index's binding and the
    /// msg1); empty when a rekey or a pending session is already held.
    #[cfg(test)]
    pub(crate) fn start_rekey_now(
        &mut self,
        now: PeerInstant,
        indices: &mut crate::utils::index::IndexAllocator,
        local: &fips_core::proto::rekey::NodeKeys,
    ) -> LinkOutputs {
        let transport = self.bound_transport();
        let Some(rekey) = self.rekey.as_mut() else {
            return LinkOutputs::new();
        };
        let mut scratch = Vec::new();
        with_tags(|tags| {
            let mut env = Env {
                indices,
                transport,
                tags,
                workers: false,
                jitter: &mut ThreadJitter,
                local,
                scratch: &mut scratch,
            };
            rekey.start_now(now, &mut env)
        })
    }

    /// Test-only: the index of this node's own rekey in flight, which a msg2
    /// names; `None` with no attempt in flight.
    #[cfg(test)]
    pub(crate) fn rekey_our_index(&self) -> Option<SessionIndex> {
        self.rekey
            .as_ref()?
            .bindings()
            .into_iter()
            .find(|b| b.purpose == fips_core::proto::rekey::Purpose::Attempt)
            .map(|b| SessionIndex::new(b.index))
    }

    /// Seal the link prompt under this peer's session `tag` at `now`.
    pub(crate) fn seal_prompt(
        &mut self,
        now: PeerInstant,
        tag: fips_core::proto::rekey::EpochTag,
    ) -> Result<fips_core::proto::rekey::SealedPrompt<LinkProfile>, SealRefusal> {
        match self.rekey.as_mut() {
            Some(rekey) => rekey.seal_prompt(now, tag),
            None => Err(SealRefusal::NotEstablished),
        }
    }

    /// Reset what a cutover resets beside the machine: the replay
    /// suppression and handshake line counts, the frames counted on the
    /// previous session, and the link MMP counters. The node runs it for
    /// each cutover the link machine reports.
    pub(crate) fn after_cutover(&mut self) {
        self.send.prev_frames = 0;
        self.reset_replay_suppressed();
        self.hs_lines.roll();

        // Reset MMP counters to avoid metric discontinuity
        let now_ms = crate::time::mono_ms();
        if let Some(mmp) = &mut self.send.mmp {
            mmp.reset_for_rekey(now_ms);
        }
    }

    /// Whether a drain is in progress.
    pub(crate) fn is_draining(&self) -> bool {
        self.rekey
            .as_ref()
            .is_some_and(|rekey| rekey.drain_deadline().is_some())
    }

    /// How long ago the last cutover happened; `None` if there has been none.
    pub(crate) fn since_cutover(&self) -> Option<Duration> {
        self.rekey.as_ref()?.last_cutover().map(since)
    }

    /// Test-only: offer the current session's receive half to the decrypt
    /// workers, as a poll does while no worker holds it, for a test that
    /// starts the worker pool after the link was promoted.
    #[cfg(test)]
    pub(crate) fn offer_to_workers(&self) -> LinkOutputs {
        self.rekey
            .as_ref()
            .map(LinkRekey::offer_held)
            .unwrap_or_default()
    }

    /// End the link's rekey machine as the peer is removed, returning the
    /// outputs that unbind, revoke and release every index it held (its
    /// sessions' and its own rekey handshake's), and the peer's startup
    /// epoch with the replay record the machine kept, for the node to hand
    /// to a later link with the peer at that epoch. Empty outputs and no
    /// record for a peer without a session.
    pub(crate) fn close(&mut self) -> (LinkOutputs, Option<([u8; 8], Record)>) {
        // The reason only labels an own rekey handshake the machine
        // abandons, which the node counts nowhere.
        let Some(rekey) = self.rekey.take() else {
            return (LinkOutputs::new(), None);
        };
        let (out, carry) = rekey.close(fips_core::proto::rekey::Close::Admin);
        (
            out,
            carry.map(|c| (c.peer_epoch.unwrap_or_default(), c.record)),
        )
    }
}

#[cfg(test)]
#[path = "tests/active.rs"]
mod tests;
