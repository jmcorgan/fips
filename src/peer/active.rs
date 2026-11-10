//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use super::data::{Departed, PeerData};
use super::{
    LinkCaps, LinkOutput, LinkOutputs, LinkProfile, LinkRekey, Match, PathCaps, PeerBundle,
    PeerInstant, PeerPath, Roam, UdpSlot, peer_now, since,
};
#[cfg(test)]
use super::{Medium, PathSet, Rebind};
use crate::config::MmpConfig;
use crate::node::diag::HsLineCounts;
use crate::node::session::{ThreadJitter, with_tags};
use crate::node::settle::table::Transition;
use crate::noise::NoiseSession;
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::{NegotiationPayload, NodeProfile};
use crate::proto::mmp::MmpPeerState;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Ipv6Address, NodeAddr, PeerIdentity};
use fips_core::proto::fmp::rekey::{LinkKeys, LinkLocal};
use fips_core::proto::path::{Account, Charge, Outputs};
#[cfg(test)]
use fips_core::proto::rekey::{Bond, Ids};
use fips_core::proto::rekey::{
    Close, Completed, CycleView, Env, IndexLease, Input, PeerKey, Record, Role, SealRefusal,
    Sealed, SendCopy, SetupFacts, Slot,
};
use fips_core::proto::settle::input::Input as In;
use fips_core::proto::settle::join::{Caps, Event, Joined, Setup, Step, join};
use fips_core::proto::settle::links::LinkNo;
#[cfg(unix)]
use portable_atomic::AtomicU64;
use portable_atomic::Ordering;
use secp256k1::XOnlyPublicKey;
use std::fmt;
#[cfg(unix)]
use std::sync::Arc;
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
/// A test's peer is built with it outside the settlement core's join, which
/// builds every node's machine (test builds only).
#[cfg(test)]
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
    let local = LinkLocal::for_call(caps.local, caps.profile, Some(theirs.as_u32()));
    let mut scratch = Vec::new();
    Ok(with_tags(|tags| {
        let mut env = Env {
            indices: &mut *caps.indices,
            transport,
            tags,
            workers: caps.workers,
            jitter: &mut ThreadJitter,
            local: &local,
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

/// This node's keys `keys` and node profile `profile` for one call into the
/// link machine `rekey`: a rekey's msg3 declares the session it replaces by
/// the index the peer receives the current session on.
fn link_local(
    rekey: &LinkRekey,
    keys: &fips_core::proto::rekey::NodeKeys,
    profile: NodeProfile,
) -> LinkLocal {
    LinkLocal::for_call(keys, profile, rekey.theirs(Slot::Current))
}

/// What the settlement core's join returns to a node: the steps for one
/// peer, front to back.
type LinkJoined = Joined<LinkProfile, UdpSlot, PeerInstant>;

/// Run `f` with the capabilities a link's rekey machine is built with,
/// lent from `caps` for a machine bound on `transport` whose current
/// session the peer receives on `theirs`, now. The epoch tag source is held
/// for the whole call.
fn lent<R>(
    caps: &mut LinkCaps<'_>,
    transport: TransportId,
    theirs: SessionIndex,
    f: impl FnOnce(&mut Caps<'_, '_, LinkProfile, PeerInstant>) -> R,
) -> R {
    let local = LinkLocal::for_call(caps.local, caps.profile, Some(theirs.as_u32()));
    let mut scratch = Vec::new();
    with_tags(|tags| {
        let mut env = Env {
            indices: &mut *caps.indices,
            transport,
            tags,
            workers: caps.workers,
            jitter: &mut ThreadJitter,
            local: &local,
            scratch: &mut scratch,
        };
        f(&mut Caps {
            params: caps.params,
            me: caps.me,
            now: peer_now(),
            env: &mut env,
        })
    })
}

/// What building a peer's machines hands the node to carry out once it holds
/// the peer: the rekey machine's outputs and the core inputs.
type Started = (LinkOutputs, Vec<In>);

/// What closing a peer's machines hands the node: every path's driver slot
/// to release, and the rekey machine's outputs.
type Stopped = (Outputs<UdpSlot>, LinkOutputs);

/// The steps `joined` holds, as the node carries them out: the rekey
/// machine's outputs and the bundle's, each in its order, and the core
/// inputs. Building and closing a rekey machine report no restart, teardown
/// or replacement, so only a start on a link the core records tells the core
/// anything: that the new bundle's original path is Live.
fn split(joined: LinkJoined) -> (LinkOutputs, Outputs<UdpSlot>, Vec<In>) {
    let mut rekey = LinkOutputs::new();
    let mut paths = Outputs::new();
    let mut core = Vec::new();
    for step in joined {
        match step {
            Step::Rekey(o) => rekey.push(o),
            Step::Path(o) => paths.push(o),
            Step::Core(input) => core.push(input),
            Step::Replace(_) => {
                debug_assert!(
                    false,
                    "a build or close of the machines asked for a replacement"
                );
            }
        }
    }
    (rekey, paths, core)
}

/// The path machine of a link established now on (`transport_id`,
/// `addr`), its original path, with the parameters and facts `caps` gives
/// (multipath v1 draft, Section 4).
fn new_bundle(transport_id: TransportId, addr: TransportAddr, caps: &PathCaps<'_>) -> PeerBundle {
    let env = fips_core::proto::path::Env {
        facts: caps.facts,
        cost: 1.0,
    };
    PeerBundle::new(peer_now(), transport_id, addr, caps.params, &env)
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
        last_rx: None,
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
/// dispatch: the transport target and, per path, the connected-UDP handle.
/// The epochs, their keys, indices and key-epoch bits and the
/// session-relative time base live in the peer's link rekey machine; the hot
/// per-packet counters live in its [`PeerData`].
///
/// Co-located, not behind `Arc`/`ArcSwap` — the data plane is not sharded, so
/// the hot path reads this by plain borrow. Publishing behind `Arc`/`ArcSwap`
/// is later-increment plumbing for a sharded data plane.
#[derive(Debug)]
struct PeerSendState {
    /// The machine of the link's paths: the paths this peer is reachable
    /// over, and which one *our* frames go out on. `None` for a peer not
    /// yet bound to a transport.
    bundle: Option<PeerBundle>,
    /// Link used to reach this peer.
    link_id: LinkId,
}

impl PeerSendState {
    /// Empty send-state for a peer with no Noise session yet.
    fn new(link_id: LinkId) -> Self {
        Self {
            bundle: None,
            link_id,
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

    // === Rekey (Key Rotation) ===
    /// The link's rekey machine: its epochs and their keys, indices and
    /// key-epoch bits, this node's own rekey handshake in flight, the
    /// drain, the pending session with the role that made it and its
    /// install time, the peer's startup epoch, dampening, the link's age,
    /// the rekey jitter and the record of answered msg1s. `None` for a peer
    /// built without a Noise session.
    rekey: Option<LinkRekey>,

    // === Per-Peer Record ===
    /// Everything held about this peer but its identity and its two machines.
    data: PeerData,

    // === Published active-send-state (two-tier boundary) ===
    /// The send-critical subset read (and, on roam/responder-cutover, written)
    /// directly by the data plane. See `PeerSendState`.
    send: PeerSendState,

    /// Whether a test changed the link's bundle past the feed of the
    /// settlement core's record of the link: a test mutator of the paths, or
    /// a test's own call of [`account`](Self::account). The live audit then
    /// holds the record to the bundle no longer (test builds only).
    #[cfg(test)]
    past_feed: bool,
}

impl ActivePeer {
    /// Create a new active peer from verified identity.
    ///
    /// Called after successful authentication handshake.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn new(identity: PeerIdentity, link_id: LinkId, authenticated_at: u64) -> Self {
        let now = peer_now();
        Self {
            npub: identity.npub(),
            short_npub: identity.short_npub(),
            identity,
            rekey: None,
            data: PeerData::new(authenticated_at, now),
            send: PeerSendState::new(link_id),
            #[cfg(test)]
            past_feed: false,
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
        peer.data.link_stats = link_stats;
        peer
    }

    /// Create from verified identity with Noise session and index tracking.
    ///
    /// This is the primary constructor for the wire protocol path. The
    /// session becomes the first epoch of the peer's link rekey machine,
    /// under `our_index`, the lease link setup took, and the peer's
    /// `their_index`, bound on `transport_id`; the machine is bonded to the
    /// identity's key. The link's path machine is built next, its original
    /// path at (`transport_id`, `current_addr`); the settlement core's join
    /// makes both calls. `link` is the core's number for the link, where the
    /// node's link table records it. Returns the peer and what the node
    /// carries out once it holds the peer: the rekey machine's outputs, the
    /// binding of `our_index` among them, and the core inputs, the original
    /// path recorded Live on `link`. Hands the lease back, building nothing,
    /// when the session authenticated another key than `identity`'s, which a
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
        link: Option<LinkNo>,
        caps: &mut LinkCaps<'_>,
    ) -> Result<(Self, Started), IndexLease> {
        // Compute MMP report gating: A sends to B iff A.provides AND B.wants
        let our_neg = NegotiationPayload::fmp(0, 0, our_profile);
        let their_neg = NegotiationPayload::fmp(0, 0, peer_profile);
        let send_sr = our_neg.provides_sr() && their_neg.wants_sr();
        let send_rr = our_neg.provides_rr() && their_neg.wants_rr();

        let key = PeerKey::from_xonly(&identity.pubkey());
        let facts = setup_facts(remote_epoch, std::mem::take(&mut caps.record));
        let setup = Setup {
            done: completed(
                noise_session,
                facts.peer_epoch.unwrap_or_default(),
                their_index,
            ),
            lease: our_index,
            theirs: their_index.as_u32(),
            transport: transport_id,
        };
        let env = fips_core::proto::path::Env {
            facts: caps.path.facts,
            cost: 1.0,
        };
        let params = caps.path.params;
        let addr = *identity.node_addr();
        let (mut rekey, mut bundle) = (None, None);
        let joined = lent(caps, transport_id, their_index, |caps| {
            join(
                addr,
                Event::Start {
                    rekey: &mut rekey,
                    bundle: &mut bundle,
                    key,
                    setup,
                    facts,
                    caps,
                    to: (transport_id, current_addr),
                    params,
                    env: &env,
                    link,
                },
            )
        })?;
        let (out, paths, core) = split(joined);
        debug_assert!(paths.is_empty(), "a new bundle reports nothing");
        let mut send = PeerSendState::new(link_id);
        send.bundle = bundle;
        let mut data = PeerData::new(authenticated_at, peer_now());
        data.link_stats = link_stats;
        data.peer_profile = peer_profile;
        data.send_sr = send_sr;
        data.send_rr = send_rr;
        data.mmp = Some(MmpPeerState::new(
            mmp_config.mode,
            mmp_config.log_interval_secs,
            mmp_config.owd_window_size,
        ));
        let peer = Self {
            npub: identity.npub(),
            short_npub: identity.short_npub(),
            identity,
            rekey,
            data,
            send,
            #[cfg(test)]
            past_feed: false,
        };
        Ok((peer, (out, core)))
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
        _is_initiator: bool,
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
            profile: NodeProfile::Full,
            path: super::test_caps(),
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
        peer.send.bundle = Some(new_bundle(transport_id, current_addr, &caps.path));
        peer.data.mmp = Some(MmpPeerState::new(
            mmp_config.mode,
            mmp_config.log_interval_secs,
            mmp_config.owd_window_size,
        ));
        peer.rekey = Some(rekey);
        peer
    }

    // === Connected-UDP fast path ===

    /// Refcount the active path's `connect()`-ed UDP socket if installed.
    /// Encrypt-worker send path uses this to bypass the wildcard
    /// listen socket's per-packet sockaddr handling.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn connected_udp(
        &self,
    ) -> Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>> {
        self.active_path()
            .and_then(|path| path.driver().connected_udp())
    }

    /// Install a `connect()`-ed UDP socket with its paired recv drain
    /// thread on the active path. The two own each other's lifetime: the
    /// drain is the only consumer of packets on this socket. A no-op on a
    /// peer with no path: there is no address to have connected to.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn set_connected_udp(
        &mut self,
        socket: std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>,
        drain: crate::transport::udp::PeerRecvDrain,
    ) {
        if let Some(slot) = self.active_slot() {
            slot.set_connected_udp(socket, drain);
        }
    }

    /// Clear the active path's connected UDP socket + drain. The drain
    /// exits via self-pipe signal; the kernel fd closes on last `Arc`
    /// drop (any in-flight worker jobs holding the old `Arc` stay
    /// valid until they complete).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(dead_code)] // called from session-deregister + rekey follow-up
    pub(crate) fn clear_connected_udp(&mut self) {
        if let Some(slot) = self.active_slot() {
            slot.clear_connected_udp();
        }
    }

    /// Whether the path at `index` holds a connected socket, active or not.
    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn socket_at(&self, index: usize) -> bool {
        self.send
            .bundle
            .as_ref()
            .and_then(|b| b.paths().get(index))
            .is_some_and(|p| p.driver().connected_udp().is_some())
    }

    /// Seat a connected socket with its recv drain on the path at `index`,
    /// active or not. A no-op where no path is at `index`.
    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn seat_socket(
        &mut self,
        index: usize,
        socket: std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>,
        drain: crate::transport::udp::PeerRecvDrain,
    ) {
        if let Some(slot) = self.send.bundle.as_mut().and_then(|b| b.driver_mut(index)) {
            slot.set_connected_udp(socket, drain);
        }
    }

    /// The driver slot of the path our frames go out on.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn active_slot(&mut self) -> Option<&mut UdpSlot> {
        let bundle = self.send.bundle.as_mut()?;
        let index = bundle.paths().active_index()?;
        bundle.driver_mut(index)
    }

    /// Dispose of a path the path set discarded and handed back: its
    /// connected socket and drain go here, in the shell, drain first as for
    /// the active path, never inside a path rule.
    #[cfg(test)]
    fn retire(path: Option<PeerPath>) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(mut path) = path {
            path.driver_mut().clear_connected_udp();
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        drop(path);
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

    /// The transport this peer's indices are bound on: the active path's,
    /// the one it is reached over. A peer with a session always has one.
    fn bound_transport(&self) -> TransportId {
        self.transport_id().unwrap_or(TransportId::new(0))
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
    /// dial, under this node's `ours` and the peer's `theirs`, at `to`, the
    /// transport and source address of the message that completed that
    /// handshake.
    ///
    /// When both nodes dial each other at once, each completes both an outbound
    /// and an inbound handshake; the smaller node's outbound handshake wins,
    /// and both ends converge on the link it dialled (FRC-2201, Section 5.7).
    /// The smaller node moves to that session when the peer's msg2 completes it
    /// second, the larger node when the peer's msg3 does, and each takes that
    /// message's transport and source address as the peer's: the moved
    /// session's binding is recorded on `to`'s transport, and the peer is held
    /// at `to`, across transports if need be, as the original path of the
    /// renewed path machine. The link's rekey machine is closed, which
    /// abandons its own rekey in flight, ends a responder pending and the drain
    /// of the previous session, and releases every index they held, and a new
    /// one is built on `session` from what the closed one hands back: the moved
    /// session keeps the replaced one's key-epoch bit and start (so its rekey
    /// age and inner-header timestamps carry on), the link's age, the time the
    /// peer was last heard, the key-epoch bit last seen from the peer and the
    /// replay record. `caps` lends the index allocator and keys, the parameters
    /// the new machine is built with and whether a decrypt-worker pool runs, to
    /// which the new session is offered at once; its record is not read.
    ///
    /// `dial` is the link of the handshake whose session the peer moves onto,
    /// `own` says the dial answered was this node's own or a later one
    /// rather than a crossing won on the tie-break, and `inbound` that the
    /// handshake is an inbound leg the peer's msg3 completed rather than this
    /// node's own dial.
    ///
    /// Returns the outputs that unbind, revoke and release what the closed
    /// machine held and bind (and offer) the new session, and the outputs of
    /// the path machine's renewal. Hands `ours` back in a release, leaving the
    /// machine and the peer's pair as they were, when `session` authenticated
    /// another key than the peer's; the path outputs are then empty. The
    /// peer's record is then reset by the transition table's cells for a
    /// move, whether or not the move was refused: the replay suppression
    /// counter and the repeated handshake line counts always, since the
    /// session changed, and, once the link has moved, the link's
    /// counter-derived MMP state, as a cutover does, since the new session's
    /// frame counter starts again at 0. The move starts the path machine
    /// again at `to`, as a new link (multipath v1 draft, Sections 5.2 and
    /// 5.4): a path already held at `to`, active or not, stays with its
    /// connected socket and its count of failed frames, every other path is
    /// released, and when none is held there `to` becomes the new link's
    /// original path ([`PeerBundle::renew`]); `caps.path` gives the facts it
    /// reads.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn move_session(
        &mut self,
        session: NoiseSession,
        ours: IndexLease,
        theirs: SessionIndex,
        to: (TransportId, TransportAddr),
        dial: LinkId,
        own: bool,
        inbound: bool,
        caps: &mut LinkCaps<'_>,
    ) -> (LinkOutputs, Outputs<UdpSlot>) {
        let (out, paths, built) = self.rebuild(session, ours, theirs, to, caps);
        self.settle(&Transition::Move {
            dial,
            own,
            built,
            inbound,
        });
        (out, paths)
    }

    /// The machine part of [`move_session`](Self::move_session), through the
    /// settlement core's join: close the rekey machine, build it again on
    /// `session` from what it carried, and renew the bundle at `to`. Returns
    /// the outputs, the path outputs, and whether the machine was rebuilt;
    /// when it was not, the record is left to the caller.
    fn rebuild(
        &mut self,
        session: NoiseSession,
        ours: IndexLease,
        theirs: SessionIndex,
        to: (TransportId, TransportAddr),
        caps: &mut LinkCaps<'_>,
    ) -> (LinkOutputs, Outputs<UdpSlot>, bool) {
        // The mutation lane's break: the link stays on its old transport and
        // its bundle is not renewed.
        let kept = node_fault!(MoveKeepsOldPair).then(|| self.bound_transport());
        let transport = kept.unwrap_or(to.0);
        // The mutation lane's break: the rebuilt machine does not offer its
        // session to the decrypt workers.
        caps.workers &= !node_fault!(MoveSkipsWorkerOffer);
        // The epoch the closed machine carries; building does not read it.
        let epoch = self.rekey.as_ref().and_then(|r| r.view().peer_epoch);
        let setup = Setup {
            done: completed(session, epoch.unwrap_or_default(), theirs),
            lease: ours,
            theirs: theirs.as_u32(),
            transport,
        };
        let env = fips_core::proto::path::Env {
            facts: caps.path.facts,
            cost: self.live_cost(),
        };
        let addr = *self.identity.node_addr();
        let rekey = &mut self.rekey;
        let bundle = self.send.bundle.as_mut().filter(|_| kept.is_none());
        let joined = lent(caps, transport, theirs, |caps| {
            join(
                addr,
                Event::Shift {
                    rekey,
                    bundle,
                    setup,
                    caps,
                    to,
                    env: &env,
                },
            )
        });
        match joined {
            Ok(joined) => {
                let built = joined.built;
                let (out, paths, core) = split(joined);
                debug_assert!(core.is_empty(), "a move told the core something");
                (out, paths, built)
            }
            Err(lease) => (vec![LinkOutput::Release(lease)], Vec::new(), false),
        }
    }

    /// The transport our frames to this peer go out on: the active path's.
    pub fn transport_id(&self) -> Option<TransportId> {
        self.active_path().map(|path| path.transport_id())
    }

    /// Whether any path of the link, active or not, in any state, is on
    /// `transport_id`.
    pub(crate) fn uses(&self, transport_id: TransportId) -> bool {
        self.send.bundle.as_ref().is_some_and(|b| {
            b.paths()
                .paths()
                .iter()
                .any(|p| p.transport_id() == transport_id)
        })
    }

    /// The address our frames to this peer go to: the active path's.
    pub fn current_addr(&self) -> Option<&TransportAddr> {
        self.active_path().map(|path| path.addr())
    }

    /// Every path this peer is reachable over. The active one is
    /// [`active_path`](Self::active_path).
    // Read by tests until the path switch reads it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn paths(&self) -> &[PeerPath] {
        self.send.bundle.as_ref().map_or(&[], |b| b.paths().paths())
    }

    /// The paths this peer is reachable over, with their identifiers and
    /// state. Panics for a peer not yet bound to a transport.
    #[cfg(test)]
    pub(crate) fn path_set(&self) -> &PathSet {
        self.bundle().expect("the peer is bound").paths()
    }

    /// The path our frames go out on, if the peer has one.
    pub(crate) fn active_path(&self) -> Option<&PeerPath> {
        self.send.bundle.as_ref().and_then(|b| b.paths().active())
    }

    /// The machine of the link's paths, once the peer is bound.
    pub(crate) fn bundle(&self) -> Option<&PeerBundle> {
        self.send.bundle.as_ref()
    }

    /// The machine of the link's paths, to step, once the peer is bound.
    pub(crate) fn bundle_mut(&mut self) -> Option<&mut PeerBundle> {
        self.send.bundle.as_mut()
    }

    /// Close the link's path machine, and return every path's driver slot
    /// to release (draft Section 5.8), for a test that re-points the peer.
    /// The peer then holds no path (test builds only).
    #[cfg(test)]
    pub(crate) fn close_paths(&mut self) -> Outputs<UdpSlot> {
        self.send
            .bundle
            .take()
            .map(PeerBundle::close)
            .unwrap_or_default()
    }

    /// Account for one authentic frame of the link, `len` bytes long with
    /// link message type `msg_type`, received at `now` from (`transport_id`,
    /// `addr`): [`PeerBundle::account`], which attributes it to its path and,
    /// while the link holds one path, roams that path's address inside its
    /// transport, as FMP v1 does. A frame that arrives on a transport the
    /// peer has no path on is still delivered (the demux is by index alone)
    /// but creates nothing and moves nothing: an authentic frame proves the
    /// peer produced it, not that it came from where it claims, so an
    /// on-path relay rewriting the source (a rogue AP, anyone on a shared
    /// L2) could otherwise move the whole send side onto another transport.
    /// A peer with no path at all is bound by its first authentic frame,
    /// and the result then says [`Roam::Bound`].
    ///
    /// [`Roam::changed`] says whether the address our frames go to changed,
    /// so the caller can drop the `connect(2)`-ed UDP socket whose 5-tuple
    /// just went stale, and [`Roam::left`] names the link the peer left, the
    /// only one that loses its verification. A roam of a path that is not
    /// active drops that path's own connected socket here.
    pub(crate) fn account(
        &mut self,
        now: PeerInstant,
        transport_id: TransportId,
        addr: &TransportAddr,
        len: usize,
        msg_type: u8,
    ) -> Account {
        let bound = self.send.bundle.is_none();
        if bound {
            self.bind(transport_id, addr.clone());
        }
        let Some(bundle) = self.send.bundle.as_mut() else {
            unreachable!("the peer was bound above");
        };
        let mut account = bundle.account(now, transport_id, addr, len, msg_type);
        if bound {
            account.roam = Roam::Bound;
        }
        // The frame's accounting tells the core of the roam and puts the
        // flag back; any other caller is a test's, past the feed.
        #[cfg(test)]
        if account.roam != Roam::Unmoved {
            self.past_feed = true;
        }
        // A path that is not active roamed: its socket aims at the old address.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Roam::Standby { index } = account.roam
            && let Some(slot) = bundle.driver_mut(index)
        {
            slot.clear_connected_udp();
        }
        account
    }

    /// The pair of the link's one path while it is not active, which a roam
    /// of that path leaves and [`Roam::Standby`] does not name: read before
    /// [`account`](Self::account), so the roam can be reported whole. One
    /// test per frame, and a copy of the pair only while no path is active.
    pub(crate) fn standby(&self) -> Option<(TransportId, TransportAddr)> {
        let paths = self.send.bundle.as_ref()?.paths();
        if paths.active_index().is_some() || paths.len() != 1 {
            return None;
        }
        paths.get(0).map(|p| (p.transport_id(), p.addr().clone()))
    }

    /// Whether a test changed the link's bundle past the feed of the
    /// settlement core's record of the link (test builds only).
    #[cfg(test)]
    pub(crate) fn past_feed(&self) -> bool {
        self.past_feed
    }

    /// Put back what [`past_feed`](Self::past_feed) read before the frame's
    /// accounting, which tells the core of the roam itself (test builds
    /// only).
    #[cfg(test)]
    pub(crate) fn set_past_feed(&mut self, was: bool) {
        self.past_feed = was;
    }

    /// Bind a peer that holds no path to (`transport_id`, `addr`), its
    /// link's original path, on a path machine built as
    /// [`unbound_caps`](super::unbound_caps) says.
    fn bind(&mut self, transport_id: TransportId, addr: TransportAddr) {
        let caps = super::unbound_caps();
        self.send.bundle = Some(new_bundle(transport_id, addr, &caps));
    }

    /// Account for an authentic heartbeat from (`transport_id`, `addr`), for
    /// tests of the roaming rule: see [`account`](Self::account).
    #[cfg(test)]
    pub fn set_current_addr(&mut self, transport_id: TransportId, addr: TransportAddr) -> Roam {
        let heartbeat = crate::proto::link::LinkMessageType::Heartbeat.to_byte();
        self.account(peer_now(), transport_id, &addr, 0, heartbeat)
            .roam
    }

    /// Ask for the peer's send side to move to `(transport_id, addr)`.
    ///
    /// The deliberate counterpart of [`set_current_addr`](Self::set_current_addr):
    /// that one is the roaming rule and never crosses transports; this one
    /// is a path change. If the peer already holds that path it becomes the
    /// active one, or it is bound if the peer has no path yet. A pair the
    /// peer does not hold is admitted as a new path to be probed, and the
    /// send side stays where it is. No path is re-pointed onto a new
    /// address. `medium` is the kind of `transport_id`. See
    /// [`PathSet::rebind`], past the path machine; for tests.
    #[cfg(test)]
    pub fn rebind_transport(
        &mut self,
        transport_id: TransportId,
        addr: TransportAddr,
        medium: Medium,
    ) -> Rebind {
        self.past_feed = true;
        let Some(bundle) = self.send.bundle.as_mut() else {
            self.bind(transport_id, addr);
            return Rebind::Switched;
        };
        let (result, evicted) = bundle
            .paths_mut()
            .rebind(transport_id, addr, medium, rand::random);
        Self::retire(evicted);
        result
    }

    /// What the path (`transport_id`, `addr`) is to this peer at this end:
    /// [`Match::Proven`] for a held path that is Live or that one of our
    /// probes has had answered (the link's original path is both), with
    /// whether it is the active path, [`Match::Unproven`] for a held path
    /// that is neither, still Probing, and [`Match::None`] when the pair is
    /// not held. The active path answers `Proven { active: true, .. }`, so
    /// that is the test for "this pair is where our frames to the peer go".
    pub(crate) fn path_match(&self, transport_id: TransportId, addr: &TransportAddr) -> Match {
        self.send
            .bundle
            .as_ref()
            .map_or(Match::None, |b| b.paths().classify(transport_id, addr))
    }

    /// The bound peer's path set, to change past the path machine, for
    /// tests of the set's rules.
    #[cfg(test)]
    fn test_paths(&mut self) -> &mut PathSet {
        self.past_feed = true;
        self.send
            .bundle
            .as_mut()
            .expect("the test peer is bound")
            .paths_mut()
    }

    /// Hold (`transport_id`, `addr`) as a new Probing path beside the
    /// peer's others, for tests that need a path not yet acked.
    #[cfg(test)]
    pub(crate) fn admit_path(&mut self, transport_id: TransportId, addr: TransportAddr) {
        let admission = self
            .test_paths()
            .admit(transport_id, addr, Medium::Other, rand::random)
            .expect("the test path is admitted");
        if let super::Admission::Added { evicted, .. } = admission {
            Self::retire(evicted);
        }
    }

    /// Mark the held path (`transport_id`, `addr`) acked, as an answer to
    /// one of our probes on it would, for tests that need a held path ready
    /// to carry the link.
    #[cfg(test)]
    pub(crate) fn ack_path(&mut self, transport_id: TransportId, addr: &TransportAddr) {
        let paths = self.test_paths();
        let index = paths
            .find(transport_id, addr)
            .expect("the test path is held");
        paths.mark_acked(index);
    }

    /// Mark the held path (`transport_id`, `addr`) Dead, as unanswered
    /// probes would, for tests that need a held path given up on.
    #[cfg(test)]
    pub(crate) fn kill_path(&mut self, transport_id: TransportId, addr: &TransportAddr) {
        let paths = self.test_paths();
        let index = paths
            .find(transport_id, addr)
            .expect("the test path is held");
        paths.mark_dead(index, peer_now());
    }

    /// Replace the peer's paths with a single original path on
    /// `(transport_id, addr)`, for tests whose premise is a single-path peer
    /// that has moved to another transport. Production never re-points a
    /// path; the path switch will move a peer between held paths. The new
    /// path machine is built as [`unbound_caps`](super::unbound_caps) says,
    /// multipath disabled, as every caller's node runs.
    #[cfg(test)]
    pub(crate) fn repin(&mut self, transport_id: TransportId, addr: TransportAddr) {
        self.past_feed = true;
        for out in self.close_paths() {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let fips_core::proto::path::Output::Released { mut driver, .. } = out {
                driver.clear_connected_udp();
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            drop(out);
        }
        self.bind(transport_id, addr);
    }

    // === Handshake Resend ===

    /// Store wire-format msg2 for resend on duplicate msg1.
    pub(crate) fn set_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.data.handshake_msg2 = Some(msg2);
    }

    /// Get stored msg2 bytes for resend.
    pub(crate) fn handshake_msg2(&self) -> Option<&[u8]> {
        self.data.handshake_msg2.as_deref()
    }

    // === Replay Detection Suppression ===

    /// Increment replay suppression counter. Returns the new count.
    pub fn increment_replay_suppressed(&mut self) -> u32 {
        self.data.replay_total.fetch_add(1, Ordering::Relaxed);
        self.replay_suppressed_count()
    }

    /// Reset replay suppression counter, returning previous count.
    pub fn reset_replay_suppressed(&mut self) -> u32 {
        let total = self.replay_suppressed_total();
        let count = self.replay_count(total);
        self.data.replay_base = total;
        count
    }

    /// Current replay suppression count: refusals since the last session
    /// reset, on either receive path.
    pub fn replay_suppressed_count(&self) -> u32 {
        self.replay_count(self.replay_suppressed_total())
    }

    /// The count since the last session reset, given the total.
    fn replay_count(&self, total: u64) -> u32 {
        u32::try_from(total.saturating_sub(self.data.replay_base)).unwrap_or(u32::MAX)
    }

    /// The total at the last session reset, which the count is taken from.
    #[cfg(test)]
    pub(crate) fn replay_base(&self) -> u64 {
        self.data.replay_base
    }

    /// Refused replays since this peer was promoted. No session reset clears
    /// the total; a connection that replaces the peer starts a new one.
    pub fn replay_suppressed_total(&self) -> u64 {
        self.data.replay_total.load(Ordering::Relaxed)
    }

    /// The running total, for a decrypt worker to add its refusals to.
    #[cfg(unix)]
    pub(crate) fn replay_total(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.data.replay_total)
    }

    // === Repeated Handshake Lines ===

    /// This peer's repeated handshake line counts.
    #[cfg(test)]
    pub(crate) fn hs_lines(&self) -> &HsLineCounts {
        &self.data.hs_lines
    }

    /// This peer's repeated handshake line counts, to count a line.
    pub(crate) fn hs_lines_mut(&mut self) -> &mut HsLineCounts {
        &mut self.data.hs_lines
    }

    // === Decryption Failure Tracking ===

    /// Count a frame of the link that failed to authenticate, received at
    /// `now` from (`transport_id`, `addr`), on the path of that pair:
    /// [`PeerBundle::charge`], which counts it only on the link's original
    /// path or a path proven by a probe exchange. A peer that holds no path
    /// counts nothing.
    pub(crate) fn charge(
        &mut self,
        now: PeerInstant,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Charge {
        self.send
            .bundle
            .as_mut()
            .map_or(Charge::Nothing, |b| b.charge(now, transport_id, addr))
    }

    /// Start again the count of failures on the path of (`transport_id`,
    /// `addr`), for an authentic frame of the link from there that is not
    /// accounted: [`PeerBundle::authentic`]. A pair no path holds starts no
    /// count again.
    pub(crate) fn authentic(&mut self, transport_id: TransportId, addr: &TransportAddr) {
        if let Some(bundle) = self.send.bundle.as_mut() {
            bundle.authentic(transport_id, addr);
        }
    }

    /// The count of consecutive frames that failed to authenticate on the
    /// path the node sends on, the active path; 0 for a peer that holds no
    /// path. For a link of one path it is the count of its original pair.
    pub fn consecutive_decrypt_failures(&self) -> u32 {
        self.active_path().map_or(0, |p| p.live().fails())
    }

    /// Record the receiver index of a frame that failed to decrypt.
    pub(crate) fn record_failed(&mut self, idx: SessionIndex) {
        self.data.failed_idx = Some(idx);
    }

    /// The receiver index of the last frame that failed to decrypt.
    pub(crate) fn last_failed(&self) -> Option<SessionIndex> {
        self.data.failed_idx
    }

    /// Count one frame authenticated on the previous session.
    pub(crate) fn count_previous(&mut self) {
        self.data.prev_frames = self.data.prev_frames.saturating_add(1);
    }

    /// Frames authenticated on the previous session since the last cutover.
    pub(crate) fn prev_frames(&self) -> u64 {
        self.data.prev_frames
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
        self.data.peer_profile
    }

    /// Whether to send sender reports to this peer.
    pub fn send_sr(&self) -> bool {
        self.data.send_sr
    }

    /// Whether to send receiver reports to this peer.
    pub fn send_rr(&self) -> bool {
        self.data.send_rr
    }

    // === Tree Accessors ===

    /// Get the peer's tree coordinates, if known.
    pub fn coords(&self) -> Option<&TreeCoordinate> {
        self.data.ancestry.as_ref()
    }

    /// Get the peer's parent declaration, if known.
    pub fn declaration(&self) -> Option<&ParentDeclaration> {
        self.data.declaration.as_ref()
    }

    /// Check if this peer has a known tree position.
    pub fn has_tree_position(&self) -> bool {
        self.data.declaration.is_some() && self.data.ancestry.is_some()
    }

    // === Filter Accessors ===

    /// Get the peer's inbound filter, if known.
    pub fn inbound_filter(&self) -> Option<&BloomFilter> {
        self.data.inbound_filter.as_ref()
    }

    /// Get the filter sequence number.
    pub fn filter_sequence(&self) -> u64 {
        self.data.filter_sequence
    }

    /// When the peer's filter was received, in the milliseconds `update_filter`
    /// was given.
    #[cfg(test)]
    pub(crate) fn filter_received_at(&self) -> u64 {
        self.data.filter_received_at
    }

    /// Check if this peer's filter is stale.
    pub fn filter_is_stale(&self, current_time_ms: u64, stale_threshold_ms: u64) -> bool {
        if self.data.filter_received_at == 0 {
            return true;
        }
        current_time_ms.saturating_sub(self.data.filter_received_at) > stale_threshold_ms
    }

    /// Check if a destination might be reachable through this peer.
    pub fn may_reach(&self, node_addr: &NodeAddr) -> bool {
        match &self.data.inbound_filter {
            Some(filter) => filter.contains(node_addr),
            None => false,
        }
    }

    /// Check if we need to send this peer a filter update.
    pub fn needs_filter_update(&self) -> bool {
        self.data.pending_filter_update
    }

    // === Statistics Accessors ===

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        &self.data.link_stats
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.data.link_stats
    }

    // === MMP Accessors ===

    /// Get MMP state (None for legacy peers without sessions).
    pub fn mmp(&self) -> Option<&MmpPeerState> {
        self.data.mmp.as_ref()
    }

    /// Get mutable MMP state.
    pub fn mmp_mut(&mut self) -> Option<&mut MmpPeerState> {
        self.data.mmp.as_mut()
    }

    /// Link cost for routing decisions.
    ///
    /// Returns a scalar cost where lower is better (1.0 = ideal): the
    /// measured cost, [`Self::live_cost`], except across a change of the
    /// link's active path, where the path machine holds the value from
    /// just before the change until the switch dwell has passed and two
    /// receiver reports have arrived. The hold is this node's own choice:
    /// the multipath v1 draft leaves the link cost of a bundle to the node
    /// (Section 5.12, its note). The clock is read only while the machine
    /// holds a cost, which a link of one path never does.
    pub fn link_cost(&self) -> f64 {
        let live = self.live_cost();
        match self.bundle() {
            Some(bundle) if bundle.holding() => bundle.cost(peer_now(), live),
            _ => live,
        }
    }

    /// The link cost as measured now: the
    /// [`quality_index`](crate::proto::mmp::quality_index) of the link's
    /// ETX and smoothed RTT, or 1.0 (optimistic default) when MMP metrics
    /// are not yet available, matching depth-only parent selection
    /// behavior.
    pub(crate) fn live_cost(&self) -> f64 {
        match self.mmp() {
            Some(mmp) => {
                let etx = mmp.metrics.etx;
                match mmp.metrics.srtt_ms() {
                    Some(srtt_ms) => crate::proto::mmp::quality_index(etx, srtt_ms),
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
        self.data.authenticated_at
    }

    /// When an authenticated frame from this peer last arrived, on the peer
    /// clock; the promotion instant before the first.
    pub(crate) fn heard_at(&self) -> PeerInstant {
        self.data.heard_at
    }

    /// When this peer was last seen.
    pub fn last_seen(&self) -> u64 {
        self.data.last_seen
    }

    /// Whether an authenticated frame from this peer has arrived since it was
    /// promoted.
    // Not the record's own `heard`, which is `is_heard` and which a dialled
    // peering sets before any frame arrives.
    #[allow(clippy::misnamed_getters)]
    pub(crate) fn heard(&self) -> bool {
        self.data.frame_heard
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.data.last_seen)
    }

    /// Connection duration since authentication.
    pub fn connection_duration(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.data.authenticated_at)
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
        self.data.last_heartbeat_sent
    }

    /// Record that a heartbeat reached the transport without error.
    ///
    /// Call this *after* the send, and only when it returned cleanly. Marking
    /// before the send makes a failed heartbeat indistinguishable from a
    /// delivered one, which then suppresses the next attempt for a full
    /// `heartbeat_interval_secs` although the peer has heard nothing.
    pub fn mark_heartbeat_sent(&mut self, now: Instant) {
        self.data.last_heartbeat_sent = Some(now);
        self.data.last_heartbeat_attempt = Some(now);
    }

    /// When a heartbeat to this peer was last attempted, whatever came of it.
    pub(crate) fn last_heartbeat_attempt(&self) -> Option<Instant> {
        self.data.last_heartbeat_attempt
    }

    /// Record that a heartbeat send was attempted.
    ///
    /// Call this *before* the send, so an attempt that fails, or one that never
    /// returns, still spaces the next one out.
    pub(crate) fn mark_heartbeat_attempt(&mut self, now: Instant) {
        self.data.last_heartbeat_attempt = Some(now);
    }

    // === State Updates ===

    /// Record an authenticated frame from this peer: refresh the last-seen
    /// time and mark the peer as heard.
    pub fn touch(&mut self, current_time_ms: u64) {
        if !node_fault!(TouchKeepsHeardInstant) {
            self.data.heard_at = peer_now();
        }
        self.data.last_seen = current_time_ms;
        self.data.frame_heard = true;
    }

    /// Step the instant this peer was last heard back by `age`, as for a
    /// peering quiet that long. The wall-clock `last_seen` is not moved.
    #[cfg(test)]
    pub(crate) fn test_backdate_heard(&mut self, age: Duration) {
        self.data.heard_at = fips_core::time::Instant::checked_sub(self.data.heard_at, age)
            .expect("the peer clock reaches back past the backdate");
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
        self.data.declaration = Some(declaration);
        self.data.ancestry = Some(ancestry);
        self.data.last_seen = current_time_ms;
    }

    /// Clear peer's tree position.
    pub fn clear_tree_position(&mut self) {
        self.data.declaration = None;
        self.data.ancestry = None;
    }

    // === Tree Announce Rate Limiting ===

    /// Set the minimum interval between TreeAnnounce messages (milliseconds).
    pub fn set_tree_announce_min_interval_ms(&mut self, ms: u64) {
        self.data.tree_announce_min_interval_ms = ms;
    }

    /// The minimum interval between TreeAnnounce messages (milliseconds).
    #[cfg(test)]
    pub(crate) fn tree_announce_min_interval_ms(&self) -> u64 {
        self.data.tree_announce_min_interval_ms
    }

    /// When this peer was last sent a TreeAnnounce, in the monotonic
    /// milliseconds (`crate::time::mono_ms`) `can_send_tree_announce`
    /// compares; `None` if it never was.
    pub fn last_tree_announce_sent_ms(&self) -> Option<u64> {
        self.data.last_tree_announce_sent_ms
    }

    /// Set when this peer was last sent a TreeAnnounce, in monotonic
    /// milliseconds or `None` for never, leaving a pending one pending.
    pub fn set_last_tree_announce_sent_ms(&mut self, ms: Option<u64>) {
        self.data.last_tree_announce_sent_ms = ms;
    }

    /// Whether the rate limit lets a TreeAnnounce go to this peer at
    /// `now_ms`, a monotonic reading: always for a peer never sent one,
    /// otherwise once the interval has passed since the last.
    pub fn can_send_tree_announce(&self, now_ms: u64) -> bool {
        if node_fault!(TreeNoneAsZero) {
            return now_ms.saturating_sub(self.data.last_tree_announce_sent_ms.unwrap_or(0))
                >= self.data.tree_announce_min_interval_ms;
        }
        self.data
            .last_tree_announce_sent_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= self.data.tree_announce_min_interval_ms)
    }

    /// Record that we sent a TreeAnnounce to this peer at `now_ms`, a
    /// monotonic reading.
    pub fn record_tree_announce_sent(&mut self, now_ms: u64) {
        self.data.last_tree_announce_sent_ms = Some(now_ms);
        self.data.pending_tree_announce = false;
    }

    /// Mark that a tree announce is pending (deferred by the rate limit or by
    /// a failed link send).
    pub fn mark_tree_announce_pending(&mut self) {
        self.data.pending_tree_announce = true;
    }

    /// Check if a deferred tree announce is waiting to be sent.
    pub fn has_pending_tree_announce(&self) -> bool {
        self.data.pending_tree_announce
    }

    // === Filter Updates ===

    /// Update peer's inbound filter.
    pub fn update_filter(&mut self, filter: BloomFilter, sequence: u64, current_time_ms: u64) {
        self.data.inbound_filter = Some(filter);
        self.data.filter_sequence = sequence;
        self.data.filter_received_at = current_time_ms;
        self.data.last_seen = current_time_ms;
    }

    /// Clear peer's inbound filter.
    pub fn clear_filter(&mut self) {
        self.data.inbound_filter = None;
        self.data.filter_sequence = 0;
        self.data.filter_received_at = 0;
    }

    /// Mark that we need to send this peer a filter update.
    pub fn mark_filter_update_needed(&mut self) {
        self.data.pending_filter_update = true;
    }

    /// Clear the pending filter update flag.
    pub fn clear_filter_update_needed(&mut self) {
        self.data.pending_filter_update = false;
    }

    // === Rekey (Key Rotation) ===

    /// When the current Noise session was established; `None` without a
    /// session.
    #[cfg(test)]
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
        self.data.mmp = Some(MmpPeerState::new(
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

    /// Every index this peer's link rekey machine binds, with the transport
    /// recorded at the binding and whether a decrypt worker holds that
    /// session's receive half, for the audit of the node's index map and
    /// worker table against the machine. In test and debug builds only.
    #[cfg(any(test, debug_assertions))]
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

    /// Test-only seam: hold the peer at `profile`, sending it neither report,
    /// as a negotiation with a peer of that profile that wants none would.
    #[cfg(test)]
    pub(crate) fn test_take_profile(&mut self, profile: NodeProfile) {
        self.data.peer_profile = profile;
        self.data.send_sr = false;
        self.data.send_rr = false;
    }

    /// Test-only seam: hand the link's rekey machine `record` as the record of
    /// the setup it was built from, as a machine holding a setup record would.
    /// A no-op for a peer without a session.
    #[cfg(test)]
    pub(crate) fn test_note_setup(&mut self, record: Record) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.note_setup(record);
        }
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

    /// Whether `declared`, the index a peer's rekey msg3 names as the one it
    /// receives the session it replaces on, is this node's index of a
    /// session the link's rekey machine holds: the current one, or the
    /// previous one while the machine still holds it. After a cutover the
    /// peer may not have heard of yet (its msg3 lost, the cutover taken
    /// after the delay), the peer's own rekey still names the session that
    /// is previous here, and the machine settles which completion stands.
    pub(crate) fn declares_own_session(&self, declared: SessionIndex) -> bool {
        [Slot::Current, Slot::Previous]
            .into_iter()
            .any(|slot| self.index(slot) == Some(declared))
    }

    /// Get the pending new session's our_index.
    pub(crate) fn pending_our_index(&self) -> Option<SessionIndex> {
        self.index(Slot::Pending)
    }

    /// Get the pending new session's their_index.
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
    #[cfg(test)]
    pub(crate) fn pending_role(&self) -> Option<Role> {
        match self.rekey.as_ref()?.view().cycle {
            CycleView::PendI(_) => Some(Role::Initiator),
            CycleView::PendR => Some(Role::Responder),
            CycleView::Idle | CycleView::Init => None,
        }
    }

    /// Step this peer's link rekey machine with `input` at `now`, lending
    /// it the node's index allocator `indices`, its keys `local`, its node
    /// profile `profile` and whether a decrypt-worker pool exists, and
    /// return what the node must carry out, front to back. Empty for a peer
    /// without a session. Its index bindings are made on the transport the
    /// peer is reached over now.
    pub(crate) fn step_link(
        &mut self,
        now: PeerInstant,
        input: Input<'_, LinkProfile>,
        indices: &mut crate::utils::index::IndexAllocator,
        local: &fips_core::proto::rekey::NodeKeys,
        profile: NodeProfile,
        workers: bool,
    ) -> LinkOutputs {
        self.step_link_with(now, input, indices, local, profile, workers)
            .0
    }

    /// Step this peer's link rekey machine with a msg2 `bytes` as the reply
    /// to its own rekey, as [`step_link`](Self::step_link) steps it. Also
    /// returns whether the msg2 read but authenticated a key other than the
    /// peer's: the machine refuses that msg2 as it refuses one that does not
    /// read, and the caller counts the two apart.
    pub(crate) fn step_link_reply(
        &mut self,
        now: PeerInstant,
        bytes: &[u8],
        indices: &mut crate::utils::index::IndexAllocator,
        local: &fips_core::proto::rekey::NodeKeys,
        profile: NodeProfile,
        workers: bool,
    ) -> (LinkOutputs, bool) {
        let input = Input::Reply { bytes, route: () };
        let (out, replied) = self.step_link_with(now, input, indices, local, profile, workers);
        let mismatch = replied.is_some()
            && out.iter().any(|o| {
                matches!(
                    o,
                    LinkOutput::Reject(fips_core::proto::rekey::Reason::ReplyUnauthenticated)
                )
            });
        (out, mismatch)
    }

    /// Step the link rekey machine with `input`, returning its outputs and
    /// the key a msg2 read during the call authenticated.
    fn step_link_with(
        &mut self,
        now: PeerInstant,
        input: Input<'_, LinkProfile>,
        indices: &mut crate::utils::index::IndexAllocator,
        local: &fips_core::proto::rekey::NodeKeys,
        profile: NodeProfile,
        workers: bool,
    ) -> (LinkOutputs, Option<PeerKey>) {
        let transport = self.bound_transport();
        let Some(rekey) = self.rekey.as_mut() else {
            return (LinkOutputs::new(), None);
        };
        let local = link_local(rekey, local, profile);
        let mut scratch = Vec::new();
        let out = with_tags(|tags| {
            let mut env = Env {
                indices,
                transport,
                tags,
                workers,
                jitter: &mut ThreadJitter,
                local: &local,
                scratch: &mut scratch,
            };
            rekey.step(now, input, &mut env)
        });
        (out, local.replied())
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
        let local = link_local(rekey, local, NodeProfile::Full);
        let mut scratch = Vec::new();
        with_tags(|tags| {
            let mut env = Env {
                indices,
                transport,
                tags,
                workers: false,
                jitter: &mut ThreadJitter,
                local: &local,
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

    /// Reset what a cutover this node made as `role` resets beside the
    /// machine, by the transition table: the replay suppression and
    /// handshake line counts, the frames counted on the previous session,
    /// and the link MMP counters. The node runs it for each cutover the link
    /// machine reports.
    pub(crate) fn after_cutover(&mut self, role: Role) {
        self.settle(&Transition::Cutover { role });
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

    /// Close the link's machines as the peer is removed, through the
    /// settlement core's join: the path machine, then the rekey machine.
    /// Returns every path's driver slot to release (draft Section 5.8), and
    /// the outputs that unbind, revoke and release every index the rekey
    /// machine held (its sessions' and its own rekey handshake's). A peer
    /// without a session gives empty outputs. The peer then holds no path
    /// and no machine.
    pub(crate) fn stop(&mut self) -> Stopped {
        // The reason only labels an own rekey handshake the machine
        // abandons, which the node counts nowhere.
        let event = Event::Stop {
            rekey: &mut self.rekey,
            bundle: &mut self.send.bundle,
            why: Close::Admin,
        };
        match join(*self.identity.node_addr(), event) {
            Ok(joined) => {
                // The replay record a closed machine carries is not kept:
                // this line files no record for a later link.
                let (out, paths, core) = split(joined);
                debug_assert!(core.is_empty(), "a removal told the core something");
                (paths, out)
            }
            Err(lease) => (Outputs::new(), vec![LinkOutput::Release(lease)]),
        }
    }

    /// Apply `t`'s cells to the peer's record, reading the monotonic clock
    /// once for an MMP reset's jitter grace. The peer's identity, its
    /// machines and the node's state are not the record's, and `t` does not
    /// reach them here.
    pub(crate) fn settle(&mut self, t: &Transition) {
        self.data.settle(t, crate::time::mono_ms());
    }

    /// End the peer's record as the peer is removed, handing over what the
    /// removal reads of it. The peer's identity and machines go with it; a
    /// caller closes the machines and the paths first.
    pub(crate) fn depart(self) -> Departed {
        self.data.depart()
    }
}

#[cfg(test)]
#[path = "tests/active.rs"]
mod tests;
