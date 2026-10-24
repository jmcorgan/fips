//! End-to-end session state.
//!
//! One `SessionEntry` per remote endpoint, from the first message of its
//! Noise XX handshake (SessionSetup, SessionAck, SessionMsg3, carried inside
//! SessionDatagram envelopes through the mesh) to its removal. The entry's
//! rekey machine runs that first handshake, then holds the session's keys
//! and rotates them.

use crate::NodeAddr;
use crate::config::SessionMmpConfig;
use crate::identity::OsEntropy;
use crate::proto::fsp::FspInnerFlags;
use crate::proto::fsp::wire::{
    FSP_FLAG_CP, FSP_FLAG_K, FSP_HEADER_SIZE, FSP_INNER_HEADER_SIZE, build_fsp_header,
    fsp_prepend_inner_header,
};
use crate::proto::mmp::MmpSessionState;
use crate::proto::stp::TreeCoordinate;
use crate::time::WallStamp;
use fips_core::noise::aead::AeadKey;
use fips_core::noise::{MAX_MESSAGE_SIZE, NoiseError, TAG_SIZE};
use fips_core::proto::fsp::rekey::{FspProfile, SessionLocal};
use fips_core::proto::rekey::{
    Config, CycleView, Env, EpochTag, FrameHint, Identity, Input, JitterSource, MAX_AFTER,
    NodeKeys, Output, Outputs, Params, PeerKey, Profile, Reason, Rekey, Role, SealRefusal, Sealed,
    TagSource,
};
use fips_core::time::{Clock, Instant};
use rand::RngExt;
use secp256k1::{PublicKey, XOnlyPublicKey};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// The clock the session table measures its timers on: the host's monotonic
/// clock, so a step of the system clock neither fires nor holds a session
/// timer. Times the control API reports are converted to Unix milliseconds at
/// the edge, through `WallStamp`.
pub(crate) type SessionClock = crate::time::HostClock;

/// An instant on [`SessionClock`].
pub(crate) type SessionInstant = <SessionClock as Clock>::Instant;

/// The rekey machine of one session: its first handshake (this node's own
/// attempt, the peer's setups held as candidates, the retained msg3), then
/// its epochs and their keys, the frame opens, its own rekeys, the setups,
/// acks and msg3s of every rekey, and every cutover, drain and retained msg3.
pub(crate) type SessionRekey = Rekey<FspProfile<OsEntropy>, SessionClock>;

/// What one call to a session's rekey machine asks the shell to do.
pub(crate) type SessionOutputs = Outputs<FspProfile<OsEntropy>>;

/// One thing a session's rekey machine asks the shell to do.
pub(crate) type SessionOutput = Output<FspProfile<OsEntropy>>;

/// The session clock's instant `ms` milliseconds after its test epoch.
#[cfg(test)]
pub(crate) fn session_at(ms: u64) -> SessionInstant {
    crate::time::at::<SessionClock>(ms)
}

/// The startup epoch a test session built by `SessionEntry::keyed` or
/// `keyed_as` records for its peer. A rekey the test's peer writes under
/// any other epoch completes as a restart.
#[cfg(test)]
pub(crate) const TEST_PEER_EPOCH: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44];

/// `ms` milliseconds after `t`, for tests that name an instant relative to
/// another.
#[cfg(test)]
pub(crate) fn session_after(t: SessionInstant, ms: u64) -> SessionInstant {
    t.checked_add(Duration::from_millis(ms))
        .expect("a test instant fits the clock's range")
}

/// Time from `earlier` to `now` in whole milliseconds, zero when `earlier`
/// is the later one.
pub(crate) fn age_ms(now: SessionInstant, earlier: SessionInstant) -> u64 {
    now.saturating_duration_since(earlier).as_millis() as u64
}

// The session machines draw their rekey jitter over the range the deployed
// trigger has always used.
const _: () = assert!(Config::fsp().jitter as i64 == crate::node::REKEY_JITTER_SECS);

/// The epoch tags of every session and link machine in the process, so no
/// tag is reused while the process runs.
static TAGS: Mutex<TagSource> = Mutex::new(TagSource::new());

/// Run `f` with the process's epoch tag source.
pub(crate) fn with_tags<R>(f: impl FnOnce(&mut TagSource) -> R) -> R {
    let mut tags = TAGS.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut tags)
}

/// Rekey jitter drawn from the thread's random generator.
pub(crate) struct ThreadJitter;

impl JitterSource for ThreadJitter {
    /// A value drawn uniformly from `[0, bound]`.
    fn draw(&mut self, bound: u16) -> u16 {
        rand::rng().random_range(0..=bound)
    }
}

/// The parameters a session's rekey machine runs with, from the node's
/// configuration: the rekey thresholds (`node.rekey.after_secs` and
/// `after_messages`) start the machine's own rekeys; the handshake timeout,
/// the tick and the resend count bound the first handshake's setup resends
/// and shape its retained msg3's ladder, the confirmation window and the
/// rekey msg3 ladder; everything else is the session defaults.
///
/// A threshold above what the machine accepts (the configuration idiom for
/// switching that trigger off) is taken as the largest it accepts, which
/// never falls due in practice. A session has no link age, and its machine
/// never reads the IK msg1 eligibility rule the link-age setting serves, so
/// that setting is zero and the time trigger is bounded below only by the
/// jitter, as the configuration's own validation bounds it. A session responder
/// holds no pending epoch, so the pending hold is read only as the cap on
/// the abandon backoff; it is raised above the confirmation window when a
/// long handshake timeout would otherwise put it below, which the machine
/// refuses. Timers the machine still refuses (a tick of zero, or a
/// handshake timeout under the tick plus 3 s) fall back to the session
/// defaults, with a warning the first time.
pub(crate) fn session_params(node: &crate::config::NodeConfig) -> Params {
    static TIMERS_WARNED: AtomicBool = AtomicBool::new(false);
    let base = Config {
        link_age: Duration::ZERO,
        ..Config::fsp()
    };
    let handshake = Duration::from_secs(node.rate_limit.handshake_timeout_secs);
    let check = Duration::from_secs(node.tick_interval_secs);
    let confirm = handshake.saturating_add(check);
    let configured = Config {
        handshake,
        check,
        resends: u8::try_from(node.rate_limit.handshake_max_resends).unwrap_or(u8::MAX),
        hold: base
            .hold
            .max(confirm.saturating_add(Duration::from_secs(1))),
        ..base
    };
    let timers = match Params::new(configured) {
        Ok(_) => configured,
        Err(e) => {
            if !TIMERS_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    error = %e,
                    handshake_timeout_secs = node.rate_limit.handshake_timeout_secs,
                    tick_interval_secs = node.tick_interval_secs,
                    "Session rekey timers use the defaults: the configured handshake timeout and tick do not fit"
                );
            }
            base
        }
    };
    let triggered = Config {
        after: Duration::from_secs(node.rekey.after_secs.min(MAX_AFTER)),
        messages: node.rekey.after_messages.min(base.soft),
        ..timers
    };
    // The configuration's validation refuses an interval at or below the
    // jitter and a message trigger of zero, so only a configuration built
    // without it reaches the fallback.
    Params::new(triggered).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Session rekeys use the default thresholds");
        Params::new(timers).expect("the session defaults are valid")
    })
}

/// Run `f` with the environment a session call borrows: no session
/// indices, no transport, the process's epoch tags, no decrypt workers, the
/// thread's jitter and this node's keys for the call, `local`.
fn with_env<R>(
    local: &SessionLocal,
    f: impl FnOnce(&mut Env<'_, FspProfile<OsEntropy>>) -> R,
) -> R {
    let mut scratch = Vec::new();
    with_tags(|tags| {
        let mut env = Env {
            indices: &mut (),
            transport: (),
            tags,
            workers: false,
            jitter: &mut ThreadJitter,
            local,
            scratch: &mut scratch,
        };
        f(&mut env)
    })
}

/// The machine's form of the static key `key`: its X coordinate.
fn peer_key(key: &PublicKey) -> PeerKey {
    PeerKey::from_xonly(&key.x_only_public_key().0)
}

/// The rekey machine of a session whose first handshake with the peer
/// whose static key is `remote` completed at `now` with `session`, the peer
/// in startup epoch `peer_epoch`, for a test that needs a session without
/// running its handshake. `local` and `me` are this node's keys and
/// address, and `params` the machine's parameters.
#[cfg(test)]
pub(crate) fn keyed(
    params: Params,
    local: &NodeKeys,
    me: NodeAddr,
    remote: &PublicKey,
    session: crate::noise::NoiseSession,
    peer_epoch: [u8; 8],
    now: SessionInstant,
) -> SessionRekey {
    use fips_core::proto::fsp::rekey::SessionKeys;
    use fips_core::proto::rekey::{Bond, Completed, Ids, Record, SetupFacts};
    let bond = Bond::Key(peer_key(remote));
    let done = Completed::<FspProfile<OsEntropy>> {
        session: Box::new(SessionKeys::new(session)),
        remote: PeerKey::from_xonly(&remote.x_only_public_key().0),
        epoch: peer_epoch,
        theirs: None,
    };
    let first = bond
        .check(done)
        .expect("a test session bonds to the key it authenticated");
    let facts = SetupFacts {
        peer_epoch: Some(peer_epoch),
        k: false,
        link_since: now,
        started: now,
        peer_k: None,
        record: Record::new(),
    };
    // An unindexed profile with no decrypt workers makes no binding and no
    // delegation, so there are no outputs to execute.
    let local = SessionLocal::for_call(local, false);
    let (machine, _) = with_env(&local, |env| {
        SessionRekey::established(params, bond, me, first, Ids::unindexed(()), facts, now, env)
    });
    machine
}

/// Why a frame could not be sealed under a session.
#[derive(Debug)]
pub(crate) enum SealFailure {
    /// The session has no established keys.
    NotEstablished,
    /// The keys refused: the frame is too large, or the send counter is
    /// spent.
    Noise(NoiseError),
}

/// One session message sealed under the current epoch, with the header
/// fields and inner-header timestamp that epoch fixed.
pub(crate) struct SealedFrame {
    /// The counter the message was sealed on.
    pub(crate) counter: u64,
    /// The inner-header timestamp, counted from the epoch's base.
    pub(crate) timestamp: u32,
    /// The 12-byte FSP header, the associated data of the seal.
    pub(crate) header: [u8; FSP_HEADER_SIZE],
    /// The sealed inner header and body.
    pub(crate) ciphertext: Vec<u8>,
}

/// A prompt the session's rekey machine asked for, sealed: a CoordsWarmup
/// under the epoch the machine named, with the coordinates of the peer's
/// own handshake message for when the shell has none cached.
pub(crate) struct PromptFrame {
    /// The counter the prompt was sealed on.
    pub(crate) counter: u64,
    /// The inner-header timestamp, counted from the epoch's base.
    pub(crate) timestamp: u32,
    /// The 12-byte FSP header, with the coordinates flag set.
    pub(crate) header: [u8; FSP_HEADER_SIZE],
    /// The sealed inner header.
    pub(crate) ciphertext: Vec<u8>,
    /// The coordinates the peer's handshake message carried, if any.
    pub(crate) route: Option<TreeCoordinate>,
    /// The prompt was sealed under the epoch session MMP measures.
    pub(crate) measured: bool,
}

/// One session message built under the current epoch for a sender that
/// seals it off this task: the reserved counter, a copy of the send key,
/// the header and the plaintext to seal, each fixed by that epoch.
pub(crate) struct ReservedFrame {
    /// The counter reserved for the message.
    pub(crate) counter: u64,
    /// The send key to seal it with.
    pub(crate) key: AeadKey,
    /// The inner-header timestamp, counted from the epoch's base.
    pub(crate) timestamp: u32,
    /// The 12-byte FSP header, the associated data of the seal.
    pub(crate) header: [u8; FSP_HEADER_SIZE],
    /// The inner header and body to seal.
    pub(crate) plaintext: Vec<u8>,
}

/// Most candidates one session's machine holds: setups naming its address
/// that it answered and whose msg3 has not arrived. The half-open share of
/// the session table counts an opening session's candidates one by one,
/// and below this many times the share in entries it cannot be reached.
pub(crate) const MAX_CANDIDATES: usize = <FspProfile<OsEntropy> as Profile>::CANDIDATES;

/// A single end-to-end session with a remote node.
///
/// Its rekey machine runs the first handshake and, once a completion bonds
/// the peer, holds the session's keys: who the peer is known to be, whether
/// the session is established and every handshake state are the machine's,
/// read through its view. `Established` sessions are the larger kind of
/// entry: the machine boxes each epoch's keys itself, and boxing the machine
/// too would add an allocation per session and a second indirection on
/// every seal and open.
pub(crate) struct SessionEntry {
    /// Remote node's address (session table key).
    #[allow(dead_code)]
    remote_addr: NodeAddr,
    /// The session's rekey machine.
    machine: SessionRekey,
    /// When the session was created, or this node last opened it.
    created_at: SessionInstant,
    /// Last application data activity timestamp.
    /// Only updated for DataPacket send/receive and session establishment.
    /// MMP reports do not update this field. Used for idle session timeout.
    last_activity: SessionInstant,
    /// Remaining data packets that should include COORDS_PRESENT.
    /// Initialized from config when session becomes Established;
    /// reset on CoordsRequired receipt.
    coords_warmup_remaining: u8,
    /// Whether this node was the initiator of the handshake that
    /// established the session.
    initiator: bool,
    /// Largest on-the-wire frame this node has sent toward the remote since
    /// the last accepted path-MTU decrease or release, in bytes.
    ///
    /// Corroborates a reactive `MtuExceeded`, which is unauthenticated: an
    /// honest report exists only because a frame this node emitted did not
    /// fit some hop, so an honest report always names a value below this.
    /// Reset on each accepted decrease and on release so one historical
    /// large send cannot vouch for a session's whole lifetime.
    max_sent_wire_len: u16,
    /// Session-layer MMP state. Initialized on Established transition.
    mmp: Option<MmpSessionState>,
    /// The epoch whose frames the MMP receiver measures: the current one, from the moment MMP starts and again at each cutover.
    /// A frame or report authenticated under any other epoch is not
    /// recorded, since its counters and timestamps belong to that epoch.
    mmp_epoch: Option<EpochTag>,

    // === Traffic Counters ===
    /// Total data packets sent on this session.
    packets_sent: u64,
    /// Total data packets received on this session.
    packets_recv: u64,
    /// Total data bytes sent on this session (FSP payload).
    bytes_sent: u64,
    /// Total data bytes received on this session (FSP payload).
    bytes_recv: u64,
    /// SessionSetup copies of this node's first-handshake attempt sent so
    /// far, for the control socket's resend count.
    setups_sent: u32,
    /// The key this node opened the session toward, if it opened one. Names
    /// the peer before a completion has proven its key.
    opened_key: Option<XOnlyPublicKey>,
}

impl SessionEntry {
    /// An entry for `remote_addr` around `machine`, created at `now`.
    fn new(remote_addr: NodeAddr, machine: SessionRekey, now: SessionInstant) -> Self {
        Self {
            remote_addr,
            machine,
            created_at: now,
            last_activity: now,
            coords_warmup_remaining: 0,
            initiator: false,
            max_sent_wire_len: 0,
            mmp: None,
            mmp_epoch: None,
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            setups_sent: 0,
            opened_key: None,
        }
    }

    /// A session this node opens at `now` toward `remote_addr`, whose
    /// static key is `peer`: the machine starts this node's first attempt at
    /// once, and the outputs carry its setup. `local`, `me` and `params` are
    /// this node's keys, its address and the machine's parameters.
    pub(crate) fn opened(
        remote_addr: NodeAddr,
        peer: &PublicKey,
        params: Params,
        local: &NodeKeys,
        me: NodeAddr,
        now: SessionInstant,
    ) -> (Self, SessionOutputs) {
        let opened_key = peer.x_only_public_key().0;
        let peer = peer_key(peer);
        let local = SessionLocal::for_call(local, true);
        let (machine, out) = with_env(&local, |env| {
            SessionRekey::opening_outbound(params, peer, me, now, (), env)
        });
        let mut entry = Self::new(remote_addr, machine, now);
        entry.opened_key = Some(opened_key);
        (entry, out)
    }

    /// A session opened at `now` by a setup whose Noise msg1 `msg1` claims
    /// the address `claimed`, arriving over the link peer `carrier` with the
    /// initiator's coordinates `route`: the machine holds it as a candidate
    /// and asks for its SessionAck, or refuses it, which the outputs then
    /// end with a teardown. Nothing the setup says is proven; the peer is
    /// only `claimed` until a msg3 completes the candidate.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn answering(
        claimed: NodeAddr,
        msg1: &[u8],
        carrier: NodeAddr,
        route: TreeCoordinate,
        params: Params,
        local: &NodeKeys,
        me: NodeAddr,
        now: SessionInstant,
    ) -> (Self, SessionOutputs) {
        let setup = Input::Setup {
            msg1,
            carrier,
            route,
            only: (),
        };
        let local = SessionLocal::for_call(local, true);
        let (machine, out) = with_env(&local, |env| {
            SessionRekey::opening_inbound(params, claimed, me, now, setup, (), env)
        });
        (Self::new(claimed, machine, now), out)
    }

    /// Start this node's own first attempt at `now` toward the peer whose
    /// static key is `peer`, in a session the peer's setups opened. Every
    /// candidate is kept, so the first handshake to complete decides the
    /// session, and the entry dates from now, as a session this node opened
    /// would.
    pub(crate) fn open(
        &mut self,
        peer: &PublicKey,
        now: SessionInstant,
        local: &NodeKeys,
    ) -> SessionOutputs {
        self.opened_key = Some(peer.x_only_public_key().0);
        let input = Input::Open {
            peer: peer_key(peer),
            only: (),
        };
        let out = self.step(now, input, local);
        if self.is_initiating() {
            self.created_at = now;
            self.last_activity = now;
            self.setups_sent = 0;
        }
        out
    }

    /// Who the peer is known to be: the static key a completion
    /// authenticated, or until then only the address the session is for.
    pub(crate) fn identity(&self) -> Identity {
        self.machine.view().identity
    }

    /// The peer's static key, once a completion has authenticated it.
    pub(crate) fn peer_key(&self) -> Option<XOnlyPublicKey> {
        match self.identity() {
            Identity::Proven(key) => XOnlyPublicKey::from_byte_array(key.bytes()).ok(),
            Identity::Claimed(_) => None,
        }
    }

    /// The peer's static key as far as this node knows it: proven by a
    /// completion, or else the key this node opened the session toward.
    pub(crate) fn key(&self) -> Option<XOnlyPublicKey> {
        self.peer_key().or(self.opened_key)
    }

    /// What the control socket reports of who the peer is: `proven` once a
    /// completion has authenticated its key, `unproven` until then, whether
    /// a setup claiming the address or this node's own dial opened it.
    pub(crate) fn identity_status(&self) -> &'static str {
        match self.identity() {
            Identity::Proven(_) => "proven",
            Identity::Claimed(_) => "unproven",
        }
    }

    /// Update the last application data activity timestamp.
    ///
    /// Only call for DataPacket send/receive and session establishment,
    /// not for MMP reports. Used by the idle session timeout.
    pub(crate) fn touch(&mut self, now: SessionInstant) {
        self.last_activity = now;
    }

    /// Check if the session is established: a first handshake completed.
    pub(crate) fn is_established(&self) -> bool {
        self.machine.view().current.is_some()
    }

    /// Whether this node's own first-handshake attempt is in flight.
    pub(crate) fn is_initiating(&self) -> bool {
        let view = self.machine.view();
        view.current.is_none() && view.cycle == CycleView::Init
    }

    /// Whether the first handshake is open with only the peer's setups
    /// held, awaiting a msg3, and no attempt of this node's.
    pub(crate) fn is_awaiting_msg3(&self) -> bool {
        let view = self.machine.view();
        view.current.is_none() && view.cycle != CycleView::Init
    }

    /// How many setups the machine holds as candidates, first-handshake or
    /// rekey, awaiting their msg3.
    pub(crate) fn candidate_count(&self) -> usize {
        self.machine.view().candidates
    }

    /// How much of the half-open share this entry takes: one per candidate
    /// while the first handshake is open, since each was opened by a setup
    /// nobody has proven. An established session's candidates are bounded
    /// by the session itself.
    pub(crate) fn half_open_count(&self) -> usize {
        if self.is_established() {
            0
        } else {
            self.candidate_count()
        }
    }

    /// Whether a setup with Noise msg1 `msg1` arriving over `carrier` at
    /// `now` would be held as a new candidate beside the others, rather than
    /// answered from a held one, refused, or put in an evicted one's place.
    pub(crate) fn grows(&self, now: SessionInstant, msg1: &[u8], carrier: NodeAddr) -> bool {
        self.machine.grows(now, msg1, carrier)
    }

    /// Whether a deadline or start instant of the machine is at or before
    /// `now`, so that a poll at `now` has something to do.
    pub(crate) fn wake_due(&self, now: SessionInstant) -> bool {
        self.machine.next_wake().is_some_and(|w| w <= now)
    }

    /// Settle the entry's own state when its first handshake has just
    /// completed at `now`: which end started the handshake that completed,
    /// `warmup` coordinate-carrying packets, session MMP from `mmp`, and the
    /// idle timer.
    pub(crate) fn establish(&mut self, warmup: u8, mmp: &SessionMmpConfig, now: SessionInstant) {
        self.initiator = self
            .machine
            .view()
            .current
            .is_some_and(|cur| cur.role == Role::Initiator);
        self.coords_warmup_remaining = warmup;
        self.init_mmp(mmp);
        self.touch(now);
    }

    /// Count a SessionSetup copy of this node's first attempt sent.
    pub(crate) fn note_setup_sent(&mut self) {
        self.setups_sent = self.setups_sent.saturating_add(1);
    }

    /// How many times this node resent its first attempt's SessionSetup.
    pub(crate) fn resend_count(&self) -> u32 {
        self.setups_sent.saturating_sub(1)
    }

    /// Get creation time. Used as the probe's session-identity check: an
    /// entry with a different creation stamp is a replacement, not ours.
    pub(crate) fn created_at(&self) -> SessionInstant {
        self.created_at
    }

    /// Get last activity time.
    pub(crate) fn last_activity(&self) -> SessionInstant {
        self.last_activity
    }

    /// Remaining DataPackets that should include COORDS_PRESENT.
    pub(crate) fn coords_warmup_remaining(&self) -> u8 {
        self.coords_warmup_remaining
    }

    /// Set the coords warmup counter (used on Established transition
    /// and CoordsRequired reset).
    pub(crate) fn set_coords_warmup_remaining(&mut self, value: u8) {
        self.coords_warmup_remaining = value;
    }

    /// Largest wire frame sent toward the remote since the last accepted
    /// path-MTU decrease or release.
    pub(crate) fn max_sent_wire_len(&self) -> u16 {
        self.max_sent_wire_len
    }

    /// Note a frame of `wire_len` bytes sent toward the remote, keeping the
    /// largest. Frames beyond `u16::MAX` saturate, which only ever makes the
    /// corroboration more permissive and cannot exceed what a path MTU can
    /// name.
    pub(crate) fn record_sent_wire_len(&mut self, wire_len: usize) {
        let wire_len = u16::try_from(wire_len).unwrap_or(u16::MAX);
        self.max_sent_wire_len = self.max_sent_wire_len.max(wire_len);
    }

    /// Forget what has been sent, so the next reactive report needs fresh
    /// evidence of its own.
    pub(crate) fn clear_sent_wire_len(&mut self) {
        self.max_sent_wire_len = 0;
    }

    /// Compute a session-relative timestamp for the FSP inner header.
    ///
    /// Returns the milliseconds from the current epoch's timestamp base to
    /// `now` truncated to u32, or 0 when `now` reads before it. Wraps
    /// naturally at ~49.7 days, which is fine for relative timing. Before
    /// the session is established it is `now`'s Unix milliseconds truncated
    /// the same way, as when an unset start read as zero.
    pub(crate) fn session_timestamp(&self, now: SessionInstant) -> u32 {
        let base = self
            .keys()
            .and_then(|keys| keys.view().current.and_then(|cur| cur.base));
        match base {
            Some(start) => age_ms(now, start) as u32,
            None => now.wall_ms() as u32,
        }
    }

    /// Whether this node initiated the session: of an established session,
    /// whether it started the handshake that established it; while the
    /// first handshake is open, whether its own attempt is in flight.
    pub(crate) fn is_initiator(&self) -> bool {
        if self.is_established() {
            self.initiator
        } else {
            self.is_initiating()
        }
    }

    /// Get a reference to the session-layer MMP state, if initialized.
    pub(crate) fn mmp(&self) -> Option<&MmpSessionState> {
        self.mmp.as_ref()
    }

    /// Get a mutable reference to the session-layer MMP state, if initialized.
    pub(crate) fn mmp_mut(&mut self) -> Option<&mut MmpSessionState> {
        self.mmp.as_mut()
    }

    /// Initialize session-layer MMP state (called on Established transition),
    /// measuring the current epoch.
    pub(crate) fn init_mmp(&mut self, config: &SessionMmpConfig) {
        self.mmp = Some(MmpSessionState::new(
            config.mode,
            config.log_interval_secs,
            config.owd_window_size,
        ));
        self.mmp_epoch = self.current_tag();
    }

    /// The session-layer MMP state, if it measures the epoch `tag`. A frame
    /// or report authenticated under another epoch, the one a cutover
    /// retired, gets `None` and is not recorded.
    pub(crate) fn epoch_mmp(&mut self, tag: EpochTag) -> Option<&mut MmpSessionState> {
        if self.mmp_epoch != Some(tag) {
            return None;
        }
        self.mmp.as_mut()
    }

    /// The current epoch's tag, once the session is established.
    pub(crate) fn current_tag(&self) -> Option<EpochTag> {
        self.machine.view().current.map(|cur| cur.tag)
    }

    // === Traffic Counters ===

    /// Record a sent data packet.
    pub(crate) fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received data packet.
    pub(crate) fn record_recv(&mut self, bytes: usize) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
    }

    /// Get traffic counters: (packets_sent, packets_recv, bytes_sent, bytes_recv).
    pub(crate) fn traffic_counters(&self) -> (u64, u64, u64, u64) {
        (
            self.packets_sent,
            self.packets_recv,
            self.bytes_sent,
            self.bytes_recv,
        )
    }

    // === Rekey (Key Rotation) ===

    /// The rekey machine, once the session is established.
    fn keys(&self) -> Option<&SessionRekey> {
        self.is_established().then_some(&self.machine)
    }

    /// The rekey machine, mutably, once the session is established.
    fn keys_mut(&mut self) -> Option<&mut SessionRekey> {
        if self.is_established() {
            Some(&mut self.machine)
        } else {
            None
        }
    }

    /// Current K-bit epoch value.
    pub(crate) fn current_k_bit(&self) -> bool {
        self.keys()
            .and_then(|keys| keys.view().current.map(|cur| cur.k))
            .unwrap_or(false)
    }

    /// Whether a completed rekey session waits for its cutover.
    pub(crate) fn has_pending(&self) -> bool {
        self.keys()
            .is_some_and(|keys| keys.view().pending.is_some())
    }

    /// When the current epoch started (for the rekey timer): the session's
    /// establishment or its last cutover. `None` before it is established.
    pub(crate) fn session_start(&self) -> Option<SessionInstant> {
        self.keys()
            .and_then(|keys| keys.view().current.map(|cur| cur.started))
    }

    /// Frames sealed under the current epoch so far; zero before the
    /// session is established.
    #[cfg(test)]
    pub(crate) fn send_counter(&self) -> u64 {
        self.keys().map_or(0, SessionRekey::sent)
    }

    /// Per-session symmetric rekey-timer jitter offset (seconds).
    ///
    /// Drawn when the session is established and at each rekey cutover;
    /// uniform over `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`. Callers add
    /// this to the configured `node.rekey.after_secs` to obtain the
    /// effective trigger interval for this session. Zero before the session
    /// is established.
    #[cfg(test)]
    pub(crate) fn rekey_jitter_secs(&self) -> i64 {
        self.keys().map_or(0, |keys| i64::from(keys.jitter_secs()))
    }

    /// Seal one session message of `msg_type` carrying `body` under the
    /// current epoch at `now`. The epoch fixes everything about it but the
    /// message: the key and counter, the header's key-epoch bit (whatever
    /// `flags` says of it) and the inner-header timestamp, counted from its
    /// base. `flags` gives the header's other bits.
    ///
    /// A message too large for one frame is refused before a counter is
    /// reserved, so the refusal costs no counter.
    pub(crate) fn seal_frame(
        &mut self,
        now: SessionInstant,
        flags: u8,
        msg_type: u8,
        body: &[u8],
    ) -> Result<SealedFrame, SealFailure> {
        let keys = self.keys_mut().ok_or(SealFailure::NotEstablished)?;
        let size = FSP_INNER_HEADER_SIZE + body.len();
        if size > MAX_MESSAGE_SIZE - TAG_SIZE {
            return Err(SealFailure::Noise(NoiseError::MessageTooLarge {
                size,
                max: MAX_MESSAGE_SIZE - TAG_SIZE,
            }));
        }
        let sealed = keys.seal(now).map_err(seal_refusal)?;
        let (timestamp, header, plaintext) = self.frame(&sealed, flags, msg_type, body);
        let ciphertext =
            fips_core::noise::seal(sealed.key.key(), sealed.counter, &header, &plaintext)
                .map_err(SealFailure::Noise)?;
        Ok(SealedFrame {
            counter: sealed.counter,
            timestamp,
            header,
            ciphertext,
        })
    }

    /// Build one session message of `msg_type` carrying `body` under the
    /// current epoch at `now`, as [`SessionEntry::seal_frame`] does, but
    /// leave the seal to a sender off this task: the counter is reserved
    /// and a copy of the send key handed over. `None` when the keys hand
    /// out no copy.
    pub(crate) fn reserve_send(
        &mut self,
        now: SessionInstant,
        flags: u8,
        msg_type: u8,
        body: &[u8],
    ) -> Result<Option<ReservedFrame>, SealFailure> {
        let keys = self.keys_mut().ok_or(SealFailure::NotEstablished)?;
        let sealed = keys.seal(now).map_err(seal_refusal)?;
        let Some(key) = sealed.key.key().cloned() else {
            return Ok(None);
        };
        let (timestamp, header, plaintext) = self.frame(&sealed, flags, msg_type, body);
        Ok(Some(ReservedFrame {
            counter: sealed.counter,
            key,
            timestamp,
            header,
            plaintext,
        }))
    }

    /// The inner-header timestamp, the header and the plaintext of one
    /// message sealed as `sealed`: every field an epoch fixes is taken from
    /// the epoch `sealed` names, so no send path can mix one epoch's key
    /// with another's key-epoch bit or timestamp base.
    fn frame<S>(
        &self,
        sealed: &Sealed<S>,
        flags: u8,
        msg_type: u8,
        body: &[u8],
    ) -> (u32, [u8; FSP_HEADER_SIZE], Vec<u8>) {
        let timestamp = sealed.elapsed.as_millis() as u32;
        let inner_flags = FspInnerFlags::new().to_byte();
        let plaintext = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, body);
        let k = if sealed.k { FSP_FLAG_K } else { 0 };
        let flags = (flags & !FSP_FLAG_K) | k;
        let header = build_fsp_header(sealed.counter, flags, plaintext.len() as u16);
        (timestamp, header, plaintext)
    }

    /// Take a SessionSetup's Noise msg1 `msg1` through the machine at `now`:
    /// it arrived over the link peer `carrier` carrying the initiator's
    /// coordinates `route`. The machine answers it from a held candidate,
    /// refuses it, or holds it as a new candidate and asks for its
    /// SessionAck; nothing else changes, since a setup authenticates nothing.
    pub(crate) fn step_setup(
        &mut self,
        msg1: &[u8],
        carrier: NodeAddr,
        route: TreeCoordinate,
        now: SessionInstant,
        local: &NodeKeys,
    ) -> SessionOutputs {
        let input = Input::Setup {
            msg1,
            carrier,
            route,
            only: (),
        };
        self.step(now, input, local)
    }

    /// Take a SessionAck's Noise msg2 `bytes`, which carried the
    /// responder's coordinates `route`, through the machine at `now` as the
    /// reply to its own attempt, first handshake or rekey. Also returns
    /// whether the ack read but authenticated a key the session is not
    /// bonded to: the machine refuses that ack as it refuses one that does
    /// not read, and the caller counts the two apart.
    pub(crate) fn step_reply(
        &mut self,
        bytes: &[u8],
        route: TreeCoordinate,
        now: SessionInstant,
        local: &NodeKeys,
    ) -> (SessionOutputs, bool) {
        let local = self.local(local);
        let out = self.step_with(now, Input::Reply { bytes, route }, &local);
        let mismatch = local.replied().is_some()
            && out
                .iter()
                .any(|o| matches!(o, Output::Reject(Reason::ReplyUnauthenticated)));
        (out, mismatch)
    }

    /// Take a SessionMsg3's Noise msg3 `bytes` through the machine at `now`,
    /// which tries it against every candidate it holds.
    pub(crate) fn step_final(
        &mut self,
        bytes: &[u8],
        now: SessionInstant,
        local: &NodeKeys,
    ) -> SessionOutputs {
        self.step(now, Input::Final { bytes, only: () }, local)
    }

    /// This node's keys `keys` for one call into the machine, marked as the
    /// session's first handshake while the machine holds no epoch.
    fn local(&self, keys: &NodeKeys) -> SessionLocal {
        SessionLocal::for_call(keys, self.machine.view().current.is_none())
    }

    /// Step the machine with `input` at `now`, then follow its current
    /// epoch with the session MMP.
    fn step(
        &mut self,
        now: SessionInstant,
        input: Input<'_, FspProfile<OsEntropy>>,
        local: &NodeKeys,
    ) -> SessionOutputs {
        let local = self.local(local);
        self.step_with(now, input, &local)
    }

    /// Step the machine with `input` at `now` under the call's keys
    /// `local`, then follow its current epoch with the session MMP.
    fn step_with(
        &mut self,
        now: SessionInstant,
        input: Input<'_, FspProfile<OsEntropy>>,
        local: &SessionLocal,
    ) -> SessionOutputs {
        let machine = &mut self.machine;
        let out = with_env(local, |env| machine.step(now, input, env));
        self.follow_epoch();
        out
    }

    /// Tell the machine an application Data message was sealed at `now`,
    /// which arms its silence trigger until the peer is next heard under
    /// the current keys. The row emits nothing, so there are no outputs to
    /// run.
    pub(crate) fn data_sent(&mut self, now: SessionInstant, local: &NodeKeys) {
        let out = self.step(now, Input::DataSent { only: () }, local);
        debug_assert!(out.is_empty(), "a sealed data message asks for nothing");
    }

    /// Whether the machine has a rekey of its own in flight: an attempt
    /// still waiting for its SessionAck.
    #[cfg(test)]
    pub(crate) fn rekey_attempt(&self) -> bool {
        self.keys()
            .is_some_and(|keys| keys.view().cycle == fips_core::proto::rekey::CycleView::Init)
    }

    /// Open the encrypted FSP message `frame` through the machine at `now`:
    /// it tries every held epoch on the unmodified frame (the pending one
    /// first when the frame's key-epoch bit `k` differs from the current
    /// epoch's), runs the row of the epoch that authenticated it, and
    /// delivers the plaintext into `frame` at the range a `Deliver` output
    /// names. The ciphertext starts at `body`; the first 12 bytes are the
    /// associated data. Refused while the first handshake is open.
    pub(crate) fn step_frame(
        &mut self,
        frame: &mut [u8],
        body: usize,
        counter: u64,
        k: bool,
        now: SessionInstant,
        local: &NodeKeys,
    ) -> SessionOutputs {
        let hint = FrameHint {
            counter,
            k,
            index: 0,
            body,
        };
        self.step(now, Input::Frame { buf: frame, hint }, local)
    }

    /// Poll the machine at `now`: its setup resends, probes, retained msg3,
    /// prompt repeats, confirmation deadline, drain end, candidate expiries,
    /// the deadline of its own attempt, and its trigger, which starts a
    /// rekey. `reachable` is whether a next hop toward the peer exists,
    /// without which no rekey starts; the session MMP's smoothed round trip
    /// is handed in first, since it widens the probe grace and a rekey
    /// setup's first resend interval.
    pub(crate) fn poll_rekey(
        &mut self,
        now: SessionInstant,
        reachable: bool,
        local: &NodeKeys,
    ) -> SessionOutputs {
        let srtt = self
            .mmp
            .as_ref()
            .and_then(|m| m.metrics.srtt_ms())
            .map(|ms| Duration::from_micros((ms * 1000.0) as u64));
        let local = self.local(local);
        let m = &mut self.machine;
        let out = with_env(&local, |env| {
            let path = Input::PathFacts {
                reachable,
                srtt,
                only: (),
            };
            let mut out = m.step(now, path, env);
            out.extend(m.step(now, Input::Poll, env));
            out
        });
        self.follow_epoch();
        out
    }

    /// Seal the prompt the machine asked for under the epoch `tag` at `now`:
    /// a CoordsWarmup whose inner header the machine built, under that
    /// epoch's key, counter and key-epoch bit, with the coordinates flag set
    /// for the coordinates the sender adds.
    pub(crate) fn seal_prompt(
        &mut self,
        now: SessionInstant,
        tag: EpochTag,
    ) -> Result<PromptFrame, SealFailure> {
        let measured = self.mmp_epoch == Some(tag);
        let keys = self.keys_mut().ok_or(SealFailure::NotEstablished)?;
        let prompt = keys.seal_prompt(now, tag).map_err(seal_refusal)?;
        let sealed = prompt.sealed;
        let k = if sealed.k { FSP_FLAG_K } else { 0 };
        let header = build_fsp_header(
            sealed.counter,
            FSP_FLAG_CP | k,
            prompt.plaintext.len() as u16,
        );
        let ciphertext =
            fips_core::noise::seal(sealed.key.key(), sealed.counter, &header, &prompt.plaintext)
                .map_err(SealFailure::Noise)?;
        Ok(PromptFrame {
            counter: sealed.counter,
            timestamp: sealed.elapsed.as_millis() as u32,
            header,
            ciphertext,
            route: prompt.route,
            measured,
        })
    }

    /// Restart the session MMP receiver when the machine's current epoch has
    /// changed (a cutover, or a return to the drained
    /// epoch), so they measure the current epoch alone.
    fn follow_epoch(&mut self) {
        let tag = self.current_tag();
        if tag == self.mmp_epoch {
            return;
        }
        if let Some(mmp) = &mut self.mmp {
            mmp.reset_for_rekey(crate::time::mono_ms());
        }
        self.mmp_epoch = tag;
    }

    /// Whether the previous epoch is still held after a cutover.
    pub(crate) fn is_draining(&self) -> bool {
        self.keys()
            .is_some_and(|keys| keys.view().previous.is_some())
    }

    // === Test-only helpers ===

    /// Stop the machine's time and message triggers from starting another
    /// rekey of its own for the rest of a test.
    #[cfg(test)]
    pub(crate) fn quiet_rekeys(&mut self) {
        if let Some(keys) = self.keys_mut() {
            keys.quiet();
        }
    }

    /// The current epoch's session, once the session is established.
    #[cfg(test)]
    pub(crate) fn current_session(&self) -> Option<&crate::noise::NoiseSession> {
        use fips_core::proto::fsp::rekey::SessionKeys;
        self.keys()?
            .keys(fips_core::proto::rekey::Slot::Current)
            .map(SessionKeys::session)
    }

    /// The machine's next deadline or start instant, if it has one.
    #[cfg(test)]
    pub(crate) fn next_wake(&self) -> Option<SessionInstant> {
        self.machine.next_wake()
    }

    /// The pending new session (completed rekey, not yet cut over).
    #[cfg(test)]
    pub(crate) fn pending_new_session(&self) -> Option<&crate::noise::NoiseSession> {
        use fips_core::proto::fsp::rekey::SessionKeys;
        self.keys()?
            .keys(fips_core::proto::rekey::Slot::Pending)
            .map(SessionKeys::session)
    }

    /// An established session for a test, keyed by `session` and bonded to
    /// the key it authenticated, built at `now` for a node at the zero
    /// address with random keys and default parameters, made by a first
    /// handshake this node started when `initiator` is set. The zero address
    /// sorts below every peer, so a test that needs this node at the larger
    /// address uses [`Self::keyed_as`].
    #[cfg(test)]
    pub(crate) fn keyed(
        remote_addr: NodeAddr,
        session: crate::noise::NoiseSession,
        now: SessionInstant,
        initiator: bool,
    ) -> Self {
        let local = NodeKeys::new(crate::Identity::generate().keypair(), [0; 8]);
        let me = NodeAddr::from_bytes([0; 16]);
        let params = session_params(&crate::config::NodeConfig::default());
        Self::keyed_as(remote_addr, session, params, &local, me, now, initiator)
    }

    /// An established session for a test as [`Self::keyed`] builds it, for
    /// the node whose machine parameters, keys and address are `params`,
    /// `local` and `me`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn keyed_as(
        remote_addr: NodeAddr,
        session: crate::noise::NoiseSession,
        params: Params,
        local: &NodeKeys,
        me: NodeAddr,
        now: SessionInstant,
        initiator: bool,
    ) -> Self {
        let remote = *session.remote_static();
        let machine = keyed(params, local, me, &remote, session, TEST_PEER_EPOCH, now);
        let mut entry = Self::new(remote_addr, machine, now);
        entry.initiator = initiator;
        entry
    }

    /// A session this node opened toward `remote` at `now` for a test, its
    /// first setup sent and unanswered, built for a node with `keypair` at
    /// the address it derives.
    #[cfg(test)]
    pub(crate) fn opened_for_test(
        remote: &PublicKey,
        keypair: secp256k1::Keypair,
        now: SessionInstant,
    ) -> Self {
        let addr = NodeAddr::from_pubkey(&remote.x_only_public_key().0);
        let me = NodeAddr::from_pubkey(&keypair.x_only_public_key().0);
        let local = NodeKeys::new(keypair, [0; 8]);
        let params = session_params(&crate::config::NodeConfig::default());
        let (mut entry, _) = Self::opened(addr, remote, params, &local, me, now);
        entry.note_setup_sent();
        entry
    }

    /// A session opened at `now` for a test by one setup claiming the
    /// address `claimed` from an initiator nobody knows, held as a candidate
    /// by a node with `keypair` at the address it derives.
    #[cfg(test)]
    pub(crate) fn answering_for_test(
        claimed: NodeAddr,
        keypair: secp256k1::Keypair,
        now: SessionInstant,
    ) -> Self {
        let mut stranger =
            crate::noise::HandshakeState::new_initiator(crate::Identity::generate().keypair());
        let msg1 = stranger.write_message_1().expect("a msg1");
        let me = NodeAddr::from_pubkey(&keypair.x_only_public_key().0);
        let local = NodeKeys::new(keypair, [0; 8]);
        let params = session_params(&crate::config::NodeConfig::default());
        let carrier = NodeAddr::from_bytes([0xEE; 16]);
        let route = TreeCoordinate::root(carrier);
        let (entry, _) = Self::answering(claimed, &msg1, carrier, route, params, &local, me, now);
        assert_eq!(entry.candidate_count(), 1, "the setup is held");
        entry
    }
}

/// The send-side failure a machine's seal refusal stands for.
fn seal_refusal(refusal: SealRefusal) -> SealFailure {
    match refusal {
        SealRefusal::Exhausted => SealFailure::Noise(NoiseError::NonceOverflow),
        SealRefusal::NotEstablished | SealRefusal::NotSealable => SealFailure::NotEstablished,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod overlapping_epoch_tests;
