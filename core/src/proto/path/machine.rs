//! The machine of one link's paths: [`Bundle`].
//!
//! A [`Bundle`] holds the link's [`PathSet`], built around the original
//! path, and runs over it the path probe exchange of the multipath v1 draft
//! (Section 5.1) and the liveness of each path (Section 5.6). It is
//! sans-IO: each call takes the current instant and returns the
//! [`Output`]s the shell executes front to back. It reads no clock, draws
//! its random values from the host's entropy source, and never drops a
//! path's driver slot: every slot it gives up is in an output.
//! [`Bundle::account`] attributes each authentic frame of the link to its
//! path (Section 5.3) and tracks the peer's active path (Section 5.12), and
//! [`Bundle::charge`] counts each frame that failed to authenticate against
//! its path (Section 5.3).
//!
//! Path policy (Section 5.5) is checked where a path is probed for the
//! first time, created by the peer's probe, moved to a new address, or
//! probed again from Dead, at its cadence or at once, and where the peer's
//! probe would bring a path back from Dead, which reads the rules for a
//! path that probe would create: the link's class and kind are its
//! original path's, fixed when the bundle is built, and the facts are read
//! at each check. The original path is the link and is never refused.
//!
//! The bundle holds the candidates the host reports in its [`Candidates`]
//! table, whatever the peer's capability and path policy. A candidate is
//! admitted as a Probing path only while the peer is capable, its entry
//! is not held back and path policy allows probing it, and only on a
//! fresh report of it, its release, the peer turning capable, or a poll
//! after a rule refused it at its last attempt, so a change in the facts
//! takes effect at the next poll: never on a repeat or room freed by a
//! discard. A discarded
//! path's pair is held back until its transport regains carrier or comes
//! back, a source reports it afresh, or local discovery finds the peer
//! again on its transport (Section 5.6). A held-back pair no source lists
//! is offered once at its release and then forgotten unless admitted. A
//! candidate never moves a path.
//!
//! Until the peer is known to be capable, the bundle sends nothing but
//! capability probes (Section 5.2), held in its [`Capability`] record: on
//! the original path, of the smallest size, one at a time, only while it
//! holds a candidate path policy lets it probe, three over the span and
//! then at a doubling gap up to a cap. When the first round goes
//! unanswered it reports [`Output::NotCapable`]. An answer, or any path
//! message from the peer, makes the peer capable, and every candidate that
//! may be probed is then admitted. A capability probe's timeout never
//! counts toward the original path's liveness.
//!
//! A step runs in phases: the trips that `charge` recorded, then the expiry
//! of the probes whose timeout passed before the step's instant, the
//! capability probe's among them, then the peer turning capable on a path
//! message, then the input, then the expiry of unanswered probes and the
//! state changes they cause, then the choice of the active path (Section
//! 5.7): a mandatory change when the active path failed, else, while it
//! is Live, a discretionary one: at once to a Live path the operator's
//! pin names, or to a path of a higher tier, by its transport's role,
//! else to a path that, for the switch dwell, could carry a
//! `FilterAnnounce` where the active path cannot, was preferred where it
//! is not, or scored better by the switch margin. Then
//! come the grace of Dead paths,
//! then the capability probe and the probes due. When a local transport is
//! removed or loses carrier, the input phase tells the peer of each path
//! on it with a `PathClose` (Section 5.8). A candidate on a
//! connection-oriented transport has a connection opened before it is
//! probed, with [`Output::Connect`]. [`Bundle::next_wake`] names the
//! earliest instant a poll has work, which after every step lies ahead of
//! the step's instant.
//!
//! A Probing or Dead path's probes step down a ladder of sizes once a
//! padded one goes unanswered, so the first size a narrow hop carries is
//! proven; a Live path on a connectionless transport proven below its
//! link MTU searches upward with padded probes held outside its ring,
//! whose loss counts toward nothing. Each change of the size proven is an
//! [`Output::Proven`].
//!
//! A path that has stopped answering is held to a floor (Section 5.6). A
//! path that is not Probing stops answering when it becomes Dead, or once
//! `PATH_SILENCE_MAX` has passed since the earliest probe no matching
//! answer has followed, whichever is sooner. While stopped, its probes on
//! its own cadence, whatever its state, go no sooner than
//! `PATH_DEAD_PROBE_INTERVAL_MIN` after the stop and after the first, and
//! each later gap at least doubles, up to `PATH_DEAD_PROBE_INTERVAL_MAX`;
//! a path that was our active path when it left Live, or is at the stop,
//! is first re-checked every `PATH_DEAD_PROBE_INTERVAL_MIN` until
//! `PATH_DEAD_RECHECK_SPAN` after it went silent, its gaps doubling only
//! from there, so a silent outage of the path that carried the link is
//! found within about a second of its end; a connection asked for in
//! place of such a probe counts as one, and the probe sent when it opens
//! starts the next gap. Exempt, neither held nor
//! counted: the probe at once when the peer's probe brings a Dead path
//! back, those Section 5.7 requires at once, the early probe when the peer
//! clears `ACTIVE`, and the probe sent when a connection opens. An answer
//! in time ends the stop. So does the peer's probe bringing a Dead path
//! back, which starts the discovery probes afresh. Carrier's return, or
//! finding the peer again, brings a Dead path back with its stop kept, so
//! the floor holds and counts the discovery probes that follow, the
//! revival's own first among them; the peer's probe on a path it does
//! not bring back keeps the stop too. An answer to a probe already
//! counted unanswered is late, and a late answer is not a matching one
//! anywhere (Section 5.6): it gives a round trip and does not end the
//! stop ([`Answer::matching`]).
//!
//! Every change of active path holds the link's cost, a choice of this
//! implementation, since the draft leaves the link cost of a bundle to the
//! node (Section 5.12, its note): [`Bundle::cost`] gives the cost from
//! the start of the step that made the change until the switch dwell has
//! passed and two receiver reports, each an [`Input::Report`], have been
//! stepped after it. The hold is timed on the host's instants and reads
//! no clock; its end is not a wake, since nothing is done there.
//!
//! With multipath disabled (`Config::enabled` false) the bundle sends no
//! path message, asks for no connection and discards every path message
//! unanswered (Section 8.2), so its peer holds it as not capable; frames,
//! failures, carrier, removal, the pin, receiver reports and orphaning are
//! handled as when it is enabled.

use alloc::vec::Vec;
use core::cmp::Reverse;
use core::fmt;
use core::marker::PhantomData;

use super::candidate::{Candidates, Report};
use super::capable::Capability;
use super::live::{Answer, Sent};
use super::params::{PATH_SILENCE_MAX, Params};
use super::rules::{self, Rule, Scope};
use super::select::{self, Field, Hold, Pin, Rival};
use super::set::{Admission, Match, PATH_MAX_PER_PEER, PathSet, PathState, PeerPath, Roam};
use super::wire::{
    PATH_PROBE_MIN_SIZE, PathAck, PathCaps, PathClose, PathCloseReason, PathFlags, PathProbe,
    ack_len,
};
use super::{Env, Input, Output, Outputs, PathRef, Refusal, Role, Source, Switch, Why};
use crate::entropy::EntropySource;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::link::LinkMessageType;
use crate::time::{Clock, Duration, Instant, backoff, deadline};
use crate::transport::{TransportAddr, TransportId};

/// A random `u32` from the host's source `E`.
fn draw<E: EntropySource>() -> u32 {
    let mut b = [0u8; 4];
    E::fill(&mut b);
    u32::from_le_bytes(b)
}

/// The capability bits this node's path messages carry: none, since it
/// does not aggregate.
fn caps() -> PathCaps {
    PathCaps::with_aggregate(false)
}

/// The pair of `path`.
fn pair<I: Instant, D: Default>(path: &PeerPath<I, D>) -> PathRef {
    PathRef {
        transport: path.transport_id(),
        addr: path.addr().clone(),
    }
}

/// Whether `path` contends for the link: Live and acked, the paths a
/// choice of active path ranks and the operator's pin is in force on.
fn contends<I: Instant, D: Default>(path: &PeerPath<I, D>) -> bool {
    path.state() == PathState::Live && path.acked()
}

/// Whether `input` exists only for multipath: a candidate or its
/// unlisting, a path message from the peer, a connection report or a
/// beacon. A bundle with multipath disabled discards them (draft Section
/// 8.2); every other input concerns a link of one path too.
fn multipath(input: &Input) -> bool {
    match input {
        Input::Candidate { .. }
        | Input::Unlisted { .. }
        | Input::Probe { .. }
        | Input::Ack { .. }
        | Input::Close { .. }
        | Input::Connected { .. }
        | Input::Beacon { .. } => true,
        Input::Poll
        | Input::Carrier { .. }
        | Input::SendFailed { .. }
        | Input::Present { .. }
        | Input::Removed { .. }
        | Input::Pin { .. }
        | Input::Unpin
        | Input::Report => false,
    }
}

/// Whether `input` is a path message from the peer: any of them shows the
/// peer implements multipath (draft Section 5.2). A beacon is not
/// authenticated, so it shows nothing.
fn heard(input: &Input) -> bool {
    match input {
        Input::Probe { .. } | Input::Ack { .. } | Input::Close { .. } => true,
        Input::Poll
        | Input::Beacon { .. }
        | Input::Candidate { .. }
        | Input::Unlisted { .. }
        | Input::Carrier { .. }
        | Input::SendFailed { .. }
        | Input::Present { .. }
        | Input::Removed { .. }
        | Input::Connected { .. }
        | Input::Pin { .. }
        | Input::Unpin
        | Input::Report => false,
    }
}

/// The earlier of `a` and `b`, either of which may be absent.
fn earliest<I: Instant>(a: Option<I>, b: Option<I>) -> Option<I> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// Whether a frame of link message type `msg_type` shows which path the
/// peer sends on: any link message but a session datagram or a path
/// message (draft Section 5.12), a type this node does not know included.
fn marks(msg_type: u8) -> bool {
    match LinkMessageType::from_byte(msg_type) {
        Some(
            LinkMessageType::SessionDatagram
            | LinkMessageType::PathProbe
            | LinkMessageType::PathAck
            | LinkMessageType::PathClose,
        ) => false,
        Some(
            LinkMessageType::SenderReport
            | LinkMessageType::ReceiverReport
            | LinkMessageType::TreeAnnounce
            | LinkMessageType::FilterAnnounce
            | LinkMessageType::LookupRequest
            | LinkMessageType::LookupResponse
            | LinkMessageType::Disconnect
            | LinkMessageType::Heartbeat,
        )
        | None => true,
    }
}

/// Whether a frame of link message type `msg_type` carries a path message,
/// which is attributed by its own rules (draft Sections 5.1 and 5.3) and
/// never roams a path.
fn signal(msg_type: u8) -> bool {
    matches!(
        LinkMessageType::from_byte(msg_type),
        Some(LinkMessageType::PathProbe | LinkMessageType::PathAck | LinkMessageType::PathClose)
    )
}

/// Whether a frame of link message type `msg_type` is the peer's tunnel
/// traffic, which holds a probe's verdict on its path: a session datagram.
/// The peer's path messages go on paths it has left, and its heartbeats,
/// reports and other link control on an idle link, so neither shows that
/// the path carries data.
fn carries(msg_type: u8) -> bool {
    match LinkMessageType::from_byte(msg_type) {
        Some(LinkMessageType::SessionDatagram) => true,
        // The defect's shape: every frame but a path message holds it.
        _ if node_fault!(VerdictCountsControl) => !signal(msg_type),
        _ => false,
    }
}

/// What [`Bundle::account`] did with one authentic frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// The index of the path of the frame's pair, or `None` for a frame
    /// from no path. A path message's frame is moved, when the message is
    /// stepped, to the path the message concerns, if that is another.
    pub path: Option<usize>,
    /// Whether the frame may feed the link's timing samples: always on a
    /// link of one path, and otherwise only when it arrived on the peer's
    /// active path.
    pub sample: bool,
    /// What the single-path roam did: nothing, unless the link holds only
    /// its original path and the frame is not a path message.
    pub roam: Roam,
}

/// What [`Bundle::charge`] did with one frame that failed to authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    /// The frame came from no original or acked path, so it counts toward
    /// nothing (draft Section 5.3).
    Nothing,
    /// It was counted on its path, below the limit or past it.
    Counted,
    /// Its path's count reached the limit, and the path is kept as it is:
    /// no other path is Live or acked Suspect, or the path is neither Live
    /// nor Suspect. The shell logs it.
    Warn,
    /// Its path's count reached the limit with another path Live or acked
    /// Suspect: the next step marks the path Dead as of this failure. The
    /// shell steps a poll at once.
    Tripped,
}

/// What the operator is shown of a link's paths at one instant
/// ([`Bundle::view`]).
#[derive(Clone, Debug, PartialEq)]
pub struct View {
    /// Whether multipath is enabled on this node.
    pub enabled: bool,
    /// Whether the peer has shown it implements multipath.
    pub capable: bool,
    /// Whether the link's cost is held at the instant of the view.
    pub held: bool,
    /// The operator's pin, if any.
    pub pin: Option<PinView>,
    /// Every path held, in the set's order.
    pub paths: Vec<PathView>,
}

/// The operator's pin as a [`View`] shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinView {
    /// The pin.
    pub pin: Pin,
    /// Whether it is in force: a Live, acked path it names is held. While
    /// it is not, the pin is suspended and paths are chosen as with none.
    pub enforced: bool,
}

/// One path as a [`View`] shows it.
#[derive(Clone, Debug, PartialEq)]
pub struct PathView {
    /// The path's pair.
    pub to: PathRef,
    /// Our identifier of the path.
    pub id: u32,
    /// Its state.
    pub state: PathState,
    /// Whether it is the path this node sends on.
    pub active: bool,
    /// Whether it is proven: bound, or answered in this link.
    pub acked: bool,
    /// Whether the peer's latest probe or matched ack on it said the peer
    /// sends on it.
    pub remote: bool,
    /// Whether the operator's pin names it, in force or suspended.
    pub pinned: bool,
    /// Its latest round trip.
    pub rtt: Option<Duration>,
    /// Its least round trip in the window.
    pub least: Option<Duration>,
    /// The round-trip samples in the window.
    pub samples: usize,
    /// Its smoothed ETX.
    pub etx: f64,
    /// Its score, lower being better, once it has a round trip.
    pub score: Option<f64>,
    /// Its proven MTU: the largest path message one of our probes and
    /// its answer both carried.
    pub mtu: Option<usize>,
    /// The authentic frames attributed to it, modulo 2^32.
    pub frames: u32,
    /// The total length of those frames in bytes, modulo 2^32.
    pub bytes: u32,
    /// The age of its latest authentic frame at the instant of the view.
    pub heard: Option<Duration>,
    /// Its consecutive unanswered probes since it last changed state.
    pub misses: u32,
    /// Frames that failed to authenticate on it since the latest
    /// authentic one.
    pub fails: u32,
}

/// The machine of one link's paths.
///
/// `C` is the host's clock, of whose instants every call takes the current
/// one; `E` the host's entropy source, from which path identifiers and each
/// path's first `probe_id` are drawn; and `D` the driver slot each path
/// carries for the host.
pub struct Bundle<C: Clock, E: EntropySource, D: Default> {
    params: Params,
    set: PathSet<C::Instant, D>,
    /// Whether the peer has shown it implements multipath. Until it has,
    /// the machine sends nothing.
    capable: bool,
    /// The instant the bundle was made, which `rx_time_us` counts from.
    origin: C::Instant,
    /// Our `path_id` of the peer's active path as this node sees it, or
    /// `None` when the latest frame that marks it came from no path.
    peer_active: Option<u32>,
    /// Our `path_id` of the link's original path, while it is held.
    original: Option<u32>,
    /// The link's anonymity class and kind, its original path's.
    scope: Scope,
    /// The candidates the host reported.
    table: Candidates,
    /// The capability probes sent while the peer is not known to be
    /// capable.
    record: Capability<C::Instant>,
    /// Whether a candidate allowed capability probes at the latest send
    /// phase, or a roam of the original path may have freed one since.
    eligible: bool,
    /// The frame of the path message last accounted, until the next step:
    /// our `path_id` of the path of its pair, if any, and its length.
    frame: Option<(Option<u32>, usize)>,
    /// Whether no original or acked path is left. The bundle then answers
    /// nothing until the shell closes it.
    orphaned: bool,
    /// The discretionary change under way: our `path_id` of the path the
    /// link would move to, and the instant from which it has scored better
    /// than the active path by the switch margin.
    dwell: Option<(u32, C::Instant)>,
    /// Our `path_id` of the path the latest change of active path left, if
    /// that change was mandatory: a return to it needs no switch margin.
    left: Option<u32>,
    /// The operator's pin, until it is lifted, by the operator or by the
    /// host when the peer is replaced and the link kept, or its transport
    /// goes; a new bundle holds none, and [`Self::renew`] keeps it.
    pin: Option<Pin>,
    /// The hold on the link's cost from the latest change of active path,
    /// in force or ended.
    hold: Option<Hold<C::Instant>>,
    source: PhantomData<fn() -> E>,
}

// Written out: a derive would ask `C` and `E` for `Debug`, which neither a
// host clock nor an entropy source needs.
impl<C: Clock, E: EntropySource, D: Default + fmt::Debug> fmt::Debug for Bundle<C, E, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bundle")
            .field("params", &self.params)
            .field("set", &self.set)
            .field("capable", &self.capable)
            .field("origin", &self.origin)
            .field("peer_active", &self.peer_active)
            .field("original", &self.original)
            .field("scope", &self.scope)
            .field("table", &self.table)
            .field("record", &self.record)
            .field("eligible", &self.eligible)
            .field("frame", &self.frame)
            .field("orphaned", &self.orphaned)
            .field("dwell", &self.dwell)
            .field("left", &self.left)
            .field("pin", &self.pin)
            .field("hold", &self.hold)
            .finish()
    }
}

impl<C: Clock, E: EntropySource, D: Default> Bundle<C, E, D> {
    /// The bundle of a link established at `now` on (`transport`, `addr`):
    /// that pair is its original path, Live, acked and active (draft
    /// Section 5.6), and its class and kind, read from `env`'s facts now,
    /// are the link's for its life (Section 5.5). The peer is not yet known
    /// to be capable.
    pub fn new(
        now: C::Instant,
        transport: TransportId,
        addr: TransportAddr,
        params: Params,
        env: &Env<'_>,
    ) -> Self {
        let scope = rules::link(env.facts, transport, &addr);
        let mut set = PathSet::new();
        let bound = set.bind_original(transport, addr, draw::<E>);
        debug_assert!(
            matches!(bound, Ok(None)),
            "an empty set binds without evicting"
        );
        let original = set.get(0).map(PeerPath::path_id);
        Self {
            params,
            set,
            capable: false,
            origin: now,
            peer_active: None,
            original,
            scope,
            table: Candidates::new(),
            record: Capability::new(),
            eligible: false,
            frame: None,
            orphaned: false,
            dwell: None,
            left: None,
            pin: None,
            hold: None,
            source: PhantomData,
        }
    }

    /// Take one input at `now`, and return what the shell must do, in
    /// order.
    ///
    /// Each trip [`Self::charge`] recorded is applied first; then every
    /// probe due before `now` goes unanswered, with the state changes that
    /// causes; then the input; then every probe due by `now` goes
    /// unanswered; then the active path is chosen: a mandatory change, else
    /// a discretionary one; then Dead paths past their grace are discarded;
    /// then the probes due are sent. Every input runs every phase, and a
    /// probe whose timeout passed before `now` has gone unanswered before
    /// the input is taken, so a poll and any other input see the same
    /// timers, whether or not the host polled at each wake: an answer that
    /// comes after its probe's timeout is late either way. A path message
    /// from a peer not yet known to be capable makes it capable before the
    /// input is taken, and every candidate held that may be probed is
    /// admitted then; a capability probe still outstanding after the input,
    /// which did not answer it, is answered late if at all. The capability
    /// probe goes first in the send phase, while the peer is not capable.
    /// The link's cost is read before any phase, so a change of active path
    /// holds the cost from the start of its step, and a report stepped
    /// with the change counts toward the hold before it, not the new one.
    /// Before any phase, a hold on the link's cost found ended is cleared,
    /// unless the input is a poll made before [`Self::next_wake`], which
    /// changes nothing and so leaves an ended hold in place for the next
    /// step; clearing it changes no value [`Self::cost`] returns.
    /// Once the bundle is orphaned, a step does nothing. With multipath
    /// disabled, a candidate, its unlisting, a path message or a connection
    /// report is taken as a poll: it is not answered, is not held and does
    /// not make the peer capable.
    pub fn step(&mut self, now: C::Instant, input: Input, env: &mut Env<'_>) -> Outputs<D> {
        let mut out = Outputs::new();
        let frame = self.frame.take();
        if self.orphaned {
            return out;
        }
        let dwell = self.params.cfg.switch_dwell;
        if self
            .hold
            .is_some_and(|hold| hold.held(now, dwell).is_none())
            && !(matches!(input, Input::Poll) && self.next_wake().is_none_or(|wake| now < wake))
        {
            self.hold = None;
        }
        let input = if self.muted(&input) {
            Input::Poll
        } else {
            input
        };
        let held = self.cost(now, env.cost);
        let before = self.set.active().map(|p| (p.path_id(), p.state()));
        self.trips(&mut out);
        self.expire(now, true, &mut out);
        if heard(&input) && !self.capable {
            self.turn(env, &mut out);
        }
        match input {
            Input::Poll => self.reoffer(env, &mut out),
            Input::Candidate {
                transport,
                addr,
                source,
            } => self.candidate(now, PathRef { transport, addr }, source, env, &mut out),
            Input::Unlisted {
                transport,
                addr,
                source,
            } => {
                self.table.unlist(transport, &addr, source);
            }
            Input::Probe {
                transport,
                addr,
                msg,
            } => self.probe(now, PathRef { transport, addr }, msg, frame, env, &mut out),
            Input::Ack {
                transport,
                addr,
                msg,
            } => self.ack(now, PathRef { transport, addr }, msg, frame, env, &mut out),
            Input::Close {
                transport,
                addr,
                msg,
            } => self.closed(now, PathRef { transport, addr }, msg, &mut out),
            Input::Carrier { transport, up } => self.carrier(now, transport, up, env, &mut out),
            Input::SendFailed { transport, addr } => {
                self.unreachable(now, PathRef { transport, addr }, &mut out);
            }
            Input::Present {
                transport,
                present: true,
            } => self.carrier(now, transport, true, env, &mut out),
            Input::Present {
                transport,
                present: false,
            } => self.removed(transport, true, &mut out),
            Input::Removed { transport } => self.removed(transport, false, &mut out),
            Input::Connected {
                transport,
                addr,
                ok,
            } => self.connected(now, PathRef { transport, addr }, ok, &mut out),
            Input::Pin { transport, addr } => self.pin = Some(Pin { transport, addr }),
            Input::Unpin => self.pin = None,
            Input::Report => self.report(now),
            Input::Beacon { transport, addr } => self.beacon(now, PathRef { transport, addr }),
        }
        // A capability probe still outstanding once the peer is capable is
        // answered late, if at all.
        if self.capable
            && let Some(sent) = self.record.take()
        {
            self.lapse(sent);
        }
        self.expire(now, false, &mut out);
        if !self.select(now, held, before, env, &mut out) {
            return out;
        }
        self.grace(now, &mut out);
        self.sends(now, env, &mut out);
        out
    }

    /// The earliest instant at which a poll has work: a trip recorded by
    /// [`Self::charge`], an outstanding probe going unanswered, a probe, or
    /// the connection a probe needs, falling due on a path that has room
    /// for it (a probe held by the floor falls due at the floor's instant),
    /// a Dead path's grace ending where it would be discarded, the
    /// switch dwell of a discretionary change ending, or, while the peer is
    /// not known to be capable, the outstanding capability probe going
    /// unanswered or, while a candidate allowed them at the last step, the
    /// next capability probe falling due. `None` when nothing is probed and
    /// nothing is timed, as with multipath disabled, and once the bundle is
    /// orphaned. After every step it is `None` or later than the step's
    /// instant.
    pub fn next_wake(&self) -> Option<C::Instant> {
        if self.orphaned {
            return None;
        }
        let live = self.any_live();
        let dwell = self.params.cfg.switch_dwell;
        let mut wake = self.dwell.map(|(_, start)| deadline(start, dwell));
        for (i, p) in self.set.paths().iter().enumerate() {
            wake = earliest(wake, p.live().tripped());
            wake = earliest(wake, p.live().earliest_due());
            if self.probed(i) && p.live().room(self.cap(i, false)) {
                // A path due at once is sent in the step that makes it so;
                // `origin` is in the past of every step.
                wake = earliest(wake, Some(p.live().next_at().unwrap_or(self.origin)));
            }
            wake = earliest(wake, self.ends(i, live));
        }
        if self.params.cfg.enabled && !self.capable {
            // A capability probe due at once is sent in the step that
            // makes it so, unless a roam has only now freed a candidate.
            let open = self.eligible;
            let due = self.record.wake(open);
            wake = earliest(wake, due.or_else(|| open.then_some(self.origin)));
        }
        wake
    }

    /// Account for one authentic frame of the link, `len` bytes long with
    /// link message type `msg_type`, received at `now` on `transport` from
    /// `addr`.
    ///
    /// The shell calls this for every frame of the link that authenticates
    /// and passes the replay check, and for no other (draft Section 5.3).
    /// `len` is the whole FMP frame's length, the unit of the draft's
    /// `rx_bytes`. A path message's frame is accounted before the decoded
    /// message is stepped, so an ack counts the probe it answers.
    ///
    /// While the link holds only its original path, it applies the
    /// single-path roam of [`PathSet::roam`] to a frame that is not a path
    /// message, as FMP v1 does, and returns its result; a roam that moved
    /// the original path may free a candidate's pair, so the next wake
    /// then reads the capability gate again. A path message, or
    /// any frame once the original path is not the link's one path, moves
    /// no address (draft Section 5.3). With multipath disabled a path
    /// message's frame roams too: such a node's every link is one whose
    /// peer is not capable, which FMP v1 governs whatever the frame
    /// carries (Sections 8.2 and 9.2). It attributes the frame to the path
    /// of its pair, or to none, and counts it there; the step that handles
    /// a probe or a matched ack moves the frame to the path the message
    /// concerns when that is another (draft Section 5.1). It tracks the
    /// peer's active path. It never creates a path, never changes the
    /// active path, and allocates nothing. Once the bundle is orphaned it
    /// attributes no frame and roams nothing.
    pub fn account(
        &mut self,
        now: C::Instant,
        transport: TransportId,
        addr: &TransportAddr,
        len: usize,
        msg_type: u8,
    ) -> Account {
        if self.orphaned {
            return Account {
                path: None,
                sample: false,
                roam: Roam::Unmoved,
            };
        }
        let message = signal(msg_type);
        let roam = if (message && self.params.cfg.enabled) || !self.single() {
            Roam::Unmoved
        } else {
            self.set.roam(transport, addr.clone(), draw::<E>)
        };
        if roam != Roam::Unmoved {
            // The pair the original path left may be a candidate's: the
            // next wake reads the capability gate again.
            self.eligible = true;
        }
        let path = self.set.find(transport, addr);
        let id = path.and_then(|i| self.set.get(i)).map(PeerPath::path_id);
        if let Some(p) = path.and_then(|i| self.set.path_mut(i)) {
            p.live_mut().heard(len, now);
            if carries(msg_type) {
                p.live_mut().carried(now);
            }
        }
        if marks(msg_type) {
            self.peer_active = id;
        }
        let sample = self.set.len() <= 1 || (id.is_some() && id == self.peer_active);
        self.frame = message.then_some((id, len));
        Account { path, sample, roam }
    }

    /// Count one frame of the link that failed to authenticate, received at
    /// `now` on `transport` from `addr` (draft Section 5.3).
    ///
    /// It counts only on the original path and on paths acked in this
    /// link, in any state; a frame from any other pair counts toward
    /// nothing. When the count reaches the limit and another path is Live
    /// or acked Suspect, a Live or Suspect path's trip is recorded for the
    /// next step, which marks it Dead as of `now`, and this returns
    /// [`Charge::Tripped`]; [`Self::next_wake`] is then at or before `now`,
    /// so the shell's poll at once is not early. Otherwise reaching the
    /// limit returns [`Charge::Warn`] and changes nothing. An authentic
    /// frame on the path, through [`Self::account`] or [`Self::authentic`],
    /// starts the count again. It allocates nothing, and once the bundle is
    /// orphaned it counts nothing.
    pub fn charge(
        &mut self,
        now: C::Instant,
        transport: TransportId,
        addr: &TransportAddr,
    ) -> Charge {
        if self.orphaned {
            return Charge::Nothing;
        }
        let proven = matches!(self.set.classify(transport, addr), Match::Proven { .. });
        let Some(i) = self.set.find(transport, addr).filter(|_| proven) else {
            return Charge::Nothing;
        };
        let limit = u32::from(self.params.cfg.auth_limit);
        let trips = self.trippable(i);
        let Some(live) = self.set.path_mut(i).map(PeerPath::live_mut) else {
            return Charge::Nothing;
        };
        if live.fail() != limit {
            return Charge::Counted;
        }
        if !trips {
            return Charge::Warn;
        }
        live.trip(now);
        Charge::Tripped
    }

    /// Start again the count of authentication failures on the path of
    /// (`transport`, `addr`), for an authentic frame of the link from there
    /// that the shell does not account, such as one too short to carry a
    /// message (draft Section 5.3: a path's count is reset when an authentic
    /// frame of the link arrives on that path). A pair no path holds starts
    /// no count again. It does nothing else, and allocates nothing.
    pub fn authentic(&mut self, transport: TransportId, addr: &TransportAddr) {
        if let Some(p) = self
            .set
            .find(transport, addr)
            .and_then(|i| self.set.path_mut(i))
        {
            p.live_mut().forgive();
        }
    }

    /// Hand back every path's driver slot as the link is removed, in set
    /// order, marking to keep the peer's active path, and every path while
    /// the peer is not known to be capable.
    pub fn close(self) -> Outputs<D> {
        let mut out = Outputs::new();
        let capable = self.capable;
        let active = self.peer_active;
        for p in self.set.into_paths() {
            out.push(Output::Released {
                to: pair(&p),
                keep: !capable || active == Some(p.path_id()),
                driver: p.into_driver(),
            });
        }
        out
    }

    /// Start the link again at `to`, the transport and address FMP v1 moved
    /// the link to, as a won crossed handshake does at `now` (draft Section
    /// 5.2: a new link holds no capability record; Section 5.4: the pair the
    /// link moved to is the new link's original path).
    ///
    /// When a path is held at `to`, active or not, it stays, as the new
    /// link's original path, Live, acked and active, under a new `path_id`
    /// no path of the old link held, with its driver slot and its count of
    /// failed frames; the rest of its liveness starts again. It is not
    /// released, since releasing it would close the connection the link now
    /// sends on. Otherwise the new link's original path is a new path at
    /// `to`, Live, acked and active, under such a `path_id`, with a slot of
    /// its own. The link's class and kind are read from `env`'s facts
    /// again, for the original path. The peer is no longer known to be
    /// capable, and the candidates, the capability probes, the frame being
    /// stepped and a discretionary change under way are dropped. The
    /// operator's pin and the hold on the link's cost are kept. Every path
    /// that does not stay comes back in an [`Output::Released`], in set
    /// order, marked to keep as [`Self::close`] marks it. Every path of the
    /// old link, the one that stays included, is logged as ending, and the
    /// new link's original path as beginning, each for [`Why::Renewed`], so
    /// that no `path_id` changes unlogged. A bundle holding no path is left
    /// as it is.
    pub fn renew(
        &mut self,
        now: C::Instant,
        env: &Env<'_>,
        to: (TransportId, TransportAddr),
    ) -> Outputs<D> {
        let mut out = Outputs::new();
        if self.set.is_empty() {
            return out;
        }
        let id = loop {
            let id = draw::<E>();
            if id != 0 && self.set.paths().iter().all(|p| p.path_id() != id) {
                break id;
            }
        };
        let kept = self.set.find(to.0, &to.1);
        let capable = self.capable;
        let peer_active = self.peer_active;
        let mut stays = None;
        for (i, p) in core::mem::take(&mut self.set)
            .into_paths()
            .into_iter()
            .enumerate()
        {
            out.push(Output::State {
                to: pair(&p),
                path_id: p.path_id(),
                from: Some(p.state()),
                next: None,
                why: Why::Renewed,
            });
            if Some(i) == kept {
                stays = Some(p);
                continue;
            }
            out.push(Output::Released {
                to: pair(&p),
                keep: !capable || peer_active == Some(p.path_id()),
                driver: p.into_driver(),
            });
        }
        let path = match stays {
            Some(p) => p.reborn(id),
            None => PeerPath::original(to.0, to.1, id),
        };
        out.push(Output::State {
            to: pair(&path),
            path_id: id,
            from: None,
            next: Some(path.state()),
            why: Why::Renewed,
        });
        self.scope = rules::link(env.facts, path.transport_id(), path.addr());
        self.set = PathSet::holding(path);
        self.capable = false;
        self.origin = now;
        self.peer_active = None;
        self.original = Some(id);
        self.table = Candidates::new();
        self.record = Capability::new();
        self.eligible = false;
        self.frame = None;
        self.orphaned = false;
        self.dwell = None;
        self.left = None;
        out
    }

    /// The driver slot of the path at `index`, for the shell to install or
    /// clear what it holds for that path.
    pub fn driver_mut(&mut self, index: usize) -> Option<&mut D> {
        self.set.path_mut(index).map(PeerPath::driver_mut)
    }

    /// The paths held, to change past the machine: for tests of the set's
    /// rules through a host's peer.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn paths_mut(&mut self) -> &mut PathSet<C::Instant, D> {
        &mut self.set
    }

    /// The paths held.
    pub fn paths(&self) -> &PathSet<C::Instant, D> {
        &self.set
    }

    /// Whether the peer has shown it implements multipath.
    pub fn capable(&self) -> bool {
        self.capable
    }

    /// The link's anonymity class and kind: its original path's, fixed
    /// when the bundle was built.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The candidates held.
    pub fn candidates(&self) -> &Candidates {
        &self.table
    }

    /// The capability probes sent while the peer was not known to be
    /// capable.
    pub fn capability(&self) -> &Capability<C::Instant> {
        &self.record
    }

    /// The operator's pin, if any, in force or suspended. It lasts until
    /// `Input::Unpin`, which the host also steps when the peer is replaced
    /// and the link kept, its transport's removal, or the bundle's end.
    pub fn pin(&self) -> Option<&Pin> {
        self.pin.as_ref()
    }

    /// The link's cost for the spanning tree at `now`, given the cost
    /// `live` the host measures now: the cost held at the latest change
    /// of active path, until the switch dwell has passed since the change
    /// and two receiver reports have been stepped after it, and `live`
    /// otherwise. The end of a hold is not a wake: nothing changes there
    /// but what this returns. The hold is this implementation's choice;
    /// the draft states no rule for the link cost of a bundle (Section
    /// 5.12, its note).
    pub fn cost(&self, now: C::Instant, live: f64) -> f64 {
        let dwell = self.params.cfg.switch_dwell;
        self.hold
            .and_then(|hold| hold.held(now, dwell))
            .unwrap_or(live)
    }

    /// Whether the link's cost is held, or was and has not yet been found
    /// ended: from a change of active path until the first step after the
    /// hold's end that is not a poll made before [`Self::next_wake`]. While
    /// it is false, [`Self::cost`] returns the cost it is given at any
    /// instant, so the host need not read its clock to ask. A bundle with
    /// multipath disabled never changes path, so it never holds.
    pub fn holding(&self) -> bool {
        self.hold.is_some()
    }

    /// What the operator is shown of the link's paths at `now`: whether
    /// multipath is enabled and the peer capable, whether the cost is held
    /// at `now`, the pin and whether it is in force, and each path's
    /// state, standing and measurements, with the age of its latest
    /// authentic frame at `now`. It reads nothing but `self` and `now`.
    pub fn view(&self, now: C::Instant) -> View {
        let dwell = self.params.cfg.switch_dwell;
        let active = self.set.active_index();
        let paths = self
            .set
            .paths()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let live = p.live();
                let to = pair(p);
                PathView {
                    pinned: self.pin.as_ref().is_some_and(|pin| pin.names(&to)),
                    to,
                    id: p.path_id(),
                    state: p.state(),
                    active: active == Some(i),
                    acked: p.acked(),
                    remote: live.peer(),
                    rtt: live.rtt(),
                    least: live.min_rtt(),
                    samples: live.samples(),
                    etx: live.etx(),
                    score: select::score(live),
                    mtu: live.mtu(),
                    frames: live.frames(),
                    bytes: live.bytes(),
                    heard: live.heard_at().map(|at| now.saturating_duration_since(at)),
                    misses: live.misses(),
                    fails: live.fails(),
                }
            })
            .collect();
        View {
            enabled: self.params.cfg.enabled,
            capable: self.capable,
            held: self.hold.and_then(|hold| hold.held(now, dwell)).is_some(),
            pin: self.pin.clone().map(|pin| PinView {
                pin,
                enforced: self.enforced(),
            }),
            paths,
        }
    }

    /// Whether the operator's pin is in force: it is set and names a path
    /// that [`contends`], the test [`Self::rivals`] applies, so a view
    /// never shows a pin in force that selection does not follow.
    fn enforced(&self) -> bool {
        self.pin.as_ref().is_some_and(|pin| {
            self.set
                .paths()
                .iter()
                .any(|p| contends(p) && pin.names(&pair(p)))
        })
    }

    /// A receiver report at `now`: counted toward the hold on the link's
    /// cost while one is in force, and otherwise nothing.
    fn report(&mut self, now: C::Instant) {
        let dwell = self.params.cfg.switch_dwell;
        if let Some(hold) = self
            .hold
            .as_mut()
            .filter(|hold| hold.held(now, dwell).is_some())
        {
            hold.report();
        }
    }

    /// `source`'s report of the candidate `to` (draft Sections 5.4, the
    /// note, and 5.6). The pair is held in the table, or the report is
    /// refused when the table is full; a repeat does nothing more. A fresh
    /// report releases the pair's entry; from local discovery it is the
    /// peer found again on the transport, which releases every entry held
    /// back there and brings back every Dead path there. Otherwise a held
    /// Dead path at the pair itself is brought back. A Dead path comes
    /// back, while the peer is capable, only where [`Self::again`] allows
    /// it, and the pair is refused, naming the rule, when it does not.
    /// Then the entry, and each one released, is offered for admission
    /// ([`Self::enlist`]). A candidate never moves a path.
    fn candidate(
        &mut self,
        now: C::Instant,
        to: PathRef,
        source: Source,
        env: &Env<'_>,
        out: &mut Outputs<D>,
    ) {
        let set = &self.set;
        let report = self
            .table
            .report(to.transport, to.addr.clone(), source, |t, a| {
                set.find(t, a).is_some()
            });
        let slot = match report {
            Report::New(slot) | Report::Again(slot) => slot,
            Report::Repeat(_) => return,
            Report::Full => {
                out.push(Output::Refused {
                    to,
                    why: Refusal::Table,
                });
                return;
            }
        };
        let found = source == Source::Discovery;
        let released = if found {
            self.table.release(to.transport)
        } else {
            0
        };
        if self.capable {
            for i in 0..self.set.len() {
                let Some(p) = self.set.get(i) else {
                    continue;
                };
                let on = p.transport_id() == to.transport;
                let here = on && p.addr() == &to.addr;
                if p.state() != PathState::Dead || !(here || (found && on)) {
                    continue;
                }
                match self.again(i, env) {
                    Ok(()) => self.revive(i, now, Why::Found, out),
                    Err(rule) if here => out.push(Output::Refused {
                        to: to.clone(),
                        why: Refusal::Rule(rule),
                    }),
                    Err(_) => {}
                }
            }
        }
        self.enlist(slot, false, env, out);
        self.enlists(released & !(1 << slot), env, out);
    }

    /// Offer the candidate in `slot` for admission (draft Section 5.6, the
    /// first row): while the peer is capable, an entry not held back whose
    /// pair is not held as a path is admitted as a Probing path, probed in
    /// this step, or on a connection-oriented transport connected first,
    /// when path policy allows probing it (Sections 5.1 and 5.5). A pair
    /// the rules refuse is refused, naming the rule, and stays held, with
    /// the rule recorded in its entry; any other outcome clears the record.
    /// `again` says the attempt is a poll's re-offer ([`Self::reoffer`])
    /// rather than one a report, a release or the peer turning capable
    /// triggered: a triggered attempt reports every refusal, while a
    /// re-offer reports one only when the refusing rule differs from the
    /// one recorded, so a candidate the facts still refuse is not reported
    /// at every poll.
    fn enlist(&mut self, slot: usize, again: bool, env: &Env<'_>, out: &mut Outputs<D>) {
        if !self.capable {
            return;
        }
        let Some(e) = self.table.get(slot) else {
            return;
        };
        if e.held() || self.set.find(e.transport(), e.addr()).is_some() {
            return;
        }
        let last = e.refused();
        let to = PathRef {
            transport: e.transport(),
            addr: e.addr().clone(),
        };
        if let Err(rule) = self.probes(&to, env) {
            self.table.mark(slot, Some(rule));
            if !again || last != Some(rule) {
                out.push(Output::Refused {
                    to,
                    why: Refusal::Rule(rule),
                });
            }
            return;
        }
        let transport = to.transport;
        let admitted = self.admit(to, env, out);
        // A candidate refused for room waits for its next trigger; a poll
        // does not offer it again.
        self.table.mark(slot, None);
        let Some(i) = admitted else {
            return;
        };
        if env.facts.oriented(transport)
            && let Some(p) = self.set.path_mut(i)
        {
            p.live_mut().unlink();
        }
        self.note(i, None, Why::Candidate, out);
    }

    /// [`Self::enlist`] each released slot whose bit `mask` sets, in slot
    /// order, then forget each of them that no source lists and that was
    /// not admitted: a pair given up on is offered once at its release, and
    /// is no candidate after it (Sections 5.2 and 5.6).
    fn enlists(&mut self, mask: u8, env: &Env<'_>, out: &mut Outputs<D>) {
        for slot in 0..PATH_MAX_PER_PEER {
            if mask & (1 << slot) != 0 {
                self.enlist(slot, false, env, out);
            }
        }
        let set = &self.set;
        self.table.prune(mask, |t, a| set.find(t, a).is_some());
    }

    /// The peer has shown it implements multipath (draft Section 5.2): it
    /// is capable from now on, and every candidate held that may be probed
    /// is admitted, in slot order. No capability probe goes after this; the
    /// step hands one still outstanding to the original path's late record
    /// once its input is taken, so the input may still answer it in time.
    fn turn(&mut self, env: &Env<'_>, out: &mut Outputs<D>) {
        self.capable = true;
        out.push(Output::Capable);
        for slot in 0..PATH_MAX_PER_PEER {
            self.enlist(slot, false, env, out);
        }
    }

    /// Offer again, in slot order, each held candidate a rule refused at
    /// its last admission attempt (draft Section 5.5): a change in the
    /// facts since then, such as an ACL that now admits the peer or a
    /// transport added, admits it at this poll without a fresh report of
    /// it. With the facts unchanged each is refused by the same rule
    /// again, which gives nothing and changes nothing. Only while the peer
    /// is capable, since only then is anything admitted.
    fn reoffer(&mut self, env: &Env<'_>, out: &mut Outputs<D>) {
        if !self.capable {
            return;
        }
        for slot in 0..PATH_MAX_PER_PEER {
            if self.table.get(slot).is_some_and(|e| e.refused().is_some()) {
                self.enlist(slot, true, env, out);
            }
        }
    }

    /// Hold back the pair of a path just discarded (draft Section 5.6, "No
    /// scheduled retry"): it is not admitted again until it is released.
    /// With multipath disabled nothing is held.
    fn shelve(&mut self, to: PathRef) {
        if !self.params.cfg.enabled {
            return;
        }
        let set = &self.set;
        self.table
            .hold(to.transport, to.addr, |t, a| set.find(t, a).is_some());
    }

    /// A probe from the peer (draft Section 5.1, step 2): find or create
    /// its path, count the probe's `frame` there, record its `ACTIVE` flag,
    /// and answer it on the pair it came from. A path the probe created is
    /// probed in this step, and one it brought back from Dead, where path
    /// policy allows, at once. A
    /// probe that would create a path, or move one, against path policy
    /// (Section 5.5) is refused: not answered, and nothing learned or
    /// moved.
    fn probe(
        &mut self,
        now: C::Instant,
        from: PathRef,
        msg: PathProbe,
        frame: Option<(Option<u32>, usize)>,
        env: &Env<'_>,
        out: &mut Outputs<D>,
    ) {
        if !msg.answerable() {
            out.push(Output::Refused {
                to: from,
                why: Refusal::Short,
            });
            return;
        }
        let Some(i) = self.place(now, &from, &msg, env, out) else {
            return;
        };
        self.attribute(i, frame, now);
        self.flag(i, msg.flags.active());
        let Some(path) = self.set.get(i) else {
            return;
        };
        let live = path.live();
        let ack = PathAck {
            probe_id: msg.probe_id,
            flags: self.flags(i),
            path_id: path.path_id(),
            echo_path_id: msg.path_id,
            caps: caps(),
            rx_time_us: self.clock(now),
            rx_frames: live.frames(),
            rx_bytes: live.bytes(),
            len: ack_len(msg.len, env.facts.mtu(from.transport, &from.addr)),
        };
        out.push(Output::Send {
            to: from,
            bytes: ack.encode(),
        });
    }

    /// Find the path a probe from `from` concerns, in the draft's order: by
    /// the peer's `path_id` on the arrival transport, then by the pair, and
    /// otherwise a new Probing path within the limits. A path found by its
    /// identifier moves to the probe's address only when no other path
    /// holds that pair, and never while it is the link's original path and
    /// the only one. A Dead path found becomes Probing only where
    /// [`Self::revives`] allows it (draft Section 5.6, the Dead row for a
    /// probe received and accepted, "Policy allows" read as the rules for a
    /// path the probe would create): the peer's probe brings a Dead path
    /// other than the original back exactly where a probe from its pair
    /// could create a path. Elsewhere a probe that finds a held Dead path
    /// is answered and leaves it Dead, while one that finds no path at its
    /// pair is refused. Returns the path's index, or `None` with the probe
    /// refused.
    ///
    /// Path policy applies to creating a path and to moving one (draft
    /// Section 5.5 and Section 5.1, step 2, read as concerning a path the
    /// probe would create): a probe that finds a path at its own pair is
    /// taken whatever the rules, so the peer can prove a path this node
    /// only dials, the original path included.
    fn place(
        &mut self,
        now: C::Instant,
        from: &PathRef,
        msg: &PathProbe,
        env: &Env<'_>,
        out: &mut Outputs<D>,
    ) -> Option<usize> {
        let by_id = self.set.find_by_peer(from.transport, msg.path_id);
        let i = if let Some(i) = by_id {
            if let Err(rule) = self.follow(i, from, env, out) {
                out.push(Output::Refused {
                    to: from.clone(),
                    why: Refusal::Rule(rule),
                });
                return None;
            }
            i
        } else if let Some(i) = self.set.find(from.transport, &from.addr) {
            self.set.learn_peer(i, msg.path_id);
            i
        } else {
            if let Err(rule) = self.creates(from, env) {
                out.push(Output::Refused {
                    to: from.clone(),
                    why: Refusal::Rule(rule),
                });
                return None;
            }
            let i = self.admit(from.clone(), env, out)?;
            self.set.learn_peer(i, msg.path_id);
            self.note(i, None, Why::Probed, out);
            return Some(i);
        };
        if self.state(i) == Some(PathState::Dead) && self.revives(i, env).is_ok() {
            self.revive(i, now, Why::Probed, out);
        }
        Some(i)
    }

    /// An ack from the peer (draft Section 5.1, step 3): it matches one of
    /// our outstanding probes by (`echo_path_id`, `probe_id`), on whatever
    /// transport it arrives, the capability probe outstanding included
    /// (Section 5.2). Only a match records the peer's identifier, a round
    /// trip, the proven MTU and the peer's `ACTIVE` flag, and makes the
    /// path Live; a capability probe's answer gives no loss sample and
    /// proves no MTU. A matching answer, one in time or to the capability
    /// probe, ends a stop the path holds. An answer to a probe that has
    /// timed out gives a round trip and nothing else: it does not end a
    /// stop ([`Answer::matching`]). The ack's `frame` counts on the
    /// path of the probe it answers, on time or late. A match from a new
    /// address moves the path there only where path policy allows it, and
    /// never while it is the link's original path and the only one; a move
    /// refused or not made leaves the address as it was, and the rest of
    /// the match stands.
    fn ack(
        &mut self,
        now: C::Instant,
        from: PathRef,
        msg: PathAck,
        frame: Option<(Option<u32>, usize)>,
        env: &Env<'_>,
        out: &mut Outputs<D>,
    ) {
        let Some(i) = self.ours(msg.echo_path_id) else {
            out.push(Output::Refused {
                to: from,
                why: Refusal::Unmatched,
            });
            return;
        };
        let gap = self.params.cfg.standby_interval;
        let seek = self
            .set
            .path_mut(i)
            .and_then(|p| p.live_mut().seek_answer(msg.probe_id, gap));
        if let Some(len) = seek {
            self.attribute(i, frame, now);
            let raised = self
                .set
                .path_mut(i)
                .is_some_and(|p| p.live_mut().seek_proved(len, msg.len, now));
            if raised {
                self.proven(i, out);
            }
            return;
        }
        let ring = self
            .set
            .path_mut(i)
            .and_then(|p| p.live_mut().answer(msg.probe_id));
        let held = match ring {
            Some(_) => None,
            None => self.record.answer(msg.echo_path_id, msg.probe_id),
        };
        if ring.is_some() || held.is_some() {
            self.attribute(i, frame, now);
        }
        if (held.is_some() || ring.is_some_and(|a| a.matching()))
            && let Some(p) = self.set.path_mut(i)
        {
            p.live_mut().resume();
        }
        let window = self.params.window;
        let horizon = self.params.cfg.horizon;
        let sent = match (ring, held) {
            (Some(Answer::InTime(sent)), _) | (None, Some(sent)) => sent,
            (Some(Answer::Late(sent)), _) => {
                if let Some(p) = self.set.path_mut(i) {
                    p.live_mut().sample(
                        now,
                        now.saturating_duration_since(sent.at),
                        window,
                        horizon,
                    );
                }
                return;
            }
            (None, None) => {
                out.push(Output::Refused {
                    to: from,
                    why: Refusal::Unmatched,
                });
                return;
            }
        };
        self.set.learn_peer(i, msg.path_id);
        let Some(path) = self.set.path_mut(i) else {
            return;
        };
        let from_state = path.state();
        let live = path.live_mut();
        live.sample(now, now.saturating_duration_since(sent.at), window, horizon);
        // A capability probe is held outside the ring: its answer is no
        // loss sample, and at the smallest size it proves no MTU.
        let mut proved = false;
        if ring.is_some() {
            live.fold(true);
            // Only a probe padded past the smallest size proves an MTU.
            if sent.len > PATH_PROBE_MIN_SIZE {
                proved = live.prove(sent.len.min(msg.len));
            }
        }
        if proved {
            self.proven(i, out);
        }
        self.set.mark_acked(i);
        self.flag(i, msg.flags.active());
        // A move the rules refuse is skipped; the answer still counts.
        let _ = self.follow(i, &from, env, out);
        if from_state != PathState::Live {
            self.shift(i, PathState::Live, now, Why::Answered, out);
        }
    }

    /// A close from the peer, naming our identifier for the path (draft
    /// Section 7.4): a Live or Suspect path becomes Dead.
    fn closed(&mut self, now: C::Instant, from: PathRef, msg: PathClose, out: &mut Outputs<D>) {
        let Some(i) = self.ours(msg.path_id) else {
            out.push(Output::Refused {
                to: from,
                why: Refusal::Unknown,
            });
            return;
        };
        let Some(state) = self.set.get(i).map(PeerPath::state) else {
            return;
        };
        match state {
            PathState::Live | PathState::Suspect => {
                self.shift(i, PathState::Dead, now, Why::Closed, out);
            }
            PathState::Probing | PathState::Dead => {}
        }
    }

    /// The local transport `transport` lost or regained carrier (draft
    /// Section 5.6). On a loss, the peer is told of each path on it (draft
    /// Section 5.8), and each Live path on it becomes Suspect; nothing else
    /// changes. On a return, each Dead path held on it, acked or not,
    /// becomes Probing where [`Self::again`] allows it, its first probe
    /// held to the floor ([`Self::revive`]), and every candidate held back
    /// on it is released and offered for admission.
    fn carrier(
        &mut self,
        now: C::Instant,
        transport: TransportId,
        up: bool,
        env: &Env<'_>,
        out: &mut Outputs<D>,
    ) {
        if !up {
            self.farewell(transport, PathCloseReason::CarrierLost, out);
        }
        for i in 0..self.set.len() {
            let Some(path) = self.set.get(i) else {
                continue;
            };
            if path.transport_id() != transport {
                continue;
            }
            match (path.state(), up) {
                (PathState::Live, false) => {
                    self.shift(i, PathState::Suspect, now, Why::Carrier, out);
                }
                (PathState::Dead, true) => {
                    if self.again(i, env).is_ok() {
                        self.revive(i, now, Why::Returned, out);
                    }
                }
                (PathState::Probing | PathState::Suspect | PathState::Dead, false)
                | (PathState::Probing | PathState::Live | PathState::Suspect, true) => {}
            }
        }
        if up {
            let released = self.table.release(transport);
            self.enlists(released, env, out);
        }
    }

    /// A send on `to` failed as unreachable: its path becomes Suspect if it
    /// is Live (draft Section 5.6).
    fn unreachable(&mut self, now: C::Instant, to: PathRef, out: &mut Outputs<D>) {
        let Some(i) = self.set.find(to.transport, &to.addr) else {
            return;
        };
        if self.state(i) == Some(PathState::Live) {
            self.shift(i, PathState::Suspect, now, Why::Unreachable, out);
        }
    }

    /// The connection asked for to `to` settled (`ok`). Only a path whose
    /// connection was being opened takes the report; for any other it
    /// changes nothing. An opened connection has the path probed at once.
    /// On a path that has stopped answering, a connection asked for on a
    /// slot of its own cadence counted that slot; once it opens, the next
    /// probe on the cadence waits at least the gap that slot used, from
    /// the opening. A failed one counts as one unanswered discovery probe:
    /// the next connection is asked for a discovery interval on, and with
    /// `discovery` failures in a row the Probing path becomes Dead.
    fn connected(&mut self, now: C::Instant, to: PathRef, ok: bool, out: &mut Outputs<D>) {
        let Some(i) = self.set.find(to.transport, &to.addr) else {
            return;
        };
        let discovery = u32::from(self.params.cfg.discovery);
        let probing = self.state(i) == Some(PathState::Probing);
        let Some(live) = self.set.path_mut(i).map(PeerPath::live_mut) else {
            return;
        };
        if !live.settle(ok) {
            return;
        }
        live.rebase(now, ok);
        if ok {
            live.urge();
            return;
        }
        if probing && live.misses() >= discovery {
            self.shift(i, PathState::Dead, now, Why::Connect, out);
            return;
        }
        let interval = self.interval(i);
        if let Some(p) = self.set.path_mut(i) {
            p.live_mut().schedule(Some(deadline(now, interval)));
        }
    }

    /// The local transport `transport` was removed, or its interface left
    /// (`absent`) (draft Section 5.6): the peer is told of each path on it
    /// (draft Section 5.8), and then every path on it is discarded at once,
    /// the active path included. An absent interface's candidates are held
    /// back, the discarded pairs among them, until it comes back; a removed
    /// transport's are forgotten. Either way a pin of the transport is
    /// lifted.
    fn removed(&mut self, transport: TransportId, absent: bool, out: &mut Outputs<D>) {
        if self
            .pin
            .as_ref()
            .is_some_and(|pin| pin.transport == transport)
        {
            self.pin = None;
        }
        if absent && self.params.cfg.enabled {
            self.table.absent(transport);
        }
        self.farewell(transport, PathCloseReason::InterfaceGone, out);
        let mut i = 0;
        while i < self.set.len() {
            let on = self
                .set
                .get(i)
                .is_some_and(|p| p.transport_id() == transport);
            match on.then(|| self.set.discard(i)).flatten() {
                Some(p) => {
                    let to = pair(&p);
                    self.release(p, Why::Removed, out);
                    if absent {
                        self.shelve(to);
                    }
                }
                None => i += 1,
            }
        }
        if !absent {
            self.table.forget(transport);
        }
    }

    /// Tell a capable peer that each path on `transport` whose identifier
    /// it gave us is going away, for `reason` (draft Section 5.8): one
    /// `PathClose` per path, naming the peer's identifier for it, all on
    /// the one Live path [`Self::away`] picks off that transport. With no
    /// such path, nothing is sent.
    fn farewell(&self, transport: TransportId, reason: PathCloseReason, out: &mut Outputs<D>) {
        if !self.speaks() {
            return;
        }
        let Some(via) = self.away(transport).and_then(|i| self.set.get(i)).map(pair) else {
            return;
        };
        for p in self.set.paths() {
            if p.transport_id() != transport {
                continue;
            }
            let Some(path_id) = p.peer_id() else {
                continue;
            };
            out.push(Output::Send {
                to: via.clone(),
                bytes: PathClose { path_id, reason }.encode().to_vec(),
            });
        }
    }

    /// The path a close of the paths on `transport` travels on: our active
    /// path when it is Live and not on that transport, else the Live path
    /// of lowest index not on it. Never a path on the transport closing.
    fn away(&self, transport: TransportId) -> Option<usize> {
        let usable = |i: &usize| {
            self.set
                .get(*i)
                .is_some_and(|p| p.state() == PathState::Live && p.transport_id() != transport)
        };
        self.set
            .active_index()
            .filter(usable)
            .or_else(|| (0..self.set.len()).find(usable))
    }

    /// Choose the active path after the input and the expiry (draft
    /// Section 5.7), given the active path's identifier and state before
    /// the step.
    ///
    /// A Suspect active path gives way to the best Live path, and a Dead
    /// one, or one being probed again after Dead, to the best Live path,
    /// else the best acked Suspect path; otherwise it stays active. With
    /// the active path discarded, the best Live path takes its place, else
    /// the best acked Suspect path, else the acked path most recently Live;
    /// with no acked path left, the bundle is orphaned and this returns
    /// false. The best Live path is the one [`Self::rank`] takes: of those
    /// the operator's pin names, while it names any, of the highest tier
    /// present, and of those that carry a `FilterAnnounce`, while any
    /// does, by score among the paths with enough samples, a preferred one
    /// within the switch margin of the best first; the best
    /// acked Suspect path has the least latest round trip ([`Self::best`]),
    /// whatever its tier. A Live active path gives way only by the
    /// discretionary change of [`Self::better`].
    /// Every change of active path, and every step at which the active path
    /// is not Live, ends the switch dwell. Every change holds the link's
    /// cost at `held`, the cost at the start of the step, which is the
    /// cost of a hold still in force if there is one, and records the path
    /// it left if it was mandatory, so a return to that path once it is
    /// Live again needs no switch margin ([`Self::better`]). When the active path
    /// became Suspect or Dead or was discarded in this step and no path is
    /// Live, every acked Dead path that [`Self::again`] allows, and every
    /// acked path being probed again after Dead, is probed at once
    /// ([`Self::rescued`]), within the discovery limit [`Self::sends`]
    /// applies. With nothing Live, the path made active in place of a
    /// discarded active path is probed at once too (Section 5.7): a
    /// Suspect or Probing one here, and a Dead one by that rule, where the
    /// probe rules allow it, as Section 5.6 has it.
    fn select(
        &mut self,
        now: C::Instant,
        held: f64,
        before: Option<(u32, PathState)>,
        env: &Env<'_>,
        out: &mut Outputs<D>,
    ) -> bool {
        let active = self.set.active_index();
        if active.and_then(|a| self.state(a)) != Some(PathState::Live) {
            self.dwell = None;
        }
        let next = match active {
            None => {
                let Some(i) = self
                    .rank(None, env)
                    .or_else(|| self.best(PathState::Suspect))
                    .or_else(|| self.recent())
                else {
                    self.orphaned = true;
                    out.push(Output::Orphaned);
                    return false;
                };
                Some((i, None, Switch::Handover))
            }
            Some(a) => {
                let to = match self.state(a) {
                    Some(PathState::Suspect) => {
                        self.rank(Some(a), env).map(|i| (i, Switch::Mandatory))
                    }
                    Some(PathState::Dead | PathState::Probing) => self
                        .rank(Some(a), env)
                        .or_else(|| self.best(PathState::Suspect))
                        .map(|i| (i, Switch::Mandatory)),
                    Some(PathState::Live) => self.better(now, a, env),
                    None => None,
                };
                to.map(|(i, why)| (i, Some(a), why))
            }
        };
        if let Some((i, from, why)) = next {
            self.dwell = None;
            if from.is_none()
                && !self.any_live()
                && let Some(p) = self.set.path_mut(i)
                && matches!(p.state(), PathState::Suspect | PathState::Probing)
            {
                p.live_mut().urge();
            }
            let from = from.and_then(|a| self.set.get(a));
            let left = from
                .map(PeerPath::path_id)
                .filter(|_| why == Switch::Mandatory);
            let from = from.map(pair);
            if self.set.activate(i)
                && let Some(p) = self.set.get(i)
            {
                self.left = left;
                out.push(Output::Switched {
                    from,
                    to: pair(p),
                    why,
                });
                self.hold = Some(Hold::new(held, now));
            }
        }
        if self.failed(before) && !self.any_live() {
            for i in 0..self.set.len() {
                if self.rescued(i, env)
                    && let Some(p) = self.set.path_mut(i)
                {
                    p.live_mut().urge();
                }
            }
        }
        true
    }

    /// Whether path `i` is probed at once when the active path fails with
    /// nothing Live (Section 5.7): an acked path that is Dead, where
    /// [`Self::again`] allows it, or that is being probed again after Dead,
    /// whether the peer's probe, its carrier's return or its rediscovery
    /// brought it back. The discovery limit is applied where the probe is
    /// sent ([`Self::sends`]).
    fn rescued(&self, i: usize, env: &Env<'_>) -> bool {
        match self.set.get(i) {
            Some(p) if p.acked() => match p.state() {
                PathState::Dead => self.again(i, env).is_ok(),
                PathState::Probing => true,
                PathState::Live | PathState::Suspect => false,
            },
            _ => false,
        }
    }

    /// The Live, acked paths, each in its slot as a rival of a choice: its
    /// score once it has `min_samples` round-trip samples, its latest round
    /// trip, the tier of its transport's role, read from the facts, whether
    /// it carries a `FilterAnnounce`, by its link MTU from the facts or the
    /// smaller size it is proven to carry where that counts
    /// (`select::carried`), its medium, read from the facts, and whether the
    /// operator's pin names it.
    fn rivals(&self, env: &Env<'_>) -> Field {
        let min = usize::from(self.params.cfg.min_samples);
        let mut field: Field = [None; PATH_MAX_PER_PEER];
        for (i, p) in self.set.paths().iter().enumerate() {
            if !contends(p) {
                continue;
            }
            let live = p.live();
            let role = env.facts.role(p.transport_id());
            let carried = select::carried(
                env.facts.mtu(p.transport_id(), p.addr()),
                live.mtu(),
                env.facts.oriented(p.transport_id()),
            );
            let rival = Rival {
                index: i,
                score: select::score(live).filter(|_| live.samples() >= min),
                rtt: live.rtt(),
                steady: select::steady(live).filter(|_| live.samples() >= min),
                base: live.base_rtt(),
                tier: select::tier(role),
                preferred: role == Role::Preferred,
                pinned: self.pin.as_ref().is_some_and(|pin| pin.names(&pair(p))),
                fits: carried >= select::FILTER_FRAME,
                medium: env.facts.medium(p.transport_id(), p.addr()),
            };
            if let Some(slot) = field.get_mut(i) {
                *slot = Some(rival);
            }
        }
        field
    }

    /// The best Live, acked path other than `active`, as
    /// [`select::choose`] ranks them: of those the operator's pin names,
    /// while it names any, of the highest tier present, and of those that
    /// carry a `FilterAnnounce`, while any does, the least score among the
    /// paths with enough samples, unless a preferred one scores within the
    /// switch margin of it, else the least latest round trip.
    fn rank(&self, active: Option<usize>, env: &Env<'_>) -> Option<usize> {
        let mut field = self.rivals(env);
        if let Some(slot) = active.and_then(|a| field.get_mut(a)) {
            *slot = None;
        }
        select::choose(&field, self.params.cfg.switch_margin)
    }

    /// The discretionary change from the Live active path `a` at `now`, if
    /// one is due (draft Section 5.7 and its note, and the note of Section
    /// 5.5), to the Live, acked path [`select::choose`] ranks first. When
    /// the operator's pin names that path and not `a`, the change is due at
    /// once, as [`Switch::Pinned`], whatever its tier and samples. When
    /// its tier is higher than `a`'s, the change is due at once, whatever
    /// its samples, so a backup or never path gives way as soon as a path
    /// of a higher tier is Live. Otherwise the path must have
    /// enough samples to be scored, and either carry a `FilterAnnounce`
    /// while `a` cannot, be preferred while `a` is not, run over a known
    /// medium faster than `a`'s, also known ([`select::quicker`]), or score
    /// better than `a`, also scored, by more than the switch margin, or by
    /// any amount when the latest change of active path was mandatory and
    /// left it, or `a`, scored, must score more than the switch margin
    /// times the best score [`select::best`] finds, so it holds the link by
    /// no precedence (the path taken may itself hold its place by one); a
    /// change for any of those last three, on score, waits
    /// while [`select::held`] holds it, and a change for a faster medium
    /// while [`select::waits`] holds it, so load on `a` alone does not hand
    /// the link to a path slower at its best; and that must hold at every
    /// step for the switch dwell.
    /// The dwell starts at the first step at which it holds, starts again
    /// when the path ranked first changes, and ends at any step at which it
    /// does not hold, so a path that only scores the same as `a` never
    /// takes its place unless it alone carries a `FilterAnnounce`, is
    /// preferred, or runs over a faster known medium.
    fn better(&mut self, now: C::Instant, a: usize, env: &Env<'_>) -> Option<(usize, Switch)> {
        let margin = self.params.cfg.switch_margin;
        let field = self.rivals(env);
        let rival = |i: usize| field.get(i).copied().flatten();
        let pick = select::choose(&field, margin)
            .filter(|&t| t != a)
            .and_then(rival)
            .zip(rival(a));
        if let Some((to, from)) = pick {
            if to.pinned && !from.pinned {
                return Some((to.index, Switch::Pinned));
            }
            if to.tier > from.tier {
                return Some((to.index, Switch::Discretionary));
            }
        }
        let best = select::best(&field);
        let back = |to: &Rival| {
            self.left
                .is_some_and(|id| self.set.get(to.index).map(PeerPath::path_id) == Some(id))
                && !node_fault!(ReturnNeedsMargin)
        };
        let target = pick
            .filter(|(to, from)| {
                to.score.is_some_and(|st| {
                    let scored = from
                        .score
                        .is_some_and(|s| s > st * margin || best.is_some_and(|b| s > b * margin))
                        || (back(to) && from.score.is_some_and(|s| s > st));
                    (to.fits && !from.fits)
                        || (to.preferred && !from.preferred)
                        || (select::quicker(to.medium, from.medium)
                            && !select::waits(to, from, margin))
                        || (scored && !select::held(to, from, margin))
                })
            })
            .and_then(|(to, _)| self.set.get(to.index).map(|p| (to.index, p.path_id())));
        let Some((t, id)) = target else {
            self.dwell = None;
            return None;
        };
        let start = match self.dwell {
            Some((held, start)) if held == id => start,
            Some(_) | None => {
                self.dwell = Some((id, now));
                now
            }
        };
        let due = deadline(start, self.params.cfg.switch_dwell);
        (now >= due).then_some((t, Switch::Discretionary))
    }

    /// The acked path in `state` with the least latest round trip, one
    /// with none measured last, the lower index on a tie: how an acked
    /// Suspect path is chosen when no path is Live.
    fn best(&self, state: PathState) -> Option<usize> {
        self.set
            .paths()
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state() == state && p.acked())
            .min_by_key(|(i, p)| (p.live().rtt().is_none(), p.live().rtt(), *i))
            .map(|(i, _)| i)
    }

    /// The acked path, Dead or being probed again after Dead, that left
    /// Live most recently, the lower index on a tie.
    fn recent(&self) -> Option<usize> {
        self.set
            .paths()
            .iter()
            .enumerate()
            .filter(|(_, p)| p.acked() && matches!(p.state(), PathState::Dead | PathState::Probing))
            .min_by_key(|(i, p)| {
                let at = p.live().live_at();
                (at.is_none(), Reverse(at), *i)
            })
            .map(|(i, _)| i)
    }

    /// Whether the path active before the step, `before`, became Suspect
    /// or Dead in it, or was discarded.
    fn failed(&self, before: Option<(u32, PathState)>) -> bool {
        let Some((id, was)) = before else {
            return false;
        };
        match self.ours(id).and_then(|i| self.state(i)) {
            None => true,
            Some(now) => now != was && matches!(now, PathState::Suspect | PathState::Dead),
        }
    }

    /// Apply each trip [`Self::charge`] recorded, in set order: the path
    /// becomes Dead as of the failure that tripped it (draft Section 5.6),
    /// if it may still trip. A trip that no longer may, since the paths
    /// that made it possible have left Live or Suspect, is dropped.
    fn trips(&mut self, out: &mut Outputs<D>) {
        for i in 0..self.set.len() {
            let Some(at) = self.set.path_mut(i).and_then(|p| p.live_mut().untrip()) else {
                continue;
            };
            if self.trippable(i) {
                self.shift(i, PathState::Dead, at, Why::AuthLimit, out);
            }
        }
    }

    /// Whether path `i` may be marked Dead for its authentication failures
    /// (draft Sections 5.3 and 5.6): it is Live or Suspect, and another
    /// path is Live or acked Suspect.
    fn trippable(&self, i: usize) -> bool {
        let open = matches!(self.state(i), Some(PathState::Live | PathState::Suspect));
        let other = self.set.paths().iter().enumerate().any(|(j, p)| {
            j != i
                && (p.state() == PathState::Live || (p.state() == PathState::Suspect && p.acked()))
        });
        open && other
    }

    /// Time out every probe due by `now`, or with `overdue` only those due
    /// before `now`, oldest first on each path, except one whose verdict
    /// waits for the verdict cap while the peer's session datagrams arrive
    /// on its path (`Liveness::expire`), and apply the state changes
    /// the counts cause (draft Section 5.6): a Live path with `suspect` in
    /// a row becomes Suspect, a Suspect one with `retire` becomes Dead, and
    /// a Probing one with `discovery` becomes Dead. A Dead path's count
    /// only spaces its probes. Only a Live path's timeouts are ETX loss
    /// samples. A capability probe timed out counts on no path; the last
    /// of the first round reports the link not capable (Section 5.2).
    fn expire(&mut self, now: C::Instant, overdue: bool, out: &mut Outputs<D>) {
        let cfg = self.params.cfg;
        for i in 0..self.set.len() {
            loop {
                let Some(path) = self.set.path_mut(i) else {
                    break;
                };
                let state = path.state();
                let live = path.live_mut();
                let Some(counted) = live.expire(now, overdue, cfg.verdict_cap) else {
                    break;
                };
                if !counted {
                    continue;
                }
                if state == PathState::Live {
                    live.fold(false);
                }
                let misses = live.misses();
                let next = match state {
                    PathState::Live if misses >= u32::from(cfg.suspect) => {
                        Some((PathState::Suspect, Why::Timeout))
                    }
                    PathState::Suspect if misses >= u32::from(cfg.retire) => {
                        Some((PathState::Dead, Why::Retired))
                    }
                    PathState::Probing if misses >= u32::from(cfg.discovery) => {
                        Some((PathState::Dead, Why::Exhausted))
                    }
                    PathState::Probing | PathState::Live | PathState::Suspect | PathState::Dead => {
                        None
                    }
                };
                if let Some((next, why)) = next {
                    self.shift(i, next, now, why, out);
                }
            }
        }
        if let Some((sent, round)) = self.record.expire(now, overdue, &cfg) {
            self.lapse(sent);
            if round {
                out.push(Output::NotCapable);
            }
        }
    }

    /// Discard each Dead path whose grace has ended (draft Section 5.6):
    /// one never acked, and an acked one only while a path of the link is
    /// Live. The active path is never discarded here. Nothing schedules a
    /// discarded pair again: it is held back.
    fn grace(&mut self, now: C::Instant, out: &mut Outputs<D>) {
        let live = self.any_live();
        let mut i = 0;
        while i < self.set.len() {
            if self.ends(i, live).is_some_and(|end| end <= now) {
                if let Some(p) = self.set.discard(i) {
                    let to = pair(&p);
                    self.release(p, Why::Grace, out);
                    self.shelve(to);
                }
            } else {
                i += 1;
            }
        }
    }

    /// Send the capability probe due, if any ([`Self::ask`]), then each
    /// probe due: on a probed path whose next probe is due and has room in
    /// its ring, or that asked for one at once. A path that needs a
    /// connection has one asked for in place of the probe. Every request
    /// for a probe at once ends here, sent or not. A probe on its own
    /// cadence of a path that has stopped answering, or the connection
    /// asked for in its place, waits for the floor's instant and is
    /// counted there; one asked for at once is neither held nor counted. A
    /// Probing path sends nothing once it has sent `discovery` probes
    /// ([`Self::spent`]); one asked for at once then is dropped, and the
    /// path becomes Dead when the last times out. No probed path's next
    /// probe is left further off than one interval of its cadence, or the
    /// floor's instant, whichever is later. A Dead path's probe, at its
    /// cadence or at once, goes only where [`Self::again`] allows it. One
    /// refused at once is dropped; one refused at its cadence is put off
    /// by an interval, unsent and not counted, so the rules are read again
    /// then.
    fn sends(&mut self, now: C::Instant, env: &Env<'_>, out: &mut Outputs<D>) {
        self.ask(now, env, out);
        for i in 0..self.set.len() {
            let urgent = self
                .set
                .path_mut(i)
                .is_some_and(|p| p.live_mut().take_urgent());
            if !self.probed(i) {
                continue;
            }
            self.pace(i, now);
            let cap = self.cap(i, urgent);
            let ready = self.set.get(i).is_some_and(|p| {
                let live = p.live();
                live.room(cap) && (urgent || live.next_at().is_none_or(|at| at <= now))
            });
            if !ready {
                continue;
            }
            if self.spent(i) {
                continue;
            }
            let held = if urgent { None } else { self.stopped(i, now) };
            if let Some(free) = held.filter(|free| now < *free) {
                if let Some(p) = self.set.path_mut(i) {
                    p.live_mut().schedule(Some(free));
                }
                continue;
            }
            if self.state(i) == Some(PathState::Dead) && self.again(i, env).is_err() {
                let interval = self.interval(i);
                if let Some(p) = self.set.path_mut(i) {
                    let live = p.live_mut();
                    if live.next_at().is_none_or(|at| at <= now) {
                        live.schedule(Some(deadline(now, interval)));
                    }
                }
                continue;
            }
            if self.set.get(i).is_some_and(|p| p.live().unlinked()) {
                self.connect(i, out);
                if held.is_some()
                    && let Some(p) = self.set.path_mut(i)
                {
                    let live = p.live_mut();
                    live.spend(now);
                    live.owe();
                }
            } else {
                let seeks = !urgent && held.is_none();
                if seeks && !node_fault!(SeekCountsLoss) {
                    self.seek(i, now, env, out);
                }
                self.send(i, now, env, out);
                if seeks && node_fault!(SeekCountsLoss) {
                    self.seek(i, now, env, out);
                }
                if held.is_some()
                    && let Some(p) = self.set.path_mut(i)
                {
                    let live = p.live_mut();
                    live.spend(now);
                    let next = live.next_at().max(live.held());
                    live.schedule(next);
                }
            }
        }
    }

    /// Whether path `i` has stopped answering (draft Section 5.6), and if
    /// so the instant from which its next probe on its own cadence may go.
    /// A path that is not Probing stops once `PATH_SILENCE_MAX` has passed
    /// since the earliest probe no matching answer has followed, at that
    /// instant, if it has not already; entering Dead stops it too
    /// ([`Self::shift`]). A stop, once held, holds whatever the path's
    /// state, a Probing path brought back by carrier or rediscovery
    /// included, until a matching answer or the peer's probe bringing the
    /// path back from Dead ends it.
    fn stopped(&mut self, i: usize, now: C::Instant) -> Option<C::Instant> {
        let probing = self.state(i) == Some(PathState::Probing);
        let active = self.set.active_index() == Some(i);
        let live = self.set.path_mut(i)?.live_mut();
        if !probing
            && !live.stopped()
            && let Some(at) = live.quiet().map(|quiet| deadline(quiet, PATH_SILENCE_MAX))
            && at <= now
        {
            live.halt(at, active);
        }
        live.held()
    }

    /// Whether path `i` is Probing and has sent all `discovery` probes it
    /// may (draft Section 5.6, the Probing rows; `MAX_DISCOVERY_PROBES`,
    /// Appendix A): every probe sent while Probing counts, at once or on
    /// the cadence, the unanswered ones and those still outstanding. A
    /// probe still outstanding from before the path left Dead is counted
    /// here only until it times out, which counts as no miss, so it can
    /// put a probe off but never takes one of the eight.
    fn spent(&self, i: usize) -> bool {
        let limit = usize::from(self.params.cfg.discovery);
        self.state(i) == Some(PathState::Probing)
            && self.set.get(i).is_some_and(|p| {
                let live = p.live();
                live.misses() as usize + live.outstanding() >= limit
            })
    }

    /// Bring path `i`'s next probe to no later than one interval of its
    /// cadence from `now`. Each probe schedules the next at the interval of
    /// the moment it went, so a path whose cadence has since quickened (one
    /// answered back to Live from Dead or Probing, made our active path, or
    /// marked `ACTIVE` by the peer) is probed at its new cadence from now
    /// on, not when the old interval ends (draft Section 5.6). A path that
    /// has stopped answering is not brought earlier than the floor's
    /// instant ([`Self::stopped`]).
    fn pace(&mut self, i: usize, now: C::Instant) {
        let by = deadline(now, self.interval(i));
        let by = self.stopped(i, now).map_or(by, |free| by.max(free));
        if let Some(p) = self.set.path_mut(i) {
            let live = p.live_mut();
            if live.next_at().is_some_and(|at| at > by) {
                live.schedule(Some(by));
            }
        }
    }

    /// Ask the host to open a connection for path `i`, in place of its
    /// probe. Nothing is probed on the path until the connection settles.
    fn connect(&mut self, i: usize, out: &mut Outputs<D>) {
        let Some(path) = self.set.path_mut(i) else {
            return;
        };
        path.live_mut().dial();
        out.push(Output::Connect { to: pair(path) });
    }

    /// Admit `to` under the path limits, handing back the Dead path
    /// discarded to make room, if one was, and holding back its pair;
    /// refuse it when no room can be made.
    fn admit(&mut self, to: PathRef, env: &Env<'_>, out: &mut Outputs<D>) -> Option<usize> {
        let medium = env.facts.medium(to.transport, &to.addr);
        match self
            .set
            .admit(to.transport, to.addr.clone(), medium, draw::<E>)
        {
            Ok(Admission::Added { index, evicted }) => {
                if let Some(p) = evicted {
                    let gone = pair(&p);
                    self.release(p, Why::Evicted, out);
                    self.shelve(gone);
                }
                Some(index)
            }
            Ok(Admission::Known(index)) => Some(index),
            Err(_) => {
                out.push(Output::Refused {
                    to,
                    why: Refusal::Full,
                });
                None
            }
        }
    }

    /// Log a path discarded for `why`, and hand back its slot, marked to
    /// keep if the peer still sends on the path or is not known to be
    /// capable.
    fn release(&mut self, p: PeerPath<C::Instant, D>, why: Why, out: &mut Outputs<D>) {
        if self.original == Some(p.path_id()) {
            self.original = None;
        }
        out.push(Output::State {
            to: pair(&p),
            path_id: p.path_id(),
            from: Some(p.state()),
            next: None,
            why,
        });
        out.push(Output::Released {
            to: pair(&p),
            keep: !self.capable || self.peer_active == Some(p.path_id()),
            driver: p.into_driver(),
        });
    }

    /// Count the frame of the path message being stepped, `frame` as
    /// [`Self::account`] took it, on path `i`, the path the message
    /// concerns (draft Sections 5.1 and 5.3), when the frame's pair gave
    /// it to another path or to none: the frame leaves that path's counts
    /// and joins path `i`'s.
    fn attribute(&mut self, i: usize, frame: Option<(Option<u32>, usize)>, now: C::Instant) {
        let Some((from, len)) = frame else {
            return;
        };
        if self.set.get(i).map(PeerPath::path_id) == from {
            return;
        }
        let was = from.and_then(|id| self.ours(id));
        if let Some(p) = was.and_then(|j| self.set.path_mut(j)) {
            p.live_mut().shed(len);
        }
        if let Some(p) = self.set.path_mut(i) {
            p.live_mut().heard(len, now);
        }
    }

    /// Whether the link holds only its original path: only then may a
    /// frame roam a path, as FMP v1's rule for the peer's address does
    /// (draft Section 5.3).
    fn single(&self) -> bool {
        self.set.len() == 1 && self.set.get(0).map(PeerPath::path_id) == self.original
    }

    /// Move path `i` to the address of `to` when an authenticated path
    /// message attributed to it arrives from there, on its own transport,
    /// and no other path holds that pair (draft Section 5.3), unless path
    /// policy refuses the path at its new address (Section 5.5): a moved
    /// path is probed there. The original path is never refused. While the
    /// link's only path is its original path no path message moves it,
    /// since FMP v1's address rule governs that path (Section 5.3). The
    /// slot that aimed at the old address goes back to the host.
    fn follow(
        &mut self,
        i: usize,
        to: &PathRef,
        env: &Env<'_>,
        out: &mut Outputs<D>,
    ) -> Result<(), Rule> {
        if self
            .set
            .get(i)
            .is_none_or(|p| p.transport_id() != to.transport)
            || self.set.find(to.transport, &to.addr).is_some()
            || self.single()
        {
            return Ok(());
        }
        if !self.first(i) {
            rules::moves(env.facts, self.scope, self.mixed(), to.transport, &to.addr)?;
        }
        let Some(old) = self.set.readdress(i, to.addr.clone()) else {
            return Ok(());
        };
        let Some(path) = self.set.path_mut(i) else {
            return Ok(());
        };
        out.push(Output::Moved {
            from: PathRef {
                transport: to.transport,
                addr: old,
            },
            to: to.clone(),
            driver: path.take_driver(),
        });
        Ok(())
    }

    /// Whether path `i` is the link's original path.
    fn first(&self, i: usize) -> bool {
        self.original.is_some() && self.set.get(i).map(PeerPath::path_id) == self.original
    }

    /// Whether kinds may be mixed in the link's paths.
    fn mixed(&self) -> bool {
        self.params.cfg.mix_kinds
    }

    /// Whether path policy lets this node probe `to` as a new path: a
    /// candidate (draft Sections 5.1, step 1, and 5.5).
    fn probes(&self, to: &PathRef, env: &Env<'_>) -> Result<(), Rule> {
        rules::probe(env.facts, self.scope, self.mixed(), to.transport, &to.addr)
    }

    /// Whether path policy lets a probe from `to` create a path there
    /// (draft Sections 5.1, step 2, and 5.5).
    fn creates(&self, to: &PathRef, env: &Env<'_>) -> Result<(), Rule> {
        rules::admit(env.facts, self.scope, self.mixed(), to.transport, &to.addr)
    }

    /// Whether path policy lets this node probe the held Dead path `i`
    /// again: on carrier's return, on finding the peer again, at the Dead
    /// cadence, at once when the active path leaves Live or when asked for
    /// at once otherwise (draft Section 5.6, "Policy allows"), read as the
    /// rules for probing a candidate, the original path always
    /// ([`Self::holds`]).
    fn again(&self, i: usize, env: &Env<'_>) -> Result<(), Rule> {
        self.holds(i, env, rules::probe)
    }

    /// Whether path policy lets the peer's accepted probe bring the held
    /// Dead path `i` back to Probing (draft Section 5.6, the Dead row for a
    /// probe received and accepted, "Policy allows"), read as the rules for
    /// a path that probe would create (Sections 5.1, step 2, and 5.5), the
    /// original path always ([`Self::holds`]).
    fn revives(&self, i: usize, env: &Env<'_>) -> Result<(), Rule> {
        self.holds(i, env, rules::admit)
    }

    /// Whether `rule` allows the held path `i` at its pair. The original
    /// path defines the link's class and kind and is always allowed,
    /// whatever the rules, a peer the ACL denies included.
    fn holds(&self, i: usize, env: &Env<'_>, rule: rules::Check) -> Result<(), Rule> {
        let Some(p) = self.set.get(i) else {
            return Ok(());
        };
        if self.first(i) {
            return Ok(());
        }
        rule(
            env.facts,
            self.scope,
            self.mixed(),
            p.transport_id(),
            p.addr(),
        )
    }

    /// Send a capability probe, while the peer is not known to be capable
    /// and multipath is enabled (draft Section 5.2): only while a
    /// candidate allows it ([`Self::gate`], read now), one at a time, at
    /// the record's schedule, on the original path, of the smallest size,
    /// carrying the original path's identifier and a `probe_id` of its
    /// sequence. The probe is held in the record, not the path's ring.
    fn ask(&mut self, now: C::Instant, env: &Env<'_>, out: &mut Outputs<D>) {
        if !self.params.cfg.enabled || self.capable {
            return;
        }
        let open = self.gate(env);
        self.eligible = open;
        if !open || !self.record.due(now) {
            return;
        }
        let Some(i) = self.original.and_then(|id| self.ours(id)) else {
            return;
        };
        let flags = self.flags(i);
        let cfg = self.params.cfg;
        let Some(path) = self.set.path_mut(i) else {
            return;
        };
        let to = pair(path);
        let path_id = path.path_id();
        let live = path.live_mut();
        let timeout = live.timeout(cfg.timeout, cfg.verdict_cap);
        let probe_id = live.take_id(draw::<E>);
        self.record.send(now, path_id, probe_id, timeout, &cfg);
        let msg = PathProbe::new(probe_id, path_id, flags, caps()).with_len(PATH_PROBE_MIN_SIZE);
        out.push(Output::Send {
            to,
            bytes: msg.encode(),
        });
    }

    /// Whether the link holds a candidate that allows capability probes
    /// (draft Section 5.2): one not held back, whose pair is not held as a
    /// path, that path policy lets this node probe under the facts now.
    fn gate(&self, env: &Env<'_>) -> bool {
        self.table.iter().any(|e| {
            !e.held()
                && self.set.find(e.transport(), e.addr()).is_none()
                && rules::probe(env.facts, self.scope, self.mixed(), e.transport(), e.addr())
                    .is_ok()
        })
    }

    /// Keep a capability probe that timed out, or that the peer turned
    /// capable before answering, in the original path's record of
    /// timed-out probes: an answer to it gives a round trip and nothing
    /// else.
    fn lapse(&mut self, sent: Sent<C::Instant>) {
        let original = self.original.and_then(|id| self.ours(id));
        if let Some(p) = original.and_then(|i| self.set.path_mut(i)) {
            p.live_mut().lapse(sent);
        }
    }

    /// Send a probe on path `i`, and schedule the next. While the path is
    /// unproven, Probing or Dead it is padded to the link MTU (draft
    /// Section 5.1, step 1, where padding is local), except that once a
    /// padded probe of its current state has gone unanswered its sizes
    /// step down a ladder, the smallest last (`Liveness::size`): a hop
    /// narrower than our link MTU, or a receiver whose buffer is smaller,
    /// drops a padded probe, and the first size answered is proven; a
    /// smallest one answered proves the path, though no MTU, so a path
    /// proven so is no worse off than a link of one path between two nodes
    /// whose MTUs differ. Each change of the size proven goes to the shell
    /// in an `Output::Proven`, and a Live path proven below its link MTU
    /// searches upward beside these probes ([`Self::seek`]). A Dead path
    /// on a connection-oriented transport, re-checked after it carried the
    /// link, that has proven a size is probed at that size, not on the
    /// ladder, so its probes never close the connection with one oversized.
    /// On a connectionless transport such a path keeps the ladder, so a
    /// path whose MTU shrank during its outage is still found. Otherwise the probe is of the smallest size. It goes unanswered
    /// after the probe timeout. Nothing goes when the path's ring is full.
    fn send(&mut self, i: usize, now: C::Instant, env: &Env<'_>, out: &mut Outputs<D>) {
        let flags = self.flags(i);
        let interval = self.interval(i);
        let floor = self.params.cfg.timeout;
        let cap = self.params.cfg.verdict_cap;
        let Some(path) = self.set.path_mut(i) else {
            return;
        };
        let to = pair(path);
        let full = env
            .facts
            .mtu(to.transport, &to.addr)
            .saturating_sub(FRAME_OVERHEAD)
            .max(PATH_PROBE_MIN_SIZE);
        let live = path.live();
        let proven = live
            .mtu()
            .filter(|_| live.recheck().is_some() && env.facts.oriented(to.transport));
        let len = match (path.state(), proven) {
            (PathState::Dead, Some(mtu)) => mtu.clamp(PATH_PROBE_MIN_SIZE, full),
            (PathState::Probing | PathState::Dead, _) => live.size(full),
            (PathState::Live | PathState::Suspect, _) => PATH_PROBE_MIN_SIZE,
        };
        let path_id = path.path_id();
        let live = path.live_mut();
        let due = deadline(now, live.timeout(floor, cap));
        let Some(probe_id) = live.send(now, due, len, draw::<E>) else {
            return;
        };
        live.schedule(Some(deadline(now, interval)));
        let msg = PathProbe::new(probe_id, path_id, flags, caps()).with_len(len);
        out.push(Output::Send {
            to,
            bytes: msg.encode(),
        });
    }

    /// Send a search probe on path `i` just ahead of its probe at its
    /// cadence, where one may go (`Liveness::seek_size`): the path is Live,
    /// on a connectionless transport, since on a stream binding an oversized
    /// probe closes the connection (draft Section 5.1), with no probe
    /// unanswered in its current run, so the search never rides a run that
    /// could reach `PATH_TIMEOUT_K`. A search probe outstanding is judged
    /// first (`Liveness::seek_judge`). Search probes go at most once per
    /// standby interval, are held outside the ring, and are judged lost
    /// after the probe timeout; their loss is neither a miss nor an ETX
    /// sample.
    fn seek(&mut self, i: usize, now: C::Instant, env: &Env<'_>, out: &mut Outputs<D>) {
        let flags = self.flags(i);
        let gap = self.params.cfg.standby_interval;
        let floor = self.params.cfg.timeout;
        let cap = self.params.cfg.verdict_cap;
        let Some(path) = self.set.path_mut(i) else {
            return;
        };
        let to = pair(path);
        if path.state() != PathState::Live
            || (env.facts.oriented(to.transport) && !node_fault!(SeekOnStreams))
        {
            return;
        }
        let full = env
            .facts
            .mtu(to.transport, &to.addr)
            .saturating_sub(FRAME_OVERHEAD)
            .max(PATH_PROBE_MIN_SIZE);
        let path_id = path.path_id();
        let live = path.live_mut();
        let timeout = live.timeout(floor, cap);
        live.seek_judge(now, timeout, gap);
        if live.misses() > 0 {
            return;
        }
        let Some(len) = live.seek_size(full, now) else {
            return;
        };
        let probe_id = if node_fault!(SeekCountsLoss) {
            live.seek_ring(now, deadline(now, timeout), gap, len, draw::<E>)
        } else {
            Some(live.seek_send(now, len, draw::<E>))
        };
        let Some(probe_id) = probe_id else {
            return;
        };
        let msg = PathProbe::new(probe_id, path_id, flags, caps()).with_len(len);
        out.push(Output::Send {
            to,
            bytes: msg.encode(),
        });
    }

    /// Report path `i`'s proven MTU, which has just changed, in frame bytes.
    fn proven(&self, i: usize, out: &mut Outputs<D>) {
        let Some(path) = self.set.get(i) else {
            return;
        };
        if let Some(mtu) = path.live().mtu() {
            out.push(Output::Proven {
                to: pair(path),
                mtu: mtu.saturating_add(FRAME_OVERHEAD),
            });
        }
    }

    /// The flags of a path message on path `i`: `ACTIVE` exactly when it is
    /// our active path (draft Section 5.7).
    fn flags(&self, i: usize) -> PathFlags {
        PathFlags::with_active(self.set.active_index() == Some(i))
    }

    /// `now` on the clock an ack reports: microseconds since the bundle
    /// was made, modulo 2^32.
    fn clock(&self, now: C::Instant) -> u32 {
        now.saturating_duration_since(self.origin).as_micros() as u32
    }

    /// Index of the path we call `path_id`, on any transport.
    fn ours(&self, path_id: u32) -> Option<usize> {
        self.set.paths().iter().position(|p| p.path_id() == path_id)
    }

    /// Whether path `i` is probed at all: the bundle speaks, the path is
    /// not the link's one path while Live (FMP's heartbeat covers that),
    /// it is not a Dead path never acked (draft Section 5.6), and no
    /// connection is being opened for it.
    fn probed(&self, i: usize) -> bool {
        let Some(p) = self.set.get(i) else {
            return false;
        };
        let lone = self.set.len() == 1 && p.state() == PathState::Live;
        let forgotten = p.state() == PathState::Dead && !p.acked();
        self.speaks() && !lone && !forgotten && !p.live().pending()
    }

    /// Whether the bundle may send path messages and ask for connections:
    /// multipath is enabled and the peer has shown it implements it (draft
    /// Sections 5.2 and 8.2).
    fn speaks(&self) -> bool {
        self.params.cfg.enabled && self.capable
    }

    /// Whether `input` is discarded, taken as a poll: multipath is
    /// disabled and the input exists only for multipath.
    fn muted(&self, input: &Input) -> bool {
        !self.params.cfg.enabled && multipath(input)
    }

    /// How many probes path `i` may keep outstanding: the ring on a Live or
    /// Suspect path, and one on a Probing or Dead path, whose rows send the
    /// next probe when the last goes unanswered, unless a probe is asked
    /// for at once. On a Probing path a probe at once still counts toward
    /// the discovery limit ([`Self::spent`]).
    fn cap(&self, i: usize, urgent: bool) -> usize {
        let ring = usize::from(self.params.cfg.ring);
        match self.state(i) {
            Some(PathState::Live | PathState::Suspect) => ring,
            Some(PathState::Probing | PathState::Dead) | None => {
                if urgent {
                    ring
                } else {
                    1
                }
            }
        }
    }

    /// The interval from a probe on path `i` to the next (draft Section
    /// 5.6). Live or Suspect: the active interval on our active path or one
    /// the peer marks `ACTIVE`, else the standby interval. Probing: from
    /// the active interval, doubling with each unanswered probe up to the
    /// heartbeat interval. Dead: from the standby interval, doubling up to
    /// the Dead cap, or, while its stop re-checks a path that carried the
    /// link, the stop's least gap within the same bounds: the standby
    /// interval through the span, then doubling. On a path that has
    /// stopped answering the floor may hold a probe later than this.
    fn interval(&self, i: usize) -> Duration {
        let cfg = &self.params.cfg;
        let Some(p) = self.set.get(i) else {
            return cfg.standby_interval;
        };
        let misses = p.live().misses();
        match p.state() {
            PathState::Probing => backoff(misses, cfg.active_interval, cfg.heartbeat),
            PathState::Dead => match p.live().recheck() {
                Some(gap) => gap.min(cfg.dead_interval).max(cfg.standby_interval),
                None => backoff(misses, cfg.standby_interval, cfg.dead_interval),
            },
            PathState::Live | PathState::Suspect => {
                if self.set.active_index() == Some(i) || p.live().peer() {
                    cfg.active_interval
                } else {
                    cfg.standby_interval
                }
            }
        }
    }

    /// When path `i`'s grace ends, if the grace phase would then discard
    /// it: a Dead path that is not active, never acked or with a path of
    /// the link Live (`live`).
    fn ends(&self, i: usize, live: bool) -> Option<C::Instant> {
        let p = self.set.get(i)?;
        let open = p.state() == PathState::Dead
            && self.set.active_index() != Some(i)
            && (!p.acked() || live);
        let since = p.dead_since()?;
        open.then(|| deadline(since, self.params.cfg.grace))
    }

    /// Whether any path of the link is Live.
    fn any_live(&self) -> bool {
        self.set
            .paths()
            .iter()
            .any(|p| p.state() == PathState::Live)
    }

    /// Path `i`'s state.
    fn state(&self, i: usize) -> Option<PathState> {
        self.set.get(i).map(PeerPath::state)
    }

    /// Record the `ACTIVE` flag of the peer's probe or matched ack on path
    /// `i`. When it goes from set to clear, the path is probed at once: the
    /// change prompts a probe and changes no state (draft Section 5.6). On
    /// a Probing path that probe counts toward `MAX_DISCOVERY_PROBES`. It is
    /// not held to the floor of a path that has stopped answering, nor
    /// counted there.
    fn flag(&mut self, i: usize, active: bool) {
        if let Some(p) = self.set.path_mut(i) {
            let live = p.live_mut();
            if live.flag(active) {
                live.urge();
            }
        }
    }

    /// An unauthenticated beacon was heard from `to`. A path held there
    /// that is Probing and was never acked, has none of its probes
    /// outstanding, has its next not yet due, and has not had a probe
    /// brought forward by a beacon since it entered Probing, has its next
    /// probe, or the connection that probe needs, due now, and the beacon
    /// is recorded. The probe is not asked for at once: it keeps the
    /// Probing cap of one outstanding, the discovery limit counts it
    /// ([`Self::spent`]) and the floor of a path that has stopped answering
    /// holds it ([`Self::stopped`]), as it does a probe on the path's own
    /// cadence (draft Section 5.6: only an authenticated prompt skips the
    /// gaps). A path whose next probe is already due gains nothing from
    /// the beacon and keeps it for a later one. Any other beacon changes
    /// nothing, and none changes a state or the peer's capability.
    fn beacon(&mut self, now: C::Instant, to: PathRef) {
        let Some(i) = self.set.find(to.transport, &to.addr) else {
            return;
        };
        let Some(p) = self.set.path_mut(i) else {
            return;
        };
        let live = p.live();
        if p.state() != PathState::Probing
            || p.acked()
            || live.beaconed()
            || live.outstanding() > 0
            || live.next_at().is_none_or(|at| at <= now)
        {
            return;
        }
        let live = p.live_mut();
        live.beacon();
        live.schedule(None);
    }

    /// Bring the Dead path `i` back to Probing for `why`. Brought back by
    /// the peer's probe, which shows the address is the peer's, it starts
    /// afresh: its stop ends and it is probed at once. Brought back by
    /// carrier's return or by finding the peer again, which do not show
    /// that, it keeps its stop, and its first probe is due now on its own
    /// cadence: the floor holds it and counts it, as it does the discovery
    /// probes after it.
    fn revive(&mut self, i: usize, now: C::Instant, why: Why, out: &mut Outputs<D>) {
        self.shift(i, PathState::Probing, now, why, out);
        if let Some(p) = self.set.path_mut(i) {
            let live = p.live_mut();
            if why == Why::Probed {
                live.resume();
                live.urge();
            } else {
                live.schedule(None);
            }
        }
    }

    /// Move path `i` to `next` for `why`, and log it. Every change of state
    /// starts the unanswered count again (draft Section 5.6, path
    /// lifetime), and leaving Dead also keeps a probe still outstanding
    /// from before from counting when it times out. Leaving Live records
    /// the instant, and whether the path was our active path then.
    /// Entering Dead gives up the outstanding probes, schedules the Dead
    /// cadence's first probe a standby interval on, and stops the path
    /// answering, unless the silence clock stopped it sooner or it already
    /// holds a stop.
    fn shift(
        &mut self,
        i: usize,
        next: PathState,
        now: C::Instant,
        why: Why,
        out: &mut Outputs<D>,
    ) {
        let Some(from) = self.state(i) else {
            return;
        };
        let standby = self.params.cfg.standby_interval;
        let active = self.set.active_index() == Some(i);
        if next == PathState::Dead {
            // Judged in the state the path is leaving: the sooner of the
            // two ways to stop answering holds.
            self.stopped(i, now);
        }
        self.set.transition(i, next, now);
        if let Some(p) = self.set.path_mut(i) {
            let live = p.live_mut();
            live.fresh();
            if from == PathState::Dead {
                live.thaw();
            }
            if from == PathState::Live && next != PathState::Live {
                live.left(now, active);
            }
            if next == PathState::Dead {
                live.clear();
                live.schedule(Some(deadline(now, standby)));
                live.halt(now, active);
            }
        }
        self.note(i, Some(from), why, out);
    }

    /// Log path `i`'s state, entered from `from` for `why`.
    fn note(&self, i: usize, from: Option<PathState>, why: Why, out: &mut Outputs<D>) {
        if let Some(p) = self.set.get(i) {
            out.push(Output::State {
                to: pair(p),
                path_id: p.path_id(),
                from,
                next: Some(p.state()),
                why,
            });
        }
    }
}
