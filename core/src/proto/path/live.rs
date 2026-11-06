//! One path's liveness: the probes it has outstanding, its count of
//! unanswered probes, what the answers measured, the frames received on
//! it, its count of authentication failures, whether it has the
//! connection a probe needs, and whether it has stopped answering.
//!
//! On a Probing or Dead path, a path's probes are padded to the link MTU
//! until a padded one sent in its current state goes unanswered; from
//! then on, until its state changes, each probe takes the other size
//! from the one before it, the smallest after a padded one. So a path to
//! a receiver that drops a frame of the sender's link MTU is still
//! proven, by a probe of the smallest size, which proves no MTU.
//!
//! A path's silence clock is the send instant of the earliest probe no
//! matching answer has followed. Once the path has stopped answering
//! (draft Section 5.6), its stop holds the instant from which its next
//! probe on its own cadence may go and the least gap after that one, which
//! doubles with each probe counted, from `PATH_DEAD_PROBE_INTERVAL_MIN` up
//! to `PATH_DEAD_PROBE_INTERVAL_MAX`. The machine decides when a path
//! stops and which probes count.
//!
//! Sans-IO, with no allocation: the probe ring, the record of timed-out
//! probes and the round-trip samples are fixed arrays. Every accessor is
//! read-only; every method that changes a `Liveness` is visible only inside
//! the path module, for the machine.

use super::params::{PATH_DEAD_PROBE_INTERVAL_MAX, PATH_DEAD_PROBE_INTERVAL_MIN, RING};
use super::wire::PATH_PROBE_MIN_SIZE;
use crate::proto::mmp::EWMA_LONG_ALPHA;
use crate::time::{Duration, Instant, deadline};

/// Round-trip samples a path keeps for its minimum.
const SAMPLES: usize = 32;

/// Timed-out probes a path remembers, so that a late answer to one still
/// gives a round-trip sample.
const LATE: usize = 4;

/// One probe sent on a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sent<I> {
    /// The probe's `probe_id`.
    pub probe_id: u32,
    /// When it was sent.
    pub at: I,
    /// When it is unanswered, if no answer has come.
    pub due: I,
    /// Its whole length, counted from its link message type byte.
    pub len: usize,
}

/// How an answer matched one of a path's probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<I> {
    /// It answered an outstanding probe.
    InTime(Sent<I>),
    /// It answered a probe that had already timed out. It gives a round
    /// trip and nothing else.
    Late(Sent<I>),
}

impl<I> Answer<I> {
    /// Whether the answer is a matching one (draft Section 5.6): an answer
    /// in time is. A late answer, to a probe already counted unanswered,
    /// is not a matching answer anywhere: it gives a round trip and does
    /// not ack or prove the path, record the peer's `path_id`, move an
    /// address or end a stop.
    pub fn matching(&self) -> bool {
        match self {
            Self::InTime(_) => true,
            Self::Late(_) => false,
        }
    }
}

/// A path's stop, while it has stopped answering (draft Section 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stop<I> {
    /// The instant from which the next probe on the path's own cadence may
    /// go.
    free: I,
    /// The least gap after that probe.
    gap: Duration,
    /// The gap the latest probe counted used.
    used: Duration,
    /// Whether the latest slot counted went to a connection asked for in
    /// place of a probe, not yet settled.
    owed: bool,
}

/// Whether a path has the connection its probes need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    /// It has one, or its transport needs none.
    Up,
    /// It needs one opened before it is probed.
    Down,
    /// One is being opened.
    Pending,
}

/// Whether `a` comes after `b` in a `probe_id` sequence, modulo 2^32.
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// One path's liveness: its outstanding probes, its `probe_id` sequence,
/// its unanswered count, the measurements its answers gave, the frames
/// received on it, the frames that failed to authenticate, its
/// connection, its silence clock and, once it has stopped answering, its
/// stop.
#[derive(Clone, Debug)]
pub struct Liveness<I> {
    /// Outstanding probes, oldest first, packed at the front.
    ring: [Option<Sent<I>>; RING],
    /// Timed-out probes, newest last.
    late: [Option<Sent<I>>; LATE],
    /// The next `probe_id`, drawn at random before the path's first probe.
    next_id: Option<u32>,
    /// When the next probe is due; `None` for at once.
    next_at: Option<I>,
    /// Whether a probe is asked for at once, for the next send phase only.
    urgent: bool,
    /// Consecutive unanswered probes, in send order.
    misses: u32,
    /// The newest `probe_id` answered in time.
    answered: Option<u32>,
    /// The latest round-trip sample.
    rtt: Option<Duration>,
    /// The round-trip samples of the window, with the instant of each.
    rtts: [Option<(I, Duration)>; SAMPLES],
    /// The expected transmission count, smoothed: 1 when every probe is
    /// answered.
    etx: f64,
    /// The largest path message proven to cross the path both ways, in
    /// bytes from its link message type byte.
    mtu: Option<usize>,
    /// Whether the peer's latest probe or matched ack on the path carried
    /// `ACTIVE`: the peer sends data on it.
    peer: bool,
    /// Authentic frames of the link attributed to the path, modulo 2^32.
    frames: u32,
    /// Their total length, in bytes, modulo 2^32.
    bytes: u32,
    /// When the latest of them arrived.
    heard_at: Option<I>,
    /// When the path last left Live.
    live_at: Option<I>,
    /// Frames of the link that failed to authenticate on the path since
    /// the latest authentic one (draft Section 5.3).
    fails: u32,
    /// The instant of the failure that took the count to the limit, while
    /// the step that marks the path Dead for it is still to come.
    trip: Option<I>,
    /// Whether the path has the connection its probes need.
    connect: Link,
    /// The send instant of the earliest probe since the latest matching
    /// answer: the path's silence clock.
    quiet: Option<I>,
    /// The path's stop, while it has stopped answering.
    stop: Option<Stop<I>>,
    /// The first `probe_id` of the path's current state, taken when it
    /// last changed state; `None` before its first probe, when every
    /// probe is of the current state.
    epoch: Option<u32>,
    /// Whether a padded probe sent in the current state has timed out.
    fallen: bool,
    /// The length of the latest probe sent in the current state.
    last: Option<usize>,
    /// The first `probe_id` whose timeout counts as unanswered, set when
    /// the path last left Dead and dropped once no probe before it is
    /// outstanding, so the comparison never spans half the `probe_id`
    /// space; `None` when every probe counts.
    since: Option<u32>,
}

impl<I: Instant> Liveness<I> {
    /// A path that has sent no probe and measured nothing.
    pub(super) fn new() -> Self {
        Self {
            ring: [None; RING],
            late: [None; LATE],
            next_id: None,
            next_at: None,
            urgent: false,
            misses: 0,
            answered: None,
            rtt: None,
            rtts: [None; SAMPLES],
            etx: 1.0,
            mtu: None,
            peer: false,
            frames: 0,
            bytes: 0,
            heard_at: None,
            live_at: None,
            fails: 0,
            trip: None,
            connect: Link::Up,
            quiet: None,
            stop: None,
            epoch: None,
            fallen: false,
            last: None,
            since: None,
        }
    }

    /// Probes sent and not yet answered or timed out.
    pub fn outstanding(&self) -> usize {
        self.ring.iter().flatten().count()
    }

    /// Consecutive unanswered probes, in send order, since the path last
    /// changed state.
    pub fn misses(&self) -> u32 {
        self.misses
    }

    /// The latest round-trip sample.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// The least round trip among the window's samples.
    pub fn min_rtt(&self) -> Option<Duration> {
        self.rtts.iter().flatten().map(|&(_, rtt)| rtt).min()
    }

    /// Round-trip samples in the window.
    pub fn samples(&self) -> usize {
        self.rtts.iter().flatten().count()
    }

    /// The smoothed expected transmission count.
    pub fn etx(&self) -> f64 {
        self.etx
    }

    /// The proven MTU: the largest path message, in bytes from its type
    /// byte, that one of our probes and its answer both carried.
    pub fn mtu(&self) -> Option<usize> {
        self.mtu
    }

    /// Authentic frames of the link attributed to the path, modulo 2^32:
    /// the `rx_frames` of the path's acks.
    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// The total length of those frames, in bytes, modulo 2^32: the
    /// `rx_bytes` of the path's acks.
    pub fn bytes(&self) -> u32 {
        self.bytes
    }

    /// When the latest authentic frame attributed to the path arrived.
    pub fn heard_at(&self) -> Option<I> {
        self.heard_at
    }

    /// When the next probe is due; `None` for at once, once the path is
    /// probed at all.
    pub fn next_at(&self) -> Option<I> {
        self.next_at
    }

    /// The earliest instant an outstanding probe goes unanswered.
    pub fn earliest_due(&self) -> Option<I> {
        self.ring.iter().flatten().map(|s| s.due).min()
    }

    /// Frames of the link that failed to authenticate on the path since
    /// the latest authentic one arrived on it.
    pub fn fails(&self) -> u32 {
        self.fails
    }

    /// The send instant of the earliest probe since the latest matching
    /// answer, if one has gone since.
    pub(super) fn quiet(&self) -> Option<I> {
        self.quiet
    }

    /// Record that the path stopped answering at `at`, unless it already
    /// has: its next probe on its own cadence goes no sooner than
    /// `PATH_DEAD_PROBE_INTERVAL_MIN` after `at`, and the one after that no
    /// sooner than the same again after it.
    pub(super) fn halt(&mut self, at: I) {
        if self.stop.is_none() {
            self.stop = Some(Stop {
                free: deadline(at, PATH_DEAD_PROBE_INTERVAL_MIN),
                gap: PATH_DEAD_PROBE_INTERVAL_MIN,
                used: PATH_DEAD_PROBE_INTERVAL_MIN,
                owed: false,
            });
        }
    }

    /// Whether the path has stopped answering.
    pub(super) fn stopped(&self) -> bool {
        self.stop.is_some()
    }

    /// While the path has stopped answering, the instant from which its
    /// next probe on its own cadence may go.
    pub(super) fn held(&self) -> Option<I> {
        self.stop.map(|s| s.free)
    }

    /// Count a slot of the path's own cadence used at `at`, while it has
    /// stopped answering: the next waits the least gap, which then doubles
    /// up to `PATH_DEAD_PROBE_INTERVAL_MAX`.
    pub(super) fn spend(&mut self, at: I) {
        if let Some(s) = self.stop.as_mut() {
            s.used = s.gap;
            s.free = deadline(at, s.gap);
            s.gap = s.gap.saturating_mul(2).min(PATH_DEAD_PROBE_INTERVAL_MAX);
            s.owed = false;
        }
    }

    /// Mark the slot just counted as gone to a connection asked for in
    /// place of a probe.
    pub(super) fn owe(&mut self) {
        if let Some(s) = self.stop.as_mut() {
            s.owed = true;
        }
    }

    /// Settle the connection a counted slot went to, at `at`: opened
    /// (`ok`), the probe sent then is that slot's, so the next waits the
    /// gap that slot used from the opening. The gap is not doubled again.
    /// A failed one moves nothing, and a slot not owed changes nothing.
    pub(super) fn rebase(&mut self, at: I, ok: bool) {
        if let Some(s) = self.stop.as_mut().filter(|s| s.owed) {
            s.owed = false;
            if ok {
                s.free = s.free.max(deadline(at, s.used));
            }
        }
    }

    /// End the stop and restart the silence clock, as a matching answer
    /// does.
    pub(super) fn resume(&mut self) {
        self.quiet = None;
        self.stop = None;
    }

    /// When the path last left Live, the latest instant it was known to
    /// work.
    pub(super) fn live_at(&self) -> Option<I> {
        self.live_at
    }

    /// Record that the path left Live at `now`.
    pub(super) fn left(&mut self, now: I) {
        self.live_at = Some(now);
    }

    /// Whether the peer's latest probe or matched ack on the path said it
    /// sends data on it.
    pub(super) fn peer(&self) -> bool {
        self.peer
    }

    /// Record the `ACTIVE` flag of the peer's latest probe or matched ack
    /// on the path. Returns whether it went from set to clear.
    pub(super) fn flag(&mut self, active: bool) -> bool {
        let dropped = self.peer && !active;
        self.peer = active;
        dropped
    }

    /// Ask for a probe at once, in the next send phase only.
    pub(super) fn urge(&mut self) {
        self.urgent = true;
    }

    /// Whether a probe was asked for at once, clearing the request.
    pub(super) fn take_urgent(&mut self) -> bool {
        core::mem::take(&mut self.urgent)
    }

    /// Schedule the next probe for `at`; `None` for at once.
    pub(super) fn schedule(&mut self, at: Option<I>) {
        self.next_at = at;
    }

    /// The probe timeout: the larger of `floor` and three times the latest
    /// round trip (draft Section 5.6).
    pub(super) fn timeout(&self, floor: Duration) -> Duration {
        floor.max(self.rtt.map_or(Duration::ZERO, |r| r.saturating_mul(3)))
    }

    /// Whether another probe may go out with at most `cap` outstanding.
    pub(super) fn room(&self, cap: usize) -> bool {
        self.outstanding() < cap.min(RING)
    }

    /// Record a probe of `len` bytes sent at `at` and unanswered at `due`,
    /// and return its `probe_id`, or `None` when the ring is full. The
    /// path's first `probe_id` comes from `draw`; each later one is the
    /// last plus one, modulo 2^32.
    pub(super) fn send(
        &mut self,
        at: I,
        due: I,
        len: usize,
        draw: impl FnOnce() -> u32,
    ) -> Option<u32> {
        let slot = self.ring.iter().position(Option::is_none)?;
        if self.ring.iter().flatten().all(|s| self.counts(s.probe_id)) {
            self.since = None;
        }
        let probe_id = self.take_id(draw);
        self.quiet.get_or_insert(at);
        self.last = Some(len);
        self.ring[slot] = Some(Sent {
            probe_id,
            at,
            due,
            len,
        });
        Some(probe_id)
    }

    /// Take the path's next `probe_id`, for a probe held outside the ring
    /// or in it. The first comes from `draw`; each later one is the last
    /// plus one, modulo 2^32 (draft Section 5.1).
    pub(super) fn take_id(&mut self, draw: impl FnOnce() -> u32) -> u32 {
        let probe_id = *self.next_id.get_or_insert_with(draw);
        self.next_id = Some(probe_id.wrapping_add(1));
        probe_id
    }

    /// Keep a probe held outside the ring, which has timed out or will
    /// not be matched in time, in the late record, giving up the oldest:
    /// an answer to it gives a round trip and nothing else.
    pub(super) fn lapse(&mut self, sent: Sent<I>) {
        self.remember(sent);
    }

    /// Match an answer to the probe `probe_id`. An outstanding probe is
    /// taken from the ring, keeping the rest in send order, and ends the
    /// run of unanswered probes. A timed-out one is taken from the late
    /// record and changes nothing else: its timeout still counts.
    pub(super) fn answer(&mut self, probe_id: u32) -> Option<Answer<I>> {
        let found = |s: &Option<Sent<I>>| s.is_some_and(|s| s.probe_id == probe_id);
        if let Some(slot) = self.ring.iter().position(found) {
            let sent = self.ring[slot].take()?;
            self.compact();
            self.misses = 0;
            if self.answered.is_none_or(|a| after(probe_id, a)) {
                self.answered = Some(probe_id);
            }
            return Some(Answer::InTime(sent));
        }
        let slot = self.late.iter().position(found)?;
        self.late[slot].take().map(Answer::Late)
    }

    /// Time out the oldest outstanding probe due at or before `now`, or
    /// with `overdue` strictly before it, if there is one, and keep it in
    /// the late record. Returns whether it counted as unanswered: it does
    /// unless a probe sent after it has been answered in time, or it was
    /// sent before the path last left Dead ([`Self::thaw`]).
    pub(super) fn expire(&mut self, now: I, overdue: bool) -> Option<bool> {
        let slot = self
            .ring
            .iter()
            .position(|s| s.is_some_and(|s| s.due < now || (!overdue && s.due == now)))?;
        let sent = self.ring[slot].take()?;
        self.compact();
        self.remember(sent);
        let current = self.epoch.is_none_or(|e| !after(e, sent.probe_id));
        if current && sent.len > PATH_PROBE_MIN_SIZE {
            self.fallen = true;
        }
        let counted =
            self.counts(sent.probe_id) && self.answered.is_none_or(|a| !after(a, sent.probe_id));
        if counted {
            self.misses = self.misses.saturating_add(1);
        }
        Some(counted)
    }

    /// Start the unanswered count again, as every change of state does
    /// (draft Section 5.6, path lifetime), and start the choice of probe
    /// size again ([`Self::small`]): a probe sent before the change, still
    /// outstanding, is not of the new state, so its timeout does not
    /// count toward that choice.
    pub(super) fn fresh(&mut self) {
        self.misses = 0;
        self.epoch = self.next_id;
        self.fallen = false;
        self.last = None;
    }

    /// Start the path afresh as it leaves Dead, after [`Self::fresh`]: a
    /// probe still outstanding from before does not count as unanswered
    /// when it times out, toward any count (draft Section 5.6, path
    /// lifetime). It stays in the ring, since it has not been counted
    /// unanswered: an answer to it before its timeout is still a matching
    /// one, and one after is late.
    pub(super) fn thaw(&mut self) {
        self.since = self.next_id;
    }

    /// Whether the probe `probe_id` counts as unanswered when it times
    /// out: it was not sent before the path last left Dead.
    fn counts(&self, probe_id: u32) -> bool {
        self.since.is_none_or(|s| !after(s, probe_id))
    }

    /// Whether the next probe of a Probing or Dead path goes at the
    /// smallest size rather than padded: once a padded probe sent in its
    /// current state has timed out, its probes alternate, the smallest
    /// after a padded one and padded after the smallest, until its state
    /// changes. A receiver whose buffer is smaller than our link MTU drops
    /// every padded probe, and the smallest one still proves the path.
    pub(super) fn small(&self) -> bool {
        self.fallen && self.last.is_some_and(|len| len > PATH_PROBE_MIN_SIZE)
    }

    /// Give up every outstanding probe, as a path entering Dead does. The
    /// late record keeps them, so an answer still gives a round trip.
    pub(super) fn clear(&mut self) {
        for slot in 0..RING {
            if let Some(sent) = self.ring[slot].take() {
                self.remember(sent);
            }
        }
    }

    /// Record a round trip of `rtt` measured at `now`, keeping in the
    /// window only the samples of the last `window`.
    pub(super) fn sample(&mut self, now: I, rtt: Duration, window: Duration) {
        self.rtt = Some(rtt);
        for s in self.rtts.iter_mut() {
            if s.is_some_and(|(at, _)| now.saturating_duration_since(at) > window) {
                *s = None;
            }
        }
        let slot = match self.rtts.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => self
                .rtts
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.map(|(at, _)| at))
                .map_or(0, |(i, _)| i),
        };
        self.rtts[slot] = Some((now, rtt));
    }

    /// Fold one probe's outcome into the ETX: the long average of the
    /// delivery ratio, inverted and clamped to between 1 and 100.
    pub(super) fn fold(&mut self, delivered: bool) {
        let ratio = (1.0 / self.etx).clamp(0.01, 1.0);
        let sample = if delivered { 1.0 } else { 0.0 };
        let next = ratio + EWMA_LONG_ALPHA * (sample - ratio);
        self.etx = (1.0 / next.max(0.01)).clamp(1.0, 100.0);
    }

    /// Record `mtu` bytes as proven.
    pub(super) fn prove(&mut self, mtu: usize) {
        self.mtu = Some(mtu);
    }

    /// Count one authentic frame of `len` bytes received at `now`. The
    /// counts wrap modulo 2^32, as the draft's `rx_frames` and `rx_bytes`
    /// do. It ends the run of authentication failures (draft Section 5.3).
    pub(super) fn heard(&mut self, len: usize, now: I) {
        self.frames = self.frames.wrapping_add(1);
        self.bytes = self.bytes.wrapping_add(len as u32);
        self.heard_at = Some(now);
        self.fails = 0;
    }

    /// Take back one frame of `len` bytes from the counts, as a path
    /// message's frame moves to the path the message concerns. When it
    /// arrived, and the end of the run of failures, stay as they are.
    pub(super) fn shed(&mut self, len: usize) {
        self.frames = self.frames.wrapping_sub(1);
        self.bytes = self.bytes.wrapping_sub(len as u32);
    }

    /// Take `fails` as the count of frames that failed to authenticate, as
    /// a path carried into a new link keeps its count.
    pub(super) fn inherit(&mut self, fails: u32) {
        self.fails = fails;
    }

    /// End the run of authentication failures without counting a frame, as
    /// an authentic frame of the link on the path does when it is not
    /// accounted (draft Section 5.3).
    pub(super) fn forgive(&mut self) {
        self.fails = 0;
    }

    /// Count one frame that failed to authenticate, and return the count.
    pub(super) fn fail(&mut self) -> u32 {
        self.fails = self.fails.saturating_add(1);
        self.fails
    }

    /// Record that the failures reached the limit at `at`, for the next
    /// step to mark the path Dead.
    pub(super) fn trip(&mut self, at: I) {
        self.trip = Some(at);
    }

    /// The instant of a trip recorded and not yet applied.
    pub(super) fn tripped(&self) -> Option<I> {
        self.trip
    }

    /// Take the trip recorded, if there is one.
    pub(super) fn untrip(&mut self) -> Option<I> {
        self.trip.take()
    }

    /// Record that the path needs a connection opened before its first
    /// probe, as a candidate on a connection-oriented transport does.
    pub(super) fn unlink(&mut self) {
        self.connect = Link::Down;
    }

    /// Whether the path needs a connection opened before it is probed.
    pub(super) fn unlinked(&self) -> bool {
        self.connect == Link::Down
    }

    /// Whether a connection is being opened for the path.
    pub(super) fn pending(&self) -> bool {
        self.connect == Link::Pending
    }

    /// Record that a connection is being opened for the path.
    pub(super) fn dial(&mut self) {
        self.connect = Link::Pending;
    }

    /// Record how the connection being opened settled: `ok`, the path has
    /// it; otherwise it needs another, and the failure counts as one
    /// unanswered probe. Returns whether a connection was being opened;
    /// when none was, nothing changes.
    pub(super) fn settle(&mut self, ok: bool) -> bool {
        if self.connect != Link::Pending {
            return false;
        }
        if ok {
            self.connect = Link::Up;
        } else {
            self.connect = Link::Down;
            self.misses = self.misses.saturating_add(1);
        }
        true
    }

    /// Keep a timed-out probe in the late record, giving up the oldest.
    fn remember(&mut self, sent: Sent<I>) {
        self.late.rotate_left(1);
        self.late[LATE - 1] = Some(sent);
    }

    /// Pack the ring's outstanding probes at its front, in send order.
    fn compact(&mut self) {
        let mut w = 0;
        for r in 0..RING {
            if let Some(s) = self.ring[r].take() {
                self.ring[w] = Some(s);
                w += 1;
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/live.rs"]
mod tests;
