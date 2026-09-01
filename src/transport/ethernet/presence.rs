//! Interface presence state for interface-bound transports.
//!
//! A transport bound to a network interface is a long-lived object that is
//! *sometimes bound*. The interface it names may not exist when the daemon
//! starts, may appear minutes later, may vanish and return mid-operation, and
//! may never appear at all. This module holds the state that makes that
//! observable and drives the rebind loop in [`super`].
//!
//! ```text
//! Absent ──attach──> Binding ──ok──> Present
//!   ^                   │              │
//!   └──── fail/backoff ─┘              │
//!   └──────────── detach ──────────────┘
//! ```
//!
//! Two invariants do the work:
//!
//! - **The transport object survives detach.** Config, `TransportId`,
//!   statistics, and the neighbor buffer persist; only the file descriptor and
//!   its loops go. A transport is never destroyed because its interface went
//!   away.
//! - **Start-time absence and runtime detach are the same transition.** A node
//!   that boots before wifi and a node whose wifi reloads at 03:00 take one
//!   code path.
//!
//! Presence tracks `IFF_UP` — the interface exists and the operator has
//! enabled it — and deliberately not `IFF_RUNNING`: binding needs no carrier,
//! and a socket outlives a carrier flap. Carrier is reported alongside it
//! rather than steering it. See
//! [`interface_present`](super::io::interface_present) for why.

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

/// Read a lock, ignoring poisoning.
///
/// Every value guarded in this module is plain data — an `Instant`, an
/// `Option<[u8; 6]>` — that a panic mid-write cannot leave logically
/// inconsistent, so poisoning carries no information worth propagating.
/// Treating it as a failure is what would hurt: the callers here are on the
/// presence path, and "assume the worst" there means a transport that reports
/// itself bound while every send fails, or a binder that tears down and
/// rebinds every second forever. A stuck state is a worse outcome than
/// reading a byte written by a thread that later panicked.
fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Write a lock, ignoring poisoning. See [`read`].
fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

/// How absence of the configured interface is reported.
///
/// Describes *the interface's presence*, not the transport's importance: an
/// optional interface that is present is used exactly as hard as any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbsencePolicy {
    /// Naming an interface in configuration is a statement that you expect it,
    /// so the default is to complain: absence degrades node health from the
    /// first edge, and if it outlasts [`ABSENCE_ERROR_AFTER`] — the window in
    /// which it could still have been an ordinary bring-up race — it is
    /// reported once at `error`.
    Required,
    /// Absence is normal for this interface (a dock adapter, a radio that only
    /// exists on some hardware): no health impact, `info` on the edge.
    Optional,
}

impl AbsencePolicy {
    /// `optional: true` in configuration selects [`AbsencePolicy::Optional`].
    pub fn from_optional(optional: bool) -> Self {
        if optional {
            Self::Optional
        } else {
            Self::Required
        }
    }

    /// Whether absence should be hidden from node health.
    pub fn is_optional(self) -> bool {
        matches!(self, Self::Optional)
    }

    /// Operator-facing label, used by `show_transports`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

/// Where a transport sits in the presence cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// The interface is not there (or is there without carrier). No socket, no
    /// loops; the watcher is waiting.
    Absent,
    /// The interface appeared and a bind is in flight, or a non-absence bind
    /// failure is backing off.
    Binding,
    /// Bound, with a live socket and running loops.
    Present,
}

impl Presence {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Binding,
            2 => Self::Present,
            _ => Self::Absent,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::Binding => 1,
            Self::Present => 2,
        }
    }

    /// Operator-facing label, used by `show_transports`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Binding => "binding",
            Self::Present => "present",
        }
    }
}

impl std::fmt::Display for Presence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Shared, lock-light presence state.
///
/// Written by the transport's binder task, read by `send`, by the control
/// plane, and by tests. Held behind an `Arc` so the binder task can outlive
/// any particular borrow of the transport.
#[derive(Debug)]
pub struct PresenceState {
    phase: AtomicU8,
    /// Successful binds since the transport was created. `1` after a clean
    /// start; every increment past that is a rebind.
    binds: AtomicU64,
    /// Failed bind attempts since the last successful bind. Reset on bind.
    attempts: AtomicU32,
    /// When the current phase was entered.
    since: RwLock<Instant>,
    /// MAC observed at the last successful bind. A name reappearing with a
    /// different MAC is different hardware, not the same device returning.
    last_mac: RwLock<Option<[u8; 6]>>,
}

impl Default for PresenceState {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceState {
    /// A fresh tracker in [`Presence::Absent`].
    pub fn new() -> Self {
        Self {
            phase: AtomicU8::new(Presence::Absent.as_u8()),
            binds: AtomicU64::new(0),
            attempts: AtomicU32::new(0),
            since: RwLock::new(Instant::now()),
            last_mac: RwLock::new(None),
        }
    }

    /// Current phase.
    pub fn presence(&self) -> Presence {
        Presence::from_u8(self.phase.load(Ordering::Acquire))
    }

    /// Whether the transport currently holds a bound socket.
    pub fn is_present(&self) -> bool {
        self.presence() == Presence::Present
    }

    /// How long the current presence *episode* has been held.
    ///
    /// Episode, not phase: `Binding` is part of the absence episode until it
    /// succeeds. An interface that has been gone for a week while a bind is
    /// retried and refused every second must report a week, not one second —
    /// otherwise [`ABSENCE_ERROR_AFTER`] is never reached and the
    /// operator-facing `since_secs` reads as a healthy young absence forever.
    pub fn since(&self) -> Duration {
        read(&self.since).elapsed()
    }

    /// Restart the episode clock, for a transport that is about to start.
    ///
    /// `new()` stamps the clock at construction, but construction and
    /// `start_async` need not be adjacent — config load and supervisor staging
    /// sit between them. Left alone, a transport staged for longer than
    /// [`ABSENCE_ERROR_AFTER`] logs the sustained-absence error on its very
    /// first binder tick, having given the interface no bring-up window at
    /// all. The window is supposed to absorb exactly that race.
    pub fn mark_starting(&self) {
        *write(&self.since) = Instant::now();
    }

    /// Successful binds since creation (`1` after a clean start).
    pub fn binds(&self) -> u64 {
        self.binds.load(Ordering::Relaxed)
    }

    /// Failed bind attempts since the last successful bind.
    pub fn attempts(&self) -> u32 {
        self.attempts.load(Ordering::Relaxed)
    }

    /// MAC observed at the last successful bind, if any.
    pub fn last_mac(&self) -> Option<[u8; 6]> {
        *read(&self.last_mac)
    }

    /// Move to `phase`, returning `true` if this was an actual edge.
    ///
    /// Edge-vs-level is what the logging policy keys on: logged once on
    /// entering absence and once on recovery, never per retry attempt.
    ///
    /// The episode clock ([`Self::since`]) restarts only when *boundness*
    /// changes — Present↔not-Present. A failed bind walks
    /// `Absent → Binding → Absent`, and resetting the clock on those would
    /// hide a permanent absence behind a timer that never gets past one
    /// second.
    pub fn transition(&self, phase: Presence) -> bool {
        let prev = Presence::from_u8(self.phase.swap(phase.as_u8(), Ordering::AcqRel));
        if prev == phase {
            return false;
        }
        if (prev == Presence::Present) != (phase == Presence::Present) {
            *write(&self.since) = Instant::now();
        }
        true
    }

    /// Record a successful bind at `mac`.
    ///
    /// Returns `true` when the interface came back as *different hardware* —
    /// the name reappeared with a MAC other than the one last bound. The
    /// caller drops cached neighbor state rather than silently resuming onto
    /// a different adapter.
    pub fn record_bind(&self, mac: [u8; 6]) -> bool {
        let changed = match *read(&self.last_mac) {
            Some(prev) => prev != mac,
            None => false,
        };
        *write(&self.last_mac) = Some(mac);
        self.binds.fetch_add(1, Ordering::Relaxed);
        self.attempts.store(0, Ordering::Relaxed);
        self.transition(Presence::Present);
        changed
    }

    /// Record a failed bind attempt, returning the new attempt count.
    pub fn record_attempt(&self) -> u32 {
        self.attempts.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Backoff for bind failures that are *not* absence — permission denied,
/// buffer sizing, a BPF device shortage. Absence itself does not back off
/// where an event source is available: there is nothing to poll.
///
/// 1 s doubling to a 30 s ceiling.
pub fn bind_backoff(attempts: u32) -> Duration {
    const BASE_SECS: u64 = 1;
    const CEILING_SECS: u64 = 30;
    let shift = attempts.saturating_sub(1).min(5);
    Duration::from_secs((BASE_SECS << shift).min(CEILING_SECS))
}

/// How long a *required* interface may be absent before it is an error.
///
/// Absence is a state the presence machine handles, so it is not an error for
/// happening — a daemon that wins the race against its own radio, or a cable
/// out for two seconds, is the ordinary case this mechanism exists to absorb,
/// and calling that an error at t=0 and "recovered" at t=0.2 s is cry-wolf.
/// Past this window it is no longer a race: something an operator has to fix
/// is wrong, and the log should say so once.
///
/// One window for both shapes of absence. A node that boots before its wifi
/// and a node whose wifi reloads at 03:00 take one code path everywhere else
/// in this module; giving them different deadlines would reintroduce exactly
/// the start-versus-runtime asymmetry the presence machine removed.
///
/// Tuned against the platforms this exists for: comfortably past a veth or a
/// container coming up, short enough that a mesh radio which never appears is
/// named while somebody is still watching the boot. Raising it hides a real
/// fault for longer; lowering it starts reporting ordinary bring-up races.
pub const ABSENCE_ERROR_AFTER: Duration = Duration::from_secs(10);

/// Minimum lifetime for a binding to count as a real recovery.
///
/// A socket that dies sooner than this never really came back.
pub const MIN_STABLE_BINDING: Duration = Duration::from_secs(10);

/// Consecutive short-lived bindings before the binder stops treating a
/// successful bind as a recovery.
pub const CHURN_THRESHOLD: u32 = 3;

/// Damping for the rebind loop.
///
/// Backoff covers *failed* binds; this covers the opposite and nastier case —
/// binds that keep **succeeding** into a socket that dies moments later. A
/// receive loop that gives up on a persistent error while the interface stays
/// `UP` produces exactly that: tear down, rebind, succeed, fail again, once
/// per second, forever. Undamped it is an `error!`/`info!` pair and a
/// `Degraded`→`Running` health flap every cycle, which defeats both the
/// "log edges, not attempts" rule and the meaning of `Degraded`.
///
/// So: count consecutive bindings that die young, back off between them on
/// the same 1 s → 30 s curve, and once the streak reaches
/// [`CHURN_THRESHOLD`] stop announcing each bind as a recovery — hold the
/// node at its degraded reading until a binding actually survives
/// [`MIN_STABLE_BINDING`]. A binding that holds ends the streak.
///
/// Pure state, driven by an injected clock, so the policy is testable without
/// a network interface.
#[derive(Debug, Default)]
pub struct ChurnGuard {
    /// Consecutive bindings that died younger than [`MIN_STABLE_BINDING`].
    streak: u32,
    /// When the current binding was established.
    bound_at: Option<Instant>,
    /// Whether the current binding was announced as a recovery.
    announced: bool,
}

/// What the caller should do about a successful bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindOutcome {
    /// Log the recovery and publish presence now. `false` while churning:
    /// the bind is held back until it proves it will last.
    pub announce: bool,
}

/// What the caller should do about a detach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetachOutcome {
    /// Publish absence. `false` when the binding that just died was never
    /// announced, so there is nothing to retract.
    pub retract: bool,
    /// Log the detach edge. `false` once churning — the fact has been said.
    pub log_edge: bool,
    /// This detach is the one that crossed [`CHURN_THRESHOLD`]; say so once.
    pub entered_churn: bool,
    /// Wait this long before trying to bind again.
    pub backoff: Option<Duration>,
}

impl ChurnGuard {
    /// A guard with no history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consecutive short-lived bindings, for logging and tests.
    pub fn streak(&self) -> u32 {
        self.streak
    }

    /// Record a successful bind.
    pub fn bound(&mut self, now: Instant) -> BindOutcome {
        self.bound_at = Some(now);
        let announce = self.streak < CHURN_THRESHOLD;
        if announce {
            self.announced = true;
        }
        BindOutcome { announce }
    }

    /// Called on every tick while bound. Returns `true` exactly once, at the
    /// moment a held-back binding has proved stable and should be announced.
    pub fn stabilized(&mut self, now: Instant) -> bool {
        let Some(bound_at) = self.bound_at else {
            return false;
        };
        if now.duration_since(bound_at) < MIN_STABLE_BINDING {
            return false;
        }
        let newly_announced = !self.announced;
        self.streak = 0;
        self.announced = true;
        newly_announced
    }

    /// Record a detach.
    pub fn detached(&mut self, now: Instant) -> DetachOutcome {
        let young = self
            .bound_at
            .is_some_and(|t| now.duration_since(t) < MIN_STABLE_BINDING);
        self.bound_at = None;

        if young {
            self.streak += 1;
        } else {
            self.streak = 0;
        }

        DetachOutcome {
            retract: std::mem::take(&mut self.announced),
            log_edge: self.streak < CHURN_THRESHOLD,
            entered_churn: self.streak == CHURN_THRESHOLD,
            backoff: (self.streak > 0).then(|| bind_backoff(self.streak)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn presence_starts_absent() {
        let p = PresenceState::new();
        assert_eq!(p.presence(), Presence::Absent);
        assert_eq!(p.binds(), 0);
        assert_eq!(p.attempts(), 0);
        assert!(p.last_mac().is_none());
    }

    #[test]
    fn transition_reports_edges_only() {
        let p = PresenceState::new();
        assert!(p.transition(Presence::Binding));
        assert!(!p.transition(Presence::Binding));
        assert!(p.transition(Presence::Present));
    }

    #[test]
    fn bind_records_mac_and_clears_attempts() {
        let p = PresenceState::new();
        p.record_attempt();
        p.record_attempt();
        assert_eq!(p.attempts(), 2);

        let mac = [0x02, 0, 0, 0, 0, 1];
        assert!(!p.record_bind(mac), "first bind is not a hardware change");
        assert_eq!(p.attempts(), 0);
        assert_eq!(p.binds(), 1);
        assert_eq!(p.presence(), Presence::Present);
        assert_eq!(p.last_mac(), Some(mac));
    }

    #[test]
    fn rebind_on_same_mac_is_not_a_hardware_change() {
        let p = PresenceState::new();
        let mac = [0x02, 0, 0, 0, 0, 1];
        p.record_bind(mac);
        p.transition(Presence::Absent);
        assert!(!p.record_bind(mac));
        assert_eq!(p.binds(), 2);
    }

    #[test]
    fn rebind_on_different_mac_is_a_hardware_change() {
        let p = PresenceState::new();
        p.record_bind([0x02, 0, 0, 0, 0, 1]);
        p.transition(Presence::Absent);
        assert!(p.record_bind([0x02, 0, 0, 0, 0, 2]));
    }

    #[test]
    fn backoff_climbs_to_a_ceiling() {
        assert_eq!(bind_backoff(0), Duration::from_secs(1));
        assert_eq!(bind_backoff(1), Duration::from_secs(1));
        assert_eq!(bind_backoff(2), Duration::from_secs(2));
        assert_eq!(bind_backoff(3), Duration::from_secs(4));
        assert_eq!(bind_backoff(6), Duration::from_secs(30));
        assert_eq!(bind_backoff(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn the_error_deadline_outlasts_an_ordinary_bring_up_race() {
        // The window has to clear the races it exists to absorb — a veth
        // arriving a fraction of a second late, a container starting — while
        // staying short enough that a radio which never appears is named
        // during the boot somebody is watching. It is also the one deadline:
        // start-time absence and a runtime detach share it.
        assert!(
            ABSENCE_ERROR_AFTER >= Duration::from_secs(5),
            "shorter than a bring-up race would report the ordinary case"
        );
        assert!(
            ABSENCE_ERROR_AFTER <= Duration::from_secs(60),
            "longer and a required interface that never appears goes unsaid \
             for the whole boot"
        );
    }

    // ── The absence clock measures an episode, not a phase ────────────────

    #[test]
    fn a_failed_bind_does_not_restart_the_absence_clock() {
        // An interface that is present but refuses to bind walks
        // Absent → Binding → Absent on every retry. If those edges reset the
        // clock, `since_secs` reads as a one-second-old absence forever and
        // the error deadline is never reached — so a permission error would
        // sit silently behind a healthy-looking counter.
        let p = PresenceState::new();
        std::thread::sleep(Duration::from_millis(30));
        let before = p.since();

        assert!(p.transition(Presence::Binding));
        assert!(p.transition(Presence::Absent));
        assert!(p.transition(Presence::Binding));
        assert!(p.transition(Presence::Absent));

        assert!(
            p.since() >= before,
            "the absence clock ran backwards across failed binds"
        );
    }

    #[test]
    fn the_clock_restarts_only_when_boundness_changes() {
        let p = PresenceState::new();
        std::thread::sleep(Duration::from_millis(30));

        // Absent → Present restarts it: a new episode began.
        p.record_bind([0x02, 0, 0, 0, 0, 1]);
        assert!(p.since() < Duration::from_millis(30));

        std::thread::sleep(Duration::from_millis(30));
        let bound_for = p.since();

        // Present → Present is not an edge at all.
        assert!(!p.transition(Presence::Present));
        assert!(p.since() >= bound_for);

        // Present → Absent restarts it: the episode ended.
        assert!(p.transition(Presence::Absent));
        assert!(p.since() < Duration::from_millis(30));
    }

    // ── Poisoning must not be a stuck state ───────────────────────────────

    #[test]
    fn a_poisoned_lock_still_reports_presence() {
        // `.ok()`-style handling would make a poisoned lock read as "no MAC,
        // no socket, tasks dead" — a transport reporting itself present while
        // every send fails, and a binder rebinding once a second forever.
        // Poisoning carries no information about plain data, so it is ignored.
        let p = Arc::new(PresenceState::new());
        p.record_bind([0x02, 0, 0, 0, 0, 7]);

        let poisoner = Arc::clone(&p);
        let panicked = std::thread::spawn(move || {
            let _guard = poisoner.last_mac.write().unwrap();
            panic!("poison the lock while holding it");
        })
        .join();
        assert!(panicked.is_err(), "the helper thread was supposed to panic");
        assert!(
            p.last_mac.is_poisoned(),
            "the lock was supposed to be poisoned"
        );

        assert_eq!(
            p.last_mac(),
            Some([0x02, 0, 0, 0, 0, 7]),
            "a poisoned lock must not erase the binding"
        );
        // And the clock still answers rather than collapsing to zero.
        let _ = p.since();
    }

    // ── Rebind churn ──────────────────────────────────────────────────────

    #[test]
    fn a_healthy_bind_and_detach_is_not_churn() {
        let mut g = ChurnGuard::new();
        let t0 = Instant::now();
        assert!(g.bound(t0).announce, "a first bind is a recovery");

        // Held well past the stability floor, then lost.
        let out = g.detached(t0 + MIN_STABLE_BINDING + Duration::from_secs(60));
        assert!(out.retract, "an announced binding must be retracted");
        assert!(out.log_edge, "an isolated detach is worth a line");
        assert!(!out.entered_churn);
        assert_eq!(out.backoff, None, "one clean outage must not back off");
        assert_eq!(g.streak(), 0);
    }

    #[test]
    fn an_unseeded_guard_retracts_nothing_and_never_repairs_itself() {
        // Why `binder_loop` seeds the guard when it inherits a binding from
        // `start_async`, rather than leaving it fresh.
        //
        // A guard that was never told about a bind believes it has announced
        // nothing, so it asks for no retraction — and health, which learned
        // `present: true` from the inline bind, would keep reading `Full` with
        // the interface gone. `stabilized` cannot rescue it either: with no
        // `bound_at` there is nothing for it to judge stable.
        let mut g = ChurnGuard::new();
        let t0 = Instant::now();

        assert!(
            !g.stabilized(t0 + MIN_STABLE_BINDING + Duration::from_secs(60)),
            "a guard with no recorded bind has nothing to stabilize"
        );

        let out = g.detached(t0 + Duration::from_secs(60));
        assert!(
            !out.retract,
            "an unseeded guard retracts nothing — which is exactly why the \
             binder must seed it from the inline bind"
        );
    }

    #[test]
    fn a_seeded_guard_retracts_the_edge_the_inline_bind_published() {
        // The fix, from the binder's angle: seeding with `bound` is what makes
        // the first detach after a clean start reach node health.
        let mut g = ChurnGuard::new();
        let t0 = Instant::now();
        g.bound(t0);

        let out = g.detached(t0 + MIN_STABLE_BINDING + Duration::from_secs(60));
        assert!(
            out.retract,
            "the edge `start_async` published must be retracted on detach"
        );
        assert!(out.log_edge);
    }

    #[test]
    fn short_lived_bindings_back_off() {
        // The failure this guards: a receive loop that gives up on a
        // persistent error while the interface stays UP. Bind succeeds, dies,
        // rebinds, dies — once per second, forever, undamped.
        let mut g = ChurnGuard::new();
        let mut t = Instant::now();

        for expected in [1u64, 2, 4] {
            g.bound(t);
            t += Duration::from_secs(1);
            let out = g.detached(t);
            assert_eq!(
                out.backoff,
                Some(Duration::from_secs(expected)),
                "streak {} should back off {expected}s",
                g.streak()
            );
        }
        assert_eq!(g.streak(), 3);
    }

    #[test]
    fn churn_stops_announcing_and_stops_logging() {
        let mut g = ChurnGuard::new();
        let mut t = Instant::now();

        // The detaches below the threshold are still news and still logged.
        for _ in 0..CHURN_THRESHOLD - 1 {
            assert!(g.bound(t).announce);
            t += Duration::from_secs(1);
            let out = g.detached(t);
            assert!(out.log_edge, "the first few detaches are still news");
            assert!(!out.entered_churn);
        }

        // The detach that crosses the threshold reports the churn instead of
        // the edge: one line saying "this keeps happening", not two saying
        // "it happened" and "it keeps happening".
        assert!(g.bound(t).announce);
        t += Duration::from_secs(1);
        let crossing = g.detached(t);
        assert!(crossing.entered_churn, "crossing must be announced once");
        assert!(!crossing.log_edge, "the churn line replaces the edge line");

        // Past the threshold: bindings are no longer announced as recoveries,
        // so node health stays put instead of flapping every second, and the
        // edges stop being logged.
        for _ in 0..5 {
            assert!(!g.bound(t).announce, "a churning bind is not a recovery");
            t += Duration::from_secs(1);
            let out = g.detached(t);
            assert!(!out.log_edge, "churn must not log per cycle");
            assert!(!out.retract, "nothing was announced, so nothing to retract");
            assert!(
                !out.entered_churn,
                "the threshold is crossed once, not repeatedly"
            );
        }
    }

    #[test]
    fn backoff_during_churn_is_capped() {
        let mut g = ChurnGuard::new();
        let mut t = Instant::now();
        let mut last = None;
        for _ in 0..12 {
            g.bound(t);
            t += Duration::from_secs(1);
            last = g.detached(t).backoff;
        }
        assert_eq!(
            last,
            Some(Duration::from_secs(30)),
            "churn backoff must climb to the ceiling and stop"
        );
    }

    #[test]
    fn a_binding_that_lasts_ends_the_streak_and_announces_once() {
        let mut g = ChurnGuard::new();
        let mut t = Instant::now();

        // Churn into the held-back state.
        for _ in 0..CHURN_THRESHOLD + 1 {
            g.bound(t);
            t += Duration::from_secs(1);
            g.detached(t);
        }
        assert!(!g.bound(t).announce);

        // Not yet stable: still nothing to say.
        assert!(!g.stabilized(t + Duration::from_secs(1)));

        // Survived the floor: announce exactly once, and the streak is over.
        let stable_at = t + MIN_STABLE_BINDING;
        assert!(
            g.stabilized(stable_at),
            "a binding that lasts is a recovery"
        );
        assert!(
            !g.stabilized(stable_at + Duration::from_secs(60)),
            "recovery is announced once, not on every tick"
        );
        assert_eq!(g.streak(), 0);

        // And the next detach behaves like an ordinary one again.
        let out = g.detached(stable_at + Duration::from_secs(60));
        assert!(out.retract);
        assert!(out.log_edge);
        assert_eq!(out.backoff, None);
    }

    #[test]
    fn stabilized_is_silent_for_an_ordinary_binding() {
        // A bind that was announced immediately must not be announced again
        // when it passes the stability floor.
        let mut g = ChurnGuard::new();
        let t = Instant::now();
        assert!(g.bound(t).announce);
        assert!(!g.stabilized(t + MIN_STABLE_BINDING + Duration::from_secs(1)));
    }

    #[test]
    fn policy_labels() {
        assert_eq!(AbsencePolicy::from_optional(true), AbsencePolicy::Optional);
        assert_eq!(AbsencePolicy::from_optional(false), AbsencePolicy::Required);
        assert!(AbsencePolicy::Optional.is_optional());
        assert!(!AbsencePolicy::Required.is_optional());
        assert_eq!(AbsencePolicy::Required.as_str(), "required");
    }
}
