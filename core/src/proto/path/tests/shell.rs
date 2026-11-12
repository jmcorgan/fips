//! The test shell: a node that runs one [`Bundle`] as a host would, and
//! checks after every call the rules no output may break, whatever the
//! test asserts beside them.
//!
//! The checks are functions over one call's outputs, so
//! `each_shell_check_fails_on_an_output_that_breaks_it` can show each one
//! firing on a hand-built output that breaks it. [`Checks`] holds what they
//! remember across calls and runs them around one step, for this shell and
//! for any other that drives a real bundle.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::fmt;

use crate::entropy::EntropySource;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::link::LinkMessageType;
use crate::proto::mmp::quality_index;
use crate::proto::path::rules;
use crate::proto::path::wire::{
    PATH_PROBE_MIN_SIZE, PathAck, PathCaps, PathClose, PathCloseReason, PathFlags, PathProbe,
};
use crate::proto::path::{
    Account, Bundle, Charge, Class, Config, Env, Facts, Input, Kind, Medium, Output, Outputs,
    Params, PathRef, PathState, PeerPath, Pin, Refusal, Role, Scope, Source, Switch, Why,
};
use crate::testutil::{SeededEntropy, TestClock, TestInstant, seed_entropy};
use crate::transport::{TransportAddr, TransportId};

std::thread_local! {
    /// Driver slots dropped on this thread.
    static DROPS: Cell<usize> = const { Cell::new(0) };
    /// The last slot serial handed out on this thread.
    static SERIAL: Cell<u64> = const { Cell::new(0) };
    /// Draws [`Scripted`] gives before it falls back to the seeded source.
    static SCRIPT: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
}

/// A driver slot with a serial number that counts its drops, standing in
/// for one whose drop closes a socket.
pub(crate) struct Slot {
    /// Unique on its thread.
    pub(super) serial: u64,
}

impl Default for Slot {
    fn default() -> Self {
        let serial = SERIAL.with(|s| {
            s.set(s.get() + 1);
            s.get()
        });
        Self { serial }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        DROPS.with(|d| d.set(d.get() + 1));
    }
}

// Without the serial, so two nodes driven alike print alike.
impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Slot")
    }
}

/// Driver slots dropped on this thread so far.
pub(super) fn drops() -> usize {
    DROPS.with(Cell::get)
}

/// One fact about a transport that the stub answers in place of its
/// default.
#[derive(Clone, Copy, Debug)]
pub(super) enum Fact {
    /// Its anonymity class.
    Class(Class),
    /// Its fixed kind, or `None` for the kind of the peer's address.
    Kind(Option<Kind>),
    /// Its role.
    Role(Role),
    /// Its medium.
    Medium(Medium),
    /// Whether the node would accept the peer's handshake on it.
    Accepts(bool),
    /// Whether the node would dial the peer on it.
    Dials(bool),
}

/// The host's facts: every transport has a link MTU of 1280, has a
/// medium the host does not know, is connectionless, is clear, has the fixed kind Local, has
/// the role Normal, and accepts and dials the peer, unless the stub says
/// otherwise. The latest fact given for a transport wins, so a test may
/// change one between steps.
#[derive(Default)]
pub(super) struct Stub {
    mtus: Vec<(TransportId, usize)>,
    oriented: Vec<TransportId>,
    facts: Vec<(TransportId, Fact)>,
    /// How many facts have been given, so the shell can tell whether the
    /// facts changed between two steps.
    changes: usize,
}

impl Stub {
    /// The stub with `fact` given for `transport`.
    pub(super) fn fact(mut self, transport: TransportId, fact: Fact) -> Self {
        self.change(transport, fact);
        self
    }

    /// Give `fact` for `transport` from now on.
    pub(super) fn change(&mut self, transport: TransportId, fact: Fact) {
        self.facts.push((transport, fact));
        self.changes += 1;
    }

    /// The latest fact for `transport` that `pick` takes.
    fn latest<T>(&self, transport: TransportId, pick: impl Fn(Fact) -> Option<T>) -> Option<T> {
        self.facts
            .iter()
            .rev()
            .filter(|(t, _)| *t == transport)
            .find_map(|&(_, f)| pick(f))
    }

    /// The stub with `transport`'s link MTU set to `mtu`.
    pub(super) fn mtu(mut self, transport: TransportId, mtu: usize) -> Self {
        self.mtus.push((transport, mtu));
        self
    }

    /// The stub with `transport` connection-oriented.
    pub(super) fn oriented(mut self, transport: TransportId) -> Self {
        self.oriented.push(transport);
        self
    }
}

impl Facts for Stub {
    fn mtu(&self, transport: TransportId, _addr: &TransportAddr) -> usize {
        self.mtus
            .iter()
            .rev()
            .find(|(t, _)| *t == transport)
            .map_or(1280, |&(_, m)| m)
    }

    fn medium(&self, transport: TransportId, _addr: &TransportAddr) -> Medium {
        let pick = |f| {
            if let Fact::Medium(m) = f {
                Some(m)
            } else {
                None
            }
        };
        self.latest(transport, pick).unwrap_or(Medium::Unknown)
    }

    fn oriented(&self, transport: TransportId) -> bool {
        self.oriented.contains(&transport)
    }

    fn class(&self, transport: TransportId) -> Class {
        let pick = |f| {
            if let Fact::Class(c) = f {
                Some(c)
            } else {
                None
            }
        };
        self.latest(transport, pick).unwrap_or(Class::Clear)
    }

    fn kind(&self, transport: TransportId) -> Option<Kind> {
        let pick = |f| if let Fact::Kind(k) = f { Some(k) } else { None };
        self.latest(transport, pick).unwrap_or(Some(Kind::Local))
    }

    fn role(&self, transport: TransportId) -> Role {
        let pick = |f| if let Fact::Role(r) = f { Some(r) } else { None };
        self.latest(transport, pick).unwrap_or(Role::Normal)
    }

    fn accepts(&self, transport: TransportId) -> bool {
        let pick = |f| {
            if let Fact::Accepts(a) = f {
                Some(a)
            } else {
                None
            }
        };
        self.latest(transport, pick).unwrap_or(true)
    }

    fn dials(&self, transport: TransportId) -> bool {
        let pick = |f| {
            if let Fact::Dials(d) = f {
                Some(d)
            } else {
                None
            }
        };
        self.latest(transport, pick).unwrap_or(true)
    }
}

/// An entropy source that gives the draws queued by [`script`] first, one
/// per four-byte fill, and then falls back to [`SeededEntropy`].
pub(super) struct Scripted;

impl EntropySource for Scripted {
    fn fill(dest: &mut [u8]) {
        let next = SCRIPT.with(|s| {
            let mut s = s.borrow_mut();
            (dest.len() == 4 && !s.is_empty()).then(|| s.remove(0))
        });
        match next {
            Some(v) => dest.copy_from_slice(&v.to_le_bytes()),
            None => SeededEntropy::fill(dest),
        }
    }
}

/// Queue `draws` for [`Scripted`] on this thread.
pub(super) fn script(draws: &[u32]) {
    SCRIPT.with(|s| *s.borrow_mut() = draws.to_vec());
}

/// Local transport `n`.
pub(super) fn t(n: u32) -> TransportId {
    TransportId::new(n)
}

/// The peer's address `n`.
pub(super) fn addr(n: u8) -> TransportAddr {
    TransportAddr::from_string(&format!("10.0.0.{n}:2121"))
}

/// The peer's Internet-facing address `n`, outside every local range.
pub(super) fn public(n: u8) -> TransportAddr {
    TransportAddr::from_string(&format!("203.0.113.{n}:2121"))
}

/// The pair (`transport`, `a`).
pub(super) fn pair(transport: TransportId, a: TransportAddr) -> PathRef {
    PathRef { transport, addr: a }
}

/// One output, with each driver slot replaced by its serial: the shell
/// keeps the slot itself.
pub(crate) type Out = Output<u64>;

/// A node running one bundle on the test clock, whose link was made at
/// instant 0, on (`t(1)`, `addr(1)`) unless the test chose another pair.
pub(super) struct Node<E: EntropySource = SeededEntropy> {
    /// The machine.
    pub(super) b: Bundle<TestClock, E, Slot>,
    /// The instant the next call is made at.
    pub(super) now: TestInstant,
    /// The facts the calls see.
    pub(super) facts: Stub,
    /// The link's cost the calls see, as the host measures it.
    pub(super) cost: f64,
    /// Every slot the bundle handed out, kept so none drops during a run.
    kept: Vec<Slot>,
    /// What the checks of each call remember.
    checks: Checks,
}

impl Node<SeededEntropy> {
    /// A node whose peer is not yet known to be capable, drawing from the
    /// seeded source reseeded with `seed`.
    pub(super) fn new(seed: u64) -> Self {
        Self::make(seed)
    }

    /// A node whose peer has shown it is capable, by a message
    /// ([`Node::heard`]) at instant 0.
    pub(super) fn capable(seed: u64) -> Self {
        let mut n = Self::make(seed);
        n.heard();
        n
    }

    /// A node with multipath disabled, whose peer is not known to be
    /// capable.
    pub(super) fn disabled(seed: u64) -> Self {
        let cfg = Config {
            enabled: false,
            ..Config::draft()
        };
        Self::build(
            seed,
            Params::new(cfg).expect("the draft's values are valid"),
            Stub::default(),
            p(),
        )
    }

    /// A node whose bundle runs with `params`, its link made on
    /// `original` under `facts`, which fix the link's class and kind, and
    /// whose peer is not yet known to be capable.
    pub(super) fn on(seed: u64, params: Params, facts: Stub, original: PathRef) -> Self {
        Self::build(seed, params, facts, original)
    }
}

impl<E: EntropySource> Node<E> {
    /// A node over the source `E`, with the seeded source reseeded with
    /// `seed` for any draw `E` passes on to it.
    pub(super) fn make(seed: u64) -> Self {
        Self::build(seed, Params::draft(), Stub::default(), p())
    }

    /// A node over the source `E` whose bundle runs with `params`, its link
    /// made on `original` with the host's `facts`.
    fn build(seed: u64, params: Params, facts: Stub, original: PathRef) -> Self {
        seed_entropy(seed);
        let env = Env {
            facts: &facts,
            cost: 1.0,
        };
        let b = Bundle::new(
            TestInstant(0),
            original.transport,
            original.addr.clone(),
            params,
            &env,
        );
        let id = b.paths().get(0).expect("the original path").path_id();
        let checks = Checks::new(*params.config(), (id, original), facts.changes);
        Self {
            b,
            now: TestInstant(0),
            facts,
            cost: 1.0,
            kept: Vec::new(),
            checks,
        }
    }

    /// The node with `facts` in place of the default stub. The facts must
    /// give the link the class and kind it was made with, which the bundle
    /// fixed then; a test that needs others builds its node with them.
    pub(super) fn with(mut self, facts: Stub) -> Self {
        let (_, original) = &self.checks.first;
        assert_eq!(
            self.b.scope(),
            rules::link(&facts, original.transport, &original.addr),
            "the facts change the link's class or kind, fixed when it was made"
        );
        self.checks.seen = facts.changes;
        self.facts = facts;
        self
    }

    /// Make the peer capable by a message, as in use: step a `PathClose`
    /// from the original path's pair that names no path held. Any path
    /// message makes the peer capable (draft Section 5.2), and a close
    /// naming no path changes nothing else. Its frame is not accounted,
    /// since no wire delivered it.
    pub(super) fn heard(&mut self) -> Vec<Out> {
        let ids: Vec<u32> = self.b.paths().paths().iter().map(|p| p.path_id()).collect();
        let unknown = (1..=u32::MAX)
            .find(|id| !ids.contains(id))
            .expect("an identifier no path holds");
        let from = self
            .checks
            .original(&self.b)
            .unwrap_or_else(|| self.checks.first.1.clone());
        self.step(Input::Close {
            transport: from.transport,
            addr: from.addr,
            msg: close_from(unknown),
        })
    }

    /// Our identifier for the path at `index`.
    pub(super) fn id(&self, index: usize) -> u32 {
        self.b.paths().get(index).expect("a path held").path_id()
    }

    /// Step `input` at `now`, check the outputs and return them.
    pub(super) fn step(&mut self, input: Input) -> Vec<Out> {
        let call = self
            .checks
            .before(&self.b, self.now, &input, self.cost, self.facts.changes);
        let mut env = Env {
            facts: &self.facts,
            cost: self.cost,
        };
        let out = self.b.step(self.now, input.clone(), &mut env);
        let stepped = call.stepped(&self.b);
        let out = keep(out, &mut self.kept);
        if let Err(e) = self
            .checks
            .after(stepped, &self.b, &input, &out, &self.facts)
        {
            panic!("the shell's check failed on {input:?}: {e}\noutputs: {out:?}");
        }
        out
    }

    /// Poll at `now`.
    pub(super) fn poll(&mut self) -> Vec<Out> {
        self.step(Input::Poll)
    }

    /// Poll at the bundle's next wake, unless it is later than `until`.
    /// Returns the outputs, or `None` with no poll made.
    pub(super) fn tick(&mut self, until: TestInstant) -> Option<Vec<Out>> {
        let wake = self.b.next_wake().filter(|w| *w <= until)?;
        self.now = wake;
        Some(self.poll())
    }

    /// Close the bundle and check that every path held comes back once.
    pub(super) fn close(mut self) -> Vec<Out> {
        let held: Vec<PathRef> = self
            .b
            .paths()
            .paths()
            .iter()
            .map(|p| pair(p.transport_id(), p.addr().clone()))
            .collect();
        let before = drops();
        let out = self.b.close();
        let after = drops();
        let out = keep(out, &mut self.kept);
        let checked = slots(&out, &mut self.checks.handed, before, after)
            .and_then(|()| released_once(&held, &out));
        if let Err(e) = checked {
            panic!("the shell's check failed on close: {e}\noutputs: {out:?}");
        }
        out
    }

    /// Start the link again on its active path, as a won crossed handshake
    /// whose msg2 came from that path's pair does: [`Self::renew_to`] that
    /// pair.
    pub(super) fn renew(&mut self) -> Vec<Out> {
        let to = self
            .b
            .paths()
            .active()
            .map(|p| (p.transport_id(), p.addr().clone()))
            .expect("the renewed link has an active path");
        self.renew_to(to)
    }

    /// Start the link again at `to`, as a won crossed handshake does, and
    /// check that no slot dropped and none came back twice. The shell then
    /// follows the new original path, and the capability probes from the
    /// new link's first.
    pub(super) fn renew_to(&mut self, to: (TransportId, TransportAddr)) -> Vec<Out> {
        let before = drops();
        let env = Env {
            facts: &self.facts,
            cost: self.cost,
        };
        let out = self.b.renew(self.now, &env, to);
        let after = drops();
        let out = keep(out, &mut self.kept);
        if let Err(e) = slots(&out, &mut self.checks.handed, before, after) {
            panic!("the shell's check failed on renew: {e}\noutputs: {out:?}");
        }
        self.checks.renewed(&self.b);
        out
    }

    /// Account for an authentic frame of `len` bytes and link message type
    /// `ty` from (`transport`, `a`), and check that it dropped no slot.
    pub(super) fn account(
        &mut self,
        transport: TransportId,
        a: &TransportAddr,
        len: usize,
        ty: u8,
    ) -> Account {
        let before = drops();
        let account = self.b.account(self.now, transport, a, len, ty);
        if let Err(e) = slots(&[], &mut self.checks.handed, before, drops()) {
            panic!("the shell's check failed on a frame from {a:?}: {e}");
        }
        account
    }

    /// Charge a frame from (`transport`, `a`) that failed to authenticate,
    /// and check that it dropped no slot and that a trip makes the next
    /// wake due at once.
    pub(super) fn charge(&mut self, transport: TransportId, a: &TransportAddr) -> Charge {
        let before = drops();
        let charge = self.b.charge(self.now, transport, a);
        let checked = slots(&[], &mut self.checks.handed, before, drops())
            .and_then(|()| tripped(charge, self.b.next_wake(), self.now));
        if let Err(e) = checked {
            panic!("the shell's check failed on a failure from {a:?}: {e}");
        }
        charge
    }

    /// An authentic frame from (`transport`, `a`) that is not accounted
    /// starts its path's count of failures again; check that it dropped no
    /// slot.
    pub(super) fn authentic(&mut self, transport: TransportId, a: &TransportAddr) {
        let before = drops();
        self.b.authentic(transport, a);
        if let Err(e) = slots(&[], &mut self.checks.handed, before, drops()) {
            panic!("the shell's check failed on an authentic frame from {a:?}: {e}");
        }
    }

    /// Configuration lists the candidate (`transport`, `a`).
    pub(super) fn candidate(&mut self, transport: TransportId, a: TransportAddr) -> Vec<Out> {
        self.report(transport, a, Source::Config)
    }

    /// `source` reports the candidate (`transport`, `a`).
    pub(super) fn report(
        &mut self,
        transport: TransportId,
        a: TransportAddr,
        source: Source,
    ) -> Vec<Out> {
        self.step(Input::Candidate {
            transport,
            addr: a,
            source,
        })
    }

    /// `source` no longer lists the candidate (`transport`, `a`).
    pub(super) fn unlist(
        &mut self,
        transport: TransportId,
        a: TransportAddr,
        source: Source,
    ) -> Vec<Out> {
        self.step(Input::Unlisted {
            transport,
            addr: a,
            source,
        })
    }

    /// The peer's probe `msg` arrives on `transport` from `a`.
    pub(super) fn probe(
        &mut self,
        transport: TransportId,
        a: TransportAddr,
        msg: PathProbe,
    ) -> Vec<Out> {
        self.step(Input::Probe {
            transport,
            addr: a,
            msg,
        })
    }

    /// The peer's ack `msg` arrives on `transport` from `a`.
    pub(super) fn ack(
        &mut self,
        transport: TransportId,
        a: TransportAddr,
        msg: PathAck,
    ) -> Vec<Out> {
        self.step(Input::Ack {
            transport,
            addr: a,
            msg,
        })
    }

    /// The peer's close `msg` arrives on `transport` from `a`.
    pub(super) fn closed(
        &mut self,
        transport: TransportId,
        a: TransportAddr,
        msg: PathClose,
    ) -> Vec<Out> {
        self.step(Input::Close {
            transport,
            addr: a,
            msg,
        })
    }
}

/// What the checks of one bundle remember across calls.
pub(crate) struct Checks {
    /// Our identifier for the original path, and the pair the link was
    /// made on.
    first: (u32, PathRef),
    /// Serials of the slots handed out, to catch one handed out twice.
    handed: Vec<u64>,
    /// `Orphaned` outputs seen so far.
    orphans: usize,
    /// The bundle's settings.
    cfg: Config,
    /// The capability probes and reports seen so far.
    asked: Asked,
    /// The host's count of changes to its facts at the last step, so a poll
    /// counts as early only while the facts are unchanged since then.
    seen: usize,
}

/// What [`Checks::before`] reads ahead of one step.
pub(crate) struct Call {
    /// The call's instant.
    now: TestInstant,
    /// The link's cost the call sees.
    cost: f64,
    /// The pair of the path active before the call.
    active: Option<PathRef>,
    /// Whether the active path's transport is going.
    closing: bool,
    /// Our identifier for the path active before the call.
    leaving: Option<u32>,
    /// The paths held before the call, by our identifier.
    named: Vec<(u32, PathRef)>,
    /// Our identifier for the original path and its pair before the call.
    first: Option<(u32, PathRef)>,
    /// Whether this is a poll before the next wake.
    early: bool,
    /// The bundle before an early poll.
    was: Option<String>,
    /// The drops counted before the call.
    before: usize,
    /// The bundle's price of the link before the call.
    priced: f64,
}

/// A [`Call`] with what its step changed, read before the shell takes the
/// slots out of the outputs, for [`Checks::after`].
pub(crate) struct Stepped {
    /// What was read ahead of the step.
    call: Call,
    /// The drops counted after it.
    after: usize,
    /// The bundle's price of the link after it.
    repriced: f64,
    /// Whether an early poll left the bundle as it was.
    same: bool,
}

impl Call {
    /// Read what the step did to `b`, straight after it.
    pub(crate) fn stepped<E: EntropySource>(self, b: &Bundle<TestClock, E, Slot>) -> Stepped {
        let after = drops();
        let repriced = b.cost(self.now, self.cost);
        let same = self.was.as_ref().is_none_or(|w| *w == format!("{b:?}"));
        Stepped {
            call: self,
            after,
            repriced,
            same,
        }
    }
}

impl Checks {
    /// The checks of a bundle running `cfg`, whose original path is `first`,
    /// on a host whose facts have changed `seen` times.
    pub(crate) fn new(cfg: Config, first: (u32, PathRef), seen: usize) -> Self {
        Self {
            first,
            handed: Vec::new(),
            orphans: 0,
            cfg,
            asked: Asked::default(),
            seen,
        }
    }

    /// The original path's pair, while `b` holds it.
    fn original<E: EntropySource>(&self, b: &Bundle<TestClock, E, Slot>) -> Option<PathRef> {
        let (id, _) = &self.first;
        b.paths()
            .paths()
            .iter()
            .find(|p| p.path_id() == *id)
            .map(|p| pair(p.transport_id(), p.addr().clone()))
    }

    /// Follow the new original path of a renewed link, and its capability
    /// probes from the new link's first.
    pub(crate) fn renewed<E: EntropySource>(&mut self, b: &Bundle<TestClock, E, Slot>) {
        if let Some(path) = b.paths().get(0) {
            self.first = (
                path.path_id(),
                pair(path.transport_id(), path.addr().clone()),
            );
        }
        self.asked = Asked::default();
    }

    /// Read `b` ahead of a step of `input` at `now`. `changes` is the host's
    /// count of changes to its facts.
    pub(crate) fn before<E: EntropySource>(
        &mut self,
        b: &Bundle<TestClock, E, Slot>,
        now: TestInstant,
        input: &Input,
        cost: f64,
        changes: usize,
    ) -> Call {
        let active = b
            .paths()
            .active()
            .map(|p| pair(p.transport_id(), p.addr().clone()));
        // The active path's transport going releases it with the rest.
        let closing = matches!(
            input,
            Input::Removed { transport } | Input::Present { transport, present: false }
                if active.as_ref().is_some_and(|a| a.transport == *transport)
        );
        let leaving = b.paths().active().map(|p| p.path_id());
        let named = named(b);
        let first = self.original(b).map(|to| (self.first.0, to));
        // A poll before the next wake does nothing only while the facts
        // are unchanged since the last step (`Input::Poll`): after a change
        // it may admit a candidate a rule refused.
        let early =
            *input == Input::Poll && changes == self.seen && b.next_wake().is_none_or(|w| now < w);
        self.seen = changes;
        let was = early.then(|| format!("{b:?}"));
        let before = drops();
        let priced = b.cost(now, cost);
        Call {
            now,
            cost,
            active,
            closing,
            leaving,
            named,
            first,
            early,
            was,
            before,
            priced,
        }
    }

    /// Check one step's outputs `out`, the slots already out of them,
    /// against what was read around it and `b` after it. The first rule
    /// broken is the error.
    pub(crate) fn after<E: EntropySource>(
        &mut self,
        step: Stepped,
        b: &Bundle<TestClock, E, Slot>,
        input: &Input,
        out: &[Out],
        facts: &dyn Facts,
    ) -> Result<(), String> {
        let Stepped {
            call,
            after,
            repriced,
            same,
        } = step;
        let dead = dead(b, self.first.0);
        let terms = Terms {
            facts,
            link: b.scope(),
            mix: self.cfg.mix_kinds,
        };
        let calm = Calm {
            now: call.now,
            capable: b.capable(),
            first: call.first.as_ref(),
            eligible: eligible(b, &terms),
            cfg: &self.cfg,
        };
        quiet(out, &calm, &mut self.asked)
            .and_then(|()| silent(out, self.cfg.enabled))
            .and_then(|()| acks(Some(input), out, facts))
            .and_then(|()| sizes(out, facts))
            .and_then(|()| moves(Some(input), out))
            .and_then(|()| ruled(out, &terms, call.first.as_ref(), &dead))
            .and_then(|()| closes(out, &call.named))
            .and_then(|()| connects(out, facts, &held_pairs(b)))
            .and_then(|()| slots(out, &mut self.handed, call.before, after))
            .and_then(|()| active_kept(out, call.active.as_ref(), call.closing))
            .and_then(|()| switches(out, &acked(b)))
            .and_then(|()| chosen(out, call.leaving, &held_states(b)))
            .and_then(|()| tiered(active_pair(b).as_ref(), &live_acked(b), facts, b.pin()))
            .and_then(|()| pinned(out, b.pin()))
            .and_then(|()| frozen(out, call.priced, repriced))
            .and_then(|()| held(b))
            .and_then(|()| orphans(out, &mut self.orphans))
            .and_then(|()| idle(call.early, out, same))
            .and_then(|()| ahead(b.next_wake(), call.now))
    }
}

/// Move every slot in `out` into `kept`, leaving its serial in its place.
pub(crate) fn keep(out: Outputs<Slot>, kept: &mut Vec<Slot>) -> Vec<Out> {
    let mut serial = |driver: Slot| {
        let s = driver.serial;
        kept.push(driver);
        s
    };
    out.into_iter()
        .map(|o| match o {
            Output::Send { to, bytes } => Output::Send { to, bytes },
            Output::Moved { from, to, driver } => Output::Moved {
                from,
                to,
                driver: serial(driver),
            },
            Output::Released { to, driver, keep } => Output::Released {
                to,
                driver: serial(driver),
                keep,
            },
            Output::State {
                to,
                path_id,
                from,
                next,
                why,
            } => Output::State {
                to,
                path_id,
                from,
                next,
                why,
            },
            Output::Capable => Output::Capable,
            Output::NotCapable => Output::NotCapable,
            Output::Refused { to, why } => Output::Refused { to, why },
            Output::Switched { from, to, why } => Output::Switched { from, to, why },
            Output::Orphaned => Output::Orphaned,
            Output::Connect { to } => Output::Connect { to },
            Output::Proven { to, mtu } => Output::Proven { to, mtu },
        })
        .collect()
}

/// What the shell has seen of capability across calls.
#[derive(Default)]
pub(super) struct Asked {
    /// The instants of the capability probes sent so far.
    pub(super) sent: Vec<TestInstant>,
    /// Whether the bundle has reported the peer capable.
    pub(super) capable: bool,
    /// How often it has reported the link not capable.
    pub(super) told: usize,
}

/// What one call's capability probes are checked against.
pub(super) struct Calm<'a> {
    /// The call's instant.
    pub(super) now: TestInstant,
    /// Whether the peer is known to be capable after the call.
    pub(super) capable: bool,
    /// Our identifier for the original path and its pair before the call.
    pub(super) first: Option<&'a (u32, PathRef)>,
    /// Whether the bundle holds, after the call, a candidate that allows
    /// capability probes, by the shell's own reading ([`eligible`]).
    pub(super) eligible: bool,
    /// The bundle's settings.
    pub(super) cfg: &'a Config,
}

/// Whether `b` holds a candidate that allows capability probes (draft
/// Section 5.2): one some source lists, not held back, whose pair is not
/// held as a path, that path policy lets the node probe under `terms`.
pub(super) fn eligible<E: EntropySource>(
    b: &Bundle<TestClock, E, Slot>,
    terms: &Terms<'_>,
) -> bool {
    b.candidates().iter().any(|e| {
        let (t, a) = (e.transport(), e.addr());
        !e.sources().is_empty()
            && !e.held()
            && b.paths().find(t, a).is_none()
            && rules::probe(terms.facts, terms.link, terms.mix, t, a).is_ok()
    })
}

/// The least spacing after the `n`-th capability probe, counted from 1, by
/// the draft's rule written out again here (Section 5.2): `budget` probes
/// share `span`, then the gap starts at `span` and doubles to `cap`.
pub(super) fn spacing(n: usize, cfg: &Config) -> crate::time::Duration {
    let budget = usize::from(cfg.budget);
    if n < budget {
        return cfg.span / u32::from(cfg.budget);
    }
    let mut gap = cfg.span;
    for _ in budget..n {
        gap = gap.saturating_mul(2).min(cfg.cap);
    }
    gap.min(cfg.cap)
}

/// Until the peer is known to be capable, nothing goes but capability
/// probes and no connection is opened (draft Sections 5.2 and 8.1): each
/// is a `PathProbe` of exactly 27 bytes on the original path's pair,
/// carrying its identifier, `ACTIVE` and no capability bit; each goes at
/// least [`spacing`] after the one before; none goes in a call after which
/// no candidate allows them. The link is reported not capable at most
/// once, and never after the peer is reported capable.
pub(super) fn quiet(out: &[Out], calm: &Calm<'_>, asked: &mut Asked) -> Result<(), String> {
    for o in out {
        match o {
            Output::Capable => asked.capable = true,
            Output::NotCapable => {
                asked.told += 1;
                if asked.capable {
                    return Err(String::from("the link reported not capable after capable"));
                }
                if asked.told > 1 {
                    return Err(format!(
                        "the link reported not capable {} times",
                        asked.told
                    ));
                }
            }
            Output::Connect { to } if !calm.capable => {
                return Err(format!(
                    "a connection to {to:?} for a peer not known to be capable"
                ));
            }
            Output::Send { .. }
            | Output::Connect { .. }
            | Output::Moved { .. }
            | Output::Released { .. }
            | Output::State { .. }
            | Output::Refused { .. }
            | Output::Switched { .. }
            | Output::Orphaned
            | Output::Proven { .. } => {}
        }
    }
    if calm.capable {
        return Ok(());
    }
    for o in out {
        let Output::Send { to, bytes } = o else {
            continue;
        };
        if bytes.first() != Some(&LinkMessageType::PathProbe.to_byte()) {
            return Err(format!(
                "a path message other than a probe went on {to:?} to a peer not known to be \
                 capable"
            ));
        }
        let probe = PathProbe::decode(&bytes[1..]).map_err(|e| format!("{e:?}"))?;
        let Some((id, original)) = calm.first else {
            return Err(format!(
                "a capability probe on {to:?} with no original path"
            ));
        };
        if to != original || probe.path_id != *id {
            return Err(format!(
                "a capability probe on {to:?}, not the original path"
            ));
        }
        if bytes.len() != PATH_PROBE_MIN_SIZE {
            return Err(format!("a capability probe of {} bytes", bytes.len()));
        }
        if !probe.flags.active() || probe.caps != PathCaps::default() {
            return Err(format!("a capability probe with {probe:?}"));
        }
        if !calm.eligible {
            return Err(String::from(
                "a capability probe went with no candidate that allows one",
            ));
        }
        let n = asked.sent.len();
        if let Some(&last) = asked.sent.last() {
            let gap = spacing(n, calm.cfg);
            let since = crate::time::Duration::from_millis(calm.now.0.saturating_sub(last.0));
            if since < gap {
                return Err(format!(
                    "capability probe {} at {:?}, under {gap:?} after {last:?}",
                    n + 1,
                    calm.now
                ));
            }
        }
        asked.sent.push(calm.now);
    }
    Ok(())
}

/// With multipath disabled (`enabled` false), nothing is sent and no
/// connection is asked for, whatever the peer is held to be.
pub(super) fn silent(out: &[Out], enabled: bool) -> Result<(), String> {
    let sent = out
        .iter()
        .any(|o| matches!(o, Output::Send { .. } | Output::Connect { .. }));
    if sent && !enabled {
        return Err(String::from(
            "a path message or connection went out with multipath disabled",
        ));
    }
    Ok(())
}

/// The raw sends of `out` whose type byte is `ty`.
fn raw(out: &[Out], ty: LinkMessageType) -> Vec<(&PathRef, &[u8])> {
    out.iter()
        .filter_map(|o| {
            let Output::Send { to, bytes } = o else {
                return None;
            };
            (bytes.first() == Some(&ty.to_byte())).then_some((to, bytes.as_slice()))
        })
        .collect()
}

/// Every ack answers the probe this call was given, on the pair it came
/// from, exactly as long as the smaller of the probe and the link MTU less
/// the frame overhead, and never at less than 27 bytes, with `EXT` clear.
pub(super) fn acks(input: Option<&Input>, out: &[Out], facts: &dyn Facts) -> Result<(), String> {
    for (to, bytes) in raw(out, LinkMessageType::PathAck) {
        let Some(Input::Probe {
            transport,
            addr: from,
            msg,
        }) = input
        else {
            return Err(format!("an ack went out on {to:?} with no probe to answer"));
        };
        if to.transport != *transport || &to.addr != from {
            return Err(format!("an ack went to {to:?}, not to the probe's pair"));
        }
        if bytes.get(5).is_some_and(|f| f & PathFlags::EXT != 0) {
            return Err(String::from("an ack set EXT"));
        }
        let mtu = facts.mtu(*transport, from).saturating_sub(FRAME_OVERHEAD);
        let want = msg.len.min(mtu).max(PATH_PROBE_MIN_SIZE);
        if bytes.len() != want {
            return Err(format!("an ack is {} bytes, not {want}", bytes.len()));
        }
    }
    Ok(())
}

/// No probe is larger than its path's link MTU less the frame overhead,
/// none is shorter than 27 bytes, and none sets `EXT`.
pub(super) fn sizes(out: &[Out], facts: &dyn Facts) -> Result<(), String> {
    for (to, bytes) in raw(out, LinkMessageType::PathProbe) {
        let mtu = facts
            .mtu(to.transport, &to.addr)
            .saturating_sub(FRAME_OVERHEAD);
        if bytes.len() > mtu || bytes.len() < PATH_PROBE_MIN_SIZE {
            return Err(format!("a {}-byte probe on {to:?}, MTU {mtu}", bytes.len()));
        }
        if bytes.get(5).is_some_and(|f| f & PathFlags::EXT != 0) {
            return Err(String::from("a probe set EXT"));
        }
    }
    Ok(())
}

/// An address moves only on a path message: a probe or an ack.
pub(super) fn moves(input: Option<&Input>, out: &[Out]) -> Result<(), String> {
    let moved = out.iter().any(|o| matches!(o, Output::Moved { .. }));
    let message = matches!(input, Some(Input::Probe { .. } | Input::Ack { .. }));
    if moved && !message {
        return Err(format!("an address moved on {input:?}"));
    }
    Ok(())
}

/// What path policy is checked against: the host's facts at the call, the
/// link's class and kind, and whether it mixes kinds.
pub(super) struct Terms<'a> {
    /// The facts.
    pub(super) facts: &'a dyn Facts,
    /// The link's class and kind.
    pub(super) link: Scope,
    /// Whether kinds are mixed.
    pub(super) mix: bool,
}

/// The pairs of the Dead paths `b` holds other than the original path,
/// ours `first`.
fn dead<E: EntropySource>(b: &Bundle<TestClock, E, Slot>, first: u32) -> Vec<PathRef> {
    b.paths()
        .paths()
        .iter()
        .filter(|p| p.state() == PathState::Dead && p.path_id() != first)
        .map(|p| pair(p.transport_id(), p.addr().clone()))
        .collect()
}

/// Path policy holds at every output that admits, revives or moves a path,
/// or probes a Dead one, under the facts at the call (draft Sections 5.5
/// and 5.6). A path admitted from a candidate may be probed; one a probe
/// created may be created there; a path other than the original brought
/// back from Dead by carrier's return or by finding the peer again may be
/// probed, and one brought back by the peer's probe may be created there;
/// a path other than the original, `first` (our identifier for it
/// and its pair before the call), moved to a new pair may run there; and
/// no probe goes to a pair in `dead`, the Dead paths other than the
/// original after the call, that may not be probed. Paths held from
/// before are not checked: a change in the facts may leave one the rules
/// would refuse now.
pub(super) fn ruled(
    out: &[Out],
    terms: &Terms<'_>,
    first: Option<&(u32, PathRef)>,
    dead: &[PathRef],
) -> Result<(), String> {
    let Terms { facts, link, mix } = *terms;
    let check = |what: &str, to: &PathRef, r: Result<(), crate::proto::path::Rule>| {
        r.map_err(|rule| format!("{what} on {to:?} against the rule {rule:?}"))
    };
    for o in out {
        if let Output::State {
            to,
            path_id,
            from,
            next,
            why,
        } = o
        {
            let (t, a) = (to.transport, &to.addr);
            if from.is_none() && *next == Some(PathState::Probing) && *why == Why::Candidate {
                check(
                    "a candidate admitted",
                    to,
                    rules::probe(facts, link, mix, t, a),
                )?;
            }
            if from.is_none() && *why == Why::Probed {
                check(
                    "a path created by a probe",
                    to,
                    rules::admit(facts, link, mix, t, a),
                )?;
            }
            let back = *from == Some(PathState::Dead)
                && *next == Some(PathState::Probing)
                && first.is_none_or(|(id, _)| id != path_id);
            if back && matches!(why, Why::Returned | Why::Found) {
                check(
                    "a Dead path revived",
                    to,
                    rules::probe(facts, link, mix, t, a),
                )?;
            }
            if back && *why == Why::Probed {
                check(
                    "a Dead path revived by a probe",
                    to,
                    rules::admit(facts, link, mix, t, a),
                )?;
            }
        }
        if let Output::Moved { from, to, .. } = o
            && first.is_none_or(|(_, original)| original != from)
        {
            let r = rules::moves(facts, link, mix, to.transport, &to.addr);
            check("a path moved", to, r)?;
        }
    }
    for (to, _) in raw(out, LinkMessageType::PathProbe) {
        if dead.contains(to) {
            let r = rules::probe(facts, link, mix, to.transport, &to.addr);
            check("a Dead path probed", to, r)?;
        }
    }
    Ok(())
}

/// Each path `b` holds whose identifier the peer gave, by that identifier.
fn named<E: EntropySource>(b: &Bundle<TestClock, E, Slot>) -> Vec<(u32, PathRef)> {
    b.paths()
        .paths()
        .iter()
        .filter_map(|p| Some((p.peer_id()?, pair(p.transport_id(), p.addr().clone()))))
        .collect()
}

/// Every close names a path held before the call, by the peer's
/// identifier for it in `named`, and never travels on that path (draft
/// Section 5.8). That none goes to a peer not known to be capable is
/// [`quiet`]'s check.
pub(super) fn closes(out: &[Out], named: &[(u32, PathRef)]) -> Result<(), String> {
    for (to, close) in sent_closes(out) {
        let mut paths = named
            .iter()
            .filter(|(id, _)| *id == close.path_id)
            .peekable();
        if paths.peek().is_none() {
            return Err(format!(
                "a close on {to:?} names {:#x}, no path held",
                close.path_id
            ));
        }
        if paths.any(|(_, p)| *p == to) {
            return Err(format!("a close travels on {to:?}, the path it names"));
        }
    }
    Ok(())
}

/// The pairs of the paths `b` holds.
fn held_pairs<E: EntropySource>(b: &Bundle<TestClock, E, Slot>) -> Vec<PathRef> {
    b.paths()
        .paths()
        .iter()
        .map(|p| pair(p.transport_id(), p.addr().clone()))
        .collect()
}

/// Every connection asked for is to a path `held` after the call, on a
/// connection-oriented transport, and no probe goes on that path in the
/// same call: a probe waits for the connection to open.
pub(super) fn connects(out: &[Out], facts: &dyn Facts, held: &[PathRef]) -> Result<(), String> {
    let probed: Vec<&PathRef> = raw(out, LinkMessageType::PathProbe)
        .into_iter()
        .map(|(to, _)| to)
        .collect();
    for o in out {
        let Output::Connect { to } = o else {
            continue;
        };
        if !held.contains(to) {
            return Err(format!("a connection to {to:?}, a path not held"));
        }
        if !facts.oriented(to.transport) {
            return Err(format!(
                "a connection to {to:?} on a connectionless transport"
            ));
        }
        if probed.contains(&to) {
            return Err(format!("a probe on {to:?} with its connection asked for"));
        }
    }
    Ok(())
}

/// Every slot handed out is new, and the bundle dropped none itself.
pub(super) fn slots(
    out: &[Out],
    handed: &mut Vec<u64>,
    before: usize,
    after: usize,
) -> Result<(), String> {
    if after != before {
        return Err(format!("the call dropped {} driver slots", after - before));
    }
    for o in out {
        let serial = match o {
            Output::Moved { driver, .. } | Output::Released { driver, .. } => *driver,
            Output::Send { .. }
            | Output::State { .. }
            | Output::Capable
            | Output::NotCapable
            | Output::Refused { .. }
            | Output::Switched { .. }
            | Output::Orphaned
            | Output::Connect { .. }
            | Output::Proven { .. } => {
                continue;
            }
        };
        if handed.contains(&serial) {
            return Err(format!("slot {serial} was handed out twice"));
        }
        handed.push(serial);
    }
    Ok(())
}

/// No path is released while it is active, starting from the path active
/// before the call and following each switch in the outputs, except as
/// the bundle closes or the active path's transport goes (`closing`): the
/// active path is never evicted.
pub(super) fn active_kept(
    out: &[Out],
    active: Option<&PathRef>,
    closing: bool,
) -> Result<(), String> {
    let mut current = active;
    for o in out {
        match o {
            Output::Switched { to, .. } => current = Some(to),
            Output::Released { to, .. } if Some(to) == current && !closing => {
                return Err(format!("the active path {to:?} was released"));
            }
            Output::Released { .. }
            | Output::Send { .. }
            | Output::Moved { .. }
            | Output::State { .. }
            | Output::Capable
            | Output::NotCapable
            | Output::Refused { .. }
            | Output::Orphaned
            | Output::Connect { .. }
            | Output::Proven { .. } => {}
        }
    }
    Ok(())
}

/// The pairs of the acked paths `b` holds.
fn acked<E: EntropySource>(b: &Bundle<TestClock, E, Slot>) -> Vec<PathRef> {
    b.paths()
        .paths()
        .iter()
        .filter(|p| p.acked())
        .map(|p| pair(p.transport_id(), p.addr().clone()))
        .collect()
}

/// Every switch goes to an acked path, one of `acked`: a path carries the
/// link only once one of our probes on it has been answered.
pub(super) fn switches(out: &[Out], acked: &[PathRef]) -> Result<(), String> {
    for o in out {
        let Output::Switched { to, .. } = o else {
            continue;
        };
        if !acked.contains(to) {
            return Err(format!("a switch to {to:?}, a path not acked"));
        }
    }
    Ok(())
}

/// Each path `b` holds: our `path_id`, its pair and its state.
fn held_states<E: EntropySource>(b: &Bundle<TestClock, E, Slot>) -> Vec<(u32, PathRef, PathState)> {
    b.paths()
        .paths()
        .iter()
        .map(|p| {
            (
                p.path_id(),
                pair(p.transport_id(), p.addr().clone()),
                p.state(),
            )
        })
        .collect()
}

/// Every discretionary or pinned change goes from the path active before
/// it to another path, and both are Live after the call: such a change
/// runs only from a Live active path, to a path that may have turned Live
/// in the same call. The path active before is followed by our `path_id`,
/// from `active`, the one active before the call, through each switch in
/// the outputs, so a path that moved to a new pair in the call is still
/// the same path. `after` holds each path's identifier, pair and state
/// after the call.
pub(super) fn chosen(
    out: &[Out],
    active: Option<u32>,
    after: &[(u32, PathRef, PathState)],
) -> Result<(), String> {
    let find = |to: &PathRef| after.iter().find(|(_, held, _)| held == to);
    let live = |to: Option<&(u32, PathRef, PathState)>| {
        to.is_some_and(|(_, _, state)| *state == PathState::Live)
    };
    let mut current = active;
    for o in out {
        let Output::Switched { from, to, why } = o else {
            continue;
        };
        match why {
            Switch::Discretionary | Switch::Pinned => {
                let left = from.as_ref().and_then(find);
                let taken = find(to);
                if left.map(|(id, _, _)| *id) != current || current.is_none() {
                    return Err(format!(
                        "a {why:?} change from {from:?}, not the path active before it"
                    ));
                }
                if !live(left) || !live(taken) {
                    return Err(format!(
                        "a {why:?} change from {from:?} to {to:?}, not both Live"
                    ));
                }
                if left == taken {
                    return Err(format!("a {why:?} change from {to:?} to itself"));
                }
            }
            Switch::Mandatory | Switch::Handover => {}
        }
        current = find(to).map(|(id, _, _)| *id);
    }
    Ok(())
}

/// The pair of `b`'s active path, if it has one.
fn active_pair<E: EntropySource>(b: &Bundle<TestClock, E, Slot>) -> Option<PathRef> {
    b.paths()
        .active()
        .map(|p| pair(p.transport_id(), p.addr().clone()))
}

/// The pairs of the Live, acked paths `b` holds.
fn live_acked<E: EntropySource>(b: &Bundle<TestClock, E, Slot>) -> Vec<PathRef> {
    b.paths()
        .paths()
        .iter()
        .filter(|p| p.acked() && p.state() == PathState::Live)
        .map(|p| pair(p.transport_id(), p.addr().clone()))
        .collect()
}

/// The rank of a transport whose role is `role`, as the shell reckons it:
/// normal and preferred above backup, and backup above never.
fn standing(role: Role) -> u8 {
    match role {
        Role::Never => 0,
        Role::Backup => 1,
        Role::Normal | Role::Preferred => 2,
    }
}

/// Whether `pin` names the path `to`, as the shell reads a pin: the pin's
/// transport, and its address when it gives one.
fn names(pin: &Pin, to: &PathRef) -> bool {
    pin.transport == to.transport && pin.addr.as_ref().is_none_or(|a| *a == to.addr)
}

/// After the call, no Live, acked path, of those in `live`, ranks above
/// the active path `active` by the roles `facts` give its transport,
/// unless the operator's `pin` names the active path: a backup path, or
/// one held on a transport set never to carry paths, carries the link
/// only while no path of a higher rank is Live, or while it is pinned.
pub(super) fn tiered(
    active: Option<&PathRef>,
    live: &[PathRef],
    facts: &dyn Facts,
    pin: Option<&Pin>,
) -> Result<(), String> {
    let Some(a) = active.filter(|a| !pin.is_some_and(|pin| names(pin, a))) else {
        return Ok(());
    };
    let rank = |to: &PathRef| standing(facts.role(to.transport));
    match live.iter().find(|to| rank(to) > rank(a)) {
        Some(to) => Err(format!(
            "the active path {a:?} ranks below the Live path {to:?}"
        )),
        None => Ok(()),
    }
}

/// Every pinned change goes to a path the bundle's pin, `pin` after the
/// call, names.
pub(super) fn pinned(out: &[Out], pin: Option<&Pin>) -> Result<(), String> {
    for o in out {
        let Output::Switched {
            to,
            why: Switch::Pinned,
            ..
        } = o
        else {
            continue;
        };
        if !pin.is_some_and(|pin| names(pin, to)) {
            return Err(format!(
                "a pinned change to {to:?}, a path {pin:?} does not name"
            ));
        }
    }
    Ok(())
}

/// Across a call whose outputs `out` change the active path, the link's
/// cost the bundle gives at the call's instant, for the cost the host
/// measures, is the same after (`after`) as before (`before`): a change of
/// path holds the cost from before it.
pub(super) fn frozen(out: &[Out], before: f64, after: f64) -> Result<(), String> {
    let switched = out.iter().any(|o| matches!(o, Output::Switched { .. }));
    if switched && before.to_bits() != after.to_bits() {
        return Err(format!(
            "the link's cost went from {before} to {after} across a change of path"
        ));
    }
    Ok(())
}

/// While the bundle holds an acked path, it has an active path.
fn held<E: EntropySource>(b: &Bundle<TestClock, E, Slot>) -> Result<(), String> {
    active_held(b.paths().active().is_some(), acked(b).len())
}

/// With `acked` acked paths held, a path is `active`, unless none is.
pub(super) fn active_held(active: bool, acked: usize) -> Result<(), String> {
    if acked > 0 && !active {
        return Err(format!("no active path, with {acked} acked paths held"));
    }
    Ok(())
}

/// The bundle reports itself orphaned at most once: `seen` counts the
/// reports before this call's outputs, `out`.
pub(super) fn orphans(out: &[Out], seen: &mut usize) -> Result<(), String> {
    *seen += out.iter().filter(|o| matches!(o, Output::Orphaned)).count();
    if *seen > 1 {
        return Err(format!("orphaned {seen} times"));
    }
    Ok(())
}

/// A poll made before the bundle's next wake (`early`) does nothing: no
/// output, and the bundle the same after it (`same`).
pub(super) fn idle(early: bool, out: &[Out], same: bool) -> Result<(), String> {
    if early && !out.is_empty() {
        return Err(String::from("a poll before the next wake gave outputs"));
    }
    if early && !same {
        return Err(String::from(
            "a poll before the next wake changed the bundle",
        ));
    }
    Ok(())
}

/// After `charge` at `now` returns `Tripped`, the next wake is at or
/// before `now`, so the poll the shell then makes at once is not early.
pub(super) fn tripped(
    charge: Charge,
    wake: Option<TestInstant>,
    now: TestInstant,
) -> Result<(), String> {
    if charge == Charge::Tripped && wake.is_none_or(|w| w > now) {
        return Err(format!("a trip at {now:?} left the next wake at {wake:?}"));
    }
    Ok(())
}

/// After a step at `now`, the next wake is `None` or later than `now`.
pub(super) fn ahead(wake: Option<TestInstant>, now: TestInstant) -> Result<(), String> {
    match wake {
        Some(w) if w <= now => Err(format!("the next wake {w:?} is not after {now:?}")),
        Some(_) | None => Ok(()),
    }
}

/// Every path held before the close comes back exactly once.
pub(super) fn released_once(held: &[PathRef], out: &[Out]) -> Result<(), String> {
    let released: Vec<&PathRef> = out
        .iter()
        .filter_map(|o| {
            let Output::Released { to, .. } = o else {
                return None;
            };
            Some(to)
        })
        .collect();
    for p in held {
        let n = released.iter().filter(|r| **r == p).count();
        if n != 1 {
            return Err(format!("{p:?} was released {n} times"));
        }
    }
    if released.len() != held.len() {
        return Err(format!(
            "{} released for {} held",
            released.len(),
            held.len()
        ));
    }
    Ok(())
}

/// Probe the candidate (`transport`, `a`) and answer the probe from the
/// peer's path `peer`: the path is Live and acked. Returns its index. The
/// probes the candidate starts on the other paths are left unanswered.
pub(super) fn live_path<E: EntropySource>(
    n: &mut Node<E>,
    transport: TransportId,
    a: TransportAddr,
    peer: u32,
) -> usize {
    let out = n.candidate(transport, a.clone());
    let probe = probe_on(&out, &pair(transport, a.clone()));
    n.ack(transport, a.clone(), ack_for(&probe, peer));
    let i = n.b.paths().find(transport, &a).expect("the path is held");
    assert_eq!(n.b.paths().get(i).unwrap().state(), PathState::Live);
    i
}

/// The pair our frames go out on.
pub(super) fn active(n: &Node) -> Option<PathRef> {
    n.b.paths()
        .active()
        .map(|p| pair(p.transport_id(), p.addr().clone()))
}

/// The peer closes our path on `to`, at `ms`.
pub(super) fn shut(n: &mut Node, ms: u64, to: &PathRef) -> Vec<Out> {
    n.now = TestInstant(ms);
    let id = path(n, to).path_id();
    n.closed(to.transport, to.addr.clone(), close_from(id))
}

/// Step `input` at `ms`.
pub(super) fn step(n: &mut Node, ms: u64, input: Input) -> Vec<Out> {
    n.now = TestInstant(ms);
    n.step(input)
}

/// Carrier lost on `transport`.
pub(super) fn down(transport: u32) -> Input {
    Input::Carrier {
        transport: t(transport),
        up: false,
    }
}

/// Transport `transport` removed.
pub(super) fn gone(transport: u32) -> Input {
    Input::Removed {
        transport: t(transport),
    }
}

/// The original path.
pub(super) fn p() -> PathRef {
    pair(t(1), addr(1))
}

/// The second path, on transport 2.
pub(super) fn q() -> PathRef {
    pair(t(2), addr(2))
}

/// The third path, on transport 3.
pub(super) fn r() -> PathRef {
    pair(t(3), addr(3))
}

/// The peer's identifier for our path on `to`: 0xA on transport 1, 0xB on
/// transport 2, and so on.
pub(super) fn peer(to: &PathRef) -> u32 {
    (1..=8u32)
        .find(|&k| to.transport == t(k))
        .map_or(0xF, |k| 0x9 + k)
}

/// One state change, with the instant in milliseconds.
pub(super) type Timed = (u64, Option<PathState>, Option<PathState>, Why);

/// What a run sent and logged, each with its instant in milliseconds.
#[derive(Default)]
pub(super) struct Log {
    /// Every probe sent, with its pair.
    pub(super) probes: Vec<(u64, PathRef, PathProbe)>,
    /// Every state change.
    pub(super) states: Vec<(u64, Change)>,
    /// Every connection asked for, with its pair.
    pub(super) connects: Vec<(u64, PathRef)>,
}

impl Log {
    /// Log the outputs `out` of a step at `at`.
    pub(super) fn add(&mut self, at: TestInstant, out: &[Out]) {
        for (to, probe) in probes(out) {
            self.probes.push((at.0, to, probe));
        }
        for change in states(out) {
            self.states.push((at.0, change));
        }
        for to in asked(out) {
            self.connects.push((at.0, to));
        }
    }

    /// The instants of the probes on `to`.
    pub(super) fn on(&self, to: &PathRef) -> Vec<u64> {
        self.probes
            .iter()
            .filter(|(_, p, _)| p == to)
            .map(|(at, _, _)| *at)
            .collect()
    }

    /// The state changes of the path on `to`.
    pub(super) fn changes(&self, to: &PathRef) -> Vec<Timed> {
        self.states
            .iter()
            .filter(|(_, c)| &c.0 == to)
            .map(|(at, c)| (*at, c.2, c.3, c.4))
            .collect()
    }
}

/// Log `out`, then answer at once each probe in it that `answers` accepts,
/// given the instant in milliseconds and the probe's pair, and do the same
/// with the outputs of each answer.
pub(super) fn handle(
    n: &mut Node,
    log: &mut Log,
    out: Vec<Out>,
    answers: &mut dyn FnMut(u64, &PathRef) -> bool,
) {
    let mut queue = VecDeque::from([out]);
    while let Some(out) = queue.pop_front() {
        log.add(n.now, &out);
        for (to, probe) in probes(&out) {
            if answers(n.now.0, &to) {
                let reply = n.ack(to.transport, to.addr.clone(), ack_for(&probe, peer(&to)));
                queue.push_back(reply);
            }
        }
    }
}

/// Poll at every wake up to `until` milliseconds, handling each poll's
/// outputs as [`handle`] does.
pub(super) fn run(
    n: &mut Node,
    log: &mut Log,
    until: u64,
    answers: &mut dyn FnMut(u64, &PathRef) -> bool,
) {
    while let Some(out) = n.tick(TestInstant(until)) {
        handle(n, log, out, answers);
    }
}

/// Every probe answered.
pub(super) fn all(_: u64, _: &PathRef) -> bool {
    true
}

/// The score of the path on `to`, reckoned from its public accessors: the
/// quality index of its ETX and its least round trip in milliseconds, or
/// `None` before it has `min` round-trip samples.
pub(super) fn scored(n: &Node, to: &PathRef, min: usize) -> Option<f64> {
    let live = path(n, to).live();
    let rtt = live.min_rtt().filter(|_| live.samples() >= min)?;
    Some(quality_index(live.etx(), rtt.as_secs_f64() * 1000.0))
}

/// One change of active path: the instant in milliseconds, the path left
/// (`None` when it was discarded), the path taken, and why.
pub(super) type Turn = (u64, Option<PathRef>, PathRef, Switch);

/// The changes of active path in `out`, at `at` milliseconds.
pub(super) fn turns(at: u64, out: &[Out]) -> Vec<Turn> {
    out.iter()
        .filter_map(|o| {
            let Output::Switched { from, to, why } = o else {
                return None;
            };
            Some((at, from.clone(), to.clone(), *why))
        })
        .collect()
}

/// A network that answers our probes after a round trip: the peer's ack
/// to a probe sent at `now` on `to` arrives `rtt(now, to)` milliseconds
/// later, or never for `None`. Each path's samples are then the round
/// trips the test states, from its first probe on.
pub(super) struct Net<'r> {
    /// The round trip of a probe, by the instant it goes and its pair.
    rtt: &'r dyn Fn(u64, &PathRef) -> Option<u64>,
    /// The answers on their way: when each arrives, on which pair, and
    /// the ack, in the order the probes went.
    queue: Vec<(u64, PathRef, PathAck)>,
}

impl<'r> Net<'r> {
    /// A network with nothing on its way, answering by `rtt`.
    pub(super) fn new(rtt: &'r dyn Fn(u64, &PathRef) -> Option<u64>) -> Self {
        Self {
            rtt,
            queue: Vec::new(),
        }
    }

    /// Queue the peer's answer to each probe in `out`, the outputs of a
    /// step at `now` milliseconds.
    pub(super) fn take(&mut self, now: u64, out: &[Out]) {
        for (to, probe) in probes(out) {
            if let Some(rtt) = (self.rtt)(now, &to) {
                let ack = ack_for(&probe, peer(&to));
                self.queue.push((now + rtt, to, ack));
            }
        }
    }

    /// Step `n` at each instant before `until` milliseconds at which an
    /// answer arrives or the bundle wakes, in order, an answer before a
    /// poll at the same instant, queueing the answers to each step's
    /// probes and calling `watch` after each step. An instant already
    /// past is stepped at the node's own. Returns every change of active
    /// path, and leaves the node at `until` with nothing stepped there.
    pub(super) fn run(
        &mut self,
        n: &mut Node,
        until: u64,
        watch: &mut dyn FnMut(&Node, u64),
    ) -> Vec<Turn> {
        let mut seen = Vec::new();
        loop {
            let next = self
                .queue
                .iter()
                .enumerate()
                .min_by_key(|(i, (at, _, _))| (*at, *i))
                .map(|(i, (at, _, _))| (i, *at));
            let wake = n.b.next_wake().map(|w| w.0);
            let answer = next.filter(|&(_, at)| wake.is_none_or(|w| at <= w));
            let Some(at) = answer.map(|(_, at)| at).or(wake).filter(|&at| at < until) else {
                break;
            };
            n.now = TestInstant(at.max(n.now.0));
            let out = match answer {
                Some((i, _)) => {
                    let (_, to, ack) = self.queue.remove(i);
                    n.ack(to.transport, to.addr, ack)
                }
                None => n.poll(),
            };
            let now = n.now.0;
            seen.extend(turns(now, &out));
            self.take(now, &out);
            watch(n, now);
        }
        n.now = TestInstant(until.max(n.now.0));
        seen
    }
}

/// A capable node at instant 0 whose second path, on transport 2, is Live,
/// with every probe so far answered: the original path is our active path,
/// probed every 200 ms, and the second a standby.
pub(super) fn two(seed: u64) -> Node {
    let mut n = Node::capable(seed);
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut Log::default(), out, &mut all);
    assert_eq!(state(&n, &q()), PathState::Live);
    n
}

/// The state of the path on `to`.
pub(super) fn state(n: &Node, to: &PathRef) -> PathState {
    path(n, to).state()
}

/// The path on `to`.
pub(super) fn path<'n>(n: &'n Node, to: &PathRef) -> &'n PeerPath<TestInstant, Slot> {
    let i =
        n.b.paths()
            .find(to.transport, &to.addr)
            .expect("the path is held");
    n.b.paths().get(i).unwrap()
}

/// Step `input` at `ms` and log it.
pub(super) fn at(n: &mut Node, log: &mut Log, ms: u64, input: Input) -> Vec<Out> {
    n.now = TestInstant(ms);
    let out = n.step(input);
    log.add(n.now, &out);
    out
}

/// `PATH_DEAD_PROBE_INTERVAL_MIN` and `PATH_DEAD_PROBE_INTERVAL_MAX`, in
/// milliseconds (multipath v1 draft, Appendix A), for the floor checks.
pub(super) const FLOOR_MIN: u64 = 1_000;
pub(super) const FLOOR_MAX: u64 = 30_000;

/// The first probe of `cadence` that breaks the floor of draft Section 5.6
/// for a path that stopped answering at `stop` (ms): the first no sooner
/// than 1 s after the stop, the second no sooner than 1 s after the first,
/// and each later gap at least twice the one before, up to 30 s.
pub(super) fn floor_breaks(stop: u64, cadence: &[u64]) -> Option<String> {
    let mut free = stop + FLOOR_MIN;
    let mut gap = FLOOR_MIN;
    for (k, &at) in cadence.iter().enumerate() {
        if at < free {
            return Some(format!(
                "probe {} at {at} ms is before {free} ms (stopped at {stop} ms): {cadence:?}",
                k + 1
            ));
        }
        free = at + gap;
        gap = (gap * 2).min(FLOOR_MAX);
    }
    None
}

/// The instant (ms) from which the floor of draft Section 5.6 lets the next
/// probe go on a path that stopped answering at `stop`, after the probes on
/// its own cadence `cadence`.
pub(super) fn free_after(stop: u64, cadence: &[u64]) -> u64 {
    let mut free = stop + FLOOR_MIN;
    let mut gap = FLOOR_MIN;
    for &at in cadence {
        free = at + gap;
        gap = (gap * 2).min(FLOOR_MAX);
    }
    free
}

/// A probe from the peer on its path `path_id`, `len` bytes long.
pub(super) fn probe_from(path_id: u32, probe_id: u32, len: usize) -> PathProbe {
    PathProbe::new(probe_id, path_id, PathFlags::default(), PathCaps::default()).with_len(len)
}

/// A probe from the peer on its path `path_id`, of the smallest size, with
/// `ACTIVE` set or clear.
pub(super) fn marked(path_id: u32, probe_id: u32, active: bool) -> PathProbe {
    PathProbe::new(
        probe_id,
        path_id,
        PathFlags::with_active(active),
        PathCaps::default(),
    )
    .with_len(27)
}

/// The peer's answer to our `probe`, from its path `path_id`, as long as
/// the probe.
pub(super) fn ack_for(probe: &PathProbe, path_id: u32) -> PathAck {
    PathAck {
        probe_id: probe.probe_id,
        flags: PathFlags::default(),
        path_id,
        echo_path_id: probe.path_id,
        caps: PathCaps::default(),
        rx_time_us: 0,
        rx_frames: 0,
        rx_bytes: 0,
        len: probe.len,
    }
}

/// A close from the peer naming our path `path_id`.
pub(super) fn close_from(path_id: u32) -> PathClose {
    PathClose {
        path_id,
        reason: PathCloseReason::Unspecified,
    }
}

/// The probes sent in `out`, decoded, with their pairs.
pub(super) fn probes(out: &[Out]) -> Vec<(PathRef, PathProbe)> {
    raw(out, LinkMessageType::PathProbe)
        .into_iter()
        .map(|(to, b)| {
            (
                to.clone(),
                PathProbe::decode(&b[1..]).expect("a probe decodes"),
            )
        })
        .collect()
}

/// The one probe sent in `out` on `to`, decoded; the test fails unless
/// there is exactly one.
pub(super) fn probe_on(out: &[Out], to: &PathRef) -> PathProbe {
    let on: Vec<PathProbe> = probes(out)
        .into_iter()
        .filter(|(p, _)| p == to)
        .map(|(_, probe)| probe)
        .collect();
    let [probe] = on[..] else {
        panic!("one probe on {to:?}: {out:?}");
    };
    probe
}

/// The pairs of the connections asked for in `out`.
pub(super) fn asked(out: &[Out]) -> Vec<PathRef> {
    out.iter()
        .filter_map(|o| {
            let Output::Connect { to } = o else {
                return None;
            };
            Some(to.clone())
        })
        .collect()
}

/// The acks sent in `out`, decoded, with their pairs.
pub(super) fn sent_acks(out: &[Out]) -> Vec<(PathRef, PathAck)> {
    raw(out, LinkMessageType::PathAck)
        .into_iter()
        .map(|(to, b)| {
            (
                to.clone(),
                PathAck::decode(&b[1..]).expect("an ack decodes"),
            )
        })
        .collect()
}

/// The closes sent in `out`, decoded, with their pairs.
pub(super) fn sent_closes(out: &[Out]) -> Vec<(PathRef, PathClose)> {
    raw(out, LinkMessageType::PathClose)
        .into_iter()
        .map(|(to, b)| {
            (
                to.clone(),
                PathClose::decode(&b[1..]).expect("a close decodes"),
            )
        })
        .collect()
}

/// The state changes logged in `out`: pair, our id, from, next and why.
pub(super) type Change = (PathRef, u32, Option<PathState>, Option<PathState>, Why);

/// The state changes in `out`.
pub(super) fn states(out: &[Out]) -> Vec<Change> {
    out.iter()
        .filter_map(|o| {
            let Output::State {
                to,
                path_id,
                from,
                next,
                why,
            } = o
            else {
                return None;
            };
            Some((to.clone(), *path_id, *from, *next, *why))
        })
        .collect()
}

/// The refusals in `out`.
pub(super) fn refusals(out: &[Out]) -> Vec<(PathRef, Refusal)> {
    out.iter()
        .filter_map(|o| {
            let Output::Refused { to, why } = o else {
                return None;
            };
            Some((to.clone(), *why))
        })
        .collect()
}

/// The moves in `out`: from, to and the old slot's serial.
pub(super) fn moved(out: &[Out]) -> Vec<(PathRef, PathRef, u64)> {
    out.iter()
        .filter_map(|o| {
            let Output::Moved { from, to, driver } = o else {
                return None;
            };
            Some((from.clone(), to.clone(), *driver))
        })
        .collect()
}

/// The releases in `out`: the pair and its slot's serial.
pub(super) fn released(out: &[Out]) -> Vec<(PathRef, u64)> {
    out.iter()
        .filter_map(|o| {
            let Output::Released { to, driver, .. } = o else {
                return None;
            };
            Some((to.clone(), *driver))
        })
        .collect()
}

/// The releases in `out`: the pair and whether its slot is to be kept.
pub(super) fn keeps(out: &[Out]) -> Vec<(PathRef, bool)> {
    out.iter()
        .filter_map(|o| {
            let Output::Released { to, keep, .. } = o else {
                return None;
            };
            Some((to.clone(), *keep))
        })
        .collect()
}

/// A send of `bytes` on `to`.
fn send(to: &PathRef, bytes: Vec<u8>) -> Out {
    Output::Send {
        to: to.clone(),
        bytes,
    }
}

#[test]
fn each_shell_check_fails_on_an_output_that_breaks_it() {
    let facts = Stub::default().mtu(t(2), 1000);
    let p1 = pair(t(1), addr(1));
    let p2 = pair(t(2), addr(2));
    let probe = probe_from(7, 1, 1200);
    let input = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: probe,
    };
    let fits = ack_for(&probe, 9);
    let ack = |len: usize| send(&p2, PathAck { len, ..fits }.encode());

    // Before the peer is capable: anything but a capability probe, a
    // connection, a capability probe on another pair or path, of another
    // size, flags or capability bits, one with no candidate allowing it,
    // or one too soon after the last; and the link reported not capable
    // twice, or after it was reported capable.
    let out = [send(&p1, probe_from(5, 1, 27).encode())];
    let cfg = Config::draft();
    let first = (5, p1.clone());
    let calm = |now: u64, capable: bool, eligible: bool| Calm {
        now: TestInstant(now),
        capable,
        first: Some(&first),
        eligible,
        cfg: &cfg,
    };
    let fresh = |out: &[Out], c: Calm<'_>| quiet(out, &c, &mut Asked::default());
    let active = PathFlags::with_active(true);
    let none = PathCaps::default();
    let asking = |to: &PathRef, path_id: u32, flags: PathFlags, caps: PathCaps, len: usize| {
        send(
            to,
            PathProbe::new(9, path_id, flags, caps)
                .with_len(len)
                .encode(),
        )
    };
    let ask = || asking(&p1, 5, active, none, 27);
    assert!(fresh(&[ask()], calm(0, false, true)).is_ok());
    assert!(fresh(&[ask()], calm(0, false, false)).is_err());
    assert!(fresh(&[ask()], calm(0, true, false)).is_ok());
    assert!(fresh(&[asking(&p2, 5, active, none, 27)], calm(0, false, true)).is_err());
    assert!(fresh(&[asking(&p1, 6, active, none, 27)], calm(0, false, true)).is_err());
    assert!(fresh(&[asking(&p1, 5, active, none, 28)], calm(0, false, true)).is_err());
    let clear = PathFlags::default();
    assert!(fresh(&[asking(&p1, 5, clear, none, 27)], calm(0, false, true)).is_err());
    let offer = PathCaps::with_aggregate(true);
    assert!(fresh(&[asking(&p1, 5, active, offer, 27)], calm(0, false, true)).is_err());
    let shut = |to: &PathRef, path_id: u32| {
        let close = PathClose {
            path_id,
            reason: PathCloseReason::InterfaceGone,
        };
        send(to, close.encode().to_vec())
    };
    assert!(fresh(&[shut(&p2, 0xB)], calm(0, false, true)).is_err());
    assert!(fresh(&[shut(&p2, 0xB)], calm(0, true, true)).is_ok());
    let answer = send(&p1, ack_for(&probe_from(7, 1, 27), 9).encode());
    assert!(fresh(&[answer], calm(0, false, true)).is_err());
    let connect = |to: &PathRef| Output::Connect { to: to.clone() };
    assert!(fresh(&[connect(&p2)], calm(0, false, true)).is_err());
    assert!(fresh(&[connect(&p2)], calm(0, true, true)).is_ok());
    // Spacing: three over 30 s, then 30 s, doubling.
    assert!(fresh(&[ask(), ask()], calm(0, false, true)).is_err());
    let mut asked = Asked::default();
    for (ms, ok) in [
        (0, true),
        (9_999, false),
        (10_000, true),
        (20_000, true),
        (49_999, false),
        (50_000, true),
        (109_999, false),
        (110_000, true),
    ] {
        let r = quiet(&[ask()], &calm(ms, false, true), &mut asked);
        assert_eq!(r.is_ok(), ok, "{ms}: {r:?}");
    }
    assert_eq!(spacing(8, &cfg), cfg.cap);
    let mut asked = Asked::default();
    let told = || [Output::NotCapable];
    assert!(quiet(&told(), &calm(0, false, true), &mut asked).is_ok());
    assert!(quiet(&told(), &calm(0, false, true), &mut asked).is_err());
    let mut asked = Asked::default();
    let late = [Output::Capable, Output::NotCapable];
    assert!(quiet(&late, &calm(0, true, true), &mut asked).is_err());
    let mut asked = Asked::default();
    let early = [Output::NotCapable, Output::Capable];
    assert!(quiet(&early, &calm(0, true, true), &mut asked).is_ok());

    // A send or a connection with multipath disabled.
    assert!(silent(&out, false).is_err());
    assert!(silent(&[connect(&p2)], false).is_err());
    assert!(silent(&out, true).is_ok());
    assert!(silent(&[connect(&p2)], true).is_ok());
    assert!(silent(&[Output::Capable], false).is_ok());

    // A connection to a path not held, on a connectionless transport, or
    // with a probe beside it on the same path.
    let oriented = Stub::default().oriented(t(2));
    let both = [p1.clone(), p2.clone()];
    assert!(connects(&[connect(&p2)], &oriented, &both).is_ok());
    assert!(connects(&[connect(&p2)], &oriented, core::slice::from_ref(&p1)).is_err());
    assert!(connects(&[connect(&p1)], &oriented, &both).is_err());
    let beside = [connect(&p2), send(&p2, probe_from(5, 1, 27).encode())];
    assert!(connects(&beside, &oriented, &both).is_err());
    let apart = [connect(&p2), send(&p1, probe_from(5, 1, 27).encode())];
    assert!(connects(&apart, &oriented, &both).is_ok());

    // A close on the path it names, or naming no path held.
    let named = [(0xB, p2.clone())];
    assert!(closes(&[shut(&p1, 0xB)], &named).is_ok());
    assert!(closes(&[shut(&p2, 0xB)], &named).is_err());
    assert!(closes(&[shut(&p1, 0xC)], &named).is_err());

    // Acks: the right one passes; no probe to answer, another pair, the
    // wrong length either way, and EXT each fail.
    assert!(acks(Some(&input), &[ack(1000 - FRAME_OVERHEAD)], &facts).is_ok());
    let candidate = Input::Candidate {
        transport: t(2),
        addr: addr(2),
        source: Source::Config,
    };
    assert!(acks(Some(&candidate), &[ack(1000 - FRAME_OVERHEAD)], &facts).is_err());
    assert!(acks(None, &[ack(1000 - FRAME_OVERHEAD)], &facts).is_err());
    let elsewhere = [send(&p1, PathAck { len: 964, ..fits }.encode())];
    assert!(acks(Some(&input), &elsewhere, &facts).is_err());
    assert!(acks(Some(&input), &[ack(1200)], &facts).is_err());
    assert!(acks(Some(&input), &[ack(27)], &facts).is_err());
    let mut ext = PathAck {
        len: 1000 - FRAME_OVERHEAD,
        ..fits
    }
    .encode();
    ext[5] |= PathFlags::EXT;
    assert!(acks(Some(&input), &[send(&p2, ext)], &facts).is_err());

    // Probes: over the MTU, under 27 bytes, or with EXT.
    let at = |len: usize| send(&p2, probe_from(5, 1, len).encode());
    assert!(sizes(&[at(1000 - FRAME_OVERHEAD)], &facts).is_ok());
    assert!(sizes(&[at(1001 - FRAME_OVERHEAD)], &facts).is_err());
    let mut short = probe_from(5, 1, 27).encode();
    short.truncate(26);
    assert!(sizes(&[send(&p2, short)], &facts).is_err());
    let mut ext = probe_from(5, 1, 27).encode();
    ext[5] |= PathFlags::EXT;
    assert!(sizes(&[send(&p2, ext)], &facts).is_err());

    // A move on anything but a probe or an ack.
    let move_out = [Output::Moved {
        from: p1.clone(),
        to: p2.clone(),
        driver: 1,
    }];
    assert!(moves(Some(&input), &move_out).is_ok());
    assert!(moves(Some(&candidate), &move_out).is_err());
    assert!(moves(None, &move_out).is_err());

    // A slot handed out twice, or one dropped inside the call.
    let release = |to: &PathRef, driver: u64| Output::Released {
        to: to.clone(),
        driver,
        keep: false,
    };
    let mut handed = Vec::new();
    assert!(slots(&[release(&p2, 1)], &mut handed, 0, 0).is_ok());
    assert!(slots(&[release(&p2, 1)], &mut handed, 0, 0).is_err());
    assert!(slots(&[], &mut handed, 0, 1).is_err());

    // The active path released other than at the close or as its
    // transport goes, before or after a switch.
    assert!(active_kept(&[release(&p1, 2)], Some(&p1), false).is_err());
    assert!(active_kept(&[release(&p1, 2)], Some(&p1), true).is_ok());
    assert!(active_kept(&[release(&p2, 2)], Some(&p1), false).is_ok());
    let switch = || Output::Switched {
        from: Some(p1.clone()),
        to: p2.clone(),
        why: Switch::Mandatory,
    };
    let away = [switch(), release(&p1, 2)];
    assert!(active_kept(&away, Some(&p1), false).is_ok());
    let onto = [switch(), release(&p2, 2)];
    assert!(active_kept(&onto, Some(&p1), false).is_err());

    // A discretionary or pinned change from a path other than the one
    // active before it, followed through the call's switches and by
    // identifier across a move; from or to a path not Live after the call;
    // or to the path it leaves. A mandatory change is not held to it.
    let entry = |id: u32, to: &PathRef, state: PathState| (id, to.clone(), state);
    let both = [
        entry(1, &p1, PathState::Live),
        entry(2, &p2, PathState::Live),
    ];
    let turn = |from: &PathRef, to: &PathRef, why: Switch| Output::Switched {
        from: Some(from.clone()),
        to: to.clone(),
        why,
    };
    let leave = |from: &PathRef, to: &PathRef| turn(from, to, Switch::Discretionary);
    assert!(chosen(&[leave(&p1, &p2)], Some(1), &both).is_ok());
    assert!(chosen(&[leave(&p1, &p2)], Some(2), &both).is_err());
    assert!(chosen(&[leave(&p1, &p2)], None, &both).is_err());
    let gone = Output::Switched {
        from: None,
        to: p2.clone(),
        why: Switch::Discretionary,
    };
    assert!(chosen(&[gone], Some(1), &both).is_err());
    let left = [
        entry(1, &p1, PathState::Suspect),
        entry(2, &p2, PathState::Live),
    ];
    assert!(chosen(&[leave(&p1, &p2)], Some(1), &left).is_err());
    assert!(chosen(&[turn(&p1, &p2, Switch::Mandatory)], Some(1), &left).is_ok());
    let probing = [
        entry(1, &p1, PathState::Live),
        entry(2, &p2, PathState::Probing),
    ];
    assert!(chosen(&[leave(&p1, &p2)], Some(1), &probing).is_err());
    assert!(chosen(&[leave(&p1, &p1)], Some(1), &both).is_err());
    let moved = pair(t(1), addr(9));
    let across = [
        entry(1, &moved, PathState::Live),
        entry(2, &p2, PathState::Live),
    ];
    assert!(chosen(&[leave(&moved, &p2)], Some(1), &across).is_ok());
    let back = [turn(&p1, &p2, Switch::Mandatory), leave(&p2, &p1)];
    assert!(chosen(&back, Some(1), &both).is_ok());
    let stale = [turn(&p1, &p2, Switch::Mandatory), leave(&p1, &p2)];
    assert!(chosen(&stale, Some(1), &both).is_err());
    // A pinned change is held to the same.
    let pin = |from: &PathRef, to: &PathRef| turn(from, to, Switch::Pinned);
    assert!(chosen(&[pin(&p1, &p2)], Some(1), &both).is_ok());
    assert!(chosen(&[pin(&p1, &p2)], Some(2), &both).is_err());
    assert!(chosen(&[pin(&p1, &p2)], Some(1), &left).is_err());
    assert!(chosen(&[pin(&p1, &p2)], Some(1), &probing).is_err());
    assert!(chosen(&[pin(&p1, &p1)], Some(1), &both).is_err());

    // An active path whose transport's role ranks below that of a Live,
    // acked path, backup below normal and never below backup, and that the
    // pin does not name.
    let live = [p1.clone(), p2.clone()];
    let roles = |one: Role, two: Role| {
        Stub::default()
            .fact(t(1), Fact::Role(one))
            .fact(t(2), Fact::Role(two))
    };
    let level = roles(Role::Normal, Role::Preferred);
    assert!(tiered(Some(&p1), &live, &level, None).is_ok());
    assert!(tiered(Some(&p2), &live, &level, None).is_ok());
    let backup = roles(Role::Backup, Role::Normal);
    assert!(tiered(Some(&p1), &live, &backup, None).is_err());
    assert!(tiered(Some(&p2), &live, &backup, None).is_ok());
    assert!(tiered(Some(&p1), core::slice::from_ref(&p1), &backup, None).is_ok());
    assert!(tiered(None, &live, &backup, None).is_ok());
    let never = roles(Role::Never, Role::Backup);
    assert!(tiered(Some(&p1), &live, &never, None).is_err());
    assert!(tiered(Some(&p2), &live, &never, None).is_ok());
    // A pin of the active path, by its pair or its transport, exempts it;
    // a pin of another path, or of another address on its transport, does
    // not.
    let on = |to: &PathRef, addr: Option<TransportAddr>| Pin {
        transport: to.transport,
        addr,
    };
    let pin_p1 = on(&p1, Some(p1.addr.clone()));
    assert!(tiered(Some(&p1), &live, &backup, Some(&pin_p1)).is_ok());
    assert!(tiered(Some(&p1), &live, &backup, Some(&on(&p1, None))).is_ok());
    assert!(tiered(Some(&p1), &live, &backup, Some(&on(&p2, None))).is_err());
    assert!(tiered(Some(&p1), &live, &backup, Some(&on(&p1, Some(addr(9))))).is_err());

    // A pinned change to a path the pin does not name, or with no pin.
    let pinned_to = |to: &PathRef| turn(&p1, to, Switch::Pinned);
    assert!(pinned(&[pinned_to(&p2)], Some(&on(&p2, None))).is_ok());
    assert!(pinned(&[pinned_to(&p2)], Some(&on(&p2, Some(p2.addr.clone())))).is_ok());
    assert!(pinned(&[pinned_to(&p2)], Some(&on(&p2, Some(addr(9))))).is_err());
    assert!(pinned(&[pinned_to(&p2)], Some(&pin_p1)).is_err());
    assert!(pinned(&[pinned_to(&p2)], None).is_err());
    assert!(pinned(&[turn(&p1, &p2, Switch::Mandatory)], None).is_ok());

    // The link's cost changed across a call that changes path; a call
    // that changes none may change it.
    assert!(frozen(&[switch()], 1.5, 1.5).is_ok());
    assert!(frozen(&[switch()], 1.5, 3.0).is_err());
    assert!(frozen(&[turn(&p1, &p2, Switch::Pinned)], 3.0, 1.5).is_err());
    assert!(frozen(&[], 1.5, 3.0).is_ok());

    // A switch to a path not acked.
    assert!(switches(&[switch()], core::slice::from_ref(&p2)).is_ok());
    assert!(switches(&[switch()], core::slice::from_ref(&p1)).is_err());

    // No active path while an acked path is held.
    assert!(active_held(true, 2).is_ok());
    assert!(active_held(false, 0).is_ok());
    assert!(active_held(false, 1).is_err());

    // A second report of the bundle orphaned, in one call or two.
    let mut seen = 0;
    assert!(orphans(&[Output::Orphaned], &mut seen).is_ok());
    assert!(orphans(&[], &mut seen).is_ok());
    assert!(orphans(&[Output::Orphaned], &mut seen).is_err());
    let mut seen = 0;
    assert!(orphans(&[Output::Orphaned, Output::Orphaned], &mut seen).is_err());

    // A poll before the wake that gave outputs or changed the bundle.
    assert!(idle(true, &[], true).is_ok());
    assert!(idle(true, &move_out, true).is_err());
    assert!(idle(true, &[], false).is_err());
    assert!(idle(false, &move_out, false).is_ok());

    // A next wake not after the step's instant.
    let ms = TestInstant;
    assert!(ahead(None, ms(5)).is_ok());
    assert!(ahead(Some(ms(6)), ms(5)).is_ok());
    assert!(ahead(Some(ms(5)), ms(5)).is_err());
    assert!(ahead(Some(ms(4)), ms(5)).is_err());

    // A trip that leaves the next wake later than the failure, or none.
    assert!(tripped(Charge::Tripped, Some(ms(5)), ms(5)).is_ok());
    assert!(tripped(Charge::Tripped, Some(ms(4)), ms(5)).is_ok());
    assert!(tripped(Charge::Tripped, Some(ms(6)), ms(5)).is_err());
    assert!(tripped(Charge::Tripped, None, ms(5)).is_err());
    assert!(tripped(Charge::Warn, None, ms(5)).is_ok());

    // A close that misses a path or releases one twice.
    let held = [p1.clone(), p2.clone()];
    assert!(released_once(&held, &[release(&p1, 3), release(&p2, 4)]).is_ok());
    assert!(released_once(&held, &[release(&p1, 3)]).is_err());
    assert!(released_once(&held, &[release(&p1, 3), release(&p1, 4)]).is_err());

    // Path policy: transport 2 takes the kind of the peer's address, 3 is
    // Tor, 4 refuses the peer's handshake and 5 does not dial, on a clear
    // Local link whose original path is p1.
    let ruling = Stub::default()
        .fact(t(2), Fact::Kind(None))
        .fact(t(3), Fact::Class(Class::Tor))
        .fact(t(4), Fact::Accepts(false))
        .fact(t(5), Fact::Dials(false));
    let terms = Terms {
        facts: &ruling,
        link: Scope {
            class: Class::Clear,
            kind: Kind::Local,
        },
        mix: false,
    };
    let (p3, p4, p5) = (
        pair(t(3), addr(3)),
        pair(t(4), addr(4)),
        pair(t(5), addr(5)),
    );
    let first = (0x77, p1.clone());
    let first = Some(&first);
    let change = |to: &PathRef, path_id: u32, from: Option<PathState>, why: Why| Output::State {
        to: to.clone(),
        path_id,
        from,
        next: Some(PathState::Probing),
        why,
    };
    let fine = |o: Out| ruled(&[o], &terms, first, &[]).is_ok();
    // A candidate admitted where it may not be probed.
    assert!(fine(change(&p2, 1, None, Why::Candidate)));
    assert!(!fine(change(&p3, 1, None, Why::Candidate)));
    assert!(!fine(change(&p5, 1, None, Why::Candidate)));
    assert!(fine(change(&p4, 1, None, Why::Candidate)));
    // A path created by a probe where it may not be created.
    assert!(fine(change(&p2, 1, None, Why::Probed)));
    assert!(!fine(change(&p3, 1, None, Why::Probed)));
    assert!(!fine(change(&p4, 1, None, Why::Probed)));
    assert!(fine(change(&p5, 1, None, Why::Probed)));
    // A Dead path other than the original revived by carrier or by the
    // peer found again where it may not be probed, or by the peer's probe
    // where it may not be created; only the original passes.
    let dead = Some(PathState::Dead);
    assert!(fine(change(&p2, 1, dead, Why::Returned)));
    assert!(!fine(change(&p5, 1, dead, Why::Returned)));
    assert!(!fine(change(&p3, 1, dead, Why::Found)));
    assert!(fine(change(&p5, 0x77, dead, Why::Found)));
    assert!(fine(change(&p5, 1, dead, Why::Probed)));
    assert!(!fine(change(&p4, 1, dead, Why::Probed)));
    assert!(!fine(change(&p3, 1, dead, Why::Probed)));
    assert!(fine(change(&p4, 0x77, dead, Why::Probed)));
    // A path other than the original moved to a pair it may not run on.
    let shift = |from: &PathRef, to: &PathRef| Output::Moved {
        from: from.clone(),
        to: to.clone(),
        driver: 1,
    };
    let far = pair(t(2), public(2));
    assert!(fine(shift(&p2, &pair(t(2), addr(9)))));
    assert!(!fine(shift(&p2, &far)));
    assert!(!fine(shift(&p3, &pair(t(3), addr(9)))));
    assert!(fine(shift(&p1, &far)));
    // A probe to a Dead path other than the original where it may not be
    // probed.
    let probe5 = send(&p5, probe_from(5, 1, 27).encode());
    assert!(ruled(core::slice::from_ref(&probe5), &terms, first, &[]).is_ok());
    assert!(
        ruled(
            core::slice::from_ref(&probe5),
            &terms,
            first,
            core::slice::from_ref(&p5)
        )
        .is_err()
    );
    let probe2 = send(&p2, probe_from(5, 1, 27).encode());
    assert!(ruled(&[probe2], &terms, first, core::slice::from_ref(&p2)).is_ok());
}
