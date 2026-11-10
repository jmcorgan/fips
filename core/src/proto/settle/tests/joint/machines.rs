//! One held peer's rekey machine and path bundle, for a test shell.
//!
//! [`Machines`] builds, carries and closes a peer's `Rekey<Ik>` and
//! `Bundle` through the settlement core's join function (`settle::join`:
//! its start, move and stop), steps them, and returns what
//! they asked for as [`Event`]s, in order. It holds no settlement state:
//! what the core is told of each event is the shell's, which asks the join
//! function (`route.rs`).
//!
//! Two outputs need nothing but the machine and the node's own
//! capabilities, and are carried out here: a prompt is sealed at once, as
//! `Output::Prompt` asks, and a released lease goes back to the node's
//! pool. Every other output is returned as the machine gave it.
//!
//! A node's capabilities are its [`Kit`]: its stub keys, index pool, epoch
//! tags, jitter, scratch buffer, stream of path identifiers and transport
//! facts, which every held peer's machines borrow at each call, as each
//! link borrows the node's.
//!
//! Every call that may write an ephemeral takes the world name it is to be
//! drawn from (`names.rs`): a poll or a trigger the name of the msg1 it
//! would send, a msg1 the name of the handshake it starts.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::proto::link::LinkMessageType;
use crate::proto::path::tests::shell::{Checks, Out, Slot, keep};
use crate::proto::path::wire::{PathAck, PathClose, PathProbe};
use crate::proto::path::{self, Bundle, Input as PathInput, Output as PathOutput, PathRef, Roam};
use crate::proto::rekey::tests::stub::{
    Ik, Kid, Local, Mid, Pool, frame, hint, kid, read_msg1, seal_to,
};
use crate::proto::rekey::{
    self, Arrival, Carry, Close, Completed, IndexLease, Input, Output, Record, Rekey, SetupFacts,
    TagSource, Wire,
};
use crate::proto::settle::input::Input as In;
use crate::proto::settle::join::{self, Caps, Joined, Step, join};
use crate::proto::settle::links::LinkNo;
use crate::testutil::{TestClock, TestInstant};

use super::super::super::model::history::{Addr, Epoch, Hs, Node};
use super::super::world::{Kind, Ms};
use super::Mode;
use super::facts::{Draw, Stream, Transports, at, pair};
use super::names::{addr, answerer, key, local, opener};

/// A peer's rekey machine.
pub type Machine = Rekey<Ik, TestClock>;

/// A peer's path bundle.
pub type Paths = Bundle<TestClock, Draw, Slot>;

/// A node's capabilities, lent to each held peer's machines per call.
#[derive(Debug)]
pub struct Kit {
    /// The node's stub keys and epoch.
    pub local: Local,
    /// Its index pool.
    pub pool: Pool,
    /// Its epoch tags.
    pub tags: TagSource,
    /// Its jitter source, which draws the midpoint of the band.
    pub jitter: Mid,
    /// The machines' scratch buffer.
    pub scratch: Vec<u8>,
    /// Its stream of path identifiers.
    pub draws: Stream,
    /// Its transports' facts.
    pub facts: Transports,
}

impl Kit {
    /// The capabilities of node `me` in its life of epoch `epoch`, on the
    /// world transports `kinds`.
    pub fn new(me: Node, epoch: Epoch, kinds: &BTreeMap<u8, Kind>) -> Self {
        Self {
            local: local(me, epoch),
            pool: Pool::new(100),
            tags: TagSource::new(),
            jitter: Mid::default(),
            scratch: Vec::new(),
            draws: Stream::new(me),
            facts: Transports::new(kinds),
        }
    }

    /// A rekey machine's `Env` over these capabilities, for a link on
    /// transport `transport`. No decrypt worker is modelled.
    fn env(&mut self, transport: u8) -> rekey::Env<'_, Ik> {
        self.lent(transport).0
    }

    /// The capabilities split for one call of the join function: a rekey
    /// machine's `Env` for a link on transport `transport`, the transports'
    /// facts a bundle reads, and the stream its draws are lent from.
    fn lent(&mut self, transport: u8) -> (rekey::Env<'_, Ik>, &Transports, &mut Stream) {
        let Self {
            local,
            pool,
            tags,
            jitter,
            scratch,
            draws,
            facts,
        } = self;
        let env = rekey::Env {
            indices: pool,
            transport,
            tags,
            workers: false,
            jitter,
            local,
            scratch,
        };
        (env, facts, draws)
    }
}

/// One thing a peer's machines asked for or did, in order.
#[derive(Debug)]
pub enum Event {
    /// An output of the rekey machine, other than a prompt or a release.
    Rekey(Output<Ik>),
    /// A prompt the rekey machine asked for, sealed under `tag`.
    Prompt {
        /// The epoch it is sealed under.
        tag: rekey::EpochTag,
        /// The frame.
        wire: Wire,
    },
    /// The rekey machine released the lease on `index`, now back in the
    /// node's pool.
    Freed(u32),
    /// An output of the bundle, each driver slot by its serial: the slots
    /// are dropped once the path shell's checks have read the step, and
    /// nothing in the world reads a driver.
    Path(Out),
    /// The link's one path followed an authentic frame from `from` to
    /// `to`, which the bundle reports in no output (`Bundle::account`).
    Roamed {
        /// The pair it left.
        from: Addr,
        /// The pair it holds now.
        to: Addr,
    },
    /// A bundle holding no path bound the frame's pair `at` as its
    /// original path.
    Bound {
        /// The pair.
        at: Addr,
    },
}

/// A completed handshake a peer's rekey machine is built on.
#[derive(Debug)]
pub struct Setup {
    /// The completion.
    pub done: Completed<Ik>,
    /// This node's index for the session.
    pub lease: IndexLease,
    /// The peer's index for it.
    pub theirs: u32,
}

/// One held peer's rekey machine and bundle.
#[derive(Debug)]
pub struct Machines {
    peer: Node,
    mode: Mode,
    rekey: Machine,
    bundle: Paths,
    /// This node's own address for each of the bundle's paths, by the
    /// peer's pair, since a path names only the peer's.
    locals: Vec<(Addr, Addr)>,
    /// The address this node reaches each candidate from, by the peer's
    /// pair, for the path the bundle admits it as, which may be in a later
    /// step than the report's.
    offered: Vec<(Addr, Addr)>,
    /// What the path shell's checks remember of the bundle across steps.
    checks: Checked,
    /// The rules of the path shell's checks the bundle broke since the
    /// shell last took them.
    failed: Vec<String>,
}

/// The path shell's checks of one bundle. Their memory (the slot serials
/// handed out, the orphanings and capability probes seen) holds nothing a
/// successor of the world reads but their own verdicts, and the serials
/// are counted per thread, so it prints nothing into a key.
struct Checked(Checks);

impl core::fmt::Debug for Checked {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Checked")
    }
}

/// The outputs `out`, each driver slot by its serial, the slots dropped.
fn kept(out: path::Outputs<Slot>) -> Vec<Out> {
    let mut slots = Vec::new();
    let out = keep(out, &mut slots);
    drop(slots);
    out
}

impl Machines {
    /// The machines of a link to `peer` set up at `now` on `setup`, its
    /// original path the peer's pair `at`, reached from this node's
    /// address `from`, with the replay record `record`: the rekey machine
    /// with what link setup knows (the link and the session starting now,
    /// nothing heard yet, the peer's epoch from the handshake), and a bundle
    /// whose original path is `at`, Live, acked and active.
    #[allow(clippy::too_many_arguments)]
    pub fn fresh(
        kit: &mut Kit,
        now: Ms,
        peer: Node,
        mode: Mode,
        setup: Setup,
        record: Record,
        at: Addr,
        from: Addr,
    ) -> (Self, Vec<Event>) {
        let (m, events, _) = Self::held(kit, now, peer, mode, setup, record, at, from, None);
        (m, events)
    }

    /// The machines [`Self::fresh`] builds, for a peer the core holds on
    /// `link`, if given: with the core inputs the join function gives for
    /// the start, which on a link are its original path, Live.
    #[allow(clippy::too_many_arguments)]
    pub fn held(
        kit: &mut Kit,
        now: Ms,
        peer: Node,
        mode: Mode,
        setup: Setup,
        record: Record,
        at: Addr,
        from: Addr,
        link: Option<LinkNo>,
    ) -> (Self, Vec<Event>, Vec<In>) {
        let facts = SetupFacts {
            peer_epoch: Some(setup.done.epoch),
            k: false,
            link_since: TestInstant(now),
            started: TestInstant(now),
            peer_k: None,
            last_rx: None,
            record,
        };
        Self::founded(kit, now, peer, mode, setup, facts, (at, from), link)
    }

    /// The machines of the session a candidate rule moves the peer onto at
    /// `now` while it keeps this one: a rekey machine built on `setup` from
    /// what this one shows (the peer's epoch, the link's age, the current
    /// session's start and key-epoch bit, the last frame heard, the bit
    /// last seen from the peer) and a copy of its replay record, which is
    /// what a cross-connection move would carry, and a new bundle whose
    /// original path is the peer's pair `to`, reached from `from`. This
    /// one stays as it is, to open frames under the session kept. A test's
    /// choice: the node has no second machine for one peer. With the core
    /// inputs the join function gives for the start on `link`.
    pub fn beside(
        &self,
        kit: &mut Kit,
        now: Ms,
        setup: Setup,
        to: Addr,
        from: Addr,
        link: LinkNo,
    ) -> (Self, Vec<Event>, Vec<In>) {
        let v = self.rekey.view();
        let (peer_k, record) = self.rekey.memory();
        let cur = v.current.as_ref();
        let facts = SetupFacts {
            peer_epoch: v.peer_epoch,
            k: cur.is_some_and(|e| e.k),
            link_since: v.link_since,
            started: cur.map_or(TestInstant(now), |e| e.started),
            peer_k,
            last_rx: v.last_rx,
            record: record.clone(),
        };
        Self::founded(
            kit,
            now,
            self.peer,
            self.mode,
            setup,
            facts,
            (to, from),
            Some(link),
        )
    }

    /// The machines of a link to `peer` set up at `now` on `setup` with
    /// the rekey facts `facts`, and a bundle whose original path is the
    /// peer's pair `at`, reached from `from`, Live, acked and active: both
    /// built by the join function's start, with the core inputs it gives
    /// for a peer held on `link`.
    #[allow(clippy::too_many_arguments)]
    fn founded(
        kit: &mut Kit,
        now: Ms,
        peer: Node,
        mode: Mode,
        setup: Setup,
        facts: SetupFacts<TestInstant>,
        (at, from): (Addr, Addr),
        link: Option<LinkNo>,
    ) -> (Self, Vec<Event>, Vec<In>) {
        let params = if fault!(ModeIgnored) {
            // The defect's shape: the bundle built enabled whatever the
            // node's setting.
            Mode::On.path()
        } else {
            mode.path()
        };
        let p = pair(at);
        let me = kit.local.addr();
        let (mut rekey, mut bundle): (Option<Machine>, Option<Paths>) = (None, None);
        let joined = {
            let (mut renv, facts_of, draws) = kit.lent(at.transport);
            let env = path::Env {
                facts: facts_of,
                cost: 1.0,
            };
            let mut caps = Caps {
                params: mode.rekey(),
                me,
                now: TestInstant(now),
                env: &mut renv,
            };
            let start = join::Event::Start {
                rekey: &mut rekey,
                bundle: &mut bundle,
                key: key(peer),
                setup: setup.joined(at.transport),
                facts,
                caps: &mut caps,
                to: (p.transport, p.addr),
                params,
                env: &env,
                link,
            };
            draws.lend(|| join(addr(peer), start))
        };
        let joined = joined.unwrap_or_else(|lease| {
            kit.pool.free(lease.release());
            panic!("the setup authenticated {peer:?}'s key")
        });
        let rekey = rekey.expect("a start that returned built the rekey machine");
        let bundle = bundle.expect("a start that returned built the bundle");
        let first = bundle
            .paths()
            .get(0)
            .map(|q| {
                (
                    q.path_id(),
                    pair(super::facts::addr(q.transport_id(), q.addr())),
                )
            })
            .expect("a new bundle holds its original path");
        let mut m = Self {
            peer,
            mode,
            rekey,
            bundle,
            locals: alloc::vec![(at, from)],
            offered: Vec::new(),
            checks: Checked(Checks::new(mode.config(), first, 0)),
            failed: Vec::new(),
        };
        let (events, told) = sorted(kit, Some(&mut m.rekey), now, joined);
        (m, events, told)
    }

    /// Move the peer onto `setup` at `now`, as a cross-connection move
    /// does, through the join function's move: the rekey machine closed
    /// and built again from what it carried (its link age, key-epoch bits,
    /// last frame heard and replay record), then the bundle started again
    /// at the peer's pair `to`, reached from `from`.
    pub fn moved(
        self,
        kit: &mut Kit,
        now: Ms,
        setup: Setup,
        to: Addr,
        from: Addr,
    ) -> (Self, Vec<Event>) {
        let Self {
            peer,
            mode,
            rekey,
            mut bundle,
            locals,
            offered: _,
            checks,
            failed,
        } = self;
        if fault!(MoveBuildsStale) {
            // The defect's shape: the machine runs on as it was, on the
            // session of the handshake moved off, and the one moved onto
            // goes unused.
            kit.pool.free(setup.lease.release());
            let mut m = Self {
                peer,
                mode,
                rekey,
                bundle,
                locals: Vec::new(),
                offered: Vec::new(),
                checks,
                failed,
            };
            let events = m.renewed(kit, now, to, from, locals);
            return (m, events);
        }
        // The defect's shape where the switch is on: the bundle is not
        // started again, so it is withheld from the move.
        let renew = !fault!(RenewSkipped);
        let p = pair(to);
        let me = kit.local.addr();
        let mut slot = Some(rekey);
        let joined = {
            let (mut renv, facts_of, draws) = kit.lent(to.transport);
            let env = path::Env {
                facts: facts_of,
                cost: 1.0,
            };
            let mut caps = Caps {
                params: mode.rekey(),
                me,
                now: TestInstant(now),
                env: &mut renv,
            };
            let shift = join::Event::Shift {
                rekey: &mut slot,
                bundle: renew.then_some(&mut bundle),
                setup: setup.joined(to.transport),
                caps: &mut caps,
                to: (p.transport, p.addr),
                env: &env,
            };
            draws.lend(|| join(addr(peer), shift))
        };
        let joined = joined.unwrap_or_else(|_| unreachable!("only a start is refused"));
        assert!(
            joined.built,
            "a move of {peer:?}'s machines carried them onto a setup of its key"
        );
        let mut m = Self {
            peer,
            mode,
            rekey: slot.expect("a move that built holds the machine built"),
            bundle,
            locals: Vec::new(),
            offered: Vec::new(),
            checks,
            failed,
        };
        let (events, told) = sorted(kit, Some(&mut m.rekey), now, joined);
        assert!(told.is_empty(), "a move tells the core nothing: {told:?}");
        if renew {
            m.kept(to, from, locals);
        } else {
            m.locals = locals;
        }
        (m, events)
    }

    /// Start the bundle again at the peer's pair `to`, reached from
    /// `from`, as a cross-connection move does, keeping of `locals` only
    /// the address for `to`. Only the machine kept stale by a switch takes
    /// this way; a move goes through the join function.
    fn renewed(
        &mut self,
        kit: &mut Kit,
        now: Ms,
        to: Addr,
        from: Addr,
        locals: Vec<(Addr, Addr)>,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        if fault!(RenewSkipped) {
            self.locals = locals;
        } else {
            let p = pair(to);
            let Kit { draws, facts, .. } = kit;
            let env = path::Env { facts, cost: 1.0 };
            let bundle = &mut self.bundle;
            let out = draws.lend(|| bundle.renew(TestInstant(now), &env, (p.transport, p.addr)));
            events.extend(kept(out).into_iter().map(Event::Path));
            self.kept(to, from, locals);
        }
        events
    }

    /// After the bundle started again at the peer's pair `to`, reached
    /// from `from`: the path shell's checks told, and of `locals` only the
    /// address for `to` kept.
    fn kept(&mut self, to: Addr, from: Addr, mut locals: Vec<(Addr, Addr)>) {
        self.checks.0.renewed(&self.bundle);
        locals.retain(|(a, _)| *a == to);
        if locals.is_empty() {
            locals.push((to, from));
        }
        self.locals = locals;
    }

    /// Close both machines as the peer is removed, through the join
    /// function's stop: the bundle, handing back every path's slot, then
    /// the rekey machine with `why`. Returns the events and what the rekey
    /// machine carried, for the node's record store.
    pub fn close(
        self,
        kit: &mut Kit,
        now: Ms,
        why: Close,
    ) -> (Vec<Event>, Option<Carry<TestInstant>>) {
        let Self {
            peer,
            rekey,
            bundle,
            ..
        } = self;
        let (mut rekey, mut bundle) = (Some(rekey), Some(bundle));
        let stop = join::Event::Stop {
            rekey: &mut rekey,
            bundle: &mut bundle,
            why,
        };
        let mut joined = join::<Ik, TestClock, Draw, Slot>(addr(peer), stop)
            .unwrap_or_else(|_| unreachable!("only a start is refused"));
        let carry = joined.carry.take();
        let (events, told) = sorted(kit, None, now, joined);
        assert!(
            told.is_empty(),
            "a removal tells the core nothing: {told:?}"
        );
        (events, carry)
    }

    /// A msg1 of handshake `hs` from the peer, its bytes `bytes`, read at
    /// node level and handed to the rekey machine as arriving `arrival`;
    /// nothing when it does not read as a msg1 to this node.
    pub fn msg1(
        &mut self,
        kit: &mut Kit,
        now: Ms,
        hs: Hs,
        bytes: &[u8],
        arrival: Arrival,
    ) -> Vec<Event> {
        let Some(tok) = read_msg1(&kit.local, bytes) else {
            return Vec::new();
        };
        kit.local.name(answerer(hs));
        self.step(kit, now, Input::PeerMsg1 { tok, arrival })
    }

    /// A msg2 routed to this machine by its receiver index.
    pub fn reply(&mut self, kit: &mut Kit, now: Ms, bytes: &[u8]) -> Vec<Event> {
        self.step(kit, now, Input::Reply { bytes, route: () })
    }

    /// A frame routed to this machine by its receiver index, on the slow
    /// path; the events and the frame's buffer after the call, which a
    /// `Deliver`'s range indexes.
    pub fn frame(&mut self, kit: &mut Kit, now: Ms, bytes: &[u8]) -> (Vec<Event>, Vec<u8>) {
        let mut buf = bytes.to_vec();
        let h = hint(&buf);
        let transport = self.transport();
        let out = self.rekey.step(
            TestInstant(now),
            Input::Frame {
                buf: &mut buf,
                hint: h,
            },
            &mut kit.env(transport),
        );
        let events = self.rekeyed(kit, now, out);
        (events, buf)
    }

    /// Poll both machines at `now`, the rekey machine first; a msg1 its
    /// time trigger sends takes the name `next`.
    pub fn poll(&mut self, kit: &mut Kit, now: Ms, next: Hs) -> Vec<Event> {
        kit.local.name(opener(next));
        let mut events = self.step(kit, now, Input::Poll);
        events.extend(self.path(kit, now, PathInput::Poll, None));
        events
    }

    /// Fire the rekey machine's time trigger at `now`, through the test
    /// hook that brings it forward while every other start condition still
    /// decides; the msg1 it sends, if any, takes the name `next`.
    pub fn trigger(&mut self, kit: &mut Kit, now: Ms, next: Hs) -> Vec<Event> {
        kit.local.name(opener(next));
        let transport = self.transport();
        let out = self
            .rekey
            .trigger(TestInstant(now), &mut kit.env(transport));
        self.rekeyed(kit, now, out)
    }

    /// Seal `plaintext` under the current epoch; `None` when the machine
    /// refuses to seal.
    pub fn seal(&mut self, now: Ms, plaintext: &[u8]) -> Option<Wire> {
        let sealed = self.rekey.seal(TestInstant(now)).ok()?;
        Some(frame(&sealed, plaintext))
    }

    /// Account one authentic frame of the link, `len` bytes of link
    /// message type `kind`, from the peer's pair `src` to this node's
    /// address `local`. A one-path roam, which the bundle reports in no
    /// output, comes back as [`Event::Roamed`] or [`Event::Bound`]; for a
    /// path that is not active the pair it left is the one read before the
    /// call, since the bundle names only its index. Also returns whether
    /// the frame came from a pair the link holds no path at and the roam
    /// did not follow it, which the heard feed reads.
    pub fn account(
        &mut self,
        kit: &mut Kit,
        now: Ms,
        src: Addr,
        local: Addr,
        len: usize,
        kind: u8,
    ) -> (Vec<Event>, bool) {
        let before: Vec<Addr> = self
            .bundle
            .paths()
            .paths()
            .iter()
            .map(|p| super::facts::addr(p.transport_id(), p.addr()))
            .collect();
        let p = pair(src);
        let bundle = &mut self.bundle;
        let got = kit
            .draws
            .lend(|| bundle.account(TestInstant(now), p.transport, &p.addr, len, kind));
        let unpathed = got.path.is_none() && got.roam == Roam::Unmoved;
        let event = match got.roam {
            Roam::Unmoved => None,
            Roam::Bound => Some(Event::Bound { at: src }),
            Roam::Roamed { from } => Some(Event::Roamed {
                from: super::facts::addr(from.0, &from.1),
                to: src,
            }),
            Roam::Standby { index } => before
                .get(index)
                .map(|&from| Event::Roamed { from, to: src }),
        };
        if let Some(Event::Roamed { from, to }) = &event {
            self.locals.retain(|(a, _)| a != from);
            self.locals.push((*to, local));
        } else if let Some(Event::Bound { at }) = &event {
            self.locals.push((*at, local));
        }
        (event.into_iter().collect(), unpathed)
    }

    /// Step the bundle with `input` at `now`. A path the step creates is
    /// reached from the address its candidate was offered from, or else
    /// from this node's address `local`, when given; a candidate the input
    /// reports is offered from `local`.
    pub fn path(
        &mut self,
        kit: &mut Kit,
        now: Ms,
        input: PathInput,
        local: Option<Addr>,
    ) -> Vec<Event> {
        if let (
            PathInput::Candidate {
                transport, addr, ..
            },
            Some(l),
        ) = (&input, local)
        {
            let a = super::facts::addr(*transport, addr);
            self.offered.retain(|(p, _)| *p != a);
            self.offered.push((a, l));
        }
        let call = self
            .checks
            .0
            .before(&self.bundle, TestInstant(now), &input, 1.0, 0);
        let bundle = &mut self.bundle;
        let Kit { draws, facts, .. } = kit;
        let mut env = path::Env { facts, cost: 1.0 };
        let out = draws.lend(|| bundle.step(TestInstant(now), input.clone(), &mut env));
        let stepped = call.stepped(&self.bundle);
        let out = kept(out);
        if let Err(e) = self
            .checks
            .0
            .after(stepped, &self.bundle, &input, &out, &kit.facts)
        {
            self.failed
                .push(format!("the path shell's check failed on {input:?}: {e}"));
        }
        for o in &out {
            match o {
                PathOutput::State { to, from: None, .. } => {
                    let a = at(to);
                    let offered = self.offered.iter().find(|(p, _)| *p == a).map(|(_, l)| *l);
                    if let Some(l) = offered.or(local) {
                        self.locals.retain(|(p, _)| *p != a);
                        self.locals.push((a, l));
                    }
                }
                PathOutput::State { to, next: None, .. } | PathOutput::Released { to, .. } => {
                    let a = at(to);
                    if self.bundle.paths().find(to.transport, &to.addr).is_none() {
                        self.locals.retain(|(p, _)| *p != a);
                    }
                }
                PathOutput::Moved { from, to, .. } => {
                    let (was, now) = (at(from), at(to));
                    for (p, _) in self.locals.iter_mut().filter(|(p, _)| *p == was) {
                        *p = now;
                    }
                }
                PathOutput::State { .. }
                | PathOutput::Send { .. }
                | PathOutput::Capable
                | PathOutput::NotCapable
                | PathOutput::Refused { .. }
                | PathOutput::Switched { .. }
                | PathOutput::Orphaned
                | PathOutput::Connect { .. } => {}
            }
        }
        out.into_iter().map(Event::Path).collect()
    }

    /// A path message from the peer, its plaintext `plain` from the type
    /// byte, arriving from the peer's pair `src` at this node's address
    /// `local`, its frame already accounted ([`Self::account`]): decoded
    /// and stepped into the bundle, as the node steps it at either setting
    /// (a disabled bundle takes it as a poll). Nothing when `plain` is no
    /// path message, or when it does not decode, which the node drops
    /// unanswered. A path the message creates is reached from `local`.
    pub fn message(
        &mut self,
        kit: &mut Kit,
        now: Ms,
        src: Addr,
        local: Addr,
        plain: &[u8],
    ) -> Vec<Event> {
        let Some(input) = decode(src, plain) else {
            return Vec::new();
        };
        self.path(kit, now, input, Some(local))
    }

    /// Take the rules of the path shell's checks the bundle broke since
    /// the last call: each step of the bundle is checked as the path
    /// shell checks it (`Checks::before`, `Checks::after`).
    pub fn failures(&mut self) -> Vec<String> {
        core::mem::take(&mut self.failed)
    }

    /// Run the path shell's checks over a step of `input` at `now` as if
    /// the bundle had answered `out`, which a test plants: the bundle is
    /// not stepped, and the checks remember the planted outputs as their
    /// own.
    pub fn plant(
        &mut self,
        kit: &Kit,
        now: Ms,
        input: &PathInput,
        out: &[Out],
    ) -> Result<(), String> {
        let call = self
            .checks
            .0
            .before(&self.bundle, TestInstant(now), input, 1.0, 0);
        let stepped = call.stepped(&self.bundle);
        self.checks
            .0
            .after(stepped, &self.bundle, input, out, &kit.facts)
    }

    /// The peer's address as this node treats it: the bundle's active
    /// path, as the node's is (`current_addr`, `src/peer/active.rs`).
    /// `None` while no path is active, when the node sends the peer
    /// nothing.
    pub fn active(&self) -> Option<Addr> {
        self.bundle
            .paths()
            .active()
            .map(|p| super::facts::addr(p.transport_id(), p.addr()))
    }

    /// What the peer's pair `at` is to the bundle's paths (`path_match`).
    pub fn matched(&self, at: Addr) -> path::Match {
        let q = pair(at);
        self.bundle.paths().classify(q.transport, &q.addr)
    }

    /// This node's own address on the path to the peer's pair `at`.
    pub fn local(&self, at: Addr) -> Option<Addr> {
        self.locals.iter().find(|(p, _)| *p == at).map(|(_, l)| *l)
    }

    /// The earliest instant either machine has something to do.
    pub fn wake(&self) -> Option<Ms> {
        let r = self.rekey.next_wake().map(|t| t.0);
        let b = self.bundle.next_wake().map(|t| t.0);
        r.into_iter().chain(b).min()
    }

    /// The earliest instant the rekey machine has something to do: the
    /// machines' wake leaving out the bundle's.
    pub fn paced(&self) -> Option<Ms> {
        self.rekey.next_wake().map(|t| t.0)
    }

    /// The peer.
    pub fn peer(&self) -> Node {
        self.peer
    }

    /// The node's multipath setting.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The rekey machine.
    pub fn rekey(&self) -> &Machine {
        &self.rekey
    }

    /// Whether the link and the session are past the two start floors
    /// `floors` at `now`, as the rekey machine's start reads them.
    pub fn eligible(&self, floors: (Ms, Ms), now: Ms) -> bool {
        let v = self.rekey.view();
        let (link, session) = floors;
        now.saturating_sub(v.link_since.0) >= link
            && v.current
                .is_some_and(|c| now.saturating_sub(c.started.0) >= session)
    }

    /// What an abstract far end's frame of `plaintext` at `counter` is on
    /// the wire, under the session `want` this machine holds: sealed with
    /// the far end's key, toward this node's index, with the key-epoch bit
    /// the machine holds for that session. `None` when it holds no such
    /// session. This is stub crypto, with no decision in it.
    pub fn sealed(&self, want: Kid, counter: u64, plaintext: &[u8]) -> Option<Wire> {
        let (v, pk) = (self.rekey.view(), self.rekey.peek());
        [
            (pk.current, v.current.map(|e| e.k)),
            (pk.pending, v.pending.map(|e| e.k)),
            (pk.previous, v.previous.map(|e| e.k)),
        ]
        .into_iter()
        .find_map(|(e, k)| {
            let e = e.filter(|e| kid(e.session) == want)?;
            let index = e.ours?;
            Some(seal_to(e.session, index, counter, k?, plaintext))
        })
    }

    /// What an abstract far end's frame under the session `want` of the
    /// handshake `hs` is on the wire: the next frame of that session by
    /// `counters`, which this node keeps per handshake since such an end
    /// keeps none, or, for a copy the explorer made, the last one again,
    /// which the machine refuses as a replay.
    pub fn written(
        &self,
        counters: &mut BTreeMap<u32, u64>,
        (hs, want): (Hs, Kid),
        copy: bool,
        plaintext: &[u8],
    ) -> Option<Wire> {
        let next = counters.entry(hs.0).or_insert(0);
        let counter = if copy && *next > 0 {
            *next - 1
        } else {
            *next += 1;
            *next - 1
        };
        self.sealed(want, counter, plaintext)
    }

    /// Quiet the rekey machine's own time and message triggers, for the
    /// driver (`../drive.rs`), whose histories say when a rekey starts. A
    /// rekey the shell fires through the trigger hook still starts.
    pub fn quiet(&mut self) {
        self.rekey.quiet();
    }

    /// The bundle.
    pub fn bundle(&self) -> &Paths {
        &self.bundle
    }

    /// Write the explorer's key of both machines at `now` to `out`: every
    /// field of the rekey machine that can change (`Rekey::state`, which
    /// its own explorer keys on), every field of the bundle (its `Debug`),
    /// and this node's address for each path. `view` and `bindings` would
    /// not do: they leave out the session's counters and replay window,
    /// the cycle's detail, the deadlines, the replay record and most of the
    /// machine's memory, and the bundle's candidates, capability record and
    /// timers, each of which a successor reads.
    pub fn key(&self, now: Ms, out: &mut String) {
        let _ = write!(out, "{:?} {:?} ", self.peer, self.mode);
        if fault!(KeyFromView) {
            // The defect's shape: the machines keyed on what they show.
            let _ = write!(
                out,
                "{:?} {:?} {:?} {:?}",
                self.rekey.view(),
                self.rekey.bindings(),
                self.bundle.view(TestInstant(now)),
                self.bundle.paths()
            );
        } else {
            let _ = self.rekey.state(out);
            if !fault!(KeyOmitsBundle) {
                let _ = write!(out, " {:?}", self.bundle);
            }
        }
        let _ = write!(out, " {:?} {:?};", self.locals, self.offered);
    }

    /// The transport the link's frames go out on now: the active path's,
    /// or the original path's while none is active.
    fn transport(&self) -> u8 {
        let paths = self.bundle.paths();
        paths
            .active()
            .or_else(|| paths.get(0))
            .map_or(0, |p| u8::try_from(p.transport_id().as_u32()).unwrap_or(0))
    }

    /// Step the rekey machine with `input` at `now`.
    fn step(&mut self, kit: &mut Kit, now: Ms, input: Input<'_, Ik>) -> Vec<Event> {
        let transport = self.transport();
        let out = self
            .rekey
            .step(TestInstant(now), input, &mut kit.env(transport));
        self.rekeyed(kit, now, out)
    }

    /// The rekey machine's outputs as events, a prompt sealed and a lease
    /// freed on the way.
    fn rekeyed(&mut self, kit: &mut Kit, now: Ms, out: Vec<Output<Ik>>) -> Vec<Event> {
        let mut events = Vec::new();
        for o in out {
            events.push(carried(kit, Some(&mut self.rekey), now, o));
        }
        events
    }
}

/// Whether `kind` is the link message type of a path message.
pub fn messaged(kind: u8) -> bool {
    [
        LinkMessageType::PathProbe,
        LinkMessageType::PathAck,
        LinkMessageType::PathClose,
    ]
    .iter()
    .any(|t| t.to_byte() == kind)
}

/// The bundle input the path message `plain`, from its type byte, makes
/// when it arrives from the peer's pair `src`, decoded by the path codec;
/// `None` for no path message or one that does not decode.
pub fn decode(src: Addr, plain: &[u8]) -> Option<PathInput> {
    let (&kind, body) = plain.split_first()?;
    let PathRef { transport, addr } = pair(src);
    if kind == LinkMessageType::PathProbe.to_byte() {
        let msg = PathProbe::decode(body).ok()?;
        Some(PathInput::Probe {
            transport,
            addr,
            msg,
        })
    } else if kind == LinkMessageType::PathAck.to_byte() {
        let msg = PathAck::decode(body).ok()?;
        Some(PathInput::Ack {
            transport,
            addr,
            msg,
        })
    } else if kind == LinkMessageType::PathClose.to_byte() {
        let msg = PathClose::decode(body).ok()?;
        Some(PathInput::Close {
            transport,
            addr,
            msg,
        })
    } else {
        None
    }
}

/// One rekey output as an event: a prompt sealed by `machine`, a lease
/// freed into the kit's pool, anything else as it is.
fn carried(kit: &mut Kit, machine: Option<&mut Machine>, now: Ms, o: Output<Ik>) -> Event {
    match o {
        Output::Prompt { tag } => {
            let m = machine.expect("only a live machine asks for a prompt");
            let sealed = m
                .seal_prompt(TestInstant(now), tag)
                .expect("a prompt the machine asked for seals");
            Event::Prompt {
                tag,
                wire: frame(&sealed.sealed, &sealed.plaintext),
            }
        }
        Output::Release(lease) => {
            let index = lease.release();
            kit.pool.free(index);
            Event::Freed(index)
        }
        o @ (Output::Send { .. }
        | Output::Deliver { .. }
        | Output::Bind { .. }
        | Output::Unbind { .. }
        | Output::Delegate { .. }
        | Output::Revoke { .. }
        | Output::Installed { .. }
        | Output::Retired { .. }
        | Output::Reverted { .. }
        | Output::PeerRestarted { .. }
        | Output::Rekeyed { .. }
        | Output::ReplaceRequested { .. }
        | Output::Reject(_)
        | Output::Abandoned(_)
        | Output::Teardown(_)) => Event::Rekey(o),
    }
}

/// The steps of one call of the join function as events, in order, and
/// the core inputs among them: a rekey machine output carried as
/// [`carried`] carries it, with `machine` to seal a prompt, and a bundle
/// output with each driver slot by its serial. A machine call asks the
/// core's gates for no replacement: the rekey machine asks for one only at
/// a msg1.
fn sorted(
    kit: &mut Kit,
    mut machine: Option<&mut Machine>,
    now: Ms,
    joined: Joined<Ik, Slot, TestInstant>,
) -> (Vec<Event>, Vec<In>) {
    let mut events = Vec::new();
    let mut told = Vec::new();
    for step in joined {
        match step {
            Step::Rekey(o) => events.push(carried(kit, machine.as_deref_mut(), now, o)),
            Step::Path(o) => events.extend(kept(alloc::vec![o]).into_iter().map(Event::Path)),
            Step::Core(i) => told.push(i),
            Step::Replace(_) => panic!("a machine call asked for a replacement"),
        }
    }
    (events, told)
}

impl Setup {
    /// The setup as the join function takes it, its index bound on world
    /// transport `transport`.
    fn joined(self, transport: u8) -> join::Setup<Ik> {
        join::Setup {
            done: self.done,
            lease: self.lease,
            theirs: self.theirs,
            transport,
        }
    }
}

use crate::proto::path::Source;
use crate::proto::rekey::{Msg1Read, MsgKind, Profile, allocate};

use super::super::starts::{A, B, BLE, TCP, UDP, home};
use super::super::world::Kind as World;
use super::names::{msg2 as answer, opened, opener as named};

/// The world's three transports.
fn kinds() -> BTreeMap<u8, World> {
    [
        (UDP, World::Datagram),
        (TCP, World::Stream),
        (BLE, World::Ble),
    ]
    .into_iter()
    .collect()
}

/// The world epoch of node `n` in its first life, as the world's parties
/// number it.
fn life(n: Node) -> Epoch {
    Epoch(u32::from(n.0) << 8)
}

/// Both nodes' kits.
pub(super) fn kits() -> (Kit, Kit) {
    (
        Kit::new(A, life(A), &kinds()),
        Kit::new(B, life(B), &kinds()),
    )
}

/// One end's half of a completed handshake: its setup and replay record.
pub(super) type Half = (Setup, Record);

/// Handshake `hs` from `x` to `y`, each end's index drawn from its kit,
/// completed at both ends: the initiator's half, the responder's, and the
/// msg2.
pub(super) fn exchange(kx: &mut Kit, ky: &mut Kit, y: Node, hs: Hs) -> (Half, Half, Wire) {
    let lx = allocate(&mut kx.pool).expect("an index");
    let ly = allocate(&mut ky.pool).expect("an index");
    let (ix, iy) = (lx.index(), ly.index());
    kx.local.name(named(hs));
    let (state, m1) = Ik::initiate(&kx.local, &key(y), Some(ix)).expect("writes");
    let tok = read_msg1(&ky.local, &m1).expect("the msg1 reads");
    ky.local.name(answerer(hs));
    let (done_y, m2) = tok.get().answer(&ky.local, Some(iy)).expect("answers");
    let done_x = Ik::reply(&state, &kx.local, &m2)
        .expect("the msg2 reads")
        .done;
    let (whole, eph) = (tok.get().digest(), tok.get().ephemeral());
    let x = (
        Setup {
            done: done_x,
            lease: lx,
            theirs: iy,
        },
        Record::setup(whole, eph, None),
    );
    let y = (
        Setup {
            done: done_y,
            lease: ly,
            theirs: ix,
        },
        Record::setup(whole, eph, Some(m2.clone())),
    );
    (x, y, m2)
}

/// Give a setup's lease back to its kit's pool, unused.
pub(super) fn unused(kit: &mut Kit, s: Setup) {
    kit.pool.free(s.lease.release());
}

/// The bytes of the handshake message of `kind` among `events`.
fn sent(events: &[Event], kind: MsgKind) -> Wire {
    events
        .iter()
        .find_map(|e| {
            if let Event::Rekey(Output::Send { msg, kind: k, .. }) = e
                && *k == kind
            {
                Some(msg.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("a {kind:?} is sent: {events:?}"))
}

/// The prompt among `events`: the epoch it is sealed under, and its
/// frame.
fn prompted(events: &[Event]) -> (rekey::EpochTag, Wire) {
    events
        .iter()
        .find_map(|e| {
            if let Event::Prompt { tag, wire } = e {
                Some((*tag, wire.clone()))
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("a prompt is sealed: {events:?}"))
}

/// Whether `events` report a cutover.
fn rekeyed(events: &[Event]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, Event::Rekey(Output::Rekeyed { .. })))
}

/// The session `m` holds as current.
fn current(m: &Machines) -> Kid {
    kid(m
        .rekey()
        .peek()
        .current
        .expect("an established machine has a current epoch")
        .session)
}

/// Every index `kit`'s pool holds is one `m` binds.
fn conserved(kit: &Kit, m: &Machines) {
    let mut bound: Vec<u32> = m.rekey().bindings().iter().map(|b| b.index).collect();
    bound.sort_unstable();
    let held: Vec<u32> = kit.pool.used.iter().copied().collect();
    assert_eq!(bound, held, "the pool holds exactly the indices bound");
}

const H0: Hs = Hs(0x0101_0001);
const H1: Hs = Hs(0x0101_0002);
const H2: Hs = Hs(0x0101_0003);
const DATA: &[u8] = &[0x10, 1, 2, 3, 4, 5, 6, 7];

#[test]
fn two_peers_machines_rekey_and_both_cut_over_on_one_session() {
    let (mut ka, mut kb) = kits();
    let ((sa, ra), (sb, rb), _) = exchange(&mut ka, &mut kb, B, H0);
    let (ua, ub) = (home(0, UDP), home(1, UDP));
    let (mut a, _) = Machines::fresh(&mut ka, 0, B, Mode::Off, sa, ra, ub, ua);
    let (mut b, _) = Machines::fresh(&mut kb, 0, A, Mode::Off, sb, rb, ua, ub);
    let first = current(&a);
    assert_eq!(
        current(&b),
        first,
        "precondition: link setup left one session"
    );
    let t = 40_000;
    let ev = a.trigger(&mut ka, t, H1);
    let m1 = sent(&ev, MsgKind::Msg1);
    let on = Arrival {
        on_link: true,
        reachable: true,
    };
    let ev = b.msg1(&mut kb, t, H1, &m1, on);
    let m2 = sent(&ev, MsgKind::Msg2);
    a.reply(&mut ka, t, &m2);
    let w = a.wake().expect("the initiator cuts over at a poll");
    assert!(
        w <= t + 1_000,
        "the initiator cuts over at the next check: wake {w}"
    );
    let ev = a.poll(&mut ka, w, H2);
    assert!(rekeyed(&ev), "the initiator cuts over: {ev:?}");
    let (tag, prompt) = prompted(&ev);
    assert_eq!(
        a.rekey().view().current.map(|c| c.tag),
        Some(tag),
        "the prompt is sealed under the epoch cut over to"
    );
    b.account(&mut kb, w, ua, ub, prompt.len(), 0x51);
    let (ev, _) = b.frame(&mut kb, w, &prompt);
    assert!(rekeyed(&ev), "the responder cuts over at the frame: {ev:?}");
    let session = current(&a);
    assert_eq!(current(&b), session, "both ends cut over to one session");
    assert_ne!(session, first, "the session is the rekey's");
    assert_eq!(
        opened(A, life(A), B, H1, 0, &m2),
        Some(session),
        "the initiator's ephemeral is the one the world names for the rekey's msg1"
    );
    assert_eq!(
        answer(B, life(B), H1, &m1, 0).map(|(_, id)| id),
        Some(session),
        "the responder's ephemeral is the one the world names for its answer"
    );
    let data = a.seal(w, DATA).expect("the new session seals");
    let (ev, buf) = b.frame(&mut kb, w, &data);
    let got = ev.iter().find_map(|e| {
        if let Event::Rekey(Output::Deliver { range, .. }) = e {
            buf.get(range.clone())
        } else {
            None
        }
    });
    assert_eq!(got, Some(DATA), "the new session carries data");
    assert_eq!(a.active(), Some(ub), "the peer is at its one path");
    conserved(&ka, &a);
    conserved(&kb, &b);
}

#[test]
fn a_move_keeps_the_record_the_link_age_and_renews_the_bundle() {
    let (mut ka, mut kb) = kits();
    let ((sa, ra), (sb, _), _) = exchange(&mut ka, &mut kb, B, H0);
    unused(&mut kb, sb);
    let (ua, ub) = (home(0, UDP), home(1, UDP));
    let (ta, tb) = (home(0, TCP), home(1, TCP));
    let (a, _) = Machines::fresh(&mut ka, 0, B, Mode::Off, sa, ra, ub, ua);
    let record = a.rekey().memory().1.len();
    assert!(record >= 1, "precondition: the setup is on record");
    let old: Vec<u32> = a.rekey().bindings().iter().map(|b| b.index).collect();
    let t = 40_000;
    let ((sa, _), (sb, _), m2) = exchange(&mut ka, &mut kb, B, H1);
    unused(&mut kb, sb);
    let (a, ev) = a.moved(&mut ka, t, sa, tb, ta);
    assert_eq!(
        a.rekey().view().link_since,
        TestInstant(0),
        "the moved session keeps the link's age"
    );
    assert_eq!(
        a.rekey().memory().1.len(),
        record,
        "the moved session keeps the replay record"
    );
    assert_eq!(
        Some(current(&a)),
        opened(A, life(A), B, H1, 0, &m2),
        "the machine runs the session moved onto"
    );
    assert_eq!(
        a.active(),
        Some(tb),
        "the bundle starts again at the pair moved to"
    );
    assert!(
        ev.iter().any(|e| matches!(
            e,
            Event::Path(PathOutput::Released { to, keep: true, .. }) if at(to) == ub
        )),
        "the old link's path is released, kept, since the peer is not capable: {ev:?}"
    );
    assert_eq!(
        a.local(tb),
        Some(ta),
        "the new path is reached from its own address"
    );
    assert_eq!(a.local(ub), None, "the old path's address is forgotten");
    for i in old {
        assert!(
            ev.iter().any(|e| matches!(e, Event::Freed(f) if *f == i)),
            "the closed machine's index {i} goes back to the pool: {ev:?}"
        );
    }
    conserved(&ka, &a);
    let (_, carry) = a.close(&mut ka, t, Close::Admin);
    assert!(ka.pool.used.is_empty(), "closing returns every index");
    assert_eq!(
        carry.map(|c| c.record.len()),
        Some(record),
        "the record goes to the store at the close"
    );
}

#[test]
fn an_abstract_far_ends_frame_opens_at_the_machine_holding_its_session() {
    let (mut ka, mut kb) = kits();
    let ((sa, ra), (sb, _), _) = exchange(&mut ka, &mut kb, B, H0);
    unused(&mut kb, sb);
    let (ua, ub) = (home(0, UDP), home(1, UDP));
    let (mut a, _) = Machines::fresh(&mut ka, 0, B, Mode::Off, sa, ra, ub, ua);
    let session = current(&a);
    let first = a.sealed(session, 0, DATA).expect("the machine holds it");
    let (ev, buf) = a.frame(&mut ka, 10, &first);
    let got = ev.iter().find_map(|e| {
        if let Event::Rekey(Output::Deliver { range, .. }) = e {
            buf.get(range.clone())
        } else {
            None
        }
    });
    assert_eq!(got, Some(DATA), "the frame opens to what was sealed");
    let (ev, _) = a.frame(&mut ka, 10, &first);
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Rekey(Output::Reject(rekey::Reason::Replay)))),
        "the same counter again is a replay: {ev:?}"
    );
    assert_eq!(
        a.sealed(([0; 8], [1; 8]), 1, DATA),
        None,
        "nothing is sealed under a session the machine does not hold"
    );
    a.close(&mut ka, 10, Close::Admin);
}

#[test]
fn a_disabled_bundle_takes_a_candidate_as_a_poll_and_an_enabled_one_holds_it() {
    for mode in [Mode::Off, Mode::On] {
        let (mut ka, mut kb) = kits();
        let ((sa, ra), (sb, _), _) = exchange(&mut ka, &mut kb, B, H0);
        unused(&mut kb, sb);
        let (ua, ub) = (home(0, UDP), home(1, UDP));
        let (mut a, _) = Machines::fresh(&mut ka, 0, B, mode, sa, ra, ub, ua);
        assert_eq!(
            (a.peer(), a.mode()),
            (B, mode),
            "precondition: built as asked"
        );
        assert!(
            a.bundle().next_wake().is_none(),
            "precondition: a one-path link with no candidate has no bundle wake ({})",
            mode.name()
        );
        let tb = pair(home(1, TCP));
        let candidate = PathInput::Candidate {
            transport: tb.transport,
            addr: tb.addr.clone(),
            source: Source::Config,
        };
        let ev = a.path(&mut ka, 1_000, candidate, Some(home(0, TCP)));
        let held = a
            .bundle()
            .candidates()
            .iter()
            .any(|e| e.transport() == tb.transport && *e.addr() == tb.addr);
        match mode {
            Mode::Off => {
                assert!(
                    !held && ev.is_empty() && a.bundle().next_wake().is_none(),
                    "a disabled bundle takes the candidate as a poll: held {held}, {ev:?}"
                );
            }
            Mode::On => {
                assert!(held, "an enabled bundle holds the candidate");
                assert!(
                    a.bundle().next_wake().is_some(),
                    "and wakes for the capability probe it allows"
                );
            }
        }
        a.close(&mut ka, 1_000, Close::Admin);
    }
}
