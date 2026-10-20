//! The deterministic two-party simulator.
//!
//! [`World`] holds two test shells (`stub::Node`) whose machines talk over a
//! channel of datagrams in flight, executes each machine's outputs as a
//! shell would, models a decrypt worker and a next-only leg table where the
//! profile has them, and checks the oracles after every event. The explorer
//! (`explore.rs`) drives the same world one chosen event at a time; the
//! random runs here drive it from a seeded schedule:
//!
//! - **Channel.** Per datagram: loss, duplication (up to three copies, each
//!   delayed on its own), a base delay with a heavy tail that has no upper
//!   bound, partitions and per-direction asymmetry.
//! - **Adversary.** Garbage of each message's length, bit-flipped genuine
//!   messages, replays of captured datagrams (IK msg1s included, some with
//!   their sender index rewritten), withheld frames released later, a
//!   msg3 completed under a third identity, and setups from a third party
//!   on other carriers.
//! - **Time.** One virtual clock. A timer-driven shell polls each machine
//!   at its `next_wake`; a tick-driven one polls every second. A node can
//!   be suspended, and then polls late.
//! - **Traffic.** Two-way, one-way or silent.
//!
//! Every fault decision is a pure function of the run's seed and a stable
//! key (the datagram's ordinal, the adversary slot), so a run can be
//! replayed from its seed, and a failing run's decisions can be removed one
//! at a time while it still fails, leaving a minimal schedule.
//!
//! The oracles (each named in the message of the failure it reports):
//!
//! - O1 convergence: once healed and idle, both ends hold the same current
//!   epoch, no attempt, no pending, and (indexed) matching index pairs.
//! - O2 bounded outage: no direction loses data frames to an epoch the
//!   receiver does not hold for longer than the run's bound.
//! - O3 conservation: the indices a shell holds are the ones its machine
//!   binds (plus those its leg table holds), and no lease leaks.
//! - O4 deadlines: after a poll, the machine's next wake is in the future,
//!   and no own attempt outlives its absolute deadline.
//! - O5 unauthenticated input: a forged input leaves the state (bar
//!   candidates) unchanged, and a copy of a datagram the node already took
//!   leaves it unchanged bar candidates and the replay record, except a
//!   replayed IK msg1 the record did not hold (its sender index rewritten
//!   or not), which is the accepted residual and is reported as one. Which
//!   msg1s the record holds is not read from the machine: the world keeps
//!   its own list of the ephemerals each node answered, refused or handed
//!   to a replacement, within the record's bound and for the machine's
//!   lifetime, and any msg1 (copy or not) on that list that arms a pending
//!   fails O5 instead of counting as the residual.
//! - O6 memory: candidates and the record stay within their bounds.
//! - O7 rotation under forgery: on a lossless channel with the adversary
//!   active, cutovers stay on cadence.
//! - O8 key retention: no previous epoch outlives the drain ceiling.
//! - O9 workers: the worker's epochs are exactly the delegated ones.
//! - O10 residual containment: a residual replay adopts, confirms,
//!   refreshes and retires nothing.
//! - O11 no orphan: a machine without a current epoch holds an attempt or a
//!   candidate and has a next wake, and none is still opening once healed.
//! - Sealing: data is sealed only under an epoch the peer has held, unless
//!   it was assumed, installed first, or delayed.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::stub::{
    DATA, Ev, Hs, Kid, Local, Mid, Msg, Node, Stub, bytes, frame, hint, kid, ordered,
    pair_jittered, worker_open,
};
use crate::proto::rekey::{
    Close, CycleView, Digest, EpochTag, EvidenceKind, IndexLease, Input, Intent, Msg1Read, MsgKind,
    Params, PeerKey, RECORD_BOUND, Reason, RecvHome, Wire, allocate, leaked,
};
use crate::testutil::{SplitMix64, TestInstant};

/// Log a formatted line on world `$w`, formatting nothing while its log
/// is off.
macro_rules! note {
    ($w:expr, $($fmt:tt)*) => {
        if $w.logging {
            let line = format!($($fmt)*);
            $w.note(line);
        }
    };
}

/// A data frame counts toward O2 only if it arrived this soon after it was
/// sent; a frame delayed longer may legitimately find its epoch retired.
const FRESH: u64 = 2_000;

/// The step cap of one run, so a guard switched off that makes a machine
/// spin fails instead of hanging.
const STEPS: u64 = 2_000_000;

/// Where a datagram in flight came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// A node sent it: a handshake message or a prompt.
    Sent,
    /// A data frame a node sealed.
    Data,
    /// A channel duplicate or an adversary replay of datagram `of`.
    Copy(u64),
    /// The adversary made it.
    Forged,
}

/// One datagram in flight.
#[derive(Clone, Debug)]
pub(crate) struct Flight {
    pub(crate) id: u64,
    pub(crate) to: usize,
    /// When the channel delivers it (the explorer ignores this).
    pub(crate) at: u64,
    /// When it was sent.
    pub(crate) sent: u64,
    pub(crate) msg: Msg,
    pub(crate) origin: Origin,
    /// The carrier of a forged setup; genuine setups use the stub's own.
    pub(crate) carrier: u8,
}

impl Flight {
    /// The datagram this one is, or copies.
    fn root(&self) -> u64 {
        match self.origin {
            Origin::Copy(of) => of,
            Origin::Sent | Origin::Data | Origin::Forged => self.id,
        }
    }
}

/// A leg the next-only leg table holds: its handshake, its lease, the msg1
/// it answered and the msg2 it sent.
struct Leg {
    hs: Hs,
    lease: Option<IndexLease>,
    msg1: Wire,
    msg2: Wire,
    until: u64,
}

/// A decrypt worker's registration of one epoch.
#[derive(Clone, Debug)]
struct Reg {
    tag: EpochTag,
    recv: super::stub::RecvKey,
    seen: BTreeSet<u64>,
}

/// What the oracles remember across events.
#[derive(Debug, Default)]
pub(crate) struct Track {
    /// Every key identity each node has held in any slot.
    held: [BTreeSet<Kid>; 2],
    /// How each node's epochs were installed.
    evidence: [BTreeMap<EpochTag, EvidenceKind>; 2],
    /// The datagrams (by root) each node has taken.
    taken: [BTreeSet<u64>; 2],
    /// The frames (by root) each node authenticated.
    authed: [BTreeSet<u64>; 2],
    /// Per receiver, in arrival order: (sent at, delivered) for each fresh
    /// data frame's first arrival.
    data: [Vec<(u64, bool)>; 2],
    /// Rejects and abandons: (instant, node, name).
    pub(crate) outcomes: Vec<(u64, usize, String)>,
    pub(crate) reverts: u32,
    pub(crate) assumed: u32,
    /// Install instants of rekey cutovers, per node.
    pub(crate) installs: [Vec<u64>; 2],
    /// Instants each node started an own attempt.
    pub(crate) starts: [Vec<u64>; 2],
    /// Residual outcomes, named.
    pub(crate) residuals: Vec<String>,
    /// The adversary's msg1 copies with a rewritten sender index, by id.
    rewrites: BTreeSet<u64>,
    /// Per node, oldest first: the ephemerals of the IK msg1s its machine
    /// has answered, refused or handed to a replacement, which its replay
    /// record must still hold. Kept from the machine's outputs, never from
    /// its record, and cleared when the shell drops the machine (the world
    /// discards the record a close hands back).
    owed: [Vec<Digest>; 2],
    /// Teardowns, per node.
    pub(crate) teardowns: [u32; 2],
    leak0: usize,
}

/// A class of datagram a scripted rule matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// A handshake message of this kind.
    Hs(MsgKind),
    /// A frame the machine asked for, under the sender's current epoch (a
    /// prompt or keepalive).
    Prompt,
    /// A frame the machine asked for under another epoch (a probe).
    Probe,
    /// A data frame.
    Data,
}

/// What a scripted rule does to the datagrams it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fate {
    /// Lose them.
    Drop,
    /// Withhold the first one and release it at this instant.
    HoldOnce(u64),
}

/// A scripted channel rule: datagrams of `class` from node `from` sent in
/// `[since, until)` meet `fate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) from: usize,
    pub(crate) class: Class,
    pub(crate) since: u64,
    pub(crate) until: u64,
    pub(crate) fate: Fate,
}

/// The channel's settings for one run.
#[derive(Clone, Debug)]
pub(crate) struct Cfg {
    /// Loss per direction, per mille, indexed by receiver.
    pub(crate) loss: [u64; 2],
    /// Duplication per direction, per mille.
    pub(crate) dup: [u64; 2],
    /// Base one-way delay and its spread, ms, per receiver.
    pub(crate) lat: [u64; 2],
    pub(crate) spread: [u64; 2],
    /// Heavy-tail chance per mille.
    pub(crate) tail: u64,
    /// Data frames withheld and released 10 to 60 s later, per mille.
    pub(crate) withhold: u64,
    /// The adversary acts about this often (ms); 0 is no adversary.
    pub(crate) adversary: u64,
    /// Partitions: (receiver, from, until).
    pub(crate) partitions: Vec<(usize, u64, u64)>,
    /// Suspensions: (node, from, until).
    pub(crate) suspends: Vec<(usize, u64, u64)>,
    /// A decrypt worker pool exists (indexed profiles only).
    pub(crate) workers: bool,
    /// Offers the worker refuses, per mille.
    pub(crate) refuse: u64,
    /// Worker losses: (node, at).
    pub(crate) losses: Vec<(usize, u64)>,
    /// A tick-driven shell instead of a timer-driven one.
    pub(crate) tick: bool,
    /// Data gap per node, ms; 0 is silent.
    pub(crate) gap: [u64; 2],
    /// Faults stop here; the run heals after.
    pub(crate) fault_end: u64,
    /// Each direction keeps its datagrams in order, as a path without
    /// faults does; reordering is a fault.
    pub(crate) fifo: bool,
    /// Scripted rules, applied before any drawn fault, in every phase.
    pub(crate) rules: Vec<Rule>,
}

impl Cfg {
    /// A lossless channel with short fixed delays, no adversary, two-way
    /// traffic every half second, and a timer-driven shell.
    pub(crate) fn clean() -> Self {
        Self {
            loss: [0; 2],
            dup: [0; 2],
            lat: [20; 2],
            spread: [10; 2],
            tail: 0,
            withhold: 0,
            adversary: 0,
            partitions: Vec::new(),
            suspends: Vec::new(),
            workers: false,
            refuse: 0,
            losses: Vec::new(),
            tick: false,
            gap: [500; 2],
            fault_end: 0,
            fifo: true,
            rules: Vec::new(),
        }
    }

    /// A faulty channel drawn from `seed`, faults ending at `end`.
    pub(crate) fn faulty(seed: u64, end: u64, indexed: bool) -> Self {
        let mut g = SplitMix64::new(seed ^ 0x5eed);
        let mut c = Self::clean();
        for d in 0..2 {
            c.loss[d] = g.below(300);
            c.dup[d] = g.below(100);
            c.lat[d] = 5 + g.below(200);
            c.spread[d] = 1 + g.below(c.lat[d]);
        }
        c.tail = g.below(40);
        c.withhold = g.below(30);
        c.adversary = if g.chance(500) {
            1_000 + g.below(9_000)
        } else {
            0
        };
        for _ in 0..g.below(3) {
            let from = g.below(end);
            c.partitions.push((
                g.below(2) as usize,
                from,
                (from + 1_000 + g.below(40_000)).min(end),
            ));
        }
        for _ in 0..g.below(3) {
            let from = g.below(end);
            c.suspends.push((
                g.below(2) as usize,
                from,
                (from + 500 + g.below(20_000)).min(end),
            ));
        }
        c.workers = indexed && g.chance(500);
        c.refuse = g.below(400);
        for _ in 0..g.below(3) {
            c.losses.push((g.below(2) as usize, g.below(end)));
        }
        c.tick = g.chance(500);
        c.gap = match g.below(3) {
            0 => [100 + g.below(900), 100 + g.below(900)],
            1 => [100 + g.below(900), 0],
            _ => [0, 0],
        };
        c.fault_end = end;
        c.fifo = g.chance(300);
        c
    }
}

/// Decision purposes, the first part of each decision's key.
mod why {
    pub(super) const LOSS: u64 = 1;
    pub(super) const DUP: u64 = 2;
    pub(super) const TAIL: u64 = 3;
    pub(super) const HOLD: u64 = 4;
    pub(super) const ADV: u64 = 5;
    pub(super) const REFUSE: u64 = 6;
    pub(super) const LAT: u64 = 10;
    pub(super) const COPY: u64 = 11;
    pub(super) const DATA: u64 = 12;
}

/// The default parameters of `P`'s layer.
pub(crate) fn params<P: Stub>() -> Params {
    match P::LAYER {
        crate::proto::rekey::Layer::Fmp => Params::fmp(),
        crate::proto::rekey::Layer::Fsp => Params::fsp(),
    }
}

/// The fault decisions of one run: drawn from the seed and recorded, or
/// read from a recorded script, so a run can be replayed and shrunk.
#[derive(Clone, Debug)]
pub(crate) struct Chan {
    pub(crate) seed: u64,
    pub(crate) cfg: Cfg,
    /// When replaying, the decisions to take; any other is the default.
    pub(crate) script: Option<BTreeMap<(u64, u64), u64>>,
    /// The decisions that fired, in generation mode.
    pub(crate) fired: BTreeMap<(u64, u64), u64>,
    ord: u64,
}

impl Chan {
    /// The channel of `cfg`, drawing from `seed`.
    pub(crate) fn new(seed: u64, cfg: Cfg) -> Self {
        Self {
            seed,
            cfg,
            script: None,
            fired: BTreeMap::new(),
            ord: 0,
        }
    }

    /// The decision for (`purpose`, `key`): `draw` maps a mixed value to it,
    /// 0 being the default; past the fault phase every fault is 0.
    fn decide(&mut self, now: u64, purpose: u64, key: u64, draw: impl FnOnce(u64) -> u64) -> u64 {
        if now >= self.cfg.fault_end {
            return 0;
        }
        match &self.script {
            Some(s) => s.get(&(purpose, key)).copied().unwrap_or(0),
            None => {
                let v = draw(SplitMix64::mix(self.seed, &[purpose, key]));
                if v != 0 {
                    self.fired.insert((purpose, key), v);
                }
                v
            }
        }
    }

    /// A deterministic value for (`purpose`, `parts`) that is not a fault.
    fn value(&self, purpose: u64, parts: &[u64]) -> u64 {
        let mut all = alloc::vec![purpose];
        all.extend_from_slice(parts);
        SplitMix64::mix(self.seed, &all)
    }
}

/// The two nodes, the datagrams between them and what the oracles track.
pub(crate) struct World<P: Stub> {
    pub(crate) n: [Node<P>; 2],
    pub(crate) params: Params,
    pub(crate) now: u64,
    pub(crate) flight: Vec<Flight>,
    next: u64,
    pub(crate) t: Track,
    /// The run's event log, for replay and for a failure's report.
    pub(crate) log: Vec<String>,
    /// The first oracle failure.
    pub(crate) failure: Option<String>,
    /// Whether events are logged; the explorer turns it off and replays a
    /// failing path with it on.
    pub(crate) logging: bool,
    /// The O2 bound, ms; `None` checks nothing.
    pub(crate) bound: Option<u64>,
    /// The fault channel; `None` for the explorer, which chooses every
    /// delivery itself.
    pub(crate) chan: Option<Chan>,
    workers: [BTreeMap<u32, Reg>; 2],
    legs: [Vec<Leg>; 2],
    addrs: [crate::identity::NodeAddr; 2],
    keys: [PeerKey; 2],
    /// Genuine datagrams the adversary has seen, newest last.
    captured: Vec<Flight>,
    offers: u64,
    steps: u64,
    /// When the dialing node, torn down while opening, dials again.
    redial: Option<u64>,
    opening: bool,
    /// The first message of each node's latest own attempt.
    first: [Option<Wire>; 2],
    /// The latest delivery instant per receiver, for a FIFO channel.
    last_at: [u64; 2],
    /// The scripted rules that have withheld their one datagram.
    held: Vec<usize>,
}

impl<P: Stub> World<P> {
    /// Two established machines set up at 0; `swap` puts the larger
    /// address at index 0. `jitter` seeds both jitter sources, or leaves
    /// them drawing the middle of the band (equal draws, so both ends
    /// trigger in the same instant).
    pub(crate) fn pair(params: Params, swap: bool, jitter: Option<u64>) -> Self {
        let (a, b) = ordered(1, 2);
        let (a, b) = if swap { (b, a) } else { (a, b) };
        let mids = [0u64, 1].map(|i| Mid {
            queued: Vec::new(),
            seeded: jitter.map(|s| SplitMix64::new(SplitMix64::mix(s, &[i]))),
        });
        let (na, nb) = pair_jittered::<P>(a, b, 0, params, None, mids);
        let mut w = Self::with([na, nb], params);
        w.sample(0);
        w.sample(1);
        w
    }

    /// As [`World::pair`], each node's jitter draws taken from `queued`
    /// first and then from the middle of the band.
    pub(crate) fn pair_queued(params: Params, swap: bool, queued: [Vec<u16>; 2]) -> Self {
        let (a, b) = ordered(1, 2);
        let (a, b) = if swap { (b, a) } else { (a, b) };
        let mids = queued.map(|q| Mid {
            queued: q,
            seeded: None,
        });
        let (na, nb) = pair_jittered::<P>(a, b, 0, params, None, mids);
        let mut w = Self::with([na, nb], params);
        w.sample(0);
        w.sample(1);
        w
    }

    /// A first handshake: node 0 opens toward node 1, which has no machine
    /// until the first setup reaches it. `swap` puts the larger address at
    /// index 0.
    pub(crate) fn opening(params: Params, swap: bool, jitter: Option<u64>) -> Self {
        let (a, b) = ordered(1, 2);
        let (a, b) = if swap { (b, a) } else { (a, b) };
        let mut na = Node::<P>::new(a);
        let mut nb = Node::<P>::new(b);
        if let Some(s) = jitter {
            na.jitter.seeded = Some(SplitMix64::new(SplitMix64::mix(s, &[0])));
            nb.jitter.seeded = Some(SplitMix64::new(SplitMix64::mix(s, &[1])));
        }
        let mut w = Self::with([na, nb], params);
        w.opening = true;
        w.dial();
        w
    }

    /// The world around two shells.
    fn with(n: [Node<P>; 2], params: Params) -> Self {
        let addrs = [n[0].local.addr(), n[1].local.addr()];
        let keys = [n[0].local.key, n[1].local.key];
        let t = Track {
            leak0: leaked(),
            ..Track::default()
        };
        Self {
            n,
            params,
            now: 0,
            flight: Vec::new(),
            next: 0,
            t,
            log: Vec::new(),
            failure: None,
            logging: true,
            bound: None,
            chan: None,
            workers: [BTreeMap::new(), BTreeMap::new()],
            legs: [Vec::new(), Vec::new()],
            addrs,
            keys,
            captured: Vec::new(),
            offers: 0,
            steps: 0,
            redial: None,
            opening: false,
            first: [None, None],
            last_at: [0, 0],
            held: Vec::new(),
        }
    }

    /// Record the first failure of an oracle.
    pub(crate) fn fail(&mut self, msg: String) {
        if self.failure.is_none() {
            self.log.push(format!("{:>9} FAIL {msg}", self.now));
            self.failure = Some(format!("at {} ms: {msg}", self.now));
        }
    }

    /// Add a line to the log.
    fn note(&mut self, what: String) {
        self.log.push(format!("{:>9} {what}", self.now));
    }

    // ---- driving the nodes ----

    /// Node 0 dials node 1 afresh.
    fn dial(&mut self) {
        let peer = self.keys[1];
        let now = self.now;
        let evs = self.n[0].open_out(now, peer, self.params);
        note!(self, "n0 opens: {evs:?}");
        self.after(0, &evs, true);
    }

    /// Poll node `x`.
    pub(crate) fn poll(&mut self, x: usize) {
        if self.n[x].m.is_none() {
            return;
        }
        let now = self.now;
        let evs = self.n[x].poll(now);
        if !evs.is_empty() {
            note!(self, "n{x} poll: {evs:?}");
        }
        self.after(x, &evs, true);
        if let Some(w) = self.n[x].wake
            && self.n[x].m.is_some()
            && w <= now
        {
            self.fail(format!(
                "O4: n{x}'s next wake {w} is not after the poll at {now}"
            ));
        }
        let budget = self.params.budget.as_millis() as u64;
        if let Some(m) = &self.n[x].m
            && m.view().cycle == CycleView::Init
            && let Some(&s) = self.t.starts[x].last()
            && now >= s + budget
        {
            self.fail(format!(
                "O4: n{x}'s attempt started at {s} outlived its deadline at {} in the poll at {now}",
                s + budget
            ));
        }
    }

    /// Node `x` seals one data frame, if it can.
    pub(crate) fn data(&mut self, x: usize) {
        let now = self.now;
        let Some(m) = self.n[x].m.as_mut() else {
            return;
        };
        if m.view().current.is_none() {
            return;
        }
        let kid_now = m.peek().current.map(|c| kid(c.session));
        let Ok(sealed) = m.seal(TestInstant(now)) else {
            return;
        };
        self.n[x].rewake();
        let ev = self.t.evidence[x].get(&sealed.tag).copied();
        let checked = matches!(ev, Some(EvidenceKind::Proof | EvidenceKind::Frame));
        if checked
            && let Some(k) = kid_now
            && !self.t.held[1 - x].contains(&k)
        {
            self.fail(format!(
                "Sealing: n{x} seals data under {:?} ({ev:?}), which its peer never held",
                sealed.tag
            ));
        }
        let f = frame(&sealed, DATA);
        self.enqueue(x, Msg::Frame(f, sealed.tag), Origin::Data);
        if let Some(only) = P::fsp() {
            let evs = self.n[x].step(now, Input::DataSent { only });
            self.after(x, &evs, false);
        }
    }

    /// Take the datagram `id` out of flight and deliver it.
    pub(crate) fn deliver(&mut self, id: u64) {
        let Some(i) = self.flight.iter().position(|f| f.id == id) else {
            return;
        };
        let f = self.flight.remove(i);
        self.take(f);
    }

    /// Drop the datagram `id`.
    pub(crate) fn lose(&mut self, id: u64) {
        self.flight.retain(|f| f.id != id);
    }

    /// Put a copy of datagram `id` in flight, arriving at `at`.
    pub(crate) fn copy(&mut self, id: u64, at: u64) {
        if let Some(f) = self.flight.iter().find(|f| f.id == id).cloned() {
            let root = f.root();
            self.push(f.to, f.msg, Origin::Copy(root), at, f.sent, f.carrier);
        }
    }

    /// Inject `msg` toward `to` now, as the adversary.
    pub(crate) fn inject(&mut self, to: usize, msg: Msg, origin: Origin, carrier: u8) {
        let now = self.now;
        let id = self.push(to, msg, origin, now, now, carrier);
        self.deliver(id);
    }

    /// Add a datagram to the flight list; returns its id.
    fn push(
        &mut self,
        to: usize,
        msg: Msg,
        origin: Origin,
        at: u64,
        sent: u64,
        carrier: u8,
    ) -> u64 {
        let id = self.next;
        self.next += 1;
        self.flight.push(Flight {
            id,
            to,
            at,
            sent,
            msg,
            origin,
            carrier,
        });
        id
    }

    /// A node sent `msg`: decide its fate on the channel and put it in
    /// flight (the explorer's world puts every datagram in flight as is).
    fn enqueue(&mut self, from: usize, msg: Msg, origin: Origin) {
        let to = 1 - from;
        let now = self.now;
        let class = self.class(from, &msg, origin);
        let Some(chan) = self.chan.as_mut() else {
            let id = self.push(to, msg, origin, now, now, 1);
            self.capture(id);
            return;
        };
        let ord = chan.ord;
        chan.ord += 1;
        let cfg = chan.cfg.clone();
        for (i, rule) in cfg.rules.iter().enumerate() {
            if rule.from != from || rule.class != class || !(rule.since..rule.until).contains(&now)
            {
                continue;
            }
            match rule.fate {
                Fate::Drop => {
                    note!(self, "rule {i} drops n{from}'s {class:?}");
                    return;
                }
                Fate::HoldOnce(at) if !self.held.contains(&i) => {
                    self.held.push(i);
                    note!(self, "rule {i} withholds n{from}'s {class:?} until {at}");
                    let id = self.push(to, msg, origin, at, now, 1);
                    self.capture(id);
                    return;
                }
                Fate::HoldOnce(_) => {}
            }
        }
        let parted = cfg
            .partitions
            .iter()
            .any(|&(r, a, b)| r == to && (a..b).contains(&now));
        let lost =
            parted || chan.decide(now, why::LOSS, ord, |v| u64::from(v % 1000 < cfg.loss[to])) != 0;
        let base = cfg.lat[to] + chan.value(why::LAT, &[ord]) % cfg.spread[to].max(1);
        let tail = chan.decide(now, why::TAIL, ord, |v| {
            if v % 1000 < cfg.tail {
                base << (1 + (v >> 20) % 12)
            } else {
                0
            }
        });
        let held = if origin == Origin::Data {
            chan.decide(now, why::HOLD, ord, |v| {
                if v % 1000 < cfg.withhold {
                    10_000 + (v >> 16) % 50_000
                } else {
                    0
                }
            })
        } else {
            0
        };
        let dups = chan.decide(now, why::DUP, ord, |v| {
            if v % 1000 < cfg.dup[to] {
                1 + (v >> 24) % 3
            } else {
                0
            }
        });
        let copy_at: Vec<u64> = (0..dups)
            .map(|i| now + cfg.lat[to] + chan.value(why::COPY, &[ord, i]) % (4 * cfg.lat[to] + 1))
            .collect();
        if lost {
            note!(self, "lost n{from}->n{to} #{ord}");
            if dups == 0 {
                return;
            }
        }
        // A FIFO path keeps its ordinary datagrams in order; a datagram
        // given a tail or withheld is the reordering fault itself, and
        // holds nothing up behind it.
        let mut at = now + base + tail + held;
        if (cfg.fifo || now >= cfg.fault_end) && tail + held == 0 {
            at = at.max(self.last_at[to]);
            self.last_at[to] = at;
        }
        let id = self.push(to, msg.clone(), origin, at, now, 1);
        self.capture(id);
        if lost {
            self.flight.retain(|f| f.id != id);
        }
        for at in copy_at {
            self.push(to, msg.clone(), Origin::Copy(id), at, now, 1);
        }
    }

    /// The class of a datagram node `from` sends.
    fn class(&self, from: usize, msg: &Msg, origin: Origin) -> Class {
        match (msg, origin) {
            (Msg::Hs(k, _), _) => Class::Hs(*k),
            (Msg::Frame(..), Origin::Data) => Class::Data,
            (Msg::Frame(_, tag), Origin::Sent | Origin::Copy(_) | Origin::Forged) => {
                let cur = self.n[from]
                    .m
                    .as_ref()
                    .and_then(|m| m.view().current.map(|c| c.tag));
                if cur == Some(*tag) {
                    Class::Prompt
                } else {
                    Class::Probe
                }
            }
        }
    }

    /// Let the adversary see datagram `id`.
    fn capture(&mut self, id: u64) {
        if let Some(f) = self.flight.iter().find(|f| f.id == id).cloned() {
            self.captured.push(f);
            if self.captured.len() > 64 {
                self.captured.remove(0);
            }
        }
    }

    /// Deliver `f` to its node, with the O5 check around it.
    fn take(&mut self, f: Flight) {
        let x = f.to;
        let root = f.root();
        let is_frame = matches!(f.msg, Msg::Frame(..));
        let repeat = match f.origin {
            Origin::Copy(_) if is_frame => self.t.authed[x].contains(&root),
            Origin::Copy(_) => self.t.taken[x].contains(&root),
            Origin::Forged => true,
            Origin::Sent | Origin::Data => false,
        };
        let first = !self.t.taken[x].contains(&root);
        let ephemeral = match &f.msg {
            Msg::Hs(MsgKind::Msg1, b) => {
                super::stub::read_msg1(&self.n[x].local, b).map(|m| m.get().ephemeral())
            }
            Msg::Hs(..) | Msg::Frame(..) => None,
        };
        let watched = repeat || ephemeral.is_some();
        let forged = f.origin == Origin::Forged;
        let before = self.n[x].m.as_ref().filter(|_| watched).map(|m| {
            (
                m.digest_core(forged),
                m.view().last_rx,
                format!("{:?}", m.view().cycle),
            )
        });
        let evs = self.take_raw(&f);
        self.t.taken[x].insert(root);
        let authed = evs
            .iter()
            .any(|e| matches!(e, Ev::Deliver(..) | Ev::Reject(Reason::ShortPlaintext)));
        if is_frame && authed {
            self.t.authed[x].insert(root);
        }
        if f.origin == Origin::Data && first && self.now.saturating_sub(f.sent) <= FRESH {
            let delivered = evs.iter().any(|e| matches!(e, Ev::Deliver(..)));
            if self.n[x].m.is_some() {
                self.t.data[x].push((f.sent, delivered));
                self.outage(x);
            }
        }
        let Some((digest, last_rx, cycle)) = before else {
            return;
        };
        let Some(m) = self.n[x].m.as_ref() else {
            return;
        };
        let after_cycle = m.view().cycle;
        let refreshed = m.view().last_rx != last_rx;
        let changed = m.digest_core(forged) != digest;
        let msg1 = matches!(f.msg, Msg::Hs(MsgKind::Msg1, _));
        let copied = matches!(f.origin, Origin::Copy(_));
        let armed = after_cycle == CycleView::PendR && cycle != "PendR";
        if let Some(e) = ephemeral {
            if armed && self.t.owed[x].contains(&e) {
                self.fail(format!(
                    "O5: {:?} of #{root} at n{x} armed a pending from a msg1 its record holds: {evs:?}",
                    f.origin
                ));
                return;
            }
            self.owe(x, e, armed, &evs);
        }
        if msg1 && copied && armed {
            let how = if self.t.rewrites.contains(&f.id) {
                "rewritten"
            } else {
                "replayed"
            };
            let name = format!("{how} msg1 answered in {cycle}");
            self.t.residuals.push(name.clone());
            note!(self, "residual: {name}");
            let bad = evs.iter().find(|e| {
                matches!(
                    e,
                    Ev::Installed(..) | Ev::Retired(..) | Ev::Rekeyed(..) | Ev::Reverted(..)
                )
            });
            if let Some(e) = bad {
                self.fail(format!("O10: a residual replay at n{x} emitted {e:?}"));
            }
            if refreshed {
                self.fail(format!("O10: a residual replay at n{x} refreshed liveness"));
            }
            return;
        }
        if repeat && changed {
            self.fail(format!(
                "O5: {:?} of #{root} at n{x} changed the state: {evs:?}",
                f.origin
            ));
        }
    }

    /// Add the ephemeral `e` of a msg1 node `x` just took to the list its
    /// record must hold, when the take armed a pending (whose exit records
    /// it) or drew a refusal or replacement that records it. A refusal for
    /// a copy already on the list records nothing new.
    fn owe(&mut self, x: usize, e: Digest, armed: bool, evs: &[Ev<P::Transport>]) {
        let recorded = armed
            || evs.iter().any(|ev| {
                matches!(
                    ev,
                    Ev::Replace
                        | Ev::Reject(Reason::OffLink | Reason::PendingHeld | Reason::DualInitWon)
                )
            });
        let owed = &mut self.t.owed[x];
        if recorded && !owed.contains(&e) {
            owed.push(e);
            if owed.len() > RECORD_BOUND {
                owed.remove(0);
            }
        }
    }

    /// Hand `f` to node `x`'s shell: the leg table, the worker, a new
    /// first-handshake machine, or the machine.
    fn take_raw(&mut self, f: &Flight) -> Vec<Ev<P::Transport>> {
        let x = f.to;
        let now = self.now;
        if P::MESSAGES == 3
            && P::fsp().is_none()
            && let Msg::Hs(kind @ (MsgKind::Setup | MsgKind::Msg3), b) = &f.msg
        {
            return self.leg_table(x, *kind, b);
        }
        if self.n[x].m.is_none() {
            if let (Msg::Hs(MsgKind::Setup, _), true) = (&f.msg, P::fsp().is_some()) {
                let claimed = self.addrs[1 - x];
                let evs = self.n[x].open_in(now, claimed, &f.msg, self.params);
                note!(self, "n{x} opens inbound: {evs:?}");
                self.after(x, &evs, false);
                return evs;
            }
            note!(self, "n{x} has no session for #{}", f.id);
            return Vec::new();
        }
        if let Msg::Frame(b, _) = &f.msg
            && let Some(evs) = self.worker_frame(x, b)
        {
            return evs;
        }
        let evs = match (&f.msg, f.origin, P::fsp()) {
            (Msg::Hs(MsgKind::Setup, b), Origin::Forged, Some(_)) if f.carrier != 1 => {
                self.n[x].setup_on(now, P::carrier(f.carrier), b)
            }
            _ => self.n[x].recv(now, &f.msg),
        };
        let quiet = f.origin == Origin::Data && matches!(evs.as_slice(), [Ev::Deliver(..)]);
        if !quiet {
            note!(self, "n{x} takes #{} {:?}: {evs:?}", f.id, f.origin);
        }
        self.after(x, &evs, false);
        evs
    }

    /// The next-only leg table at node `x`: answer a msg1 into a leg, or
    /// complete a leg on its msg3 and hand the completion to the machine.
    fn leg_table(&mut self, x: usize, kind: MsgKind, b: &[u8]) -> Vec<Ev<P::Transport>> {
        let now = self.now;
        if self.n[x].m.is_none() {
            return Vec::new();
        }
        match kind {
            MsgKind::Setup => {
                if let Some(l) = self.legs[x].iter().find(|l| l.msg1 == b) {
                    let m2 = l.msg2.clone();
                    self.enqueue(x, Msg::Hs(MsgKind::Msg2, m2), Origin::Sent);
                    return Vec::new();
                }
                let Some(lease) = allocate(&mut self.n[x].indices) else {
                    return Vec::new();
                };
                let Some((hs, m2)) = P::leg(&self.n[x].local, b, lease.index()) else {
                    let i = lease.release();
                    P::free(&mut self.n[x].indices, i);
                    return Vec::new();
                };
                self.legs[x].push(Leg {
                    hs,
                    lease: Some(lease),
                    msg1: b.to_vec(),
                    msg2: m2.clone(),
                    until: now + self.params.config().handshake.as_millis() as u64,
                });
                note!(self, "n{x} leg table answers");
                self.enqueue(x, Msg::Hs(MsgKind::Msg2, m2), Origin::Sent);
                Vec::new()
            }
            MsgKind::Msg3 => {
                let Some(i) = self.legs[x]
                    .iter()
                    .position(|l| P::done(&l.hs, b, None).is_some())
                else {
                    return Vec::new();
                };
                let leg = self.legs[x].remove(i);
                let Some(tok) = P::done(&leg.hs, b, leg.lease) else {
                    return Vec::new();
                };
                let evs = self.n[x].step(
                    now,
                    Input::PeerDone {
                        tok,
                        intent: Intent::Rekey,
                    },
                );
                note!(self, "n{x} leg completes: {evs:?}");
                self.after(x, &evs, false);
                evs
            }
            MsgKind::Msg1 | MsgKind::Msg2 | MsgKind::Ack => Vec::new(),
        }
    }

    /// Expire the leg table's legs past their deadline.
    fn expire_legs(&mut self, x: usize) {
        let now = self.now;
        let (done, keep): (Vec<Leg>, Vec<Leg>) = core::mem::take(&mut self.legs[x])
            .into_iter()
            .partition(|l| l.until <= now);
        self.legs[x] = keep;
        for l in done {
            if let Some(lease) = l.lease {
                let i = lease.release();
                P::free(&mut self.n[x].indices, i);
            }
        }
    }

    /// A frame whose index a worker holds goes to the worker, which opens
    /// it and reports it to the machine.
    fn worker_frame(&mut self, x: usize, b: &[u8]) -> Option<Vec<Ev<P::Transport>>> {
        let only = P::fmp()?;
        if b.len() < super::stub::HEADER {
            return None;
        }
        let h = hint(b);
        let reg = self.workers[x].get_mut(&h.index)?;
        let opened = worker_open(&reg.recv, b);
        let fresh = reg.recv.floor.is_none_or(|f| h.counter > f)
            && reg.recv.highest.is_none_or(|hi| h.counter > hi)
            && !reg.seen.contains(&h.counter);
        let tag = reg.tag;
        let Some((h, _plain)) = opened.filter(|_| fresh) else {
            note!(self, "n{x} worker refuses a frame");
            return Some(Vec::new());
        };
        reg.seen.insert(h.counter);
        let now = self.now;
        let mut evs = self.n[x].step(
            now,
            Input::WorkerFrame {
                tag,
                k: h.k,
                counter: h.counter,
                only,
            },
        );
        note!(self, "n{x} worker delivers: {evs:?}");
        self.after(x, &evs, false);
        evs.push(Ev::Deliver(
            crate::proto::rekey::Slot::Current,
            tag,
            DATA.to_vec(),
        ));
        Some(evs)
    }

    /// The worker at node `x` is lost: report every epoch it held.
    pub(crate) fn lose_worker(&mut self, x: usize) {
        let Some(only) = P::fmp() else {
            return;
        };
        let now = self.now;
        let indices: Vec<u32> = self.workers[x].keys().copied().collect();
        for index in indices {
            let Some(reg) = self.workers[x].remove(&index) else {
                continue;
            };
            if self.n[x].m.is_none() {
                continue;
            }
            let evs = self.n[x].step(now, Input::Undelegated { tag: reg.tag, only });
            note!(self, "n{x} worker lost {:?}: {evs:?}", reg.tag);
            self.after(x, &evs, false);
        }
    }

    // ---- after every step ----

    /// Execute what the step left for the shell and check the per-step
    /// oracles. `polled` is true when the step was a poll.
    fn after(&mut self, x: usize, evs: &[Ev<P::Transport>], polled: bool) {
        self.steps += 1;
        if self.steps > STEPS {
            self.fail(String::from("the run exceeded its step cap"));
        }
        let now = self.now;
        for m in self.n[x].sent() {
            self.enqueue(x, m, Origin::Sent);
        }
        for e in evs {
            match e {
                Ev::Installed(tag, _, ev) => {
                    self.t.evidence[x].insert(*tag, *ev);
                    if *ev == EvidenceKind::Assumed {
                        self.t.assumed += 1;
                    }
                    if *ev != EvidenceKind::First {
                        self.t.installs[x].push(now);
                    }
                }
                Ev::Reverted(_) => self.t.reverts += 1,
                Ev::Reject(r) => self.t.outcomes.push((now, x, format!("{r:?}"))),
                Ev::Abandoned(a) => self.t.outcomes.push((now, x, format!("{a:?}"))),
                Ev::Revoke(tag, _, index) => {
                    if self.workers[x].get(index).is_some_and(|r| r.tag == *tag) {
                        self.workers[x].remove(index);
                    }
                }
                Ev::Send(MsgKind::Msg1 | MsgKind::Setup, b, _) => {
                    if self.first[x].as_ref() != Some(b) {
                        self.first[x] = Some(b.clone());
                        self.t.starts[x].push(now);
                    }
                }
                Ev::Send(..)
                | Ev::Prompt(_)
                | Ev::Deliver(..)
                | Ev::Bind(..)
                | Ev::Unbind(..)
                | Ev::Delegate(..)
                | Ev::Release(_)
                | Ev::Retired(_)
                | Ev::Restarted(..)
                | Ev::Rekeyed(_)
                | Ev::Replace
                | Ev::Teardown(_) => {}
            }
        }
        self.offer(x);
        if evs.iter().any(|e| matches!(e, Ev::Teardown(_))) {
            self.teardown(x);
            return;
        }
        self.sample(x);
        self.check(x, polled);
    }

    /// Hand the shell's worker offers to the worker model, which accepts
    /// or refuses each.
    fn offer(&mut self, x: usize) {
        let offers = core::mem::take(&mut self.n[x].offers);
        let Some(only) = P::fmp() else {
            return;
        };
        for (tag, index, recv) in offers {
            let ord = self.offers;
            self.offers += 1;
            let now = self.now;
            let refuse = match self.chan.as_mut() {
                Some(c) => {
                    let p = c.cfg.refuse;
                    c.decide(now, why::REFUSE, ord, |v| u64::from(v % 1000 < p)) != 0
                }
                None => false,
            };
            if refuse || self.n[x].m.is_none() {
                continue;
            }
            self.workers[x].insert(
                index,
                Reg {
                    tag,
                    recv,
                    seen: BTreeSet::new(),
                },
            );
            let evs = self.n[x].step(now, Input::Delegated { tag, only });
            note!(self, "n{x} worker accepts {tag:?}: {evs:?}");
            self.after(x, &evs, false);
        }
    }

    /// The machine at `x` asked to be torn down: close it as the shell
    /// does.
    fn teardown(&mut self, x: usize) {
        let now = self.now;
        if self.n[x].m.is_none() {
            return;
        }
        self.t.teardowns[x] += 1;
        self.t.owed[x].clear();
        let (evs, _) = self.n[x].close(now, Close::OpeningTeardown);
        note!(self, "n{x} torn down: {evs:?}");
        for m in self.n[x].sent() {
            self.enqueue(x, m, Origin::Sent);
        }
        self.workers[x].clear();
        if x == 0 && self.opening {
            self.redial = Some(now + 1_000);
        }
    }

    /// Remember every key node `x` holds now.
    fn sample(&mut self, x: usize) {
        if let Some(m) = &self.n[x].m {
            let p = m.peek();
            for e in [&p.current, &p.previous, &p.pending].into_iter().flatten() {
                self.t.held[x].insert(kid(e.session));
            }
        }
    }

    /// The per-step oracles at node `x`.
    fn check(&mut self, x: usize, polled: bool) {
        let now = self.now;
        let Some(m) = &self.n[x].m else {
            return;
        };
        let v = m.view();
        let p = m.peek();
        let mut errs: Vec<String> = Vec::new();
        // O3: the shell's indices are the machine's and the leg table's.
        let bound = m.bindings().len() + self.legs[x].iter().filter(|l| l.lease.is_some()).count();
        if P::held(&self.n[x].indices) != bound {
            errs.push(format!(
                "O3: n{x} holds {} indices, its machine and legs {bound}",
                P::held(&self.n[x].indices)
            ));
        }
        if leaked() != self.t.leak0 {
            errs.push(format!("O3: {} leases leaked", leaked() - self.t.leak0));
        }
        // O6: bounded memory.
        if p.record > RECORD_BOUND + 1 {
            errs.push(format!("O6: n{x}'s record holds {}", p.record));
        }
        // O8: no previous epoch past the ceiling (after a poll).
        if let (Some(end), Some(cur)) = (p.drain_end, &p.current) {
            let ceiling = cur.started.0 + self.params.config().retention.as_millis() as u64;
            if end.0 > ceiling || (polled && now >= end.0) {
                errs.push(format!(
                    "O8: n{x} keeps a previous epoch to {} past its ceiling {ceiling}",
                    end.0
                ));
            }
        }
        // O9: the worker holds exactly the delegated epochs.
        let delegated: BTreeSet<EpochTag> = [&v.current, &v.previous]
            .into_iter()
            .flatten()
            .filter(|e| e.recv == RecvHome::Delegated)
            .map(|e| e.tag)
            .collect();
        let registered: BTreeSet<EpochTag> = self.workers[x].values().map(|r| r.tag).collect();
        if delegated != registered {
            errs.push(format!(
                "O9: n{x}'s worker holds {registered:?}, the machine delegated {delegated:?}"
            ));
        }
        // O11: no orphan machine.
        if v.current.is_none() {
            if v.cycle == CycleView::Idle && v.candidates == 0 {
                errs.push(format!("O11: n{x} opens with no attempt and no candidate"));
            }
            if m.next_wake().is_none() {
                errs.push(format!("O11: n{x} opens with no next wake"));
            }
        }
        for e in errs {
            self.fail(e);
        }
    }

    /// O2 at receiver `x` as frames arrive: with a zero bound, any data
    /// frame lost to keys fails at once; other bounds are judged at the end
    /// of the run, when every frame's fate is known.
    fn outage(&mut self, x: usize) {
        if self.bound == Some(0) && self.t.data[x].last().is_some_and(|&(_, ok)| !ok) {
            let sent = self.t.data[x].last().map_or(0, |&(s, _)| s);
            self.fail(format!(
                "O2: n{} to n{x} lost a data frame sent at {sent} (bound 0 ms)",
                1 - x
            ));
        }
    }

    /// O2 at the end of a run: the longest stretch, by send instant, of
    /// data frames each direction lost to keys stays within the bound.
    pub(crate) fn outages(&mut self) {
        let Some(bound) = self.bound else {
            return;
        };
        for x in 0..2 {
            let mut data = self.t.data[x].clone();
            data.sort_unstable();
            let mut start: Option<u64> = None;
            let mut worst = (0u64, 0u64);
            for (sent, ok) in data {
                if ok {
                    start = None;
                    continue;
                }
                let s = *start.get_or_insert(sent);
                if sent - s >= worst.1 - worst.0 {
                    worst = (s, sent);
                }
            }
            if worst.1 - worst.0 > bound {
                self.fail(format!(
                    "O2: n{} to n{x} lost every data frame sent from {} to {} (bound {bound} ms)",
                    1 - x,
                    worst.0,
                    worst.1
                ));
            }
        }
    }

    /// O1: both ends hold the same current epoch and nothing else is in
    /// progress.
    pub(crate) fn converged(&self) -> Result<(), String> {
        let (Some(a), Some(b)) = (&self.n[0].m, &self.n[1].m) else {
            return Err(String::from("O1: a node has no session"));
        };
        let (pa, pb) = (a.peek(), b.peek());
        let (Some(ca), Some(cb)) = (&pa.current, &pb.current) else {
            return Err(String::from("O1: a node is not established"));
        };
        if kid(ca.session) != kid(cb.session) {
            return Err(String::from("O1: the ends hold different current epochs"));
        }
        if a.view().cycle != CycleView::Idle || b.view().cycle != CycleView::Idle {
            return Err(format!(
                "O1: cycles {:?} and {:?}",
                a.view().cycle,
                b.view().cycle
            ));
        }
        if pa
            .candidates
            .iter()
            .chain(&pb.candidates)
            .any(|d| d.0 <= self.now)
        {
            return Err(String::from("O1: an expired candidate is held"));
        }
        if P::INDEXED && (ca.theirs != cb.ours || cb.theirs != ca.ours) {
            return Err(String::from("O1: the index pairs disagree"));
        }
        Ok(())
    }

    /// The earliest instant either node's timer shell polls.
    pub(crate) fn wake(&self) -> Option<u64> {
        let a = self.n[0].m.as_ref().and(self.n[0].wake);
        let b = self.n[1].m.as_ref().and(self.n[1].wake);
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// A key that tells two explored states apart: both machines, the
    /// datagrams in flight, the worker and leg tables, and the clock,
    /// formatted straight into a hasher.
    pub(crate) fn key(&self) -> u64 {
        use core::fmt::Write as _;
        use core::hash::Hasher as _;
        /// A `fmt::Write` that feeds a hasher.
        struct Feed(std::hash::DefaultHasher);
        impl core::fmt::Write for Feed {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                self.0.write(s.as_bytes());
                Ok(())
            }
        }
        let mut fl: Vec<(usize, &Msg, Origin, u8)> = self
            .flight
            .iter()
            .map(|f| (f.to, &f.msg, f.origin, f.carrier))
            .collect();
        fl.sort_by(|a, b| {
            (a.0, bytes(a.1), format!("{:?}", a.2), a.3).cmp(&(
                b.0,
                bytes(b.1),
                format!("{:?}", b.2),
                b.3,
            ))
        });
        let mut h = Feed(std::hash::DefaultHasher::new());
        for n in &self.n {
            let _ = match &n.m {
                Some(m) => m.state(&mut h),
                None => h.write_str("none"),
            };
        }
        let _ = write!(
            h,
            "{}|{:?}|{:?}|{:?}|{}|{}",
            self.now,
            fl,
            self.workers[0].keys().collect::<Vec<_>>(),
            self.workers[1].keys().collect::<Vec<_>>(),
            self.legs[0].len(),
            self.legs[1].len(),
        );
        h.0.finish()
    }
}

// ---- the random runs ----

/// Run `w` on its channel until `end`.
pub(crate) fn run_until<P: Stub>(w: &mut World<P>, end: u64) {
    let mut data_at = [0u64; 2];
    let gaps = w.chan.as_ref().map_or([0, 0], |c| c.cfg.gap);
    for x in 0..2 {
        if gaps[x] > 0 {
            data_at[x] = w.now + gaps[x] / 2 + x as u64 * 7;
        }
    }
    let mut adv_k = w.now / 1_000 + 1;
    let mut adv_at = adv_k * 1_000;
    let cfg = w.chan.as_ref().expect("a run has a channel").cfg.clone();
    let mut stalled = 0u32;
    while w.failure.is_none() {
        // The instant node `x`, suspended at `t`, resumes: the end of the
        // chain of overlapping suspensions that holds `t`.
        let susp = |x: usize, t: u64| {
            let mut end = None;
            let mut at = t;
            while let Some(&(_, _, b)) = cfg
                .suspends
                .iter()
                .find(|&&(n, a, b)| n == x && (a..b).contains(&at))
            {
                end = Some(b);
                at = b;
            }
            end
        };
        let mut t = u64::MAX;
        for f in &w.flight {
            let at = susp(f.to, f.at).map_or(f.at, |b| b.max(f.at));
            t = t.min(at.max(w.now));
        }
        for x in 0..2 {
            if w.n[x].m.is_none() {
                continue;
            }
            if cfg.tick {
                t = t.min((w.now / 1_000 + 1) * 1_000);
            } else if let Some(wk) = w.n[x].wake {
                let wk = wk.max(w.now);
                t = t.min(susp(x, wk).unwrap_or(wk));
            }
            if gaps[x] > 0 {
                let d = data_at[x].max(w.now);
                t = t.min(susp(x, d).unwrap_or(d));
            }
        }
        for &(_, a, b) in &cfg.suspends {
            for e in [a, b] {
                if e > w.now {
                    t = t.min(e);
                }
            }
        }
        for &(_, at) in &cfg.losses {
            if at > w.now {
                t = t.min(at);
            }
        }
        if cfg.adversary > 0 && w.now < cfg.fault_end {
            t = t.min(adv_at);
        }
        if let Some(r) = w.redial {
            t = t.min(r);
        }
        if cfg.tick {
            t = t.min((w.now / 1_000 + 1) * 1_000);
        }
        if t > end {
            w.now = end;
            break;
        }
        let advanced = t > w.now;
        stalled = if advanced { 0 } else { stalled + 1 };
        if stalled > 10_000 {
            w.fail(format!("the scheduler stalled at {t}"));
            break;
        }
        w.now = t;
        // Deliveries due now, oldest first.
        let mut due: Vec<(u64, u64)> = w
            .flight
            .iter()
            .filter(|f| f.at <= t && susp(f.to, t).is_none())
            .map(|f| (f.at, f.id))
            .collect();
        due.sort_unstable();
        for (_, id) in due {
            w.deliver(id);
        }
        for x in 0..2 {
            if susp(x, t).is_some() {
                continue;
            }
            w.expire_legs(x);
            let wake_due = w.n[x].wake.is_some_and(|wk| wk <= t);
            let tick_due = cfg.tick && advanced && t % 1_000 == 0;
            let resumed = cfg.suspends.iter().any(|&(n, _, b)| n == x && b == t);
            if (!cfg.tick && wake_due) || tick_due || resumed {
                w.poll(x);
            }
            if gaps[x] > 0 && data_at[x] <= t {
                w.data(x);
                let jit = w
                    .chan
                    .as_ref()
                    .map_or(0, |c| c.value(why::DATA, &[x as u64, t]));
                data_at[x] = t + gaps[x] / 2 + jit % gaps[x].max(1);
            }
        }
        for &(x, at) in &cfg.losses {
            if at == t && t < cfg.fault_end {
                w.lose_worker(x);
            }
        }
        if cfg.adversary > 0 && t >= adv_at && t < cfg.fault_end {
            adversary(w, adv_k);
            adv_k += cfg.adversary / 1_000 + 1;
            adv_at = adv_k * 1_000;
        }
        if w.redial.is_some_and(|r| r <= t) {
            w.redial = None;
            if w.n[0].m.is_none() {
                w.dial();
            }
        }
    }
}

/// The adversary's action for slot `k`, if it acts in it.
fn adversary<P: Stub>(w: &mut World<P>, k: u64) {
    let now = w.now;
    let chan = w.chan.as_mut().expect("a channel");
    let v = chan.decide(now, why::ADV, k, |v| v | 1);
    if v == 0 || w.captured.is_empty() {
        return;
    }
    let pick = w.captured[((v >> 8) % w.captured.len() as u64) as usize].clone();
    let action = (v >> 40) % 6;
    let to = pick.to;
    let msg = match action {
        // Garbage of the right length for the kind.
        0 => {
            let mut b = super::stub::bytes(&pick.msg);
            let keep = match pick.msg {
                Msg::Frame(..) => super::stub::HEADER,
                Msg::Hs(..) => 1,
            };
            for (i, byte) in b.iter_mut().enumerate().skip(keep) {
                *byte = SplitMix64::mix(v, &[i as u64]) as u8;
            }
            relabel(&pick.msg, b)
        }
        // A bit-flipped genuine message. A flip the receiver's msg1 read
        // still authenticates landed in the sender index, which no MAC
        // covers: that is a copy of the genuine msg1 under a rewritten
        // header, judged as a replay rather than a forgery.
        1 => {
            let mut b = super::stub::bytes(&pick.msg);
            let i = 1 + ((v >> 16) as usize % (b.len() - 1));
            b[i] ^= 1 << ((v >> 4) % 8);
            if rewritable(w, &pick) && super::stub::read_msg1(&w.n[to].local, &b).is_some() {
                rewrite(w, &pick, b);
                return;
            }
            relabel(&pick.msg, b)
        }
        // A replay of the captured datagram; every other replay of an IK
        // msg1 also rewrites its sender index.
        2 | 3 => {
            if action == 3 && rewritable(w, &pick) {
                let mut b = super::stub::bytes(&pick.msg);
                b[1..5].copy_from_slice(&((v >> 12) as u32 | 1).to_le_bytes());
                rewrite(w, &pick, b);
                return;
            }
            note!(w, "adversary replays #{} to n{to}", pick.id);
            w.inject(to, pick.msg.clone(), Origin::Copy(pick.root()), 1);
            return;
        }
        // A msg3 under a third identity, or a third party's setup.
        _ if P::fsp().is_some() => {
            let third = Local::new(99, 99);
            if action == 4 {
                let setups: Vec<&Flight> = w
                    .captured
                    .iter()
                    .filter(|f| matches!(f.msg, Msg::Hs(MsgKind::Setup, _)))
                    .collect();
                let acks: Vec<&Flight> = w
                    .captured
                    .iter()
                    .filter(|f| matches!(f.msg, Msg::Hs(MsgKind::Ack, _)))
                    .collect();
                let (Some(s), Some(a)) = (setups.last(), acks.last()) else {
                    return;
                };
                let (ei, er) = super::stub::ephemerals(
                    &super::stub::bytes(&s.msg),
                    &super::stub::bytes(&a.msg),
                );
                let m3 = super::stub::forge3(&third, ei, er);
                let to = s.to;
                note!(w, "adversary sends a third identity's msg3 to n{to}");
                w.inject(to, Msg::Hs(MsgKind::Msg3, m3), Origin::Forged, 1);
            } else {
                let mut m = alloc::vec![1u8];
                m.extend_from_slice(&v.to_le_bytes());
                let carrier = 2 + ((v >> 12) % 2) as u8;
                let to = ((v >> 3) % 2) as usize;
                note!(
                    w,
                    "adversary sends a third party's setup to n{to} on {carrier}"
                );
                w.inject(to, Msg::Hs(MsgKind::Setup, m), Origin::Forged, carrier);
            }
            return;
        }
        _ => return,
    };
    note!(w, "adversary forges toward n{to}");
    w.inject(to, msg, Origin::Forged, 1);
}

/// Whether `pick` is an IK msg1 its receiver's msg1 read authenticates,
/// so the adversary can rewrite its sender index unnoticed.
fn rewritable<P: Stub>(w: &World<P>, pick: &Flight) -> bool {
    matches!(pick.msg, Msg::Hs(MsgKind::Msg1, _))
        && super::stub::read_msg1(&w.n[pick.to].local, &bytes(&pick.msg)).is_some()
}

/// Deliver `b`, the msg1 `pick` with its sender index rewritten, as a copy
/// of `pick`.
fn rewrite<P: Stub>(w: &mut World<P>, pick: &Flight, b: Wire) {
    let to = pick.to;
    note!(
        w,
        "adversary rewrites the sender index of #{} to n{to}",
        pick.id
    );
    w.t.rewrites.insert(w.next);
    w.inject(to, Msg::Hs(MsgKind::Msg1, b), Origin::Copy(pick.root()), 1);
}

/// `bytes` labelled as the same kind of message as `like`.
fn relabel(like: &Msg, bytes: Wire) -> Msg {
    match like {
        Msg::Hs(k, _) => Msg::Hs(*k, bytes),
        Msg::Frame(_, t) => Msg::Frame(bytes, *t),
    }
}

/// How a run ended.
#[derive(Debug)]
pub(crate) struct Report {
    pub(crate) failure: Option<String>,
    pub(crate) log: Vec<String>,
    pub(crate) track: Track,
    pub(crate) fired: BTreeMap<(u64, u64), u64>,
}

/// The heal period after faults stop: the liveness bound, a handshake plus
/// a rotation plus a pending hold.
pub(crate) fn heal(params: &Params) -> u64 {
    let c = params.config();
    (c.handshake + c.after + c.hold).as_millis() as u64 + u64::from(c.jitter) * 1_000
}

/// A world of profile `P` for a run: established (or opening), with the
/// larger address at index 0 when `swap`.
pub(crate) fn world<P: Stub>(
    params: Params,
    opening: bool,
    swap: bool,
    jitter: Option<u64>,
) -> World<P> {
    if opening {
        World::opening(params, swap, jitter)
    } else {
        World::pair(params, swap, jitter)
    }
}

/// One run: faults until `cfg.fault_end`, the heal period, then until both
/// ends are idle; O1 at the end. `script` replays recorded decisions.
pub(crate) fn run<P: Stub>(
    seed: u64,
    cfg: Cfg,
    opening: bool,
    bound: Option<u64>,
    script: Option<BTreeMap<(u64, u64), u64>>,
) -> Report {
    let params = params::<P>();
    let swap = SplitMix64::mix(seed, &[0xab]) % 2 == 1;
    let jitter = Some(SplitMix64::mix(seed, &[0xcd]));
    let fault_end = cfg.fault_end;
    let workers = cfg.workers;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut w = world::<P>(params, opening, swap, jitter);
        w.n[0].workers = workers;
        w.n[1].workers = workers;
        let mut chan = Chan::new(seed, cfg);
        chan.script = script;
        w.chan = Some(chan);
        w.bound = bound;
        run_until(&mut w, fault_end + heal(&params));
        let extra = w.now + heal(&params);
        while w.failure.is_none() && w.now < extra {
            if w.converged().is_ok() {
                break;
            }
            let next = w.now + 500;
            run_until(&mut w, next);
        }
        if w.failure.is_none()
            && let Err(e) = w.converged()
        {
            w.fail(e);
        }
        w.outages();
        for x in 0..2 {
            if let Some(m) = &w.n[x].m
                && m.view().current.is_none()
            {
                w.fail(format!("O11: n{x} is still opening once healed"));
            }
        }
        let fired = w.chan.as_ref().map(|c| c.fired.clone()).unwrap_or_default();
        Report {
            failure: w.failure.take(),
            log: core::mem::take(&mut w.log),
            track: core::mem::take(&mut w.t),
            fired,
        }
    }));
    result.unwrap_or_else(|e| {
        let msg = e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| String::from(*s)))
            .unwrap_or_default();
        Report {
            failure: Some(format!("panic: {msg}")),
            log: Vec::new(),
            track: Track::default(),
            fired: BTreeMap::new(),
        }
    })
}

/// Remove decisions from a failing run's script, then partitions,
/// suspensions and worker losses from its settings, while it still fails;
/// return the smallest failing script and settings found.
pub(crate) fn shrink<P: Stub>(
    seed: u64,
    cfg: &Cfg,
    opening: bool,
    bound: Option<u64>,
    fired: BTreeMap<(u64, u64), u64>,
) -> (BTreeMap<(u64, u64), u64>, Cfg) {
    let fails = |s: &BTreeMap<(u64, u64), u64>, c: &Cfg| {
        run::<P>(seed, c.clone(), opening, bound, Some(s.clone()))
            .failure
            .is_some()
    };
    let mut cur = fired;
    let mut cfg = cfg.clone();
    let mut chunk = cur.len().div_ceil(2).max(1);
    loop {
        let keys: Vec<(u64, u64)> = cur.keys().copied().collect();
        let mut removed = false;
        for part in keys.chunks(chunk) {
            let mut trial = cur.clone();
            for k in part {
                trial.remove(k);
            }
            if fails(&trial, &cfg) {
                cur = trial;
                removed = true;
            }
        }
        if !removed {
            if chunk == 1 {
                break;
            }
            chunk = chunk.div_ceil(2);
        }
    }
    for which in 0..3 {
        let mut i = 0;
        loop {
            let mut trial = cfg.clone();
            let len = match which {
                0 => trial.partitions.len(),
                1 => trial.suspends.len(),
                _ => trial.losses.len(),
            };
            if i >= len {
                break;
            }
            match which {
                0 => drop(trial.partitions.remove(i)),
                1 => drop(trial.suspends.remove(i)),
                _ => drop(trial.losses.remove(i)),
            }
            if fails(&cur, &trial) {
                cfg = trial;
            } else {
                i += 1;
            }
        }
    }
    (cur, cfg)
}

/// Run `seeds` faulty runs of `P` and panic with the first failure's seed,
/// minimal schedule and log; return the runs' residuals.
pub(crate) fn faulty_runs<P: Stub>(
    name: &str,
    seeds: core::ops::Range<u64>,
    opening: bool,
) -> Vec<String> {
    let mut residuals = Vec::new();
    for seed in seeds {
        let params = params::<P>();
        let end = 300_000;
        let cfg = Cfg::faulty(seed, end, P::INDEXED);
        let bound = Some(heal(&params));
        let r = run::<P>(seed, cfg.clone(), opening, bound, None);
        if let Some(f) = r.failure {
            if std::env::var_os("FIPS_SIM_NOSHRINK").is_some() {
                std::eprintln!("FULL LOG\n{}", r.log.join("\n"));
                panic!(
                    "{name} seed {seed}: {f}\n{cfg:?}\nlog tail:\n{}",
                    tail(&r.log)
                );
            }
            let (min, small) = shrink::<P>(seed, &cfg, opening, bound, r.fired);
            let again = run::<P>(seed, small.clone(), opening, bound, Some(min.clone()));
            panic!(
                "{name} seed {seed}: {f}\nminimal schedule {min:?} fails with {:?}\n{small:?}\nlog tail:\n{}",
                again.failure,
                tail(&again.log)
            );
        }
        residuals.extend(r.track.residuals);
    }
    residuals
}

/// The last lines of a run's log, for a failure's report.
pub(crate) fn tail(log: &[String]) -> String {
    let from = log.len().saturating_sub(300);
    log[from..].join("\n")
}

/// The fault phase of a random run, ms.
const FAULT_PHASE: u64 = 300_000;

/// Replay the faulty run of `P` drawn from `seed`.
pub(crate) fn replay<P: Stub>(seed: u64, opening: bool) -> Report {
    let cfg = Cfg::faulty(seed, FAULT_PHASE, P::INDEXED);
    run::<P>(seed, cfg, opening, Some(heal(&params::<P>())), None)
}

/// A clean run of `P` lasting about ten minutes, with data gaps `gap`.
fn clean_run<P: Stub>(seed: u64, gap: [u64; 2], jitter: bool, opening: bool) -> Report {
    let mut cfg = Cfg::clean();
    cfg.gap = gap;
    cfg.fault_end = 600_000;
    let params = params::<P>();
    let swap = seed % 2 == 1;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut w = world::<P>(params, opening, swap, jitter.then_some(seed));
        w.chan = Some(Chan::new(seed, cfg));
        w.bound = Some(0);
        run_until(&mut w, 600_000);
        if w.failure.is_none() {
            let extra = w.now + heal(&params);
            while w.converged().is_err() && w.now < extra && w.failure.is_none() {
                let next = w.now + 500;
                run_until(&mut w, next);
            }
            if let Err(e) = w.converged() {
                w.fail(e);
            }
        }
        Report {
            failure: w.failure.take(),
            log: core::mem::take(&mut w.log),
            track: core::mem::take(&mut w.t),
            fired: BTreeMap::new(),
        }
    }));
    result.unwrap_or_else(|_| Report {
        failure: Some(String::from("panic")),
        log: Vec::new(),
        track: Track::default(),
        fired: BTreeMap::new(),
    })
}

/// The outcomes a healthy crossing may show.
const CROSSING: [&str; 3] = ["DualInitWon", "TieBreakKept", "Yielded"];

/// The rejects of the losing attempt's messages still in flight when a
/// crossing resolves: its replies, its msg3, and its probes, which are
/// sealed under an epoch the receiver never held ("replays of nothing").
const NOTHING: [&str; 7] = [
    "Replay",
    "FrameUnauthenticated",
    "UnknownAttempt",
    "LateReply",
    "UnknownIndex",
    "FinalNoAttempt",
    "FinalUnauthenticated",
];

/// The criteria of a clean run: no reject, abandon, revert, assumed
/// cutover or residual, except a healthy crossing's outcomes when both ends
/// started within one round trip; and, when `cadence`, every rotation
/// within the jitter band of the time trigger.
///
/// With `unproven` (a silent session of a profile whose responder cuts over
/// at msg3), a drain that ends unevidenced is allowed: the initiator's only
/// frames are prompts, which a responder cannot tell from probes, so the
/// responder never sees evidence and keeps the old epoch to the ceiling.
fn clean_outcomes(t: &Track, p: &Params, cadence: bool, unproven: bool) -> Result<usize, String> {
    let rtt = 1_000;
    let mut crossings = 0;
    for (at, x, name) in &t.outcomes {
        let started = |n: usize| t.starts[n].iter().rev().find(|&&s| s <= *at).copied();
        let crossed = match (started(*x), started(1 - x)) {
            (Some(a), Some(b)) => a.abs_diff(b) <= rtt && at - a.min(b) <= 4 * rtt,
            _ => false,
        };
        if CROSSING.contains(&name.as_str()) && crossed {
            crossings += 1;
            continue;
        }
        if NOTHING.contains(&name.as_str()) && crossed {
            continue;
        }
        if unproven && name == "AdoptionNotSeen" {
            continue;
        }
        return Err(format!("n{x} reported {name} at {at} in a clean run"));
    }
    if t.reverts + t.assumed > 0 || !t.residuals.is_empty() {
        return Err(format!(
            "{} reverts, {} assumed cutovers, residuals {:?}",
            t.reverts, t.assumed, t.residuals
        ));
    }
    if cadence {
        let c = p.config();
        let after = c.after.as_millis() as u64;
        let jitter = u64::from(c.jitter) * 1_000;
        for x in 0..2 {
            let mut last = 0;
            for &i in &t.installs[x] {
                let gap = i - last;
                if gap + jitter + 3_000 < after || gap > after + jitter + 3_000 {
                    return Err(format!("n{x} rotated after {gap} ms, off the cadence"));
                }
                last = i;
            }
            if t.installs[x].len() < 3 {
                return Err(format!("n{x} rotated only {} times", t.installs[x].len()));
            }
        }
    }
    Ok(crossings)
}

use super::stub::{Ik, Xk, XkFrame, Xx};

/// Seeds per profile of the faulty runs.
const FAULTY: u64 = 24;

/// IK seeds whose adversary has a msg1 with a rewritten sender index
/// answered (one while idle, one while initiating), so residual
/// containment is checked on the path where that copy is read first.
const REWRITTEN: [u64; 2] = [124, 197];

#[test]
fn faulty_runs_hold_every_oracle_and_converge_once_healed() {
    faulty_runs::<Ik>("ik", 0..FAULTY, false);
    for seed in REWRITTEN {
        let got = faulty_runs::<Ik>("ik rewritten", seed..seed + 1, false);
        assert!(
            got.iter().any(|r| r.starts_with("rewritten")),
            "ik seed {seed} no longer answers a rewritten msg1: {got:?}"
        );
    }
    faulty_runs::<Xk>("xk", 0..FAULTY, false);
    faulty_runs::<Xk>("xk opening", 0..FAULTY, true);
    faulty_runs::<XkFrame>("xk frame", 0..FAULTY, false);
    faulty_runs::<Xx>("xx", 0..FAULTY, false);
}

/// Check every clean run of `P` over `seeds`.
fn clean_runs<P: Stub>(name: &str, seeds: core::ops::Range<u64>) {
    let p = params::<P>();
    for seed in seeds {
        let at_proof = P::RESPONDER_CUTOVER == crate::proto::rekey::ResponderCutover::AtProof
            && P::MESSAGES == 3;
        for gap in [[300, 700], [0, 0]] {
            let unproven = at_proof && gap == [0, 0];
            let r = clean_run::<P>(seed, gap, true, false);
            let verdict = r.failure.clone().map_or_else(
                || clean_outcomes(&r.track, &p, true, unproven).map(|_| ()),
                Err,
            );
            if let Err(e) = verdict {
                panic!(
                    "{name} clean seed {seed} gap {gap:?}: {e}\nlog tail:\n{}",
                    tail(&r.log)
                );
            }
        }
    }
}

#[test]
fn clean_runs_rotate_on_cadence_with_no_reject_abandon_revert_or_assumed_cutover() {
    clean_runs::<Ik>("ik", 0..8);
    clean_runs::<Xk>("xk", 0..8);
    clean_runs::<XkFrame>("xk frame", 0..8);
    clean_runs::<Xx>("xx", 0..8);
}

/// Clean runs of `P` with equal jitter draws, so both ends start every
/// rotation in the same instant.
fn crossing_runs<P: Stub>(name: &str) {
    let p = params::<P>();
    let mut crossings = 0;
    for seed in 0..4 {
        let r = clean_run::<P>(seed, [300, 700], false, false);
        // `resolve` keeps an own attempt against the peer's only at the
        // smaller address (no peer restarts here), so a kept-own refusal
        // anywhere else names the wrong survivor.
        let smaller = usize::from(seed % 2 == 1);
        let wrong = r
            .track
            .outcomes
            .iter()
            .find(|(_, x, o)| *x != smaller && (o == "TieBreakKept" || o == "DualInitWon"));
        let verdict = match (r.failure.clone(), wrong) {
            (Some(f), _) => Err(f),
            (None, Some((at, x, o))) => Err(format!(
                "n{x}, the larger node, kept its own attempt ({o}) at {at}"
            )),
            (None, None) => clean_outcomes(&r.track, &p, false, false),
        };
        match verdict {
            Ok(n) => crossings += n,
            Err(e) => panic!(
                "{name} crossing seed {seed}: {e}\nlog tail:\n{}",
                tail(&r.log)
            ),
        }
    }
    assert!(
        crossings > 0,
        "{name}: no crossing happened, so nothing was tested"
    );
}

#[test]
fn crossing_runs_converge_with_only_the_tie_break_outcomes() {
    crossing_runs::<Ik>("ik");
    crossing_runs::<Xk>("xk");
    crossing_runs::<XkFrame>("xk frame");
    crossing_runs::<Xx>("xx");
}

/// Lossless runs of `P` with the adversary active: every oracle holds and
/// no rotation is deferred past the time trigger plus two attempt budgets.
fn forged_runs<P: Stub>(name: &str, opening: bool) {
    let p = params::<P>();
    let c = p.config();
    for seed in 0..6 {
        let mut cfg = Cfg::clean();
        cfg.adversary = 2_000;
        cfg.fault_end = 600_000;
        let r = run::<P>(seed, cfg, opening, Some(0), None);
        if let Some(f) = r.failure {
            panic!(
                "{name} forged seed {seed}: {f}\nlog tail:\n{}",
                tail(&r.log)
            );
        }
        let limit = (c.after + 2 * c.handshake).as_millis() as u64 + u64::from(c.jitter) * 1_000;
        let residual = (c.hold + c.handshake).as_millis() as u64;
        for x in 0..2 {
            let mut last = 0;
            for &i in &r.track.installs[x] {
                let replays = r.track.residuals.len() as u64;
                assert!(
                    i - last <= limit + replays * residual + 2_000,
                    "O7: {name} seed {seed}: n{x} went {} ms between cutovers",
                    i - last
                );
                last = i;
            }
        }
    }
}

#[test]
fn lossless_runs_under_forgery_hold_every_oracle_and_keep_rotating() {
    forged_runs::<Ik>("ik", false);
    forged_runs::<Xk>("xk", false);
    forged_runs::<Xk>("xk opening", true);
    forged_runs::<XkFrame>("xk frame", false);
}

#[test]
fn simulator_replay_from_a_seed_is_byte_identical() {
    for seed in [3, 11] {
        let a = replay::<Ik>(seed, false);
        let b = replay::<Ik>(seed, false);
        assert_eq!(a.log, b.log, "ik seed {seed} replays identically");
        let cfg = Cfg::faulty(seed, FAULT_PHASE, true);
        let c = run::<Ik>(seed, cfg, false, Some(heal(&params::<Ik>())), Some(a.fired));
        assert_eq!(
            a.log, c.log,
            "ik seed {seed} replays identically from its script"
        );
        let a = replay::<Xk>(seed, false);
        let b = replay::<Xk>(seed, false);
        assert_eq!(a.log, b.log, "xk seed {seed} replays identically");
    }
}

/// Run a scripted schedule: `w` on a clean channel with `gap` and `rules`,
/// every frame bound by O2's `bound`, until `end`, then until both ends are
/// idle and agree (O1).
pub(crate) fn scripted<P: Stub>(
    mut w: World<P>,
    gap: [u64; 2],
    rules: Vec<Rule>,
    end: u64,
    bound: u64,
) -> Report {
    let mut cfg = Cfg::clean();
    cfg.gap = gap;
    cfg.rules = rules;
    let p = w.params;
    w.chan = Some(Chan::new(1, cfg));
    w.bound = Some(bound);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        run_until(&mut w, end);
        let extra = w.now + heal(&p);
        while w.failure.is_none() && w.now < extra && w.converged().is_err() {
            let next = w.now + 500;
            run_until(&mut w, next);
        }
        if w.failure.is_none()
            && let Err(e) = w.converged()
        {
            w.fail(e);
        }
        w.outages();
        Report {
            failure: w.failure.take(),
            log: core::mem::take(&mut w.log),
            track: core::mem::take(&mut w.t),
            fired: BTreeMap::new(),
        }
    }));
    result.unwrap_or_else(|e| Report {
        failure: Some(format!(
            "panic: {}",
            e.downcast_ref::<String>().cloned().unwrap_or_default()
        )),
        log: Vec::new(),
        track: Track::default(),
        fired: BTreeMap::new(),
    })
}
