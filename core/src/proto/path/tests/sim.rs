//! The deterministic two-party simulator.
//!
//! [`World`] holds two test shells, A and B, each running one `Bundle`,
//! joined by wires. A wire joins one of A's pairs (its transport and B's
//! address on it) to one of B's (its transport and A's address on it), with
//! a one-way delay of 1 to 100 ms in each direction and a loss rate. In the
//! uneven shape A has two transports and B one, so B holds its two paths on
//! one transport and tells them apart by A's two addresses (draft Section
//! 5.1); in the even shape each end has two. The world delivers path
//! messages and data frames as a host would: each frame is accounted with
//! `Bundle::account`, and a path message is then decoded and stepped. Each
//! node sends a data frame every 100 ms and a heartbeat every second on its
//! active path, and is polled at its next wake. Scripted [`Rule`]s drop one
//! class of datagram (probe, ack, close, data or all) in one direction or
//! both on one wire for a window.
//!
//! Neither end starts knowing its peer capable. At the start the second
//! wire's candidate goes to one end only, A or B by the seed, as local
//! discovery would report it. That end, holding a candidate it may probe,
//! sends capability probes on the original wire; the first that arrives
//! makes the other end capable, and its answer makes the first end
//! capable (draft Section 5.2). The other end then learns the second path
//! from a probe; in the uneven shape with A first, B learns it on its one
//! transport from A's probe from a new address (draft Section 5.1, step 2,
//! and its note). A test may instead mark the second wire at one end with
//! a transport of another anonymity class, or one whose role is never to
//! carry paths, and give both ends its candidate: path policy at that end
//! refuses it (Section 5.5), while the other end may probe it. A wire is
//! healed while no rule covers it and it loses nothing. At its heal, and
//! while it stays healed after one, the world reports the wire's candidate
//! again to each end that holds no path for it, or holds it only Dead and
//! never acked, as a host's candidate source would: the draft probes a
//! forgotten candidate only once its source reports it again. An end that
//! held a path for a healed wire and lost it is given the candidate again
//! the same way. Held paths recover by their own cadence. A marked wire is
//! never given again.
//!
//! Before every step the world gives each end, as the link cost the host
//! measures, its active wire's score from the wire's own delays,
//! `1 + (d_A + d_B) / 100`, with `d_A` and `d_B` the wire's one-way delays
//! in milliseconds, or 1 with no active path. Each end is stepped a
//! receiver report every `R` milliseconds, `R` drawn for each end from 500
//! to 2,500, so the dwell ends some holds on the cost and the reports
//! others. A test may give a transport a role at either end before the
//! run starts.
//!
//! Every delay and loss decision is a pure function of the run's seed and a
//! stable key (the wire, the direction and the datagram's serial on it), so
//! a run replays from its seed.
//!
//! The oracles, checked after every event, each named in the message of the
//! failure it reports, with `d` the larger one-way delay of the wire
//! concerned and a round trip of `2d`:
//!
//! - **shell**: both shells' checks on every call, the next wake lying
//!   ahead of every step among them;
//! - **quiet**: until an end reports its peer capable it sends nothing
//!   but probes of exactly 27 bytes, all on the original wire (draft
//!   Section 5.2), and it reports its peer capable once;
//! - **capable**: once the original wire is healed and an end not yet
//!   capable holds a candidate it may probe, both ends are capable by the
//!   later of that instant and the end's next capability probe, read then
//!   and checked against the schedule from the probes the world saw, plus
//!   a probe timeout and `2d`;
//! - **marked**: the end that refuses a marked wire never holds a path on
//!   it and never answers a probe on it, and neither end ever has its
//!   path acked or Live;
//! - **live**: once a wire has been healed for the slowest Dead cadence
//!   plus a probe timeout and `2d`, its path is Live at both ends; an end
//!   given the candidate again counts from that report, and nothing counts
//!   before both ends are capable;
//! - **switch**: when a rule drops every datagram on the wire of an end's
//!   Live active path, in one direction or both, for longer than the bound,
//!   and another of the end's paths is Live on a wire that stays clean
//!   through it, the end switches within three active probe intervals, a
//!   probe timeout and `2d`. When the rule drops only what the end sends,
//!   the peer's data frames still arrive on the wire and its probes' verdicts
//!   may wait for them up to the verdict cap, so the cap stands in the
//!   bound in place of the probe timeout when it is the larger;
//! - **orphan**: no end is orphaned while a wire delivers both ways;
//! - **fixed**: no frame roams a path and no path message moves one, since
//!   no end's address on a wire ever changes;
//! - **counts**: between two acks one path sends, the difference of their
//!   `rx_frames` equals the frames the path's wire delivered to that end
//!   between them, a probe's own frame among them;
//! - **dwell**: every discretionary switch at an end goes to a path that
//!   has been Live at that end, without a break, for at least the switch
//!   dwell, the original wire's path Live from instant 0 until it first
//!   leaves Live, unless the tier of its transport's role there is higher than
//!   the tier of the path it leaves, which gives way at once;
//! - **hold**: from a step at an end that switches until both the switch
//!   dwell has passed since it and two receiver reports have been stepped
//!   at that end after it, `Bundle::cost` gives the cost it gave just
//!   before that step, and afterwards the cost the host measures; a switch
//!   in that span starts a new one from the cost held;
//! - **settle**: in a run with no rule and no loss, with no role set or
//!   one wire preferred at both ends, each end's target wire is worked
//!   out from the wires' scores and the switch margin by the oracle's own
//!   arithmetic. With no role set the target is the second wire when the
//!   first scores worse than the margin times the second's score, and
//!   otherwise the first; with one wire preferred, the preferred wire when
//!   it scores at most the margin times the other's, and otherwise the
//!   other. An end whose target is the first wire never switches. An end
//!   whose target is the second is on it, having switched once, by the
//!   instant the second wire turned Live there plus the probes still owed
//!   for enough samples at the standby interval, `2d`, the dwell and
//!   100 ms. A run whose deciding ratio lies within 0.01 of the margin may
//!   end on either wire, having switched at most once.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use super::shell::{Fact, Node, Out, Slot, Stub, Terms, addr, eligible, pair, spacing, t};
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::link::LinkMessageType;
use crate::proto::path::wire::{PATH_PROBE_MIN_SIZE, PathAck, PathClose, PathProbe};
use crate::proto::path::{
    Config, Facts, Input, Output, Params, PathRef, PathState, Refusal, Roam, Role, Source, Switch,
};
use crate::testutil::{SplitMix64, TestInstant};

/// The end that holds the link's first transport, and in the uneven shape
/// a second one.
const A: usize = 0;

/// The other end.
const B: usize = 1;

/// The ends, in the order every phase visits them.
const ENDS: [usize; 2] = [A, B];

/// The length of a data frame, in bytes.
const DATA: usize = 200;

/// The type byte of a session datagram.
const DATAGRAM: u8 = 0x00;

/// The type byte of a heartbeat.
const HEARTBEAT: u8 = 0x51;

/// The first key of each kind of draw from the run's seed, so draws of
/// different kinds never share a key.
const NODE: u64 = 0x6e6f_6465;

/// See [`NODE`].
const DELAY: u64 = 0x6465_6c61;

/// See [`NODE`].
const LOSS: u64 = 0x6c6f_7373;

/// See [`NODE`].
const RULES: u64 = 0x7275_6c65;

/// See [`NODE`].
const TEST: u64 = 0x7465_7374;

/// See [`NODE`].
const REPORT: u64 = 0x7265_706f;

/// The receiver reports after a switch that the **hold** oracle waits for,
/// beside the dwell.
const REPORTS: usize = 2;

/// The kinds of datagram a rule drops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// Path probes.
    Probe,
    /// Path acks.
    Ack,
    /// Path closes.
    Close,
    /// Data frames and heartbeats.
    Data,
    /// Everything.
    All,
}

/// Every class, for drawing one.
const CLASSES: [Class; 5] = [
    Class::Probe,
    Class::Ack,
    Class::Close,
    Class::Data,
    Class::All,
];

/// A scripted fault: datagrams of `class` sent on `wire` by `from` (by
/// either end when `None`) in `[start, end)` milliseconds are dropped.
#[derive(Clone, Copy, Debug)]
struct Rule {
    /// The wire.
    wire: usize,
    /// The sending end, or `None` for both directions.
    from: Option<usize>,
    /// What it drops.
    class: Class,
    /// The window's first instant.
    start: u64,
    /// The instant after its last.
    end: u64,
}

impl Rule {
    /// Whether the rule is in force at `at`.
    fn active(&self, at: u64) -> bool {
        self.start <= at && at < self.end
    }

    /// Whether it drops a datagram of `class` sent on `wire` by `from` at
    /// `at`.
    fn drops(&self, wire: usize, from: usize, class: Class, at: u64) -> bool {
        self.wire == wire
            && self.from.is_none_or(|f| f == from)
            && (self.class == Class::All || self.class == class)
            && self.active(at)
    }

    /// Whether it drops everything on its wire in at least one direction.
    fn cuts(&self) -> bool {
        self.class == Class::All
    }
}

/// The ends' transports: in the uneven shape A has two and B one, so B
/// holds both its paths on one transport and tells them apart by A's two
/// addresses; in the even shape each end has two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// A with two transports, B with one.
    Uneven,
    /// Two transports at each end.
    Even,
}

/// The second wire marked at one end with a transport that path policy
/// there refuses.
#[derive(Clone, Copy, Debug)]
struct Mark {
    /// The wire.
    wire: usize,
    /// The end that refuses it.
    end: usize,
}

/// One wire between the two ends.
struct Wire {
    /// Each end's pair for it, by end.
    ends: [PathRef; 2],
    /// The one-way delay from each end, in milliseconds.
    delay: [u64; 2],
    /// Datagrams lost per thousand, in each direction.
    loss: u64,
    /// Datagrams sent so far from each end: the serial of each loss draw.
    sent: [u64; 2],
    /// Frames delivered so far to each end, modulo 2^32.
    delivered: [u32; 2],
    /// The instant each end was last given the wire's candidate again.
    reported: [u64; 2],
    /// Whether each end has held a path for the wire.
    held: [bool; 2],
}

impl Wire {
    /// The larger of its two one-way delays, in milliseconds.
    fn worst(&self) -> u64 {
        self.delay[A].max(self.delay[B])
    }
}

/// What a datagram carries.
enum Payload {
    /// A path message, from its type byte.
    Path(Vec<u8>),
    /// Any other frame of the link, by length and type byte.
    Frame { len: usize, ty: u8 },
}

impl Payload {
    /// What a rule sees it as.
    fn class(&self) -> Class {
        let ty = self.ty();
        if ty == LinkMessageType::PathProbe.to_byte() {
            Class::Probe
        } else if ty == LinkMessageType::PathAck.to_byte() {
            Class::Ack
        } else if ty == LinkMessageType::PathClose.to_byte() {
            Class::Close
        } else {
            Class::Data
        }
    }

    /// Its link message type byte.
    fn ty(&self) -> u8 {
        match self {
            Payload::Path(bytes) => bytes.first().copied().unwrap_or(DATAGRAM),
            Payload::Frame { ty, .. } => *ty,
        }
    }

    /// The whole FMP frame's length, in bytes.
    fn size(&self) -> usize {
        match self {
            Payload::Path(bytes) => bytes.len() + FRAME_OVERHEAD,
            Payload::Frame { len, .. } => *len,
        }
    }
}

/// A datagram in flight.
struct Datagram {
    /// The wire it travels on.
    wire: usize,
    /// The end it arrives at.
    to: usize,
    /// What it carries.
    payload: Payload,
}

/// One switch the **switch** oracle waits for.
struct Watch {
    /// The end that must switch.
    end: usize,
    /// When its wire was cut.
    from: u64,
    /// The latest instant the switch may come.
    by: u64,
    /// Whether it came.
    met: bool,
}

/// What the oracles saw, so a test can show they ran.
#[derive(Default)]
struct Seen {
    /// Instants at which a path was required Live, per wire.
    live: Vec<usize>,
    /// Pairs of acks whose counts were compared, per wire.
    compared: Vec<usize>,
    /// Of those, the pairs with more than the probe's frame between them,
    /// per wire.
    wide: Vec<usize>,
    /// Switches waited for, per end.
    armed: [usize; 2],
    /// Switches that came in time, per end.
    met: [usize; 2],
    /// Reports of the link not capable, per end.
    told: [usize; 2],
    /// Bounds the **capable** oracle set, per end.
    awaited: [usize; 2],
    /// Probes the other end sent on the marked wire.
    marked: usize,
    /// Refusals by path policy at the marked end on the marked wire.
    refused: usize,
    /// Switches, per end.
    switched: [usize; 2],
    /// Discretionary switches the **dwell** oracle checked, per end.
    dwelt: [usize; 2],
    /// Holds the **hold** oracle checked while in force, per end.
    held: [usize; 2],
    /// Holds whose second report came before the dwell had passed, so the
    /// dwell ended them, and those whose second report came after it.
    decided: [usize; 2],
    /// Checks the **settle** oracle made, per end: every check while the
    /// target is the first wire or the run is exempt, and every check from
    /// the deadline on while it is the second.
    settled: [usize; 2],
    /// The **settle** oracle's target wire, unless the run is exempt.
    aim: Option<usize>,
    /// Whether the run's deciding ratio lies within 0.01 of the margin.
    exempt: bool,
}

/// The hold on an end's link cost that the **hold** oracle follows, from
/// the end's latest switch.
#[derive(Clone, Copy, Debug)]
struct Span {
    /// The cost `Bundle::cost` gave just before the step that switched.
    cost: f64,
    /// The instant of that step, in milliseconds.
    at: u64,
    /// Receiver reports stepped at the end since that step while the hold
    /// was in force.
    reports: usize,
    /// Whether an oracle check has seen it in force.
    checked: bool,
}

impl Span {
    /// Whether the hold is in force at `now` under a switch dwell of
    /// `dwell` milliseconds: before the dwell has passed since the switch,
    /// or while a report is still owed.
    fn force(&self, now: u64, dwell: u64) -> bool {
        now < self.at + dwell || self.reports < REPORTS
    }
}

/// The simulator: two shells, their wires, the rules, and the datagrams in
/// flight, on one clock of whole milliseconds.
struct World {
    /// The run's seed.
    seed: u64,
    /// The current instant, in milliseconds.
    now: u64,
    /// A and B.
    nodes: [Node; 2],
    /// The wires, the link's original pair first.
    wires: Vec<Wire>,
    /// The scripted faults.
    rules: Vec<Rule>,
    /// Datagrams in flight, by arrival instant and send order.
    queue: BTreeMap<(u64, u64), Datagram>,
    /// Datagrams sent so far, for the queue's order.
    serial: u64,
    /// The latest ack each end sent on each wire for each of its paths: its
    /// `rx_frames` and the wire's delivered count then.
    acks: BTreeMap<(usize, usize, u32), (u32, u32)>,
    /// The switches waited for.
    watches: Vec<Watch>,
    /// What the oracles saw.
    seen: Seen,
    /// The settings both bundles run with.
    cfg: Config,
    /// Every event, when the run is traced.
    trace: Option<String>,
    /// A slot serial taken at the start, so a trace names slots by their
    /// order in the run.
    base: u64,
    /// The instant each end reported its peer capable.
    capable: [Option<u64>; 2],
    /// The instants of each end's capability probes.
    asked: [Vec<u64>; 2],
    /// The instant by which both ends must be capable, for each end the
    /// **capable** oracle waits on.
    awaits: [Option<u64>; 2],
    /// The marked wire, if any.
    mark: Option<Mark>,
    /// The interval of each end's receiver reports, in milliseconds.
    every: [u64; 2],
    /// The instant of each end's next receiver report.
    due: [u64; 2],
    /// The instant each end's path for each wire last turned Live, while it
    /// stays Live, by end and wire; the original wire's from instant 0.
    lived: BTreeMap<(usize, usize), u64>,
    /// The hold the **hold** oracle follows at each end, from its latest
    /// switch.
    spans: [Option<Span>; 2],
}

impl World {
    /// A world of `shape` seeded with `seed`, each wire losing `loss`
    /// datagrams per thousand, with no rule. At instant 0 the second
    /// wire's candidate is reported to one end only, A or B by the seed,
    /// so the other end learns the path from a probe.
    fn new(seed: u64, shape: Shape, loss: [u64; 2]) -> Self {
        Self::tuned(seed, shape, loss, Config::draft())
    }

    /// A world as [`World::new`] makes it, both ends running with `cfg`.
    fn tuned(seed: u64, shape: Shape, loss: [u64; 2], cfg: Config) -> Self {
        // A on one seed in four, and otherwise B in the uneven shape.
        let first = if seed % 4 == 2 || shape == Shape::Even {
            A
        } else {
            B
        };
        Self::make(seed, shape, loss, Vec::new(), None, &[first], cfg)
    }

    /// A world of `shape` seeded with `seed` whose second wire is marked at
    /// end `end` with `fact` about its transport there, and whose second
    /// wire's candidate is reported to both ends at instant 0.
    fn marked(seed: u64, shape: Shape, end: usize, fact: Fact) -> Self {
        let mark = Some((end, fact));
        Self::make(
            seed,
            shape,
            [0, 0],
            Vec::new(),
            mark,
            &ENDS,
            Config::draft(),
        )
    }

    /// A world of `shape` seeded with `seed`, each wire losing `loss`
    /// datagrams per thousand, with `rules` in force from the start, the
    /// second wire marked at one end with one fact about its transport
    /// there when `mark` gives them, and the second wire's candidate
    /// reported at instant 0 to each end of `offer`, both ends running
    /// with `cfg`. Neither end knows its peer capable.
    fn make(
        seed: u64,
        shape: Shape,
        loss: [u64; 2],
        rules: Vec<Rule>,
        mark: Option<(usize, Fact)>,
        offer: &[usize],
        cfg: Config,
    ) -> Self {
        let base = Slot::default().serial;
        // Each end's original path is (t(1), addr(1)): the first wire.
        let original = pair(t(1), addr(1));
        let far = match shape {
            Shape::Uneven => [pair(t(2), addr(1)), pair(t(1), addr(2))],
            Shape::Even => [pair(t(2), addr(2)), pair(t(2), addr(2))],
        };
        let nodes = ENDS.map(|end| {
            let mut facts = Stub::default();
            if let Some((marked, fact)) = mark
                && marked == end
            {
                assert_ne!(
                    far[end].transport, original.transport,
                    "a marked transport carries the original pair"
                );
                facts = facts.fact(far[end].transport, fact);
            }
            let seed = SplitMix64::mix(seed, &[NODE, end as u64]);
            let params = Params::new(cfg).expect("valid settings");
            Node::on(seed, params, facts, original.clone())
        });
        let ends = [[original.clone(), original], far];
        let wires = ends
            .into_iter()
            .enumerate()
            .map(|(w, ends)| Wire {
                ends,
                delay: ENDS.map(|e| 1 + SplitMix64::mix(seed, &[DELAY, w as u64, e as u64]) % 100),
                loss: loss[w],
                sent: [0; 2],
                delivered: [0; 2],
                reported: [0; 2],
                held: [w == 0; 2],
            })
            .collect();
        let every = ENDS.map(|e| 500 + SplitMix64::mix(seed, &[REPORT, e as u64]) % 2_001);
        let mut world = Self {
            seed,
            now: 0,
            nodes,
            wires,
            rules,
            queue: BTreeMap::new(),
            serial: 0,
            acks: BTreeMap::new(),
            watches: Vec::new(),
            seen: Seen {
                live: alloc::vec![0; 2],
                compared: alloc::vec![0; 2],
                wide: alloc::vec![0; 2],
                ..Seen::default()
            },
            cfg,
            trace: None,
            base,
            capable: [None; 2],
            asked: [Vec::new(), Vec::new()],
            awaits: [None; 2],
            mark: mark.map(|(end, _)| Mark { wire: 1, end }),
            every,
            due: every,
            // The original path starts Live, with no `State` output.
            lived: ENDS.iter().map(|&e| ((e, 0), 0)).collect(),
            spans: [None; 2],
        };
        for &end in offer {
            world.report(end, 1);
        }
        world.check();
        world
    }

    /// Record every event from now on.
    fn traced(mut self) -> Self {
        self.trace = Some(String::new());
        self
    }

    /// The world with end `end`'s transport for wire `wire` given `role`
    /// in its facts, before the run starts. Roles are read at each step, so
    /// the candidates reported at instant 0 change nothing.
    fn role(mut self, end: usize, wire: usize, role: Role) -> Self {
        assert_eq!(self.now, 0, "a role is given before the run starts");
        let transport = self.wires[wire].ends[end].transport;
        let shared = (0..self.wires.len())
            .any(|w| w != wire && self.wires[w].ends[end].transport == transport);
        assert!(
            !shared,
            "{end}'s transport for wire {wire} carries another wire"
        );
        self.nodes[end].facts.change(transport, Fact::Role(role));
        self
    }

    /// Add `count` rules, each on a wire, a direction and a class drawn at
    /// random, starting in `[first, last)` and lasting `[short, long)`
    /// milliseconds.
    fn flaps(&mut self, count: u64, first: u64, last: u64, short: u64, long: u64) {
        let mut g = SplitMix64::new(SplitMix64::mix(self.seed, &[RULES]));
        for _ in 0..count {
            let start = first + g.below(last - first);
            let from = match g.below(3) {
                0 => Some(A),
                1 => Some(B),
                _ => None,
            };
            self.rules.push(Rule {
                wire: g.below(self.wires.len() as u64) as usize,
                from,
                class: CLASSES[g.below(CLASSES.len() as u64) as usize],
                start,
                end: start + short + g.below(long - short),
            });
        }
    }

    /// Add rules one after another until `until` milliseconds, 20 to 120
    /// seconds apart: half of them cut a wire in one direction or both, the
    /// rest drop one class of datagram; most last up to a minute, and one
    /// in seven 10 to 15 minutes, past the grace of a Dead path.
    #[cfg(feature = "slow-tests")]
    fn churn(&mut self, until: u64) {
        let mut g = SplitMix64::new(SplitMix64::mix(self.seed, &[RULES]));
        let mut start = 10_000;
        loop {
            start += 20_000 + g.below(100_000);
            if start >= until {
                return;
            }
            let long = if g.chance(143) {
                600_000 + g.below(300_000)
            } else {
                1_000 + g.below(60_000)
            };
            let from = match g.below(3) {
                0 => Some(A),
                1 => Some(B),
                _ => None,
            };
            let class = if g.chance(500) {
                Class::All
            } else {
                CLASSES[g.below(CLASSES.len() as u64) as usize]
            };
            self.rules.push(Rule {
                wire: g.below(self.wires.len() as u64) as usize,
                from,
                class,
                start,
                end: start + long,
            });
        }
    }

    /// Run until `until` milliseconds, event by event.
    fn run(&mut self, until: u64) {
        loop {
            let next = self.upcoming();
            if next > until {
                return;
            }
            self.now = next;
            self.instant();
        }
    }

    /// The next instant at which anything happens.
    fn upcoming(&self) -> u64 {
        let mut next = (self.now / 100 + 1) * 100;
        if let Some((&(at, _), _)) = self.queue.first_key_value() {
            next = next.min(at);
        }
        for n in &self.nodes {
            if let Some(w) = n.b.next_wake() {
                next = next.min(w.0);
            }
        }
        for r in &self.rules {
            for edge in [r.start, r.end] {
                if edge > self.now {
                    next = next.min(edge);
                }
            }
        }
        for &due in &self.due {
            next = next.min(due);
        }
        next
    }

    /// Everything due at the current instant: the switches the rules
    /// starting now call for, the datagrams arriving, the traffic, the
    /// polls, the receiver reports, the candidates reported again, and the
    /// oracles.
    fn instant(&mut self) {
        self.arm();
        while let Some(entry) = self.queue.first_entry() {
            if entry.key().0 != self.now {
                break;
            }
            let d = entry.remove();
            self.deliver(d);
        }
        if self.now.is_multiple_of(100) {
            self.traffic();
        }
        for end in ENDS {
            let due = self.nodes[end]
                .b
                .next_wake()
                .is_some_and(|w| w.0 <= self.now);
            if due {
                self.drive(end, Input::Poll);
            }
        }
        for end in ENDS {
            if self.due[end] <= self.now {
                self.due[end] = self.now + self.every[end];
                self.drive(end, Input::Report);
            }
        }
        for w in 0..self.wires.len() {
            if !self.healed(w) || self.refused(w) {
                continue;
            }
            for end in ENDS {
                let lost = self.lost(end, w);
                if lost && (self.wires[w].held[end] || self.cured(w)) {
                    self.report(end, w);
                }
            }
        }
        self.check();
    }

    /// Give end `end` the candidate of wire `w`, as local discovery that
    /// dropped the pair and lists it again: the report is fresh, so it
    /// releases the pair if it was held back.
    fn report(&mut self, end: usize, w: usize) {
        let to = self.wires[w].ends[end].clone();
        self.wires[w].reported[end] = self.now;
        let inputs = [
            Input::Unlisted {
                transport: to.transport,
                addr: to.addr.clone(),
                source: Source::Discovery,
            },
            Input::Candidate {
                transport: to.transport,
                addr: to.addr,
                source: Source::Discovery,
            },
        ];
        for input in inputs {
            self.drive(end, input);
        }
    }

    /// Step `input` at end `end` at the current instant, with the end's
    /// link cost set first to its active wire's, and carry out its outputs.
    /// For the **hold** oracle, the cost `Bundle::cost` gives just before
    /// the step must be the cost the oracle expects; a step that switches
    /// starts a new hold from that cost, and a report stepped while the
    /// hold is in force counts toward it.
    fn drive(&mut self, end: usize, input: Input) {
        let now = self.now;
        let dwell = ms(self.cfg.switch_dwell);
        let live = self.live(end);
        let span = self.spans[end];
        let n = &mut self.nodes[end];
        n.now = TestInstant(now);
        n.cost = live;
        let cost = n.b.cost(n.now, live);
        if let Err(e) = holding(span, now, dwell, live, cost) {
            self.fail(format!("{e}, at {end} before {input:?}"));
        }
        let out = self.nodes[end].step(input.clone());
        if out.iter().any(|o| matches!(o, Output::Switched { .. })) {
            self.spans[end] = Some(Span {
                cost,
                at: now,
                reports: 0,
                checked: false,
            });
        } else if input == Input::Report
            && let Some(s) = self.spans[end].as_mut().filter(|s| s.force(now, dwell))
        {
            s.reports += 1;
            if s.reports == REPORTS {
                self.seen.decided[usize::from(now >= s.at + dwell)] += 1;
            }
        }
        self.handle(end, &input, out);
    }

    /// The link cost the host measures at end `end`: the score of its
    /// active wire, or 1 with none.
    fn live(&self, end: usize) -> f64 {
        self.active(end).map_or(1.0, |w| self.rated(w))
    }

    /// The score of wire `w` from its own delays: one plus its round trip
    /// over 100 ms.
    fn rated(&self, w: usize) -> f64 {
        let wire = &self.wires[w];
        1.0 + (wire.delay[A] + wire.delay[B]) as f64 / 100.0
    }

    /// Whether end `end` holds no path for wire `w`, or holds it only Dead
    /// and never acked, so only a report brings it back.
    fn lost(&self, end: usize, w: usize) -> bool {
        self.path(end, w)
            .is_none_or(|(state, acked)| state == PathState::Dead && !acked)
    }

    /// The state of end `end`'s path for wire `w`, and whether it is acked.
    fn path(&self, end: usize, w: usize) -> Option<(PathState, bool)> {
        let to = &self.wires[w].ends[end];
        let paths = self.nodes[end].b.paths();
        let p = paths.get(paths.find(to.transport, &to.addr)?)?;
        Some((p.state(), p.acked()))
    }

    /// Whether wire `w` has had a rule end.
    fn cured(&self, w: usize) -> bool {
        self.rules.iter().any(|r| r.wire == w && r.end <= self.now)
    }

    /// Whether wire `w` is healed now: no rule in force and no loss.
    fn healed(&self, w: usize) -> bool {
        self.wires[w].loss == 0 && !self.rules.iter().any(|r| r.wire == w && r.active(self.now))
    }

    /// Whether wire `w` is marked, so one end's path policy refuses it.
    fn refused(&self, w: usize) -> bool {
        self.mark.is_some_and(|m| m.wire == w)
    }

    /// The instant since which end `end`'s path for wire `w` must be Live
    /// once the bound has passed: the wire's latest heal, the latest
    /// report to that end, or the instant both ends were capable, whichever
    /// is latest. `None` while it is not healed, while an end is not
    /// capable, and for a marked wire.
    fn since(&self, end: usize, w: usize) -> Option<u64> {
        let (Some(a), Some(b)) = (self.capable[A], self.capable[B]) else {
            return None;
        };
        if !self.healed(w) || self.refused(w) {
            return None;
        }
        let heal = self
            .rules
            .iter()
            .filter(|r| r.wire == w && r.end <= self.now)
            .map(|r| r.end)
            .max()
            .unwrap_or(0);
        Some(heal.max(self.wires[w].reported[end]).max(a.max(b)))
    }

    /// The **live** oracle's bound for wire `w`, in milliseconds: the
    /// slowest Dead cadence, a probe timeout and `2d`.
    fn settle(&self, w: usize) -> u64 {
        let d = self.wires[w].worst();
        ms(self.cfg.dead_interval) + self.timeout(d) + 2 * d
    }

    /// The **switch** oracle's bound for a wire whose larger one-way delay
    /// is `d`: three active probe intervals, a probe timeout and `2d`. For
    /// an end whose own sending alone is cut (`own`), the peer's data frames
    /// still arrive and may hold its verdicts to the verdict cap, which then
    /// stands in place of the probe timeout when it is the larger.
    fn detect(&self, d: u64, own: bool) -> u64 {
        let wait = if own {
            self.timeout(d).max(ms(self.cfg.verdict_cap))
        } else {
            self.timeout(d)
        };
        3 * ms(self.cfg.active_interval) + wait + 2 * d
    }

    /// The probe timeout of a path whose round trip is `2d`.
    fn timeout(&self, d: u64) -> u64 {
        ms(self.cfg.timeout).max(3 * 2 * d)
    }

    /// The wire of end `end`'s pair `to`.
    fn wire(&self, end: usize, to: &PathRef) -> Option<usize> {
        self.wires.iter().position(|w| &w.ends[end] == to)
    }

    /// The wire of end `end`'s active path.
    fn active(&self, end: usize) -> Option<usize> {
        let p = self.nodes[end].b.paths().active()?;
        self.wire(end, &pair(p.transport_id(), p.addr().clone()))
    }

    /// Arm the **switch** oracle for each rule that starts now and cuts a
    /// wire: each end whose active path is Live on that wire, and has a
    /// Live path on another wire that stays clean through the bound, must
    /// switch within it, if the cut lasts that long.
    fn arm(&mut self) {
        let starting: Vec<Rule> = self
            .rules
            .iter()
            .filter(|r| r.start == self.now && r.cuts())
            .copied()
            .collect();
        for r in starting {
            for end in ENDS {
                let own = r.from == Some(end);
                let by = self.now + self.detect(self.wires[r.wire].worst(), own);
                if r.end <= by {
                    continue;
                }
                let on = self.active(end) == Some(r.wire)
                    && self
                        .path(end, r.wire)
                        .is_some_and(|(s, _)| s == PathState::Live);
                let other = (0..self.wires.len()).any(|w| {
                    w != r.wire
                        && self.path(end, w).is_some_and(|(s, _)| s == PathState::Live)
                        && self.clean(w, self.now, by)
                });
                if on && other {
                    self.seen.armed[end] += 1;
                    self.watches.push(Watch {
                        end,
                        from: self.now,
                        by,
                        met: false,
                    });
                }
            }
        }
    }

    /// Whether wire `w` loses nothing and no rule covers it in `[from, to]`.
    fn clean(&self, w: usize, from: u64, to: u64) -> bool {
        self.wires[w].loss == 0
            && !self
                .rules
                .iter()
                .any(|r| r.wire == w && r.start <= to && r.end > from)
    }

    /// Each end sends a data frame on its active path, and on each whole
    /// second a heartbeat too.
    fn traffic(&mut self) {
        if self.now == 0 {
            return;
        }
        for end in ENDS {
            let Some(w) = self.active(end) else {
                continue;
            };
            self.send(
                end,
                w,
                Payload::Frame {
                    len: DATA,
                    ty: DATAGRAM,
                },
            );
            if self.now.is_multiple_of(1000) {
                let beat = Payload::Frame {
                    len: FRAME_OVERHEAD + 1,
                    ty: HEARTBEAT,
                };
                self.send(end, w, beat);
            }
        }
    }

    /// Send `payload` from end `from` on wire `w`, unless the wire loses it
    /// or a rule drops it.
    fn send(&mut self, from: usize, w: usize, payload: Payload) {
        let wire = &mut self.wires[w];
        wire.sent[from] += 1;
        let key = [LOSS, w as u64, from as u64, wire.sent[from]];
        let lost = SplitMix64::mix(self.seed, &key) % 1000 < wire.loss;
        let delay = wire.delay[from];
        let class = payload.class();
        let ruled = self.rules.iter().any(|r| r.drops(w, from, class, self.now));
        if let Some(trace) = &mut self.trace {
            let fate = if lost || ruled { "dropped" } else { "sent" };
            let _ = writeln!(
                trace,
                "{} {from} {fate} on {w}: {:?} {} bytes",
                self.now,
                class,
                payload.size()
            );
        }
        if lost || ruled {
            return;
        }
        self.serial += 1;
        let d = Datagram {
            wire: w,
            to: 1 - from,
            payload,
        };
        self.queue.insert((self.now + delay, self.serial), d);
    }

    /// Deliver `d` as a host would: account for its frame, then step a path
    /// message.
    fn deliver(&mut self, d: Datagram) {
        let (end, w) = (d.to, d.wire);
        let to = self.wires[w].ends[end].clone();
        let wire = &mut self.wires[w];
        wire.delivered[end] = wire.delivered[end].wrapping_add(1);
        let n = &mut self.nodes[end];
        n.now = TestInstant(self.now);
        let account = n.account(to.transport, &to.addr, d.payload.size(), d.payload.ty());
        if let Some(trace) = &mut self.trace {
            let _ = writeln!(trace, "{} {end} heard on {w}: {account:?}", self.now);
        }
        if account.roam != Roam::Unmoved {
            self.fail(format!(
                "fixed: {end} roamed on a frame over wire {w}: {account:?}"
            ));
        }
        let Payload::Path(bytes) = d.payload else {
            return;
        };
        let input = self.decode(&to, &bytes);
        self.drive(end, input);
    }

    /// The input a path message `bytes` arriving on `to` makes.
    fn decode(&self, to: &PathRef, bytes: &[u8]) -> Input {
        let (transport, addr) = (to.transport, to.addr.clone());
        let ty = bytes.first().copied();
        let body = bytes.get(1..).unwrap_or_default();
        if ty == Some(LinkMessageType::PathProbe.to_byte()) {
            let msg = PathProbe::decode(body).expect("a probe decodes");
            Input::Probe {
                transport,
                addr,
                msg,
            }
        } else if ty == Some(LinkMessageType::PathAck.to_byte()) {
            let msg = PathAck::decode(body).expect("an ack decodes");
            Input::Ack {
                transport,
                addr,
                msg,
            }
        } else {
            let msg = PathClose::decode(body).expect("a close decodes");
            Input::Close {
                transport,
                addr,
                msg,
            }
        }
    }

    /// Carry out end `end`'s outputs for `input`: send what it sends, note
    /// its switches, when it reports its peer capable or the link not
    /// capable, its refusals of a marked wire, and when each of its paths
    /// turns Live or leaves Live, and check the **quiet**, **marked**,
    /// **counts**, **orphan** and **dwell** oracles.
    fn handle(&mut self, end: usize, input: &Input, out: Vec<Out>) {
        if let Some(trace) = &mut self.trace {
            let _ = writeln!(trace, "{} {end} took {input:?}", self.now);
            for o in &out {
                let _ = writeln!(trace, "  {}", line(o, self.base));
            }
        }
        for o in out {
            match o {
                Output::Send { to, bytes } => {
                    let Some(w) = self.wire(end, &to) else {
                        self.fail(format!("{end} sent on {to:?}, which no wire joins"));
                    };
                    if self.capable[end].is_none() {
                        self.quiet(end, w, &bytes);
                    }
                    self.marking(end, w, &bytes);
                    if bytes.first() == Some(&LinkMessageType::PathAck.to_byte()) {
                        self.counts(end, &bytes);
                    }
                    self.send(end, w, Payload::Path(bytes));
                }
                Output::Capable => {
                    if self.capable[end].replace(self.now).is_some() {
                        self.fail(format!("quiet: {end} reported its peer capable twice"));
                    }
                }
                Output::NotCapable => self.seen.told[end] += 1,
                Output::Refused { to, why } => {
                    let at = self.mark.filter(|m| m.end == end);
                    if let Some(m) = at
                        && self.wires[m.wire].ends[end] == to
                        && matches!(why, Refusal::Rule(_))
                    {
                        self.seen.refused += 1;
                    }
                }
                Output::Switched { from, to, why } => {
                    let now = self.now;
                    self.seen.switched[end] += 1;
                    for watch in self.watches.iter_mut() {
                        if watch.end == end && !watch.met && watch.from < now && now <= watch.by {
                            watch.met = true;
                            self.seen.met[end] += 1;
                        }
                    }
                    if why == Switch::Discretionary {
                        self.dwelling(end, from.as_ref(), &to);
                    }
                }
                Output::Orphaned => {
                    let open = (0..self.wires.len()).any(|w| {
                        !self
                            .rules
                            .iter()
                            .any(|r| r.wire == w && r.cuts() && r.active(self.now))
                    });
                    if open {
                        self.fail(format!("orphan: {end} orphaned with a wire delivering"));
                    }
                }
                Output::Moved { from, to, .. } => {
                    self.fail(format!("fixed: {end} moved its path on {from:?} to {to:?}"));
                }
                Output::State { to, from, next, .. } => {
                    if let Some(w) = self.wire(end, &to) {
                        if next != Some(PathState::Live) {
                            self.lived.remove(&(end, w));
                        } else if from != Some(PathState::Live) {
                            self.lived.insert((end, w), self.now);
                        }
                    }
                }
                Output::Released { .. } | Output::Connect { .. } | Output::Proven { .. } => {}
            }
        }
    }

    /// The **dwell** oracle on a discretionary switch at end `end` from
    /// `from` to `to`.
    fn dwelling(&mut self, end: usize, from: Option<&PathRef>, to: &PathRef) {
        let since = self
            .wire(end, to)
            .and_then(|w| self.lived.get(&(end, w)).copied());
        let facts = &self.nodes[end].facts;
        let left = from.map(|f| facts.role(f.transport));
        let dwell = ms(self.cfg.switch_dwell);
        if let Err(e) = dwelt(self.now, since, dwell, left, facts.role(to.transport)) {
            self.fail(format!("{e}, at {end} from {from:?} to {to:?}"));
        }
        self.seen.dwelt[end] += 1;
    }

    /// The **quiet** oracle on the path message `bytes` that end `end`
    /// sends on wire `w` before it knows its peer capable: a capability
    /// probe, of exactly 27 bytes, on the original wire.
    fn quiet(&mut self, end: usize, w: usize, bytes: &[u8]) {
        let probe = bytes.first() == Some(&LinkMessageType::PathProbe.to_byte());
        if w != 0 || !probe || bytes.len() != PATH_PROBE_MIN_SIZE {
            self.fail(format!(
                "quiet: {end} sent {} bytes of type {:?} on wire {w} before it knew its peer \
                 capable",
                bytes.len(),
                bytes.first()
            ));
        }
        self.asked[end].push(self.now);
    }

    /// The **marked** oracle on the path message `bytes` that end `end`
    /// sends on wire `w`: the end that refuses a marked wire answers no
    /// probe on it. Counts the other end's probes on it.
    fn marking(&mut self, end: usize, w: usize, bytes: &[u8]) {
        let Some(m) = self.mark.filter(|m| m.wire == w) else {
            return;
        };
        let ty = bytes.first().copied();
        if end == m.end && ty == Some(LinkMessageType::PathAck.to_byte()) {
            self.fail(format!(
                "marked: {end} answered a probe on the marked wire {w}"
            ));
        }
        if end != m.end && ty == Some(LinkMessageType::PathProbe.to_byte()) {
            self.seen.marked += 1;
        }
    }

    /// The **counts** oracle on an ack end `end` sends. The ack's path is
    /// the one its `path_id` names, which counts the probe's frame even when
    /// the probe came on another pair (draft Section 5.1, step 2).
    fn counts(&mut self, end: usize, bytes: &[u8]) {
        let ack = PathAck::decode(bytes.get(1..).unwrap_or_default()).expect("an ack decodes");
        let paths = self.nodes[end].b.paths().paths();
        let Some(to) = paths
            .iter()
            .find(|p| p.path_id() == ack.path_id)
            .map(|p| pair(p.transport_id(), p.addr().clone()))
        else {
            self.fail(format!(
                "counts: {end} acked for {:#x}, no path",
                ack.path_id
            ));
        };
        let Some(w) = self.wire(end, &to) else {
            self.fail(format!("counts: {end}'s path on {to:?} is on no wire"));
        };
        let delivered = self.wires[w].delivered[end];
        let key = (end, w, ack.path_id);
        let Some((rx, then)) = self.acks.insert(key, (ack.rx_frames, delivered)) else {
            return;
        };
        let want = delivered.wrapping_sub(then);
        let got = ack.rx_frames.wrapping_sub(rx);
        if want != got {
            self.fail(format!(
                "counts: {end}'s path {:#x} on wire {w} counted {got} frames between two acks, \
                 the wire delivered {want}",
                ack.path_id
            ));
        }
        self.seen.compared[w] += 1;
        if want > 1 {
            self.seen.wide[w] += 1;
        }
    }

    /// The **capable**, **marked**, **hold**, **settle**, **live** and
    /// **switch** oracles at the current instant.
    fn check(&mut self) {
        self.awaited();
        self.marks();
        self.holds();
        self.settles();
        for w in 0..self.wires.len() {
            for end in ENDS {
                if self.path(end, w).is_some() {
                    self.wires[w].held[end] = true;
                }
                let Some(since) = self.since(end, w) else {
                    continue;
                };
                if self.now < since + self.settle(w) {
                    continue;
                }
                self.seen.live[w] += 1;
                let state = self.path(end, w);
                if state.is_none_or(|(s, _)| s != PathState::Live) {
                    self.fail(format!(
                        "live: wire {w} healed since {since} ms, and {end}'s path for it is \
                         {state:?}"
                    ));
                }
            }
        }
        if let Some(late) = self.watches.iter().find(|w| !w.met && w.by < self.now) {
            self.fail(format!(
                "switch: {} still on its wire {} ms after it was cut at {} ms",
                late.end,
                late.by - late.from,
                late.from
            ));
        }
    }

    /// The **capable** oracle at the current instant. A bound already set
    /// must not have passed with an end still not capable. While the
    /// original wire is healed, an end not yet capable that holds a
    /// candidate it may probe sets one, from its next capability probe,
    /// which must be where the schedule puts it after the probes the world
    /// saw. A bound lapses once both ends are capable or the original wire
    /// is no longer healed.
    fn awaited(&mut self) {
        let both = self.capable.iter().all(Option::is_some);
        if !both
            && let Some(by) = self.awaits.iter().flatten().copied().min()
            && self.now > by
        {
            self.fail(format!(
                "capable: the ends not both capable by {by} ms, capable at {:?}",
                self.capable
            ));
        }
        if both || !self.healed(0) {
            self.awaits = [None; 2];
            return;
        }
        let d = self.wires[0].worst();
        for end in ENDS {
            if self.awaits[end].is_some() || self.capable[end].is_some() {
                continue;
            }
            let n = &self.nodes[end];
            let terms = Terms {
                facts: &n.facts,
                link: n.b.scope(),
                mix: self.cfg.mix_kinds,
            };
            if !eligible(&n.b, &terms) {
                continue;
            }
            let next = n.b.capability().next_at().map(|i| i.0);
            let asked = &self.asked[end];
            let want = asked
                .last()
                .map(|&last| last + ms(spacing(asked.len(), &self.cfg)));
            if next != want {
                self.fail(format!(
                    "capable: {end}'s next capability probe at {next:?} ms, the schedule's at \
                     {want:?} ms"
                ));
            }
            let start = next.unwrap_or(self.now).max(self.now);
            self.awaits[end] = Some(start + self.timeout(d) + 2 * d);
            self.seen.awaited[end] += 1;
        }
    }

    /// The **marked** oracle at the current instant: the end that refuses
    /// the marked wire holds no path on it, and neither end has its path
    /// acked or Live.
    fn marks(&self) {
        let Some(m) = self.mark else {
            return;
        };
        if let Some(state) = self.path(m.end, m.wire) {
            self.fail(format!(
                "marked: {} holds a path on the marked wire {}: {state:?}",
                m.end, m.wire
            ));
        }
        for end in ENDS {
            if let Some((state, acked)) = self.path(end, m.wire)
                && (acked || state == PathState::Live)
            {
                self.fail(format!(
                    "marked: {end}'s path on the marked wire {} is {state:?}, acked {acked}",
                    m.wire
                ));
            }
        }
    }

    /// The **hold** oracle at the current instant, at each end.
    fn holds(&mut self) {
        let now = self.now;
        let dwell = ms(self.cfg.switch_dwell);
        for end in ENDS {
            let live = self.live(end);
            let cost = self.nodes[end].b.cost(TestInstant(now), live);
            if let Err(e) = holding(self.spans[end], now, dwell, live, cost) {
                self.fail(format!("{e}, at {end}"));
            }
            if let Some(s) = self.spans[end].as_mut()
                && !s.checked
                && s.force(now, dwell)
            {
                s.checked = true;
                self.seen.held[end] += 1;
            }
        }
    }

    /// The **settle** oracle at the current instant, at each end, in a run
    /// with no rule and no loss and with no role set or one wire preferred
    /// at both ends.
    fn settles(&mut self) {
        if !self.rules.is_empty() || self.wires.iter().any(|w| w.loss > 0) {
            return;
        }
        let Some(preferred) = self.favoured() else {
            return;
        };
        let margin = self.cfg.switch_margin;
        let (want, ratio) = aim([self.rated(0), self.rated(1)], margin, preferred);
        let exempt = (ratio - margin).abs() < 0.01;
        self.seen.exempt = exempt;
        self.seen.aim = (!exempt).then_some(want);
        // The probes still owed for enough samples once the second wire
        // is Live with one, each answered within `2d`, then the dwell.
        let owed = u64::from(self.cfg.min_samples).saturating_sub(1);
        let wait = owed * ms(self.cfg.standby_interval)
            + 2 * self.wires[1].worst()
            + ms(self.cfg.switch_dwell)
            + 100;
        for end in ENDS {
            let deadline = self.lived.get(&(end, 1)).map(|&l| l + wait);
            let judged = exempt || want == 0 || deadline.is_some_and(|d| self.now >= d);
            let (active, switched) = (self.active(end), self.seen.switched[end]);
            if let Err(e) = settled(want, exempt, deadline, self.now, active, switched) {
                self.fail(format!("{e}, at {end}, the ratio {ratio:.3}"));
            }
            if judged {
                self.seen.settled[end] += 1;
            }
        }
    }

    /// The wire preferred at both ends, read from each end's facts:
    /// `Some(None)` with no role set, `Some(Some(w))` with wire `w`
    /// preferred at both ends and no other role set, and `None` otherwise,
    /// when the **settle** oracle does not apply.
    fn favoured(&self) -> Option<Option<usize>> {
        let roles: Vec<[Role; 2]> = self
            .wires
            .iter()
            .map(|w| ENDS.map(|end| self.nodes[end].facts.role(w.ends[end].transport)))
            .collect();
        let normal = |w: usize| roles[w] == [Role::Normal; 2];
        if (0..roles.len()).all(normal) {
            return Some(None);
        }
        (0..roles.len())
            .find(|&w| {
                roles[w] == [Role::Preferred; 2] && (0..roles.len()).all(|o| o == w || normal(o))
            })
            .map(Some)
    }

    /// Fail the run, naming the seed, the instant and the oracle.
    fn fail(&self, what: String) -> ! {
        panic!("seed {:#x} at {} ms: {what}", self.seed, self.now);
    }
}

/// `d` in whole milliseconds.
fn ms(d: crate::time::Duration) -> u64 {
    d.as_millis() as u64
}

/// The tier of a transport whose role is `role`, by the oracles' own
/// reading of the draft (Section 5.5 and its note): never below backup,
/// backup below normal and preferred.
fn rung(role: Role) -> u8 {
    match role {
        Role::Never => 0,
        Role::Backup => 1,
        Role::Normal | Role::Preferred => 2,
    }
}

/// The **dwell** oracle on a discretionary switch at `now` to a path Live
/// since `since`, under a switch dwell of `dwell` milliseconds, from a path
/// whose transport's role is `from` to one whose role is `to`: the target
/// has been Live for the dwell, unless its tier is higher than the source's.
fn dwelt(
    now: u64,
    since: Option<u64>,
    dwell: u64,
    from: Option<Role>,
    to: Role,
) -> Result<(), String> {
    if from.is_some_and(|f| rung(to) > rung(f)) {
        return Ok(());
    }
    match since {
        Some(l) if now >= l + dwell => Ok(()),
        _ => Err(format!(
            "dwell: a discretionary switch at {now} ms to a path Live since {since:?} ms, under \
             a dwell of {dwell} ms"
        )),
    }
}

/// The **hold** oracle at `now`, under a switch dwell of `dwell`
/// milliseconds, on the cost `cost` that `Bundle::cost` gives for the
/// measured cost `live`: the cost held while `span` is in force, and
/// `live` otherwise.
fn holding(span: Option<Span>, now: u64, dwell: u64, live: f64, cost: f64) -> Result<(), String> {
    let want = span
        .filter(|s| s.force(now, dwell))
        .map_or(live, |s| s.cost);
    if cost.to_bits() == want.to_bits() {
        Ok(())
    } else {
        Err(format!(
            "hold: the cost at {now} ms is {cost}, not {want}, the measured cost {live}, the \
             hold {span:?}"
        ))
    }
}

/// The **settle** oracle's target wire from the wires' scores `s`, the
/// switch margin and the wire preferred at both ends, if any, with the
/// ratio that decides it.
fn aim(s: [f64; 2], margin: f64, preferred: Option<usize>) -> (usize, f64) {
    match preferred {
        None => (usize::from(s[0] > margin * s[1]), s[0] / s[1]),
        Some(w) => {
            let o = 1 - w;
            let on = if s[w] <= margin * s[o] { w } else { o };
            (on, s[w] / s[o])
        }
    }
}

/// The **settle** oracle at `now` on an end whose target wire is `want`,
/// which is on wire `active` and has switched `switched` times: with the
/// run exempt, at most one switch; with the first wire as target, none;
/// with the second, from `deadline` on, on it, having switched once.
fn settled(
    want: usize,
    exempt: bool,
    deadline: Option<u64>,
    now: u64,
    active: Option<usize>,
    switched: usize,
) -> Result<(), String> {
    let ok = if exempt {
        switched <= 1
    } else if want == 0 {
        switched == 0
    } else {
        deadline.is_none_or(|d| now < d) || (active == Some(1) && switched == 1)
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "settle: the target wire {want} (exempt {exempt}, deadline {deadline:?} ms), on wire \
             {active:?} at {now} ms after {switched} switches"
        ))
    }
}

/// One output for a trace, its slot named by its order in the run.
fn line(o: &Out, base: u64) -> String {
    match o {
        Output::Moved { from, to, driver } => {
            format!("Moved {from:?} to {to:?}, slot {}", driver - base)
        }
        Output::Released { to, driver, keep } => {
            format!("Released {to:?}, slot {}, keep {keep}", driver - base)
        }
        Output::Send { .. }
        | Output::State { .. }
        | Output::Capable
        | Output::NotCapable
        | Output::Refused { .. }
        | Output::Switched { .. }
        | Output::Orphaned
        | Output::Connect { .. }
        | Output::Proven { .. } => format!("{o:?}"),
    }
}

/// Seeds each test runs.
const SEEDS: u64 = 64;

/// Two simulated minutes, in milliseconds.
const MINUTES: u64 = 120_000;

/// A rule cutting wire `wire` from `from` (both ways when `None`) for
/// `[start, end)`.
fn cut(wire: usize, from: Option<usize>, start: u64, end: u64) -> Rule {
    Rule {
        wire,
        from,
        class: Class::All,
        start,
        end,
    }
}

/// The draft's settings with a switch margin no two paths reach, since
/// the simulator's scores lie between 1 and 300: an end changes its active
/// path only when that path fails.
fn steady() -> Config {
    Config {
        switch_margin: 1e6,
        ..Config::draft()
    }
}

/// The uneven shape for even seeds, the even shape for odd ones.
fn shape(seed: u64) -> Shape {
    if seed.is_multiple_of(2) {
        Shape::Uneven
    } else {
        Shape::Even
    }
}

#[test]
fn two_nodes_prove_every_path_at_both_ends_once_healed() {
    for seed in 0..SEEDS {
        let mut w = World::new(seed, Shape::Uneven, [0, 0]);
        let count = SplitMix64::mix(seed, &[TEST, 0]) % 4;
        w.flaps(count, 5_000, 50_000, 1_000, 30_000);
        w.run(MINUTES);
        for wire in 0..2 {
            assert!(w.seen.live[wire] > 0, "seed {seed}: the live oracle ran");
            for end in ENDS {
                assert_eq!(
                    w.path(end, wire).map(|(s, _)| s),
                    Some(PathState::Live),
                    "seed {seed}: {end}'s path for wire {wire} at the end"
                );
            }
        }
        // B holds both its paths on its one transport.
        let held = w.nodes[B].b.paths().paths();
        assert_eq!(held.len(), 2, "seed {seed}");
        assert!(held.iter().all(|p| p.transport_id() == t(1)), "seed {seed}");
    }
}

#[test]
fn a_failed_active_wire_moves_traffic_within_the_timeout_bound_at_both_ends() {
    for seed in 0..SEEDS {
        let mut w = World::tuned(seed, shape(seed), [0, 0], steady());
        let start = 10_000 + SplitMix64::mix(seed, &[TEST, 1]) % 20_000;
        let end = start + 5_000 + SplitMix64::mix(seed, &[TEST, 2]) % 35_000;
        w.rules.push(cut(0, None, start, end));
        w.run(start - 1);
        assert_eq!(w.active(A), Some(0), "seed {seed}");
        assert_eq!(w.active(B), Some(0), "seed {seed}");
        w.run(MINUTES);
        assert_eq!(w.seen.armed, [1, 1], "seed {seed}: both ends waited for");
        assert_eq!(w.seen.met, [1, 1], "seed {seed}: both ends switched");
        assert_eq!(w.active(A), Some(1), "seed {seed}");
        assert_eq!(w.active(B), Some(1), "seed {seed}");
    }
}

#[test]
fn a_failure_in_one_direction_moves_traffic_while_the_peers_frames_still_arrive() {
    for seed in 0..SEEDS {
        let mut w = World::tuned(seed, shape(seed), [0, 0], steady());
        let start = 10_000 + SplitMix64::mix(seed, &[TEST, 1]) % 20_000;
        let end = start + 5_000 + SplitMix64::mix(seed, &[TEST, 2]) % 35_000;
        // The end whose frames are dropped, which still hears its peer.
        let mute = ENDS[(seed / 2 % 2) as usize];
        let peer = 1 - mute;
        w.rules.push(cut(0, Some(mute), start, end));
        w.run(start);
        let before = w.wires[0].delivered[mute];
        let by = start + w.detect(w.wires[0].worst(), false);
        w.run(by);
        assert!(
            w.wires[0].delivered[mute] > before,
            "seed {seed}: {mute} still hears {peer} on the cut wire"
        );
        w.run(MINUTES);
        assert_eq!(w.seen.armed, [1, 1], "seed {seed}: both ends waited for");
        assert_eq!(w.seen.met, [1, 1], "seed {seed}: both ends switched");
    }
}

#[test]
fn the_receive_counts_of_each_path_match_the_frames_its_wire_delivered() {
    for seed in 0..SEEDS {
        let mut w = World::new(seed, Shape::Uneven, [0, 0]);
        // Cut the first wire for a while, so data runs on each in turn.
        let start = 10_000 + SplitMix64::mix(seed, &[TEST, 1]) % 10_000;
        w.rules.push(cut(0, None, start, start + 20_000));
        w.flaps(2, 60_000, 80_000, 1_000, 10_000);
        w.run(MINUTES);
        for wire in 0..2 {
            assert!(w.seen.compared[wire] > 100, "seed {seed}: wire {wire}");
            assert!(
                w.seen.wide[wire] > 0,
                "seed {seed}: data counted between probes on wire {wire}"
            );
        }
    }
}

#[test]
fn a_run_replays_byte_for_byte_from_its_seed() {
    let trace = |seed: u64| {
        let mut w = World::new(seed, shape(seed), [0, 20]).traced();
        w.flaps(3, 5_000, 40_000, 1_000, 20_000);
        w.run(60_000);
        w.trace.unwrap_or_default()
    };
    let mut last = String::new();
    for seed in 0..SEEDS {
        let first = trace(seed);
        assert!(
            first.lines().count() > 1000,
            "seed {seed}: the trace records events"
        );
        assert!(first == trace(seed), "seed {seed}: the replay differs");
        assert!(first != last, "seed {seed}: the trace depends on the seed");
        last = first;
    }
}

#[test]
fn a_first_round_lost_on_the_original_wire_is_recovered_by_the_backoff() {
    for seed in 0..SEEDS {
        // Probes are dropped on the original wire both ways from the start
        // to a seeded instant 25 to 60 seconds in, past the first round's
        // three probes and its timeout.
        let heal = 25_000 + SplitMix64::mix(seed, &[TEST, 4]) % 35_001;
        let lost = Rule {
            wire: 0,
            from: None,
            class: Class::Probe,
            start: 0,
            end: heal,
        };
        let first = ENDS[(seed / 2 % 2) as usize];
        let rules = alloc::vec![lost];
        let mut w = World::make(
            seed,
            shape(seed),
            [0, 0],
            rules,
            None,
            &[first],
            Config::draft(),
        );
        w.run(3 * MINUTES / 2);
        let mut told = [0; 2];
        told[first] = 1;
        assert_eq!(
            w.seen.told, told,
            "seed {seed}: the first round went unanswered at the end that asked"
        );
        assert!(
            w.asked[first].len() > usize::from(w.cfg.budget),
            "seed {seed}: capability probes after the first round"
        );
        assert!(
            w.seen.awaited[first] > 0,
            "seed {seed}: the capable oracle ran"
        );
        for end in ENDS {
            let at = w.capable[end].expect("capable");
            assert!(
                at >= heal,
                "seed {seed}: {end} capable at {at} ms, before {heal} ms"
            );
        }
        assert!(w.seen.live[1] > 0, "seed {seed}: the live oracle ran");
        for wire in 0..2 {
            for end in ENDS {
                assert_eq!(
                    w.path(end, wire).map(|(s, _)| s),
                    Some(PathState::Live),
                    "seed {seed}: {end}'s path for wire {wire} at the end"
                );
            }
        }
    }
}

#[test]
fn a_wire_of_another_class_never_becomes_a_path_at_the_end_that_refuses_it() {
    for seed in 0..SEEDS {
        let marked = ENDS[(seed % 2) as usize];
        // In the uneven shape B's second wire is on the transport of its
        // original pair, so only A's can be marked there.
        let shape = if marked == A && (seed / 2).is_multiple_of(2) {
            Shape::Uneven
        } else {
            Shape::Even
        };
        let fact = match seed / 4 % 3 {
            0 => Fact::Class(crate::proto::path::Class::Tor),
            1 => Fact::Class(crate::proto::path::Class::Nym),
            _ => Fact::Role(Role::Never),
        };
        let mut w = World::marked(seed, shape, marked, fact);
        w.run(MINUTES);
        let other = 1 - marked;
        assert!(
            w.seen.marked > 0,
            "seed {seed}: {other} probed the marked wire"
        );
        assert!(
            w.seen.refused > 1,
            "seed {seed}: {marked} refused it and its probes"
        );
        assert_eq!(w.seen.told, [0, 0], "seed {seed}");
        assert!(
            w.seen.awaited[other] > 0,
            "seed {seed}: the capable oracle ran"
        );
        assert!(
            w.asked[marked].is_empty(),
            "seed {seed}: {marked} held no candidate that allows a capability probe"
        );
        for end in ENDS {
            assert!(w.capable[end].is_some(), "seed {seed}: {end} capable");
            assert_eq!(
                w.path(end, 0).map(|(s, _)| s),
                Some(PathState::Live),
                "seed {seed}: {end}'s original path at the end"
            );
        }
        assert!(
            w.path(other, 1).is_some(),
            "seed {seed}: {other} still holds its probed path on the marked wire"
        );
    }
}

#[test]
fn without_faults_each_end_settles_on_the_wire_better_by_the_margin_or_stays() {
    let mut exempt = 0;
    let mut aims = [0; 2];
    let mut dwelt = 0;
    for seed in 0..SEEDS {
        let mut w = World::new(seed, shape(seed), [0, 0]);
        w.run(MINUTES);
        for end in ENDS {
            assert!(
                w.seen.settled[end] > 0,
                "seed {seed}: the settle oracle judged {end}"
            );
        }
        exempt += usize::from(w.seen.exempt);
        if let Some(wire) = w.seen.aim {
            aims[wire] += 1;
        }
        dwelt += w.seen.dwelt[A] + w.seen.dwelt[B];
    }
    assert!(exempt < 4, "{exempt} seeds within 0.01 of the margin");
    assert!(
        aims.iter().all(|&n| n > 0),
        "seeds whose target is each wire: {aims:?}"
    );
    assert!(dwelt > 0, "the dwell oracle checked a switch");
}

#[test]
fn a_preferred_wire_carries_the_link_at_both_ends_in_both_orders() {
    let mut carried = [0; 2];
    for seed in 0..SEEDS {
        // Half the seeds prefer the original wire, half the second.
        let preferred = (seed % 2) as usize;
        let mut w = World::new(seed, Shape::Even, [0, 0])
            .role(A, preferred, Role::Preferred)
            .role(B, preferred, Role::Preferred);
        w.run(MINUTES);
        for end in ENDS {
            assert!(
                w.seen.settled[end] > 0,
                "seed {seed}: the settle oracle judged {end}"
            );
        }
        if w.seen.aim == Some(preferred) {
            for end in ENDS {
                assert_eq!(w.active(end), Some(preferred), "seed {seed}: {end}");
            }
            carried[preferred] += 1;
        }
    }
    assert!(
        carried.iter().all(|&n| n > 0),
        "seeds whose preferred wire carried the link, by wire: {carried:?}"
    );
}

#[test]
fn the_cost_seen_by_the_tree_is_held_across_every_switch() {
    let mut decided = [0; 2];
    let mut held = 0;
    for seed in 0..SEEDS {
        let mut w = World::new(seed, shape(seed), [0, 0]);
        // The original wire cut both ways or in one direction, as in the
        // switch tests, then flaps on either wire.
        let start = 10_000 + SplitMix64::mix(seed, &[TEST, 1]) % 20_000;
        let end = start + 5_000 + SplitMix64::mix(seed, &[TEST, 2]) % 35_000;
        let from = match seed % 3 {
            0 => None,
            1 => Some(A),
            _ => Some(B),
        };
        w.rules.push(cut(0, from, start, end));
        w.flaps(2, 60_000, 100_000, 1_000, 10_000);
        w.run(MINUTES);
        for end in ENDS {
            if w.seen.switched[end] > 0 {
                assert!(
                    w.seen.held[end] > 0,
                    "seed {seed}: the hold oracle checked {end}'s switches"
                );
            }
        }
        held += w.seen.held[A] + w.seen.held[B];
        decided[0] += w.seen.decided[0];
        decided[1] += w.seen.decided[1];
    }
    assert!(held >= SEEDS as usize, "{held} holds checked");
    assert!(
        decided.iter().all(|&n| n > 0),
        "holds ended by the dwell and by the reports: {decided:?}"
    );
}

#[test]
fn each_selection_oracle_fires_on_a_planted_breach() {
    let named = |r: Result<(), String>, oracle: &str| {
        let e = r.expect_err("the oracle fires");
        assert!(e.starts_with(oracle), "{e}");
    };
    // A switch between paths of one tier to a path Live for 1,999 ms.
    let normal = Some(Role::Normal);
    named(
        dwelt(3_999, Some(2_000), 2_000, normal, Role::Normal),
        "dwell:",
    );
    named(dwelt(3_999, None, 2_000, normal, Role::Normal), "dwell:");
    assert_eq!(
        dwelt(4_000, Some(2_000), 2_000, normal, Role::Normal),
        Ok(())
    );
    // The same switch from a backup path to a normal one gives way at once.
    let backup = Some(Role::Backup);
    assert_eq!(
        dwelt(3_999, Some(2_000), 2_000, backup, Role::Normal),
        Ok(())
    );
    // An end still on the worse wire at its settle deadline.
    named(settled(1, false, Some(5_000), 5_000, Some(0), 0), "settle:");
    named(settled(0, false, None, 5_000, Some(1), 1), "settle:");
    assert_eq!(settled(1, false, Some(5_000), 4_999, Some(0), 0), Ok(()));
    assert_eq!(settled(1, false, Some(5_000), 5_000, Some(1), 1), Ok(()));
    // A cost that changes in the step after a switch, one report stepped,
    // and again once the dwell has passed with the second still owed.
    let span = Some(Span {
        cost: 1.5,
        at: 1_000,
        reports: 1,
        checked: false,
    });
    named(holding(span, 1_100, 2_000, 3.0, 3.0), "hold:");
    named(holding(span, 3_100, 2_000, 3.0, 3.0), "hold:");
    assert_eq!(holding(span, 3_100, 2_000, 3.0, 1.5), Ok(()));
    let paid = span.map(|s| Span { reports: 2, ..s });
    assert_eq!(holding(paid, 3_000, 2_000, 3.0, 3.0), Ok(()));
}

#[cfg(feature = "slow-tests")]
#[test]
fn hours_of_seeded_loss_and_flaps_keep_every_oracle() {
    const HOUR: u64 = 3_600_000;
    let mut armed = 0;
    for seed in 0..50 {
        let mut g = SplitMix64::new(SplitMix64::mix(seed, &[TEST, 3]));
        // Half the runs lose up to 3% of the datagrams on one wire.
        let mut loss = [0, 0];
        if g.chance(500) {
            loss[g.below(2) as usize] = 1 + g.below(30);
        }
        let mut w = World::new(seed, shape(seed), loss);
        w.churn(HOUR - 1_000_000);
        w.run(HOUR);
        assert_eq!(w.seen.met, w.seen.armed, "seed {seed}: every switch came");
        assert!(
            w.seen.compared.iter().sum::<usize>() > 0,
            "seed {seed}: counts ran"
        );
        assert!(
            w.seen.live.iter().sum::<usize>() > 0,
            "seed {seed}: live ran"
        );
        armed += w.seen.armed[A] + w.seen.armed[B];
    }
    assert!(armed > 50, "the switch oracle ran {armed} times");
}

#[test]
fn a_return_to_the_original_wire_meets_the_dwell_oracle() {
    let mut returned = 0;
    for seed in 0..SEEDS {
        let mut w = World::new(seed, Shape::Even, [0, 0])
            .role(A, 1, Role::Preferred)
            .role(B, 1, Role::Preferred);
        // A rule outside the run, so the settle oracle stands aside.
        w.rules.push(cut(1, None, 10 * MINUTES, 10 * MINUTES + 1));
        w.run(MINUTES / 2);
        if !ENDS.iter().all(|&e| w.active(e) == Some(1)) {
            continue;
        }
        assert!(
            ENDS.iter()
                .all(|&e| w.lived.get(&(e, 0)).is_none_or(|&l| l == 0)),
            "seed {seed}: wire 0 left Live"
        );
        // The original wire turns preferred and the second normal at both
        // ends, so an end whose original wire scores within the margin of
        // the second goes back to it after the dwell, the original wire
        // Live since the start.
        for end in ENDS {
            let [zero, one] = [0, 1].map(|wire| w.wires[wire].ends[end].transport);
            w.nodes[end].facts.change(zero, Fact::Role(Role::Preferred));
            w.nodes[end].facts.change(one, Fact::Role(Role::Normal));
        }
        w.run(MINUTES);
        if ENDS.iter().all(|&e| w.active(e) == Some(0)) {
            returned += 1;
        }
    }
    assert!(returned > 0, "a seed moved both ends back to wire 0");
}
