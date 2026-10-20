//! Executable models of the deployed releases, and the interop simulation of
//! new nodes against them.
//!
//! A deployed peer cannot be changed, so a new node must interoperate with
//! what each release actually does. `fmp.rs` and `fsp.rs` model the link and
//! session rekey of v0.5.0 to v0.5.3 (0.5.0 and 0.5.1 share every rekey
//! file, so one model stands for both), each rule citing the tagged lines it
//! implements. They run on real Noise handshakes and the real wire codecs,
//! so a new node built on the production profiles (`new.rs`) exchanges
//! byte-identical messages with them. [`Duo`] connects two endpoints, new or
//! modelled, over a channel whose faults are scripted per message class,
//! drives them on the shell's 1 s tick (and a new node also at its next
//! wake), and accounts for every data frame: one the channel delivered that
//! the receiver did not accept is lost, and the outage per direction is the
//! span of the lost frames' send times.
//!
//! The traces run in the files of the two layers, each against every
//! release in each role it involves.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::fmp::rekey::ik::FmpIk;
use crate::proto::fsp::rekey::xk::FspXk;
use crate::testutil::{SeededEntropy, SplitMix64};

mod explore;
mod fmp;
mod fsp;
pub(crate) mod new;

/// The entropy every endpoint of a simulation draws from, seeded per run.
pub(crate) type E = SeededEntropy;
/// The production link profile on the seeded entropy.
pub(crate) type Ik = FmpIk<E>;
/// The production session profile on the seeded entropy.
pub(crate) type Xk = FspXk<E>;

/// A deployed release, as its rekey code distinguishes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rel {
    /// v0.5.0 and v0.5.1 (`80f8f965`, `c5aeef39`): no rekey file differs
    /// between the two tags.
    V050,
    /// v0.5.2 (`53a3ec4b`).
    V052,
    /// v0.5.3 (`f4a5b4a8`).
    V053,
}

impl Rel {
    /// Every release a new node must interoperate with.
    pub(crate) const ALL: [Rel; 3] = [Rel::V050, Rel::V052, Rel::V053];
}

/// What crosses the channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Pkt {
    /// A framed link packet: a msg1, a msg2 or an established frame.
    Link(Vec<u8>),
    /// The Noise XK msg1 a `SessionSetup` carries.
    Setup(Vec<u8>),
    /// The Noise XK msg2 a `SessionAck` carries.
    Ack(Vec<u8>),
    /// The Noise XK msg3 a `SessionMsg3` carries.
    Msg3(Vec<u8>),
    /// An encrypted session message: the 12-byte header and the ciphertext.
    Frame(Vec<u8>),
}

/// What a sent packet is, as the sender labels it, for scripted faults and
/// assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// An IK msg1.
    Msg1,
    /// An IK msg2.
    Msg2,
    /// An XK setup.
    Setup,
    /// An XK ack.
    Ack,
    /// An XK msg3.
    Msg3,
    /// An application data frame.
    Data,
    /// A new node's prompt or keepalive, under its current epoch.
    Prompt,
    /// A new node's probe, under its pending epoch.
    Probe,
    /// Any other frame: a heartbeat, a deployed node's report.
    Ctl,
}

/// One packet an endpoint sends, labelled.
#[derive(Clone, Debug)]
pub(crate) struct Out {
    pub(crate) pkt: Pkt,
    pub(crate) class: Class,
}

impl Out {
    /// A labelled packet.
    pub(crate) fn new(pkt: Pkt, class: Class) -> Self {
        Self { pkt, class }
    }
}

/// What a receiver did with a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Got {
    /// A data frame was accepted, under the receiver's current epoch or not.
    Data {
        /// It authenticated under the current epoch.
        current: bool,
    },
    /// A frame was accepted that is not data.
    Frame,
    /// A frame was not accepted.
    Refused,
    /// A handshake message, or nothing to report.
    Other,
}

/// One end of a simulated link or session: a new node or a deployed model.
pub(crate) trait End {
    /// The shell's tick: a deployed node's periodic work, a new node's poll.
    fn tick(&mut self, now: u64, out: &mut Vec<Out>);
    /// A packet from the other end.
    fn recv(&mut self, now: u64, pkt: &Pkt, out: &mut Vec<Out>) -> Got;
    /// Seal data frame `seq` under the current epoch, if there is one.
    fn data(&mut self, now: u64, seq: u64, out: &mut Vec<Out>) -> bool;
    /// When the end next has timed work beside its tick (a new node's next
    /// wake), if ever.
    fn wake(&self) -> Option<u64>;
    /// Whether the end holds a link or session to the other at all.
    fn alive(&self) -> bool;
    /// Whether no rekey is in flight or pending (an own attempt, a held
    /// completion or a deployed handshake awaiting its peer).
    fn quiet(&self) -> bool;
    /// Outcomes since the last call, as text, for trace assertions.
    fn take_notes(&mut self) -> Vec<String>;
    /// A short name for the log.
    fn name(&self) -> String;
    /// The node restarts with startup epoch `epoch`, losing every peer
    /// state; only a deployed model supports it.
    fn restart(&mut self, epoch: [u8; 8]) {
        let _ = epoch;
        panic!("{} cannot restart", self.name());
    }
    /// A session to the peer is wanted at `now`; only a session end
    /// supports it.
    fn open(&mut self, now: u64, out: &mut Vec<Out>) {
        let _ = (now, out);
        panic!("{} cannot open a session", self.name());
    }
    /// A setup naming the peer arrives from third party `n` over a link of
    /// its own (stranger 0 over the peer's own link); only a new session end
    /// supports it.
    fn stranger(&mut self, now: u64, n: u8, out: &mut Vec<Out>) {
        let _ = (now, n, out);
        panic!("{} takes no stranger's setup", self.name());
    }
    /// What the end can check about its own resources at any instant (a
    /// new link node's index map against its machine and pool).
    fn check(&self) -> Result<(), String> {
        Ok(())
    }
    /// End the run: check what the end can check about its own resources
    /// (a new link node's index map against its machine and pool) and close
    /// it, releasing them.
    fn finish(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// What a scripted rule does to the packets it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fate {
    /// Lose it.
    Drop,
    /// Deliver it this many milliseconds late.
    Delay(u64),
}

/// A scripted fault: packets of `class` sent by `from` in `[since, until)`,
/// from the `skip`-th match on, at most `count` of them.
#[derive(Clone, Debug)]
pub(crate) struct Rule {
    pub(crate) from: usize,
    pub(crate) class: Class,
    pub(crate) since: u64,
    pub(crate) until: u64,
    pub(crate) skip: usize,
    pub(crate) count: usize,
    pub(crate) fate: Fate,
    /// The rule ends once its sender sends a packet of this class.
    pub(crate) stop: Option<Class>,
    matched: usize,
}

impl Rule {
    /// Drop every packet of `class` from `from` in `[since, until)`.
    pub(crate) fn drop(from: usize, class: Class, since: u64, until: u64) -> Self {
        Self {
            from,
            class,
            since,
            until,
            skip: 0,
            count: usize::MAX,
            fate: Fate::Drop,
            stop: None,
            matched: 0,
        }
    }

    /// Drop every packet of `class` from `from` until it sends a packet of
    /// class `stop`.
    pub(crate) fn until_sent(from: usize, class: Class, stop: Class) -> Self {
        Self {
            stop: Some(stop),
            ..Self::drop(from, class, 0, u64::MAX)
        }
    }

    /// Drop the first `count` packets of `class` from `from` sent at or
    /// after `since`.
    pub(crate) fn first(from: usize, class: Class, since: u64, count: usize) -> Self {
        Self {
            count,
            ..Self::drop(from, class, since, u64::MAX)
        }
    }

    /// Delay every packet of `class` from `from` in `[since, until)` by `ms`.
    pub(crate) fn delay(from: usize, class: Class, since: u64, until: u64, ms: u64) -> Self {
        Self {
            fate: Fate::Delay(ms),
            ..Self::drop(from, class, since, until)
        }
    }

    /// What this rule does to a packet of `class` from `from` sent at `now`,
    /// counting the match.
    fn apply(&mut self, from: usize, class: Class, now: u64) -> Option<Fate> {
        if from == self.from && Some(class) == self.stop {
            self.until = now;
        }
        if from != self.from || class != self.class || now < self.since || now >= self.until {
            return None;
        }
        let n = self.matched;
        self.matched += 1;
        (n >= self.skip && n - self.skip < self.count).then_some(self.fate)
    }
}

/// A packet in flight.
#[derive(Clone, Debug)]
struct Flight {
    id: u64,
    at: u64,
    from: usize,
    sent: u64,
    out: Out,
}

/// Two endpoints and the channel between them.
pub(crate) struct Duo {
    pub(crate) n: [Box<dyn End>; 2],
    pub(crate) now: u64,
    flight: Vec<Flight>,
    next_id: u64,
    /// Scripted faults.
    pub(crate) rules: Vec<Rule>,
    /// One-way latency of packets from each end, in milliseconds.
    pub(crate) lat: [u64; 2],
    /// Each end's data period; `None` for a silent end.
    pub(crate) period: [Option<u64>; 2],
    next_data: [u64; 2],
    /// Each end's tick phase within the second.
    pub(crate) phase: [u64; 2],
    /// A window in which each end sends no data, if any.
    pub(crate) hush: [Option<(u64, u64)>; 2],
    seq: u64,
    /// Send times of each end's data frames the other did not accept.
    pub(crate) lost: [Vec<u64>; 2],
    /// Each end's data frames the other accepted.
    pub(crate) got: [usize; 2],
    /// Each end's packets as sent, with their send instant.
    pub(crate) sent: [Vec<(u64, Class)>; 2],
    /// Each end's packets as delivered to the other, with what it did.
    pub(crate) recv: [Vec<(u64, Class, Got)>; 2],
    /// Every note the ends reported, with its instant and end.
    pub(crate) notes: Vec<(u64, usize, String)>,
    /// Random loss per mille, per direction, when seeded.
    pub(crate) loss: [u64; 2],
    rng: Option<SplitMix64>,
    /// Packets stay in flight until an explorer delivers them.
    held: bool,
}

impl Duo {
    /// Two endpoints, 50 ms apart each way, both sending data every second,
    /// ticking half a second out of phase.
    pub(crate) fn new(a: Box<dyn End>, b: Box<dyn End>, now: u64) -> Self {
        Self {
            n: [a, b],
            now,
            flight: Vec::new(),
            next_id: 0,
            rules: Vec::new(),
            lat: [50, 50],
            period: [Some(1_000), Some(1_000)],
            next_data: [now + 300, now + 800],
            phase: [0, 500],
            hush: [None, None],
            seq: 0,
            lost: [Vec::new(), Vec::new()],
            got: [0, 0],
            sent: [Vec::new(), Vec::new()],
            recv: [Vec::new(), Vec::new()],
            notes: Vec::new(),
            loss: [0, 0],
            rng: None,
            held: false,
        }
    }

    /// Draw random loss from `seed` at `loss` per mille in each direction.
    pub(crate) fn seeded(mut self, seed: u64, loss: u64) -> Self {
        self.rng = Some(SplitMix64::new(seed));
        self.loss = [loss, loss];
        self
    }

    /// Put `outs` from end `from` on the channel at `now`.
    fn push(&mut self, from: usize, outs: Vec<Out>) {
        for out in outs {
            self.sent[from].push((self.now, out.class));
            let mut at = Some(self.now + self.lat[from]);
            for r in &mut self.rules {
                match r.apply(from, out.class, self.now) {
                    Some(Fate::Drop) => at = None,
                    Some(Fate::Delay(ms)) => at = at.map(|t| t + ms),
                    None => {}
                }
            }
            if let Some(g) = self.rng.as_mut()
                && g.chance(self.loss[from])
            {
                at = None;
            }
            if self.held {
                at = Some(u64::MAX);
            }
            let id = self.next_id;
            self.next_id += 1;
            if let Some(at) = at {
                self.flight.push(Flight {
                    id,
                    at,
                    from,
                    sent: self.now,
                    out,
                });
            }
        }
    }

    /// Collect a note list from end `x` into the run's notes.
    fn gather(&mut self, x: usize) {
        for note in self.n[x].take_notes() {
            self.notes.push((self.now, x, note));
        }
    }

    /// The next instant anything happens, if before `end`.
    fn next_event(&self, end: u64) -> Option<u64> {
        let mut t = end;
        for f in &self.flight {
            t = t.min(f.at);
        }
        for x in 0..2 {
            let tick = next_tick(self.now, self.phase[x]);
            t = t.min(tick);
            if self.period[x].is_some() {
                t = t.min(self.next_data[x]);
            }
            if let Some(w) = self.n[x].wake() {
                t = t.min(w.max(self.now));
            }
        }
        (t < end).then_some(t)
    }

    /// Hand a packet in flight to its receiver now and account for it.
    fn deliver(&mut self, f: Flight) {
        let to = 1 - f.from;
        let mut outs = Vec::new();
        let got = self.n[to].recv(self.now, &f.out.pkt, &mut outs);
        self.recv[to].push((self.now, f.out.class, got));
        if f.out.class == Class::Data {
            match got {
                Got::Data { .. } => self.got[f.from] += 1,
                Got::Refused | Got::Frame | Got::Other => self.lost[f.from].push(f.sent),
            }
        }
        self.gather(to);
        self.push(to, outs);
    }

    /// Run until `end`: deliveries first at each instant, then data sends,
    /// then ticks and wakes.
    pub(crate) fn run_until(&mut self, end: u64) {
        self.run_to(end, None);
    }

    /// As [`Duo::run_until`], but stop after the first instant at which
    /// either end sent a packet of a class `stop` names; whether it did.
    pub(crate) fn run_to(&mut self, end: u64, stop: Option<fn(Class) -> bool>) -> bool {
        let mut guard = 0u64;
        while let Some(t) = self.next_event(end) {
            guard += 1;
            assert!(
                guard < 5_000_000,
                "the run does not progress at {}",
                self.now
            );
            let marks = [self.sent[0].len(), self.sent[1].len()];
            self.now = t;
            self.flight.sort_by_key(|f| (f.at, f.id));
            while let Some(i) = self.flight.iter().position(|f| f.at <= self.now) {
                let f = self.flight.remove(i);
                self.deliver(f);
            }
            for x in 0..2 {
                let hushed = self.hush[x].is_some_and(|(a, b)| self.now >= a && self.now < b);
                if let Some(p) = self.period[x]
                    && self.next_data[x] <= self.now
                {
                    self.next_data[x] = self.now + p;
                    if hushed {
                        continue;
                    }
                    self.seq += 1;
                    let mut outs = Vec::new();
                    if self.n[x].data(self.now, self.seq, &mut outs) {
                        self.gather(x);
                        self.push(x, outs);
                    }
                }
            }
            for x in 0..2 {
                let ticked = self.now % 1_000 == self.phase[x];
                let woken = self.n[x].wake().is_some_and(|w| w <= self.now);
                if ticked || woken {
                    let mut outs = Vec::new();
                    self.n[x].tick(self.now, &mut outs);
                    self.gather(x);
                    self.push(x, outs);
                }
            }
            if let Some(stop) = stop {
                let hit = (0..2).any(|x| self.sent[x][marks[x]..].iter().any(|s| stop(s.1)));
                if hit {
                    return true;
                }
            }
        }
        self.now = self.now.max(end);
        false
    }

    /// Hold every packet, those in flight now included, until it is
    /// delivered by [`Duo::deliver_now`], and stop the periodic data: from
    /// here on an explorer chooses every event.
    pub(crate) fn hold(&mut self) {
        self.held = true;
        self.period = [None, None];
        for f in &mut self.flight {
            f.at = u64::MAX;
        }
    }

    /// End holding: whatever is still in flight is lost, and both ends send
    /// data every second again.
    pub(crate) fn release(&mut self) {
        self.held = false;
        self.flight.clear();
        self.period = [Some(1_000), Some(1_000)];
        self.next_data = [self.now + 300, self.now + 800];
    }

    /// The packets in flight: id, sender and class.
    pub(crate) fn in_flight(&self) -> Vec<(u64, usize, Class)> {
        self.flight
            .iter()
            .map(|f| (f.id, f.from, f.out.class))
            .collect()
    }

    /// Deliver the packet `id` now, if it is in flight.
    pub(crate) fn deliver_now(&mut self, id: u64) {
        if let Some(i) = self.flight.iter().position(|f| f.id == id) {
            let f = self.flight.remove(i);
            self.deliver(f);
        }
    }

    /// Put a second copy of packet `id` in flight.
    pub(crate) fn copy(&mut self, id: u64) {
        if let Some(f) = self.flight.iter().find(|f| f.id == id).cloned() {
            let id = self.next_id;
            self.next_id += 1;
            self.flight.push(Flight { id, ..f });
        }
    }

    /// Advance to the next instant either end ticks or wakes, and run it;
    /// held packets stay in flight.
    pub(crate) fn advance(&mut self) {
        if let Some(t) = self.next_event(u64::MAX) {
            self.run_until(t + 1);
        }
    }

    /// End `x` seals a data frame now, if it can.
    pub(crate) fn send_data(&mut self, x: usize) {
        self.seq += 1;
        let seq = self.seq;
        self.act(x, |end, now, out| {
            end.data(now, seq, out);
        });
    }

    /// Run a scripted action on end `x` now and send what it sends.
    pub(crate) fn act(&mut self, x: usize, f: impl FnOnce(&mut dyn End, u64, &mut Vec<Out>)) {
        let mut outs = Vec::new();
        let now = self.now;
        f(self.n[x].as_mut(), now, &mut outs);
        self.gather(x);
        self.push(x, outs);
    }

    /// The span of end `x`'s lost data frames, from the first's send to the
    /// last's plus one data period; 0 when none was lost.
    pub(crate) fn outage(&self, x: usize) -> u64 {
        match (self.lost[x].first(), self.lost[x].last()) {
            (Some(a), Some(b)) => b - a + self.period[x].unwrap_or(1_000),
            (None, _) | (_, None) => 0,
        }
    }

    /// Whether both ends hold the same current epoch: each is alive (and,
    /// when `quiet`, has nothing in flight), and a data frame each way,
    /// delivered at once, is accepted under the receiver's current epoch.
    pub(crate) fn converged(&mut self, quiet: bool) -> Result<(), String> {
        for x in 0..2 {
            if !self.n[x].alive() {
                return Err(format!("{} holds no link or session", self.n[x].name()));
            }
            if quiet && !self.n[x].quiet() {
                return Err(format!("{} still has a rekey in flight", self.n[x].name()));
            }
        }
        for x in 0..2 {
            self.seq += 1;
            let mut outs = Vec::new();
            if !self.n[x].data(self.now, self.seq, &mut outs) {
                return Err(format!("{} cannot seal", self.n[x].name()));
            }
            self.gather(x);
            let to = 1 - x;
            let mut ignored = Vec::new();
            for out in outs.into_iter().filter(|o| o.class == Class::Data) {
                let got = self.n[to].recv(self.now, &out.pkt, &mut ignored);
                self.gather(to);
                if got != (Got::Data { current: true }) {
                    return Err(format!(
                        "{}'s data was {got:?} at {}",
                        self.n[x].name(),
                        self.n[to].name()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether end `x` reported a note containing `text`.
    pub(crate) fn noted(&self, x: usize, text: &str) -> bool {
        self.notes
            .iter()
            .any(|(_, y, n)| *y == x && n.contains(text))
    }

    /// The notes, for a failure message.
    pub(crate) fn transcript(&self) -> String {
        let mut s = String::new();
        for (t, x, n) in &self.notes {
            s.push_str(&format!("{t:>8} n{x} {n}\n"));
        }
        s
    }
}

/// The first instant after `now` at which an end ticking at `phase` within
/// each second ticks.
fn next_tick(now: u64, phase: u64) -> u64 {
    let base = now - now % 1_000 + phase;
    if base > now { base } else { base + 1_000 }
}

/// A trace's expectation, checked after it ran and healed.
pub(crate) struct Expect {
    /// The longest outage allowed from each end, in milliseconds.
    pub(crate) outage: [u64; 2],
    /// Notes each end must have reported.
    pub(crate) must: Vec<(usize, &'static str)>,
    /// Notes each end must not have reported.
    pub(crate) never: Vec<(usize, &'static str)>,
    /// The trace ends with the link removed at one end (an accepted
    /// residual a deployed peer causes), instead of converged.
    pub(crate) split: bool,
    /// Either outcome is allowed: converged, or the link removed at one
    /// end.
    pub(crate) either: bool,
    /// Rotation may stay stopped (a deployed peer's own rekey that never
    /// retires): convergence asks only that data flows on one epoch.
    pub(crate) stall: bool,
    /// Ends that must have accepted a data frame under an epoch other than
    /// their current one.
    pub(crate) previous: Vec<usize>,
}

impl Expect {
    /// No frame lost either way, no note required.
    pub(crate) fn lossless() -> Self {
        Self {
            outage: [0, 0],
            must: Vec::new(),
            never: Vec::new(),
            split: false,
            either: false,
            stall: false,
            previous: Vec::new(),
        }
    }

    /// Require end `x` to accept a data frame under a drained epoch.
    pub(crate) fn delivers_previous(mut self, x: usize) -> Self {
        self.previous.push(x);
        self
    }

    /// Allow rotation to stay stopped by a deployed peer's stuck rekey.
    pub(crate) fn stall_ok(mut self) -> Self {
        self.stall = true;
        self
    }

    /// Allow the link removed at one end in place of convergence.
    pub(crate) fn maybe_split(mut self) -> Self {
        self.either = true;
        self
    }

    /// Expect the link removed at one end instead of converged.
    pub(crate) fn split(mut self) -> Self {
        self.split = true;
        self
    }

    /// Require end `x` to report a note containing `text`.
    pub(crate) fn must(mut self, x: usize, text: &'static str) -> Self {
        self.must.push((x, text));
        self
    }

    /// Forbid end `x` a note containing `text`.
    pub(crate) fn never(mut self, x: usize, text: &'static str) -> Self {
        self.never.push((x, text));
        self
    }

    /// Allow end `x` an outage of up to `ms`.
    pub(crate) fn outage(mut self, x: usize, ms: u64) -> Self {
        self.outage[x] = ms;
        self
    }

    /// Check `duo` against the expectation, healing it for `heal` ms first.
    pub(crate) fn check(&self, name: &str, duo: &mut Duo, heal: u64) -> Result<(), String> {
        duo.rules.clear();
        duo.loss = [0, 0];
        let end = duo.now + heal;
        duo.run_until(end);
        let fail = |what: String, duo: &Duo| Err(format!("{name}: {what}\n{}", duo.transcript()));
        for x in 0..2 {
            let o = duo.outage(x);
            if o > self.outage[x] {
                return fail(
                    format!(
                        "{} lost data for {o} ms (allowed {}), first lost frame sent at {:?}",
                        duo.n[x].name(),
                        self.outage[x],
                        duo.lost[x].first()
                    ),
                    duo,
                );
            }
        }
        for (x, text) in &self.must {
            if !duo.noted(*x, text) {
                return fail(format!("n{x} never reported {text:?}"), duo);
            }
        }
        for x in &self.previous {
            let any = duo.recv[*x]
                .iter()
                .any(|r| r.1 == Class::Data && r.2 == (Got::Data { current: false }));
            if !any {
                return fail(
                    format!("n{x} accepted no data frame under a drained epoch"),
                    duo,
                );
            }
        }
        for (x, text) in &self.never {
            if duo.noted(*x, text) {
                return fail(format!("n{x} reported {text:?}"), duo);
            }
        }
        let removed = !duo.n[0].alive() || !duo.n[1].alive();
        if self.either && removed {
        } else if self.split {
            if !removed {
                return fail(String::from("the link survived at both ends"), duo);
            }
        } else if let Err(e) = duo.converged(!self.stall) {
            return fail(format!("not converged after healing: {e}"), duo);
        }
        if std::env::var_os("FIPS_LEGACY_TRACE").is_some() {
            std::println!("== {name}\n{}", duo.transcript());
        }
        let before = crate::proto::rekey::leaked();
        for x in 0..2 {
            if let Err(e) = duo.n[x].finish() {
                return fail(e, duo);
            }
        }
        let leaked = crate::proto::rekey::leaked() - before;
        if leaked != 0 {
            return fail(format!("{leaked} index leases leaked"), duo);
        }
        Ok(())
    }
}

/// Run every case, collecting failures, and fail with all of them.
pub(crate) fn all(results: Vec<Result<(), String>>) {
    let failed: Vec<String> = results.into_iter().filter_map(Result::err).collect();
    assert!(
        failed.is_empty(),
        "{} case(s) failed:\n\n{}",
        failed.len(),
        failed.join("\n\n")
    );
}

/// A boxed end, for building a `Duo`.
pub(crate) fn boxed<T: End + 'static>(end: T) -> Box<dyn End> {
    Box::new(end)
}
