//! The deployed-peer model: a bundle linked to a peer of a release that
//! implements no path message (multipath v1 draft, Section 8.1), driven
//! for simulated hours.
//!
//! [`Deployed`] is such a peer. It authenticates every frame of the link
//! and discards a path message unanswered (FRC-1201, Section 6.1), so it
//! never answers a capability probe and the node never learns that it is
//! capable. It sends a heartbeat every 10 seconds on the link's pair,
//! which the node accounts with `Bundle::account`.
//!
//! [`World`] pairs it with one node whose host has five transports: T1, a
//! clear transport that takes the kind of the peer's address, holding the
//! link's original pair; T2, clear and fixed Local; T3, Tor; T4, whose
//! role is never; and T5, on which the node would not dial the peer. A
//! pool of six candidates, one on T1 and two on T2 that path policy
//! allows and one on each of T3 to T5 that it refuses, each from one
//! source, is reported and unlisted at seeded times twenty minutes apart
//! on average. Now and then T1 loses carrier for 30 seconds, during which
//! no heartbeat arrives, and T2's interface leaves and comes back. The
//! node is stepped on each of these inputs and polled at its next wake.
//! Every draw comes from the run's seed, so a run replays from it.
//!
//! The world keeps its own account of the candidate table from its own
//! script, not from the bundle: which pairs the table holds and which are
//! held back. A fresh report enters a pair and releases it, and a fresh
//! report from local discovery releases every pair held back on its
//! transport; a repeat changes nothing; an unlisted pair is forgotten
//! unless it is held back, and one held back that its source no longer
//! lists is forgotten at its release, since a peer never capable admits
//! nothing; T2's interface leaving holds back every pair on T2 until it
//! comes back (Sections 5.4 and 5.6). A capability probe is allowed while
//! the table holds an allowed pair that its source lists and that is not
//! held back.
//!
//! The oracles, checked at every event, each named in the message of the
//! failure it reports:
//!
//! - **off-path**, **message**, **length** and **identifier**: every send
//!   goes on the link's original pair and is a `PathProbe` of exactly 27
//!   bytes carrying the original path's identifier. Each send is checked
//!   as the peer would receive it, those a carrier loss would drop
//!   included, since the bounds are on what the node sends;
//! - **candidate**: none goes while the world's account allows none;
//! - **spacing**: each goes at least the schedule's gap after the one
//!   before, the gap worked out by the shell's own formula;
//! - **hour**: at most twelve go in the hour from the first, and at most
//!   six in any hour that starts at or after the twelfth (Section 8.1);
//! - **never**: the node reports no connection, switch, capable peer,
//!   released or moved path, and is never orphaned;
//! - **not capable**: the link is reported not capable once, at the
//!   timeout of the first round's last probe, once that has passed, and
//!   never otherwise; the timeout is the floor, since the peer answers
//!   nothing and the link never measures a round trip;
//! - **original**: the original path is never Dead and never discarded;
//!
//! beside the shell's own checks on every call.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::shell::{Fact, Node, Out, Stub, addr, p, pair, spacing, t};
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::link::LinkMessageType;
use crate::proto::path::wire::{PATH_PROBE_MIN_SIZE, PathAck, PathCaps, PathFlags, PathProbe};
use crate::proto::path::{Class, Config, Input, Output, Params, PathRef, PathState, Role, Source};
use crate::testutil::{SplitMix64, TestInstant};

/// The type byte of a heartbeat.
const HEARTBEAT: u8 = 0x51;

/// The peer's heartbeat period, in milliseconds.
const BEAT: u64 = 10_000;

/// One simulated hour, in milliseconds.
const HOUR: u64 = 3_600_000;

/// The most capability probes in the hour from the first (Section 8.1).
const FIRST: usize = 12;

/// The most in any hour that starts at or after the twelfth.
const LATER: usize = 6;

/// The first key of each kind of draw from the run's seed, so draws of
/// different kinds never share a key.
const NODE: u64 = 0x6e6f_6465;

/// See [`NODE`].
const LISTS: u64 = 0x6c69_7374;

/// See [`NODE`].
const CARRIER: u64 = 0x6361_7272;

/// See [`NODE`].
const PRESENCE: u64 = 0x7072_6573;

/// `d` in whole milliseconds.
fn ms(d: crate::time::Duration) -> u64 {
    d.as_millis() as u64
}

/// A peer of a deployed release: it implements no path message, so it
/// answers nothing, and it holds the link on one pair. A frame on any
/// other pair would reach it from an address it does not hold for the
/// link.
struct Deployed {
    /// The link's pair, at the node's end.
    original: PathRef,
    /// The node's identifier for its original path.
    path_id: u32,
    /// The instants of the capability probes received, in milliseconds.
    sent: Vec<u64>,
    /// The node's settings.
    cfg: Config,
}

impl Deployed {
    /// The peer of a link made on `original`, which the node names
    /// `path_id`.
    fn new(original: PathRef, path_id: u32, cfg: Config) -> Self {
        Self {
            original,
            path_id,
            sent: Vec::new(),
            cfg,
        }
    }

    /// Take the link message `bytes` the node sent on `to` at `now`, while
    /// the world's account of the candidates allows a capability probe
    /// (`eligible`) or not, and discard it unanswered.
    fn receive(
        &mut self,
        now: u64,
        to: &PathRef,
        bytes: &[u8],
        eligible: bool,
    ) -> Result<(), String> {
        if to != &self.original {
            return Err(format!(
                "off-path: a frame on {to:?}, not the link's pair {:?}",
                self.original
            ));
        }
        if bytes.first() != Some(&LinkMessageType::PathProbe.to_byte()) {
            return Err(format!(
                "message: a link message of type {:?}, not a probe",
                bytes.first()
            ));
        }
        if bytes.len() != PATH_PROBE_MIN_SIZE {
            return Err(format!("length: a probe of {} bytes", bytes.len()));
        }
        let probe = PathProbe::decode(&bytes[1..]).map_err(|e| format!("message: {e:?}"))?;
        if probe.path_id != self.path_id {
            return Err(format!(
                "identifier: a probe naming {:#x}, not the original path {:#x}",
                probe.path_id, self.path_id
            ));
        }
        if !eligible {
            return Err(format!(
                "candidate: a capability probe at {now} ms with no candidate that allows one"
            ));
        }
        if let Some(&last) = self.sent.last() {
            let gap = ms(spacing(self.sent.len(), &self.cfg));
            if now.saturating_sub(last) < gap {
                return Err(format!(
                    "spacing: probe {} at {now} ms, under {gap} ms after {last} ms",
                    self.sent.len() + 1
                ));
            }
        }
        self.sent.push(now);
        hours(&self.sent)
    }
}

/// The hour bounds of Section 8.1 at the latest of the capability probes
/// sent at the instants `sent`, in order: at most [`FIRST`] in the hour
/// from the first, and at most [`LATER`] in any hour that starts at or
/// after the twelfth. Every hour is half-open, so probes ten minutes apart
/// put six in one, not seven.
fn hours(sent: &[u64]) -> Result<(), String> {
    let (Some(&first), Some(&last)) = (sent.first(), sent.last()) else {
        return Ok(());
    };
    let early = sent.iter().filter(|&&s| s < first + HOUR).count();
    if early > FIRST {
        return Err(format!(
            "hour: {early} probes in the hour from the first at {first} ms"
        ));
    }
    if let Some(&twelfth) = sent.get(FIRST - 1) {
        let from = twelfth.max((last + 1).saturating_sub(HOUR));
        let n = sent.iter().filter(|&&s| s >= from).count();
        if n > LATER {
            return Err(format!(
                "hour: {n} probes in the hour from {from} ms, after the twelfth"
            ));
        }
    }
    Ok(())
}

/// The **not capable** oracle at `now`, over the capability probes `sent`
/// and the instants `told` at which the link was reported not capable:
/// once, at the timeout of the `budget`-th probe, once it has passed, and
/// never otherwise. The timeout is `cfg`'s floor: the peer answers
/// nothing, so the link has no round trip.
fn told(sent: &[u64], told: &[u64], now: u64, cfg: &Config) -> Result<(), String> {
    let last = usize::from(cfg.budget).saturating_sub(1);
    let due = sent.get(last).map(|at| at + ms(cfg.timeout));
    match (due, told) {
        (_, [_, _, ..]) => Err(format!(
            "not capable: reported {} times, at {told:?} ms",
            told.len()
        )),
        (Some(due), [at]) if *at == due => Ok(()),
        (_, [at]) => Err(format!(
            "not capable: reported at {at} ms, the first round ending at {due:?} ms"
        )),
        (Some(due), []) if due <= now => Err(format!(
            "not capable: not reported by {now} ms, the first round ending at {due} ms"
        )),
        (_, []) => Ok(()),
    }
}

/// The **original** oracle: `n` holds its original path, ours `id`, and
/// it is not Dead.
fn original(n: &Node, id: u32) -> Result<(), String> {
    let paths = n.b.paths().paths();
    match paths.iter().find(|p| p.path_id() == id).map(|p| p.state()) {
        None => Err(String::from("original: the original path was discarded")),
        Some(PathState::Dead) => Err(String::from("original: the original path is Dead")),
        Some(PathState::Probing | PathState::Live | PathState::Suspect) => Ok(()),
    }
}

/// One of the world's scripted inputs.
#[derive(Clone, Copy, Debug)]
enum Event {
    /// The pool's candidate `i` is reported by its source.
    Report(usize),
    /// Its source no longer lists the pool's candidate `i`.
    Unlist(usize),
    /// T1 loses carrier (false) or regains it (true).
    Carrier(bool),
    /// T2's interface leaves (false) or comes back (true).
    Present(bool),
}

/// The world's account of one candidate of the pool.
struct Listing {
    /// Its pair.
    to: PathRef,
    /// Its one source.
    source: Source,
    /// Whether path policy lets the node probe it, by the world's facts.
    allowed: bool,
    /// Whether its source lists it.
    listed: bool,
    /// Whether the table holds an entry for it.
    kept: bool,
    /// Whether that entry is held back.
    held: bool,
}

/// The pool: one candidate on T1 and two on T2 that path policy allows,
/// then one each on T3 (Tor), T4 (role never) and T5 (not dialled) that
/// it refuses.
fn pool() -> Vec<Listing> {
    let entries = [
        (pair(t(1), addr(2)), Source::Config, true),
        (pair(t(2), addr(3)), Source::Nostr, true),
        (pair(t(2), addr(4)), Source::Discovery, true),
        (pair(t(3), addr(5)), Source::Discovery, false),
        (pair(t(4), addr(6)), Source::Config, false),
        (pair(t(5), addr(7)), Source::Nostr, false),
    ];
    entries
        .into_iter()
        .map(|(to, source, allowed)| Listing {
            to,
            source,
            allowed,
            listed: false,
            kept: false,
            held: false,
        })
        .collect()
}

/// The host's facts: T1 takes the kind of the peer's address, T3 is Tor,
/// T4's role is never and T5 does not dial; the rest are the stub's
/// defaults, clear and fixed Local.
fn facts() -> Stub {
    Stub::default()
        .fact(t(1), Fact::Kind(None))
        .fact(t(3), Fact::Class(Class::Tor))
        .fact(t(4), Fact::Role(Role::Never))
        .fact(t(5), Fact::Dials(false))
}

/// The script of a run of `until` milliseconds seeded with `seed`, in
/// order: candidate reports and unlistings about twenty minutes apart from
/// instant 0, three in five of them reports; T1's carrier lost for 30
/// seconds every 10 to 60 minutes; and T2's interface away for 1 to 21
/// minutes every 10 to 60 minutes.
fn script(seed: u64, until: u64) -> Vec<(u64, Event)> {
    let mut events = Vec::new();
    let mut g = SplitMix64::new(SplitMix64::mix(seed, &[LISTS]));
    let mut at = 0;
    while at < until {
        let i = g.below(6) as usize;
        let e = if g.chance(600) {
            Event::Report(i)
        } else {
            Event::Unlist(i)
        };
        events.push((at, e));
        at += g.below(40 * 60_000);
    }
    for (key, event) in [
        (CARRIER, Event::Carrier as fn(bool) -> Event),
        (PRESENCE, Event::Present),
    ] {
        let mut g = SplitMix64::new(SplitMix64::mix(seed, &[key]));
        let mut at = 0;
        loop {
            at += 10 * 60_000 + g.below(50 * 60_000);
            if at >= until {
                break;
            }
            let away = if key == CARRIER {
                30_000
            } else {
                60_000 + g.below(20 * 60_000)
            };
            events.push((at, event(false)));
            events.push((at + away, event(true)));
            at += away;
        }
    }
    events.sort_by_key(|(at, _)| *at);
    events
}

/// What the oracles saw, so a test can show they ran.
#[derive(Default)]
struct Seen {
    /// Capability probes sent.
    probes: usize,
    /// Probes sent after the twelfth.
    later: usize,
    /// Reports of the link not capable.
    told: usize,
    /// Events after which the world's account allowed no capability probe
    /// where it allowed one before.
    shut: usize,
    /// Heartbeats accounted.
    beats: usize,
}

impl Seen {
    /// Add `other`'s counts to these.
    fn add(&mut self, other: &Seen) {
        self.probes += other.probes;
        self.later += other.later;
        self.told += other.told;
        self.shut += other.shut;
        self.beats += other.beats;
    }
}

/// One node and its deployed peer over one run.
struct World {
    /// The run's seed.
    seed: u64,
    /// The current instant, in milliseconds.
    now: u64,
    /// The node.
    node: Node,
    /// Its peer.
    peer: Deployed,
    /// The world's account of the candidates.
    pool: Vec<Listing>,
    /// The scripted inputs, in order.
    events: Vec<(u64, Event)>,
    /// The next of them.
    next: usize,
    /// The instant of the peer's next heartbeat.
    beat: u64,
    /// Whether T1 has carrier.
    carrier: bool,
    /// The instants at which the link was reported not capable.
    told: Vec<u64>,
    /// The node's settings.
    cfg: Config,
    /// What the oracles saw.
    seen: Seen,
}

impl World {
    /// A world seeded with `seed` whose script runs for `until`
    /// milliseconds.
    fn new(seed: u64, until: u64) -> Self {
        let params = Params::draft();
        let cfg = *params.config();
        let node = Node::on(SplitMix64::mix(seed, &[NODE]), params, facts(), p());
        let peer = Deployed::new(p(), node.id(0), cfg);
        Self {
            seed,
            now: 0,
            node,
            peer,
            pool: pool(),
            events: script(seed, until),
            next: 0,
            beat: BEAT,
            carrier: true,
            told: Vec::new(),
            cfg,
            seen: Seen::default(),
        }
    }

    /// Run until `until` milliseconds, instant by instant: the peer's
    /// heartbeat, the scripted inputs, the poll at the node's next wake,
    /// and the oracles.
    fn run(&mut self, until: u64) {
        loop {
            let mut next = self.beat;
            if let Some(&(at, _)) = self.events.get(self.next) {
                next = next.min(at);
            }
            if let Some(w) = self.node.b.next_wake() {
                next = next.min(w.0);
            }
            if next > until {
                return;
            }
            self.now = next;
            self.node.now = TestInstant(next);
            if self.beat == next {
                self.beat += BEAT;
                if self.carrier {
                    self.seen.beats += 1;
                    let len = FRAME_OVERHEAD + 1;
                    self.node.account(t(1), &addr(1), len, HEARTBEAT);
                }
            }
            while let Some(&(at, e)) = self.events.get(self.next)
                && at == next
            {
                self.next += 1;
                self.apply(e);
            }
            if self.node.b.next_wake().is_some_and(|w| w.0 <= next) {
                self.step(Input::Poll);
            }
            self.check();
        }
    }

    /// Update the world's account for `e`, then step the node with it.
    fn apply(&mut self, e: Event) {
        let open = self.eligible();
        let input = match e {
            Event::Report(i) => {
                let l = &mut self.pool[i];
                let (to, source) = (l.to.clone(), l.source);
                if !l.listed {
                    (l.listed, l.kept, l.held) = (true, true, false);
                    if source == Source::Discovery {
                        self.release(to.transport);
                    }
                }
                Input::Candidate {
                    transport: to.transport,
                    addr: to.addr,
                    source,
                }
            }
            Event::Unlist(i) => {
                let l = &mut self.pool[i];
                l.listed = false;
                l.kept &= l.held;
                Input::Unlisted {
                    transport: l.to.transport,
                    addr: l.to.addr.clone(),
                    source: l.source,
                }
            }
            Event::Carrier(up) => {
                self.carrier = up;
                if up {
                    self.release(t(1));
                }
                Input::Carrier {
                    transport: t(1),
                    up,
                }
            }
            Event::Present(present) => {
                if present {
                    self.release(t(2));
                } else {
                    for l in self.pool.iter_mut().filter(|l| l.to.transport == t(2)) {
                        l.held |= l.kept;
                    }
                }
                Input::Present {
                    transport: t(2),
                    present,
                }
            }
        };
        if open && !self.eligible() {
            self.seen.shut += 1;
        }
        self.step(input);
    }

    /// Release every held-back entry on `transport`, forgetting each one
    /// its source no longer lists.
    fn release(&mut self, transport: crate::transport::TransportId) {
        for l in self.pool.iter_mut().filter(|l| l.to.transport == transport) {
            if l.held {
                l.held = false;
                l.kept = l.listed;
            }
        }
    }

    /// Whether the world's account allows a capability probe: the table
    /// holds a pair its source lists, that path policy allows and that is
    /// not held back.
    fn eligible(&self) -> bool {
        self.pool
            .iter()
            .any(|l| l.kept && l.listed && !l.held && l.allowed)
    }

    /// Step the node with `input` at the current instant and carry out its
    /// outputs.
    fn step(&mut self, input: Input) {
        self.node.now = TestInstant(self.now);
        let out = self.node.step(input.clone());
        self.handle(&input, out);
    }

    /// Hand each send in `out` to the peer, note each report of the link
    /// not capable, and check the **never** oracle.
    fn handle(&mut self, input: &Input, out: Vec<Out>) {
        for o in out {
            match o {
                Output::Send { to, bytes } => {
                    let eligible = self.eligible();
                    if let Err(e) = self.peer.receive(self.now, &to, &bytes, eligible) {
                        self.fail(e);
                    }
                    self.seen.probes += 1;
                    if self.peer.sent.len() > FIRST {
                        self.seen.later += 1;
                    }
                }
                Output::NotCapable => {
                    self.seen.told += 1;
                    self.told.push(self.now);
                }
                Output::State { .. } | Output::Refused { .. } => {}
                Output::Capable
                | Output::Connect { .. }
                | Output::Switched { .. }
                | Output::Released { .. }
                | Output::Moved { .. }
                | Output::Orphaned
                | Output::Proven { .. } => {
                    self.fail(format!("never: {o:?} on {input:?}"));
                }
            }
        }
    }

    /// The **not capable** and **original** oracles at the current instant.
    fn check(&self) {
        if let Err(e) = told(&self.peer.sent, &self.told, self.now, &self.cfg) {
            self.fail(e);
        }
        if let Err(e) = original(&self.node, self.peer.path_id) {
            self.fail(e);
        }
    }

    /// Fail the run, naming the seed, the instant and the oracle.
    fn fail(&self, what: String) -> ! {
        panic!("seed {} at {} ms: {what}", self.seed, self.now);
    }
}

/// Run `seeds` worlds of `until` milliseconds each and return what their
/// oracles saw.
fn runs(seeds: core::ops::Range<u64>, until: u64) -> Seen {
    let mut seen = Seen::default();
    for seed in seeds {
        let mut w = World::new(seed, until);
        w.run(until);
        assert_eq!(
            w.next,
            w.events.iter().filter(|(at, _)| *at <= until).count(),
            "seed {seed}: every scripted input up to the end was stepped"
        );
        seen.add(&w.seen);
    }
    seen
}

#[test]
fn a_deployed_peer_gets_only_capability_probes_within_the_budget_and_backoff() {
    let seen = runs(0..8, 2 * HOUR);
    assert!(seen.beats > 8 * 600, "the heartbeats were accounted");
    assert!(
        seen.probes > 8 * 3,
        "the probe oracles ran: {}",
        seen.probes
    );
    assert!(seen.later > 0, "the later hour bound ran");
    assert!(seen.told >= 4, "the not capable oracle ran: {}", seen.told);
    assert!(
        seen.shut >= 4,
        "the gate closed in some runs: {}",
        seen.shut
    );
}

#[cfg(feature = "slow-tests")]
#[test]
fn a_day_with_a_deployed_peer_keeps_every_capability_bound() {
    let seen = runs(0..64, 24 * HOUR);
    assert!(
        seen.later > 64 * 60,
        "probes after the twelfth: {}",
        seen.later
    );
    assert_eq!(seen.told, 64, "every run reported the link not capable");
    assert!(
        seen.shut >= 64,
        "the gate closed in some runs: {}",
        seen.shut
    );
}

/// The instants of the first `n` capability probes on the draft's
/// schedule, each the shell's gap after the one before.
fn schedule(n: usize, cfg: &Config) -> Vec<u64> {
    let mut at = 0;
    (1..=n)
        .map(|k| {
            let now = at;
            at += ms(spacing(k, cfg));
            now
        })
        .collect()
}

/// The hour bounds at each probe of `sent` in turn.
fn each_hour(sent: &[u64]) -> Result<(), String> {
    (1..=sent.len()).try_for_each(|n| hours(&sent[..n]))
}

/// Assert that `r` is a failure of `oracle`.
fn fires(r: Result<(), String>, oracle: &str) {
    let e = r.expect_err(oracle);
    assert!(e.starts_with(oracle), "{oracle} fired as: {e}");
}

#[test]
fn each_deployed_peer_oracle_fires_on_a_planted_breach() {
    let cfg = Config::draft();
    let peer = || Deployed::new(p(), 7, cfg);
    let probe = |path_id: u32, len: usize| {
        PathProbe::new(
            1,
            path_id,
            PathFlags::with_active(true),
            PathCaps::default(),
        )
        .with_len(len)
        .encode()
    };
    let ok = probe(7, PATH_PROBE_MIN_SIZE);

    // A day on the draft's schedule passes every oracle.
    let day = schedule(160, &cfg);
    assert!(day.last().is_some_and(|&l| l > 24 * HOUR));
    let mut d = peer();
    for &at in &day {
        d.receive(at, &p(), &ok, true).expect("the schedule passes");
    }
    assert_eq!(day.iter().filter(|&&s| s < HOUR).count(), FIRST);

    // An ack.
    let ack = PathAck {
        probe_id: 1,
        flags: PathFlags::default(),
        path_id: 9,
        echo_path_id: 7,
        caps: PathCaps::default(),
        rx_time_us: 0,
        rx_frames: 0,
        rx_bytes: 0,
        len: PATH_PROBE_MIN_SIZE,
    };
    fires(peer().receive(0, &p(), &ack.encode(), true), "message");
    // A probe on T2.
    fires(
        peer().receive(0, &pair(t(2), addr(2)), &ok, true),
        "off-path",
    );
    // A probe of 28 bytes.
    fires(peer().receive(0, &p(), &probe(7, 28), true), "length");
    // A probe naming another path.
    fires(peer().receive(0, &p(), &probe(8, 27), true), "identifier");
    // A probe with no candidate that allows one.
    fires(peer().receive(0, &p(), &ok, false), "candidate");
    // Two probes 5 seconds apart.
    let mut d = peer();
    d.receive(0, &p(), &ok, true).expect("the first passes");
    fires(d.receive(5_000, &p(), &ok, true), "spacing");

    // Thirteen in the first hour.
    let crowded: Vec<u64> = (0..13).map(|k| k * 270_000).collect();
    fires(each_hour(&crowded), "hour");
    // Seven in one hour after the twelfth, 599 seconds apart.
    let mut tight = schedule(FIRST, &cfg);
    let twelfth = tight[FIRST - 1];
    tight.extend((1..=6).map(|k| twelfth + k * 599_000));
    fires(each_hour(&tight), "hour");
    // Seven 600 seconds apart span a whole hour, which no half-open hour
    // holds: six at most.
    let mut spread = schedule(FIRST, &cfg);
    spread.extend((1..=6).map(|k| twelfth + k * 600_000));
    each_hour(&spread).expect("six in any hour");

    // The first round ends at 20 s; its last probe times out at 20.4 s.
    let round = [0, 10_000, 20_000];
    told(&round, &[20_400], 30_000, &cfg).expect("once, at the timeout");
    told(&round, &[], 20_399, &cfg).expect("not yet due");
    told(&round[..2], &[], HOUR, &cfg).expect("no first round ended");
    fires(told(&round, &[], 20_400, &cfg), "not capable");
    fires(told(&round, &[20_000], 30_000, &cfg), "not capable");
    fires(told(&round, &[20_400, 20_400], 30_000, &cfg), "not capable");
    fires(told(&round[..2], &[10_400], 30_000, &cfg), "not capable");

    // The original path discarded with its transport.
    let mut n = Node::on(1, Params::draft(), facts(), p());
    let id = n.id(0);
    original(&n, id).expect("held at the start");
    n.step(Input::Removed { transport: t(1) });
    fires(original(&n, id), "original");
}
