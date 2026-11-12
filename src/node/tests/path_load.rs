//! A link's paths under load, each carried by a paced first-in first-out
//! lane, in simulated time.
//!
//! Two loopback nodes with multipath on. Lane `a` is the link's original
//! path, on transport 1; every other lane is a second loopback transport at
//! each node, offered by A and proven before the run starts. Each lane is a
//! pair of pacers, one per direction, standing in front of the receiving
//! node's address on that lane: a pacer takes every frame sent to the
//! address into an unbounded queue that never refuses, carries the frames
//! one after the other at the lane's rate, and delivers each after the
//! lane's base delay. So the offered load alone sets the queueing delay,
//! and a path message waits behind the data as it does in a radio's or an
//! interface's send queue below the transport.
//!
//! Load is session datagrams from A to B on A's active path, offered at a
//! set rate. The load source sends a frame only while the lane in front of
//! it holds less than a target delay, as a sender whose window has filled a
//! buffer does, so the queue settles at that delay; nothing the node itself
//! sends is held back. Reverse traffic, when on, is one small session
//! datagram from B for every two frames of load B receives, on B's active
//! path, shaped like TCP acknowledgements. A steady stream from B on a lane
//! named by the case stands for a peer whose traffic keeps arriving on that
//! lane whatever its own verdict.
//!
//! The session datagrams carry a hop limit of zero and name no node, so the
//! receiver authenticates and accounts each one on its path, then drops it
//! unrouted. Simulated time throughout (`crate::time::freeze`), advanced in
//! 5 ms steps with the node's 50 ms path tick, so a run does not depend on
//! the host's load and replays exactly.

use std::collections::VecDeque;

use super::paths::{enabled, second_transport, state_at};
use super::rekey_parity::{linked_pair, pump};
use super::spanning_tree::{LOOPBACK_REGISTRY, TestNode, cleanup_nodes, process_available_packets};
use super::*;
use crate::peer::PathState;
use crate::proto::link::LinkMessageType;
use fips_core::proto::path::PathRef;

/// The simulated step.
const STEP: Duration = Duration::from_millis(5);

/// The node's path tick, every this many steps (50 ms, as the daemon's).
const TICK_EVERY: u32 = 10;

/// The plaintext length of one frame of load.
const LOAD_LEN: usize = 1_000;

/// The plaintext length of one frame of reverse traffic.
const ACK_LEN: usize = 60;

/// The longest the nodes may take to prove every lane at both ends.
const SETUP: Duration = Duration::from_secs(30);

/// One lane's shape.
#[derive(Clone, Copy, Debug)]
struct Spec {
    /// The lane's name in the timeline.
    name: &'static str,
    /// The transport carrying it at each node.
    transport: u32,
    /// What it carries each way, bits per second.
    bps: u64,
    /// The delay each frame takes after it is carried.
    base: Duration,
}

/// Lane `a`: the link's original path, a 1 Mbit/s lane with a 5 ms base
/// delay, the one each case loads.
const LANE_A: Spec = Spec {
    name: "a",
    transport: 1,
    bps: 1_000_000,
    base: Duration::from_millis(5),
};

/// Lane `b`: a fast idle lane, 20 Mbit/s with a 5 ms base delay, the place
/// the link goes when it leaves `a`.
const LANE_B: Spec = Spec {
    name: "b",
    transport: 2,
    bps: 20_000_000,
    base: Duration::from_millis(5),
};

/// Lane `c`: a slow lane at the rate a macOS to BlueZ BLE link carried in
/// the field, 250 kbit/s, with a 20 ms base delay.
const LANE_C: Spec = Spec {
    name: "c",
    transport: 3,
    bps: 250_000,
    base: Duration::from_millis(20),
};

/// The verdict cap the node runs with: the longest a probe's verdict waits
/// after it is sent while the peer's session datagrams arrive on its path,
/// and the cap on the timeout's term from the largest recent round trip.
/// The rig checks it against the path settings' own.
const CAP: Duration = Duration::from_secs(3);

/// One direction of a lane: the frames sent to the receiving node's address
/// on the lane, held and carried in order.
struct Pacer {
    /// The receiving node's channel, as the registry held it.
    inner: tokio::sync::mpsc::UnboundedSender<ReceivedPacket>,
    /// What the registry now hands every frame sent to the address.
    tap: tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket>,
    /// What the direction carries, bits per second.
    bps: u64,
    /// The delay each frame takes after it is carried.
    base: Duration,
    /// The frames taken, each with the instant it is delivered.
    queue: VecDeque<(Duration, ReceivedPacket)>,
    /// The instant the direction finishes carrying what it holds.
    free: Duration,
    /// Whether the direction drops everything.
    cut: bool,
    /// Frames it dropped.
    dropped: u64,
}

impl Pacer {
    /// Stand a pacer of `bps` and `base` in front of `addr`.
    fn intercept(addr: &TransportAddr, bps: u64, base: Duration) -> Self {
        let mut registry = LOOPBACK_REGISTRY.lock().unwrap();
        let (transport, inner) = registry
            .get(addr)
            .expect("the lane's address is registered")
            .clone();
        let (tx, tap) = tokio::sync::mpsc::unbounded_channel();
        registry.insert(addr.clone(), (transport, tx));
        Self {
            inner,
            tap,
            bps,
            base,
            queue: VecDeque::new(),
            free: Duration::ZERO,
            cut: false,
            dropped: 0,
        }
    }

    /// Take every frame sent since the last call at `now`, behind the ones
    /// held, unless the direction is cut.
    fn take(&mut self, now: Duration) {
        while let Ok(packet) = self.tap.try_recv() {
            if self.cut {
                self.dropped += 1;
                continue;
            }
            let bits = packet.data.len() as u64 * 8;
            let carry = Duration::from_micros(bits * 1_000_000 / self.bps);
            self.free = self.free.max(now) + carry;
            self.queue.push_back((self.free + self.base, packet));
        }
    }

    /// Deliver every frame due by `now`, in order.
    fn deliver(&mut self, now: Duration) {
        while self.queue.front().is_some_and(|(at, _)| *at <= now) {
            let (_, packet) = self.queue.pop_front().unwrap();
            let _ = self.inner.send(packet);
        }
    }

    /// The delay a frame taken at `now` waits before it is carried.
    fn backlog(&self, now: Duration) -> Duration {
        self.free.saturating_sub(now)
    }

    /// Drop everything from now on, and everything held.
    fn sever(&mut self, now: Duration) {
        self.cut = true;
        self.dropped += self.queue.len() as u64;
        self.queue.clear();
        self.free = now;
    }
}

/// A lane: its shape, each node's address on it, and a pacer each way,
/// `[A to B, B to A]`.
struct Lane {
    spec: Spec,
    /// A's address on the lane, then B's.
    addrs: [TransportAddr; 2],
    pacers: [Pacer; 2],
}

/// The load A offers.
#[derive(Clone, Copy, Debug)]
struct Load {
    /// The offered rate, bits per second.
    bps: u64,
    /// The queue the source keeps in front of the active lane at most.
    target: Duration,
}

/// What B sends back.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Reverse {
    /// Nothing.
    Off,
    /// One small session datagram per two frames of load received, on B's
    /// active path.
    Acks,
    /// A steady stream of small session datagrams at this rate, bits per
    /// second, on lane `a` whatever B's active path.
    Steady(u64),
}

/// What one sample of the link shows.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Seen {
    /// The transport of A's active path.
    active: TransportId,
    /// The state of lane `a`'s path at A, then at B.
    a: [Option<PathState>; 2],
}

/// The nodes, their lanes, and the simulated clock's position.
struct Rig {
    nodes: Vec<TestNode>,
    lanes: Vec<Lane>,
    steps: u32,
    load: Option<Load>,
    reverse: Reverse,
    /// A's credit toward the next frame of load, in bit-milliseconds.
    credit: u64,
    /// B's credit toward the next frame of a steady reverse stream.
    back: u64,
    /// Frames of load A sent.
    sent: u64,
    /// Frames of load the source held back because the queue was full.
    held: u64,
    /// Frames of reverse traffic B sent.
    acks: u64,
}

impl Rig {
    /// Two linked nodes with a lane of each shape in `specs`, the first
    /// lane `a`, every lane's path Live at both ends, A's active path on
    /// `a`.
    async fn new(specs: &[Spec]) -> Self {
        crate::time::freeze();
        assert_eq!(specs[0].transport, 1, "lane a is the original path");
        assert_eq!(
            CAP,
            fips_core::proto::path::Config::draft().verdict_cap,
            "the cap the cases assert against is the node's"
        );
        let mut nodes = linked_pair(enabled(), enabled()).await;
        let b = *nodes[1].node.node_addr();
        let mut addrs = vec![[nodes[0].addr.clone(), nodes[1].addr.clone()]];
        for spec in &specs[1..] {
            let t = TransportId::new(spec.transport);
            let a_at = second_transport(&mut nodes[0], t, 1280);
            let b_at = second_transport(&mut nodes[1], t, 1280);
            nodes[0].node.offer_path(&b, t, b_at.clone()).await;
            pump(&mut nodes).await;
            addrs.push([a_at, b_at]);
        }
        let lanes = specs
            .iter()
            .zip(addrs)
            .map(|(spec, addrs)| Lane {
                spec: *spec,
                pacers: [
                    Pacer::intercept(&addrs[1], spec.bps, spec.base),
                    Pacer::intercept(&addrs[0], spec.bps, spec.base),
                ],
                addrs,
            })
            .collect();
        let mut rig = Self {
            nodes,
            lanes,
            steps: 0,
            load: None,
            reverse: Reverse::Off,
            credit: 0,
            back: 0,
            sent: 0,
            held: 0,
            acks: 0,
        };
        while !rig.proven() {
            assert!(
                rig.at() < SETUP,
                "setup bound: not every lane is Live at both ends after {SETUP:?}"
            );
            rig.step().await;
        }
        assert_eq!(
            rig.seen().active,
            TransportId::new(1),
            "precondition: A's link is on lane a"
        );
        rig
    }

    /// The time since the rig started.
    fn at(&self) -> Duration {
        STEP * self.steps
    }

    /// A's address for B, and B's for A.
    fn peers(&self) -> (NodeAddr, NodeAddr) {
        (
            *self.nodes[0].node.node_addr(),
            *self.nodes[1].node.node_addr(),
        )
    }

    /// The state of lane `i`'s path at node `end`.
    fn state(&self, end: usize, i: usize) -> Option<PathState> {
        let (a, b) = self.peers();
        let peer = if end == 0 { b } else { a };
        let lane = &self.lanes[i];
        state_at(
            &self.nodes[end],
            &peer,
            TransportId::new(lane.spec.transport),
            &lane.addrs[1 - end],
        )
    }

    /// Whether every lane's path is Live at both ends.
    fn proven(&self) -> bool {
        (0..self.lanes.len()).all(|i| (0..2).all(|end| self.state(end, i) == Some(PathState::Live)))
    }

    /// The index of the lane of A's active path.
    fn active(&self) -> usize {
        let (_, b) = self.peers();
        let peer = self.nodes[0].node.get_peer(&b).expect("A holds B");
        let paths = peer.bundle().expect("A's link has a bundle").paths();
        let t = paths.active().expect("an active path").transport_id();
        self.lanes
            .iter()
            .position(|l| TransportId::new(l.spec.transport) == t)
            .expect("the active path is on a lane")
    }

    /// What the link shows now.
    fn seen(&self) -> Seen {
        Seen {
            active: TransportId::new(self.lanes[self.active()].spec.transport),
            a: [self.state(0, 0), self.state(1, 0)],
        }
    }

    /// The latest round trip of lane `a`'s path at A.
    fn rtt(&self) -> Option<Duration> {
        let (_, b) = self.peers();
        let paths = self.nodes[0].node.get_peer(&b)?.bundle()?.paths();
        let i = paths.find(TransportId::new(1), &self.lanes[0].addrs[1])?;
        paths.get(i)?.live().rtt()
    }

    /// The queue in front of B on lane `a`: the delay A's frames wait.
    fn queued(&self) -> Duration {
        self.lanes[0].pacers[0].backlog(self.at())
    }

    /// Pin both ends to lane `a`.
    async fn pin(&mut self) {
        let a_npub = self.nodes[0].node.npub();
        let b_npub = self.nodes[1].node.npub();
        self.nodes[0]
            .node
            .pin_path(&b_npub, "1", None)
            .await
            .expect("A pins lane a");
        self.nodes[1]
            .node
            .pin_path(&a_npub, "1", None)
            .await
            .expect("B pins lane a");
    }

    /// Cut lane `a` in A's sending direction, `[A to B]`, or both.
    fn cut(&mut self, both: bool) {
        let now = self.at();
        self.lanes[0].pacers[0].sever(now);
        if both {
            self.lanes[0].pacers[1].sever(now);
        }
    }

    /// Run one step: the clock moves, each lane delivers what is due, the
    /// path tick runs on its cadence, A's load and B's reverse traffic go,
    /// and every frame that arrived is handled.
    async fn step(&mut self) {
        crate::time::advance(STEP);
        self.steps += 1;
        let now = self.at();
        for lane in &mut self.lanes {
            for p in &mut lane.pacers {
                p.deliver(now);
            }
        }
        self.drain().await;
        if self.steps.is_multiple_of(TICK_EVERY) {
            self.nodes[0].node.path_tick().await;
            self.nodes[1].node.path_tick().await;
            self.drain().await;
        }
        self.offer().await;
        self.answer().await;
        self.drain().await;
    }

    /// Take what the nodes sent into the lanes and handle what arrived,
    /// until a pass moves nothing.
    async fn drain(&mut self) {
        let now = self.at();
        let mut passes = 0;
        loop {
            for lane in &mut self.lanes {
                for p in &mut lane.pacers {
                    p.take(now);
                    p.deliver(now);
                }
            }
            if process_available_packets(&mut self.nodes).await == 0 {
                break;
            }
            passes += 1;
            assert!(passes < 64, "the frames do not settle");
        }
    }

    /// Send what A's load offers this step, holding a frame back while the
    /// lane of A's active path queues the target delay or more.
    async fn offer(&mut self) {
        let Some(load) = self.load else {
            return;
        };
        let (_, b) = self.peers();
        self.credit += load.bps * STEP.as_millis() as u64;
        let need = LOAD_LEN as u64 * 8 * 1000;
        while self.credit >= need {
            self.credit -= need;
            let now = self.at();
            let lane = self.active();
            let pacer = &mut self.lanes[lane].pacers[0];
            pacer.take(now);
            if pacer.backlog(now) >= load.target {
                self.held += 1;
                continue;
            }
            let frame = datagram(LOAD_LEN);
            if self.nodes[0]
                .node
                .send_encrypted_link_message(&b, &frame)
                .await
                .is_ok()
            {
                self.sent += 1;
            }
            self.lanes[lane].pacers[0].take(now);
        }
    }

    /// Send B's reverse traffic for this step.
    async fn answer(&mut self) {
        let (a, _) = self.peers();
        match self.reverse {
            Reverse::Off => {}
            Reverse::Acks => {
                let got = self.nodes[1]
                    .node
                    .metrics()
                    .forwarding
                    .received_packets
                    .get();
                while self.acks < got / 2 {
                    let _ = self.nodes[1]
                        .node
                        .send_encrypted_link_message(&a, &datagram(ACK_LEN))
                        .await;
                    self.acks += 1;
                }
            }
            Reverse::Steady(bps) => {
                let via = PathRef {
                    transport: TransportId::new(1),
                    addr: self.lanes[0].addrs[0].clone(),
                };
                self.back += bps * STEP.as_millis() as u64;
                let need = ACK_LEN as u64 * 8 * 1000;
                while self.back >= need {
                    self.back -= need;
                    let _ = self.nodes[1]
                        .node
                        .send_via(&a, &datagram(ACK_LEN), false, Some(&via))
                        .await;
                    self.acks += 1;
                }
            }
        }
    }
}

/// A session datagram of `len` bytes of plaintext with a hop limit of zero,
/// naming no node: the receiver accounts it on its path and drops it.
fn datagram(len: usize) -> Vec<u8> {
    let mut frame = vec![0u8; len];
    frame[0] = LinkMessageType::SessionDatagram.to_byte();
    frame
}

/// What a run of one phase saw.
#[derive(Debug, Default)]
struct Tally {
    /// Changes of A's active path.
    changes: u32,
    /// Times lane `a`'s path became Suspect, at A and at B.
    suspects: [u32; 2],
    /// The instants, from the run's start, at which each end's lane `a`
    /// path became Suspect.
    suspect_at: [Vec<Duration>; 2],
    /// The instants of each change of A's active path, and the lane taken.
    turns: Vec<(Duration, &'static str)>,
    /// The longest round trip lane `a`'s path measured at A.
    rtt: Duration,
    /// The longest queue in front of B on lane `a`.
    queued: Duration,
}

/// Run `rig` for `span`, tallying into `tally` and logging into `timeline`
/// each change of A's active path or of lane `a`'s state at either end,
/// with times counted from `start`.
async fn run(
    rig: &mut Rig,
    span: Duration,
    start: Duration,
    tally: &mut Tally,
    timeline: &mut Vec<String>,
) {
    let mut last = rig.seen();
    let until = rig.at() + span;
    while rig.at() < until {
        rig.step().await;
        let now = rig.seen();
        if let Some(rtt) = rig.rtt() {
            tally.rtt = tally.rtt.max(rtt);
        }
        tally.queued = tally.queued.max(rig.queued());
        let t = rig.at() - start;
        if now.active != last.active {
            tally.changes += 1;
            tally.turns.push((t, rig.lanes[rig.active()].spec.name));
        }
        for end in 0..2 {
            if now.a[end] == Some(PathState::Suspect) && last.a[end] != Some(PathState::Suspect) {
                tally.suspects[end] += 1;
                tally.suspect_at[end].push(t);
            }
        }
        if now != last {
            timeline.push(format!(
                "t={:>6.2}s active={} a@A={:?} a@B={:?} rtt@A={:?} queue={:?}",
                t.as_secs_f64(),
                rig.lanes[rig.active()].spec.name,
                now.a[0],
                now.a[1],
                rig.rtt(),
                rig.queued(),
            ));
            last = now;
        }
    }
}

/// Print a case's timeline and tally.
fn report(case: &str, timeline: &[String], tally: &Tally, rig: &Rig) {
    println!("--- {case} ---");
    for line in timeline {
        println!("{line}");
    }
    println!(
        "changes={} suspects A={} B={} turns={:?} max rtt@A={:?} max queue={:?}; \
         load sent={} held={} reverse sent={}",
        tally.changes,
        tally.suspects[0],
        tally.suspects[1],
        tally.turns,
        tally.rtt,
        tally.queued,
        rig.sent,
        rig.held,
        rig.acks,
    );
}

/// Idle, with no load and no reverse traffic, a link on lane `a` stays
/// there for 10 s with lane `a` Live at both ends.
#[tokio::test]
async fn an_idle_paced_lane_keeps_the_link_without_a_change_or_a_suspect() {
    let mut rig = Rig::new(&[LANE_A, LANE_B]).await;
    let mut tally = Tally::default();
    let mut timeline = Vec::new();
    let start = rig.at();
    run(
        &mut rig,
        Duration::from_secs(10),
        start,
        &mut tally,
        &mut timeline,
    )
    .await;
    report("idle, unpinned", &timeline, &tally, &rig);
    assert_eq!(tally.changes, 0, "idle, the link stays on lane a");
    assert_eq!(tally.suspects, [0, 0], "idle, lane a stays Live");
    assert_eq!(rig.seen().a, [Some(PathState::Live); 2]);
    cleanup_nodes(&mut rig.nodes).await;
}

/// A two-way outage of an idle lane `a` moves A's link to lane `b` within
/// today's bound: three active probe intervals, the probe timeout floor and
/// a round trip (multipath v1 draft, Section 5.6 and 5.7). No session
/// datagram arrives on the cut lane, so nothing holds a verdict.
#[tokio::test]
async fn a_two_way_outage_of_an_idle_lane_moves_the_link_within_todays_bound() {
    let mut rig = Rig::new(&[LANE_A, LANE_B]).await;
    let mut tally = Tally::default();
    let mut timeline = Vec::new();
    let start = rig.at();
    run(
        &mut rig,
        Duration::from_secs(3),
        start,
        &mut tally,
        &mut timeline,
    )
    .await;
    assert_eq!(tally.changes, 0, "precondition: idle on lane a");
    rig.cut(true);
    let cut = rig.at();
    run(
        &mut rig,
        Duration::from_secs(5),
        cut,
        &mut tally,
        &mut timeline,
    )
    .await;
    report("two-way outage of idle lane a", &timeline, &tally, &rig);
    let bound = Duration::from_millis(3 * 200 + 400) + 2 * LANE_A.base + STEP * TICK_EVERY;
    let left = tally
        .turns
        .first()
        .map(|(t, _)| *t)
        .expect("A's link left lane a");
    assert!(
        left <= bound,
        "A's link left lane a {left:?} after the outage, past the bound {bound:?}"
    );
    assert_eq!(tally.turns[0].1, "b", "to lane b");
    cleanup_nodes(&mut rig.nodes).await;
}

/// Loaded at half its rate, with reverse traffic, a pinned lane `a` builds
/// no queue to speak of and keeps the link for 10 s, Live at both ends.
#[tokio::test]
async fn a_pinned_lane_loaded_below_its_rate_with_reverse_traffic_keeps_the_link() {
    let mut rig = Rig::new(&[LANE_A, LANE_B]).await;
    rig.pin().await;
    rig.reverse = Reverse::Acks;
    rig.load = Some(Load {
        bps: LANE_A.bps / 2,
        target: Duration::from_secs(2),
    });
    let mut tally = Tally::default();
    let mut timeline = Vec::new();
    let start = rig.at();
    run(
        &mut rig,
        Duration::from_secs(10),
        start,
        &mut tally,
        &mut timeline,
    )
    .await;
    report(
        "half-rate load, reverse on, pinned",
        &timeline,
        &tally,
        &rig,
    );
    assert!(
        rig.sent > 0 && rig.acks > 0,
        "precondition: load and reverse traffic flowed"
    );
    assert_eq!(rig.held, 0, "precondition: the source held nothing back");
    assert_eq!(tally.changes, 0, "below its rate, the link stays on lane a");
    assert_eq!(tally.suspects, [0, 0], "below its rate, lane a stays Live");
    cleanup_nodes(&mut rig.nodes).await;
}

/// Pin both ends of a rig on lanes `a` and `b` to `a`, run it idle for 3 s,
/// then load `a` at sixteen times its rate for `secs`, the source keeping
/// a 2 s queue, with `reverse` from B. Returns the rig and the loaded
/// phase's tally.
async fn onset(reverse: Reverse, secs: u64) -> (Rig, Tally) {
    let mut rig = Rig::new(&[LANE_A, LANE_B]).await;
    rig.pin().await;
    rig.reverse = reverse;
    let mut idle = Tally::default();
    let mut timeline = Vec::new();
    let start = rig.at();
    run(
        &mut rig,
        Duration::from_secs(3),
        start,
        &mut idle,
        &mut timeline,
    )
    .await;
    assert_eq!(idle.changes, 0, "precondition: idle, the link stays on a");
    rig.load = Some(Load {
        bps: 16 * LANE_A.bps,
        target: Duration::from_secs(2),
    });
    let mut loaded = Tally::default();
    run(
        &mut rig,
        Duration::from_secs(secs),
        start,
        &mut loaded,
        &mut timeline,
    )
    .await;
    report(
        &format!("2 s queue at load onset, pinned, reverse {reverse:?}"),
        &timeline,
        &loaded,
        &rig,
    );
    assert!(
        loaded.queued >= Duration::from_millis(1_900),
        "precondition: the load built its 2 s queue"
    );
    (rig, loaded)
}

/// A pinned lane whose queue jumps to 2 s at load onset, with reverse
/// traffic shaped like TCP acknowledgements, keeps the link for 20 s with
/// no change and no Suspect at either end: each end receives the peer's
/// session datagrams on the lane while its probes wait behind the data, so
/// no verdict is given before the probe's answer arrives, under the cap.
#[tokio::test]
async fn a_pinned_lane_whose_queue_jumps_to_two_seconds_under_two_way_traffic_keeps_the_link() {
    let (mut rig, loaded) = onset(Reverse::Acks, 20).await;
    assert!(rig.acks > 0, "precondition: reverse traffic flowed");
    assert_eq!(
        loaded.changes, 0,
        "defect: the loaded pinned link changed active path {} times",
        loaded.changes
    );
    assert_eq!(
        loaded.suspects,
        [0, 0],
        "defect: lane a went Suspect under load at A and B"
    );
    cleanup_nodes(&mut rig.nodes).await;
}

/// The same onset with load one way only: A receives no session datagram on
/// the lane, so its verdicts rest on its probes' answers alone, and the
/// timeout from the largest recent round trip leaves at most one excursion
/// away and back, with at most one Suspect at each end.
#[tokio::test]
async fn a_pinned_lane_whose_queue_jumps_to_two_seconds_one_way_leaves_at_most_one_excursion() {
    let (mut rig, loaded) = onset(Reverse::Off, 20).await;
    assert!(
        loaded.changes <= 2,
        "defect: the loaded pinned link changed active path {} times, past one excursion",
        loaded.changes
    );
    assert!(
        loaded.suspects.iter().all(|&n| n <= 1),
        "defect: lane a went Suspect {:?} times at A and B, past one each",
        loaded.suspects
    );
    cleanup_nodes(&mut rig.nodes).await;
}

/// The second field report's shape, unpinned, over 60 s: lane `a` fast and
/// loaded with reverse traffic, its queue growing losslessly at three
/// seconds a second to 5 s, past the cap; lane `c` an idle standby at BLE
/// rate. While its queue is under the cap, each of lane `a`'s probes is
/// answered before the cap from its sending, while the peer's session
/// datagrams keep arriving; so lane `a` goes Suspect at neither end until
/// a probe sent after the queue passed the cap has waited the cap out, and
/// a mandatory departure comes no sooner. Discretionary moves the load
/// causes on the active path's score are recorded, not asserted.
#[tokio::test]
async fn an_unpinned_lane_whose_queue_grows_past_the_cap_goes_suspect_only_after_it_does() {
    let mut rig = Rig::new(&[LANE_A, LANE_C]).await;
    rig.reverse = Reverse::Acks;
    let mut tally = Tally::default();
    let mut timeline = Vec::new();
    let start = rig.at();
    run(
        &mut rig,
        Duration::from_secs(3),
        start,
        &mut tally,
        &mut timeline,
    )
    .await;
    assert_eq!(tally.changes, 0, "precondition: idle, the link stays on a");
    rig.load = Some(Load {
        bps: 4 * LANE_A.bps,
        target: Duration::from_secs(5),
    });
    let mut over = None;
    let until = rig.at() + Duration::from_secs(60);
    while rig.at() < until {
        run(&mut rig, STEP, start, &mut tally, &mut timeline).await;
        if over.is_none() && rig.queued() >= CAP {
            over = Some(rig.at() - start);
            timeline.push(format!(
                "t={:>6.2}s the queue on a passes the cap",
                (rig.at() - start).as_secs_f64()
            ));
        }
    }
    report(
        "queue growing past the cap, unpinned, reverse on, BLE-rate standby",
        &timeline,
        &tally,
        &rig,
    );
    println!("queue passed the cap at {over:?}");
    assert!(
        tally.queued >= CAP || tally.turns.first().is_some_and(|(_, to)| *to != "a"),
        "precondition: the queue passed the cap, or the link left a before it did"
    );
    for end in 0..2 {
        for at in &tally.suspect_at[end] {
            assert!(
                over.is_some_and(|o| *at >= o + CAP),
                "defect: lane a went Suspect at {} at {at:?}, before a probe sent once its queue \
                 passed the cap ({over:?}) could wait the cap out",
                ["A", "B"][end]
            );
        }
    }
    cleanup_nodes(&mut rig.nodes).await;
}

/// Load stops for longer than the round-trip window, then starts again,
/// with reverse traffic: the restart, like the first onset, changes
/// nothing on a pinned link (the second field report's restart at 36 s).
#[tokio::test]
async fn a_pinned_lane_whose_load_restarts_after_the_window_keeps_the_link_at_the_restart() {
    let (mut rig, first) = onset(Reverse::Acks, 10).await;
    rig.load = None;
    let mut timeline = Vec::new();
    let start = rig.at();
    let mut gap = Tally::default();
    run(
        &mut rig,
        Duration::from_secs(35),
        start,
        &mut gap,
        &mut timeline,
    )
    .await;
    rig.load = Some(Load {
        bps: 16 * LANE_A.bps,
        target: Duration::from_secs(2),
    });
    let mut again = Tally::default();
    run(
        &mut rig,
        Duration::from_secs(10),
        start,
        &mut again,
        &mut timeline,
    )
    .await;
    report(
        "restart after 35 s idle, pinned, reverse on",
        &timeline,
        &again,
        &rig,
    );
    println!(
        "first onset changes={} suspects={:?}; idle gap changes={}",
        first.changes, first.suspects, gap.changes
    );
    assert!(
        again.queued >= Duration::from_millis(1_900),
        "precondition: the restarted load built its 2 s queue"
    );
    assert_eq!(
        again.changes, 0,
        "defect: the restarted load changed the pinned link's active path {} times",
        again.changes
    );
    assert_eq!(
        again.suspects,
        [0, 0],
        "defect: lane a went Suspect at the restart at A and B"
    );
    cleanup_nodes(&mut rig.nodes).await;
}

/// Load lane `a` keeping a queue of `target`, with B's session datagrams
/// arriving on `a` whatever B's own verdict, pinned, for 5 s; then cut A's
/// own sending direction on `a`. Returns how long after the cut A's link
/// left `a`, if it did within 8 s, and A's latest round trip on `a` at the
/// cut.
async fn oneway(target: Duration) -> (Option<Duration>, Duration) {
    let mut rig = Rig::new(&[LANE_A, LANE_B]).await;
    rig.pin().await;
    rig.reverse = Reverse::Steady(32_000);
    rig.load = Some(Load {
        bps: 16 * LANE_A.bps,
        target,
    });
    let mut tally = Tally::default();
    let mut timeline = Vec::new();
    let start = rig.at();
    run(
        &mut rig,
        Duration::from_secs(5),
        start,
        &mut tally,
        &mut timeline,
    )
    .await;
    assert_eq!(
        rig.seen().active,
        TransportId::new(1),
        "precondition: A's link is on lane a at the cut"
    );
    let rtt = rig.rtt().expect("precondition: lane a has a round trip");
    rig.cut(false);
    let cut = rig.at();
    let mut after = Tally::default();
    run(
        &mut rig,
        Duration::from_secs(8),
        cut,
        &mut after,
        &mut timeline,
    )
    .await;
    report(
        &format!(
            "one-way cut of A's direction under a {target:?} queue, peer's traffic still on a"
        ),
        &timeline,
        &after,
        &rig,
    );
    let left = after.turns.first().map(|(t, _)| *t);
    println!("A left lane a {left:?} after the cut; latest round trip at the cut {rtt:?}");
    cleanup_nodes(&mut rig.nodes).await;
    (left, rtt)
}

/// Under load, with B's session datagrams still arriving on lane `a`
/// whatever B's own verdict, a cut of A's own sending direction on `a`
/// moves A's link off `a` within the cap, three active probe intervals and
/// the timeout floor: a verdict waits for the peer's traffic only up to
/// the cap. The queue is kept under a third of the cap, so the probe
/// timeout from the latest round trip stays under the cap and the cap is
/// what bounds the wait.
#[tokio::test]
async fn a_one_way_failure_under_load_is_left_within_the_cap_while_the_peers_traffic_still_arrives()
{
    let (left, rtt) = oneway(Duration::from_millis(900)).await;
    assert!(
        rtt * 3 < CAP,
        "precondition: three latest round trips ({rtt:?}) are under the cap"
    );
    let bound = CAP + Duration::from_millis(3 * 200 + 400);
    assert!(
        left.is_some_and(|t| t <= bound),
        "defect: A's link left lane a {left:?} after a cut of its own direction, past {bound:?}"
    );
}

/// The same cut under a 2 s queue: the latest round trip is past a third of
/// the cap, so today's timeout of three times it, which the cap leaves
/// alone, sets the bound in the cap's place.
#[tokio::test]
async fn a_one_way_failure_under_a_queue_past_a_third_of_the_cap_is_left_within_three_round_trips()
{
    let (left, rtt) = oneway(Duration::from_secs(2)).await;
    assert!(
        rtt * 3 > CAP,
        "precondition: three latest round trips ({rtt:?}) are over the cap"
    );
    let bound = rtt * 3 + Duration::from_millis(3 * 200 + 400);
    assert!(
        left.is_some_and(|t| t <= bound),
        "defect: A's link left lane a {left:?} after a cut of its own direction, past {bound:?}"
    );
}

/// Lane `b` of the lab's oscillation: as slow as lane `a`, 1 Mbit/s, with a
/// 50 ms base delay, so idle it scores about twice `a`'s.
const LANE_FAR: Spec = Spec {
    name: "b",
    transport: 2,
    bps: 1_000_000,
    base: Duration::from_millis(50),
};

/// The horizon the node keeps each path's least round trip over, beside
/// the round-trip window.
fn horizon() -> Duration {
    fips_core::proto::path::Config::draft().horizon
}

/// Changes of A's active path over a loaded phase of `span` that the rule
/// on the active path's longer-horizon round trip allows: a discretionary
/// move away from a path its own load slowed comes only once that load has
/// filled the horizon, so at most one departure per horizon, each followed
/// by at most one return.
fn allowed(span: Duration) -> u32 {
    2 * (span.as_secs() / horizon().as_secs()) as u32
}

/// A rig on `specs` as [`Rig::new`] makes it, run idle with `reverse` on
/// for the horizon, a sixth of it more and a second, so the round trips its
/// paths measured while the nodes were set up, before the lanes paced
/// anything, have left every path's horizon. Returns the rig, with the
/// instant the idle run started, and its tally.
async fn warmed(specs: &[Spec], reverse: Reverse) -> (Rig, Duration, Tally, Vec<String>) {
    let mut rig = Rig::new(specs).await;
    rig.reverse = reverse;
    let mut tally = Tally::default();
    let mut timeline = Vec::new();
    let start = rig.at();
    let idle = horizon() + horizon() / 6 + Duration::from_secs(1);
    run(&mut rig, idle, start, &mut tally, &mut timeline).await;
    assert_eq!(tally.changes, 0, "precondition: idle, the link stays on a");
    (rig, start, tally, timeline)
}

/// Unpinned, with two lanes in the lab's shape (`a` with a 5 ms base delay,
/// `b` with 50 ms) and load above both their rates keeping a 1 s queue on
/// whichever lane carries the link, with reverse traffic: over 300 s the
/// link changes active path no more often than the longer-horizon rule
/// allows. Load on the active path raises its least round trip over the
/// sample window within seconds; moving on that alone hands the link to the
/// idle lane, whose own least round trip then rises under the load that
/// follows it, and back, every few seconds (the lab's 17 bursts in 280 s).
#[tokio::test]
async fn an_unpinned_link_loaded_past_both_lanes_rates_does_not_oscillate_between_them() {
    let (mut rig, start, _, mut timeline) = warmed(&[LANE_A, LANE_FAR], Reverse::Acks).await;
    rig.load = Some(Load {
        bps: 4 * LANE_A.bps,
        target: Duration::from_secs(1),
    });
    let span = Duration::from_secs(300);
    let mut loaded = Tally::default();
    run(&mut rig, span, start, &mut loaded, &mut timeline).await;
    report(
        "1 s queue on both lanes in turn, unpinned, reverse on, 300 s",
        &timeline,
        &loaded,
        &rig,
    );
    assert!(
        loaded.queued >= Duration::from_millis(900),
        "precondition: the load built its 1 s queue on lane a"
    );
    let bound = allowed(span);
    assert!(
        loaded.changes <= bound,
        "defect: the loaded link changed active path {} times in {span:?}, past {bound}",
        loaded.changes
    );
    cleanup_nodes(&mut rig.nodes).await;
}

/// Unpinned, lane `a` loaded so its round trip rises to about 125 ms (the
/// second field report's loaded Wi-Fi samples ran from 103 to 164 ms), with
/// reverse traffic, against an idle standby at BLE rate whose round trip is
/// about 45 ms: for 60 s, two round-trip windows, the link spends no time
/// on the slow lane after the first 5 s of load. Idle, `a` scores well
/// within the standby's; only its own load lifts its windowed score past
/// the standby's by the margin.
#[tokio::test]
async fn sustained_load_on_a_fast_lane_does_not_hand_the_link_to_an_idle_slow_standby() {
    let (mut rig, start, mut tally, mut timeline) = warmed(&[LANE_A, LANE_C], Reverse::Acks).await;
    rig.load = Some(Load {
        bps: 4 * LANE_A.bps,
        target: Duration::from_millis(120),
    });
    let onset = rig.at();
    let mut slow = Duration::ZERO;
    let until = onset + Duration::from_secs(60);
    while rig.at() < until {
        run(&mut rig, STEP, start, &mut tally, &mut timeline).await;
        if rig.active() == 1 && rig.at() > onset + Duration::from_secs(5) {
            slow += STEP;
        }
    }
    report(
        "120 ms queue on a, unpinned, reverse on, BLE-rate standby, 60 s",
        &timeline,
        &tally,
        &rig,
    );
    println!("time on the slow lane after the first 5 s of load: {slow:?}");
    assert!(
        tally.rtt >= Duration::from_millis(100),
        "precondition: lane a's round trip rose past 100 ms under load"
    );
    assert_eq!(
        slow,
        Duration::ZERO,
        "defect: the link spent {slow:?} on the slow standby after the first 5 s of load"
    );
    cleanup_nodes(&mut rig.nodes).await;
}

/// When lane `a` answered again after the outage [`outage`] makes, and
/// when the link was back on it, each counted from the outage healing.
struct Return {
    /// Lane `a` Live again at A.
    live: Duration,
    /// The link back on lane `a`, if it was within 60 s.
    back: Option<Duration>,
}

/// Unpinned, lane `a` loaded with reverse traffic and a BLE-rate standby,
/// warmed for the horizon: after 5 s of load, a 2 s outage of `a` both ways
/// moves the link to the standby by the mandatory rule, and the load
/// follows it there. Returns when `a` was Live again at A after the outage
/// healed, and when the link was back on `a`.
async fn outage() -> Return {
    let (mut rig, start, mut tally, mut timeline) = warmed(&[LANE_A, LANE_C], Reverse::Acks).await;
    rig.load = Some(Load {
        bps: 4 * LANE_A.bps,
        target: Duration::from_millis(120),
    });
    run(
        &mut rig,
        Duration::from_secs(5),
        start,
        &mut tally,
        &mut timeline,
    )
    .await;
    assert_eq!(tally.changes, 0, "precondition: the link is still on a");
    rig.cut(true);
    run(
        &mut rig,
        Duration::from_secs(2),
        start,
        &mut tally,
        &mut timeline,
    )
    .await;
    assert_eq!(rig.active(), 1, "precondition: the outage moved the link");
    for p in &mut rig.lanes[0].pacers {
        p.cut = false;
    }
    let healed = rig.at();
    timeline.push(format!(
        "t={:>6.2}s the outage of a heals",
        (healed - start).as_secs_f64()
    ));
    let mut live = None;
    let mut back = None;
    let until = healed + Duration::from_secs(60);
    while rig.at() < until && back.is_none() {
        run(&mut rig, STEP, start, &mut tally, &mut timeline).await;
        if live.is_none() && rig.state(0, 0) == Some(PathState::Live) {
            live = Some(rig.at() - healed);
        }
        if rig.active() == 0 {
            back = Some(rig.at() - healed);
        }
    }
    report(
        "2 s outage of loaded a, unpinned, reverse on, BLE-rate standby",
        &timeline,
        &tally,
        &rig,
    );
    println!("after healing: a Live at A {live:?}, link back on a {back:?}");
    cleanup_nodes(&mut rig.nodes).await;
    Return {
        live: live.expect("precondition: lane a is Live again at A"),
        back,
    }
}

/// After [`outage`], the link returns to lane `a` as it does without the
/// longer-horizon rule: within the sample window at the active cadence,
/// filled by the standby's loaded round trips, plus the dwell and a second.
/// The rule holds only moves to a path slower at its best than the active
/// path; it never holds a move to a path faster at its best.
#[tokio::test]
async fn after_a_mandatory_move_to_a_slow_standby_the_return_to_the_fast_lane_is_not_held() {
    let Return { live, back } = outage().await;
    let window = Duration::from_millis(32 * 200);
    let dwell = fips_core::proto::path::Config::draft().switch_dwell;
    let bound = live + window + dwell + Duration::from_secs(1);
    assert!(
        back.is_some_and(|t| t <= bound),
        "defect: the link returned to lane a {back:?} after the outage healed, past {bound:?}"
    );
}

/// After [`outage`], the link is back on lane `a` within the dwell and a
/// second of the outage healing. Lane `a`, idle once the load has followed
/// the link away, outscores the loaded standby as soon as it is Live
/// again; the switch margin, which keeps the link from changing between
/// paths of near scores, must not hold the return to the path a mandatory
/// move left until the standby's own loaded round trips fill its window.
#[tokio::test]
async fn after_a_mandatory_move_the_link_returns_to_the_recovered_fast_lane_within_the_dwell_and_a_second()
 {
    let Return { back, .. } = outage().await;
    let dwell = fips_core::proto::path::Config::draft().switch_dwell;
    let bound = dwell + Duration::from_secs(1);
    assert!(
        back.is_some_and(|t| t <= bound),
        "defect: the link returned to lane a {back:?} after the outage healed, past {bound:?}"
    );
}
