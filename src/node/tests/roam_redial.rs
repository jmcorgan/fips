//! A peer whose transport address changes while its node keeps running, and
//! a node that hears a held peer at a new address.
//!
//! Two real nodes on the loopback transport, which is connectionless as UDP
//! is, run every timer and every handshake and frame path of their own. The
//! thread's monotonic clock is frozen and moved only by the driver, together
//! with the wall clock, in steps of `STEP_MS`, after each of which both nodes
//! run their receive loop's timers in its tick order and everything sent is
//! handed over until both are quiet. Both peers are built by a real dial
//! (`initiate_connection`), so each carries its MMP receiver and the
//! link-dead reaper reads real silence; no peer is marked stale by hand; and
//! no timeout is shortened: every interval elapses on the frozen clock at
//! its stock length.
//!
//! A (node 0) dials B (node 1), so B holds the msg2 it answered A's setup
//! msg1 with. A's address change gives A a new loopback address on the same
//! transport and leaves its old address either black-holed (a send to it
//! succeeds and the packet is lost, as a send to a vanished link-local
//! neighbour does once queued) or unroutable (a send to it fails).
//!
//! The responder case (issue 130's Wi-Fi report) is driven three ways, by
//! what makes A send a msg1 from its new address:
//!
//! - `Trigger::Roam`: nothing but the address change. A keeps its peering
//!   and its heartbeats go out from the new address.
//! - `Trigger::Detach`: A's interface goes away and comes back at the new
//!   address, the production detach edge (`path_presence`) the receive loop
//!   runs for an interface-bound transport. A withdraws B at once, B is
//!   configured at A as an auto-connect peer, and A's reconnect dials B
//!   from the new address while B still holds a peering it heard from a
//!   moment ago.
//! - `Trigger::Outage`: A is cut off both ways for a stated time, its address
//!   changing at the start, so each end's link-dead reaper runs on its own.
//!
//! The initiator case (the BLE report) has A hear beacons of B at a new
//! address every few seconds while their session is healthy, A's transport
//! dialling what it discovers.
//!
//! Each test asserts what the tree does today, with the multipath setting
//! stated per end; these are characterisations, not targets, apart from
//! issue 130's target at the end of the responder tests.
//!
//! On this line the link handshake is Noise XX: the dialler's identity
//! first appears at its msg3, so B answers a dial from A's new address
//! before it knows the dial is A's, and settles the msg3 against the
//! peering it holds by the crossing rule, which goes by node-address order.
//! The responder tests therefore state each order on its own.

use super::paths::{beacon, capable_at, loopback};
use super::settle::with_path;
use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, add_loopback_alias, cleanup_nodes, loopback_tap,
    make_test_node_with_config,
};
use super::*;
use crate::config::PeerConfig;
use crate::node::stats::HandshakeStatsSnapshot;
use crate::proto::fmp::wire::{CommonPrefix, Msg1Header, PHASE_MSG1, PHASE_MSG2};
use crate::proto::link::LinkMessageType;
use crate::transport::loopback::LoopbackTransport;
use crate::transport::{TransportHandle, TransportId};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// How far the clocks move between two ticks of both nodes.
const STEP_MS: u64 = 500;

/// The multipath setting (`node.path.enabled`) at each end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Multipath {
    /// On at both ends.
    On,
    /// Off at both ends.
    Off,
    /// On at A only.
    AOnly,
    /// On at B only.
    BOnly,
}

impl Multipath {
    /// The setting at A.
    fn a(self) -> bool {
        matches!(self, Multipath::On | Multipath::AOnly)
    }

    /// The setting at B.
    fn b(self) -> bool {
        matches!(self, Multipath::On | Multipath::BOnly)
    }
}

/// What a send to A's old address does after A has left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OldAddr {
    /// The send succeeds and the packet is lost.
    Blackhole,
    /// The send fails.
    Unroutable,
}

/// What, besides the address change, makes A send a msg1 from its new
/// address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Trigger {
    /// Nothing: A keeps its peering with B.
    Roam,
    /// A's interface goes away and returns at the new address.
    Detach,
    /// A is cut off both ways for this many seconds.
    Outage(u64),
}

/// How B's peering with A was carried onto A's new address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum How {
    /// The same link and session, followed to the new address.
    Roamed,
    /// The same link on a session of a later rekey.
    Rekeyed,
    /// A link B promoted after the change.
    NewLink,
}

/// What a run saw, with times in seconds after the change.
#[derive(Debug)]
pub(super) struct Outcome {
    /// A's msg1s that reached B from A's new address.
    pub(super) msg1s: usize,
    /// When the first of them reached B.
    pub(super) first_msg1: Option<f64>,
    /// msg2s B sent that reached A, and how many of them were the msg2 B
    /// answered A's setup msg1 with.
    pub(super) msg2s: usize,
    pub(super) stale_msg2s: usize,
    /// B's handshake refusal counters, counted from the change.
    pub(super) b_refused: HandshakeStatsSnapshot,
    /// When A stopped holding B, and when B stopped holding A.
    pub(super) a_dropped: Option<f64>,
    pub(super) b_dropped: Option<f64>,
    /// When both ends first held one session with B at A's new address.
    pub(super) settled: Option<f64>,
    /// How B's peering reached the new address, at `settled`.
    pub(super) how: Option<How>,
    /// Packets B sent to A's old address that reached it.
    #[allow(dead_code)] // printed, never asserted
    pub(super) to_old: usize,
    /// Whether a heartbeat each way authenticated at the end of the run.
    pub(super) works: bool,
}

/// A and B, the record of what passed between them, and the clocks.
struct Pair {
    nodes: Vec<TestNode>,
    /// Time since the pair was built, in ms.
    t: u64,
    /// When A's address changed.
    change: Option<u64>,
    /// What reaches A's old address once it is black-holed.
    sink: UnboundedReceiver<ReceivedPacket>,
    sink_tx: UnboundedSender<ReceivedPacket>,
    /// B's own entry in the loopback registry while an outage holds it.
    b_entry: Option<(TransportId, UnboundedSender<ReceivedPacket>)>,
    /// B's link and index for A, and the msg2 it stored, before the change.
    before: Option<(LinkId, Option<SessionIndex>, Option<Vec<u8>>)>,
    refused: Option<HandshakeStatsSnapshot>,
    msg1s: Vec<u64>,
    /// msg1s that reached B from any address.
    msg1s_any: usize,
    /// Addresses of B's that deliver to the test, which hands what reaches
    /// them to B, and how many msg1s reached them.
    taps: Vec<UnboundedReceiver<ReceivedPacket>>,
    to_taps: usize,
    first_tap: Option<u64>,
    msg2s: usize,
    stale: usize,
    to_old: usize,
    a_dropped: Option<u64>,
    b_dropped: Option<u64>,
    settled: Option<(u64, How)>,
}

/// One pass of `node`'s timers as its receive loop runs them: the loop's
/// whole tick (`Node::tick`, every timer in its production order), then the
/// path machines' tick, which the loop runs on its own timer arm, when any
/// is armed.
async fn tick(node: &mut Node) {
    node.tick(false).await;
    if node.paths.armed() {
        node.path_tick().await;
    }
}

/// The phase of `packet`'s common prefix.
fn phase(packet: &ReceivedPacket) -> Option<u8> {
    CommonPrefix::parse(&packet.data).map(|p| p.phase)
}

/// Seconds from `from` to `at`, both in ms.
fn secs(at: u64, from: u64) -> f64 {
    at.saturating_sub(from) as f64 / 1000.0
}

impl Pair {
    /// A dialling B with the multipath setting `mp`, A's node address the
    /// smaller when `a_smaller`. B is configured at A as an auto-connect
    /// peer at its address, so A redials it after losing it.
    async fn new(mp: Multipath, a_smaller: bool) -> Pair {
        crate::time::freeze();
        let b = make_test_node_with_config(with_path(Config::new(), mp.b()), 1280).await;
        let a = loop {
            let mut config = with_path(Config::new(), mp.a());
            config.peers.push(PeerConfig::new(
                b.node.npub(),
                "loopback",
                b.addr.to_string(),
            ));
            let a = make_test_node_with_config(config, 1280).await;
            if (a.node.node_addr() < b.node.node_addr()) == a_smaller {
                break a;
            }
        };
        let (sink_tx, sink) = unbounded_channel();
        let mut nodes = vec![a, b];
        // A started daemon's state: the reconnect and discovery dials are
        // gated on it.
        for tn in nodes.iter_mut() {
            tn.node.supervisor.state = crate::node::NodeState::Running;
        }
        let mut pair = Pair {
            nodes,
            t: 0,
            change: None,
            sink,
            sink_tx,
            b_entry: None,
            before: None,
            refused: None,
            msg1s: Vec::new(),
            msg1s_any: 0,
            taps: Vec::new(),
            to_taps: 0,
            first_tap: None,
            msg2s: 0,
            stale: 0,
            to_old: 0,
            a_dropped: None,
            b_dropped: None,
            settled: None,
        };
        let id = PeerIdentity::from_pubkey_full(pair.nodes[1].node.identity().pubkey_full());
        let (tid, b_addr) = (pair.nodes[0].transport_id, pair.nodes[1].addr.clone());
        pair.nodes[0]
            .node
            .initiate_connection(tid, b_addr, Some(id))
            .await
            .expect("precondition: A's dial starts");
        pair.pump().await;
        assert!(
            pair.a_holds_b() && pair.b_holds_a(),
            "precondition: A and B peered"
        );
        pair
    }

    fn a_addr(&self) -> NodeAddr {
        *self.nodes[0].node.node_addr()
    }

    fn b_addr(&self) -> NodeAddr {
        *self.nodes[1].node.node_addr()
    }

    fn a_holds_b(&self) -> bool {
        self.nodes[0].node.get_peer(&self.b_addr()).is_some()
    }

    fn b_holds_a(&self) -> bool {
        self.nodes[1].node.get_peer(&self.a_addr()).is_some()
    }

    /// Hand each node what it was sent, recording what passes, until a
    /// round moves nothing.
    async fn pump(&mut self) {
        for _ in 0..1000 {
            let mut moved = 0;
            for at in 0..2 {
                while let Ok(packet) = self.nodes[at].packet_rx.try_recv() {
                    self.observe(at, &packet);
                    self.nodes[at].node.process_packet(packet).await;
                    moved += 1;
                }
            }
            while self.sink.try_recv().is_ok() {
                self.to_old += 1;
            }
            let mut tapped = Vec::new();
            for tap in self.taps.iter_mut() {
                while let Ok(packet) = tap.try_recv() {
                    tapped.push(packet);
                }
            }
            for packet in tapped {
                if phase(&packet) == Some(PHASE_MSG1) {
                    self.to_taps += 1;
                    self.first_tap.get_or_insert(self.t);
                }
                self.observe(1, &packet);
                self.nodes[1].node.process_packet(packet).await;
                moved += 1;
            }
            if moved == 0 {
                return;
            }
        }
        panic!("precondition: the pair went quiet within 1000 rounds");
    }

    /// Record a msg1 reaching B from A's new address, and a msg2 reaching A.
    fn observe(&mut self, at: usize, packet: &ReceivedPacket) {
        if self.change.is_none() {
            return;
        }
        match (at, phase(packet)) {
            (1, Some(PHASE_MSG1)) if Msg1Header::parse(&packet.data).is_some() => {
                self.msg1s_any += 1;
                if packet.remote_addr == self.nodes[0].addr {
                    self.msg1s.push(self.t);
                }
            }
            (0, Some(PHASE_MSG2)) => {
                self.msg2s += 1;
                let stored = self.before.as_ref().and_then(|(_, _, m)| m.as_ref());
                if stored.is_some_and(|m| *m == packet.data) {
                    self.stale += 1;
                }
            }
            _ => {}
        }
    }

    /// Move both clocks on by `STEP_MS`, run both nodes' timers, and hand
    /// over what they sent.
    async fn step(&mut self) {
        crate::time::advance(Duration::from_millis(STEP_MS));
        crate::time::step_wall(STEP_MS as i64);
        self.t += STEP_MS;
        for tn in self.nodes.iter_mut() {
            tick(&mut tn.node).await;
        }
        self.pump().await;
        self.note();
    }

    /// Run for `secs` seconds.
    async fn run(&mut self, secs: u64) {
        for _ in 0..secs * 1000 / STEP_MS {
            self.step().await;
        }
    }

    /// Record losses and the first settlement after the change.
    fn note(&mut self) {
        if self.change.is_none() {
            return;
        }
        if !self.a_holds_b() && self.a_dropped.is_none() {
            self.a_dropped = Some(self.t);
        }
        if !self.b_holds_a() && self.b_dropped.is_none() {
            self.b_dropped = Some(self.t);
        }
        if self.settled.is_none()
            && let Some(how) = self.one_session_at_the_new_address()
        {
            self.settled = Some((self.t, how));
        }
    }

    /// How B's peering reached A's new address, when both ends hold one
    /// session and B's frames to A go to that address.
    fn one_session_at_the_new_address(&self) -> Option<How> {
        let ap = self.nodes[0].node.get_peer(&self.b_addr())?;
        let bp = self.nodes[1].node.get_peer(&self.a_addr())?;
        let crossed = ap.our_index().is_some()
            && ap.our_index() == bp.their_index()
            && ap.their_index() == bp.our_index();
        if !crossed || bp.current_addr() != Some(&self.nodes[0].addr) {
            return None;
        }
        let (link, index, _) = self.before.as_ref()?;
        Some(if bp.link_id() != *link {
            How::NewLink
        } else if bp.our_index() != *index {
            How::Rekeyed
        } else {
            How::Roamed
        })
    }

    /// A's address changes: A sends from a new loopback address on the same
    /// transport, and its old address goes as `old` says.
    fn move_a(&mut self, old: OldAddr) {
        let bp = self.nodes[1]
            .node
            .get_peer(&self.a_addr())
            .expect("precondition: B holds A before the change");
        self.before = Some((
            bp.link_id(),
            bp.our_index(),
            bp.handshake_msg2().map(<[u8]>::to_vec),
        ));
        self.refused = Some(self.nodes[1].node.stats().handshake.snapshot());
        let a = &mut self.nodes[0];
        let tid = a.transport_id;
        let new = add_loopback_alias(&a.addr, tid);
        let mut registry = LOOPBACK_REGISTRY.lock().unwrap();
        match old {
            OldAddr::Blackhole => {
                registry.insert(a.addr.clone(), (tid, self.sink_tx.clone()));
            }
            OldAddr::Unroutable => {
                registry.remove(&a.addr);
            }
        }
        drop(registry);
        let lo = LoopbackTransport::with_mtu(tid, new.clone(), 1280, LOOPBACK_REGISTRY.clone());
        a.node.transports.insert(tid, TransportHandle::Loopback(lo));
        a.addr = new;
        self.change = Some(self.t);
    }

    /// Lose everything sent to B's address, or stop losing it.
    fn cut_b(&mut self, cut: bool) {
        let b = &self.nodes[1];
        let mut registry = LOOPBACK_REGISTRY.lock().unwrap();
        if cut {
            let entry = registry
                .insert(b.addr.clone(), (b.transport_id, unbounded_channel().0))
                .expect("precondition: B's address is registered");
            self.b_entry = Some(entry);
        } else if let Some(entry) = self.b_entry.take() {
            registry.insert(b.addr.clone(), entry);
        }
    }

    /// Whether a heartbeat from `from` authenticates at `to`.
    async fn heartbeat(&mut self, from: usize, to: usize) -> bool {
        let to_addr = *self.nodes[to].node.node_addr();
        let from_addr = *self.nodes[from].node.node_addr();
        let recv = |p: &Pair| {
            p.nodes[to]
                .node
                .get_peer(&from_addr)
                .map(|p| p.link_stats().packets_recv)
        };
        let before = recv(self);
        if self.nodes[from]
            .node
            .send_encrypted_link_message(&to_addr, &[LinkMessageType::Heartbeat.to_byte()])
            .await
            .is_err()
        {
            return false;
        }
        self.pump().await;
        matches!((before, recv(self)), (Some(b), Some(a)) if a > b)
    }

    /// What the run saw.
    async fn outcome(&mut self) -> Outcome {
        let change = self.change.expect("precondition: the address changed");
        let now = self.nodes[1].node.stats().handshake.snapshot();
        let was = self.refused.clone().unwrap_or_default();
        let b_refused = HandshakeStatsSnapshot {
            bad_state: now.bad_state - was.bad_state,
            unknown_connection: now.unknown_connection - was.unknown_connection,
            silent_backoff: now.silent_backoff - was.silent_backoff,
            max_peers: now.max_peers - was.max_peers,
            rekey_pending: now.rekey_pending - was.rekey_pending,
            rekey_tiebreak: now.rekey_tiebreak - was.rekey_tiebreak,
            answered_before: now.answered_before - was.answered_before,
            off_link: now.off_link - was.off_link,
            rekey_static_mismatch: now.rekey_static_mismatch - was.rekey_static_mismatch,
        };
        let works = self.heartbeat(0, 1).await && self.heartbeat(1, 0).await;
        Outcome {
            msg1s: self.msg1s.len(),
            first_msg1: self.msg1s.first().map(|&t| secs(t, change)),
            msg2s: self.msg2s,
            stale_msg2s: self.stale,
            b_refused,
            a_dropped: self.a_dropped.map(|t| secs(t, change)),
            b_dropped: self.b_dropped.map(|t| secs(t, change)),
            settled: self.settled.map(|(t, _)| secs(t, change)),
            how: self.settled.map(|(_, h)| h),
            to_old: self.to_old,
            works,
        }
    }
}

/// The responder case: A and B peer, the link runs for `age_secs`, then A's
/// address changes, with `trigger` and `old` as they say, and the pair runs
/// for `window_secs` more.
pub(super) async fn responder(
    mp: Multipath,
    a_smaller: bool,
    age_secs: u64,
    trigger: Trigger,
    old: OldAddr,
    window_secs: u64,
) -> Outcome {
    let mut pair = Pair::new(mp, a_smaller).await;
    pair.run(age_secs).await;
    assert!(
        pair.a_holds_b() && pair.b_holds_a(),
        "precondition: the link is still up at {age_secs} s"
    );
    let tid = pair.nodes[0].transport_id;
    match trigger {
        Trigger::Roam => pair.move_a(old),
        Trigger::Detach => {
            pair.nodes[0].node.path_presence(tid, false).await;
            pair.move_a(old);
            pair.nodes[0].node.path_presence(tid, true).await;
            pair.note();
        }
        Trigger::Outage(secs) => {
            pair.move_a(old);
            pair.cut_b(true);
            pair.run(secs).await;
            pair.cut_b(false);
        }
    }
    pair.pump().await;
    let ran = match trigger {
        Trigger::Outage(secs) => secs,
        _ => 0,
    };
    pair.run(window_secs.saturating_sub(ran)).await;
    let outcome = pair.outcome().await;
    cleanup_nodes(&mut pair.nodes).await;
    outcome
}

/// What the initiator case saw over its window.
#[derive(Debug)]
pub(super) struct Redials {
    /// Beacons of B at a new address A was given.
    pub(super) beacons: usize,
    /// msg1s A sent that reached B, and how many of them A sent to one of
    /// the beaconed addresses: its dials there.
    #[allow(dead_code)] // printed, never asserted
    pub(super) msg1s: usize,
    pub(super) dials: usize,
    /// When the first of those dials reached B, in seconds into the window.
    pub(super) first_dial: Option<f64>,
    /// Whether A held B as capable when the window began.
    #[allow(dead_code)] // printed, never asserted
    pub(super) capable: bool,
    /// msg2s B sent that reached A.
    #[allow(dead_code)] // printed, never asserted
    pub(super) msg2s: usize,
    /// Steps after which A's peering with B, or B's with A, sat on another
    /// link than after the step before, at A and at B.
    #[allow(dead_code)] // printed, never asserted
    pub(super) a_links: usize,
    pub(super) b_links: usize,
    /// Steps after which it sat on the same link with another index.
    #[allow(dead_code)] // printed, never asserted
    pub(super) a_indices: usize,
    #[allow(dead_code)] // printed, never asserted
    pub(super) b_indices: usize,
    /// The most consecutive decryption failures either end held for the
    /// other after any step.
    pub(super) decrypt_failures: u32,
    /// Steps after which either end held no peer for the other.
    pub(super) unpeered: usize,
    /// B's handshake refusal counters over the window.
    #[allow(dead_code)] // printed, never asserted
    pub(super) b_refused: HandshakeStatsSnapshot,
    /// The paths A holds to B at the end.
    #[allow(dead_code)] // printed, never asserted
    pub(super) a_paths: usize,
    /// Whether a heartbeat each way authenticated at the end of the run.
    pub(super) works: bool,
}

impl Pair {
    /// Each end's (link, index) for the other.
    fn sessions(&self) -> [Option<(LinkId, Option<SessionIndex>)>; 2] {
        let a = self.nodes[0]
            .node
            .get_peer(&self.b_addr())
            .map(|p| (p.link_id(), p.our_index()));
        let b = self.nodes[1]
            .node
            .get_peer(&self.a_addr())
            .map(|p| (p.link_id(), p.our_index()));
        [a, b]
    }
}

/// The initiator case: A and B peer, the link runs for `age_secs`, then for
/// `window_secs` A hears a beacon of B at a new address of B's every
/// `every_secs`, A's transport dialling what it discovers. B's old address
/// keeps working, as an established BLE connection outlives the advertising
/// address that rotated.
pub(super) async fn initiator(
    mp: Multipath,
    a_smaller: bool,
    age_secs: u64,
    every_secs: u64,
    window_secs: u64,
) -> Redials {
    let mut pair = Pair::new(mp, a_smaller).await;
    pair.run(age_secs).await;
    assert!(
        pair.a_holds_b() && pair.b_holds_a(),
        "precondition: the link is still up at {age_secs} s"
    );
    let tid = pair.nodes[0].transport_id;
    loopback(&pair.nodes[0], tid).set_autoconnect(true);
    pair.refused = Some(pair.nodes[1].node.stats().handshake.snapshot());
    pair.change = Some(pair.t);
    let start = pair.t;
    let capable = capable_at(&pair.nodes[0], &pair.b_addr());
    let mut last = pair.sessions();
    let (mut beacons, mut unpeered, mut decrypt_failures) = (0, 0, 0);
    let mut links = [0, 0];
    let mut indices = [0, 0];
    let steps_per_beacon = every_secs * 1000 / STEP_MS;
    for i in 0..window_secs * 1000 / STEP_MS {
        if i % steps_per_beacon == 0 {
            let (at, rx) = loopback_tap(pair.nodes[1].transport_id);
            pair.taps.push(rx);
            beacon(&pair.nodes[0], tid, &at, &pair.nodes[1]);
            beacons += 1;
        }
        pair.step().await;
        let now = pair.sessions();
        for end in 0..2 {
            match (last[end], now[end]) {
                (Some((l0, _)), Some((l1, _))) if l0 != l1 => links[end] += 1,
                (Some((_, i0)), Some((_, i1))) if i0 != i1 => indices[end] += 1,
                (_, None) => unpeered += 1,
                _ => {}
            }
        }
        let fails = [
            pair.nodes[0].node.get_peer(&pair.b_addr()),
            pair.nodes[1].node.get_peer(&pair.a_addr()),
        ]
        .into_iter()
        .flatten()
        .map(|p| p.consecutive_decrypt_failures())
        .max()
        .unwrap_or(0);
        decrypt_failures = decrypt_failures.max(fails);
        last = now;
    }
    let now = pair.nodes[1].node.stats().handshake.snapshot();
    let was = pair.refused.clone().unwrap_or_default();
    let b_refused = HandshakeStatsSnapshot {
        bad_state: now.bad_state - was.bad_state,
        unknown_connection: now.unknown_connection - was.unknown_connection,
        silent_backoff: now.silent_backoff - was.silent_backoff,
        max_peers: now.max_peers - was.max_peers,
        rekey_pending: now.rekey_pending - was.rekey_pending,
        rekey_tiebreak: now.rekey_tiebreak - was.rekey_tiebreak,
        answered_before: now.answered_before - was.answered_before,
        off_link: now.off_link - was.off_link,
        rekey_static_mismatch: now.rekey_static_mismatch - was.rekey_static_mismatch,
    };
    let a_paths = pair.nodes[0]
        .node
        .get_peer(&pair.b_addr())
        .and_then(|p| p.bundle())
        .map_or(0, |b| b.paths().len());
    let works = pair.heartbeat(0, 1).await && pair.heartbeat(1, 0).await;
    let out = Redials {
        beacons,
        msg1s: pair.msg1s_any,
        dials: pair.to_taps,
        first_dial: pair.first_tap.map(|t| secs(t, start)),
        capable,
        msg2s: pair.msg2s,
        a_links: links[0],
        b_links: links[1],
        a_indices: indices[0],
        b_indices: indices[1],
        decrypt_failures,
        unpeered,
        b_refused,
        a_paths,
        works,
    };
    cleanup_nodes(&mut pair.nodes).await;
    out
}

/// Every combination of the node addresses' order and what a send to A's
/// old address does, which a responder test runs under each.
const RUNS: [(bool, OldAddr); 4] = [
    (true, OldAddr::Blackhole),
    (false, OldAddr::Blackhole),
    (true, OldAddr::Unroutable),
    (false, OldAddr::Unroutable),
];

/// The responder runs of `trigger` at link age `age_secs` under every one
/// of `RUNS`, each outcome printed.
async fn responder_runs(
    mp: Multipath,
    age_secs: u64,
    trigger: Trigger,
    window_secs: u64,
) -> Vec<Outcome> {
    let mut out = Vec::new();
    for (a_smaller, old) in RUNS {
        let o = responder(mp, a_smaller, age_secs, trigger, old, window_secs).await;
        eprintln!("{mp:?} a_smaller {a_smaller} age {age_secs} s {trigger:?} {old:?}: {o:?}");
        out.push(o);
    }
    out
}

/// No msg1: B follows A to the new address on A's first heartbeat from it,
/// on the same link and session, and neither end drops the other.
async fn followed_with_no_handshake(mp: Multipath) {
    for o in responder_runs(mp, 60, Trigger::Roam, 30).await {
        assert!(
            o.msg1s == 0
                && o.settled == Some(0.5)
                && o.how == Some(How::Roamed)
                && o.a_dropped.is_none()
                && o.b_dropped.is_none()
                && o.works,
            "{o:?}"
        );
    }
}

#[tokio::test]
async fn a_peer_whose_address_changes_with_its_link_up_is_followed_on_its_first_heartbeat_with_no_handshake_multipath_off()
 {
    followed_with_no_handshake(Multipath::Off).await;
}

#[tokio::test]
async fn a_peer_whose_address_changes_with_its_link_up_is_followed_on_its_first_heartbeat_with_no_handshake_multipath_on()
 {
    followed_with_no_handshake(Multipath::On).await;
}

/// The handshake counters of `r` that refuse a msg1 or a msg3, summed.
fn refusals(r: &HandshakeStatsSnapshot) -> u64 {
    r.bad_state
        + r.unknown_connection
        + r.rekey_static_mismatch
        + r.silent_backoff
        + r.max_peers
        + r.rekey_pending
        + r.rekey_tiebreak
        + r.answered_before
        + r.off_link
}

/// A redial from A, the smaller node, as this line settles it. A's dial
/// from its new address reaches B 5 s after the change, and B answers it.
/// B learns that the dial is A's only at its msg3, which arrives on a link
/// other than the one B holds A on and declares no rekey, so B settles it
/// as a crossing by node-address order: with A the smaller, B moves onto the
/// dial's session and link. Both ends hold it 5 s after the change, B on
/// the dial's link (`How::NewLink`). One msg1 and one msg2
/// pass, none of them stale, B refuses nothing and never drops A, and A,
/// which withdrew B at the detach, dropped it at the change.
fn smaller_settles_at_its_msg3(o: &Outcome) -> bool {
    o.first_msg1 == Some(5.0)
        && o.msg1s == 1
        && refusals(&o.b_refused) == 0
        && o.msg2s == 1
        && o.stale_msg2s == 0
        && o.a_dropped == Some(0.0)
        && o.b_dropped.is_none()
        && o.settled == Some(5.0)
        && o.how == Some(How::NewLink)
        && o.works
}

/// A redial from A, the larger node, as this line settles it: the open
/// case of issue 130 here. B answers the dial 5 s after the change, A
/// promotes B on B's msg2, and at the dial's msg3 B, the smaller node,
/// keeps the session it holds A on. The two ends then sit on different
/// sessions until B's link-dead reaper removes A 30 s after the change,
/// and A's next dial settles on a new link at 40 s. Two msg1s and two
/// msg2s pass, none of them stale, and B refuses nothing.
fn larger_settles_after_the_reap(o: &Outcome) -> bool {
    o.first_msg1 == Some(5.0)
        && o.msg1s == 2
        && refusals(&o.b_refused) == 0
        && o.msg2s == 2
        && o.stale_msg2s == 0
        && o.a_dropped == Some(0.0)
        && o.b_dropped.is_some_and(|d| (29.5..=30.5).contains(&d))
        && o.settled == Some(40.0)
        && o.how == Some(How::NewLink)
        && o.works
}

/// A's interface goes and comes back at a new address, and its reconnect
/// dials B 5 s later, at each link age of `ages` at the change. A redial
/// from the smaller node settles at its msg3
/// ([`smaller_settles_at_its_msg3`]); one from the larger node settles only
/// after B reaps the old peering ([`larger_settles_after_the_reap`]).
async fn redial_settles_by_order(mp: Multipath, ages: &[u64]) {
    for &age in ages {
        let outcomes = responder_runs(mp, age, Trigger::Detach, 90).await;
        for ((a_smaller, _), o) in RUNS.into_iter().zip(outcomes) {
            if a_smaller {
                assert!(
                    smaller_settles_at_its_msg3(&o),
                    "A smaller, age {age}: {o:?}"
                );
            } else {
                assert!(
                    larger_settles_after_the_reap(&o),
                    "A larger, age {age}: {o:?}"
                );
            }
        }
    }
}

/// On a link 60 s old at the change, with B's last frame from A 9.5 s
/// before (age 60), and 51 s old, with it 0.5 s before (age 51).
const AGED: [u64; 2] = [60, 51];

/// On a link 10 s old at the change: the dial's msg1 reaches B on a link
/// 15 s old.
const YOUNG: [u64; 1] = [10];

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_settles_at_5_s_from_the_smaller_node_and_at_40_s_from_the_larger_after_the_responder_reaps_multipath_off()
 {
    redial_settles_by_order(Multipath::Off, &AGED).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_settles_at_5_s_from_the_smaller_node_and_at_40_s_from_the_larger_after_the_responder_reaps_multipath_on()
 {
    redial_settles_by_order(Multipath::On, &AGED).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_settles_at_5_s_from_the_smaller_node_and_at_40_s_from_the_larger_after_the_responder_reaps_multipath_on_at_the_redialler_only()
 {
    redial_settles_by_order(Multipath::AOnly, &AGED).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_settles_at_5_s_from_the_smaller_node_and_at_40_s_from_the_larger_after_the_responder_reaps_multipath_on_at_the_responder_only()
 {
    redial_settles_by_order(Multipath::BOnly, &AGED).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_a_young_link_settles_at_5_s_from_the_smaller_node_and_at_40_s_from_the_larger_after_the_responder_reaps_multipath_off()
 {
    redial_settles_by_order(Multipath::Off, &YOUNG).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_a_young_link_settles_at_5_s_from_the_smaller_node_and_at_40_s_from_the_larger_after_the_responder_reaps_multipath_on()
 {
    redial_settles_by_order(Multipath::On, &YOUNG).await;
}

/// A is cut off both ways for 40 s from the change: both ends' link-dead
/// reapers remove the peering at the same step, and A's reconnect after the
/// outage is promoted at once on a new link, with nothing refused.
async fn both_reap_and_the_retry_promotes(mp: Multipath) {
    for o in responder_runs(mp, 60, Trigger::Outage(40), 90).await {
        let r = &o.b_refused;
        assert!(
            o.msg1s == 1
                && r.bad_state + r.answered_before + r.off_link + r.rekey_pending == 0
                && o.stale_msg2s == 0
                && o.a_dropped.is_some()
                && o.a_dropped == o.b_dropped
                && o.settled.is_some_and(|s| s > 40.0)
                && o.settled == o.first_msg1
                && o.how == Some(How::NewLink)
                && o.works,
            "{o:?}"
        );
    }
}

#[tokio::test]
async fn after_an_outage_past_the_link_dead_timeout_both_ends_reap_and_the_redial_from_the_new_address_is_promoted_unrefused_multipath_off()
 {
    both_reap_and_the_retry_promotes(Multipath::Off).await;
}

#[tokio::test]
async fn after_an_outage_past_the_link_dead_timeout_both_ends_reap_and_the_redial_from_the_new_address_is_promoted_unrefused_multipath_on()
 {
    both_reap_and_the_retry_promotes(Multipath::On).await;
}

/// Issue 130's reported shape, on the detach trigger: a redial from a new
/// address settles before the responder reaps the old peering. A is the
/// smaller node when `a_smaller`. On this line the redial of the smaller
/// node meets it and the redial of the larger does not.
async fn settles_before_the_old_peering_is_reaped(mp: Multipath, a_smaller: bool) {
    let o = responder(mp, a_smaller, 60, Trigger::Detach, OldAddr::Blackhole, 90).await;
    eprintln!("{o:?}");
    assert!(
        o.settled.is_some() && o.b_dropped.is_none_or(|d| o.settled < Some(d)),
        "defect: the redial settled only after B reaped A's old peering: {o:?}"
    );
}

/// The target with A the smaller node, which this line meets.
#[tokio::test]
async fn a_redial_from_a_new_address_settles_before_the_responder_reaps_the_old_peering() {
    settles_before_the_old_peering_is_reaped(Multipath::Off, true).await;
}

/// The same with multipath on.
#[tokio::test]
async fn a_redial_from_a_new_address_settles_before_the_responder_reaps_the_old_peering_with_multipath_on()
 {
    settles_before_the_old_peering_is_reaped(Multipath::On, true).await;
}

/// The target with A the larger node, which this line misses: the redial
/// settles at 40 s, after B reaps the old peering at 30 s.
#[tokio::test]
#[ignore = "known defect: issue 130 on this line, a redial from a new address by the larger node settles only after the responder reaps the old peering"]
async fn a_redial_from_a_new_address_by_the_larger_node_settles_before_the_responder_reaps_the_old_peering()
 {
    settles_before_the_old_peering_is_reaped(Multipath::Off, false).await;
}

/// The same with multipath on.
#[tokio::test]
#[ignore = "known defect: issue 130 on this line, a redial from a new address by the larger node settles only after the responder reaps the old peering"]
async fn a_redial_from_a_new_address_by_the_larger_node_settles_before_the_responder_reaps_the_old_peering_with_multipath_on()
 {
    settles_before_the_old_peering_is_reaped(Multipath::On, false).await;
}

/// The initiator runs at link age 60 s in both orders, each printed.
async fn initiator_runs(mp: Multipath) -> Vec<Redials> {
    let mut out = Vec::new();
    for a_smaller in [true, false] {
        let o = initiator(mp, a_smaller, 60, 5, 120).await;
        eprintln!("{mp:?} a_smaller {a_smaller}: {o:?}");
        out.push(o);
    }
    out
}

/// A hears a beacon of B at a new address every 5 s while their session
/// carries heartbeats. Under the receive loop's whole tick the session never
/// reads stale, so A dials none of the beaconed addresses: no msg1 reaches
/// any of them, neither end ever holds no peer for the other, no decryption
/// fails, and a heartbeat each way still authenticates at the end.
async fn no_redial_and_undisturbed(mp: Multipath) {
    for o in initiator_runs(mp).await {
        assert_eq!(o.beacons, 24, "precondition: 24 beacons in 120 s");
        assert!(
            o.dials == 0
                && o.first_dial.is_none()
                && o.unpeered == 0
                && o.decrypt_failures == 0
                && o.b_links == 0
                && o.works,
            "{o:?}"
        );
    }
}

#[tokio::test]
async fn a_beacon_of_a_held_peer_at_a_new_address_draws_no_redial_and_leaves_the_session_undisturbed_multipath_off()
 {
    no_redial_and_undisturbed(Multipath::Off).await;
}

#[tokio::test]
async fn a_beacon_of_a_held_peer_at_a_new_address_draws_no_redial_and_leaves_the_session_undisturbed_multipath_on()
 {
    no_redial_and_undisturbed(Multipath::On).await;
}

#[tokio::test]
async fn a_beacon_of_a_held_peer_at_a_new_address_draws_no_redial_and_leaves_the_session_undisturbed_multipath_on_at_the_dialler_only()
 {
    no_redial_and_undisturbed(Multipath::AOnly).await;
}

#[tokio::test]
async fn a_beacon_of_a_held_peer_at_a_new_address_draws_no_redial_and_leaves_the_session_undisturbed_multipath_on_at_the_peer_only()
 {
    no_redial_and_undisturbed(Multipath::BOnly).await;
}
