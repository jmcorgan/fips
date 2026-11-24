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
//! Each test asserts what the tree does, with the multipath setting stated
//! per end. A pair can run each node's decrypt workers
//! (`Pair::workers_on`): a frame under a session offered to them is then
//! opened on a worker and its result handed back to the node, each round of
//! the hand-over waiting for the workers to finish what they were sent.

use super::dialer::Dialer;
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
pub(super) const STEP_MS: u64 = 500;

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
    #[allow(dead_code)] // printed, never asserted
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
pub(super) struct Pair {
    pub(super) nodes: Vec<TestNode>,
    /// Time since the pair was built, in ms.
    pub(super) t: u64,
    /// When A's address changed.
    pub(super) change: Option<u64>,
    /// What reaches A's old address once it is black-holed.
    pub(super) sink: UnboundedReceiver<ReceivedPacket>,
    pub(super) sink_tx: UnboundedSender<ReceivedPacket>,
    /// B's own entry in the loopback registry while an outage holds it.
    pub(super) b_entry: Option<(TransportId, UnboundedSender<ReceivedPacket>)>,
    /// B's link and index for A, and the msg2 it stored, before the change.
    pub(super) before: Option<(LinkId, Option<SessionIndex>, Option<Vec<u8>>)>,
    pub(super) refused: Option<HandshakeStatsSnapshot>,
    pub(super) msg1s: Vec<u64>,
    /// msg1s that reached B from any address.
    pub(super) msg1s_any: usize,
    /// Addresses of B's that deliver to the test, which hands what reaches
    /// them to B, and how many msg1s reached them.
    pub(super) taps: Vec<UnboundedReceiver<ReceivedPacket>>,
    pub(super) to_taps: usize,
    pub(super) first_tap: Option<u64>,
    pub(super) msg2s: usize,
    pub(super) stale: usize,
    pub(super) to_old: usize,
    pub(super) a_dropped: Option<u64>,
    pub(super) b_dropped: Option<u64>,
    pub(super) settled: Option<(u64, How)>,
    /// Every msg1 that reached B, byte for byte, in order, from the pair's
    /// first dial on.
    pub(super) seen: Vec<Vec<u8>>,
    /// Each node's decrypt worker events, once its workers run.
    #[cfg(unix)]
    pub(super) events:
        [Option<UnboundedReceiver<crate::node::decrypt_worker::DecryptWorkerEvent>>; 2],
}

/// One pass of `node`'s timers as its receive loop runs them: the loop's
/// whole tick (`Node::tick`, every timer in its production order), then the
/// path machines' tick, which the loop runs on its own timer arm, when any
/// is armed.
pub(super) async fn tick(node: &mut Node) {
    node.tick(false).await;
    if node.paths.armed() {
        node.path_tick().await;
    }
}

/// The handshake counters `now` holds past `was`.
pub(super) fn since(
    now: &HandshakeStatsSnapshot,
    was: &HandshakeStatsSnapshot,
) -> HandshakeStatsSnapshot {
    HandshakeStatsSnapshot {
        bad_state: now.bad_state - was.bad_state,
        unknown_connection: now.unknown_connection - was.unknown_connection,
        silent_backoff: now.silent_backoff - was.silent_backoff,
        max_peers: now.max_peers - was.max_peers,
        rekey_pending: now.rekey_pending - was.rekey_pending,
        rekey_tiebreak: now.rekey_tiebreak - was.rekey_tiebreak,
        answered_before: now.answered_before - was.answered_before,
        off_link: now.off_link - was.off_link,
        redial_held: now.redial_held - was.redial_held,
        redial_seen: now.redial_seen - was.redial_seen,
        redial_dampened: now.redial_dampened - was.redial_dampened,
        redials: now.redials - was.redials,
        redials_proven: now.redials_proven - was.redials_proven,
        redials_adopted: now.redials_adopted - was.redials_adopted,
        redial_session_reopens: now.redial_session_reopens - was.redial_session_reopens,
    }
}

/// The phase of `packet`'s common prefix.
pub(super) fn phase(packet: &ReceivedPacket) -> Option<u8> {
    CommonPrefix::parse(&packet.data).map(|p| p.phase)
}

/// Seconds from `from` to `at`, both in ms.
pub(super) fn secs(at: u64, from: u64) -> f64 {
    at.saturating_sub(from) as f64 / 1000.0
}

impl Pair {
    /// A dialling B with the multipath setting `mp`, A's node address the
    /// smaller when `a_smaller`. B is configured at A as an auto-connect
    /// peer at its address, so A redials it after losing it.
    pub(super) async fn new(mp: Multipath, a_smaller: bool) -> Pair {
        Pair::with_b(mp, a_smaller, |_| {}).await
    }

    /// As [`Pair::new`], with B's configuration changed by `b_config`
    /// first.
    pub(super) async fn with_b(
        mp: Multipath,
        a_smaller: bool,
        b_config: impl FnOnce(&mut Config),
    ) -> Pair {
        crate::time::freeze();
        let mut config = with_path(Config::new(), mp.b());
        b_config(&mut config);
        let b = make_test_node_with_config(config, 1280).await;
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
            seen: Vec::new(),
            #[cfg(unix)]
            events: [None, None],
        };
        let id = PeerIdentity::from_pubkey_full(pair.nodes[1].node.identity().pubkey_full());
        let (tid, b_addr) = (pair.nodes[0].transport_id, pair.nodes[1].addr.clone());
        pair.nodes[0]
            .node
            .initiate_connection(tid, b_addr, id)
            .await
            .expect("precondition: A's dial starts");
        pair.pump().await;
        assert!(
            pair.a_holds_b() && pair.b_holds_a(),
            "precondition: A and B peered"
        );
        pair
    }

    pub(super) fn a_addr(&self) -> NodeAddr {
        *self.nodes[0].node.node_addr()
    }

    pub(super) fn b_addr(&self) -> NodeAddr {
        *self.nodes[1].node.node_addr()
    }

    pub(super) fn a_holds_b(&self) -> bool {
        self.nodes[0].node.get_peer(&self.b_addr()).is_some()
    }

    pub(super) fn b_holds_a(&self) -> bool {
        self.nodes[1].node.get_peer(&self.a_addr()).is_some()
    }

    /// Hand each node what it was sent, recording what passes, until a
    /// round moves nothing.
    pub(super) async fn pump(&mut self) {
        for _ in 0..1000 {
            let mut moved = 0;
            for at in 0..2 {
                while let Ok(packet) = self.nodes[at].packet_rx.try_recv() {
                    self.observe(at, &packet);
                    self.nodes[at].node.process_packet(packet).await;
                    moved += 1;
                }
            }
            #[cfg(unix)]
            {
                moved += self.worked().await;
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

    /// Run each node's decrypt workers from now on, offering them the
    /// session each holds now; later sessions are offered at promotion.
    #[cfg(unix)]
    pub(super) fn workers_on(&mut self) {
        use crate::node::decrypt_worker::DecryptWorkerPool;
        for at in 0..2 {
            let other = *self.nodes[1 - at].node.node_addr();
            let node = &mut self.nodes[at].node;
            node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
            if let Some(offer) = node.get_peer(&other).map(|p| p.offer_to_workers()) {
                node.run_link_outputs(&other, offer);
            }
            self.events[at] = node.decrypt_fallback_rx.take();
        }
    }

    /// Wait for each node's workers to finish what they were sent, and hand
    /// what they report back to the node; the number handed back.
    #[cfg(unix)]
    async fn worked(&mut self) -> usize {
        let mut n = 0;
        for at in 0..2 {
            let Some(mut rx) = self.events[at].take() else {
                continue;
            };
            if let Some(pool) = self.nodes[at].node.supervisor.decrypt_workers.as_ref() {
                pool.barrier();
            }
            while let Ok(event) = rx.try_recv() {
                self.nodes[at]
                    .node
                    .process_decrypt_worker_event(event)
                    .await;
                n += 1;
            }
            self.events[at] = Some(rx);
        }
        n
    }

    /// Record a msg1 reaching B from A's new address, and a msg2 reaching A.
    pub(super) fn observe(&mut self, at: usize, packet: &ReceivedPacket) {
        if at == 1 && phase(packet) == Some(PHASE_MSG1) {
            self.seen.push(packet.data.clone());
        }
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
    pub(super) async fn step(&mut self) {
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
    pub(super) async fn run(&mut self, secs: u64) {
        for _ in 0..secs * 1000 / STEP_MS {
            self.step().await;
        }
    }

    /// Record losses and the first settlement after the change.
    pub(super) fn note(&mut self) {
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
    pub(super) fn one_session_at_the_new_address(&self) -> Option<How> {
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
    pub(super) fn move_a(&mut self, old: OldAddr) {
        let a = &self.nodes[0];
        let new = add_loopback_alias(&a.addr, a.transport_id);
        self.move_a_to(old, new);
    }

    /// Have what is sent to `at` from now on reach A, as A's own address
    /// does.
    pub(super) fn deliver_to_a(&self, at: &TransportAddr) {
        let mut registry = LOOPBACK_REGISTRY.lock().unwrap();
        let entry = registry
            .get(&self.nodes[0].addr)
            .cloned()
            .expect("precondition: A's address is registered");
        registry.insert(at.clone(), entry);
    }

    /// [`Pair::move_a`] to `new`, an address already delivering to A.
    pub(super) fn move_a_to(&mut self, old: OldAddr, new: TransportAddr) {
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
    pub(super) fn cut_b(&mut self, cut: bool) {
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
    pub(super) async fn heartbeat(&mut self, from: usize, to: usize) -> bool {
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
    pub(super) async fn outcome(&mut self) -> Outcome {
        let change = self.change.expect("precondition: the address changed");
        let now = self.nodes[1].node.stats().handshake.snapshot();
        let was = self.refused.clone().unwrap_or_default();
        let b_refused = since(&now, &was);
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
    responder_with(mp, (a_smaller, false), age_secs, trigger, old, window_secs).await
}

/// [`responder`], with each node's decrypt workers running when `workers`.
pub(super) async fn responder_with(
    mp: Multipath,
    (a_smaller, workers): (bool, bool),
    age_secs: u64,
    trigger: Trigger,
    old: OldAddr,
    window_secs: u64,
) -> Outcome {
    let mut pair = Pair::new(mp, a_smaller).await;
    #[cfg(unix)]
    if workers {
        pair.workers_on();
    }
    #[cfg(not(unix))]
    let _ = workers;
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
    pub(super) fn sessions(&self) -> [Option<(LinkId, Option<SessionIndex>)>; 2] {
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
    let b_refused = since(&now, &was);
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

/// A's interface goes and comes back at a new address on a link 60 s old,
/// with B's last frame from A 9.5 s before (age 60) and 0.5 s before (age
/// 51). A withdraws B at once and its reconnect dials B 5 s later. B answers
/// the dial's first msg1 into a pending redial beside the peering it holds,
/// sending its msg2 to A's new address; A promotes B on it and its first
/// frame proves the redial to B, which replaces the peering in the same
/// step. Nothing is refused, no stored msg2 goes out, B never drops A, and
/// the pair settles on a new link 5 s after the change, long before B's
/// link-dead reaper would have removed the old peering at 30 s.
async fn answered_and_settles_before_the_reap(mp: Multipath, ages: &[u64]) {
    answered_and_settles(mp, ages, false).await;
}

/// [`answered_and_settles_before_the_reap`], with each node's decrypt
/// workers running when `workers`.
async fn answered_and_settles(mp: Multipath, ages: &[u64], workers: bool) {
    for &age in ages {
        let mut runs = Vec::new();
        for (a_smaller, old) in RUNS {
            let o = responder_with(mp, (a_smaller, workers), age, Trigger::Detach, old, 60).await;
            eprintln!("{mp:?} workers {workers} a_smaller {a_smaller} age {age} s {old:?}: {o:?}");
            runs.push(o);
        }
        for o in runs {
            let r = &o.b_refused;
            assert!(
                o.first_msg1 == Some(5.0)
                    && o.settled.is_some_and(|s| s < 10.0)
                    && o.how == Some(How::NewLink)
                    && o.b_dropped.is_none()
                    && o.stale_msg2s == 0
                    && r.redials == 1
                    && r.redials_proven == 1
                    && r.off_link + r.bad_state + r.answered_before == 0
                    && o.works,
                "defect: {o:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_is_answered_and_settles_before_the_responder_would_reap_multipath_off()
 {
    answered_and_settles_before_the_reap(Multipath::Off, &[60, 51]).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_is_answered_and_settles_before_the_responder_would_reap_multipath_on()
 {
    answered_and_settles_before_the_reap(Multipath::On, &[60, 51]).await;
}

/// [`a_redial_from_a_new_address_on_an_aged_link_is_answered_and_settles_before_the_responder_would_reap_multipath_off`]
/// with each node's decrypt workers running: the redial's first frame names
/// an index no worker holds and is opened by the node, and the frame after
/// the swap goes to a worker under the session the swap offered it.
#[cfg(unix)]
#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_is_answered_and_settles_before_the_responder_would_reap_with_decrypt_workers_multipath_off()
 {
    answered_and_settles(Multipath::Off, &[60], true).await;
}

/// The same with multipath on.
#[cfg(unix)]
#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_is_answered_and_settles_before_the_responder_would_reap_with_decrypt_workers_multipath_on()
 {
    answered_and_settles(Multipath::On, &[60], true).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_is_answered_and_settles_before_the_responder_would_reap_multipath_on_at_the_redialler_only()
 {
    answered_and_settles_before_the_reap(Multipath::AOnly, &[60, 51]).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_an_aged_link_is_answered_and_settles_before_the_responder_would_reap_multipath_on_at_the_responder_only()
 {
    answered_and_settles_before_the_reap(Multipath::BOnly, &[60, 51]).await;
}

/// As on an aged link, on a link 10 s old at the change: the dial's msg1
/// reaches B on a link 15 s old, too young to rekey, and is answered into a
/// pending redial in the same way rather than refused as a replacement of a
/// peering heard from within 15 s.
#[tokio::test]
async fn a_redial_from_a_new_address_on_a_young_link_is_answered_and_settles_before_the_responder_would_reap_multipath_off()
 {
    answered_and_settles_before_the_reap(Multipath::Off, &[10]).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_on_a_young_link_is_answered_and_settles_before_the_responder_would_reap_multipath_on()
 {
    answered_and_settles_before_the_reap(Multipath::On, &[10]).await;
}

/// [`a_redial_from_a_new_address_on_a_young_link_is_answered_and_settles_before_the_responder_would_reap_multipath_off`]
/// with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn a_redial_from_a_new_address_on_a_young_link_is_answered_and_settles_before_the_responder_would_reap_with_decrypt_workers_multipath_off()
 {
    answered_and_settles(Multipath::Off, &[10], true).await;
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
/// address settles before the responder would reap the old peering.
async fn settles_before_the_old_peering_is_reaped(mp: Multipath) {
    let o = responder(mp, true, 60, Trigger::Detach, OldAddr::Blackhole, 90).await;
    eprintln!("{o:?}");
    assert!(
        o.settled.is_some() && o.b_dropped.is_none_or(|d| o.settled < Some(d)),
        "defect: the redial settled only after B reaped A's old peering: {o:?}"
    );
}

#[tokio::test]
async fn a_redial_from_a_new_address_settles_before_the_responder_reaps_the_old_peering() {
    settles_before_the_old_peering_is_reaped(Multipath::Off).await;
}

#[tokio::test]
async fn a_redial_from_a_new_address_settles_before_the_responder_reaps_the_old_peering_with_multipath_on()
 {
    settles_before_the_old_peering_is_reaped(Multipath::On).await;
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

/// Run each node's decrypt workers from now on when `on`.
pub(super) fn workers_if(pair: &mut Pair, on: bool) {
    #[cfg(unix)]
    if on {
        pair.workers_on();
    }
    #[cfg(not(unix))]
    let _ = (pair, on);
}

/// B's (link, index) for A.
fn b_session(pair: &Pair) -> Option<(LinkId, Option<SessionIndex>)> {
    pair.nodes[1]
        .node
        .get_peer(&pair.a_addr())
        .map(|p| (p.link_id(), p.our_index()))
}

/// A redial of A armed at B by hand, from a tap address of B's transport,
/// as A's identity: the dialer that keeps its handshake state, the tap's
/// address, and the msg2 B answered with.
pub(super) struct Tapped {
    pub(super) dialer: Dialer,
    pub(super) at: TransportAddr,
    /// What reaches the tap, held so that B's sends there succeed.
    _rx: UnboundedReceiver<ReceivedPacket>,
    pub(super) msg2: Vec<u8>,
}

impl Tapped {
    /// The dialer's next frame, as B receives it from the tap.
    pub(super) fn frame(&mut self, tid: TransportId) -> ReceivedPacket {
        ReceivedPacket::with_timestamp(tid, self.at.clone(), self.dialer.frame(), Node::now_ms())
    }
}

/// Arm a redial of A at B from a tap address, the dial naming sender index
/// `sidx`.
pub(super) async fn arm_from_tap(pair: &mut Pair, sidx: u32) -> Tapped {
    let tid = pair.nodes[1].transport_id;
    let (at, mut rx) = loopback_tap(tid);
    let (dialer, data) = Dialer::new(&pair.nodes[0].node, &pair.nodes[1].node, sidx);
    pair.nodes[1]
        .node
        .process_packet(ReceivedPacket::with_timestamp(
            tid,
            at.clone(),
            data,
            Node::now_ms(),
        ))
        .await;
    let msg2 = std::iter::from_fn(|| rx.try_recv().ok())
        .find(|p| phase(p) == Some(PHASE_MSG2))
        .expect("precondition: the redial's msg2 reached the tap")
        .data;
    Tapped {
        dialer,
        at,
        _rx: rx,
        msg2,
    }
}

/// A's interface goes and comes back at `new`, so A withdraws B and
/// redials it 5 s later from there.
async fn detach_to(pair: &mut Pair, new: TransportAddr) {
    let tid = pair.nodes[0].transport_id;
    pair.nodes[0].node.path_presence(tid, false).await;
    pair.move_a_to(OldAddr::Blackhole, new);
    pair.nodes[0].node.path_presence(tid, true).await;
    pair.note();
    pair.pump().await;
}

/// A redial of A is armed at B from another address while A's link to B
/// is 60 s old and working. For three seconds a heartbeat each way after
/// every step authenticates on the old session, and B keeps A on the old
/// link and index. The redial's first frame then replaces the peering, in
/// one swap, onto the redial's link and index, and a second frame under it
/// is delivered on the new peering with no second swap.
async fn delivers_until_the_first_frame(workers: bool) {
    let mut pair = Pair::new(Multipath::Off, true).await;
    workers_if(&mut pair, workers);
    pair.run(60).await;
    let a = pair.a_addr();
    let tid = pair.nodes[1].transport_id;
    let before = b_session(&pair);
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    let mut tap = arm_from_tap(&mut pair, 0xD1A1).await;
    let pending = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("precondition: a redial is pending");
    let mut kept = Vec::new();
    for step in 0..6 {
        pair.step().await;
        let ab = pair.heartbeat(0, 1).await;
        let ba = pair.heartbeat(1, 0).await;
        kept.push((step, ab, ba, b_session(&pair) == before));
    }
    tap.dialer.answered(&tap.msg2);
    let first = tap.frame(tid);
    pair.nodes[1].node.process_packet(first).await;
    pair.pump().await;
    let after = b_session(&pair);
    let recv = |p: &Pair| {
        p.nodes[1]
            .node
            .get_peer(&a)
            .map(|p| p.link_stats().packets_recv)
    };
    let r0 = recv(&pair);
    let second = tap.frame(tid);
    pair.nodes[1].node.process_packet(second).await;
    pair.pump().await;
    let r1 = recv(&pair);
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        kept.iter().all(|&(_, ab, ba, same)| ab && ba && same),
        "defect: the old peering stopped delivering before the redial's first frame: {kept:?}"
    );
    assert!(
        after == Some((pending.link, Some(pending.index)))
            && r.redials == 1
            && r.redials_proven == 1
            && r1 > r0,
        "defect: the first frame did not replace the peering once: {before:?} -> {after:?} \
         (pending {pending:?}) {r:?} frames {r0:?} -> {r1:?}"
    );
}

#[tokio::test]
async fn the_responder_keeps_the_old_peering_delivering_until_the_redials_first_frame_then_replaces_it_once()
 {
    delivers_until_the_first_frame(false).await;
}

/// [`the_responder_keeps_the_old_peering_delivering_until_the_redials_first_frame_then_replaces_it_once`]
/// with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn the_responder_keeps_the_old_peering_delivering_until_the_redials_first_frame_then_replaces_it_once_with_decrypt_workers()
 {
    delivers_until_the_first_frame(true).await;
}

/// With multipath on, A redials B from a new address after its interface
/// returns there. At B the swap frees the old peering's index, removes the
/// old link and its index entry, and leaves no path at A's old address,
/// and the audit finds no breach.
async fn swap_frees_the_old_link(workers: bool) {
    let mut pair = Pair::new(Multipath::On, true).await;
    workers_if(&mut pair, workers);
    pair.run(60).await;
    let a = pair.a_addr();
    let tid = pair.nodes[1].transport_id;
    let old_addr = pair.nodes[0].addr.clone();
    let (old_link, old_index) = match b_session(&pair) {
        Some((link, Some(index))) => (link, index),
        other => panic!("precondition: B holds A on an indexed link: {other:?}"),
    };
    assert!(
        matches!(
            pair.nodes[1]
                .node
                .get_peer(&a)
                .map(|p| p.path_match(tid, &old_addr)),
            Some(crate::peer::Match::Proven { .. })
        ),
        "precondition: B holds a proven path at A's address"
    );
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    let new = add_loopback_alias(&old_addr, pair.nodes[0].transport_id);
    detach_to(&mut pair, new).await;
    pair.run(10).await;
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    let b = &pair.nodes[1].node;
    let p = b.get_peer(&a);
    let state = (
        p.map(|p| p.link_id() != old_link),
        b.links.get(&old_link).is_none(),
        !b.index_allocator.is_allocated(old_index),
        !b.peers_by_index.contains_key(&old_index.as_u32()),
        p.map(|p| p.path_match(tid, &old_addr)),
    );
    let works = pair.heartbeat(0, 1).await && pair.heartbeat(1, 0).await;
    assert!(
        r.redials_proven == 1
            && works
            && matches!(
                state,
                (Some(true), true, true, true, Some(crate::peer::Match::None))
            ),
        "defect: (new link, old link gone, old index free, old index unmapped, old pair) {state:?} {r:?} works {works}"
    );
    // The audit's own delivery hands no decrypt worker's result back to its
    // node, so it runs on the pair without workers.
    if !workers {
        super::settle::audit::assert_coherent(&mut pair.nodes, "after the swap").await;
    }
    cleanup_nodes(&mut pair.nodes).await;
}

#[tokio::test]
async fn the_swap_frees_the_old_index_and_retires_the_old_link_and_its_paths_multipath_on() {
    swap_frees_the_old_link(false).await;
}

/// [`the_swap_frees_the_old_index_and_retires_the_old_link_and_its_paths_multipath_on`]
/// with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn the_swap_frees_the_old_index_and_retires_the_old_link_and_its_paths_multipath_on_with_decrypt_workers()
 {
    swap_frees_the_old_link(true).await;
}

/// B stops hearing A on a link 60 s old. 25 s later a redial of A is armed
/// at B from another address, and 5 s after that B's link-dead reaper
/// removes the old peering, leaving the redial pending. The redial's first
/// frame then promotes it with no peering to tear down: B holds A on the
/// redial's link and index, and the dampener, which only a swap of a
/// peering stamps, is not stamped.
async fn reaped_first(workers: bool) {
    let mut pair = Pair::new(Multipath::Off, true).await;
    workers_if(&mut pair, workers);
    pair.run(60).await;
    let a = pair.a_addr();
    let tid = pair.nodes[1].transport_id;
    pair.cut_b(true);
    pair.run(25).await;
    assert!(pair.b_holds_a(), "precondition: B still holds A at 25 s");
    let mut tap = arm_from_tap(&mut pair, 0xD1A3).await;
    let pending = pair.nodes[1]
        .node
        .redials
        .of(&a)
        .expect("precondition: a redial is pending");
    for _ in 0..30 {
        if !pair.b_holds_a() {
            break;
        }
        pair.step().await;
    }
    assert!(
        !pair.b_holds_a() && pair.nodes[1].node.redials.of(&a) == Some(pending),
        "precondition: B reaped A and kept the redial pending"
    );
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    tap.dialer.answered(&tap.msg2);
    let first = tap.frame(tid);
    pair.nodes[1].node.process_packet(first).await;
    pair.pump().await;
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    let held = b_session(&pair);
    let stamped = pair.nodes[1].node.gates().stamp(&a).is_some();
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        held == Some((pending.link, Some(pending.index))) && r.redials_proven == 1 && !stamped,
        "defect: held {held:?} (pending {pending:?}) {r:?} dampener stamped {stamped}"
    );
}

#[tokio::test]
async fn a_redial_whose_old_peering_was_reaped_first_is_promoted_at_its_first_frame_with_no_teardown()
 {
    reaped_first(false).await;
}

/// [`a_redial_whose_old_peering_was_reaped_first_is_promoted_at_its_first_frame_with_no_teardown`]
/// with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn a_redial_whose_old_peering_was_reaped_first_is_promoted_at_its_first_frame_with_no_teardown_with_decrypt_workers()
 {
    reaped_first(true).await;
}

/// With multipath on, B hears a beacon of A at an address A will move to,
/// and holds it as a path of A's it has not proven. A's interface then goes
/// and comes back at that address, and A redials B from it: the msg1 is off
/// B's link, answered as a redial, and settles before B would have reaped
/// the old peering.
#[tokio::test]
async fn a_redial_from_an_address_the_responder_learned_by_discovery_settles_before_the_reap_multipath_on()
 {
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let tid = pair.nodes[1].transport_id;
    loopback(&pair.nodes[1], tid).set_autoconnect(true);
    // Nothing reaches A at its next address yet, so B's probes there go
    // unanswered and the path stays unproven.
    let (new, _lost) = loopback_tap(pair.nodes[0].transport_id);
    beacon(&pair.nodes[1], tid, &new, &pair.nodes[0]);
    pair.step().await;
    let held = pair.nodes[1]
        .node
        .get_peer(&a)
        .map(|p| p.path_match(tid, &new));
    assert!(
        matches!(held, Some(crate::peer::Match::Unproven)),
        "precondition: B holds A's next address as a path it has not proven: {held:?}"
    );
    pair.deliver_to_a(&new);
    detach_to(&mut pair, new).await;
    pair.run(20).await;
    let o = pair.outcome().await;
    cleanup_nodes(&mut pair.nodes).await;
    let r = &o.b_refused;
    assert!(
        r.redials == 1
            && r.redials_proven == 1
            && o.settled.is_some_and(|s| s < 10.0)
            && o.b_dropped.is_none()
            && o.works,
        "defect: {o:?}"
    );
}

/// The lines B logged for A's paths: (`path_id`, `from`, `next`, `why`),
/// in order.
fn b_path_lines(logs: &crate::testutil::LogCapture, b: &Node, a: &NodeAddr) -> Vec<[String; 4]> {
    use crate::testutil::log_field;
    let name = b.peer_display_name(a);
    logs.lines_with("Path state changed")
        .into_iter()
        .filter(|l| log_field(l, "peer") == Some(name.as_str()))
        .map(|l| {
            ["path_id", "from", "next", "why"]
                .map(|f| log_field(&l, f).unwrap_or_default().to_string())
        })
        .collect()
}

/// With multipath on, B holds A's next address as a path it is still
/// probing when A's redial from that address replaces the peering, so the
/// new link's original path sits at the pair of an old path that never left
/// Probing. B's log ends every path of the old link, that one among them,
/// and then begins the new link's original path, as a renewal logs a link
/// that starts again. A reader of the log, such as the chaos harness's path
/// timelines, would otherwise count every probe the new link sends there as
/// one endless Probing episode of the old path.
#[tokio::test]
async fn a_redials_swap_logs_the_end_of_every_old_path_and_the_start_of_the_new_original_multipath_on()
 {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    let mut pair = Pair::new(Multipath::On, true).await;
    pair.run(60).await;
    let a = pair.a_addr();
    let tid = pair.nodes[1].transport_id;
    loopback(&pair.nodes[1], tid).set_autoconnect(true);
    // Nothing reaches A at its next address yet, so B's probes there go
    // unanswered and the path stays Probing.
    let (new, _lost) = loopback_tap(pair.nodes[0].transport_id);
    beacon(&pair.nodes[1], tid, &new, &pair.nodes[0]);
    pair.step().await;
    let old = pair.nodes[1].node.path_states(&a);
    let probing = old
        .iter()
        .find(|(to, _, state)| {
            to.addr == new && *state == fips_core::proto::path::PathState::Probing
        })
        .map(|(_, id, _)| *id);
    let Some(probing) = probing else {
        panic!("precondition: B is probing A's next address as a path of the old link: {old:?}");
    };
    pair.deliver_to_a(&new);
    detach_to(&mut pair, new.clone()).await;
    pair.run(20).await;
    let b = &pair.nodes[1].node;
    let proven = b.stats().handshake.redials_proven;
    let now = b.path_states(&a);
    let lines = b_path_lines(&logs, b, &a);
    cleanup_nodes(&mut pair.nodes).await;
    let original = now
        .iter()
        .find(|(to, _, _)| to.addr == new)
        .map(|(_, id, _)| *id);
    assert!(
        proven == 1 && original.is_some_and(|id| id != probing),
        "precondition: the redial replaced the peering, with a new path at A's next address: \
         proven {proven}, paths {now:?}"
    );
    let last = |id: u32| lines.iter().rev().find(|l| l[0] == id.to_string()).cloned();
    let unended: Vec<_> = old
        .iter()
        .filter(|(_, id, _)| last(*id).is_none_or(|l| l[2] != "None"))
        .map(|(_, id, _)| (*id, last(*id)))
        .collect();
    assert!(
        unended.is_empty(),
        "defect: the swap left old paths with no logged end, the one probing at A's next \
         address ({probing}) among them: {unended:?}"
    );
    let begun = original.and_then(|id| lines.iter().find(|l| l[0] == id.to_string()).cloned());
    assert!(
        begun
            .as_ref()
            .is_some_and(|l| l[1] == "None" && l[3] == "Renewed"),
        "defect: the new link's original path at A's next address has no logged start: {begun:?}"
    );
}

/// A, the smaller node, is B's parent. A's interface goes and comes back
/// at a new address and A redials B from it. Across the swap B keeps A as
/// its parent at every step and never declares itself again (its own
/// declaration's sequence is unchanged), and it still holds A's tree
/// declaration and filter at the end.
async fn swap_keeps_the_parent(workers: bool) {
    let mut pair = Pair::new(Multipath::Off, true).await;
    workers_if(&mut pair, workers);
    pair.run(60).await;
    let a = pair.a_addr();
    let mine = |p: &Pair| {
        let d = p.nodes[1].node.tree_state().my_declaration();
        (*d.parent_id(), d.sequence())
    };
    let before = mine(&pair);
    assert_eq!(before.0, a, "precondition: A is B's parent");
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    let tid = pair.nodes[0].transport_id;
    let new = add_loopback_alias(&pair.nodes[0].addr, tid);
    detach_to(&mut pair, new).await;
    let mut seen = vec![mine(&pair)];
    for _ in 0..20 {
        pair.step().await;
        seen.push(mine(&pair));
    }
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    let held = pair.nodes[1]
        .node
        .get_peer(&a)
        .map(|p| (p.declaration().is_some(), p.inbound_filter().is_some()));
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        r.redials_proven == 1 && seen.iter().all(|m| *m == before) && held == Some((true, true)),
        "defect: B's (parent, sequence) {before:?} -> {seen:?}, A's declaration and filter {held:?}, {r:?}"
    );
}

#[tokio::test]
async fn the_swap_keeps_the_redialers_tree_declaration_and_filter_and_the_responders_parent_when_the_redialer_was_its_parent()
 {
    swap_keeps_the_parent(false).await;
}

/// [`the_swap_keeps_the_redialers_tree_declaration_and_filter_and_the_responders_parent_when_the_redialer_was_its_parent`]
/// with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn the_swap_keeps_the_redialers_tree_declaration_and_filter_and_the_responders_parent_when_the_redialer_was_its_parent_with_decrypt_workers()
 {
    swap_keeps_the_parent(true).await;
}
