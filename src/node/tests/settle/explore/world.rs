//! A world of two or three real nodes on one transport, and what each step
//! of a schedule does to them.
//!
//! The nodes are real `Node`s on a real transport: the in-process loopback,
//! TCP on 127.0.0.1, or the BLE transport over the mock radio. Each node's
//! receive channel is the test's, so nothing a node is sent reaches it until
//! the world hands it over. Every dial goes through `initiate_connection`,
//! the path a configured peer takes; time moves by `crate::time::advance`.
//!
//! What a node is sent waits in the world's hold. A msg1 or a msg2 is handed
//! over only when a step names it. An established frame flows on its own
//! after each step, once no msg1 or msg2 that arrived before it from the
//! same source is still held: a frame does not overtake the handshake packet
//! it followed, as it cannot on one connection, and nothing of a schedule's
//! has to name the frames a node sends that the core's world does not.
//! A world told to `hold` keeps established frames held as well, until a
//! heal, so a step hands over only the packet it names.

use super::super::super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, bridge_to_unbounded, cleanup_nodes, restarted_node,
};
use super::super::super::*;
use super::super::{heartbeat_reaches, loopback_node, resolve_connect, settled, with_path};
use super::model::Tap;
use super::script::{Kind, Step, run};
use crate::config::TcpConfig;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1, PHASE_MSG2};
use crate::transport::loopback::LoopbackTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::{LinkState, TransportHandle, TransportId};
use std::collections::VecDeque;

/// The transport a world's nodes share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Medium {
    /// The in-process loopback: connectionless, and a send is in the
    /// receiver's channel when it returns.
    Loopback,
    /// TCP on 127.0.0.1: connection-oriented, and a frame reaches the
    /// receiver's channel from its connection's own task.
    Tcp,
    /// The BLE transport over the mock radio: connection-oriented, one
    /// link per pair, with the transport's key exchange before the
    /// handshake.
    #[cfg(ble_available)]
    Ble,
}

impl Medium {
    /// Rounds in which nothing moved before the nodes count as quiet. On
    /// the loopback a send lands before it returns, so one round tells; on
    /// a connection-oriented transport a frame may still be on its way.
    fn quiet(self) -> usize {
        match self {
            Medium::Loopback => 1,
            _ => 10,
        }
    }

    /// Rounds in which no frame moved before the frames count as settled
    /// after a step: one on the loopback, and five, 50 ms, on a
    /// connection-oriented transport.
    fn settle(self) -> usize {
        match self {
            Medium::Loopback => 1,
            _ => 5,
        }
    }

    /// Let what is in flight move between two rounds.
    async fn pause(self) {
        match self {
            Medium::Loopback => tokio::task::yield_now().await,
            _ => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}

/// The most rounds a `Heal` runs before it gives up on the nodes going
/// quiet, and a step's frames before they count as settled.
const HEAL_ROUNDS: usize = 300;

/// The class of `packet`, or `None` for an established frame or anything
/// else the receive dispatch is left to judge.
fn kind_of(packet: &ReceivedPacket) -> Option<Kind> {
    match CommonPrefix::parse(&packet.data).map(|p| p.phase) {
        Some(PHASE_MSG1) => Some(Kind::Msg1),
        Some(PHASE_MSG2) => Some(Kind::Msg2),
        _ => None,
    }
}

/// Real nodes on one transport, driven a step at a time.
pub(super) struct World {
    /// The nodes, in ascending order of node address.
    pub(super) nodes: Vec<TestNode>,
    medium: Medium,
    /// The configuration every node runs, and every restart takes.
    config: Config,
    /// Each node's transports, by index: the transport's id and the node's
    /// own address on it.
    ends: Vec<Vec<(TransportId, TransportAddr)>>,
    /// What each node has been sent and not yet handed, in the order it
    /// arrived.
    held: Vec<VecDeque<ReceivedPacket>>,
    /// Whether established frames flow after each step (`flow`); when not,
    /// they wait, with everything else, for a `heal`.
    flowing: bool,
    /// The reference model beside the nodes, where a test set one: told of
    /// every packet sent and handed over, every advance of the clock, rekey
    /// and restart, and every rekey poll handed to it to run.
    pub(super) tap: Option<Tap>,
    /// Every BLE node's radio, by its address, for the mock connects.
    #[cfg(ble_available)]
    radio: ble::Radio,
}

impl World {
    /// `count` nodes on `medium`, each with one transport, with multipath
    /// set as `on`. On the loopback the thread's monotonic clock is frozen
    /// first, so from here on only `advance` moves it: real time, a wait for
    /// a decrypt worker or a stalled host among it, does not reach the
    /// nodes' timers. A TCP or BLE world's clock is left running: the TCP
    /// crossing with multipath on does not heal on a frozen clock.
    pub(super) async fn new(medium: Medium, count: usize, on: bool) -> World {
        if medium == Medium::Loopback {
            crate::time::freeze();
        }
        let config = with_path(Config::new(), on);
        #[cfg(ble_available)]
        let radio = ble::Radio::default();
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            nodes.push(match medium {
                Medium::Loopback => loopback_node(on).await,
                Medium::Tcp => tcp_end(make_node_with(config.clone()), "127.0.0.1:0").await,
                #[cfg(ble_available)]
                Medium::Ble => {
                    let at = ble::addr(nodes.len());
                    ble::end(make_node_with(config.clone()), at, &radio).await
                }
            });
        }
        nodes.sort_by_key(|tn| *tn.node.node_addr());
        let ends = nodes
            .iter()
            .map(|tn| vec![(tn.transport_id, tn.addr.clone())])
            .collect();
        World {
            nodes,
            medium,
            config,
            ends,
            held: vec![VecDeque::new(); count],
            flowing: true,
            tap: None,
            #[cfg(ble_available)]
            radio,
        }
    }

    /// Give every node one more loopback transport, at an address of its
    /// own that delivers to the node's receive channel. Returns the new
    /// transport's index.
    pub(super) fn add_transport(&mut self) -> usize {
        assert_eq!(
            self.medium,
            Medium::Loopback,
            "precondition: only a loopback world takes a second transport"
        );
        let t = self.ends[0].len();
        let tid = TransportId::new(t as u32 + 1);
        for (tn, ends) in self.nodes.iter_mut().zip(self.ends.iter_mut()) {
            let addr = super::super::alias(&ends[0].1, tid);
            let lo =
                LoopbackTransport::with_mtu(tid, addr.clone(), 1280, LOOPBACK_REGISTRY.clone());
            tn.node
                .transports
                .insert(tid, TransportHandle::Loopback(lo));
            ends.push((tid, addr));
        }
        t
    }

    /// Node `from` dials node `to` at its address on transport `transport`,
    /// through `initiate_connection`.
    pub(super) async fn dial(&mut self, from: usize, to: usize, transport: usize) {
        let id = PeerIdentity::from_pubkey_full(self.nodes[to].node.identity().pubkey_full());
        let addr = self.ends[to][transport].1.clone();
        let tid = self.ends[from][transport].0;
        self.nodes[from]
            .node
            .initiate_connection(tid, addr, id)
            .await
            .expect("precondition: the dial starts");
        self.flow().await;
    }

    /// Node `node` polls its pending connects until none is left.
    pub(super) async fn connected(&mut self, node: usize) {
        resolve_connect(&mut self.nodes[node]).await;
        self.flow().await;
    }

    /// How many packets of class `kind` node `at` holds.
    pub(super) fn held(&mut self, at: usize, kind: Kind) -> usize {
        self.collect();
        self.held[at]
            .iter()
            .filter(|p| kind_of(p) == Some(kind))
            .count()
    }

    /// The packets of class `kind` node `at` holds, in the order they
    /// arrived, so a step can be named by what a packet carries.
    pub(super) fn packets(&mut self, at: usize, kind: Kind) -> Vec<ReceivedPacket> {
        self.collect();
        self.held[at]
            .iter()
            .filter(|p| kind_of(p) == Some(kind))
            .cloned()
            .collect()
    }

    /// Lose everything sent and not yet handed over, at every node, as what
    /// is in flight is lost when the clock moves in the core's world.
    pub(super) fn clear(&mut self) {
        self.collect();
        for held in self.held.iter_mut() {
            held.clear();
        }
    }

    /// Hold established frames as well from here on: a step hands over only
    /// the packet it names, and a frame waits for a `heal`, as in the
    /// core's world, whose nodes send no frame between handshake steps.
    pub(super) fn hold(&mut self) {
        self.flowing = false;
    }

    /// Where in node `to`'s hold its `nth` packet of class `kind` is. On a
    /// connection-oriented transport a packet may still be on its way, so
    /// this waits up to 2 s for it.
    async fn find(&mut self, to: usize, kind: Kind, nth: usize) -> usize {
        for _ in 0..200 {
            self.collect();
            if let Some((i, _)) = self.held[to]
                .iter()
                .enumerate()
                .filter(|(_, p)| kind_of(p) == Some(kind))
                .nth(nth)
            {
                return i;
            }
            if self.medium == Medium::Loopback {
                break;
            }
            self.medium.pause().await;
        }
        let kinds: Vec<Option<Kind>> = self.held[to].iter().map(kind_of).collect();
        panic!("precondition: node {to} holds no {kind:?} number {nth}; it holds {kinds:?}");
    }

    /// Hand node `to` its `nth` held packet of class `kind`.
    pub(super) async fn deliver(&mut self, to: usize, kind: Kind, nth: usize) {
        let i = self.find(to, kind, nth).await;
        let packet = self.held[to].remove(i).expect("a found packet is held");
        give(
            &mut self.nodes[to].node,
            &mut self.tap,
            &self.ends,
            to,
            packet,
        )
        .await;
        self.flow().await;
    }

    /// Drop node `to`'s `nth` held packet of class `kind`.
    pub(super) async fn lose(&mut self, to: usize, kind: Kind, nth: usize) {
        let i = self.find(to, kind, nth).await;
        self.held[to].remove(i);
        self.flow().await;
    }

    /// Hand node `to` a copy of its `nth` held packet of class `kind`, and
    /// keep the packet held.
    pub(super) async fn duplicate(&mut self, to: usize, kind: Kind, nth: usize) {
        let i = self.find(to, kind, nth).await;
        let copy = self.held[to][i].clone();
        give(
            &mut self.nodes[to].node,
            &mut self.tap,
            &self.ends,
            to,
            copy,
        )
        .await;
        self.flow().await;
    }

    /// Swap node `to`'s `nth` held packet of class `kind` with the next one
    /// of that class it holds.
    pub(super) async fn swap(&mut self, to: usize, kind: Kind, nth: usize) {
        let i = self.find(to, kind, nth).await;
        let j = self.find(to, kind, nth + 1).await;
        self.held[to].swap(i, j);
        self.flow().await;
    }

    /// Hand each node every held frame no held msg1 or msg2 from the same
    /// source arrived before, and what those send in turn, until a round
    /// moves none, `Medium::settle` rounds running.
    pub(super) async fn flow(&mut self) {
        if !self.flowing {
            return;
        }
        let mut idle = 0;
        for _ in 0..HEAL_ROUNDS {
            self.collect();
            if self.frames().await == 0 {
                idle += 1;
                if idle >= self.medium.settle() {
                    return;
                }
            } else {
                idle = 0;
            }
            self.medium.pause().await;
        }
    }

    /// One round of `flow`: hand each node, in arrival order, the frames it
    /// held when the round began that no held handshake packet from the
    /// same source arrived before.
    async fn frames(&mut self) -> usize {
        let mut handed = self.results().await;
        for (at, (tn, held)) in self.nodes.iter_mut().zip(self.held.iter_mut()).enumerate() {
            let mut blocked = Vec::new();
            let mut kept = VecDeque::with_capacity(held.len());
            let mut free = Vec::new();
            for packet in std::mem::take(held) {
                let source = (packet.transport_id, packet.remote_addr.clone());
                if kind_of(&packet).is_some() {
                    blocked.push(source);
                    kept.push_back(packet);
                } else if blocked.contains(&source) {
                    kept.push_back(packet);
                } else {
                    free.push(packet);
                }
            }
            *held = kept;
            for packet in free {
                give(&mut tn.node, &mut self.tap, &self.ends, at, packet).await;
                handed += 1;
            }
        }
        handed
    }

    /// Hand over everything sent, polling every node's pending connects,
    /// until the nodes are quiet. Returns false if they were still sending
    /// after `HEAL_ROUNDS` rounds.
    pub(super) async fn heal(&mut self) -> bool {
        let mut idle = 0;
        for _ in 0..HEAL_ROUNDS {
            for tn in self.nodes.iter_mut() {
                tn.node.poll_pending_connects().await;
            }
            if self.hand().await == 0 {
                idle += 1;
                if idle >= self.medium.quiet() {
                    return true;
                }
            } else {
                idle = 0;
            }
            self.medium.pause().await;
        }
        false
    }

    /// Run what each node's decrypt workers sent back, the frames they
    /// opened and the failures they reported, as the receive loop does, and
    /// return how many. A world whose nodes run no pool has none. A worker
    /// runs on a thread of its own, so each node's workers are first waited
    /// for until each has handled everything it was sent (bounded at 60 s):
    /// every job a round handed over has its result run in the next round,
    /// and a round that moves nothing has no frame left on a worker.
    async fn results(&mut self) -> usize {
        #[cfg(unix)]
        {
            let mut ran = 0;
            for tn in self.nodes.iter_mut() {
                if let Some(pool) = tn.node.supervisor.decrypt_workers.as_ref()
                    && !node_fault!(WorldSkipsWorkerWait)
                {
                    pool.barrier();
                }
                let Some(mut rx) = tn.node.decrypt_fallback_rx.take() else {
                    continue;
                };
                while let Ok(event) = rx.try_recv() {
                    tn.node.process_decrypt_worker_event(event).await;
                    ran += 1;
                }
                tn.node.decrypt_fallback_rx = Some(rx);
            }
            ran
        }
        #[cfg(not(unix))]
        0
    }

    /// Move what has reached each node's receive channel into the world's
    /// hold, after what is already there.
    fn collect(&mut self) {
        for (at, (tn, held)) in self.nodes.iter_mut().zip(self.held.iter_mut()).enumerate() {
            while let Ok(packet) = tn.packet_rx.try_recv() {
                if let Some(tap) = self.tap.as_mut() {
                    tap.sent(at, &packet, &self.ends);
                }
                held.push_back(packet);
            }
        }
    }

    /// Hand each node everything it held when the round began, in order, as
    /// its receive loop would. A packet sent during the round waits for the
    /// next, so a round moves every exchange one hop.
    async fn hand(&mut self) -> usize {
        let mut handed = self.results().await;
        self.collect();
        for (at, (tn, held)) in self.nodes.iter_mut().zip(self.held.iter_mut()).enumerate() {
            for packet in std::mem::take(held) {
                give(&mut tn.node, &mut self.tap, &self.ends, at, packet).await;
                handed += 1;
            }
        }
        handed
    }

    /// The monotonic clock moves `ms` milliseconds on, and every node runs
    /// its timers once.
    pub(super) async fn advance(&mut self, ms: u64) {
        crate::time::advance(Duration::from_millis(ms));
        if let Some(tap) = self.tap.as_mut() {
            tap.advance(ms);
        }
        for (at, tn) in self.nodes.iter_mut().enumerate() {
            tick(&mut tn.node, at, &mut self.tap).await;
        }
        self.flow().await;
    }

    /// Node `at` restarts: a new run of its identity, with no peers, at the
    /// same addresses. What was sent to the old run and not yet handed over
    /// stays held for the new one, as a packet in flight across a restart
    /// would reach it.
    pub(super) async fn restart(&mut self, at: usize) {
        self.collect();
        if let Some(tap) = self.tap.as_mut() {
            tap.restart(at);
        }
        let config = self.config.clone();
        let mut fresh = match self.medium {
            Medium::Loopback => restarted_node(&self.nodes[at], config),
            Medium::Tcp => {
                let bind = self.ends[at][0]
                    .1
                    .as_str()
                    .expect("precondition: a TCP address is text")
                    .to_string();
                stop(&mut self.nodes[at]).await;
                tcp_end(rerun(&self.nodes[at], config), &bind).await
            }
            #[cfg(ble_available)]
            Medium::Ble => {
                let addr = ble::parse(&self.ends[at][0].1);
                stop(&mut self.nodes[at]).await;
                ble::end(rerun(&self.nodes[at], config), addr, &self.radio).await
            }
        };
        for (tid, addr) in self.ends[at].iter().skip(1) {
            rebind(&mut fresh, *tid, addr);
        }
        let mut old = std::mem::replace(&mut self.nodes[at], fresh);
        stop(&mut old).await;
        self.closed(at).await;
        self.flow().await;
    }

    /// Wait, up to a second, until no other node's transport holds a
    /// connection at node `at`'s address, so the old run's closed
    /// connections are seen at the far end before the next step. A
    /// connection the other node accepted from the old run is keyed by the
    /// old run's port, not its address, and is not waited for. Nothing to
    /// wait for on the loopback.
    async fn closed(&self, at: usize) {
        if self.medium == Medium::Loopback {
            return;
        }
        let addr = &self.ends[at][0].1;
        for _ in 0..100 {
            let open = self.nodes.iter().enumerate().any(|(i, tn)| {
                i != at
                    && tn.node.transports.values().any(|t| {
                        matches!(
                            t.connection_state(addr),
                            crate::transport::ConnectionState::Connected
                        )
                    })
            });
            if !open {
                return;
            }
            self.medium.pause().await;
        }
        panic!(
            "precondition: the other nodes saw node {at}'s old connections close within a second"
        );
    }

    /// Node `at` starts a rekey of every link it holds. Its session with
    /// each peer is aged past its rekey trigger, and the peer's end of the
    /// same session past the floor below which a msg1 from a held peer is a
    /// fresh dial and not a rekey, but short of the peer's own trigger, as
    /// the time between two sessions' jittered triggers leaves them. Then
    /// the node polls its rekeys.
    pub(super) async fn rekey(&mut self, at: usize) {
        let after = self.nodes[at].node.config().node.rekey.after_secs;
        let age = Duration::from_secs(after + crate::node::REKEY_JITTER_SECS as u64 + 1);
        let floor = fips_core::proto::rekey::DEPLOYED_SESSION_FLOOR + Duration::from_secs(5);
        let me = *self.nodes[at].node.node_addr();
        if let Some(tap) = self.tap.as_mut() {
            tap.rekey(at, age, floor);
        }
        let peers: Vec<NodeAddr> = self.nodes[at].node.peers.keys().copied().collect();
        for peer in &peers {
            self.nodes[at]
                .node
                .get_peer_mut(peer)
                .expect("precondition: a held peer")
                .test_backdate_session_established(age);
            if let Some(end) = self
                .nodes
                .iter_mut()
                .find(|tn| tn.node.node_addr() == peer)
                .and_then(|tn| tn.node.get_peer_mut(&me))
            {
                end.test_backdate_session_established(floor);
            }
        }
        let node = &mut self.nodes[at].node;
        node.poll_link_rekeys().await;
        assert!(
            peers
                .iter()
                .any(|p| node.get_peer(p).is_some_and(|p| p.rekey_in_progress())),
            "precondition: node {at} started a rekey"
        );
        self.flow().await;
        if let Some(tap) = self.tap.as_mut() {
            tap.rekeyed();
        }
    }
}

/// One pass of node `at`'s timers, in the order its receive loop's tick
/// runs them: handshake timeouts, transport connects, msg1 resends,
/// retries, link heartbeats and rekeys, then the path machines when any is
/// armed. The rekey poll, where a rekey's initiator cuts over, goes through
/// the world's tap where it has one.
async fn tick(node: &mut Node, at: usize, tap: &mut Option<Tap>) {
    node.check_timeouts().await;
    node.poll_pending_connects().await;
    node.drive_peer_timers(Node::interval_ms()).await;
    node.process_pending_retries(Node::peering_now()).await;
    node.check_link_heartbeats().await;
    match tap {
        Some(tap) => tap.poll(at, node).await,
        None => node.poll_link_rekeys().await,
    }
    if node.paths.armed() {
        node.path_tick().await;
    }
}

/// Hand `packet` to node `at`, through the world's tap where it has one.
async fn give(
    node: &mut Node,
    tap: &mut Option<Tap>,
    ends: &[Vec<(TransportId, TransportAddr)>],
    at: usize,
    packet: ReceivedPacket,
) {
    match tap {
        Some(tap) => tap.give(at, node, packet, ends).await,
        None => node.process_packet(packet).await,
    }
}

/// A new run of `tn`'s identity under `config`, with no transport.
fn rerun(tn: &TestNode, config: Config) -> Node {
    Node::with_identity(tn.node.identity().clone(), config)
        .expect("precondition: the restarted node builds")
}

/// Stop every transport `tn` runs, closing its listeners and connections.
async fn stop(tn: &mut TestNode) {
    for (_, t) in tn.node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Put a second loopback transport `tid` at `addr` on a restarted `tn`, its
/// address delivering to `tn`'s channel as before the restart.
fn rebind(tn: &mut TestNode, tid: TransportId, addr: &TransportAddr) {
    let (_, tx) = LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .get(&tn.addr)
        .expect("precondition: the restarted node's first address is registered")
        .clone();
    LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .insert(addr.clone(), (tid, tx));
    let lo = LoopbackTransport::with_mtu(tid, addr.clone(), 1280, LOOPBACK_REGISTRY.clone());
    tn.node
        .transports
        .insert(tid, TransportHandle::Loopback(lo));
}

/// `node` with one real TCP transport, id 1, listening at `bind`. As
/// `settle::tcp_node`, which binds an ephemeral port only; a restart binds
/// the port its node had.
async fn tcp_end(mut node: Node, bind: &str) -> TestNode {
    let tid = TransportId::new(1);
    let config = TcpConfig {
        bind_addr: Some(bind.to_string()),
        mtu: Some(1400),
        ..Default::default()
    };
    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = TcpTransport::new(tid, None, config, packet_tx);
    transport
        .start_async()
        .await
        .expect("precondition: the TCP transport starts");
    let addr = TransportAddr::from_string(
        &transport
            .local_addr()
            .expect("precondition: the TCP transport is bound")
            .to_string(),
    );
    node.transports.insert(tid, TransportHandle::Tcp(transport));
    TestNode {
        node,
        transport_id: tid,
        packet_rx: bridge_to_unbounded(packet_rx),
        addr,
    }
}

/// BLE nodes over the mock radio.
#[cfg(ble_available)]
mod ble {
    use super::super::super::super::ble::base_config;
    use super::super::super::super::spanning_tree::{TestNode, bridge_to_unbounded};
    use super::super::super::super::*;
    use crate::transport::ble::BleTransport;
    use crate::transport::ble::addr::BleAddr;
    use crate::transport::ble::io::{MockBleIo, MockBleStream};
    use crate::transport::{TransportError, TransportHandle, TransportId};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Every node's radio in a world, by the node's address, so a connect
    /// reaches the node it names.
    pub(super) type Radio = Arc<Mutex<HashMap<String, Arc<MockBleIo>>>>;

    /// The BLE address of the world's node `n`.
    pub(super) fn addr(n: usize) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n as u8],
        }
    }

    /// The BLE address `addr` names.
    pub(super) fn parse(addr: &TransportAddr) -> BleAddr {
        BleAddr::parse(addr.as_str().expect("precondition: a BLE address is text"))
            .expect("precondition: a BLE address parses")
    }

    /// `node` on a BLE transport, id 1, at `at`, with the transport's key
    /// exchange under the node's own key, as the daemon runs it. Its radio
    /// joins `radio`, and a connect it makes opens a fresh mock link to the
    /// node `radio` holds at the address named, whose accept loop takes the
    /// far end. As `ble::make_test_node_ble_from`, which takes no node.
    pub(super) async fn end(mut node: Node, at: BleAddr, radio: &Radio) -> TestNode {
        let tid = TransportId::new(1);
        let io = MockBleIo::new("hci0", at.clone());
        let (packet_tx, packet_rx) = packet_channel(256);
        let mut transport = BleTransport::new(tid, None, base_config(), io, packet_tx);
        transport.set_local_pubkey(node.identity().pubkey().serialize());
        transport
            .start_async()
            .await
            .expect("precondition: the BLE transport starts");
        let book = Arc::clone(radio);
        let own = at.clone();
        transport.io().set_connect_handler(move |to, _psm| {
            let far = book
                .lock()
                .unwrap()
                .get(&to.to_transport_addr().to_string())
                .cloned()
                .ok_or(TransportError::ConnectionRefused)?;
            let (near, theirs) = MockBleStream::pair(own.clone(), to.clone(), 2048);
            tokio::spawn(async move { far.inject_inbound(theirs).await });
            Ok(near)
        });
        let ta = at.to_transport_addr();
        radio
            .lock()
            .unwrap()
            .insert(ta.to_string(), Arc::clone(transport.io()));
        node.transports.insert(tid, TransportHandle::Ble(transport));
        TestNode {
            node,
            transport_id: tid,
            packet_rx: bridge_to_unbounded(packet_rx),
            addr: ta,
        }
    }
}

// ---------------------------------------------------------------------------
// The world's own tests
// ---------------------------------------------------------------------------

/// What node `from` holds of its dial to node `to` on transport 0: the link
/// record's state, whether a pending transport connect names the link, and
/// whether its control machine keeps its msg1 for resending. `None` when no
/// link of `from`'s is at `to`'s address.
fn dial_seen(world: &World, from: usize, to: usize) -> Option<(LinkState, bool, bool)> {
    let node = &world.nodes[from].node;
    let (tid, addr) = &world.ends[to][0];
    let link = node
        .links
        .values()
        .find(|l| l.transport_id() == *tid && l.remote_addr() == addr)?;
    let id = link.link_id();
    let connecting = node
        .peering
        .pending_connects
        .iter()
        .any(|p| p.link_id == id);
    let resends = node
        .peer_machines
        .get(&id)
        .is_some_and(|m| m.conn_handshake_msg1().is_some());
    Some((link.state(), connecting, resends))
}

/// A dial in a world is the one `initiate_connection` makes. On a
/// connection-oriented transport the link starts connecting, with a pending
/// connect and no msg1 yet, and `Connected` completes it and arms the msg1;
/// on the loopback the link is connected at once and the msg1 armed. Then
/// `Heal` leaves the two nodes on one working session.
async fn dial_made(medium: Medium, on: bool) {
    let mut world = World::new(medium, 2, on).await;
    let dial = Step::Dial {
        from: 0,
        to: 1,
        transport: 0,
    };
    run(&mut world, &[dial]).await;
    let oriented = medium != Medium::Loopback;
    let at_dial = dial_seen(&world, 0, 1);
    run(&mut world, &[Step::Connected { node: 0 }]).await;
    let connected = dial_seen(&world, 0, 1);
    let want = if oriented {
        (LinkState::Connecting, true, false)
    } else {
        (LinkState::Connected, false, true)
    };
    let quiet = run(&mut world, &[Step::Heal]).await;
    let one = settled(&mut world.nodes, 0, 1).await;
    cleanup_nodes(&mut world.nodes).await;
    assert_eq!(
        (at_dial, connected),
        (Some(want), Some((LinkState::Connected, false, true))),
        "defect: the dial is not the one initiate_connection makes on {medium:?}"
    );
    assert!(quiet, "defect: the nodes did not go quiet");
    assert_eq!(one, Ok(()), "defect: the dial did not settle");
}

#[tokio::test]
async fn a_dial_in_a_world_goes_through_initiate_connection_on_loopback() {
    dial_made(Medium::Loopback, false).await;
}

#[tokio::test]
async fn a_dial_in_a_world_goes_through_initiate_connection_on_loopback_with_multipath_on() {
    dial_made(Medium::Loopback, true).await;
}

#[tokio::test]
async fn a_dial_in_a_world_goes_through_initiate_connection_on_tcp() {
    dial_made(Medium::Tcp, false).await;
}

#[tokio::test]
async fn a_dial_in_a_world_goes_through_initiate_connection_on_tcp_with_multipath_on() {
    dial_made(Medium::Tcp, true).await;
}

#[cfg(ble_available)]
#[tokio::test]
async fn a_dial_in_a_world_goes_through_initiate_connection_on_ble() {
    dial_made(Medium::Ble, false).await;
}

#[cfg(ble_available)]
#[tokio::test]
async fn a_dial_in_a_world_goes_through_initiate_connection_on_ble_with_multipath_on() {
    dial_made(Medium::Ble, true).await;
}

/// The session `world`'s node `at` holds its peer `peer` on: (ours, theirs).
fn session(
    world: &World,
    at: usize,
    peer: usize,
) -> Option<(Option<SessionIndex>, Option<SessionIndex>)> {
    let addr = *world.nodes[peer].node.node_addr();
    world.nodes[at]
        .node
        .get_peer(&addr)
        .map(|p| (p.our_index(), p.their_index()))
}

/// A rekey, time, a restart and a redial each do what their step says: the
/// rekey moves the rekeying node onto a new session, which carries a
/// heartbeat each way once time has let it cut over, the restarted node holds no
/// peer, and a dial to it from the node that held its old run leaves the
/// pair on one working session again.
async fn steps_run(medium: Medium, on: bool) {
    let mut world = World::new(medium, 2, on).await;
    let dial = |from, to| Step::Dial {
        from,
        to,
        transport: 0,
    };
    run(
        &mut world,
        &[dial(0, 1), Step::Connected { node: 0 }, Step::Heal],
    )
    .await;
    assert_eq!(
        settled(&mut world.nodes, 0, 1).await,
        Ok(()),
        "precondition: the dial settled"
    );
    let first = session(&world, 0, 1);
    run(
        &mut world,
        &[Step::Rekey { node: 0 }, Step::Heal, Step::Advance(5_000)],
    )
    .await;
    let rekeyed = session(&world, 0, 1);
    let after_rekey = [
        heartbeat_reaches(&mut world.nodes, 0, 1).await,
        heartbeat_reaches(&mut world.nodes, 1, 0).await,
    ];
    run(&mut world, &[Step::Restart { node: 1 }]).await;
    let remembered = world.nodes[1].node.peers.len();
    let quiet = run(
        &mut world,
        &[dial(0, 1), Step::Connected { node: 0 }, Step::Heal],
    )
    .await;
    let after_redial = settled(&mut world.nodes, 0, 1).await;
    cleanup_nodes(&mut world.nodes).await;
    let mut bad = Vec::new();
    if rekeyed == first {
        bad.push(format!("the rekey left the session as it was: {first:?}"));
    }
    if after_rekey.iter().any(Result::is_err) {
        bad.push(format!("heartbeats after the rekey: {after_rekey:?}"));
    }
    if remembered != 0 {
        bad.push(format!("the restarted node holds {remembered} peers"));
    }
    if !quiet {
        bad.push("the nodes did not go quiet after the redial".to_string());
    }
    if let Err(e) = after_redial {
        bad.push(format!("after the redial: {e}"));
    }
    assert!(bad.is_empty(), "defect: on {medium:?}: {bad:#?}");
}

#[tokio::test]
async fn a_world_rekeys_restarts_and_redials_to_one_session_on_loopback() {
    steps_run(Medium::Loopback, false).await;
}

#[tokio::test]
async fn a_world_rekeys_restarts_and_redials_to_one_session_on_loopback_with_multipath_on() {
    steps_run(Medium::Loopback, true).await;
}

#[tokio::test]
async fn a_world_rekeys_restarts_and_redials_to_one_session_on_tcp() {
    steps_run(Medium::Tcp, false).await;
}

#[tokio::test]
async fn a_world_rekeys_restarts_and_redials_to_one_session_on_tcp_with_multipath_on() {
    steps_run(Medium::Tcp, true).await;
}

#[cfg(ble_available)]
#[tokio::test]
async fn a_world_rekeys_restarts_and_redials_to_one_session_on_ble() {
    steps_run(Medium::Ble, false).await;
}

#[cfg(ble_available)]
#[tokio::test]
async fn a_world_rekeys_restarts_and_redials_to_one_session_on_ble_with_multipath_on() {
    steps_run(Medium::Ble, true).await;
}

/// A dial on a loopback world's second transport runs on it: the pair
/// settles, and each end holds its peer on a link of that transport.
async fn second_transport(on: bool) {
    let mut world = World::new(Medium::Loopback, 2, on).await;
    let t = world.add_transport();
    let quiet = run(
        &mut world,
        &[
            Step::Dial {
                from: 0,
                to: 1,
                transport: t,
            },
            Step::Heal,
        ],
    )
    .await;
    let one = settled(&mut world.nodes, 0, 1).await;
    let on_t: Vec<Option<TransportId>> = [(0, 1), (1, 0)]
        .iter()
        .map(|&(at, peer)| {
            let node = &world.nodes[at].node;
            let addr = world.nodes[peer].node.node_addr();
            node.get_peer(addr)
                .and_then(|p| node.links.get(&p.link_id()))
                .map(|l| l.transport_id())
        })
        .collect();
    cleanup_nodes(&mut world.nodes).await;
    assert!(quiet, "defect: the nodes did not go quiet");
    assert_eq!(one, Ok(()), "defect: the dial did not settle");
    assert_eq!(
        on_t,
        vec![Some(world.ends[0][t].0); 2],
        "defect: the pair is not held on the second transport"
    );
}

#[tokio::test]
async fn a_dial_on_a_worlds_second_transport_runs_on_it() {
    second_transport(false).await;
}

#[tokio::test]
async fn a_dial_on_a_worlds_second_transport_runs_on_it_with_multipath_on() {
    second_transport(true).await;
}

/// Whether `world`'s nodes 0 and 1 hold each other on one session, each
/// end's index the other's peer index.
fn one_session(world: &World) -> bool {
    matches!(
        (session(world, 0, 1), session(world, 1, 0)),
        (Some((Some(a), Some(b))), Some((Some(c), Some(d)))) if a == d && b == c
    )
}

/// A pair in a world, on a frozen clock, holds one session while time
/// passes a second at a time for 40 s, past the 30 s link-dead timeout,
/// with a heal after each second: each node's heartbeats fall due on the
/// clock its link-dead check reads, so each hears the other in time.
async fn held_past_dead(on: bool) {
    crate::time::freeze();
    let mut world = World::new(Medium::Loopback, 2, on).await;
    let dial = Step::Dial {
        from: 0,
        to: 1,
        transport: 0,
    };
    let settled_at_dial = run(&mut world, &[dial, Step::Connected { node: 0 }, Step::Heal]).await;
    assert!(
        settled_at_dial && one_session(&world),
        "precondition: the dial left the pair on one session"
    );
    let mut lost = None;
    for second in 1..=40 {
        let quiet = run(&mut world, &[Step::Advance(1_000), Step::Heal]).await;
        if lost.is_none() && !(quiet && one_session(&world)) {
            lost = Some((second, quiet, session(&world, 0, 1), session(&world, 1, 0)));
        }
    }
    cleanup_nodes(&mut world.nodes).await;
    assert_eq!(
        lost, None,
        "defect: the pair lost its one session (second, quiet, node 0's, node 1's)"
    );
}

#[tokio::test]
async fn a_pair_in_a_world_holds_one_session_through_time_past_the_link_dead_timeout() {
    held_past_dead(false).await;
}

#[tokio::test]
async fn a_pair_in_a_world_holds_one_session_through_time_past_the_link_dead_timeout_with_multipath_on()
 {
    held_past_dead(true).await;
}

/// Whether `world`'s node `at` holds node `peer` as a peer.
fn holds(world: &World, at: usize, peer: usize) -> bool {
    let addr = world.nodes[peer].node.node_addr();
    world.nodes[at].node.get_peer(addr).is_some()
}

/// What a dial's handshake has reached at one step: whether node 0 holds
/// node 1, whether node 1 holds node 0, and the msg1s and msg2s each holds
/// unhanded, node 0's first.
type Reached = (bool, bool, [usize; 4]);

/// The state `Reached` reads in `world`.
fn reached(world: &mut World) -> Reached {
    (
        holds(world, 0, 1),
        holds(world, 1, 0),
        [
            world.held(0, Kind::Msg1),
            world.held(0, Kind::Msg2),
            world.held(1, Kind::Msg1),
            world.held(1, Kind::Msg2),
        ],
    )
}

/// A world hands a node a msg1 or a msg2 only at the step that names it:
/// after the dial node 1 holds the msg1 and neither node the other; after
/// the msg1, node 1 holds node 0 and node 0 holds the answer unread; after
/// the msg2, both hold each other, nothing is left held, and the pair is on
/// one working session. Each stage is checked before the next step runs, so
/// a packet handed early reds here and not at the next step's lookup.
async fn named_only(medium: Medium, on: bool) {
    let mut world = World::new(medium, 2, on).await;
    let dial = Step::Dial {
        from: 0,
        to: 1,
        transport: 0,
    };
    let msg1 = Step::Handshake {
        to: 1,
        kind: Kind::Msg1,
        nth: 0,
    };
    let msg2 = Step::Handshake {
        to: 0,
        kind: Kind::Msg2,
        nth: 0,
    };
    let stages: [(&[Step], Reached); 3] = [
        (
            &[dial, Step::Connected { node: 0 }],
            (false, false, [0, 0, 1, 0]),
        ),
        (&[msg1], (false, true, [0, 1, 0, 0])),
        (&[msg2], (true, true, [0, 0, 0, 0])),
    ];
    for (n, (steps, want)) in stages.iter().enumerate() {
        run(&mut world, steps).await;
        let seen = reached(&mut world);
        assert_eq!(
            seen, *want,
            "defect: on {medium:?}, after stage {n}, a node was handed what no step named, or not what one did"
        );
    }
    let one = settled(&mut world.nodes, 0, 1).await;
    cleanup_nodes(&mut world.nodes).await;
    assert_eq!(one, Ok(()), "defect: the handshake did not settle");
}

#[tokio::test]
async fn a_world_delivers_only_what_the_schedule_names_on_loopback() {
    named_only(Medium::Loopback, false).await;
}

#[tokio::test]
async fn a_world_delivers_only_what_the_schedule_names_on_loopback_with_multipath_on() {
    named_only(Medium::Loopback, true).await;
}

#[tokio::test]
async fn a_world_delivers_only_what_the_schedule_names_on_tcp() {
    named_only(Medium::Tcp, false).await;
}

#[tokio::test]
async fn a_world_delivers_only_what_the_schedule_names_on_tcp_with_multipath_on() {
    named_only(Medium::Tcp, true).await;
}

#[cfg(ble_available)]
#[tokio::test]
async fn a_world_delivers_only_what_the_schedule_names_on_ble() {
    named_only(Medium::Ble, false).await;
}

#[cfg(ble_available)]
#[tokio::test]
async fn a_world_delivers_only_what_the_schedule_names_on_ble_with_multipath_on() {
    named_only(Medium::Ble, true).await;
}

/// A held msg1 can be dropped, duplicated, or swapped with the next one, on
/// the loopback. Dropped, its responder never reads it. Duplicated, the
/// responder reads it and it stays held. Swapped with a third node's later
/// msg1, the responder's first read is the later one.
async fn varied(on: bool) {
    let dial = |from, to| Step::Dial {
        from,
        to,
        transport: 0,
    };
    let at = |to, nth| (to, Kind::Msg1, nth);
    let mut bad = Vec::new();

    let mut world = World::new(Medium::Loopback, 2, on).await;
    let (to, kind, nth) = at(1, 0);
    run(
        &mut world,
        &[dial(0, 1), Step::Drop { to, kind, nth }, Step::Heal],
    )
    .await;
    let dropped = (holds(&world, 1, 0), world.held(1, Kind::Msg1));
    if dropped != (false, 0) {
        bad.push(format!("dropped: (holds, msg1s held) {dropped:?}"));
    }
    cleanup_nodes(&mut world.nodes).await;

    let mut world = World::new(Medium::Loopback, 2, on).await;
    run(&mut world, &[dial(0, 1), Step::Duplicate { to, kind, nth }]).await;
    let copied = (holds(&world, 1, 0), world.held(1, Kind::Msg1));
    if copied != (true, 1) {
        bad.push(format!("duplicated: (holds, msg1s held) {copied:?}"));
    }
    cleanup_nodes(&mut world.nodes).await;

    let mut world = World::new(Medium::Loopback, 3, on).await;
    let (to, kind, nth) = at(0, 0);
    run(
        &mut world,
        &[
            dial(1, 0),
            dial(2, 0),
            Step::Swap { to, kind, nth },
            Step::Handshake { to, kind, nth },
        ],
    )
    .await;
    let first = (holds(&world, 0, 1), holds(&world, 0, 2));
    if first != (false, true) {
        bad.push(format!("swapped: (holds node 1, holds node 2) {first:?}"));
    }
    cleanup_nodes(&mut world.nodes).await;

    assert!(bad.is_empty(), "defect: {bad:#?}");
}

#[tokio::test]
async fn a_held_packet_can_be_dropped_duplicated_and_swapped() {
    varied(false).await;
}

#[tokio::test]
async fn a_held_packet_can_be_dropped_duplicated_and_swapped_with_multipath_on() {
    varied(true).await;
}
