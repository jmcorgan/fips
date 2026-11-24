//! A deployed release's dialer on two transports, against this node as the
//! responder.
//!
//! A release before the redial rule dials a peer on both of its transports
//! at once. When the first dial promotes and the second's answer arrives
//! while it holds the peer, and it wins the tie-break between its two dials,
//! it moves onto the second dial's session without moving address: it frees
//! the first session's index with no drain, sends under the new session on
//! the first transport, and closes the second connection. The responder,
//! having heard the first peering, answered the second msg1 as a redial, so
//! the first frame under the redial's session arrives on the held link's
//! transport, from the held link's pair.
//!
//! No such dialer runs here. The device makes a node of this tree behave as
//! one, between two loopback nodes that each hold a second loopback
//! transport, with a relay the driver applies as it hands packets over. The
//! client (node 0) is a node of this tree, which at its second dial's msg2
//! moves to its link on transport 2. The relay is per cycle:
//!
//! - It is off at the start of a cycle, so the second msg1 sets up a
//!   candidate on the server's transport 2 and its msg2 comes back.
//! - It engages at the client's swap: the first hand-over after which the
//!   client holds the server on its transport-2 link. While engaged, the
//!   client's packets on transport 2 reach the server on transport 1, from
//!   the client's transport-1 address; the server's packets to the client's
//!   transport-1 address reach the client on transport 2, from the
//!   server's transport-2 address; and the server's packets to the client's
//!   transport-2 address are lost, since the client closed that connection.
//! - It disengages once the client no longer holds the server, so the
//!   client's next dials go out unrelabelled and the next cycle repeats the
//!   first.
//!
//! The server then sees what a deployed release that wins the tie-break
//! sends, and each later rekey msg1 of either end arrives on that end's
//! held link. While the relay is off, delivery on transport 2 can be held
//! back by a stated delay, as a slower second transport holds it.
//!
//! The driver runs both nodes on a frozen clock, moved in steps of 500 ms
//! with the wall clock, each node's receive-loop timers ticked after each
//! step and everything sent handed over until both are quiet, as
//! `roam_redial.rs` drives its pair. Where a test has the client redial, the
//! driver dials both of the server's addresses at once whenever the client
//! holds no peer and has no dial out, as the deployed release's reconnect
//! does: two loopback transports share a type, and a configured peer's
//! address is resolved to a transport by its type.
//!
//! The tests: the reproduction (the server keeps the held link and moves it
//! onto the redial's session, at both address orders and multipath
//! settings), the run of 300 s over which the flap would repeat, the
//! dialer of this tree that moves to its second dial (the existing swap,
//! with multipath off and on), and the adopted redial's msg1 sent again.

use super::super::roam_redial::{STEP_MS, tick};
use super::super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, cleanup_nodes, make_test_node_with_config,
};
use super::super::*;
use super::audit::assert_coherent;
use super::{alias, with_path};
use crate::node::stats::HandshakeStatsSnapshot;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};
use crate::proto::link::LinkMessageType;
use crate::transport::loopback::LoopbackTransport;
use crate::transport::{TransportHandle, TransportId};

/// The client: a dialer of this tree, made to send as a deployed release.
const C: usize = 0;

/// The server: the responder under test.
const S: usize = 1;

/// How long delivery on transport 2 is held back while the relay is off,
/// in the run that repeats the cycle: about the time a deployed release's
/// second dial, over Tor, trailed its first.
const SECOND_DELAY_MS: u64 = 4_000;

/// How long the pair runs after the server hears the client and before the
/// client's second dial, in seconds: past the first exchange of tree
/// announces and filters, and short of the 30 s link age.
const SETTLE_SECS: u64 = 20;

/// The run over which the flap would repeat, in seconds: at about one cycle
/// every 90 s in the field, at least three.
const RUN_SECS: u64 = 300;

/// The client, the server, the relay between them and what the driver saw.
struct Device {
    nodes: Vec<TestNode>,
    /// Time since the device was built, in ms.
    t: u64,
    t1: TransportId,
    t2: TransportId,
    /// Each node's address on transport 1 and on transport 2.
    c1: TransportAddr,
    c2: TransportAddr,
    s1: TransportAddr,
    s2: TransportAddr,
    /// Whether the relay may engage at all: off for a dialer of this tree
    /// left as it is.
    relays: bool,
    /// Whether the relay is engaged now.
    engaged: bool,
    /// How long delivery on transport 2 is held back while the relay is off.
    delay: u64,
    /// Packets held back, with when each is due and the node it is for.
    held: Vec<(u64, usize, ReceivedPacket)>,
    /// Whether the driver redials the server on both transports whenever
    /// the client holds no peer.
    redials: bool,
    /// The link of the server's pending redial, when one was seen.
    leg: Option<LinkId>,
    /// The first msg1 that reached the server on transport 2, as sent.
    second: Option<ReceivedPacket>,
    /// When the server first moved its held link onto a redial's session.
    adopted: Option<u64>,
    /// Whether each end held the other at the last look.
    holding: [bool; 2],
    /// Each end's link and session index for the other at the last look.
    session: [Option<(LinkId, Option<SessionIndex>)>; 2],
    /// Each end's count of starts of holding the other.
    promotions: [usize; 2],
    /// Each end's count of ends of holding the other.
    drops: [usize; 2],
    /// Each end's count of session index changes on an unchanged link after
    /// the adoption: its link rekey cutovers, in either role.
    cutovers: [usize; 2],
    /// The client's tree announces and filters received when the server
    /// adopted, once it did.
    at_adoption: Option<(u64, u64)>,
}

impl Device {
    /// A client and a server, the client's node address the smaller when
    /// `c_smaller`, each with multipath `on` and a second loopback
    /// transport; the client has dialed the server on transport 1, and
    /// everything sent was handed over.
    async fn new(on: bool, c_smaller: bool) -> Device {
        crate::time::freeze();
        let s = make_test_node_with_config(with_path(Config::new(), on), 1280).await;
        let c = loop {
            let c = make_test_node_with_config(with_path(Config::new(), on), 1280).await;
            if (c.node.node_addr() < s.node.node_addr()) == c_smaller {
                break c;
            }
        };
        let mut nodes = vec![c, s];
        let t1 = nodes[C].transport_id;
        let t2 = TransportId::new(2);
        let mut second = Vec::new();
        for tn in nodes.iter_mut() {
            tn.node.supervisor.state = crate::node::NodeState::Running;
            let a2 = alias(&tn.addr, t2);
            let lo = LoopbackTransport::with_mtu(t2, a2.clone(), 1280, LOOPBACK_REGISTRY.clone());
            tn.node.transports.insert(t2, TransportHandle::Loopback(lo));
            second.push(a2);
        }
        let mut d = Device {
            c1: nodes[C].addr.clone(),
            s1: nodes[S].addr.clone(),
            c2: second[C].clone(),
            s2: second[S].clone(),
            nodes,
            t: 0,
            t1,
            t2,
            relays: true,
            engaged: false,
            delay: 0,
            held: Vec::new(),
            redials: false,
            leg: None,
            second: None,
            adopted: None,
            holding: [false; 2],
            session: [None; 2],
            promotions: [0; 2],
            drops: [0; 2],
            cutovers: [0; 2],
            at_adoption: None,
        };
        d.dial(t1).await;
        d.pump().await;
        assert!(
            d.holds(C) && d.holds(S),
            "precondition: the client's first dial peered the two"
        );
        d
    }

    fn addr(&self, at: usize) -> NodeAddr {
        *self.nodes[at].node.node_addr()
    }

    /// Whether node `at` holds the other.
    fn holds(&self, at: usize) -> bool {
        self.nodes[at].node.get_peer(&self.addr(1 - at)).is_some()
    }

    /// The link node `at` holds the other on.
    fn link(&self, at: usize) -> Option<LinkId> {
        self.nodes[at]
            .node
            .get_peer(&self.addr(1 - at))
            .map(|p| p.link_id())
    }

    /// The transport and address node `at` sends to the other on.
    fn pair(&self, at: usize) -> Option<(TransportId, TransportAddr)> {
        self.nodes[at].node.peer_link(&self.addr(1 - at))
    }

    /// The server's handshake counters.
    fn counters(&self) -> HandshakeStatsSnapshot {
        self.nodes[S].node.stats().handshake.snapshot()
    }

    /// The client dials the server's address on `tid`.
    async fn dial(&mut self, tid: TransportId) {
        let to = if tid == self.t1 {
            self.s1.clone()
        } else {
            self.s2.clone()
        };
        let id = PeerIdentity::from_pubkey_full(self.nodes[S].node.identity().pubkey_full());
        self.nodes[C]
            .node
            .initiate_connection(tid, to, id)
            .await
            .expect("precondition: the client's dial starts");
    }

    /// Where `packet`, sent to node `at`, goes: handed over as it is,
    /// relabelled, held back, or lost.
    fn route(&mut self, at: usize, mut packet: ReceivedPacket) -> Option<ReceivedPacket> {
        if self.engaged {
            return self.relabel(at, packet);
        }
        if packet.transport_id == self.t2 && self.delay > 0 {
            self.held.push((self.t + self.delay, at, packet));
            return None;
        }
        if at == S && packet.transport_id == self.t2 && phase(&packet) == Some(PHASE_MSG1) {
            self.second.get_or_insert_with(|| packet.clone());
        }
        packet.timestamp_ms = Node::now_ms();
        Some(packet)
    }

    /// The engaged relay's rules for `packet`, sent to node `at`.
    fn relabel(&self, at: usize, mut packet: ReceivedPacket) -> Option<ReceivedPacket> {
        let (t1, t2) = (self.t1, self.t2);
        if at == S && packet.transport_id == t2 && packet.remote_addr == self.c2 {
            packet.transport_id = t1;
            packet.remote_addr = self.c1.clone();
        } else if at == C && packet.transport_id == t1 && packet.remote_addr == self.s1 {
            packet.transport_id = t2;
            packet.remote_addr = self.s2.clone();
        } else if at == C && packet.transport_id == t2 {
            return None;
        }
        packet.timestamp_ms = Node::now_ms();
        Some(packet)
    }

    /// Hand each node what it was sent, through the relay, looking after
    /// each packet, until a round moves nothing.
    async fn pump(&mut self) {
        for _ in 0..1000 {
            let mut moved = 0;
            for at in [C, S] {
                while let Ok(packet) = self.nodes[at].packet_rx.try_recv() {
                    moved += 1;
                    if let Some(packet) = self.route(at, packet) {
                        self.nodes[at].node.process_packet(packet).await;
                        self.look();
                    }
                }
            }
            if moved == 0 {
                return;
            }
        }
        panic!("precondition: the device went quiet within 1000 rounds");
    }

    /// Record what changed: the server's pending redial and its adoption,
    /// the relay's engagement, each end's starts and ends of holding the
    /// other, and each end's cutovers after the adoption.
    fn look(&mut self) {
        let c = self.addr(C);
        if let Some(r) = self.nodes[S].node.redials.of(&c) {
            self.leg = Some(r.link);
        }
        let adopting = self.adopted.is_none() && self.counters().redials_adopted > 0;
        if adopting {
            self.adopted = Some(self.t);
            let m = self.nodes[C].node.metrics();
            self.at_adoption = Some((m.tree.received.get(), m.bloom.received.get()));
        }
        let on_second = self.pair(C).is_some_and(|(tid, _)| tid == self.t2);
        if self.relays && on_second {
            self.engaged = true;
        }
        if !self.holds(C) {
            self.engaged = false;
        }
        for at in [C, S] {
            let holds = self.holds(at);
            if holds && !self.holding[at] {
                self.promotions[at] += 1;
            }
            if !holds && self.holding[at] {
                self.drops[at] += 1;
            }
            self.holding[at] = holds;
            let now = self.nodes[at]
                .node
                .get_peer(&self.addr(1 - at))
                .map(|p| (p.link_id(), p.our_index()));
            let rekeyed = matches!(
                (self.session[at], now),
                (Some((l0, i0)), Some((l1, i1))) if l0 == l1 && i0 != i1
            );
            if rekeyed && self.adopted.is_some() && !(adopting && at == S) {
                self.cutovers[at] += 1;
            }
            self.session[at] = now;
        }
    }

    /// Move both clocks on by a step, hand over what is due of what was
    /// held back, run both nodes' timers, redial if the client holds no
    /// peer, and hand over what they sent.
    async fn step(&mut self) {
        crate::time::advance(Duration::from_millis(STEP_MS));
        crate::time::step_wall(STEP_MS as i64);
        self.t += STEP_MS;
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|(at, _, _)| *at <= self.t);
        self.held = later;
        for (_, to, packet) in due {
            let packet = if self.engaged {
                self.relabel(to, packet)
            } else {
                Some(packet)
            };
            if let Some(mut packet) = packet {
                if to == S && phase(&packet) == Some(PHASE_MSG1) && packet.transport_id == self.t2 {
                    self.second.get_or_insert_with(|| packet.clone());
                }
                packet.timestamp_ms = Node::now_ms();
                self.nodes[to].node.process_packet(packet).await;
                self.look();
            }
        }
        for tn in self.nodes.iter_mut() {
            tick(&mut tn.node).await;
        }
        self.look();
        if self.redials && !self.holds(C) && self.nodes[C].node.dials_in_flight().next().is_none() {
            self.dial(self.t1).await;
            self.dial(self.t2).await;
        }
        self.pump().await;
    }

    /// Run for `secs` seconds.
    async fn run(&mut self, secs: u64) {
        for _ in 0..secs * 1000 / STEP_MS {
            self.step().await;
        }
    }

    /// Run until the server has heard the client on the first peering.
    async fn until_heard(&mut self) {
        let c = self.addr(C);
        for _ in 0..20 {
            if self.nodes[S].node.core.held(&c).is_some_and(|h| h.heard) {
                return;
            }
            self.step().await;
        }
        panic!("precondition: the server heard the client within 10 s");
    }

    /// Whether a heartbeat from `from` authenticates at the other end, sent
    /// through the relay.
    async fn heartbeat(&mut self, from: usize) -> bool {
        let to = 1 - from;
        let from_addr = self.addr(from);
        let recv = |d: &Device| {
            d.nodes[to]
                .node
                .get_peer(&from_addr)
                .map(|p| p.link_stats().packets_recv)
        };
        let before = recv(self);
        let to_addr = self.addr(to);
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

    /// Whether the two hold one session: each end's index the other's peer
    /// index.
    fn one_session(&self) -> bool {
        let (Some(cp), Some(sp)) = (
            self.nodes[C].node.get_peer(&self.addr(S)),
            self.nodes[S].node.get_peer(&self.addr(C)),
        ) else {
            return false;
        };
        cp.our_index().is_some()
            && cp.our_index() == sp.their_index()
            && cp.their_index() == sp.our_index()
    }

    /// Whether node `at`'s index allocator holds exactly the index of the
    /// session it holds the other on: none leaked, none freed early.
    fn indices_exact(&self, at: usize) -> bool {
        let node = &self.nodes[at].node;
        let ours = node
            .get_peer(&self.addr(1 - at))
            .and_then(|p| p.our_index());
        ours.is_some_and(|i| node.index_allocator.is_allocated(i))
            && node.index_allocator.count() == 1
    }
}

/// The phase of `packet`'s common prefix.
fn phase(packet: &ReceivedPacket) -> Option<u8> {
    CommonPrefix::parse(&packet.data).map(|p| p.phase)
}

/// The client dials the server on transport 1 and the server hears it; then
/// the client dials the server's transport-2 address, the server answers it
/// as a redial, and the client moves onto it, sending as a deployed release
/// that won the tie-break. The device, the server's held link before the
/// second dial and its session index then.
async fn legacy_winner(on: bool, c_smaller: bool) -> (Device, LinkId, Option<SessionIndex>) {
    let mut d = Device::new(on, c_smaller).await;
    d.until_heard().await;
    // The pair's first tree announces and filters are exchanged and
    // settled, so what either sends next has a cause of its own.
    d.run(SETTLE_SECS).await;
    let held = d
        .link(S)
        .expect("precondition: the server holds the client");
    let index = d.nodes[S]
        .node
        .get_peer(&d.addr(C))
        .and_then(|p| p.our_index());
    let was = d.counters();
    d.dial(d.t2).await;
    d.pump().await;
    assert!(
        d.counters().redials > was.redials && d.leg.is_some(),
        "precondition: the server answered the second dial as a redial"
    );
    assert!(
        d.engaged,
        "precondition: the client moved onto its second dial, engaging the relay"
    );
    let c = d.addr(C);
    for _ in 0..20 {
        if d.nodes[S].node.redials.of(&c).is_none() {
            break;
        }
        d.step().await;
    }
    assert!(
        d.nodes[S].node.redials.of(&c).is_none(),
        "precondition: a frame of the client's proved the redial within 10 s"
    );
    (d, held, index)
}

/// The reproduction. The server keeps the client on the link it held, at
/// its pair, with the redial's session and index; the redial's link and
/// handshake entry go; each index allocator holds exactly its session's
/// index; a heartbeat authenticates each way, and the audit is clean. The
/// client is sent a tree announce and a filter under the new session. With
/// multipath on, the server's bundle holds one path, at the held pair, and
/// the link is not counted capable until the renewed bundle finds it again.
/// Before the fix the server is on the redial's link, sending to the
/// transport-2 address the client closed, and its heartbeat is lost.
async fn reproduction(on: bool, c_smaller: bool) {
    let (mut d, held, index) = legacy_winner(on, c_smaller).await;
    let leg = d.leg.expect("precondition: the redial's link was seen");
    let c = d.addr(C);
    let s_on = d.link(S);
    assert_eq!(
        (s_on, d.pair(S)),
        (Some(held), Some((d.t1, d.c1.clone()))),
        "defect: the server left the link it held for the redial's (link {leg}), at the transport-2 address the client closed"
    );
    // The adoption's tree announce and filter, within the announce's rate
    // limit and the filter's tick.
    d.run(5).await;
    let (tree, bloom) = d
        .at_adoption
        .expect("precondition: the adoption was counted");
    let m = d.nodes[C].node.metrics();
    let (tree_now, bloom_now) = (m.tree.received.get(), m.bloom.received.get());
    assert!(
        tree_now > tree && bloom_now > bloom,
        "defect: the client was not sent a tree announce and a filter under the new session: tree {tree} to {tree_now}, filter {bloom} to {bloom_now}"
    );
    let sp = d.nodes[S]
        .node
        .get_peer(&c)
        .expect("the server holds the client");
    assert_ne!(sp.our_index(), index, "the server holds a new session");
    assert!(d.one_session(), "one session at both ends");
    assert_eq!(d.counters().redials_adopted, 1);
    assert_eq!(d.counters().redials_proven, 0);
    assert!(
        d.nodes[S].node.handshakes.get(&leg).is_none()
            && d.nodes[S].node.links.get(&leg).is_none()
            && d.nodes[S].node.redials.of(&c).is_none(),
        "the redial's link, handshake entry and pending redial are gone"
    );
    assert!(
        d.indices_exact(S) && d.indices_exact(C),
        "each index allocator holds exactly its session's index: server {}, client {}",
        d.nodes[S].node.index_allocator.count(),
        d.nodes[C].node.index_allocator.count()
    );
    if on {
        let sp = d.nodes[S].node.get_peer(&c).expect("held");
        let paths: Vec<(TransportId, TransportAddr)> = sp
            .bundle()
            .map(|b| {
                b.paths()
                    .paths()
                    .iter()
                    .map(|p| (p.transport_id(), p.addr().clone()))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            paths,
            vec![(d.t1, d.c1.clone())],
            "the bundle holds one path, at the held pair"
        );
        let capable = d.nodes[S]
            .node
            .links
            .no(&held)
            .and_then(|no| d.nodes[S].node.core.links().get(no))
            .map(|r| r.capable);
        assert_eq!(
            capable,
            Some(false),
            "the held link is not counted capable until the renewed bundle finds it again"
        );
        assert!(
            !d.nodes[S].node.in_use(d.t2, &d.c2, held),
            "nothing uses the redial's transport-2 pair, so its connection is not kept open"
        );
    }
    assert!(
        d.heartbeat(C).await && d.heartbeat(S).await,
        "a heartbeat authenticates each way"
    );
    assert_coherent(&mut d.nodes, "after the adoption").await;
    cleanup_nodes(&mut d.nodes).await;
}

#[tokio::test]
async fn a_legacy_winners_redial_proven_on_the_held_link_keeps_the_server_on_that_link_client_smaller()
 {
    reproduction(false, true).await;
}

#[tokio::test]
async fn a_legacy_winners_redial_proven_on_the_held_link_keeps_the_server_on_that_link_client_larger()
 {
    reproduction(false, false).await;
}

#[tokio::test]
async fn a_legacy_winners_redial_proven_on_the_held_link_keeps_the_server_on_that_link_client_smaller_with_multipath_on()
 {
    reproduction(true, true).await;
}

#[tokio::test]
async fn a_legacy_winners_redial_proven_on_the_held_link_keeps_the_server_on_that_link_client_larger_with_multipath_on()
 {
    reproduction(true, false).await;
}

/// The flap. The client dials both of the server's addresses whenever it
/// holds none, transport 2's delivery 4 s behind transport 1's, and the
/// device runs for 300 s. One promotion at each end, no end drops the
/// other, and each end cuts over a link rekey at least once after the
/// adoption. Before the fix the server sends to the address the client
/// closed, the client drops it at link-dead and dials again, and the cycle
/// repeats.
#[tokio::test]
async fn a_legacy_winner_dialing_over_two_transports_keeps_one_session_for_300_s() {
    let mut d = Device::new(false, true).await;
    d.delay = SECOND_DELAY_MS;
    d.redials = true;
    d.dial(d.t2).await;
    d.pump().await;
    d.run(RUN_SECS).await;
    let seen = format!(
        "promotions {:?}, drops {:?}, cutovers {:?}, adopted at {:?} ms, counters {:?}",
        d.promotions,
        d.drops,
        d.cutovers,
        d.adopted,
        d.counters()
    );
    assert!(
        d.promotions == [1, 1] && d.drops == [0, 0],
        "defect: the pair did not keep one peering for {RUN_SECS} s: {seen}"
    );
    assert!(
        d.adopted.is_some() && d.cutovers.iter().all(|&n| n >= 1),
        "each end cut over a link rekey after the adoption: {seen}"
    );
    assert!(
        d.heartbeat(C).await && d.heartbeat(S).await,
        "a heartbeat authenticates each way: {seen}"
    );
    cleanup_nodes(&mut d.nodes).await;
}

/// A dialer of this tree that moves to its second dial, on transport 2, is
/// left as it is: its first frame under the redial's session reaches the
/// server on the redial's transport, from the redial's pair, so the server
/// swaps onto the redial's link as before. With multipath on the held link
/// holds no path on transport 2 here, since a path at the pair the second
/// msg1 came from would have made that msg1 one of the held link's.
async fn master_dialer(on: bool) {
    let mut d = Device::new(on, true).await;
    d.relays = false;
    d.until_heard().await;
    let was = d.counters();
    d.dial(d.t2).await;
    d.pump().await;
    d.run(2).await;
    let now = d.counters();
    assert_eq!(
        (
            now.redials - was.redials,
            now.redials_proven - was.redials_proven,
            now.redials_adopted - was.redials_adopted,
        ),
        (1, 1, 0),
        "defect: the redial of a dialer that moved to it was not swapped"
    );
    assert_eq!(
        (d.pair(C), d.pair(S)),
        (Some((d.t2, d.s2.clone())), Some((d.t2, d.c2.clone()))),
        "both ends on transport 2"
    );
    assert!(d.one_session() && d.heartbeat(C).await && d.heartbeat(S).await);
    assert_coherent(&mut d.nodes, "after the swap").await;
    cleanup_nodes(&mut d.nodes).await;
}

#[tokio::test]
async fn a_redial_of_a_dialer_that_moved_to_its_second_transport_is_swapped() {
    master_dialer(false).await;
}

#[tokio::test]
async fn a_redial_of_a_dialer_that_moved_to_its_second_transport_is_swapped_with_multipath_on() {
    master_dialer(true).await;
}

/// The adopted redial's msg1 sent again on transport 2 after the adoption
/// is refused: no redial is answered or armed, and the server stays on the
/// held link with the adopted session.
#[tokio::test]
async fn an_adopted_redials_msg1_sent_again_is_refused_and_opens_no_redial() {
    let (mut d, held, _) = legacy_winner(false, true).await;
    assert_eq!(
        d.counters().redials_adopted,
        1,
        "precondition: the server adopted the redial"
    );
    let c = d.addr(C);
    let index = d.nodes[S].node.get_peer(&c).and_then(|p| p.our_index());
    let mut again = d
        .second
        .clone()
        .expect("precondition: the second msg1 was seen");
    again.timestamp_ms = Node::now_ms();
    let was = d.counters();
    d.nodes[S].node.process_packet(again).await;
    d.pump().await;
    let now = d.counters();
    assert!(
        now.redials == was.redials && d.nodes[S].node.redials.of(&c).is_none(),
        "defect: the adopted redial's msg1 sent again armed a redial: {was:?} to {now:?}"
    );
    assert_eq!(
        (
            d.link(S),
            d.nodes[S].node.get_peer(&c).and_then(|p| p.our_index())
        ),
        (Some(held), index),
        "the server stays on the held link with the adopted session"
    );
    cleanup_nodes(&mut d.nodes).await;
}
