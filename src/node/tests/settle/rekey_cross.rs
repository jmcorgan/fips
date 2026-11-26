//! A rekey crossed by dials on a second transport, on real nodes, scripted
//! by hand outside the explorer's world: the core's start 9 as the explorer
//! writes it (`explore/starts.rs`, `REKEYING` and `CROSSING_REKEY`).
//!
//! Two loopback nodes with two transports each. Node `a` dials node `b` on
//! transport 0 and the pair settles; `a` starts a rekey with `b`'s end of
//! the session past the floor below which a msg1 is a fresh dial; then `a`
//! dials `b` on transport 1 and `b` dials `a` there. Nothing a node is sent
//! reaches it until the test hands it over: `b` reads `a`'s rekey msg1, then
//! `a`'s dial msg1; `a` reads `b`'s dial msg1, then the first msg2 it holds.
//! An established frame is handed over after each step once no msg1 or
//! msg2 from the same source is held ahead of it. One variant loses `a`'s
//! dial msg1 to `b` instead of handing it over.
//!
//! Then the leaf, as the explorer heals one: everything is handed over, and
//! the clock moves a second at a time, each node running its receive-loop
//! tick, with each dialer holding neither its peer nor a dial redialing.
//! The explorer judges at its leaf, short of the 30 s handshake and
//! link-dead timeouts; these tests run on to 31 s and 60 s and judge there
//! too, each judgement on a run of its own, since a judgement's heartbeats
//! change the state it reads. Each test asserts, at its `defect:`
//! assertion, that the pair is coherent at all three: a breach at the leaf
//! that the timeouts end by 31 s or 60 s is still a breach.
//!
//! Every run prints its record: each packet each node sent, each step, each
//! change of a node's peer with the packet or tick that made it, and at each
//! checkpoint each node's peer, pending rekey session and live links.
//!
//! In the smaller order the pair is coherent at every checkpoint. The
//! smaller node's pending redial leg at its held link's pair names that
//! pair in the index until the leg is reaped, which the audit allows,
//! since a msg1 from the pair is still judged on the held link (the
//! `..._answered_on_the_held_link` tests show that).
//!
//! In the larger order the crossed redials are settled by the dial
//! tie-break at each leg's first frame, and the `..._without_a_split_...`
//! tests show the pair is not split. The smaller node is still left
//! holding a responder pending of the larger's rekey that the larger never
//! adopts, so the larger-order tests that judge the whole pair fail today
//! and are ignored as known defects (`testing/ignored-tests.txt`), which
//! `testing/known-defect-lane.sh` runs and expects to fail; with the dial's
//! msg1 lost, the resent msg1 is answered as a rekey into such a pending.
//! The explorer's start 9 pins it where it finds it (`explore/starts.rs`).
//!
//! The last tests script the other arrival order of crossed dials on
//! transport 1: the larger node dials from a second address of its own, so
//! the smaller reads that dial's msg1 at a pair off its own dial, after it
//! has moved onto its own dial.

use super::super::roam_redial::since;
use super::super::spanning_tree::{LOOPBACK_REGISTRY, TestNode, cleanup_nodes};
use super::super::*;
use super::audit::audit;
use super::{alias, loopback_node, settled};
use crate::proto::fmp::wire::{
    CommonPrefix, EncryptedHeader, Msg1Header, Msg2Header, PHASE_MSG1, PHASE_MSG2,
};
use crate::transport::loopback::LoopbackTransport;
use crate::transport::{TransportHandle, TransportId};
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// The class of a handshake packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Msg1,
    Msg2,
}

/// The class of `packet`, or `None` for an established frame.
fn kind_of(packet: &ReceivedPacket) -> Option<Kind> {
    match CommonPrefix::parse(&packet.data).map(|p| p.phase) {
        Some(PHASE_MSG1) => Some(Kind::Msg1),
        Some(PHASE_MSG2) => Some(Kind::Msg2),
        _ => None,
    }
}

/// Which node of the pair rekeys and dials first, as the explorer's
/// `Order`: `Smaller` as the start is written, `Larger` with the nodes
/// exchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    Smaller,
    Larger,
}

/// Where a run is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Judge {
    /// Where the explorer's heal ends its leaf.
    Leaf,
    /// This many seconds into the leaf.
    At(u64),
}

/// How long a leaf runs at most, in seconds.
const LEAF_END: u64 = 60;

/// The explorer's leaf bound before every pair agrees (`LEAF_SECS`).
const LEAF_SECS: u64 = 25;

/// The explorer's bound once every pair agrees while a dial is still out
/// (`DIAL_SECS`).
const DIAL_SECS: u64 = 31;

/// A peer as one node holds it: (ours, theirs, link).
type View = Option<(Option<SessionIndex>, Option<SessionIndex>, LinkId)>;

/// Two loopback nodes with two transports each, and what each was sent and
/// not yet handed.
struct Rig {
    /// The nodes, in ascending order of node address.
    nodes: Vec<TestNode>,
    /// Each node's transports, by index: its id and the node's address.
    ends: Vec<Vec<(TransportId, TransportAddr)>>,
    /// What each node has been sent and not yet handed, in arrival order.
    held: Vec<VecDeque<ReceivedPacket>>,
    /// The run's name, the prefix of each line it prints.
    name: String,
    /// Where the run is: the build, the script, or a second of the leaf.
    at: String,
    /// Each node whose established frames `flow` keeps held, until a
    /// `heal` hands them over.
    hold: [bool; 2],
}

impl Rig {
    /// Two nodes with multipath set as `on`, on a frozen clock, each with a
    /// second loopback transport.
    async fn new(on: bool, name: String) -> Rig {
        crate::time::freeze();
        let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
        nodes.sort_by_key(|tn| *tn.node.node_addr());
        let mut ends: Vec<Vec<(TransportId, TransportAddr)>> = nodes
            .iter()
            .map(|tn| vec![(tn.transport_id, tn.addr.clone())])
            .collect();
        let tid = TransportId::new(2);
        for (tn, ends) in nodes.iter_mut().zip(ends.iter_mut()) {
            let addr = alias(&ends[0].1, tid);
            let lo =
                LoopbackTransport::with_mtu(tid, addr.clone(), 1280, LOOPBACK_REGISTRY.clone());
            tn.node
                .transports
                .insert(tid, TransportHandle::Loopback(lo));
            ends.push((tid, addr));
        }
        Rig {
            nodes,
            ends,
            held: vec![VecDeque::new(), VecDeque::new()],
            name,
            at: "build".to_string(),
            hold: [false; 2],
        }
    }

    /// Print one line of the record.
    fn note(&self, line: impl AsRef<str>) {
        println!("[{}] {}: {}", self.name, self.at, line.as_ref());
    }

    /// The node and transport whose address on `tid` is `addr`.
    fn whose(&self, tid: TransportId, addr: &TransportAddr) -> String {
        for (n, ends) in self.ends.iter().enumerate() {
            for (t, (id, a)) in ends.iter().enumerate() {
                if *id == tid && a == addr {
                    return format!("node {n} t{t}");
                }
            }
        }
        format!("{addr} on {tid}")
    }

    /// `packet`, sent to node `to`, as the record names it.
    fn describe(&self, to: usize, packet: &ReceivedPacket) -> String {
        let from = self.whose(packet.transport_id, &packet.remote_addr);
        let what = match kind_of(packet) {
            Some(Kind::Msg1) => match Msg1Header::parse(&packet.data) {
                Some(h) => format!("msg1 sender {}", h.sender_idx.as_u32()),
                None => "msg1 (unparsed)".to_string(),
            },
            Some(Kind::Msg2) => match Msg2Header::parse(&packet.data) {
                Some(h) => format!(
                    "msg2 sender {} receiver {}",
                    h.sender_idx.as_u32(),
                    h.receiver_idx.as_u32()
                ),
                None => "msg2 (unparsed)".to_string(),
            },
            None => match EncryptedHeader::parse(&packet.data) {
                Some(h) => format!(
                    "frame receiver {} counter {}",
                    h.receiver_idx.as_u32(),
                    h.counter
                ),
                None => format!("other ({} bytes)", packet.data.len()),
            },
        };
        format!("{what}, {from} to node {to}")
    }

    /// Move what reached each node into the hold, recording each packet sent.
    fn collect(&mut self) {
        for at in 0..self.nodes.len() {
            let mut got = Vec::new();
            while let Ok(p) = self.nodes[at].packet_rx.try_recv() {
                got.push(p);
            }
            for p in got {
                if kind_of(&p).is_some() || self.at != "frames" {
                    self.note(format!("sent: {}", self.describe(at, &p)));
                }
                self.held[at].push_back(p);
            }
        }
    }

    /// Each node's view of the other.
    fn views(&self) -> [View; 2] {
        let v = |i: usize, j: usize| {
            self.nodes[i]
                .node
                .get_peer(self.nodes[j].node.node_addr())
                .map(|p| (p.our_index(), p.their_index(), p.link_id()))
        };
        [v(0, 1), v(1, 0)]
    }

    /// Record each node whose view of its peer changed from `was`, naming
    /// `cause`.
    fn changes(&self, was: [View; 2], cause: &str) {
        let now = self.views();
        for i in 0..2 {
            if was[i] != now[i] {
                self.note(format!(
                    "PEER CHANGE node {i}: {} -> {} at {cause}",
                    show_view(&was[i]),
                    show_view(&now[i])
                ));
            }
        }
    }

    /// Hand `packet` to node `at`, recording any peer change it makes.
    async fn give(&mut self, at: usize, packet: ReceivedPacket) {
        let what = self.describe(at, &packet);
        let was = self.views();
        if kind_of(&packet).is_some() {
            self.note(format!("handed: {what}"));
        }
        self.nodes[at].node.process_packet(packet).await;
        self.changes(was, &format!("handing {what}"));
    }

    /// Hand each node every held frame no held msg1 or msg2 from the same
    /// source arrived before, and what those send in turn, until a round
    /// moves none.
    async fn flow(&mut self) {
        let at = std::mem::replace(&mut self.at, "frames".to_string());
        for _ in 0..300 {
            self.collect();
            let mut handed = 0;
            for i in 0..self.nodes.len() {
                let mut blocked = Vec::new();
                let mut kept = VecDeque::new();
                let mut free = Vec::new();
                for p in std::mem::take(&mut self.held[i]) {
                    let source = (p.transport_id, p.remote_addr.clone());
                    if kind_of(&p).is_some() {
                        blocked.push(source);
                        kept.push_back(p);
                    } else if blocked.contains(&source) || self.hold[i] {
                        kept.push_back(p);
                    } else {
                        free.push(p);
                    }
                }
                self.held[i] = kept;
                for p in free {
                    self.give(i, p).await;
                    handed += 1;
                }
            }
            if handed == 0 {
                break;
            }
        }
        self.at = at;
    }

    /// Hand over everything held, polling every node's pending connects,
    /// until a round moves nothing. False if the nodes were still sending
    /// after 300 rounds.
    async fn heal(&mut self) -> bool {
        for _ in 0..300 {
            for tn in self.nodes.iter_mut() {
                tn.node.poll_pending_connects().await;
            }
            self.collect();
            let mut handed = 0;
            for i in 0..self.nodes.len() {
                for p in std::mem::take(&mut self.held[i]) {
                    self.give(i, p).await;
                    handed += 1;
                }
            }
            if handed == 0 {
                return true;
            }
        }
        false
    }

    /// Where in node `to`'s hold its `nth` packet of class `kind` is.
    fn find(&mut self, to: usize, kind: Kind, nth: usize) -> Option<usize> {
        self.collect();
        self.held[to]
            .iter()
            .enumerate()
            .filter(|(_, p)| kind_of(p) == Some(kind))
            .nth(nth)
            .map(|(i, _)| i)
    }

    /// Record the handshake packets node `at` holds.
    fn holding(&mut self, at: usize) {
        self.collect();
        let held: Vec<String> = self.held[at]
            .iter()
            .filter(|p| kind_of(p).is_some())
            .map(|p| self.describe(at, p))
            .collect();
        self.note(format!(
            "node {at} holds {} handshake packets: {held:?}",
            held.len()
        ));
    }

    /// Hand node `to` its `nth` held packet of class `kind`, if it holds one.
    async fn deliver(&mut self, to: usize, kind: Kind, nth: usize) -> bool {
        let Some(i) = self.find(to, kind, nth) else {
            self.note(format!("node {to} holds no {kind:?} number {nth}"));
            return false;
        };
        let p = self.held[to]
            .remove(i)
            .expect("precondition: a found packet is held");
        self.give(to, p).await;
        self.flow().await;
        true
    }

    /// Lose node `to`'s `nth` held packet of class `kind`.
    async fn lose(&mut self, to: usize, kind: Kind, nth: usize) {
        let i = self
            .find(to, kind, nth)
            .expect("precondition: the packet to lose is held");
        let p = self.held[to]
            .remove(i)
            .expect("precondition: a found packet is held");
        self.note(format!("lost: {}", self.describe(to, &p)));
        self.flow().await;
    }

    /// Node `from` dials node `to` at its address on transport `t`.
    async fn dial(&mut self, from: usize, to: usize, t: usize) {
        let id = PeerIdentity::from_pubkey_full(self.nodes[to].node.identity().pubkey_full());
        let addr = self.ends[to][t].1.clone();
        let tid = self.ends[from][t].0;
        self.note(format!("node {from} dials node {to} on t{t}"));
        self.nodes[from]
            .node
            .initiate_connection(tid, addr, id)
            .await
            .expect("precondition: the dial starts");
        self.flow().await;
    }

    /// Node `at` starts a rekey, as the explorer's `World::rekey` does: its
    /// session aged past its rekey trigger, the peer's end past the floor
    /// below which a msg1 is a fresh dial, then its rekeys polled.
    async fn rekey(&mut self, at: usize) {
        let after = self.nodes[at].node.config().node.rekey.after_secs;
        let age = Duration::from_secs(after + crate::node::REKEY_JITTER_SECS as u64 + 1);
        let floor = fips_core::proto::rekey::DEPLOYED_SESSION_FLOOR + Duration::from_secs(5);
        let me = *self.nodes[at].node.node_addr();
        let other = 1 - at;
        let peer = *self.nodes[other].node.node_addr();
        self.nodes[at]
            .node
            .get_peer_mut(&peer)
            .expect("precondition: a held peer")
            .test_backdate_session_established(age);
        self.nodes[other]
            .node
            .get_peer_mut(&me)
            .expect("precondition: the peer holds the rekeyer")
            .test_backdate_session_established(floor);
        self.note(format!("node {at} starts its rekey"));
        let was = self.views();
        self.nodes[at].node.poll_link_rekeys().await;
        self.changes(was, "the rekey poll");
        assert!(
            self.nodes[at]
                .node
                .get_peer(&peer)
                .is_some_and(|p| p.rekey_in_progress()),
            "precondition: node {at} started a rekey"
        );
        self.flow().await;
    }

    /// The clock moves a second on and every node runs its receive-loop
    /// tick, then frames flow.
    async fn advance(&mut self) {
        crate::time::advance(Duration::from_secs(1));
        for i in 0..self.nodes.len() {
            let was = self.views();
            tick(&mut self.nodes[i].node).await;
            self.changes(was, &format!("node {i}'s tick"));
        }
        self.flow().await;
    }

    /// Whether the nodes hold each other on one session.
    fn agree(&self) -> bool {
        matches!(
            self.views(),
            [Some((ao, at, _)), Some((bo, bt, _))] if ao.is_some() && ao == bt && at == bo
        )
    }

    /// Whether node `at` has a dial in progress.
    fn dialing(&self, at: usize) -> bool {
        let node = &self.nodes[at].node;
        !dials(node).is_empty() || !node.peering.pending_connects.is_empty()
    }

    /// Whether node `at` waits for a connection a path machine asked for.
    fn opening(&self, at: usize) -> bool {
        let node = &self.nodes[at].node;
        node.peers
            .keys()
            .any(|p| !node.paths.connects(p).is_empty())
    }

    /// Whether node `from` holds node `to`.
    fn holds(&self, from: usize, to: usize) -> bool {
        self.nodes[from]
            .node
            .get_peer(self.nodes[to].node.node_addr())
            .is_some()
    }

    /// Record each node's peer, pending rekey session, live links and own
    /// audits.
    fn snapshot(&self, label: &str) {
        self.note(format!(
            "== checkpoint {label}: one session {}",
            self.agree()
        ));
        for i in 0..2 {
            let j = 1 - i;
            let node = &self.nodes[i].node;
            let peer_addr = *self.nodes[j].node.node_addr();
            match node.get_peer(&peer_addr) {
                Some(p) => {
                    self.note(format!(
                        "node {i} peer: ours {:?} theirs {:?} link {} on {:?} at {:?}; rekey in progress {} (ours {:?})",
                        p.our_index().map(|x| x.as_u32()),
                        p.their_index().map(|x| x.as_u32()),
                        p.link_id(),
                        p.transport_id(),
                        p.current_addr().map(|a| self.whose(p.transport_id().unwrap_or(TransportId::new(0)), a)),
                        p.rekey_in_progress(),
                        p.rekey_our_index().map(|x| x.as_u32()),
                    ));
                    if let Some(role) = p.pending_role() {
                        let pending = (p.pending_our_index(), p.pending_their_index());
                        self.note(format!(
                            "node {i} PENDING rekey session: role {role:?}, (ours, theirs) ({:?}, {:?}); peer can adopt: {}",
                            pending.0.map(|x| x.as_u32()),
                            pending.1.map(|x| x.as_u32()),
                            self.adoptable(j, i, pending)
                        ));
                    }
                }
                None => self.note(format!("node {i} holds no peer")),
            }
            if let Some((link, index)) = redial(node, &peer_addr) {
                self.note(format!(
                    "node {i} REDIAL pending: leg link {link}, index {}",
                    index.as_u32()
                ));
            }
            for (id, link) in node.links.iter() {
                let key = (link.transport_id(), link.remote_addr().clone());
                let here = match node.links.index().get(&key) {
                    Some(x) if x == id => "indexed at its pair".to_string(),
                    Some(x) => format!("NOT INDEXED: its pair names {x}"),
                    None => "NOT INDEXED: no entry at its pair".to_string(),
                };
                let far = self.far(i, link.transport_id(), link.remote_addr());
                self.note(format!(
                    "node {i} link {id}: {:?} {:?} to {} ({}); {here}; far end: {far}",
                    link.direction(),
                    link.state(),
                    self.whose(link.transport_id(), link.remote_addr()),
                    self.class(i, *id),
                ));
            }
            let index = catch_unwind(AssertUnwindSafe(|| {
                super::super::link_index_audit::audit(node, "checkpoint")
            }))
            .is_ok();
            #[cfg(debug_assertions)]
            let live = if catch_unwind(AssertUnwindSafe(|| {
                crate::node::settle::audit::live(node, "checkpoint")
            }))
            .is_ok()
            {
                "passes"
            } else {
                "FAILS"
            };
            // The live audit is compiled only with debug assertions.
            #[cfg(not(debug_assertions))]
            let live = "not in this build";
            self.note(format!(
                "node {i} own audits: link_index_audit {}, live audit {live}",
                if index { "passes" } else { "FAILS" },
            ));
        }
    }

    /// What link `id` is to node `i`: the held peering's, a pending redial
    /// leg's, a dial's, an inbound leg's, or none of these.
    fn class(&self, i: usize, id: LinkId) -> String {
        let node = &self.nodes[i].node;
        let peer_addr = *self.nodes[1 - i].node.node_addr();
        let mut out = Vec::new();
        if node.get_peer(&peer_addr).is_some_and(|p| p.link_id() == id) {
            out.push("the held peering's link");
        }
        if redial(node, &peer_addr).is_some_and(|(l, _)| l == id) {
            out.push("a pending redial leg's inbound link");
        }
        if dials(node).contains(&id) {
            out.push("a dial");
        }
        if answer(node, id) {
            out.push("an inbound leg");
        }
        if out.is_empty() {
            "none of: held, redial leg, dial, inbound leg".to_string()
        } else {
            out.join(", ")
        }
    }

    /// What the other node's index names at the pair `tid` and `remote`
    /// name of node `i`: the far end of a link of node `i`'s.
    fn far(&self, i: usize, tid: TransportId, remote: &TransportAddr) -> String {
        let j = 1 - i;
        if !self.ends[j].iter().any(|(t, a)| *t == tid && a == remote) {
            return "not the other node's address".to_string();
        }
        let Some(mine) = self.ends[i].iter().find(|(t, _)| *t == tid) else {
            return "no address of this node on that transport".to_string();
        };
        let key = (tid, mine.1.clone());
        match self.nodes[j].node.links.index().get(&key) {
            Some(x) => format!("node {j} indexes link {x} ({}) there", self.class(j, *x)),
            None => format!("node {j} has no index entry there"),
        }
    }

    /// Whether node `at` holds a pending, current or in-flight handshake
    /// that adopts `pending`, a pending session of its peer's, by the shell
    /// audit's `Unadoptable` rule.
    fn adoptable(
        &self,
        at: usize,
        peer: usize,
        pending: (Option<SessionIndex>, Option<SessionIndex>),
    ) -> bool {
        let Some(theirs) = self.nodes[at]
            .node
            .get_peer(self.nodes[peer].node.node_addr())
        else {
            return false;
        };
        let matches = |ours: Option<SessionIndex>, their: Option<SessionIndex>| {
            ours.is_some() && ours == pending.1 && their == pending.0
        };
        matches(theirs.pending_our_index(), theirs.pending_their_index())
            || matches(theirs.our_index(), theirs.their_index())
            || (theirs.rekey_in_progress()
                && theirs.rekey_our_index().is_some()
                && theirs.rekey_our_index() == pending.1)
    }

    /// The explorer's judgement at a leaf: whether the heal went quiet with
    /// the pair on one session, `settle::settled`, then the shell audit.
    async fn judge(&mut self, label: &str, healed: bool) -> Vec<String> {
        let mut out = Vec::new();
        if !healed {
            out.push("Quiet: the heal ended with the pair not on one session".to_string());
        }
        if let Err(e) = settled(&mut self.nodes, 0, 1).await {
            out.push(format!("Settled: {e}"));
        }
        for b in audit(&mut self.nodes).await {
            out.push(format!("{b:?}"));
        }
        self.note(format!("== JUDGED at {label}: {out:#?}"));
        out
    }
}

/// A view as the record prints it.
fn show_view(v: &View) -> String {
    match v {
        Some((o, t, l)) => format!(
            "(ours {:?}, theirs {:?}, link {l})",
            o.map(|x| x.as_u32()),
            t.map(|x| x.as_u32())
        ),
        None => "none".to_string(),
    }
}

/// One pass of `node`'s receive-loop timers, then its path machines when
/// any is armed.
async fn tick(node: &mut Node) {
    node.tick(false).await;
    if node.paths.armed() {
        node.path_tick().await;
    }
}

/// The links of `node`'s dials whose msg2 it waits for.
fn dials(node: &Node) -> Vec<LinkId> {
    node.pending_outbound().values().copied().collect()
}

/// Whether `node` holds an answer's leg on `link`.
fn answer(node: &Node, link: LinkId) -> bool {
    node.leg(link)
        .is_some_and(|leg| matches!(leg.kind(), crate::proto::settle::legs::Kind::Answer { .. }))
}

/// `node`'s pending redial of `peer`: its leg's link and index.
fn redial(node: &Node, peer: &NodeAddr) -> Option<(LinkId, SessionIndex)> {
    node.redials.of(peer).map(|r| (r.link, r.index))
}

/// Build start 9 in `order` with multipath set as `on` and run its
/// script, losing `a`'s dial msg1 to `b` when `lose`, on a rig named
/// `name`. Returns the rig and the nodes `a` and `b`.
async fn scripted(order: Order, on: bool, lose: bool, name: String) -> (Rig, usize, usize) {
    let mut rig = Rig::new(on, name).await;
    let (a, b) = match order {
        Order::Smaller => (0, 1),
        Order::Larger => (1, 0),
    };
    rig.note(format!(
        "node a (rekeys, dials first) is node {a}; node b is node {b}"
    ));
    // The build: settled on transport 0, then a's rekey and the crossed
    // dials on transport 1.
    rig.dial(a, b, 0).await;
    assert!(
        rig.deliver(b, Kind::Msg1, 0).await,
        "precondition: b reads a's dial"
    );
    assert!(
        rig.deliver(a, Kind::Msg2, 0).await,
        "precondition: a reads b's answer"
    );
    assert!(
        rig.heal().await,
        "precondition: the settled pair goes quiet"
    );
    assert!(rig.agree(), "precondition: the pair settled on transport 0");
    rig.snapshot("settled on t0");
    rig.rekey(a).await;
    rig.dial(a, b, 1).await;
    rig.dial(b, a, 1).await;
    rig.snapshot("built");
    // The script.
    rig.at = "script".to_string();
    rig.holding(b);
    rig.note("step 0: b reads its first msg1");
    assert!(rig.deliver(b, Kind::Msg1, 0).await, "precondition: step 0");
    rig.holding(b);
    if lose {
        rig.note("step 1: b's first msg1 is lost");
        rig.lose(b, Kind::Msg1, 0).await;
    } else {
        rig.note("step 1: b reads its first msg1");
        assert!(rig.deliver(b, Kind::Msg1, 0).await, "precondition: step 1");
    }
    rig.holding(a);
    rig.note("step 2: a reads its first msg1");
    rig.deliver(a, Kind::Msg1, 0).await;
    rig.holding(a);
    rig.note("step 3: a reads its first msg2");
    rig.deliver(a, Kind::Msg2, 0).await;
    rig.snapshot("script done");
    (rig, a, b)
}

/// Run start 9 in `order` with multipath set as `on`, losing `a`'s dial
/// msg1 to `b` when `lose`, and judge it where `judge` says. Returns what
/// the judgement found.
async fn run(order: Order, on: bool, lose: bool, judge: Judge) -> Vec<String> {
    let name = format!(
        "{order:?}, multipath {on}{}, judged at {judge:?}",
        if lose { ", dial msg1 lost" } else { "" }
    );
    let (mut rig, a, b) = scripted(order, on, lose, name).await;
    // The leaf: the explorer's heal, then on to the end.
    let dialers = [(a, b, 0), (b, a, 1)];
    let mut agreed: Option<u64> = None;
    let mut leaf: Option<u64> = None;
    let mut found = Vec::new();
    for second in 0..=LEAF_END {
        rig.at = format!("+{second}s");
        let quiet = rig.heal().await;
        let all = rig.agree();
        if leaf.is_none() {
            let mut ended: Option<bool> = None;
            if !quiet {
                ended = Some(false);
            }
            match (agreed, all) {
                (None, true) => agreed = Some(second),
                (Some(_), false) => ended = Some(false),
                (None, false) if second >= LEAF_SECS => ended = Some(false),
                _ => {}
            }
            if ended.is_none()
                && let Some(at) = agreed
            {
                let busy = (0..2).any(|i| rig.dialing(i) || rig.opening(i));
                if !busy {
                    ended = Some(true);
                } else if second >= at + DIAL_SECS {
                    ended = Some(false);
                }
            }
            if let Some(healed) = ended {
                leaf = Some(second);
                rig.snapshot(&format!("explorer's leaf at +{second}s (healed {healed})"));
                if judge == Judge::Leaf {
                    found = rig.judge("the explorer's leaf", healed).await;
                    break;
                }
            }
        }
        if [LEAF_SECS, DIAL_SECS, LEAF_END].contains(&second) {
            rig.snapshot(&format!("+{second}s"));
            if judge == Judge::At(second) {
                found = rig.judge(&format!("+{second}s"), all).await;
                break;
            }
        }
        // Redials: before the leaf, as the explorer's heal makes them, only
        // while the pair disagrees; after it, whenever a dialer holds
        // neither its peer nor a dial.
        if leaf.is_some() || agreed.is_none() {
            for &(from, to, t) in &dialers {
                if !rig.holds(from, to) && !rig.dialing(from) {
                    rig.note(format!("REDIAL by node {from}"));
                    rig.dial(from, to, t).await;
                }
            }
        }
        rig.advance().await;
    }
    cleanup_nodes(&mut rig.nodes).await;
    found
}

/// Run start 9 in `order` at `on`, three times: judged at the explorer's
/// leaf, at 31 s and at 60 s. Asserts, marked `defect:`, that the pair is
/// coherent at each.
async fn three(order: Order, on: bool, lose: bool) {
    let leaf = run(order, on, lose, Judge::Leaf).await;
    let past = run(order, on, lose, Judge::At(DIAL_SECS)).await;
    let end = run(order, on, lose, Judge::At(LEAF_END)).await;
    println!(
        "SUMMARY {order:?} multipath {on} lose {lose}: at the explorer's leaf {leaf:?}; at +31s {past:?}; at +60s {end:?}"
    );
    assert!(
        leaf.is_empty() && past.is_empty() && end.is_empty(),
        "defect: a rekey crossed by dials on a second transport is not one coherent session at each checkpoint ({order:?}, multipath {on}, lose {lose}): at the explorer's leaf {leaf:#?}; at +31 s {past:#?}; at +60 s {end:#?}"
    );
}

/// The smaller node rekeys and dials first. The smaller node moves onto
/// its own dial on the second transport while it holds a pending redial
/// leg on an inbound link at the same pair, whose newer link names the
/// pair in the index until the leg is gone; a msg1 from the pair is still
/// judged on the held link, so the audit allows it.
#[tokio::test]
async fn a_rekey_crossed_by_dials_on_a_second_transport_ends_on_one_session() {
    three(Order::Smaller, false, false).await;
}

/// [`a_rekey_crossed_by_dials_on_a_second_transport_ends_on_one_session`] with multipath on.
#[tokio::test]
async fn a_rekey_crossed_by_dials_on_a_second_transport_ends_on_one_session_with_multipath_on() {
    three(Order::Smaller, true, false).await;
}

/// The larger node rekeys and dials first. Each node answers the other's
/// dial on the second transport as a redial and moves onto its own dial at
/// its msg2; at each leg's first frame the dial tie-break decides, so the
/// smaller node retires the larger's leg and the larger swaps onto the
/// smaller's dial. Fails today at the explorer's leaf, at 31 s and at 60 s:
/// the smaller node holds a responder pending of the larger's rekey that
/// the larger never adopts (`Unadoptable` at node 0).
#[tokio::test]
#[ignore = "known defect: crossed dials on a second transport during a rekey leave the smaller node holding a responder pending of the larger's rekey that the larger never adopts"]
async fn a_rekey_crossed_by_dials_on_a_second_transport_ends_on_one_session_larger_first() {
    three(Order::Larger, false, false).await;
}

/// [`a_rekey_crossed_by_dials_on_a_second_transport_ends_on_one_session_larger_first`] with
/// multipath on.
#[tokio::test]
#[ignore = "known defect: crossed dials on a second transport during a rekey leave the smaller node holding a responder pending of the larger's rekey that the larger never adopts"]
async fn a_rekey_crossed_by_dials_on_a_second_transport_ends_on_one_session_larger_first_with_multipath_on()
 {
    three(Order::Larger, true, false).await;
}

/// The larger node rekeys and dials first, and its dial's msg1 on the
/// second transport is lost. Fails today at the explorer's leaf, at 31 s
/// and at 60 s: once the larger node has promoted its redial leg and no
/// longer holds its own dial, the smaller node reads that dial's resent
/// msg1 at its held link's pair and answers it as a rekey, into a pending
/// responder session the larger node cannot adopt (`Unadoptable` at node 0).
#[tokio::test]
#[ignore = "known defect: after a redial swap during a rekey, a resent dial msg1 is answered as a rekey into a pending the peer cannot adopt"]
async fn a_rekey_crossed_by_dials_whose_dial_msg1_is_lost_leaves_nothing_unadoptable_larger_first()
{
    three(Order::Larger, false, true).await;
}

/// [`a_rekey_crossed_by_dials_whose_dial_msg1_is_lost_leaves_nothing_unadoptable_larger_first`]
/// with multipath on.
#[tokio::test]
#[ignore = "known defect: after a redial swap during a rekey, a resent dial msg1 is answered as a rekey into a pending the peer cannot adopt"]
async fn a_rekey_crossed_by_dials_whose_dial_msg1_is_lost_leaves_nothing_unadoptable_larger_first_with_multipath_on()
 {
    three(Order::Larger, true, true).await;
}

/// What a judgement in `found` shows of a split: a `Split`, or the two
/// findings a split leaves, the heal ending with the pair off one session
/// (`Quiet`) and the pair not settled (`Settled`).
fn split_of(found: &[String]) -> Vec<&String> {
    found
        .iter()
        .filter(|f| {
            ["Split", "Quiet", "Settled"]
                .iter()
                .any(|k| f.starts_with(k))
        })
        .collect()
}

/// Run start 9 in `order` at `on` as [`three`] does, judged at the
/// explorer's leaf, at 31 s and at 60 s, and assert, marked `defect:`,
/// that no judgement shows the pair split ([`split_of`]).
async fn unsplit(order: Order, on: bool) {
    let leaf = run(order, on, false, Judge::Leaf).await;
    let past = run(order, on, false, Judge::At(DIAL_SECS)).await;
    let end = run(order, on, false, Judge::At(LEAF_END)).await;
    println!(
        "SUMMARY {order:?} multipath {on}: at the explorer's leaf {leaf:?}; at +31s {past:?}; at +60s {end:?}"
    );
    let (leaf, past, end) = (split_of(&leaf), split_of(&past), split_of(&end));
    assert!(
        leaf.is_empty() && past.is_empty() && end.is_empty(),
        "defect: a rekey crossed by dials on a second transport leaves the pair split ({order:?}, multipath {on}): at the explorer's leaf {leaf:#?}; at +31 s {past:#?}; at +60 s {end:#?}"
    );
}

/// The larger node rekeys and dials first: each node answers the other's
/// dial on the second transport as a redial, then moves onto its own dial
/// at its msg2, and at each leg's first frame the dial tie-break decides
/// again, so the smaller node retires the larger's leg and the larger
/// swaps onto the smaller's dial. The pair is not split at any checkpoint.
/// The other half of [`a_rekey_crossed_by_dials_on_a_second_transport_ends_on_one_session_larger_first`],
/// the responder pending the smaller node is left holding, is not judged
/// here.
#[tokio::test]
async fn a_rekey_crossed_by_dials_on_a_second_transport_ends_without_a_split_larger_first() {
    unsplit(Order::Larger, false).await;
}

/// [`a_rekey_crossed_by_dials_on_a_second_transport_ends_without_a_split_larger_first`] with
/// multipath on.
#[tokio::test]
async fn a_rekey_crossed_by_dials_on_a_second_transport_ends_without_a_split_larger_first_with_multipath_on()
 {
    unsplit(Order::Larger, true).await;
}

/// The pair `node`'s link `id` is set up at, if `node` has the link.
fn pair_of(node: &Node, id: LinkId) -> Option<(TransportId, TransportAddr)> {
    node.links
        .iter()
        .find(|(l, _)| **l == id)
        .map(|(_, link)| (link.transport_id(), link.remote_addr().clone()))
}

/// The smaller order's window, at the explorer's leaf at +1 s: node 0
/// holds node 1 on its own dial on the second transport, beside a pending
/// redial leg at the same pair. Node 1 starts a rekey, and its msg1
/// reaches node 0 at that pair. Asserts, marked `defect:`, that node 0
/// judges it on the held link and answers it as a rekey, a responder
/// pending for node 1, leaving the redial leg as it was.
async fn rekey_in_window(on: bool) {
    let name = format!("Smaller, multipath {on}, node 1's rekey in the window");
    let (mut rig, _, _) = scripted(Order::Smaller, on, false, name).await;
    rig.at = "+0s".to_string();
    assert!(
        rig.heal().await,
        "precondition: the script's heal goes quiet"
    );
    rig.advance().await;
    rig.at = "+1s".to_string();
    assert!(
        rig.heal().await,
        "precondition: the window's heal goes quiet"
    );
    rig.snapshot("the window");
    let one = *rig.nodes[1].node.node_addr();
    let node = &rig.nodes[0].node;
    let (Some((leg, _)), Some(held)) =
        (redial(node, &one), node.get_peer(&one).map(|p| p.link_id()))
    else {
        panic!("precondition: node 0 holds node 1 beside a pending redial leg");
    };
    let shared = pair_of(node, held);
    assert!(
        shared.is_some() && shared == pair_of(node, leg),
        "precondition: the leg is at the held link's pair"
    );
    rig.rekey(1).await;
    let i = rig
        .find(0, Kind::Msg1, 0)
        .expect("precondition: node 1's rekey msg1 is held for node 0");
    let source = (
        rig.held[0][i].transport_id,
        rig.held[0][i].remote_addr.clone(),
    );
    assert_eq!(
        Some(source),
        shared,
        "precondition: node 1's rekey msg1 comes from the shared pair"
    );
    let was = rig.nodes[0].node.stats().handshake.snapshot();
    assert!(rig.deliver(0, Kind::Msg1, 0).await);
    rig.snapshot("node 1's rekey msg1 handed to node 0");
    let node = &rig.nodes[0].node;
    let d = since(&node.stats().handshake.snapshot(), &was);
    let pending = node.get_peer(&one).and_then(|p| p.pending_role());
    let after = redial(node, &one).map(|(l, _)| l);
    rig.note(format!(
        "node 0's handshake counters moved by {d:?}; pending {pending:?}"
    ));
    cleanup_nodes(&mut rig.nodes).await;
    // Off the held link, the msg1 is a redial, held back by the pending
    // leg's slot, or refused as off the link; on it, the rekey machine
    // answers it, or refuses it for its own rekey in flight.
    let off = d.redial_held + d.redial_seen + d.redial_dampened + d.redials + d.off_link;
    let rekeyed = pending == Some(fips_core::proto::rekey::Role::Responder)
        || d.rekey_tiebreak + d.rekey_pending > 0;
    assert!(
        off == 0 && rekeyed,
        "defect: node 1's rekey msg1 at the pair a pending redial leg shares with the held link was not judged on the held link (multipath {on}): counters moved by {d:?}, pending {pending:?}"
    );
    assert_eq!(after, Some(leg), "the redial leg is left as it was");
}

/// [`rekey_in_window`] with multipath off.
#[tokio::test]
async fn a_rekey_msg1_at_the_pair_a_redial_leg_shares_with_the_held_link_is_answered_on_the_held_link()
 {
    rekey_in_window(false).await;
}

/// [`rekey_in_window`] with multipath on.
#[tokio::test]
async fn a_rekey_msg1_at_the_pair_a_redial_leg_shares_with_the_held_link_is_answered_on_the_held_link_with_multipath_on()
 {
    rekey_in_window(true).await;
}

/// The larger node, node 1, dials the smaller on transport 1 from an
/// address of its own beside its transport-1 address, as a peer with a
/// second source address does, so the smaller reads the larger's dial msg1
/// at a pair off the smaller's own transport-1 dial. Returns the dial's
/// link at node 1.
async fn dial_from_second_address(rig: &mut Rig) -> LinkId {
    let tid = TransportId::new(3);
    let addr = alias(&rig.ends[1][0].1, tid);
    let lo = LoopbackTransport::with_mtu(tid, addr.clone(), 1280, LOOPBACK_REGISTRY.clone());
    rig.nodes[1]
        .node
        .transports
        .insert(tid, TransportHandle::Loopback(lo));
    let id = PeerIdentity::from_pubkey_full(rig.nodes[0].node.identity().pubkey_full());
    let to = rig.ends[0][1].1.clone();
    rig.note("node 1 dials node 0 on t1 from its second address");
    let was = dials(&rig.nodes[1].node);
    rig.nodes[1]
        .node
        .initiate_connection(tid, to, id)
        .await
        .expect("precondition: the dial starts");
    rig.flow().await;
    dials(&rig.nodes[1].node)
        .into_iter()
        .find(|l| !was.contains(l))
        .expect("precondition: node 1's second dial is pending")
}

/// The other arrival order of crossed dials, on real nodes, with
/// multipath set as `on`. The larger node dialed the pair on transport 0.
/// Both dial again on transport 1, the larger from a second address. The
/// larger answers the smaller's dial as a redial; the smaller reads its
/// msg2 and moves onto its own dial; only then does it read the larger's
/// dial msg1, from the second address, off that dial, and answer it as a
/// redial; then the larger reads its msg2 and moves onto its own dial.
/// The smaller's frames are held from the larger until that move. Then
/// everything is handed over, and the pair is judged at each of the next
/// five seconds, from the first tick on: it must hold one session, the
/// smaller node's dial. Asserts, marked `defect:`, that the pair is not split.
async fn answered_after_the_move(on: bool) {
    let name = format!("redial answered after the move, multipath {on}");
    let mut rig = Rig::new(on, name).await;
    let small = *rig.nodes[0].node.node_addr();
    let large = *rig.nodes[1].node.node_addr();
    rig.dial(1, 0, 0).await;
    assert!(
        rig.deliver(0, Kind::Msg1, 0).await,
        "precondition: node 0 reads node 1's dial"
    );
    assert!(
        rig.deliver(1, Kind::Msg2, 0).await,
        "precondition: node 1 reads the answer"
    );
    assert!(
        rig.heal().await,
        "precondition: the settled pair goes quiet"
    );
    assert!(rig.agree(), "precondition: the pair settled on transport 0");
    rig.dial(0, 1, 1).await;
    let s_dial = dials(&rig.nodes[0].node)
        .into_iter()
        .next()
        .expect("precondition: node 0's dial is pending");
    let l_dial = dial_from_second_address(&mut rig).await;
    rig.snapshot("built");
    rig.at = "script".to_string();
    rig.note("step 0: node 1 reads node 0's dial msg1");
    assert!(rig.deliver(1, Kind::Msg1, 0).await, "precondition: step 0");
    assert!(
        redial(&rig.nodes[1].node, &small).is_some(),
        "precondition: node 1 answered node 0's dial as a redial"
    );
    rig.hold[1] = true;
    rig.note("step 1: node 0 reads its msg2");
    assert!(rig.deliver(0, Kind::Msg2, 0).await, "precondition: step 1");
    assert_eq!(
        rig.nodes[0].node.get_peer(&large).map(|p| p.link_id()),
        Some(s_dial),
        "precondition: node 0 moved onto its own dial"
    );
    rig.note("step 2: node 0 reads node 1's dial msg1, from the second address");
    assert!(rig.deliver(0, Kind::Msg1, 0).await, "precondition: step 2");
    let Some((s_leg, _)) = redial(&rig.nodes[0].node, &large) else {
        panic!("precondition: node 0 answered node 1's dial as a redial after its move");
    };
    assert_ne!(
        pair_of(&rig.nodes[0].node, s_leg),
        pair_of(&rig.nodes[0].node, s_dial),
        "precondition: the redial is off node 0's moved-onto dial"
    );
    rig.note("step 3: node 1 reads its msg2");
    assert!(rig.deliver(1, Kind::Msg2, 0).await, "precondition: step 3");
    assert_eq!(
        rig.nodes[1].node.get_peer(&small).map(|p| p.link_id()),
        Some(l_dial),
        "precondition: node 1 moved onto its own dial"
    );
    rig.hold[1] = false;
    rig.snapshot("script done");
    // The larger swaps onto the smaller's dial at the first frame its
    // leg reads, which the smaller sends at its first tick: judged from
    // the first second on.
    assert!(
        rig.heal().await,
        "precondition: the script's heal goes quiet"
    );
    let mut found = Vec::new();
    for second in 1..=5 {
        rig.advance().await;
        rig.at = format!("+{second}s");
        assert!(rig.heal().await, "precondition: the heal goes quiet");
        let on_small = rig.nodes[0].node.get_peer(&large).map(|p| p.link_id()) == Some(s_dial);
        if !(rig.agree() && on_small) {
            found.push(format!(
                "+{second}s: {}",
                rig.views().map(|v| show_view(&v)).join(" / ")
            ));
        }
    }
    rig.snapshot("judged");
    cleanup_nodes(&mut rig.nodes).await;
    assert!(
        found.is_empty(),
        "defect: crossed dials whose redial was answered after the smaller node's move leave the pair split (multipath {on}): {found:#?}"
    );
}

/// [`answered_after_the_move`] with multipath off.
#[tokio::test]
async fn crossed_dials_answered_after_the_smaller_nodes_move_end_on_the_smaller_nodes_dial() {
    answered_after_the_move(false).await;
}

/// [`answered_after_the_move`] with multipath on.
#[tokio::test]
async fn crossed_dials_answered_after_the_smaller_nodes_move_end_on_the_smaller_nodes_dial_with_multipath_on()
 {
    answered_after_the_move(true).await;
}
