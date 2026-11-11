//! The reference model beside a world: each node's view of each peer, fed
//! what the node is handed, and each peer change the node makes held
//! against the model's transition.
//!
//! [`Tap`] keeps one `Judge` of `fips-core`'s model
//! (`proto::settle::model`) per node and peer, and turns what the world
//! does into the model's history: a msg1 or a msg2 by the ephemeral key
//! that names its handshake, an established frame by the session index it
//! carries, the clock's advances, a node's own rekey, cutover and restart.
//! Each step of the model that changes the peer is held against what the
//! node did over the same packet or rekey poll: the model's transition is
//! mapped onto the node's (`node::settle::table::Transition`) by
//! [`mapped`], and each row of the peer's state, read before and after, is
//! held to that transition's cell (`table::check_decided`). Where the model
//! changes nothing, the node must not change which session or link it
//! holds the peer on. The model holds one path per link, so its roam at a
//! peer the node holds on more than one path is held as a change of
//! nothing: the node, whose roaming rule moves a link's one path only,
//! must keep the session and link, and the roam's cells are listed, not
//! held.
//!
//! What a cell says of a row is held where it can be seen ([`decide`]): a
//! row the cell keeps must read the same; a row the cell changes is held to
//! change where the peer was not held before, for a row read off the held
//! peer alone, or where the row of the record was made to differ from a
//! fresh one first; and a row whose cell turns on the script is held to
//! change where the model's own state says it must. Every other row is not
//! checked, and is counted.

use super::super::super::*;
use super::super::table::{Expect, Outcome, Seen, check_decided, dirty_record};
use super::world::Medium;
use crate::node::settle::exec::plan::{Effect, plan};
use crate::node::settle::table::{Cell, DataRow, Row, Transition, data_cell};
use crate::peer::ActivePeer;
use crate::proto::fmp::wire::{
    CommonPrefix, EncryptedHeader, Msg1Header, Msg2Header, PHASE_ESTABLISHED, PHASE_MSG1,
    PHASE_MSG2,
};
use crate::proto::rekey::Role;
use crate::proto::settle::output::Why;
use crate::transport::{LinkId, TransportId};
use fips_core::proto::path::PathRef;
use fips_core::proto::rekey::DEPLOYED_SESSION_FLOOR;
use fips_core::proto::settle::model::history::{
    Addr, Binding, Bytes, Epoch, Event, Hs, LinkId as Line, Ms, Node as Rank,
};
use fips_core::proto::settle::model::judge::{
    Class, Judge, LocalRule, Params, Step as Judged, Transition as Change,
};
use std::collections::HashMap;

/// Where every judge's clock starts, so a rekey's backdating of a session
/// can move the model's session and link back without passing zero.
const BASE: Ms = 3_600_000;

/// The first link number the model gives a node's own dial, apart from the
/// numbers it gives the links msg1s arrive on.
const DIALS: u32 = 1 << 16;

/// Why the model's roam's cells are not held against a peer the node held
/// on more than one path.
const SEVERAL: &str = "the model holds one path per link and roams it to the frame's pair, where the node, holding the peer on more than one path, accounts the frame to its path and moves none (the roaming rule moves a link's one path only)";

/// The event of the model's history that made a change, which decides the
/// node's transition it maps onto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    /// A msg1 the node was handed.
    Msg1,
    /// A msg2 the node was handed.
    Msg2,
    /// An established frame the node was handed.
    Frame,
    /// The node cut over to its own rekey's pending session.
    Cutover,
    /// The node no longer holds the peer, with no change of the model's
    /// before it.
    Lost,
}

/// One node and peer watched across one packet or rekey poll.
struct Watch {
    /// The peer's index in the world.
    peer: usize,
    /// Its node address.
    addr: NodeAddr,
    /// What the model's steps over the packet gave, each with its event.
    judged: Vec<(Judged, Cause)>,
    /// The peer's state before, read where a change was foreseen.
    before: Option<Seen>,
    /// The pairs a reading covers beside the peer's paths.
    also: Vec<PathRef>,
    /// Whether the node did not hold the peer before.
    absent: bool,
    /// Whether the node held the peer on more than one path before.
    several: bool,
    /// The rows of the record made to differ from a fresh one's before.
    dirtied: Vec<DataRow>,
    /// Which session and link the node held the peer on before.
    held: Option<(Option<u32>, Option<u32>, LinkId)>,
    /// The handshake whose session the model held before.
    session: Option<Hs>,
    /// The node's index on the model's pending session of its own rekey,
    /// which the node is at once its cutover.
    pending: Option<u32>,
}

/// The reference model beside a world, and what holding the world's nodes
/// against it found.
pub(super) struct Tap {
    /// Every node's address, by its index in the world.
    addrs: Vec<NodeAddr>,
    /// Whether the world's transport holds a connection per link.
    binding: Binding,
    /// One judge per node and peer: `judges[node][peer]`.
    judges: Vec<Vec<Judge>>,
    /// The model's clock.
    clock: Ms,
    /// Each node's run: the epoch its packets carry, counted from 0.
    runs: Vec<u32>,
    /// Each msg1 ephemeral key seen, by handshake number less one.
    keys: Vec<Vec<u8>>,
    /// Each msg1's exact bytes seen, by number less one.
    copies: Vec<Vec<u8>>,
    /// The run of the node that sent each msg1 and msg2, by its bytes.
    epochs: HashMap<Vec<u8>, u32>,
    /// The handshake whose session a node's session index names.
    index: HashMap<(usize, u32), u32>,
    /// A node's session index on the handshake it initiated.
    own: HashMap<(usize, u32), u32>,
    /// The handshakes that are a node's own rekey.
    rekeys: Vec<u32>,
    /// The node whose rekey the world is starting.
    rekeying: Option<usize>,
    /// Each address a node has seen, numbered.
    places: HashMap<(usize, String), u16>,
    /// The link each pair a msg1 arrived on is, as the model numbers it.
    lines: HashMap<(usize, u8, String), u32>,
    /// How many dials the model has numbered.
    dials: u32,
    /// Each change that did not do what the model's transition says.
    found: Vec<String>,
    /// How many of the model's changes were held against the node's.
    checked: usize,
    /// Each kind of change held, and how many times.
    kinds: Vec<(String, usize)>,
    /// How many rows were held to an outcome.
    held: usize,
    /// How many rows of a checked change were not.
    undecided: usize,
    /// Each change not checked, with why.
    passed: Vec<String>,
}

impl Tap {
    /// A model of every node and peer of a world on `medium`, its nodes at
    /// `addrs`, each node holding nothing.
    pub(super) fn new(medium: Medium, addrs: Vec<NodeAddr>) -> Tap {
        let params = Params {
            sessionage: DEPLOYED_SESSION_FLOOR.as_millis() as Ms,
            ..Params::default()
        };
        let n = addrs.len();
        let judges = (0..n)
            .map(|i| {
                (0..n)
                    .map(|j| {
                        let mut judge = Judge::new(Rank(i as u8), Rank(j as u8), params);
                        judge.now = BASE;
                        judge
                    })
                    .collect()
            })
            .collect();
        let binding = match medium {
            Medium::Loopback => Binding::Connectionless,
            _ => Binding::Connected,
        };
        Tap {
            addrs,
            binding,
            judges,
            clock: BASE,
            runs: vec![0; n],
            keys: Vec::new(),
            copies: Vec::new(),
            epochs: HashMap::new(),
            index: HashMap::new(),
            own: HashMap::new(),
            rekeys: Vec::new(),
            rekeying: None,
            places: HashMap::new(),
            lines: HashMap::new(),
            dials: 0,
            found: Vec::new(),
            checked: 0,
            kinds: Vec::new(),
            held: 0,
            undecided: 0,
            passed: Vec::new(),
        }
    }

    /// The clock moved `ms` on.
    pub(super) fn advance(&mut self, ms: u64) {
        self.clock += ms;
        for judge in self.judges.iter_mut().flatten() {
            judge.step(Event::Advance(ms));
        }
    }

    /// Node `at` restarted: a new run, which holds nothing.
    pub(super) fn restart(&mut self, at: usize) {
        self.runs[at] += 1;
        for judge in self.judges[at].iter_mut() {
            judge.step(Event::Restart);
            judge.now = self.clock;
        }
    }

    /// Node `at` is starting its rekey of every peer, its own end of each
    /// session aged by `age` and the peer's by `floor`, as the world ages
    /// the nodes' sessions and links.
    pub(super) fn rekey(&mut self, at: usize, age: Duration, floor: Duration) {
        for peer in 0..self.addrs.len() {
            if peer != at {
                backdate(&mut self.judges[at][peer], age);
                backdate(&mut self.judges[peer][at], floor);
            }
        }
        self.rekeying = Some(at);
    }

    /// The rekey the world was starting has started.
    pub(super) fn rekeyed(&mut self) {
        self.rekeying = None;
    }

    /// `packet` reached node `to`'s channel: the model learns the handshake
    /// a msg1 starts, and the session index each end of a handshake takes,
    /// and the sender's judge takes a new msg1 as its dial or rekey.
    pub(super) fn sent(
        &mut self,
        to: usize,
        packet: &ReceivedPacket,
        ends: &[Vec<(TransportId, TransportAddr)>],
    ) {
        let Some(from) = sender(ends, to, packet) else {
            return;
        };
        match CommonPrefix::parse(&packet.data).map(|p| p.phase) {
            Some(PHASE_MSG1) => {
                let Some(h) = Msg1Header::parse(&packet.data) else {
                    return;
                };
                let (hs, new) = number(&mut self.keys, ephemeral(&h, &packet.data));
                self.epochs
                    .entry(packet.data.clone())
                    .or_insert(self.runs[from]);
                let idx = h.sender_idx.as_u32();
                self.index.insert((from, idx), hs);
                self.own.insert((from, hs), idx);
                if !new {
                    return;
                }
                let event = if self.rekeying == Some(from) {
                    self.rekeys.push(hs);
                    Event::RekeyStart { hs: Hs(hs) }
                } else {
                    let t = transport(ends, to, packet);
                    self.dials += 1;
                    Event::Dial {
                        hs: Hs(hs),
                        link: Line(DIALS + self.dials),
                        to: self.place(from, t, &ends[to][t as usize].1),
                        binding: self.binding,
                    }
                };
                // A dial or a rekey's start changes no peer.
                self.judges[from][to].step(event);
            }
            Some(PHASE_MSG2) => {
                let Some(h) = Msg2Header::parse(&packet.data) else {
                    return;
                };
                if let Some(&hs) = self.index.get(&(to, h.receiver_idx.as_u32())) {
                    self.index.insert((from, h.sender_idx.as_u32()), hs);
                    self.epochs
                        .entry(packet.data.clone())
                        .or_insert(self.runs[from]);
                }
            }
            _ => {}
        }
    }

    /// Hand `packet` to node `at`, which is `node`, and hold what the node
    /// does with it against what the model's history makes of it.
    pub(super) async fn give(
        &mut self,
        at: usize,
        node: &mut Node,
        packet: ReceivedPacket,
        ends: &[Vec<(TransportId, TransportAddr)>],
    ) {
        let Some(peer) = sender(ends, at, &packet) else {
            node.process_packet(packet).await;
            return;
        };
        let event = self.event(at, peer, node, &packet, ends);
        let pair = PathRef {
            transport: packet.transport_id,
            addr: packet.remote_addr.clone(),
        };
        let watch = self.prepare(at, peer, node, event, Some(pair)).await;
        node.process_packet(packet).await;
        self.conclude(at, node, watch).await;
    }

    /// Run node `at`'s rekey poll, which is `node`'s, and hold what it does
    /// to each peer against the model: an initiator's cutover is made here.
    pub(super) async fn poll(&mut self, at: usize, node: &mut Node) {
        let mut watches = Vec::new();
        for peer in 0..self.addrs.len() {
            if peer != at {
                watches.push(self.prepare(at, peer, node, None, None).await);
            }
        }
        node.poll_link_rekeys().await;
        for watch in watches {
            self.conclude(at, node, watch).await;
        }
    }

    /// The model's event for `packet`, handed to node `at` from `peer`:
    /// `None` for a packet of no handshake the model knows, or a frame the
    /// node holds no session for.
    fn event(
        &mut self,
        at: usize,
        peer: usize,
        node: &Node,
        packet: &ReceivedPacket,
        ends: &[Vec<(TransportId, TransportAddr)>],
    ) -> Option<(Event, Cause)> {
        let t = transport(ends, at, packet);
        let from = self.place(at, t, &packet.remote_addr);
        let epoch = Epoch(self.epochs.get(&packet.data).copied().unwrap_or(0));
        match CommonPrefix::parse(&packet.data).map(|p| p.phase)? {
            PHASE_MSG1 => {
                let h = Msg1Header::parse(&packet.data)?;
                let (hs, _) = number(&mut self.keys, ephemeral(&h, &packet.data));
                let (bytes, _) = number(&mut self.copies, &packet.data);
                let key = (at, t, packet.remote_addr.to_string());
                let next = self.lines.len() as u32 + 1;
                let link = Line(*self.lines.entry(key).or_insert(next));
                let event = Event::Msg1 {
                    hs: Hs(hs),
                    bytes: Bytes(bytes),
                    epoch,
                    link,
                    from,
                    binding: self.binding,
                    sent: true,
                };
                Some((event, Cause::Msg1))
            }
            PHASE_MSG2 => {
                let h = Msg2Header::parse(&packet.data)?;
                let hs = *self.index.get(&(at, h.receiver_idx.as_u32()))?;
                let event = if self.rekeys.contains(&hs) {
                    Event::RekeyMsg2 { hs: Hs(hs), epoch }
                } else {
                    Event::Msg2 {
                        hs: Hs(hs),
                        epoch,
                        from,
                    }
                };
                Some((event, Cause::Msg2))
            }
            PHASE_ESTABLISHED => {
                let h = EncryptedHeader::parse(&packet.data)?;
                let idx = h.receiver_idx.as_u32();
                let hs = *self.index.get(&(at, idx))?;
                let held = node.get_peer(&self.addrs[peer])?;
                let ours = [
                    held.our_index(),
                    held.pending_our_index(),
                    held.previous_our_index(),
                ];
                ours.iter()
                    .flatten()
                    .any(|i| i.as_u32() == idx)
                    .then_some((Event::Frame { hs: Hs(hs), from }, Cause::Frame))
            }
            _ => None,
        }
    }

    /// Before node `at` acts on `event` from `peer`: the model takes the
    /// event, and where the model changes the peer, or the node's own rekey
    /// may cut over, the rows of the record that change are made to differ
    /// from a fresh one's and the peer's state is read.
    async fn prepare(
        &mut self,
        at: usize,
        peer: usize,
        node: &mut Node,
        event: Option<(Event, Cause)>,
        pair: Option<PathRef>,
    ) -> Watch {
        let addr = self.addrs[peer];
        let judge = &mut self.judges[at][peer];
        let session = judge.settled().map(|s| s.0);
        let pending = judge
            .peering
            .as_ref()
            .and_then(|p| p.pending)
            .filter(|p| p.initiator)
            .and_then(|p| self.own.get(&(at, p.hs.0)).copied());
        let judged: Vec<(Judged, Cause)> = event
            .map(|(e, cause)| (judge.step(e), cause))
            .into_iter()
            .collect();
        let foreseen = judged.iter().find_map(|(s, cause)| {
            s.change
                .and_then(|change| mapped(change, *cause, s, LinkId::new(0)).ok())
        });
        let absent = node.get_peer(&addr).is_none();
        let mut dirtied = Vec::new();
        let mut due: Vec<Transition> = foreseen.into_iter().collect();
        if pending.is_some() {
            due.push(Transition::Cutover {
                role: Role::Initiator,
            });
        }
        if let Some(p) = node.get_peer_mut(&addr) {
            for t in &due {
                for row in DataRow::ALL {
                    let changes = Expect::Changed
                        == super::super::table::expect(Cell::Data(data_cell(*row, t)));
                    if changes && !dirtied.contains(row) {
                        dirty(p, *row);
                        dirtied.push(*row);
                    }
                }
            }
        }
        let also = pairs(node, pair);
        let before = if due.is_empty() {
            None
        } else {
            Some(Seen::of(node, &addr, &also).await)
        };
        Watch {
            peer,
            addr,
            judged,
            before,
            also,
            absent,
            several: node.get_peer(&addr).is_some_and(|p| p.paths().len() > 1),
            dirtied,
            held: identity(node.get_peer(&addr)),
            session,
            pending,
        }
    }

    /// After node `at` acted: the model learns of a cutover or a loss the
    /// node made, and each change of the model's is held against the node.
    async fn conclude(&mut self, at: usize, node: &Node, mut w: Watch) {
        let held = node.get_peer(&w.addr);
        let judge = &mut self.judges[at][w.peer];
        if let (Some(idx), Some(p)) = (w.pending, held)
            && p.our_index().map(|i| i.as_u32()) == Some(idx)
        {
            w.judged
                .push((judge.step(Event::RekeyCutover), Cause::Cutover));
        }
        if !w.absent && held.is_none() && w.judged.iter().all(|(s, _)| s.change.is_none()) {
            w.judged.push((judge.step(Event::Lost), Cause::Lost));
        }
        let session = judge.settled().map(|s| s.0) != w.session;
        let changes: Vec<(Judged, Cause)> = w
            .judged
            .iter()
            .filter(|(s, _)| s.change.is_some())
            .cloned()
            .collect();
        let peer = w.peer;
        match changes.as_slice() {
            [] => {
                let now = identity(held);
                if now != w.held {
                    self.found.push(format!(
                        "node {at} changed peer {peer} from {:?} to {now:?} where the model changed nothing: {:?}",
                        w.held, w.judged
                    ));
                }
            }
            [(step, cause)] => {
                let change = step.change.expect("filtered on a change");
                if change == Change::Roam && w.several {
                    let now = identity(held);
                    if now != w.held {
                        self.found.push(format!(
                            "node {at} changed peer {peer} from {:?} to {now:?} at the model's {change:?} at a {cause:?}, holding it on more than one path",
                            w.held
                        ));
                    }
                    self.passed.push(format!(
                        "node {at} peer {peer}: the model's {change:?} at a {cause:?}: {SEVERAL}"
                    ));
                    return;
                }
                let link = held.map(ActivePeer::link_id).unwrap_or(LinkId::new(0));
                let t = match mapped(change, *cause, step, link) {
                    Ok(t) => t,
                    Err(why) => {
                        self.passed.push(format!(
                            "node {at} peer {peer}: the model's {change:?} at a {cause:?}: {why}"
                        ));
                        return;
                    }
                };
                let Some(before) = w.before.take() else {
                    self.passed.push(format!(
                        "node {at} peer {peer}: the model's {change:?} at a {cause:?} was not foreseen, so the peer was not read before it"
                    ));
                    return;
                };
                let after = Seen::of(node, &w.addr, &w.also).await;
                let seen = Sight {
                    absent: w.absent,
                    dirtied: &w.dirtied,
                    session,
                    announces: plan(&t).contains(&Effect::TreeAnnounce),
                };
                let decided = check_decided(&before, &after, &t, |row, _, e| seen.decide(row, e));
                self.checked += 1;
                let kind = format!("{change:?} at a {cause:?}");
                match self.kinds.iter_mut().find(|(k, _)| *k == kind) {
                    Some((_, n)) => *n += 1,
                    None => self.kinds.push((kind, 1)),
                }
                self.held += decided.held;
                self.undecided += decided.undecided.len();
                for b in decided.breaches {
                    self.found.push(format!(
                        "node {at} peer {peer}, the model's {change:?} at a {cause:?} ({:?}): {b}",
                        step.rule
                    ));
                }
            }
            many => self.passed.push(format!(
                "node {at} peer {peer}: more than one change of the model's in one step, not checked: {many:?}"
            )),
        }
    }

    /// What holding the world against the model found on the path named
    /// `name`: each change that did not do what the model's transition
    /// says, or a finding that no change was checked at all.
    pub(super) fn verdict(&self, name: &str) -> Vec<String> {
        eprintln!(
            "{name}: {} changes checked {:?}, {} rows held, {} rows not decided; not checked: {:#?}",
            self.checked, self.kinds, self.held, self.undecided, self.passed
        );
        let mut out: Vec<String> = self.found.iter().map(|f| format!("{name}: {f}")).collect();
        if self.checked == 0 {
            out.push(format!("{name}: no peer change was held against the model"));
        }
        out
    }

    /// Address `addr` as node `at` saw it on its transport `t`, numbered.
    fn place(&mut self, at: usize, t: u8, addr: &TransportAddr) -> Addr {
        let next = self.places.len() as u16 + 1;
        let n = *self.places.entry((at, addr.to_string())).or_insert(next);
        Addr {
            transport: t,
            at: n,
        }
    }
}

/// The node's transition a change of the model's maps onto, at the event
/// that made it, the peer held on `link` after it; or why none does. The
/// fields the node's cells read are taken from the model's step: who
/// initiated, why a replacement, and whether a move answered this node's
/// own dial.
fn mapped(
    change: Change,
    cause: Cause,
    step: &Judged,
    link: LinkId,
) -> Result<Transition, &'static str> {
    match change {
        Change::Promote => Ok(Transition::Promote {
            link,
            initiator: cause == Cause::Msg2,
        }),
        Change::Replace => match (cause, step.class) {
            (Cause::Msg2, _) => Ok(Transition::Replace {
                link,
                initiator: true,
                why: Why::OwnRestart,
            }),
            (Cause::Msg1, Some(Class::Restart)) => Ok(Transition::Replace {
                link,
                initiator: false,
                why: Why::Restart,
            }),
            (Cause::Msg1, Some(Class::Replacement)) => Ok(Transition::Replace {
                link,
                initiator: false,
                why: Why::Replacement,
            }),
            _ => Err("a replacement the model makes at no msg1 or msg2"),
        },
        Change::Move if cause == Cause::Msg2 => Ok(Transition::Move {
            dial: link,
            own: step.rule == Some(LocalRule::LateSecondDial),
            built: true,
        }),
        Change::Move => Err(
            "the model's return, at the peer's first frame, to the session a later dial moved off (its late second dial rule), which the node does not make",
        ),
        Change::Keep => Ok(Transition::Keep { dial: link }),
        Change::RekeyCutover => Ok(Transition::Cutover {
            role: if cause == Cause::Cutover {
                Role::Initiator
            } else {
                Role::Responder
            },
        }),
        Change::Restarted => Err(
            "a restart found at a rekey is a cutover and the restart in one step, which the table's own test holds against both cells",
        ),
        Change::Roam => Ok(Transition::Roam),
        Change::Remove => Ok(Transition::Remove { why: Why::Dead }),
    }
}

/// What the readings across one change can show.
struct Sight<'a> {
    /// The node did not hold the peer before.
    absent: bool,
    /// The rows of the record made to differ from a fresh one's before.
    dirtied: &'a [DataRow],
    /// The model's session for the peer changed.
    session: bool,
    /// The node's transition sends the peer a tree announce.
    announces: bool,
}

impl Sight<'_> {
    /// The outcome `row` is held to across the change, from what its cell
    /// says, `expect`, or `None` where the change cannot be seen in the
    /// reading.
    fn decide(&self, row: Row, expect: Expect) -> Option<Outcome> {
        let Sight {
            absent,
            dirtied,
            session,
            announces,
        } = *self;
        // A tree announce's send writes the record's announce stamp and
        // pending mark, as any send does, and that is not the transition's
        // cell; the crossing cells tests hold the announce for it, which
        // here would change what the start does.
        if announces && matches!(row, Row::Data(DataRow::TreePending | DataRow::TreeStamp)) {
            return None;
        }
        // A row read off the held peer alone reads nothing before a peer is
        // held, and so changes as one is.
        let alone = matches!(
            row,
            Row::Link
                | Row::Paths
                | Row::Capability
                | Row::Pin
                | Row::PathFailures
                | Row::ConnectedUdp
                | Row::RekeyMachine
                | Row::Identity
        );
        match expect {
            Expect::NoSite => None,
            Expect::Kept => Some(Outcome::Kept),
            Expect::Changed => {
                let seen = match row {
                    Row::Data(d) => absent || dirtied.contains(&d),
                    _ => absent && alone,
                };
                seen.then_some(Outcome::Changed)
            }
            // The model decides the cells that turn on the script where its
            // own state does: a peer held anew, and the peer's session,
            // which its rekey machine's indices follow.
            Expect::Stated => {
                (absent && alone || row == Row::RekeyMachine && session).then_some(Outcome::Changed)
            }
        }
    }
}

/// Make `row` of `p`'s record differ from a fresh one's, as the table's
/// harness does. The spin bit is set, not flipped, as its rekey tests set
/// it (`table::rekey::set_spin`), since a reset clears it; and the replay
/// base is put below the total, as the harness's whole-record dirtying
/// leaves it, since a move of the base up to the total shows only then.
fn dirty(p: &mut ActivePeer, row: DataRow) {
    if row == DataRow::ReplayBase {
        dirty_record(p, DataRow::ReplayBase);
        dirty_record(p, DataRow::ReplayTotal);
        return;
    }
    if row != DataRow::Spin {
        dirty_record(p, row);
        return;
    }
    if let Some(m) = p.mmp_mut()
        && !m.spin_bit.tx_bit()
    {
        let bit = m.spin_bit.tx_bit();
        let seen = if m.spin_bit.is_initiator() { bit } else { !bit };
        m.spin_bit.rx_observe(seen, 1 << 41, crate::time::mono_ms());
    }
}

/// Move a judge's session and link back by `age`, as the world backdates a
/// node's end of a session, which moves its link's age with it.
fn backdate(judge: &mut Judge, age: Duration) {
    if let Some(p) = judge.peering.as_mut() {
        p.sessionborn = p.sessionborn.saturating_sub(age.as_millis() as Ms);
        p.linkborn = p.linkborn.min(p.sessionborn);
    }
}

/// Which session and link the node holds a peer on.
fn identity(held: Option<&ActivePeer>) -> Option<(Option<u32>, Option<u32>, LinkId)> {
    held.map(|p| {
        (
            p.our_index().map(|i| i.as_u32()),
            p.their_index().map(|i| i.as_u32()),
            p.link_id(),
        )
    })
}

/// Every pair a link of `node` is at, and `pair`, each once: the pairs a
/// reading covers, so that the readings before and after a change cover
/// the same ones.
fn pairs(node: &Node, pair: Option<PathRef>) -> Vec<PathRef> {
    let mut out: Vec<PathRef> = Vec::new();
    let links = node.links.values().map(|l| PathRef {
        transport: l.transport_id(),
        addr: l.remote_addr().clone(),
    });
    for to in links.chain(pair) {
        if !out.contains(&to) {
            out.push(to);
        }
    }
    out
}

/// The node `packet`, handed to node `to`, came from: the node whose
/// address it carries, or in a world of two, the other node, whose
/// connection's source port is not its address.
fn sender(
    ends: &[Vec<(TransportId, TransportAddr)>],
    to: usize,
    packet: &ReceivedPacket,
) -> Option<usize> {
    (0..ends.len())
        .find(|&j| j != to && ends[j].iter().any(|(_, a)| *a == packet.remote_addr))
        .or_else(|| (ends.len() == 2).then_some(1 - to))
}

/// The index of the transport of node `at` that `packet` arrived on.
fn transport(ends: &[Vec<(TransportId, TransportAddr)>], at: usize, packet: &ReceivedPacket) -> u8 {
    ends[at]
        .iter()
        .position(|(t, _)| *t == packet.transport_id)
        .unwrap_or(0) as u8
}

/// The ephemeral key a msg1 carries in the clear, which names its
/// handshake at both ends: the first 33 bytes of its Noise message.
fn ephemeral<'a>(h: &Msg1Header, data: &'a [u8]) -> &'a [u8] {
    let noise = &data[h.noise_msg1_offset..];
    &noise[..noise.len().min(33)]
}

/// The number `seen` gives `value`, counted from 1, adding it if it is new,
/// and whether it was.
fn number(seen: &mut Vec<Vec<u8>>, value: &[u8]) -> (u32, bool) {
    match seen.iter().position(|v| v == value) {
        Some(i) => (i as u32 + 1, false),
        None => {
            seen.push(value.to_vec());
            (seen.len() as u32, true)
        }
    }
}
