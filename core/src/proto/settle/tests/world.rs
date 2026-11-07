//! A deterministic world of two or three nodes and their transports.
//!
//! The world holds what lies between the nodes: the transports and their
//! connections, the packets in flight, a monotonic clock and a wall clock.
//! Each node is a [`Party`] that the world hands inputs to; a party acts on
//! the world through [`Net`], which sends, connects and closes. Nothing
//! here reads a real clock, a socket or a random source, so one sequence
//! of events always builds the same world.
//!
//! Three transport models, as the settlement plan states them:
//!
//! - [`Kind::Datagram`]: connectionless. A packet from a node's address
//!   reaches whichever node owns the address it was sent to, and the
//!   receiver sees the sender's address as its source.
//! - [`Kind::Stream`]: connection-oriented. A send to a listening address
//!   opens a connection, which stays connecting until the explorer resolves
//!   it; what is sent meanwhile waits. The acceptor sees the dialer at an
//!   ephemeral address of its own, and replies on the arrival connection.
//!   A close sends an end-of-stream to the far end, behind the data already
//!   in flight, and each connection delivers in order.
//! - [`Kind::Ble`]: one connection per pair of addresses, which every dial
//!   between that pair shares, and a verified mark the parties set.
//!
//! Frames are opened by stub crypto: a frame reaches its receiver only
//! when the receiver holds the session it was sealed under.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

use super::super::model::history::{Addr, Bytes, Epoch, Hs, Node};
use super::shadow::Entry;

/// Milliseconds on the world's monotonic clock.
pub type Ms = u64;

/// The node's link heartbeat interval (`heartbeat_interval_secs`, 10 s,
/// `src/config/node.rs:1698`).
pub const HEARTBEAT: Ms = 10_000;
/// The first handshake resend interval (`handshake_resend_interval_ms`,
/// 1000 ms, `src/config/node.rs:148`), doubled per resend (`:149`).
pub const RESEND: Ms = 1_000;
/// Resends per handshake attempt (`handshake_max_resends`, 5, `:150`).
pub const RESENDS: u32 = 5;
/// The handshake timeout (`handshake_timeout_secs`, 30 s, `:147`).
pub const HANDSHAKE: Ms = 30_000;
/// The reconnect interval (`retry.base_interval_secs`, 5 s, `:204`).
pub const RETRY: Ms = 5_000;
/// The rekey machine's check interval: an IK initiator cuts over at the
/// next poll after its reply (`InitiatorCutover::OnProof`,
/// `rekey/profile.rs:41-44`; `Config::fmp().check`, 1 s).
pub const CHECK: Ms = 1_000;
/// How far one wall step moves the wall clock ahead of the monotonic one.
pub const WALL_STEP: i64 = 60_000;
/// Where the acceptor's ephemeral addresses for stream connections start.
pub const EPHEMERAL: u16 = 1_000;

/// A transport's model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Connectionless.
    Datagram,
    /// Connection-oriented, a connection per dial.
    Stream,
    /// One connection per address pair, with a verified mark.
    Ble,
}

/// A packet's content, abstract: a handshake is named by its msg1's
/// ephemeral, as the model names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pkt {
    /// A msg1 from identity `id`.
    Msg1 {
        /// The sender's identity.
        id: Node,
        /// The handshake.
        hs: Hs,
        /// Its exact bytes.
        bytes: Bytes,
        /// The sender's epoch.
        epoch: Epoch,
    },
    /// A msg2 answering handshake `hs`.
    Msg2 {
        /// The sender's identity.
        id: Node,
        /// The handshake answered.
        hs: Hs,
        /// The sender's epoch.
        epoch: Epoch,
    },
    /// A frame sealed under the session of handshake `hs`.
    Frame {
        /// The sender's identity.
        id: Node,
        /// The session's handshake.
        hs: Hs,
    },
    /// The far end closed the connection.
    Eof,
}

impl Pkt {
    /// Whether this is a handshake message.
    pub fn handshake(&self) -> bool {
        matches!(self, Self::Msg1 { .. } | Self::Msg2 { .. })
    }
}

/// A connection's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Inside its connect window.
    Connecting,
    /// Open.
    Open,
    /// Closed by the end with this index.
    Closed(usize),
}

/// One end of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct End {
    /// The node.
    pub node: usize,
    /// Its own address.
    pub local: Addr,
    /// The far end's address as this end sees it.
    pub remote: Addr,
}

/// A connection; end 0 dialed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conn {
    /// Its number.
    pub id: u32,
    /// Its transport's model.
    pub kind: Kind,
    /// The dialer and the acceptor.
    pub ends: [End; 2],
    /// Its state.
    pub state: State,
    /// What each end sent inside the connect window, by end.
    pub queued: Vec<(usize, Pkt)>,
    /// The BLE verified mark, per end.
    pub verified: [bool; 2],
}

/// A packet in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flight {
    /// Its number, unique in one world.
    pub id: u64,
    /// The receiving node.
    pub to: usize,
    /// The receiver's address it arrives at.
    pub local: Addr,
    /// Its source as the receiver sees it.
    pub src: Addr,
    /// The connection it travels on, if any.
    pub conn: Option<u32>,
    /// The content.
    pub pkt: Pkt,
    /// A copy the explorer made.
    pub copy: bool,
}

/// A path event of a link's bundle, as stage A reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathEv {
    /// The link's path at `from` moved to `to`.
    Moved {
        /// The peer whose link it is.
        peer: Node,
        /// The pair before.
        from: Addr,
        /// The pair after.
        to: Addr,
    },
    /// The link's active path switched from `from` to `to`.
    Switched {
        /// The peer.
        peer: Node,
        /// The old active pair.
        from: Addr,
        /// The new active pair.
        to: Addr,
    },
    /// The link's path at `at` was released.
    Released {
        /// The peer.
        peer: Node,
        /// The pair.
        at: Addr,
        /// The peer may still send there.
        keep: bool,
    },
    /// The link's path at `at` became live (proven) or probing.
    State {
        /// The peer.
        peer: Node,
        /// The pair.
        at: Addr,
        /// Live or acked.
        live: bool,
    },
}

/// One input to a party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// A packet arrived. Frames arrive only once the stub crypto opened
    /// them.
    Packet {
        /// Its source as this node sees it.
        src: Addr,
        /// The address it arrived at.
        local: Addr,
        /// Its connection.
        conn: Option<u32>,
        /// The content.
        pkt: Pkt,
        /// The wall clock at arrival, as a packet stamp carries it.
        stamp: i64,
    },
    /// The connection this node sees at `at` closed.
    Closed {
        /// Its remote address.
        at: Addr,
    },
    /// A connect to `to` failed.
    ConnectFailed {
        /// The address dialed.
        to: Addr,
    },
    /// The clock reached the party's wake.
    Wake,
    /// The node's process restarts and forgets everything.
    Restart,
    /// Dial `peer` at `to`, from the local address `from`.
    Dial {
        /// The peer.
        peer: Node,
        /// The address dialed.
        to: Addr,
        /// The local address to send from.
        from: Option<Addr>,
    },
    /// Start an own rekey of `peer`.
    Rekey {
        /// The peer.
        peer: Node,
    },
    /// Send one frame to every peer held, now.
    Beat,
    /// A path event of a link's bundle.
    Path(PathEv),
}

/// A link's direction, as its record names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Set up by the peer's msg1.
    Inbound,
    /// Set up by this node's own dial.
    Outbound,
}

/// One held peer, as the oracles read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerView {
    /// The peer identity.
    pub peer: Node,
    /// The handshake whose session is current.
    pub cur: Hs,
    /// The initial handshake that session descends from: the one the peer
    /// was installed or moved onto; a rekey keeps it.
    pub origin: Hs,
    /// The handshake the peer's link record was set up by.
    pub link: Hs,
    /// The link record's direction.
    pub dir: Dir,
    /// The link record's address.
    pub at: Addr,
    /// The peer's current address.
    pub current: Addr,
    /// One of this node's own dials of the peer was answered while it was
    /// held, or installed it.
    pub answered: bool,
    /// The pending session, and whether this node started it.
    pub pending: Option<(Hs, bool)>,
    /// This node's own rekey in flight, unanswered.
    pub rekey: Option<Hs>,
    /// This node's own initial dials of the peer in flight.
    pub dials: Vec<Hs>,
}

/// The rekey msg1s a party sent, for the shape that names a peer's own
/// rekey msg1: the model and the model of `master` name the rekey in
/// flight; the core names every rekey it sent in this life, since a
/// replacement ends its rekey side and the msg1 is still the peer's rekey.
pub type Rekeys = Vec<(Node, Hs)>;

/// A party's state, as the oracles read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    /// The node's identity.
    pub me: Node,
    /// The peers it holds.
    pub peers: Vec<PeerView>,
    /// Every address whose connection a live link of this node still
    /// uses.
    pub needs: Vec<Addr>,
    /// Incoherences between the party's own maps.
    pub audit: Vec<String>,
    /// Sizes the party keeps bounded: name, size, bound.
    pub bounds: Vec<(&'static str, usize, usize)>,
    /// The party's history log, for its shadow; empty for the model.
    pub log: Vec<Entry>,
    /// The peers it redials whenever it holds none.
    pub configured: Vec<Node>,
    /// The rekey msg1s it sent (see [`Rekeys`]).
    pub rekeys: Rekeys,
}

impl View {
    /// The view of node `me` holding nothing.
    pub fn empty(me: Node) -> Self {
        Self {
            me,
            peers: Vec::new(),
            needs: Vec::new(),
            audit: Vec::new(),
            bounds: Vec::new(),
            log: Vec::new(),
            configured: Vec::new(),
            rekeys: Vec::new(),
        }
    }
}

/// A known shape, seen on the way, that the convergence of the model
/// with itself exempts by name. Each is detected where it happens, at a
/// delivery, from the two parties' state on either side of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shape {
    /// A frame under a session its sender had already dropped left the
    /// receiver without the session its sender is on: the late-dial
    /// fallback rule following a stale frame, back onto the dropped
    /// session or by dropping the live one, a counterexample to that rule.
    StaleFrame,
    /// The peer's own rekey msg1 left a node on its handshake, installed or
    /// replacing, where a restart had left the node unable to judge it as
    /// a rekey; an observation against FRC-1201, which says nothing of it.
    RekeyInstall,
    /// A msg1 from its sender's previous life left the receiver on its
    /// handshake; an observation against FRC-1201, whose gates admit it
    /// where the current node's replay memory does not.
    OldLife,
    /// Both of a node's own dials of one peer were answered and the
    /// later-sent msg2 was read first; reading the earlier-sent one then
    /// moved the node onto a session the peer had replaced. The late
    /// second dial answered in the other order, a defect left for later.
    LaterDialFirst,
    /// A peer's own dial, arriving while the receiver held it on a link
    /// old enough to rekey, armed a responder pending there, which the
    /// dialer settles as a crossing and may never adopt. The dial on the
    /// peer's aged link, a defect left for later.
    DialAsRekey,
}

impl Shape {
    /// Whether this shape is one of the two defects left for later, which
    /// only the runs against the models of deployed nodes exempt; the
    /// model's convergence with itself and the core explorer exclude the
    /// starts that carry them instead.
    pub fn pinned(self) -> bool {
        match self {
            Self::LaterDialFirst | Self::DialAsRekey => true,
            Self::StaleFrame | Self::RekeyInstall | Self::OldLife => false,
        }
    }
}

/// A node, as the world drives it.
pub trait Party {
    /// Take one input, acting on the world through `net`.
    fn input(&mut self, net: &mut Net, inp: Input);
    /// The earliest instant this party has something to do.
    fn wake(&self) -> Option<Ms>;
    /// A canonical digest of the party's state.
    fn digest(&self) -> String;
    /// Whether the party holds keys for the session of `hs` with `peer`.
    fn holds(&self, peer: Node, hs: Hs) -> bool;
    /// The identities this party holds a peering of.
    fn held(&self) -> Vec<Node>;
    /// Whether an own rekey of `peer` may start now.
    fn rekeyable(&self, peer: Node) -> bool;
    /// The party's state, for the oracles.
    fn view(&self) -> View;
    /// The epoch of the party's current life.
    fn epoch(&self) -> Epoch;
}

/// What lies between the nodes.
#[derive(Clone, Debug)]
pub struct Net {
    /// The monotonic clock.
    pub now: Ms,
    /// How far the wall clock runs ahead of the monotonic one.
    pub wall: i64,
    /// Each transport's model, by transport number.
    pub kinds: BTreeMap<u8, Kind>,
    /// Each node's addresses.
    pub addrs: Vec<Vec<Addr>>,
    /// Every connection opened.
    pub conns: Vec<Conn>,
    /// Packets in flight, in send order.
    pub flight: Vec<Flight>,
    /// Every msg1 that entered flight, for the replay act.
    pub captured: Vec<Flight>,
    /// Sends from these nodes fail, one per entry.
    pub failing: Vec<usize>,
    /// The next packet number.
    pub next: u64,
    /// Whether what is in flight survives an advance or a restart, as it
    /// does with `DelayUnbounded`, for this world alone.
    pub unbounded: bool,
    /// Whether to log.
    pub logging: bool,
    /// The log.
    pub log: Vec<String>,
}

impl Net {
    /// A world with no traffic: `kinds` by transport, `addrs` by node.
    pub fn new(kinds: &[(u8, Kind)], addrs: Vec<Vec<Addr>>) -> Self {
        Self {
            now: 0,
            wall: 0,
            kinds: kinds.iter().copied().collect(),
            addrs,
            conns: Vec::new(),
            flight: Vec::new(),
            captured: Vec::new(),
            failing: Vec::new(),
            next: 0,
            unbounded: false,
            logging: false,
            log: Vec::new(),
        }
    }

    /// The model of transport `t`.
    pub fn kind(&self, t: u8) -> Kind {
        *self
            .kinds
            .get(&t)
            .expect("every address's transport is in the world")
    }

    /// The node that listens at `a`.
    pub fn owner(&self, a: Addr) -> Option<usize> {
        self.addrs.iter().position(|v| v.contains(&a))
    }

    /// Node `me`'s first address on transport `t`.
    pub fn home(&self, me: usize, t: u8) -> Addr {
        *self.addrs[me]
            .iter()
            .find(|a| a.transport == t)
            .expect("each node has an address on each transport")
    }

    /// The wall clock now.
    pub fn wallnow(&self) -> i64 {
        self.now as i64 + self.wall
    }

    fn note(&mut self, s: impl FnOnce() -> String) {
        if self.logging {
            let line = format!("{:>7} {}", self.now, s());
            self.log.push(line);
        }
    }

    /// Put a packet in flight.
    fn push(&mut self, to: usize, local: Addr, src: Addr, conn: Option<u32>, pkt: Pkt, copy: bool) {
        let id = self.next;
        self.next += 1;
        let f = Flight {
            id,
            to,
            local,
            src,
            conn,
            pkt,
            copy,
        };
        if matches!(pkt, Pkt::Msg1 { .. }) && !copy {
            self.captured.push(f);
        }
        self.flight.push(f);
        if fault!(FlightByHash) {
            // The defect's shape: the flight rebuilt from a hash map, whose
            // order a fresh random state picks.
            let map: std::collections::HashMap<u64, Flight> =
                self.flight.drain(..).map(|f| (f.id, f)).collect();
            self.flight = map.into_values().collect();
        }
    }

    /// Put a forged packet in flight to node `to` at its address `local`,
    /// from `src`.
    pub fn inject(&mut self, to: usize, local: Addr, src: Addr, pkt: Pkt) {
        self.push(to, local, src, None, pkt, true);
    }

    /// The open or connecting connection node `me` sees at `remote`, the
    /// latest if there are several.
    pub fn conn(&self, me: usize, remote: Addr) -> Option<(usize, usize)> {
        self.conns
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, c)| !matches!(c.state, State::Closed(_)))
            .find_map(|(i, c)| {
                (0..2)
                    .find(|&e| c.ends[e].node == me && c.ends[e].remote == remote)
                    .map(|e| (i, e))
            })
    }

    /// Open a connection from `me` to the node listening at `to`, from
    /// `me`'s address `from`. A BLE pair already connected shares its
    /// connection.
    pub fn connect(&mut self, me: usize, from: Option<Addr>, to: Addr) -> Option<u32> {
        let kind = self.kind(to.transport);
        if kind == Kind::Datagram {
            return None;
        }
        let owner = self.owner(to)?;
        let local = from.unwrap_or_else(|| self.home(me, to.transport));
        if kind == Kind::Ble
            && !fault!(BleSecondConn)
            && let Some((i, e)) = self.conn(me, to)
            && self.conns[i].ends[e].local == local
        {
            return Some(self.conns[i].id);
        }
        let id = self.conns.len() as u32;
        let seen = match kind {
            Kind::Ble => local,
            Kind::Stream | Kind::Datagram => Addr {
                transport: to.transport,
                at: EPHEMERAL + id as u16,
            },
        };
        self.conns.push(Conn {
            id,
            kind,
            ends: [
                End {
                    node: me,
                    local,
                    remote: to,
                },
                End {
                    node: owner,
                    local: to,
                    remote: seen,
                },
            ],
            state: State::Connecting,
            queued: Vec::new(),
            verified: [false; 2],
        });
        self.note(|| format!("n{me} connects c{id} to {to:?}"));
        Some(id)
    }

    /// Whether a send from `me` to `to` would go out now. A scripted
    /// failure for `me` is spent by this check.
    pub fn sendable(&mut self, me: usize, to: Addr) -> bool {
        if let Some(i) = self.failing.iter().position(|&n| n == me) {
            self.failing.remove(i);
            return false;
        }
        match self.kind(to.transport) {
            Kind::Datagram => true,
            Kind::Stream | Kind::Ble => self.conn(me, to).is_some() || self.owner(to).is_some(),
        }
    }

    /// Send `pkt` from `me` to `to`, from `me`'s address `from` on a
    /// connectionless transport. False when there is no way to send.
    pub fn send(&mut self, me: usize, from: Option<Addr>, to: Addr, pkt: Pkt) -> bool {
        self.note(|| format!("n{me} sends {pkt:?} to {to:?}"));
        match self.kind(to.transport) {
            Kind::Datagram => {
                let src = from.unwrap_or_else(|| self.home(me, to.transport));
                if let Some(owner) = self.owner(to) {
                    self.push(owner, to, src, None, pkt, false);
                }
                true
            }
            Kind::Stream | Kind::Ble => {
                let mut at = to;
                if fault!(ReplyNewConn) && self.owner(to).is_none() {
                    // The defect's shape: a reply to an accepted connection
                    // dials the peer's listening address instead.
                    if let Some(c) = self
                        .conns
                        .iter()
                        .find(|c| c.ends[1].node == me && c.ends[1].remote == to)
                    {
                        at = self.home(c.ends[0].node, to.transport);
                    }
                }
                let found = match self.conn(me, at) {
                    Some(f) if !(fault!(ReplyNewConn) && at != to) => Some(f),
                    _ => self.connect(me, from, at).and_then(|_| self.conn(me, at)),
                };
                let Some((i, e)) = found else {
                    return false;
                };
                match self.conns[i].state {
                    State::Connecting if !fault!(SendAtDial) => {
                        self.conns[i].queued.push((e, pkt));
                    }
                    State::Connecting | State::Open => {
                        let c = &self.conns[i];
                        let far = c.ends[1 - e];
                        let id = c.id;
                        self.push(far.node, far.local, far.remote, Some(id), pkt, false);
                    }
                    State::Closed(_) => return false,
                }
                true
            }
        }
    }

    /// Node `me` closes the connection it sees at `at`: the far end gets an
    /// end-of-stream behind what is already in flight.
    pub fn close(&mut self, me: usize, at: Addr) {
        let Some((i, e)) = self.conn(me, at) else {
            return;
        };
        self.shut(i, e);
    }

    /// End `e` of connection `i` closes it.
    fn shut(&mut self, i: usize, e: usize) {
        let c = &mut self.conns[i];
        let was = c.state;
        c.state = State::Closed(e);
        c.queued.clear();
        let far = c.ends[1 - e];
        let id = c.id;
        self.note(|| format!("c{id} closed by end {e}"));
        if was == State::Open && !fault!(EofDropped) {
            self.push(far.node, far.local, far.remote, Some(id), Pkt::Eof, false);
        }
    }

    /// Set node `me`'s verified mark on the BLE connection it sees at
    /// `at`, or clear it.
    pub fn mark(&mut self, me: usize, at: Addr, on: bool) {
        if let Some((i, e)) = self.conn(me, at)
            && self.conns[i].kind == Kind::Ble
        {
            self.conns[i].verified[e] = on;
        }
    }

    /// Whether flight entry `f` may be delivered now: each direction of a
    /// connection delivers in order.
    pub fn deliverable(&self, f: &Flight) -> bool {
        match f.conn {
            None => true,
            Some(c) => {
                self.flight
                    .iter()
                    .find(|g| g.conn == Some(c) && g.to == f.to)
                    .map(|g| g.id)
                    == Some(f.id)
            }
        }
    }
}

/// The world: the parties and what lies between them.
pub struct World {
    /// The nodes, by index.
    pub parties: Vec<Box<dyn Party>>,
    /// Their identities, by index.
    pub ids: Vec<Node>,
    /// The transports, connections, flight and clocks.
    pub net: Net,
    /// Path events the start makes available, each usable once.
    pub paths: Vec<(usize, PathEv)>,
    /// Which of them have been used.
    pub used: Vec<bool>,
    /// The known shapes seen so far, each once.
    pub shapes: Vec<Shape>,
}

impl World {
    /// A world of `parties` with identities `ids` over `net`.
    pub fn new(parties: Vec<Box<dyn Party>>, ids: Vec<Node>, net: Net) -> Self {
        Self {
            parties,
            ids,
            net,
            paths: Vec::new(),
            used: Vec::new(),
            shapes: Vec::new(),
        }
    }

    /// The session node `x` holds peer `id` on, if it holds it.
    fn cur(&self, x: usize, id: Node) -> Option<Hs> {
        self.parties[x]
            .view()
            .peers
            .iter()
            .find(|p| p.peer == id)
            .map(|p| p.cur)
    }

    /// What node `x`'s delivery of `pkt` could turn out to be, judged
    /// before it is handed over, and the session that decides it.
    fn suspect(&self, x: usize, pkt: Pkt) -> Option<(Shape, Hs, Option<Hs>)> {
        let loose = fault!(ShapeLoose);
        let me = self.ids[x];
        match pkt {
            Pkt::Frame { id, hs } => {
                // The sender's own session, which the receiver holds now.
                let y = self.index(id)?;
                let theirs = self.cur(y, me)?;
                let stale = !self.parties[y].holds(me, hs);
                ((stale || loose) && self.parties[x].holds(id, theirs)).then_some((
                    Shape::StaleFrame,
                    theirs,
                    None,
                ))
            }
            Pkt::Msg1 { id, hs, epoch, .. } => {
                let y = self.index(id)?;
                if self.parties[y].epoch() != epoch || loose {
                    return Some((Shape::OldLife, hs, self.cur(x, id)));
                }
                let v = self.parties[y].view();
                let rekey = v.rekeys.contains(&(me, hs))
                    || v.peers.iter().any(|p| p.peer == me && p.rekey == Some(hs));
                if rekey {
                    return Some((Shape::RekeyInstall, hs, self.cur(x, id)));
                }
                // The sender's own dial, sent while it holds the receiver.
                let dial = v
                    .peers
                    .iter()
                    .any(|p| p.peer == me && p.dials.contains(&hs));
                dial.then(|| (Shape::DialAsRekey, hs, self.cur(x, id)))
            }
            Pkt::Msg2 { id, hs, .. } => {
                // The answer to one of the receiver's own dials, read while
                // it holds the peer on a later dial of its own life.
                let v = self.parties[x].view();
                let p = v.peers.iter().find(|p| p.peer == id)?;
                let own = |h: Hs| {
                    h.0 >> 24 == u32::from(me.0) && (h.0 >> 16) & 0xff == (hs.0 >> 16) & 0xff
                };
                let later = own(p.origin) && p.origin.0 & 0xffff > hs.0 & 0xffff;
                (p.dials.contains(&hs) && (later || loose)).then_some((
                    Shape::LaterDialFirst,
                    hs,
                    Some(p.cur),
                ))
            }
            Pkt::Eof => None,
        }
    }

    /// Record `shape` if the delivery to `x` turned out as the shape says:
    /// a stale frame left the receiver without the session its sender is
    /// on; a rekey msg1, a msg1 of a previous life, or the msg2 of an
    /// earlier own dial, left it holding the sender on that handshake as
    /// its session, which `before` was not; a dial left a responder
    /// pending on its handshake.
    fn witness(&mut self, x: usize, pkt: Pkt, shape: Shape, hs: Hs, before: Option<Hs>) {
        let (Pkt::Frame { id, .. } | Pkt::Msg1 { id, .. } | Pkt::Msg2 { id, .. }) = pkt else {
            return;
        };
        let shown = match shape {
            Shape::StaleFrame => !self.parties[x].holds(id, hs),
            Shape::RekeyInstall | Shape::OldLife | Shape::LaterDialFirst => {
                before != Some(hs) && self.cur(x, id) == Some(hs)
            }
            Shape::DialAsRekey => self.parties[x]
                .view()
                .peers
                .iter()
                .any(|p| p.peer == id && p.pending == Some((hs, false))),
        };
        if fault!(ShapeBlind) || !shown {
            return;
        }
        if !self.shapes.contains(&shape) {
            self.shapes.push(shape);
            self.shapes.sort_unstable();
            self.net.note(|| format!("n{x} shows {shape:?}"));
        }
    }

    /// Hand `inp` to node `x`.
    pub fn input(&mut self, x: usize, inp: Input) {
        let World { parties, net, .. } = self;
        net.note(|| format!("n{x} <- {inp:?}"));
        parties[x].input(net, inp);
    }

    /// The node index of identity `id`.
    pub fn index(&self, id: Node) -> Option<usize> {
        self.ids.iter().position(|&n| n == id)
    }

    /// Deliver flight entry `id`, if it is in flight.
    pub fn deliver(&mut self, id: u64) {
        let Some(i) = self.net.flight.iter().position(|f| f.id == id) else {
            return;
        };
        let f = self.net.flight.remove(i);
        if let Some(c) = f.conn {
            let conn = &self.net.conns[c as usize];
            let e = usize::from(conn.ends[0].node != f.to);
            if conn.state == State::Closed(e) {
                // The receiver closed it: nothing reaches it any more.
                return;
            }
        }
        let inp = match f.pkt {
            Pkt::Eof => Input::Closed { at: f.src },
            Pkt::Frame { id: from, hs }
                if !fault!(FrameOpensAny) && !self.parties[f.to].holds(from, hs) =>
            {
                self.net
                    .note(|| format!("n{} cannot open {:?}", f.to, f.pkt));
                return;
            }
            Pkt::Msg1 { .. } | Pkt::Msg2 { .. } | Pkt::Frame { .. } => Input::Packet {
                src: f.src,
                local: f.local,
                conn: f.conn,
                pkt: f.pkt,
                stamp: self.net.wallnow(),
            },
        };
        let suspect = self.suspect(f.to, f.pkt);
        self.input(f.to, inp);
        if let Some((shape, hs, before)) = suspect {
            self.witness(f.to, f.pkt, shape, hs, before);
        }
    }

    /// Put a copy of flight entry `id` in flight behind everything else.
    pub fn duplicate(&mut self, id: u64) {
        if let Some(f) = self.net.flight.iter().find(|f| f.id == id).copied() {
            self.net.push(f.to, f.local, f.src, f.conn, f.pkt, true);
        }
    }

    /// Re-inject captured msg1 `k` at its receiver, as an attacker that
    /// recorded it would.
    pub fn replay(&mut self, k: usize) {
        if let Some(f) = self.net.captured.get(k).copied() {
            let open = f
                .conn
                .is_none_or(|c| self.net.conns[c as usize].state == State::Open);
            if open {
                self.net.push(f.to, f.local, f.src, f.conn, f.pkt, true);
            }
        }
    }

    /// Resolve connection `c`'s connect window.
    pub fn connected(&mut self, c: u32, ok: bool) {
        let i = c as usize;
        if self.net.conns[i].state != State::Connecting {
            return;
        }
        if ok {
            self.net.conns[i].state = State::Open;
            let queued = core::mem::take(&mut self.net.conns[i].queued);
            for (e, p) in queued {
                let far = self.net.conns[i].ends[1 - e];
                self.net
                    .push(far.node, far.local, far.remote, Some(c), p, false);
            }
        } else {
            self.net.conns[i].state = State::Closed(0);
            self.net.conns[i].queued.clear();
            let End { node, remote, .. } = self.net.conns[i].ends[0];
            self.input(node, Input::ConnectFailed { to: remote });
        }
    }

    /// End `e` of connection `c` sees it fail: it is told at once and the
    /// far end gets an end-of-stream.
    pub fn fail(&mut self, c: u32, e: usize) {
        let i = c as usize;
        if self.net.conns[i].state != State::Open {
            return;
        }
        self.net.shut(i, e);
        let End { node, remote, .. } = self.net.conns[i].ends[e];
        self.input(node, Input::Closed { at: remote });
    }

    /// Node `x` restarts: its connections close and it forgets everything.
    /// A restart takes longer than a delivery may be delayed, so whatever
    /// was in flight is delivered or lost before the new life sends; the
    /// world has delivered nothing, so it is lost. The end-of-stream
    /// notices of the old life's connections die with its sockets. A dialer
    /// whose connection was still inside its connect window to `x` sees
    /// that connect fail.
    pub fn restart(&mut self, x: usize) {
        self.lose("the restart");
        if !self.unbounded() {
            self.net.flight.retain(|f| f.to != x);
        }
        let mut refused = Vec::new();
        for i in 0..self.net.conns.len() {
            let c = &self.net.conns[i];
            if let Some(e) = (0..2).find(|&e| c.ends[e].node == x)
                && !matches!(c.state, State::Closed(_))
            {
                if c.state == State::Connecting && e == 1 && !fault!(ConnectRefusedSilent) {
                    refused.push(c.ends[0]);
                }
                self.net.shut(i, e);
            }
        }
        self.input(x, Input::Restart);
        for End { node, remote, .. } in refused {
            self.input(node, Input::ConnectFailed { to: remote });
        }
    }

    /// The earliest wake of any party.
    pub fn wake(&self) -> Option<Ms> {
        self.parties.iter().filter_map(|p| p.wake()).min()
    }

    /// Advance to the earliest wake and wake every party due. A delivery
    /// is delayed by less than one wake, so whatever is in flight when the
    /// clock moves is lost.
    pub fn advance(&mut self) {
        let Some(t) = self.wake() else {
            return;
        };
        if t > self.net.now {
            self.lose("the advance");
        }
        self.net.now = self.net.now.max(t);
        for x in 0..self.parties.len() {
            if self.parties[x].wake().is_some_and(|w| w <= self.net.now) {
                self.input(x, Input::Wake);
            }
        }
    }

    /// Lose everything in flight but end-of-stream notices, which are the
    /// transport's own and still reach the far end.
    fn lose(&mut self, at: &'static str) {
        if self.unbounded() {
            return;
        }
        let before = self.net.flight.len();
        self.net.flight.retain(|f| f.pkt == Pkt::Eof);
        let lost = before - self.net.flight.len();
        if lost > 0 {
            self.net.note(|| format!("{lost} in flight lost at {at}"));
        }
    }

    /// Whether deliveries may be delayed without bound here.
    fn unbounded(&self) -> bool {
        self.net.unbounded || fault!(DelayUnbounded)
    }

    /// Advance the clock to `t`, waking parties at each wake on the way;
    /// as at a wake, what is in flight when the clock moves is lost.
    pub fn run_until(&mut self, t: Ms) {
        while let Some(w) = self.wake() {
            if w > t {
                break;
            }
            self.advance();
        }
        if t > self.net.now {
            self.lose("the clock's move");
            self.net.now = t;
        }
    }

    /// Deliver everything in flight, in order, until nothing is left or
    /// `limit` packets were delivered.
    pub fn drain(&mut self, limit: usize) {
        for _ in 0..limit {
            let Some(id) = self
                .net
                .flight
                .iter()
                .find(|f| self.net.deliverable(f))
                .map(|f| f.id)
            else {
                return;
            };
            self.deliver(id);
        }
    }

    /// A canonical digest of the whole world: every party, the connections,
    /// the flight in order without packet numbers, and both clocks.
    pub fn digest(&self) -> String {
        let mut s = String::new();
        for p in &self.parties {
            s.push_str(&p.digest());
            s.push('|');
        }
        for c in &self.net.conns {
            s.push_str(&format!(
                "{}{:?}{:?}{:?}{:?};",
                c.id, c.ends, c.state, c.queued, c.verified
            ));
        }
        // Each direction of a connection delivers in order and keeps it;
        // packets on no connection, and the directions themselves, are an
        // unordered set, so deliveries that commute reach one state.
        let mut lanes: BTreeMap<(Option<u32>, usize), Vec<String>> = BTreeMap::new();
        for f in &self.net.flight {
            let item = format!("{:?}{:?}{:?}{};", f.local, f.src, f.pkt, f.copy);
            lanes.entry((f.conn, f.to)).or_default().push(item);
        }
        for ((conn, _), items) in lanes.iter_mut() {
            if conn.is_none() {
                items.sort();
            }
        }
        for (lane, items) in &lanes {
            s.push_str(&format!("{lane:?}{}", items.concat()));
        }
        s.push_str(&format!(
            "{}/{}/{}/{:?}/{:?}/{:?}",
            self.net.now,
            self.net.wall,
            self.net.captured.len(),
            self.net.failing,
            self.used,
            self.shapes
        ));
        s
    }

    /// The digest's hash, the explorer's key.
    pub fn key(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.digest().hash(&mut h);
        h.finish()
    }
}

/// A party that holds the sessions it is given and records every input.
struct Recorder {
    sessions: Vec<(Node, Hs)>,
    seen: std::rc::Rc<core::cell::RefCell<Vec<Input>>>,
}

impl Party for Recorder {
    fn input(&mut self, _: &mut Net, inp: Input) {
        self.seen.borrow_mut().push(inp);
    }
    fn wake(&self) -> Option<Ms> {
        None
    }
    fn digest(&self) -> String {
        format!("{:?}", self.sessions)
    }
    fn holds(&self, peer: Node, hs: Hs) -> bool {
        self.sessions.contains(&(peer, hs))
    }
    fn held(&self) -> Vec<Node> {
        Vec::new()
    }
    fn rekeyable(&self, _: Node) -> bool {
        false
    }
    fn view(&self) -> View {
        View::empty(Node(0))
    }
    fn epoch(&self) -> Epoch {
        Epoch(0)
    }
}

mod checks {
    use super::super::starts::{A, B, BLE, C, TCP, UDP, home, settle, world};
    use super::*;

    #[test]
    fn a_frame_opens_only_under_a_session_the_receiver_holds() {
        let seen = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
        let rec = Recorder {
            sessions: alloc::vec![(B, Hs(7))],
            seen: seen.clone(),
        };
        let mut w = world(&[A, B], &[]);
        w.parties[0] = Box::new(rec);
        for hs in [Hs(8), Hs(7)] {
            let pkt = Pkt::Frame { id: B, hs };
            w.net.inject(0, home(0, UDP), home(1, UDP), pkt);
            let id = w.net.flight[0].id;
            w.deliver(id);
        }
        let frames: Vec<Hs> = seen
            .borrow()
            .iter()
            .filter_map(|i| match i {
                Input::Packet {
                    pkt: Pkt::Frame { hs, .. },
                    ..
                } => Some(*hs),
                Input::Packet { .. }
                | Input::Closed { .. }
                | Input::ConnectFailed { .. }
                | Input::Wake
                | Input::Restart
                | Input::Dial { .. }
                | Input::Rekey { .. }
                | Input::Beat
                | Input::Path(_) => None,
            })
            .collect();
        assert_eq!(
            frames,
            [Hs(7)],
            "only the frame under a held session reaches the party"
        );
    }

    #[test]
    fn a_party_holding_a_session_sends_a_heartbeat_at_each_heartbeat_wake() {
        let mut w = world(&[A, B], &[&[(1, UDP)], &[]]);
        w.input(
            0,
            Input::Dial {
                peer: B,
                to: home(1, UDP),
                from: None,
            },
        );
        settle(&mut w);
        assert_eq!(w.parties[0].held(), [B], "precondition: the pair is up");
        for round in 1..=2u64 {
            w.run_until(round * HEARTBEAT);
            let beats: Vec<usize> = w
                .net
                .flight
                .iter()
                .filter(|f| matches!(f.pkt, Pkt::Frame { .. }))
                .map(|f| f.to)
                .collect();
            assert_eq!(beats, [1, 0], "each end beats in round {round}");
            settle(&mut w);
        }
    }

    #[test]
    fn a_connection_oriented_reply_goes_on_the_arrival_connection() {
        let mut w = world(&[A, B], &[]);
        w.input(
            0,
            Input::Dial {
                peer: B,
                to: home(1, TCP),
                from: None,
            },
        );
        w.connected(0, true);
        let id = w.net.flight[0].id;
        w.deliver(id);
        let reply = w
            .net
            .flight
            .iter()
            .find(|f| matches!(f.pkt, Pkt::Msg2 { .. }))
            .expect("the msg2 is in flight");
        assert_eq!(reply.conn, Some(0), "the msg2 rides the msg1's connection");
        assert_eq!(
            reply.src,
            home(1, TCP),
            "the dialer sees the address it dialed"
        );
        assert_eq!(
            w.net.conns.len(),
            1,
            "no connection was opened for the reply"
        );
    }

    #[test]
    fn an_eof_reaches_the_far_end() {
        let mut w = world(&[A, B], &[&[(1, TCP)], &[]]);
        w.input(
            0,
            Input::Dial {
                peer: B,
                to: home(1, TCP),
                from: None,
            },
        );
        settle(&mut w);
        assert_eq!(w.parties[1].held(), [A], "precondition: the pair is up");
        w.fail(0, 0);
        assert!(
            w.net.flight.iter().any(|f| f.to == 1 && f.pkt == Pkt::Eof),
            "the far end's end-of-stream is in flight"
        );
        settle(&mut w);
        assert!(
            w.parties[1].held().is_empty(),
            "the far end saw its link close"
        );
    }

    #[test]
    fn a_ble_link_holds_one_connection_per_pair() {
        let mut w = world(&[A, B], &[]);
        for (x, peer, y) in [(0, B, 1), (1, A, 0)] {
            w.input(
                x,
                Input::Dial {
                    peer,
                    to: home(y, BLE),
                    from: None,
                },
            );
        }
        assert_eq!(
            w.net.conns.len(),
            1,
            "both dials share the pair's connection"
        );
    }

    #[test]
    fn a_dial_inside_the_connect_window_sends_nothing_until_it_connects() {
        let mut w = world(&[A, B], &[]);
        w.input(
            0,
            Input::Dial {
                peer: B,
                to: home(1, TCP),
                from: None,
            },
        );
        assert!(w.net.flight.is_empty(), "nothing is sent while connecting");
        w.connected(0, true);
        assert!(
            matches!(
                w.net.flight[..],
                [Flight {
                    pkt: Pkt::Msg1 { .. },
                    ..
                }]
            ),
            "the msg1 goes out once connected"
        );
    }

    #[test]
    fn what_is_in_flight_is_lost_when_the_clock_moves_and_when_its_receiver_restarts() {
        let mut w = world(&[A, B], &[]);
        w.input(
            0,
            Input::Dial {
                peer: B,
                to: home(1, UDP),
                from: None,
            },
        );
        let first = w.net.flight[0].id;
        w.advance();
        assert!(
            w.net.flight.iter().all(|f| f.id != first),
            "the msg1 sent before the clock moved is lost"
        );
        let resend = w
            .net
            .flight
            .iter()
            .find(|f| matches!(f.pkt, Pkt::Msg1 { .. }))
            .map(|f| f.id)
            .expect("precondition: the resend is in flight");
        w.restart(1);
        assert!(
            w.net.flight.iter().all(|f| f.id != resend),
            "the resend addressed to the restarting node is lost"
        );
    }

    #[test]
    fn a_dialer_inside_its_connect_window_is_told_when_the_acceptor_restarts() {
        let seen = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
        let mut w = world(&[A, B], &[]);
        w.parties[0] = Box::new(Recorder {
            sessions: Vec::new(),
            seen: seen.clone(),
        });
        w.net.connect(0, None, home(1, TCP));
        assert_eq!(
            w.net.conns[0].state,
            State::Connecting,
            "precondition: the dial is inside its connect window"
        );
        w.restart(1);
        assert!(
            seen.borrow()
                .iter()
                .any(|i| *i == Input::ConnectFailed { to: home(1, TCP) }),
            "the dialer is told its connect failed: {:?}",
            seen.borrow()
        );
    }

    #[test]
    fn an_inbound_connection_whose_msg1_was_refused_is_closed_at_the_handshake_timeout() {
        // Node 1 holds node 0, heard just now; a msg1 claiming node 0's
        // identity arrives over a new connection and is refused. Its
        // sender is a recorder that never closes anything.
        let mut w = world(&[A, B, C], &[&[(1, UDP)], &[], &[]]);
        w.input(
            0,
            Input::Dial {
                peer: B,
                to: home(1, UDP),
                from: None,
            },
        );
        settle(&mut w);
        assert_eq!(w.parties[1].held(), [A], "precondition: the pair is up");
        w.parties[2] = Box::new(Recorder {
            sessions: Vec::new(),
            seen: std::rc::Rc::new(core::cell::RefCell::new(Vec::new())),
        });
        let c = w.net.connect(2, None, home(1, TCP)).expect("a connection");
        w.connected(c, true);
        let epoch = w.parties[0].epoch();
        let pkt = Pkt::Msg1 {
            id: A,
            hs: Hs(0x0100_0099),
            bytes: Bytes(0x0100_0099),
            epoch,
        };
        w.net.send(2, None, home(1, TCP), pkt);
        settle(&mut w);
        assert_eq!(
            w.net.conns[c as usize].state,
            State::Open,
            "precondition: the refused msg1's connection is open"
        );
        let end = w.net.now + HANDSHAKE;
        w.run_until(end);
        assert_eq!(
            w.net.conns[c as usize].state,
            State::Closed(1),
            "the refusing node closes the connection at the handshake timeout"
        );
    }
}
