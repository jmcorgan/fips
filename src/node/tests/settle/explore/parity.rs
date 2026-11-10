//! The shared schedules (`fips_core::proto::settle::parity`) run on real
//! nodes, each compared with the committed trace.
//!
//! The same scripts run in the core's settlement world, on its model of
//! the node and on its joint nodes, and each side compares what its ends
//! hold with one trace file, which says what the node does. Here a real
//! pair must give the trace's node lines; a `core` line there is the
//! settlement core's, and is not read.
//!
//! Each step of a script is translated one for one into the world's, in a
//! world that holds every packet, established frames too, until a step
//! names it or a heal hands it over, as the core's world delivers only
//! what a step names:
//!
//! - a dial is the world's dial of the peer's home on the world's one
//!   transport, through `initiate_connection`;
//! - a connection opening is the node's pending connects resolved, and on
//!   BLE, where the pair shares one connection, the peer's as well;
//! - a handshake message hands its reader the first packet of that kind
//!   it holds of the handshake the script names: for a msg1, the one whose
//!   sender index is the one the sender's `nth` handshake used, counted in
//!   the order each handshake's msg1 was first seen in flight; for a msg2,
//!   the one that echoes the reader's own `nth` handshake's index;
//! - a heal hands over everything in flight until the nodes are quiet,
//!   then lets a minute pass a second at a time, everything handed over
//!   after each second;
//! - an advance lets the time pass a second at a time, running each node's
//!   timers after each, and loses what is in flight before each second, as
//!   the core's world loses what is in flight when its clock moves;
//! - a restart and a rekey are the world's own.
//!
//! Two things the world does not do for itself, the walk does. The core's
//! world configures each dialer with its peer, so a node that dials a peer
//! in a script redials it whenever it holds none; a real node here is
//! configured with none, so a heal redials, before each second, a dialer
//! that holds neither its peer nor a dial in progress. And a node times its
//! heartbeats by the host's clock, which the world does not move, while its
//! link-dead check reads the clock the world moves; so each time the walk
//! passes a multiple of the heartbeat interval, every held peer's heartbeat
//! is made due.
//!
//! After each step each end's [`Mark`] is read from the node: whether it
//! holds the peer; whose dial its current session came from, by the role
//! the session's handshake gave it; its link record's direction and the
//! address it was set up at; the address the node sends to the peer on;
//! and whether it counts the peering heard. An address is the peer's home,
//! the one a dial goes to, or neither, the source of a connection the peer
//! opened.

use super::super::super::spanning_tree::cleanup_nodes;
use super::super::super::*;
use super::script::{Kind, Step, run};
use super::starts::Order;
use super::world::{Medium, World};
use crate::noise::HandshakeRole;
use crate::proto::fmp::wire::{Msg1Header, Msg2Header};
use fips_core::proto::settle::parity::{
    self, At, Dir, Holding, Line, Mark, Packet, Place, SCRIPTS, Script, Setting, Side, Transport,
};
use std::sync::{Arc, Mutex};

/// The shared scripts no real pair runs here, by name, each with why.
pub(super) const UNRUN: &[(&str, &str)] = &[
    ("crossing-mixed-smaller-off", MIXED),
    ("crossing-mixed-larger-off", MIXED),
    ("crossing-mixed-smaller-on", MIXED),
    ("crossing-mixed-larger-on", MIXED),
];

/// Why the crossing over two transports is not run.
const MIXED: &str = "its dials go over UDP and TCP between the same two nodes, and a world's \
                     nodes run one medium: only a loopback world takes a second transport, and \
                     that one is a loopback one";

/// Why `script` is not run here: it is listed in [`UNRUN`], or it runs on
/// a transport this build does not have.
fn unrun(script: &Script) -> Option<&'static str> {
    if let Some((_, why)) = UNRUN.iter().find(|(name, _)| *name == script.name) {
        return Some(why);
    }
    if cfg!(not(ble_available)) && script.transports.contains(&Transport::Ble) {
        return Some("the BLE transport does not build here");
    }
    None
}

/// The medium a world runs `script` on: its one transport's. `None` for a
/// script on more than one transport.
fn medium(script: &Script) -> Option<Medium> {
    match script.transports {
        [Transport::Udp] => Some(Medium::Loopback),
        [Transport::Tcp] => Some(Medium::Tcp),
        #[cfg(ble_available)]
        [Transport::Ble] => Some(Medium::Ble),
        _ => None,
    }
}

/// A script under way on a real pair.
struct Walk {
    world: World,
    medium: Medium,
    /// The script's transport, which every pair of the world is on.
    transport: Transport,
    /// Which world node each of the script's nodes is.
    order: Order,
    /// Each world node's handshakes, by the sender index its msg1 carries,
    /// in the order each was first seen in flight.
    begun: [Vec<SessionIndex>; 2],
    /// The time the walk has let pass.
    elapsed: Duration,
}

impl Walk {
    /// A world for `script` on `medium` with multipath set as `on`, holding
    /// established frames.
    async fn new(script: &Script, medium: Medium, on: bool) -> Walk {
        let order = if script.smaller == 0 {
            Order::Smaller
        } else {
            Order::Larger
        };
        let mut world = World::new(medium, 2, on).await;
        world.hold();
        Walk {
            world,
            medium,
            transport: script.transports[0],
            order,
            begun: [Vec::new(), Vec::new()],
            elapsed: Duration::ZERO,
        }
    }

    /// Number each handshake whose msg1 is in flight and not yet numbered,
    /// as its sender's next.
    fn note(&mut self) {
        for at in 0..2 {
            for p in self.world.packets(at, Kind::Msg1) {
                let Some(h) = Msg1Header::parse(&p.data) else {
                    continue;
                };
                let seen = &mut self.begun[1 - at];
                if !seen.contains(&h.sender_idx) {
                    seen.push(h.sender_idx);
                }
            }
        }
    }

    /// Run one of the world's steps and number what it sent.
    async fn step(&mut self, step: Step) {
        run(&mut self.world, &[step]).await;
        self.note();
    }

    /// Where among the packets of `kind` that world node `to` holds is the
    /// first one of handshake `nth`, counted from 1 in its dialer's life.
    /// Over a connection-oriented transport a packet may still be on its
    /// way, so this waits up to 2 s for it.
    async fn find(&mut self, to: usize, kind: Packet, nth: u32) -> Result<usize, String> {
        let (dialer, class) = match kind {
            Packet::Msg1 => (1 - to, Kind::Msg1),
            Packet::Msg2 => (to, Kind::Msg2),
        };
        let n = nth as usize - 1;
        for _ in 0..200 {
            self.note();
            if let Some(&idx) = self.begun[dialer].get(n) {
                let at = self
                    .world
                    .packets(to, class)
                    .iter()
                    .position(|p| match kind {
                        Packet::Msg1 => {
                            Msg1Header::parse(&p.data).is_some_and(|h| h.sender_idx == idx)
                        }
                        Packet::Msg2 => {
                            Msg2Header::parse(&p.data).is_some_and(|h| h.receiver_idx == idx)
                        }
                    });
                if let Some(at) = at {
                    return Ok(at);
                }
            }
            if self.medium == Medium::Loopback {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(format!(
            "no {kind:?} of handshake {nth} is held at node {to}; node {dialer} began {}",
            self.begun[dialer].len()
        ))
    }

    /// Whether world node `at` has a dial in progress: a pending transport
    /// connect or a msg1 out.
    fn dialing(&self, at: usize) -> bool {
        let node = &self.world.nodes[at].node;
        !node.pending_outbound.is_empty() || !node.peering.pending_connects.is_empty()
    }

    /// Redial each of `dials`, world node to world node, whose dialer holds
    /// neither its peer nor a dial in progress, as a configured peer is
    /// redialed.
    async fn redial(&mut self, dials: &[(usize, usize)]) {
        for &(from, to) in dials {
            let peer = *self.world.nodes[to].node.node_addr();
            if self.world.nodes[from].node.get_peer(&peer).is_none() && !self.dialing(from) {
                self.step(Step::Dial {
                    from,
                    to,
                    transport: 0,
                })
                .await;
            }
        }
    }

    /// Let `ms`, at most a second, pass, each node running its timers once.
    /// When the walk passes a multiple of the heartbeat interval, every held
    /// peer's heartbeat is first made due (the module's doc says why).
    async fn pass(&mut self, ms: u64) {
        let every = Duration::from_secs(
            self.world.nodes[0]
                .node
                .config()
                .node
                .heartbeat_interval_secs,
        );
        let next = self.elapsed + Duration::from_millis(ms);
        if next.as_millis() / every.as_millis() > self.elapsed.as_millis() / every.as_millis() {
            let then = std::time::Instant::now().checked_sub(every);
            for x in 0..2 {
                let peer = *self.world.nodes[1 - x].node.node_addr();
                if let (Some(p), Some(then)) = (self.world.nodes[x].node.get_peer_mut(&peer), then)
                {
                    p.mark_heartbeat_sent(then);
                }
            }
        }
        self.world.advance(ms).await;
        self.elapsed = next;
    }

    /// Hand over everything in flight until the nodes are quiet, then let a
    /// minute pass a second at a time, redialing what `dials` names and
    /// handing everything over after each second.
    async fn heal(&mut self, dials: &[(usize, usize)]) -> Result<(), String> {
        self.note();
        if !self.world.heal().await {
            return Err("the nodes did not go quiet".to_string());
        }
        for second in 1..=60 {
            self.redial(dials).await;
            self.pass(1_000).await;
            if !self.world.heal().await {
                return Err(format!(
                    "the nodes did not go quiet {second} s into the heal"
                ));
            }
        }
        Ok(())
    }

    /// Let `ms` pass a second at a time, losing what is in flight before
    /// each second and running each node's timers after it.
    async fn advance(&mut self, ms: u64) {
        let mut left = ms;
        while left > 0 {
            let now = left.min(1_000);
            self.note();
            self.world.clear();
            self.pass(now).await;
            self.note();
            left -= now;
        }
    }

    /// Take one step of the script.
    async fn take(&mut self, step: parity::Step, dials: &[(usize, usize)]) -> Result<(), String> {
        let n = |i| self.order.node(i);
        match step {
            parity::Step::Dial { from, to, .. } => {
                let (from, to) = (n(from), n(to));
                self.step(Step::Dial {
                    from,
                    to,
                    transport: 0,
                })
                .await;
            }
            parity::Step::Connected { node } => {
                let node = n(node);
                self.step(Step::Connected { node }).await;
                #[cfg(ble_available)]
                if self.medium == Medium::Ble {
                    self.step(Step::Connected { node: 1 - node }).await;
                }
            }
            parity::Step::Handshake { to, kind, nth } => {
                let to = n(to);
                let at = self.find(to, kind, nth).await?;
                let kind = match kind {
                    Packet::Msg1 => Kind::Msg1,
                    Packet::Msg2 => Kind::Msg2,
                };
                self.step(Step::Handshake { to, kind, nth: at }).await;
            }
            parity::Step::Heal => self.heal(dials).await?,
            parity::Step::Advance(ms) => self.advance(ms).await,
            parity::Step::Restart { node } => {
                let node = n(node);
                self.step(Step::Restart { node }).await;
            }
            parity::Step::Rekey { node } => {
                let node = n(node);
                self.step(Step::Rekey { node }).await;
            }
        }
        Ok(())
    }

    /// The pair `(transport, addr)` names, as a pair of world node `peer`'s.
    fn place(&self, peer: usize, transport: TransportId, addr: &TransportAddr) -> Place {
        let home = &self.world.nodes[peer];
        let at = if transport == home.transport_id && *addr == home.addr {
            At::Home
        } else {
            At::Accepted
        };
        Place {
            transport: self.transport,
            at,
        }
    }

    /// What the script's node `x` holds of its peer.
    fn mark(&self, x: usize) -> Result<Mark, String> {
        let (wx, wy) = (self.order.node(x), self.order.node(1 - x));
        let node = &self.world.nodes[wx].node;
        let addr = self.world.nodes[wy].node.node_addr();
        let Some(peer) = node.get_peer(addr) else {
            return Ok(Mark::Unheld);
        };
        let session = match peer.noise_session().map(|s| s.role()) {
            Some(HandshakeRole::Initiator) => Side::Own,
            Some(HandshakeRole::Responder) => Side::Peer,
            None => return Err("it holds its peer with no session".to_string()),
        };
        let link = node
            .links
            .get(&peer.link_id())
            .ok_or("it holds its peer with no link record")?;
        let dir = match link.direction() {
            LinkDirection::Inbound => Dir::In,
            LinkDirection::Outbound => Dir::Out,
        };
        let (tid, to) = node
            .peer_link(addr)
            .ok_or("it holds its peer with no active pair")?;
        Ok(Mark::Held(Holding {
            session,
            dir,
            setup: self.place(wy, link.transport_id(), link.remote_addr()),
            active: self.place(wy, tid, &to),
            heard: peer.is_heard(),
        }))
    }
}

/// Every dial of `script`, in the world's indices for `order`, each once.
fn dials(script: &Script, order: Order) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for step in script.steps {
        if let parity::Step::Dial { from, to, .. } = *step {
            let dial = (order.node(from), order.node(to));
            if !out.contains(&dial) {
                out.push(dial);
            }
        }
    }
    out
}

/// Run `script` on a real pair on `medium` with multipath set as `on`, and
/// give what each end holds after each step. `at` names the step under way,
/// for a panic's report.
async fn walk(
    script: &Script,
    medium: Medium,
    on: bool,
    at: &Mutex<String>,
) -> Result<Vec<Line>, String> {
    let mut w = Walk::new(script, medium, on).await;
    let dials = dials(script, w.order);
    let mut out = Vec::new();
    let mut failed = None;
    'steps: for (i, &step) in script.steps.iter().enumerate() {
        *at.lock().expect("precondition: the step's name") =
            format!("{} step {} ({step:?})", script.name, i + 1);
        if let Err(e) = w.take(step, &dials).await {
            failed = Some(format!("{} step {}: {e}", script.name, i + 1));
            break;
        }
        for node in 0..2 {
            match w.mark(node) {
                Ok(mark) => out.push(Line {
                    step: i + 1,
                    node,
                    mark,
                }),
                Err(e) => {
                    failed = Some(format!("{} step {} n{node}: {e}", script.name, i + 1));
                    break 'steps;
                }
            }
        }
    }
    cleanup_nodes(&mut w.world.nodes).await;
    failed.map_or(Ok(out), Err)
}

/// The lines of `got` that differ from `want`, each with the line wanted.
fn differences(got: &[Line], want: &[Line]) -> Vec<String> {
    let mut out = Vec::new();
    for g in got {
        match want.iter().find(|l| l.step == g.step && l.node == g.node) {
            Some(l) if l.mark == g.mark => {}
            Some(l) => out.push(format!("`{g}` where the trace has `{l}`")),
            None => out.push(format!("`{g}` has no line in the trace")),
        }
    }
    out
}

/// Walk `script` on a thread of its own, with its own runtime and so its
/// own test clock. Gives whether every step ran, and every difference
/// from its trace's node lines.
fn compared(script: &'static Script, medium: Medium, on: bool) -> (bool, Vec<String>) {
    let at = Arc::new(Mutex::new(String::new()));
    let seen = Arc::clone(&at);
    let run = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("precondition: a runtime for the walk")
            .block_on(walk(script, medium, on, &seen))
    });
    let got = match run.join() {
        Ok(Ok(got)) => got,
        Ok(Err(e)) => return (false, vec![e]),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            let at = at.lock().map(|s| s.clone()).unwrap_or_default();
            return (false, vec![format!("{at}: a panic: {msg}")]);
        }
    };
    let Some(trace) = parity::expected(script.name) else {
        return (
            true,
            vec![format!("{}: no block in the trace", script.name)],
        );
    };
    let found = differences(&got, &trace.lines)
        .into_iter()
        .map(|d| format!("{}: {d}", script.name))
        .collect();
    (true, found)
}

/// Whether `script` runs its nodes at `setting`: every one of them.
fn at(script: &Script, setting: Setting) -> bool {
    script.settings.iter().all(|s| *s == setting)
}

/// Walk every shared script whose nodes run at `setting` and that runs
/// here, each on a thread of its own, side by side. Gives how many walked
/// to their end, how many should have (every script at the setting less
/// those not run here), and every difference.
fn compare(setting: Setting) -> (usize, usize, Vec<String>) {
    let mut found = Vec::new();
    for (name, why) in UNRUN {
        if why.is_empty() || !SCRIPTS.iter().any(|s| s.name == *name) {
            found.push(format!(
                "{name}: listed as not run, with no reason or no script"
            ));
        }
    }
    let due = SCRIPTS
        .iter()
        .filter(|s| at(s, setting) && unrun(s).is_none())
        .count();
    let mut runs = Vec::new();
    for script in SCRIPTS {
        if !script.settings.contains(&setting) {
            continue;
        }
        if script.settings.len() != 2 || !at(script, setting) {
            found.push(format!(
                "{}: {:?}, where a world runs two nodes at one setting",
                script.name, script.settings
            ));
            continue;
        }
        if unrun(script).is_some() {
            continue;
        }
        let Some(m) = medium(script) else {
            found.push(format!(
                "{}: on {:?}, which no world runs, and not listed as not run",
                script.name, script.transports
            ));
            continue;
        };
        let on = setting.enabled();
        runs.push(std::thread::spawn(move || compared(script, m, on)));
    }
    let mut walked = 0;
    for run in runs {
        let (whole, more) = run.join().expect("precondition: a walk's thread reports");
        walked += usize::from(whole);
        found.extend(more);
    }
    (walked, due, found)
}

/// Check every shared script at `setting` on real nodes.
fn check(setting: Setting) {
    let (walked, due, found) = compare(setting);
    assert!(
        found.is_empty(),
        "defect: real nodes differ from the shared trace at {setting:?}:\n{}",
        found.join("\n")
    );
    assert_eq!(
        walked, due,
        "defect: {walked} shared scripts walked at {setting:?}, {due} due"
    );
}

/// Every shared script with its nodes at multipath off gives the trace's
/// node lines on a real pair. Its breaks: a crossing's move that keeps the
/// pair it leaves (`MoveKeepsOldPair`, the active pair of a crossing over
/// TCP); a later dial of the dialer's own that the responder ignores
/// (`IgnoreOwnDial`, the session); a line of the trace changed, and a
/// script left out of the walk, each a scratch edit run by hand.
#[test]
fn every_shared_schedule_gives_its_trace_on_real_nodes() {
    check(Setting::Off);
}

/// As [`every_shared_schedule_gives_its_trace_on_real_nodes`], for the
/// scripts that state multipath on, start 18's among them.
#[test]
fn every_shared_schedule_gives_its_trace_on_real_nodes_with_multipath_on() {
    check(Setting::On);
}
