//! What feeds a joint node's bundles their candidates, and when the node
//! dials a peer it holds, as the node decides both at either multipath
//! setting.
//!
//! With multipath enabled the node reports a held peer's other addresses
//! to its bundle from three feeds (`src/node/handlers/path_intake.rs`):
//! the configuration, whose pairs for the peer are offered at each
//! promotion and each won crossed handshake, when the bundle starts again
//! (`paths_renewed`); the heard frames, an authentic frame from a pair the
//! link holds no path at, that the one-path roam did not follow and that
//! is no path message (`src/node/dataplane/encrypted.rs`,
//! `account_authentic`); and the others (a beacon, a Nostr advert, an
//! operator's request), which a start stands in for with a candidate act.
//! Each feed's pairs are listed per peer, so a pair a feed already lists
//! is not offered again, nor one another feed lists; a request is always
//! fresh. With multipath disabled nothing is listed or offered.
//!
//! The dial rule here is the node's capable clause alone: a peer that has
//! shown it implements multipath, on a node with multipath enabled, is not
//! dialled while an authentic frame has arrived on any of its paths
//! within the link-dead timeout (`active_peer_link_is_live`,
//! `src/node/lifecycle/mod.rs`); the address is held as a requested
//! candidate in its place (`connect_candidate`). Every other dial goes
//! out: the node's staleness clause is left out of the world, since the
//! scripts of several starts dial a held, live peer that is not capable.

use alloc::vec::Vec;

use crate::proto::path::Source;

use super::super::super::model::history::{Addr, Node};
use super::super::party::Configured;
use super::super::world::Ms;
use super::Mode;
use super::machines::{Machines, messaged};

/// The link-dead timeout (`link_dead_timeout_secs`, 30 s,
/// `src/config/node.rs:1732`): a capable peer is live while an authentic
/// frame arrived within it.
pub const LIVE: Ms = 30_000;

/// The pairs each feed lists for one held peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listings {
    listed: Vec<(Source, Addr)>,
}

impl Listings {
    /// `source` reports the peer at `at`: whether the bundle is offered
    /// the pair. A pair the source lists already only stays listed, and
    /// one another feed lists is listed and not offered again. A request
    /// is listed by no feed, and always offered.
    pub fn report(&mut self, source: Source, at: Addr) -> bool {
        if source == Source::Request {
            return true;
        }
        if self.listed.contains(&(source, at)) {
            return false;
        }
        let elsewhere = self.listed.iter().any(|(_, a)| *a == at);
        self.listed.push((source, at));
        !elsewhere
    }
}

/// The pairs the configuration feed lists for `peer`: the address of each
/// configured dial of it, with the address it is dialled from, if any.
pub fn configured(configured: &[Configured], peer: Node) -> Vec<(Addr, Option<Addr>)> {
    configured
        .iter()
        .filter(|c| c.peer == peer)
        .map(|c| (c.to, c.from))
        .collect()
}

/// Whether an authentic frame of link message type `kind` is one the
/// heard feed reports, on a node at `mode`: `unpathed` says it came from a
/// pair the link holds no path at and the one-path roam did not follow
/// it. A path message is left out: a probe creates a path only where its
/// own rules allow.
pub fn heard(mode: Mode, unpathed: bool, kind: u8) -> bool {
    mode.enabled() && unpathed && !messaged(kind) && !fault!(HeardFeedDropped)
}

/// Whether a dial of a peer held with machines `m`, last heard at
/// `heard`, goes out at `now` from a node at `mode`: not while the peer is
/// capable and live.
pub fn dials(mode: Mode, m: &Machines, heard: Ms, now: Ms) -> bool {
    !(mode.enabled() && m.bundle().capable() && now.saturating_sub(heard) <= LIVE)
}

use super::super::super::model::history::Event;
use super::super::explore::{Act, apply};
use super::super::oracle::every_step;
use super::super::shadow::Entry;
use super::super::starts::{A, B, Maker, TCP, UDP, dial_home, home, second, settle, world_of};
use super::super::world::{Input, PathEv, PeerView, Pkt, World};

/// Run `w` wake by wake for `ms`, delivering everything and opening every
/// connect window between wakes, as a heal does.
pub(super) fn walk(w: &mut World, ms: Ms) {
    let end = w.net.now + ms;
    loop {
        settle(w);
        match w.wake() {
            Some(t) if t <= end => w.advance(),
            _ => break,
        }
    }
    w.net.now = w.net.now.max(end);
    settle(w);
}

/// Nodes 0 and 1 made by `mk`, node 0 dialing node 1 on UDP, settled.
pub(super) fn paired(mk: Maker) -> World {
    let mut w = world_of(mk, &[A, B], &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w
}

/// The frame node `x` sends node `y` at once, taken out of flight.
pub(super) fn beat(w: &mut World, x: usize, y: usize) -> Pkt {
    apply(w, Act::Frame(x));
    taken(w, x, y)
}

/// The first frame from node `x` to node `y` in flight, taken out of it.
pub(super) fn taken(w: &mut World, x: usize, y: usize) -> Pkt {
    let id = w.ids[x];
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == y && matches!(f.pkt, Pkt::Frame { id: s, .. } if s == id))
        .unwrap_or_else(|| panic!("n{x} sends n{y} a frame"));
    w.net.flight.remove(i).pkt
}

/// Deliver to node `y` the packet `pkt`, arriving from `src` at its home
/// on that transport.
pub(super) fn arrive(w: &mut World, y: usize, src: Addr, pkt: Pkt) {
    w.net.inject(y, home(y, src.transport), src, pkt);
    let id = w.net.flight.last().expect("injected").id;
    w.deliver(id);
}

/// [`paired`], then a heartbeat of node 1's arriving at node 0 from node
/// 1's TCP home, a pair node 0's link holds no path at, as a frame sent on
/// the other link of a crossing arrives; then a minute, wake by wake.
pub(super) fn crossed(mk: Maker) -> World {
    let mut w = paired(mk);
    let pkt = beat(&mut w, 1, 0);
    arrive(&mut w, 0, home(1, TCP), pkt);
    walk(&mut w, 60_000);
    w
}

/// The addresses node `x`'s live links use, its view's `needs`, sorted
/// and without repeats.
fn used(w: &World, x: usize) -> Vec<Addr> {
    let mut v = w.parties[x].view().needs;
    v.sort_unstable_by_key(|a| (a.transport, a.at));
    v.dedup();
    v
}

/// The transports node `x`'s live links use.
fn transports(w: &World, x: usize) -> Vec<u8> {
    let mut t: Vec<u8> = used(w, x).iter().map(|a| a.transport).collect();
    t.dedup();
    t
}

/// Node `x`'s view of node `y`.
pub(super) fn peer(w: &World, x: usize, y: usize) -> PeerView {
    let id = w.ids[y];
    w.parties[x]
        .view()
        .peers
        .into_iter()
        .find(|p| p.peer == id)
        .unwrap_or_else(|| panic!("n{x} holds n{y}"))
}

/// Whether a msg1 from node `x` is in flight or waits in a connect
/// window.
fn dialled(w: &World, x: usize) -> bool {
    let id = w.ids[x];
    let msg1 = |p: &Pkt| matches!(p, Pkt::Msg1 { id: s, .. } if *s == id);
    w.net.flight.iter().any(|f| msg1(&f.pkt))
        || w.net
            .conns
            .iter()
            .any(|c| c.queued.iter().any(|(_, p)| msg1(p)))
}

/// The address the frame node `x` sends node `y` now goes to.
pub(super) fn sent(w: &mut World, x: usize, y: usize) -> Addr {
    apply(w, Act::Frame(x));
    let id = w.ids[x];
    let f = w
        .net
        .flight
        .iter()
        .rev()
        .find(|f| f.to == y && matches!(f.pkt, Pkt::Frame { id: s, .. } if s == id))
        .copied()
        .unwrap_or_else(|| panic!("n{x} sends n{y} a frame"));
    w.net.flight.retain(|g| g.id != f.id);
    f.local
}

#[test]
fn an_on_pair_with_a_candidate_becomes_capable_and_holds_a_second_path() {
    let w = crossed(super::on);
    for x in 0..2 {
        assert!(
            w.parties[x].view().audit.is_empty(),
            "n{x} audits nothing: {:?}",
            w.parties[x].view().audit
        );
        assert_eq!(
            transports(&w, x),
            [UDP, TCP],
            "n{x}'s link holds a path on each transport, once the frame heard from TCP made the pair a candidate: {:?}",
            used(&w, x)
        );
    }
    assert!(every_step(&w).is_empty(), "{:?}", every_step(&w));
}

#[test]
fn an_on_end_against_an_off_end_stays_not_capable_within_the_probe_budget() {
    let control = crossed(super::on);
    assert_eq!(
        transports(&control, 0),
        [UDP, TCP],
        "precondition: with the peer on, the candidate becomes a second path"
    );
    let mut w = crossed(super::on_off);
    walk(&mut w, 60_000);
    for x in 0..2 {
        assert_eq!(
            used(&w, x),
            [if x == 0 { home(1, UDP) } else { home(0, UDP) }],
            "n{x}'s link keeps its one path: the peer with multipath off answers no capability probe: {:?}",
            used(&w, x)
        );
    }
    assert!(every_step(&w).is_empty(), "{:?}", every_step(&w));
}

#[test]
fn a_capable_live_peer_is_not_dialled_and_a_stale_or_not_capable_one_is() {
    let mut w = crossed(super::on);
    assert_eq!(
        transports(&w, 0),
        [UDP, TCP],
        "precondition: the peer is capable"
    );
    w.net.flight.clear();
    w.input(
        0,
        Input::Dial {
            peer: B,
            to: second(1, UDP),
            from: None,
        },
    );
    assert!(
        !dialled(&w, 0),
        "a capable peer whose link is live is not dialled"
    );
    // Thirty-one seconds with nothing delivered: the link is stale.
    let t = w.net.now + 31_000;
    w.run_until(t);
    w.input(
        0,
        Input::Dial {
            peer: B,
            to: second(1, UDP),
            from: None,
        },
    );
    assert!(
        dialled(&w, 0),
        "a capable peer whose link is stale is dialled"
    );

    let mut w = crossed(super::on_off);
    assert_eq!(
        transports(&w, 0),
        [UDP],
        "precondition: the peer is not capable"
    );
    w.net.flight.clear();
    w.input(
        0,
        Input::Dial {
            peer: B,
            to: second(1, UDP),
            from: None,
        },
    );
    assert!(
        dialled(&w, 0),
        "a peer that is not capable is dialled while its link is live"
    );
}

#[test]
fn a_rekey_answer_goes_on_the_arrival_path_at_on_and_the_established_link_at_off() {
    // On: the msg1 arrives on the path node 1 does not send on.
    let mut w = crossed(super::on);
    walk(&mut w, 40_000);
    let active = sent(&mut w, 1, 0);
    let other = used(&w, 1)
        .into_iter()
        .find(|a| a.transport != active.transport)
        .expect("precondition: node 1 holds a second path");
    w.net.flight.clear();
    w.input(0, Input::Rekey { peer: B });
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == 1 && matches!(f.pkt, Pkt::Msg1 { .. }))
        .expect("node 0 sends a rekey msg1");
    let msg1 = w.net.flight.remove(i).pkt;
    arrive(&mut w, 1, other, msg1);
    let answer = w
        .net
        .flight
        .iter()
        .find(|f| f.to == 0 && matches!(f.pkt, Pkt::Msg2 { .. }))
        .copied()
        .expect("node 1 answers");
    assert_eq!(
        answer.local.transport, other.transport,
        "at On the answer goes back on the msg1's arrival path, not the active path at {active:?}"
    );
    assert!(every_step(&w).is_empty(), "{:?}", every_step(&w));

    // Off: the msg1 arrives at the setup address after the one path
    // roamed off it.
    let mut w = paired(super::off);
    walk(&mut w, 40_000);
    let pkt = beat(&mut w, 1, 0);
    arrive(&mut w, 0, second(1, UDP), pkt);
    w.net.flight.clear();
    w.input(1, Input::Rekey { peer: A });
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == 0 && matches!(f.pkt, Pkt::Msg1 { .. }))
        .expect("node 1 sends a rekey msg1");
    let f = w.net.flight[i];
    assert_eq!(f.src, home(1, UDP), "precondition: from the setup address");
    w.deliver(f.id);
    let answer = w
        .net
        .flight
        .iter()
        .find(|f| f.to == 1 && matches!(f.pkt, Pkt::Msg2 { .. }))
        .copied()
        .expect("node 0 answers");
    assert_eq!(
        answer.local,
        second(1, UDP),
        "at Off the answer goes on the established link, its one path"
    );
    assert!(every_step(&w).is_empty(), "{:?}", every_step(&w));
}

#[test]
fn a_closed_connection_on_a_link_of_two_paths_fails_that_path_and_keeps_the_link() {
    let mut w = crossed(super::on);
    let before = peer(&w, 0, 1);
    let c = w
        .net
        .conns
        .iter()
        .find(|c| {
            c.ends[0].node == 0
                && c.ends[0].remote == home(1, TCP)
                && c.state == super::super::world::State::Open
        })
        .map(|c| c.id)
        .expect("precondition: node 0's path to node 1's TCP home has a connection");
    w.fail(c, 0);
    settle(&mut w);
    let after = peer(&w, 0, 1);
    assert_eq!(
        (after.cur, after.link, after.origin),
        (before.cur, before.link, before.origin),
        "node 0 keeps the link and its session"
    );
    let lost = w.parties[0].view().log.iter().any(|e| {
        matches!(
            e,
            Entry::Ev {
                ev: Event::Lost,
                ..
            }
        )
    });
    assert!(!lost, "node 0 lost no link");
    assert_eq!(
        sent(&mut w, 0, 1).transport,
        UDP,
        "node 0's frames go on the path left"
    );
}

#[test]
fn a_path_message_roams_a_one_path_link_at_off_and_not_at_on() {
    for (mk, mode) in [(super::off_on as Maker, Mode::Off), (super::on, Mode::On)] {
        let mut w = paired(mk);
        w.net.flight.clear();
        w.input(
            1,
            Input::Path(PathEv::Candidate {
                peer: A,
                at: home(0, TCP),
                from: None,
                source: Source::Discovery,
            }),
        );
        let mut probe = None;
        for _ in 0..8 {
            if w.net
                .flight
                .iter()
                .any(|f| f.to == 0 && matches!(f.pkt, Pkt::Frame { .. }))
            {
                probe = Some(taken(&mut w, 1, 0));
                break;
            }
            w.advance();
        }
        let probe = probe.expect("precondition: node 1 sends a capability probe");
        arrive(&mut w, 0, second(1, UDP), probe);
        let to = sent(&mut w, 0, 1);
        let want = match mode {
            Mode::Off => second(1, UDP),
            Mode::On => home(1, UDP),
        };
        assert_eq!(
            to,
            want,
            "at {} node 0's frames go to {want:?} after a path message from node 1's second address",
            mode.name()
        );
    }
}
