//! Anonymous shared-media beacons from a peer the node is already linked
//! with.
//!
//! A beacon that names no key is dialled, since only the handshake can say
//! who sent it. Once a capable peer holds the beacon's pair as a proven path
//! the beacon is that peer's, and with multipath enabled it is not dialled
//! while the link is live (multipath v1 draft, Section 5.4). A dial there
//! completes as a crossed handshake, which starts the bundle again and
//! discards the standby the link would switch to. A beacon at a pair the
//! peer holds as a path still Probing, as an interface's return leaves it,
//! is not dialled while the link is live either: it brings that path's
//! next probe forward, and is not listed as the peer's beacon, since only
//! the probe's answer can prove the pair. A beacon at a pair the peer does
//! not hold, or gave up on unproven (Dead, never acked), is still dialled:
//! the beacon is not authenticated, and names nobody.
//!
//! A crossed move that takes a link off the pair its record names leaves
//! that pair keyed to the link, so a beacon there is not dialled with
//! multipath off at either end, as with it on at both.

use super::paths::{
    active_of, capable_at, disabled, enabled, loopback, quiet_for, second_transport, state_at, t2,
};
use super::rekey_parity::{linked_pair, pump};
use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, add_loopback_alias, cleanup_nodes, loopback_tap,
};
use super::*;
use crate::config::Config;
use crate::node::handlers::path_intake::Feed;
use crate::peer::{Match, PathState, PeerInstant, peer_now};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Two nodes linked on their first transport, each with a second loopback
/// transport `t2()` that auto-connects, both running, and the index of the
/// smaller node by address. Remakes the pair until `want(smaller)` holds.
async fn pair(
    cfg0: fn() -> Config,
    cfg1: fn() -> Config,
    want: fn(usize) -> bool,
) -> (Vec<TestNode>, usize) {
    loop {
        let mut nodes = linked_pair(cfg0(), cfg1()).await;
        let smaller = usize::from(nodes[1].node.node_addr() < nodes[0].node.node_addr());
        if !want(smaller) {
            cleanup_nodes(&mut nodes).await;
            continue;
        }
        for tn in &mut nodes {
            second_transport(tn, t2(), 1280);
            tn.node.supervisor.state = NodeState::Running;
            loopback(tn, t2()).set_autoconnect(true);
        }
        return (nodes, smaller);
    }
}

/// The address of `nodes[i]`'s second transport.
fn t2_addr(nodes: &[TestNode], i: usize) -> TransportAddr {
    loopback(&nodes[i], t2()).my_addr().clone()
}

/// The other node's address.
fn other(nodes: &[TestNode], x: usize) -> NodeAddr {
    *nodes[1 - x].node.node_addr()
}

/// `nodes[x]` hears an anonymous beacon from the other node's second
/// transport and runs its discovery tick; returns whether a handshake
/// started.
async fn hear(nodes: &mut [TestNode], x: usize) -> bool {
    let from = t2_addr(nodes, 1 - x);
    hear_from(nodes, x, from).await
}

/// `nodes[x]` hears an anonymous beacon from `from` on its second transport
/// and runs its discovery tick; returns whether a handshake started.
async fn hear_from(nodes: &mut [TestNode], x: usize, from: TransportAddr) -> bool {
    loopback(&nodes[x], t2()).inject_anonymous(from);
    nodes[x].node.poll_transport_discovery().await;
    nodes[x]
        .node
        .peer_machines
        .values()
        .any(|m| m.leg().is_some())
}

/// What `nodes[x]` holds the other node's second-transport pair as.
fn held(nodes: &[TestNode], x: usize) -> Match {
    nodes[x]
        .node
        .get_peer(&other(nodes, x))
        .expect("the peer is held")
        .path_match(t2(), &t2_addr(nodes, 1 - x))
}

/// The session index `nodes[x]` holds for the other node.
fn index(nodes: &[TestNode], x: usize) -> Option<SessionIndex> {
    nodes[x]
        .node
        .get_peer(&other(nodes, x))
        .and_then(|p| p.our_index())
}

/// The first anonymous beacon on a pair the link does not hold is dialled
/// (only the handshake can name its sender) and the smaller node `s`'s won
/// crossed handshake moves the link onto it. Each end is then given the
/// other's first-transport pair as a candidate, which makes the peer
/// capable and leaves that pair a Live standby, as a configured address
/// does in a two-path deployment. Returns the pair and `s`.
async fn moved_with_standby(
    cfg0: fn() -> Config,
    cfg1: fn() -> Config,
    want: fn(usize) -> bool,
) -> (Vec<TestNode>, usize) {
    let (mut nodes, s) = pair(cfg0, cfg1, want).await;
    assert!(
        hear(&mut nodes, s).await,
        "precondition: first contact is dialled"
    );
    pump(&mut nodes).await;
    for x in [0, 1] {
        let (peer, t1, a1) = (
            other(&nodes, x),
            nodes[x].transport_id,
            nodes[1 - x].addr.clone(),
        );
        nodes[x].node.offer_path(&peer, t1, a1).await;
    }
    pump(&mut nodes).await;
    (nodes, s)
}

/// Assert that each end holds the other as capable, its second-transport
/// pair as a proven path and its first-transport pair as a Live standby.
fn assert_two_paths(nodes: &[TestNode]) {
    for x in [0, 1] {
        let peer = other(nodes, x);
        assert!(capable_at(&nodes[x], &peer), "precondition: capable at {x}");
        assert!(
            matches!(held(nodes, x), Match::Proven { .. }),
            "precondition: node {x} holds the beacon's pair as a proven path"
        );
        let (t1, a1) = (nodes[x].transport_id, &nodes[1 - x].addr);
        assert_eq!(
            state_at(&nodes[x], &peer, t1, a1),
            Some(PathState::Live),
            "precondition: node {x} holds the first-transport pair Live"
        );
    }
}

/// From the move on, each end holds the other's beacon pair as a proven
/// path of a capable peer, and no beacon from it is dialled at either end:
/// the link keeps its session at both ends. Mutation: take no anonymous
/// beacon as a linked peer's (the gate removed), which reds the next test
/// too.
#[tokio::test]
async fn an_anonymous_beacon_at_a_proven_path_of_a_live_capable_peer_is_not_dialled() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    let l = 1 - s;
    assert_two_paths(&nodes);
    let before = (index(&nodes, s), index(&nodes, l));
    for x in [l, s, l, s] {
        assert!(
            !hear(&mut nodes, x).await,
            "node {x} dialled a live capable peer at a proven path"
        );
        pump(&mut nodes).await;
    }
    assert_eq!(
        (index(&nodes, s), index(&nodes, l)),
        before,
        "the link kept its session at both ends"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A proven pair the link is not active on is the peer's too: a beacon at
/// the Live standby is not dialled, which is what keeps the standby once
/// the link has switched off it. The smaller node's link moved onto t2, so
/// its first-transport pair is that standby. That pair is also the link
/// record's own, and so keyed in `addr_to_link`; the test drops the entry
/// to stand for a standby at another pair (a configured or advertised
/// address), so that only the gate stands between the beacon and a dial.
/// Mutation: take only the active proven pair as the peer's.
#[tokio::test]
async fn an_anonymous_beacon_at_a_proven_standby_of_a_live_capable_peer_is_not_dialled() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let peer = other(&nodes, s);
    let (t1, from) = (nodes[s].transport_id, nodes[1 - s].addr.clone());
    loopback(&nodes[s], t1).set_autoconnect(true);
    let m = nodes[s]
        .node
        .get_peer(&peer)
        .expect("the peer is held")
        .path_match(t1, &from);
    assert!(
        matches!(m, Match::Proven { active: false, .. }),
        "precondition: the first-transport pair is a proven standby, got {m:?}"
    );
    // The link record's own pair stays keyed; dropping the entry stands for
    // a standby at a pair other than the link's own.
    nodes[s].node.links.raw_index().remove(&(t1, from.clone()));
    loopback(&nodes[s], t1).inject_anonymous(from);
    nodes[s].node.poll_transport_discovery().await;
    assert!(
        !nodes[s]
            .node
            .peer_machines
            .values()
            .any(|m| m.leg().is_some()),
        "node {s} dialled a live capable peer at its proven standby"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A proven pair whose path has gone Dead is still the peer's while the
/// link is live: a path given up on by unanswered probes while the medium
/// still carries the peer's beacons, as under one-way loss, keeps its
/// beacon from being dialled. The smaller node's first-transport pair is
/// the proven standby; it is marked Dead and its beacon is heard. Its
/// entry in `addr_to_link`, there because it is the link record's own
/// pair, is dropped to stand for a Dead path at another pair, so that only
/// the gate stands between the beacon and a dial. Mutation: take only a
/// proven pair whose path is Live as the peer's.
#[tokio::test]
async fn an_anonymous_beacon_at_a_proven_dead_path_of_a_live_capable_peer_is_not_dialled() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let peer = other(&nodes, s);
    let (t1, from) = (nodes[s].transport_id, nodes[1 - s].addr.clone());
    loopback(&nodes[s], t1).set_autoconnect(true);
    nodes[s]
        .node
        .get_peer_mut(&peer)
        .expect("the peer is held")
        .kill_path(t1, &from);
    let m = nodes[s]
        .node
        .get_peer(&peer)
        .expect("the peer is held")
        .path_match(t1, &from);
    assert!(
        matches!(
            m,
            Match::Proven {
                active: false,
                state: PathState::Dead
            }
        ),
        "precondition: the first-transport pair is a proven Dead path, got {m:?}"
    );
    // The link record's own pair stays keyed; dropping the entry stands for
    // a Dead path at a pair other than the link's own.
    nodes[s].node.links.raw_index().remove(&(t1, from.clone()));
    assert!(capable_at(&nodes[s], &peer), "precondition: capable");
    loopback(&nodes[s], t1).inject_anonymous(from);
    nodes[s].node.poll_transport_discovery().await;
    assert!(
        !nodes[s]
            .node
            .peer_machines
            .values()
            .any(|m| m.leg().is_some()),
        "node {s} dialled a live capable peer at its proven Dead path"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The beacons leave the standby in place, so when the beacon pair's
/// interface goes the link switches to the standby and the peer is kept
/// (draft Sections 5.6 and 5.9). Mutation: take no anonymous beacon as a
/// linked peer's (the gate removed); the dial's crossed handshake starts
/// the bundle again without the standby, and the interface loss removes
/// the peer.
#[tokio::test]
async fn beacons_from_a_linked_peer_leave_its_standby_for_the_interface_loss_to_switch_to() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    for x in [1 - s, s] {
        hear(&mut nodes, x).await;
        pump(&mut nodes).await;
    }
    let peer = other(&nodes, s);
    assert_eq!(
        nodes[s].node.path_presence(t2(), false).await,
        0,
        "the peer is kept when the beacon pair's interface goes"
    );
    let standby = (nodes[s].transport_id, nodes[1 - s].addr.clone());
    assert_eq!(
        active_of(&nodes[s], &peer),
        standby,
        "the link is on the standby"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Failover is unaffected: once a capable peer has been silent past the
/// link-dead timeout, a beacon at its proven path is dialled again.
/// Mutation: skip the beacon whatever the link's liveness.
#[tokio::test]
async fn an_anonymous_beacon_at_a_proven_path_of_a_silent_peer_is_dialled() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let peer = other(&nodes, s);
    let dead = nodes[s].node.config().node.link_dead_timeout_secs + 1;
    quiet_for(&mut nodes[s], &peer, dead);
    assert!(
        hear(&mut nodes, s).await,
        "a beacon of a peer silent past link-dead is dialled"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The rule covers a capable peer only: with the peer's multipath off, a
/// beacon at the pair the link moved to is dialled as without multipath.
/// Mutation: drop the capability check.
#[tokio::test]
async fn an_anonymous_beacon_of_a_peer_not_known_capable_is_dialled_as_before() {
    // Node 0 has multipath on and is the smaller, so its won crossed
    // handshake moves its link onto the beacon's pair; node 1 has it off.
    let (mut nodes, s) = moved_with_standby(enabled, disabled, |s| s == 0).await;
    assert_eq!(s, 0);
    assert!(
        !capable_at(&nodes[0], &other(&nodes, 0)),
        "precondition: not capable"
    );
    assert!(
        matches!(held(&nodes, 0), Match::Proven { .. }),
        "precondition: the link is on the beacon's pair"
    );
    assert!(
        hear(&mut nodes, 0).await,
        "a peer not known to be capable is dialled as before"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A second address of the other node's on its second transport, which a
/// dial reaches but the link does not hold.
fn fresh_addr(nodes: &[TestNode], x: usize) -> TransportAddr {
    add_loopback_alias(&t2_addr(nodes, 1 - x), t2())
}

/// What `nodes[x]` holds (`t2()`, `addr`) as, for the other node.
fn held_at(nodes: &[TestNode], x: usize, addr: &TransportAddr) -> Match {
    nodes[x]
        .node
        .get_peer(&other(nodes, x))
        .expect("the peer is held")
        .path_match(t2(), addr)
}

/// A beacon is the live capable peer's only at a pair the link holds: one
/// from a pair it does not hold, such as a new neighbour's first contact,
/// is dialled. Mutation: take every anonymous beacon as the capable peer's
/// whatever its pair.
#[tokio::test]
async fn an_anonymous_beacon_at_a_pair_a_live_capable_peer_does_not_hold_is_dialled() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let fresh = fresh_addr(&nodes, s);
    assert_eq!(
        held_at(&nodes, s, &fresh),
        Match::None,
        "precondition: not held"
    );
    assert!(
        hear_from(&mut nodes, s, fresh).await,
        "a beacon at a pair the peer does not hold is dialled"
    );
    cleanup_nodes(&mut nodes).await;
}

/// What `nodes[x]`'s path to the other node at (`t2()`, `addr`) is: its
/// state, whether one of our probes on it has been answered, how many of
/// its probes are outstanding and when its next is due.
fn probing_at(
    nodes: &[TestNode],
    x: usize,
    addr: &TransportAddr,
) -> Option<(PathState, bool, usize, Option<PeerInstant>)> {
    let peer = nodes[x].node.get_peer(&other(nodes, x))?;
    let paths = peer.bundle()?.paths();
    let path = paths.get(paths.find(t2(), addr)?)?;
    let live = path.live();
    Some((
        path.state(),
        path.acked(),
        live.outstanding(),
        live.next_at(),
    ))
}

/// Whether `nodes[x]` holds (`t2()`, `addr`) as a path Probing and never
/// acked, with none of its probes outstanding and its next not yet due: a
/// probe on it now can only be one a beacon brought forward.
fn in_window(nodes: &[TestNode], x: usize, addr: &TransportAddr) -> bool {
    probing_at(nodes, x, addr).is_some_and(|(state, acked, outstanding, next)| {
        state == PathState::Probing
            && !acked
            && outstanding == 0
            && next.is_some_and(|at| at > peer_now())
    })
}

/// Assert [`in_window`], naming what does not hold.
fn assert_window(nodes: &[TestNode], x: usize, addr: &TransportAddr) {
    let got = probing_at(nodes, x, addr);
    assert!(
        in_window(nodes, x, addr),
        "precondition: node {x} holds the pair Probing, never acked, with no probe \
         outstanding and the next ahead; got {got:?} at {:?}",
        peer_now()
    );
}

/// Frames sent to one loopback address, taken off the wire: until
/// [`Cut::mend`], whatever goes to the address lands here instead of at
/// its node, as on a medium carrying nothing that way.
struct Cut {
    /// The address cut off.
    addr: TransportAddr,
    /// What the registry delivered to the address before the cut.
    entry: (TransportId, UnboundedSender<ReceivedPacket>),
    /// What was sent to the address since.
    rx: UnboundedReceiver<ReceivedPacket>,
}

impl Cut {
    /// Cut off `addr`.
    fn new(addr: &TransportAddr) -> Self {
        let (tx, rx) = unbounded_channel();
        let mut registry = LOOPBACK_REGISTRY.lock().unwrap();
        let entry = registry
            .get(addr)
            .expect("the address is registered")
            .clone();
        registry.insert(addr.clone(), (entry.0, tx));
        Self {
            addr: addr.clone(),
            entry,
            rx,
        }
    }

    /// Take what was sent to the address since the last call.
    fn taken(&mut self) -> Vec<ReceivedPacket> {
        let mut seen = Vec::new();
        while let Ok(p) = self.rx.try_recv() {
            seen.push(p);
        }
        seen
    }

    /// Deliver `packets` to the address's node after all.
    fn pass(&self, packets: Vec<ReceivedPacket>) {
        for p in packets {
            self.entry.1.send(p).expect("the node's channel is open");
        }
    }

    /// Restore the address.
    fn mend(self) {
        LOOPBACK_REGISTRY
            .lock()
            .unwrap()
            .insert(self.addr, self.entry);
    }
}

/// Run `nodes[x]`'s path tick every 50 ms, delivering every frame between
/// the nodes as it goes, until `x` holds (`t2()`, `addr`) [`in_window`]
/// after at least `probes` of its probes, which `taken` collects and
/// counts. Panics after 10 s.
async fn until_window(
    nodes: &mut [TestNode],
    x: usize,
    addr: &TransportAddr,
    probes: usize,
    taken: &mut dyn FnMut() -> usize,
) -> usize {
    let mut sent = taken();
    for _ in 0..200 {
        if sent >= probes && in_window(nodes, x, addr) {
            return sent;
        }
        crate::time::advance(Duration::from_millis(50));
        nodes[x].node.path_tick().await;
        pump(nodes).await;
        sent += taken();
    }
    panic!(
        "precondition: no window after {sent} probes: {:?}",
        probing_at(nodes, x, addr)
    );
}

/// The smaller node `s` of [`moved_with_standby`]'s pair, with the
/// interface of the beacon's pair gone and back, as kind C has it. `s`
/// first hears the peer's second-transport beacon, so the beacon feed
/// lists the pair. Its interface going switches the link to the
/// first-transport standby; on its return the pair is admitted again as a
/// Probing path and probed at once. The peer's second-transport address
/// is cut off from then on, so those probes go unanswered, and the tick
/// runs until a window after at least three of them. Returns the nodes,
/// `s`, the peer's second-transport address and its [`Cut`].
async fn returned_and_probing() -> (Vec<TestNode>, usize, TransportAddr, Cut) {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let peer = other(&nodes, s);
    let a2 = t2_addr(&nodes, 1 - s);
    assert!(!hear(&mut nodes, s).await, "precondition: not dialled");
    assert_eq!(
        nodes[s].node.path_presence(t2(), false).await,
        0,
        "precondition: the peer is kept when the interface goes"
    );
    let standby = (nodes[s].transport_id, nodes[1 - s].addr.clone());
    assert_eq!(
        active_of(&nodes[s], &peer),
        standby,
        "precondition: the link is on the standby"
    );
    let mut cut = Cut::new(&a2);
    nodes[s].node.path_presence(t2(), true).await;
    let mut taken = || cut.taken().len();
    let sent = until_window(&mut nodes, s, &a2, 3, &mut taken).await;
    assert!(sent >= 3, "precondition: {sent} probes went unanswered");
    (nodes, s, a2, cut)
}

/// Assert what [`returned_and_probing`] promises before its beacon: the
/// peer is capable and live, and the pair is held Probing, never acked, in
/// a window, and is not keyed in `addr_to_link`, so only the gate stands
/// between the beacon and a dial.
fn assert_returned(nodes: &[TestNode], s: usize, a2: &TransportAddr) {
    let peer = other(nodes, s);
    assert!(capable_at(&nodes[s], &peer), "precondition: capable");
    assert!(
        nodes[s].node.active_peer_link_is_live(&peer),
        "precondition: the link is live"
    );
    assert_eq!(held(nodes, s), Match::Unproven, "precondition: unproven");
    assert_window(nodes, s, a2);
    assert!(
        !nodes[s]
            .node
            .links
            .index()
            .contains_key(&(t2(), a2.clone())),
        "precondition: the pair is not keyed in addr_to_link"
    );
}

/// Kind C: the interface of the beacon's pair returns, and the pair is a
/// path Probing again while its probes go unanswered. The peer's beacon
/// there is not dialled; it brings the path's next probe forward in its
/// tick, and once that probe is answered the pair is proven Live and the
/// link kept its session. Mutations: the gate taking a proven pair only
/// (as before), which dials; the beacon stepping nothing into the path
/// machine, which sends no probe.
#[tokio::test]
async fn a_beacon_while_a_returned_interfaces_path_is_still_probing_is_probed_not_dialled() {
    crate::time::freeze();
    let (mut nodes, s, a2, mut cut) = returned_and_probing().await;
    assert_returned(&nodes, s, &a2);
    let before = (index(&nodes, s), index(&nodes, 1 - s));
    assert!(
        !hear(&mut nodes, s).await,
        "node {s} dialled a live capable peer at a pair it is probing"
    );
    let sent = cut.taken();
    assert_eq!(sent.len(), 1, "one probe on the pair in the beacon's tick");
    cut.pass(sent);
    cut.mend();
    pump(&mut nodes).await;
    assert_eq!(
        held(&nodes, s),
        Match::Proven {
            active: false,
            state: PathState::Live
        },
        "the beacon's probe proved the pair"
    );
    assert_eq!(
        (index(&nodes, s), index(&nodes, 1 - s)),
        before,
        "the link kept its session at both ends"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A beacon brings a probe forward once while the path is Probing: a
/// second, once the first one's probe has timed out unanswered and before
/// the cadence's next, sends nothing and dials nothing. Mutation: let
/// every beacon bring a probe forward.
#[tokio::test]
async fn a_second_beacon_at_a_probing_pair_brings_nothing_forward_and_dials_nothing() {
    crate::time::freeze();
    let (mut nodes, s, a2, mut cut) = returned_and_probing().await;
    assert_returned(&nodes, s, &a2);
    assert!(!hear(&mut nodes, s).await, "the first beacon was dialled");
    assert_eq!(
        cut.taken().len(),
        1,
        "precondition: the first beacon's probe"
    );
    let mut taken = || cut.taken().len();
    until_window(&mut nodes, s, &a2, 0, &mut taken).await;
    assert_returned(&nodes, s, &a2);
    assert!(!hear(&mut nodes, s).await, "the second beacon was dialled");
    assert_eq!(cut.taken().len(), 0, "the second beacon sent a probe");
    cleanup_nodes(&mut nodes).await;
}

/// The gate holds on a transport that does not auto-connect too, where no
/// beacon is dialled anyway: a beacon at a pair the peer is probing brings
/// its probe forward there as well (multipath v1 draft, Section 5.5: no
/// transport setting forbids probing a peer the node is linked with).
/// Mutation: bring the probe forward only on a transport that dials.
#[tokio::test]
async fn a_beacon_at_a_probing_pair_on_a_transport_that_does_not_auto_connect_is_probed() {
    crate::time::freeze();
    let (mut nodes, s, a2, mut cut) = returned_and_probing().await;
    loopback(&nodes[s], t2()).set_autoconnect(false);
    assert_returned(&nodes, s, &a2);
    assert!(!hear(&mut nodes, s).await, "a beacon was dialled");
    assert_eq!(cut.taken().len(), 1, "one probe on the pair in the tick");
    cleanup_nodes(&mut nodes).await;
}

/// Failover is unaffected: once a capable peer has been silent past the
/// link-dead timeout, a beacon at a pair it is probing is dialled.
/// Mutation: hold the dial of such a beacon whatever the liveness.
#[tokio::test]
async fn a_beacon_at_a_probing_pair_of_a_silent_peer_is_dialled() {
    crate::time::freeze();
    let (mut nodes, s, a2, _cut) = returned_and_probing().await;
    assert_returned(&nodes, s, &a2);
    let peer = other(&nodes, s);
    let dead = nodes[s].node.config().node.link_dead_timeout_secs + 1;
    quiet_for(&mut nodes[s], &peer, dead);
    assert!(
        hear(&mut nodes, s).await,
        "a beacon of a peer silent past link-dead is dialled"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A pair the link held and gave up on unproven, Dead and never acked, is
/// not the peer's, and its beacon is dialled as before. Mutation: take any
/// pair held unproven as one still Probing.
#[tokio::test]
async fn an_anonymous_beacon_at_a_dead_unproven_pair_of_a_live_capable_peer_is_dialled() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let fresh = fresh_addr(&nodes, s);
    let peer = other(&nodes, s);
    {
        let p = nodes[s].node.get_peer_mut(&peer).expect("the peer is held");
        p.admit_path(t2(), fresh.clone());
        p.kill_path(t2(), &fresh);
    }
    assert_eq!(
        held_at(&nodes, s, &fresh),
        Match::Unproven,
        "precondition: held unproven"
    );
    assert_eq!(
        state_at(&nodes[s], &peer, t2(), &fresh),
        Some(PathState::Dead),
        "precondition: Dead"
    );
    assert!(
        hear_from(&mut nodes, s, fresh).await,
        "a beacon at a pair given up on unproven is dialled"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Make `peer` capable at `tn`, as any path message from it does: step a
/// `PathClose` naming no path into its path machine.
async fn make_capable(tn: &mut TestNode, peer: &NodeAddr, from: TransportAddr) {
    use fips_core::proto::path::Input;
    use fips_core::proto::path::wire::{PathClose, PathCloseReason};
    let msg = PathClose {
        path_id: u32::MAX,
        reason: PathCloseReason::Operator,
    };
    let transport = tn.transport_id;
    tn.node
        .step_path(
            peer,
            Input::Close {
                transport,
                addr: from,
                msg,
            },
        )
        .await;
    assert!(capable_at(tn, peer), "precondition: capable");
}

/// A pair two capable linked peers both hold, proven at one and Probing
/// at the other, is the beacon of the one that proved it, whichever the
/// node's peers yield first: tried both ways round, so one of the two
/// lookups meets the probing peer first. Mutation: take the first peer
/// that holds the pair proven or Probing.
#[tokio::test]
async fn a_pair_proven_at_one_peer_and_probing_at_another_is_the_proven_peers_beacon() {
    use super::spanning_tree::{drain_all_packets, initiate_handshake, make_test_node_with_config};
    use crate::node::lifecycle::Held;
    let mut nodes = vec![
        make_test_node_with_config(enabled(), 1280).await,
        make_test_node_with_config(enabled(), 1280).await,
        make_test_node_with_config(enabled(), 1280).await,
    ];
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 0, 2).await;
    drain_all_packets(&mut nodes, false).await;
    let t1 = nodes[0].transport_id;
    let peers = [*nodes[1].node.node_addr(), *nodes[2].node.node_addr()];
    for (k, peer) in peers.iter().enumerate() {
        let from = nodes[k + 1].addr.clone();
        make_capable(&mut nodes[0], peer, from).await;
    }
    let pairs = [
        TransportAddr::from_string("loopback:held-by-two-a"),
        TransportAddr::from_string("loopback:held-by-two-b"),
    ];
    for (k, pair) in pairs.iter().enumerate() {
        let (proven, probing) = (peers[k], peers[1 - k]);
        for at in [proven, probing] {
            nodes[0]
                .node
                .get_peer_mut(&at)
                .expect("the peer is held")
                .admit_path(t1, pair.clone());
        }
        nodes[0]
            .node
            .get_peer_mut(&proven)
            .expect("the peer is held")
            .ack_path(t1, pair);
        assert_eq!(
            nodes[0].node.beacon_peer(t1, pair),
            Some((proven, Held::Proven)),
            "the pair proven at {proven:?} and Probing at {probing:?}"
        );
    }
    cleanup_nodes(&mut nodes).await;
}

/// A pair the link holds but has not proven, still Probing and never acked,
/// is not dialled while the link is live, and is not taken as the peer's:
/// the beacon brings the path's next probe forward and is not listed for
/// the peer. The pair is a tap no one answers, so its probes go
/// unanswered, and the beacon comes in a window after three of them.
/// Mutations: the gate taking a proven pair only (as before), which dials
/// and sends no probe; listing the probing pair as the peer's beacon.
#[tokio::test]
async fn an_anonymous_beacon_at_a_probing_pair_of_a_live_capable_peer_is_probed_not_dialled() {
    crate::time::freeze();
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let (tap, mut rx) = loopback_tap(t2());
    let peer = other(&nodes, s);
    nodes[s]
        .node
        .get_peer_mut(&peer)
        .expect("the peer is held")
        .admit_path(t2(), tap.clone());
    assert_eq!(
        held_at(&nodes, s, &tap),
        Match::Unproven,
        "precondition: held unproven"
    );
    let mut taken = || {
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    };
    until_window(&mut nodes, s, &tap, 3, &mut taken).await;
    assert_window(&nodes, s, &tap);
    assert!(
        !hear_from(&mut nodes, s, tap.clone()).await,
        "node {s} dialled a live capable peer at a pair it is probing"
    );
    assert_eq!(taken(), 1, "one probe on the pair in the beacon's tick");
    assert!(
        !nodes[s]
            .node
            .paths
            .listings
            .listed(&peer, Feed::Beacon)
            .contains(&(t2(), tap.clone())),
        "the beacon feed lists the probing pair for the peer"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A held pair one of our probes has had answered is proven, and stays the
/// peer's when it is Probing again, as a returned carrier leaves a path:
/// its beacon is not dialled. Mutation: take a proven pair as the peer's
/// only when its path is not Probing.
#[tokio::test]
async fn an_anonymous_beacon_at_an_acked_probing_pair_of_a_live_capable_peer_is_not_dialled() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let fresh = fresh_addr(&nodes, s);
    let peer = other(&nodes, s);
    {
        let p = nodes[s].node.get_peer_mut(&peer).expect("the peer is held");
        p.admit_path(t2(), fresh.clone());
        p.ack_path(t2(), &fresh);
    }
    let m = held_at(&nodes, s, &fresh);
    assert!(
        matches!(
            m,
            Match::Proven {
                active: false,
                state: PathState::Probing
            }
        ),
        "precondition: an acked Probing pair, got {m:?}"
    );
    assert!(
        !hear_from(&mut nodes, s, fresh).await,
        "node {s} dialled a live capable peer at its acked Probing pair"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The beacon taken as the peer's is reported to the peer's paths as its
/// beacon, as a named beacon of a linked peer is, so the beacon feed lists
/// the pair and its silence unlists it (draft Section 5.6). Mutation: skip
/// the beacon without reporting it.
#[tokio::test]
async fn an_anonymous_beacon_at_a_proven_path_is_listed_as_the_peers_beacon() {
    let (mut nodes, s) = moved_with_standby(enabled, enabled, |_| true).await;
    assert_two_paths(&nodes);
    let peer = other(&nodes, s);
    let pair = (t2(), t2_addr(&nodes, 1 - s));
    assert!(
        !nodes[s]
            .node
            .paths
            .listings
            .listed(&peer, Feed::Beacon)
            .contains(&pair),
        "precondition: the beacon feed does not list the pair"
    );
    assert!(!hear(&mut nodes, s).await, "precondition: not dialled");
    assert!(
        nodes[s]
            .node
            .paths
            .listings
            .listed(&peer, Feed::Beacon)
            .contains(&pair),
        "the beacon feed lists the pair for the peer"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Two nodes with multipath on, each with a second loopback transport
/// `t2()`, after the smaller node's dial on the first transport has been
/// answered only once an anonymous beacon on the second made first contact
/// and the link promoted there. The late answer is a crossed handshake the
/// smaller node wins, and it moves the link onto the first transport, which
/// starts the path machine again with that pair alone. Returns the nodes and
/// the index of the smaller one, with every step up to the move asserted.
async fn late_answer() -> (Vec<TestNode>, usize) {
    late_with(enabled, enabled).await
}

/// [`late_answer`] with the smaller node built from `cfg_s` and the larger
/// from `cfg_l`.
async fn late_with(cfg_s: fn() -> Config, cfg_l: fn() -> Config) -> (Vec<TestNode>, usize) {
    use super::rekey_parity::deliver;
    use super::spanning_tree::{initiate_handshake, make_test_node_with_config};
    let mut nodes;
    loop {
        nodes = vec![
            make_test_node_with_config(cfg_s(), 1280).await,
            make_test_node_with_config(cfg_l(), 1280).await,
        ];
        if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
            break;
        }
        cleanup_nodes(&mut nodes).await;
    }
    let (s, l) = (0, 1);
    for tn in &mut nodes {
        second_transport(tn, t2(), 1280);
        tn.node.supervisor.state = NodeState::Running;
        loopback(tn, t2()).set_autoconnect(true);
    }
    initiate_handshake(&mut nodes, s, l).await;
    assert!(
        deliver(&mut nodes[l]).await > 0,
        "precondition: msg1 reached"
    );
    let mut late = Vec::new();
    while let Ok(p) = nodes[s].packet_rx.try_recv() {
        late.push(p);
    }
    assert!(
        !late.is_empty(),
        "precondition: the first-transport msg2 is held"
    );
    assert!(
        hear(&mut nodes, s).await,
        "precondition: first contact dialled"
    );
    pump(&mut nodes).await;
    let peer = other(&nodes, s);
    assert_eq!(
        active_of(&nodes[s], &peer).0,
        t2(),
        "precondition: the link promoted on the second transport"
    );
    for p in late {
        nodes[s].node.handle_msg2(p).await;
    }
    pump(&mut nodes).await;
    assert_eq!(
        active_of(&nodes[s], &peer).0,
        nodes[s].transport_id,
        "precondition: the late answer moved the link onto the first transport"
    );
    (nodes, s)
}

/// After [`late_answer`]'s move, the pair the link left is offered to the
/// new path machine as heard, so the peer is capable again at both ends with
/// the beacon's pair proven, and the next beacon from it is not dialled.
/// Mutation: offer nothing after the move, which leaves the beacon's pair
/// unheld and the beacon dialled.
#[tokio::test]
async fn a_late_answer_that_moves_the_link_keeps_the_pair_it_left_and_its_beacon_undialled() {
    let (mut nodes, s) = late_answer().await;
    let l = 1 - s;
    let peer = other(&nodes, s);
    assert!(
        !hear(&mut nodes, s).await,
        "node {s} dialled the linked peer's beacon after the late answer"
    );
    let me = *nodes[s].node.node_addr();
    assert!(capable_at(&nodes[s], &peer), "the peer is capable at {s}");
    assert!(capable_at(&nodes[l], &me), "the peer is capable at {l}");
    assert!(
        matches!(held(&nodes, s), Match::Proven { .. }),
        "node {s} holds the beacon's pair as a proven path, got {:?}",
        held(&nodes, s)
    );
    cleanup_nodes(&mut nodes).await;
}

/// The pair [`late_answer`]'s move offers comes through the heard feed, like
/// every other heard report, so once the feed's silence passes with nothing
/// heard there the discovery tick unlists it and the candidate table drops
/// its entry. Mutation: step the pair into the path machine past the feed,
/// which leaves the entry listed after the silence.
#[tokio::test]
async fn the_pair_a_late_answers_move_offers_is_unlisted_after_the_heard_silence() {
    use crate::node::handlers::path_intake::HEARD_SILENCE;
    use fips_core::proto::path::Source;
    let (mut nodes, s) = late_answer().await;
    let peer = other(&nodes, s);
    let left = t2_addr(&nodes, 1 - s);
    let heard = |nodes: &[TestNode]| {
        nodes[s]
            .node
            .get_peer(&peer)
            .and_then(|p| p.bundle())
            .and_then(|b| {
                b.candidates()
                    .iter()
                    .find(|e| e.transport() == t2() && e.addr() == &left)
                    .map(|e| e.sources().has(Source::Heard))
            })
    };
    assert_eq!(
        heard(&nodes),
        Some(true),
        "precondition: the pair the link left is a heard candidate"
    );
    crate::time::advance(HEARD_SILENCE + Duration::from_secs(1));
    nodes[s].node.intake_expire().await;
    assert_eq!(
        heard(&nodes),
        None,
        "node {s} still lists the pair the link left after the heard silence"
    );
    assert!(
        nodes[s]
            .node
            .paths
            .listings
            .listed(&peer, Feed::Heard)
            .is_empty(),
        "the heard feed lists nothing for the peer after its silence"
    );
    cleanup_nodes(&mut nodes).await;
}

/// After [`late_with`]'s move, with the smaller node built from `cfg_s` and
/// the larger from `cfg_l`, the link record's own pair, the one the move
/// left, still names the link at the smaller node, five beacons there start
/// no handshake, and the smaller node keeps its session for the peer.
async fn left_quiet(name: &str, cfg_s: fn() -> Config, cfg_l: fn() -> Config) {
    let (mut nodes, s) = late_with(cfg_s, cfg_l).await;
    let peer = other(&nodes, s);
    let link = nodes[s]
        .node
        .get_peer(&peer)
        .expect("the peer is held")
        .link_id();
    let record = nodes[s]
        .node
        .links
        .get(&link)
        .map(|k| (k.transport_id(), k.remote_addr().clone()))
        .expect("the link record is held");
    assert_eq!(
        nodes[s].node.links.index().get(&record),
        Some(&link),
        "{name}: the link record's own pair is keyed to the link after the move"
    );
    let before = index(&nodes, s);
    let mut dials = 0;
    for _ in 0..5 {
        dials += u32::from(hear(&mut nodes, s).await);
        pump(&mut nodes).await;
    }
    assert_eq!(
        dials, 0,
        "{name}: {dials} of 5 beacons at the pair the link left were dialled"
    );
    assert_eq!(
        index(&nodes, s),
        before,
        "{name}: the smaller node kept its session for the peer"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The pair a crossed move left stays the link's with multipath off at both
/// ends. Mutation: drop the entry at the link record's own pair on release,
/// which reds the entry assertion, and without it the dial count.
#[tokio::test]
async fn a_beacon_at_the_pair_a_crossed_move_left_is_not_dialled_with_multipath_off_at_both_ends() {
    left_quiet("off at both", Config::new, Config::new).await;
}

/// As above, with multipath on at the smaller node and off at the larger,
/// where the peer is not capable at the smaller node, so the capable gate
/// does not hold the beacon.
#[tokio::test]
async fn a_beacon_at_the_pair_a_crossed_move_left_is_not_dialled_with_multipath_on_at_the_smaller_and_off_at_the_larger()
 {
    left_quiet("on at the smaller, off at the larger", enabled, Config::new).await;
}

/// As above, with multipath off at the smaller node and on at the larger.
#[tokio::test]
async fn a_beacon_at_the_pair_a_crossed_move_left_is_not_dialled_with_multipath_off_at_the_smaller_and_on_at_the_larger()
 {
    left_quiet("off at the smaller, on at the larger", Config::new, enabled).await;
}

/// The control, with multipath on at both ends. Its entry assertion covers
/// the index state the msg2 arm's renewal leaves with multipath on; its
/// no-dial and session assertions show the capable path is unchanged, since
/// the capable gate holds the beacon whether or not the pair is keyed.
#[tokio::test]
async fn a_beacon_at_the_pair_a_crossed_move_left_is_not_dialled_with_multipath_on_at_both_ends() {
    left_quiet("on at both", enabled, enabled).await;
}
