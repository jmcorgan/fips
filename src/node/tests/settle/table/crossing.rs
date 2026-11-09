//! Cells at a move and at a kept link: a crossing won, this node's own or a
//! later dial answered, and a crossing lost, on TCP and on loopback in both
//! address orders, each test a plain one and its `_with_multipath_on`
//! sibling.
//!
//! Each test stops its driver just before the site: the node holds the peer
//! from the first handshake, its own dial is pending, and the msg2 that
//! answers the dial is held. It then dirties the peer's state, reads it,
//! hands the msg2 over, and reads it again before any other packet is
//! delivered, so the two readings differ by what the site did and by
//! nothing a later frame does.
//!
//! The site's follow-up tree announce is held behind the rate limit: a send
//! writes the record's announce stamp, as any send does, and that is not
//! the transition's cell (the record's cells are "keep" at a move and at a
//! kept link). The test still requires the site to have tried to announce,
//! by the node's count of rate-limited announces.

use super::super::super::crossed_dial::{Dial, cross_dials_from, hand, phase};
use super::super::super::spanning_tree::{add_loopback_alias, process_available_packets};
use super::super::{resolve_connect, tcp_dial, tcp_pair, with_path};
use super::*;
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};

/// What a move's script decides of the cells that turn on it.
#[derive(Clone, Copy, Debug)]
struct MoveScript {
    /// Multipath is on: the renewed machine drops the planted candidate and
    /// forgets the peer's listings. With it off the bundle holds no
    /// candidate and the path intake returns at once.
    on: bool,
    /// The pair the peer is held at changed, so the BLE mark moves with it,
    /// and the path at `to` starts with no failure and no socket.
    moved: bool,
    /// The path MTU seed wrote a new value: the peer moved to another
    /// transport, or onto a link whose MTU is below the one `dirty` planted.
    /// A move within one transport keeps a tighter value, and the planted
    /// 1111 is tighter than a loopback or a TCP link.
    reseeded: bool,
    /// This node's own or later dial was answered and the session swapped,
    /// so the operator's pin ends, and the unpin step drains the queue of
    /// closes, the one the test planted with it.
    own: bool,
    /// A connection at a pair the readings cover was asked to close: the
    /// dial's, where no other peer proves its pair, or a released path's.
    closed: bool,
}

/// `Changed` if `changed`, else `Kept`.
fn by(changed: bool) -> Outcome {
    if changed {
        Outcome::Changed
    } else {
        Outcome::Kept
    }
}

/// The outcome of each cell of `Move` that turns on the script.
fn move_outcomes(s: MoveScript) -> Vec<(Row, Outcome)> {
    let mut rows = vec![
        // The dial's link record goes; the peer keeps its own.
        (Row::Link, Outcome::Changed),
        // The released pairs are unclaimed and the dial's entry dropped.
        (Row::Index, Outcome::Changed),
        // A renewal starts the link's paths again, with a new path id even
        // where `to` was held.
        (Row::Paths, Outcome::Changed),
        (Row::Capability, by(s.on)),
        // The renewal releases the path `dirty` admitted at a spare pair,
        // and its count and its slot go with it; what the path at `to`
        // keeps is checked by `held_at`.
        (Row::PathFailures, Outcome::Changed),
        (Row::ConnectedUdp, Outcome::Changed),
        // Closed with a move and rebuilt on the dial's session.
        (Row::RekeyMachine, Outcome::Changed),
        // The rebuilt machine carries the record.
        (Row::SetupRecord, Outcome::Kept),
        // The dial's machine is removed.
        (Row::ControlMachine, Outcome::Changed),
        (Row::Connection, by(s.closed)),
        (Row::BleMark, by(s.moved)),
        // The answered dial is forgotten.
        (Row::Dials, Outcome::Changed),
        (Row::PathMtu, by(s.reseeded)),
        // The test's own `record_update_sent` left no update pending.
        (Row::FilterSend, Outcome::Changed),
        // Held behind the rate limit.
        (Row::Tree, Outcome::Kept),
        // The test planted a failure.
        (Row::LookupBackoff, Outcome::Changed),
        (Row::PathCloses, by(s.own || s.closed)),
        (Row::PathListings, by(s.on)),
    ];
    if s.own {
        rows.push((Row::Pin, Outcome::Changed));
    }
    rows
}

/// The outcome of each cell of `Keep` that turns on the script: `closed`
/// says the dial's connection was asked to close at a pair the readings
/// cover, and `shared` that the dial went to the pair the peer's own link
/// is at, whose index entry is the peer's, so the dial has none to drop.
fn keep_outcomes(closed: bool, shared: bool) -> Vec<(Row, Outcome)> {
    vec![
        (Row::Link, Outcome::Changed),
        (Row::Index, by(!shared)),
        // The dial's index is freed in the allocator, which no reading
        // holds; the peer's machine and its bound indices stay.
        (Row::RekeyMachine, Outcome::Kept),
        (Row::ControlMachine, Outcome::Changed),
        (Row::Connection, by(closed)),
        (Row::Dials, Outcome::Changed),
        (Row::FilterSend, Outcome::Changed),
        (Row::Tree, Outcome::Kept),
        (Row::LookupBackoff, Outcome::Changed),
    ]
}

/// A pair as a reading names it.
fn at(transport: TransportId, addr: &TransportAddr) -> PathRef {
    PathRef {
        transport,
        addr: addr.clone(),
    }
}

/// Hold any tree announce to `peer` behind the rate limit for an hour, so
/// the site's follow-up send writes neither the record's stamp nor its
/// pending flag, which `dirty` set.
fn hold_announce(node: &mut Node, peer: &NodeAddr) {
    let p = node
        .get_peer_mut(peer)
        .expect("precondition: the node holds the peer");
    p.set_tree_announce_min_interval_ms(3_600_000);
    p.set_last_tree_announce_sent_ms(Some(crate::time::mono_ms()));
}

/// How many tree announces `node` has held back by the rate limit.
fn held_announces(node: &Node) -> u64 {
    node.metrics().tree.rate_limited.get()
}

/// The state of a peer just before the site, read after [`dirty`] and
/// [`hold_announce`].
struct Before {
    seen: Seen,
    held: u64,
}

/// Leave `peer`'s spin bit set, which a restart clears, whatever its role.
/// `dirty` flips the bit, which leaves it clear where frames had already
/// set it, and a reset would then not show.
fn spin_set(node: &mut Node, peer: &NodeAddr) {
    if let Some(m) = node.get_peer_mut(peer).and_then(ActivePeer::mmp_mut)
        && !m.spin_bit.tx_bit()
    {
        // An initiator flips on its own bit reflected; a responder copies
        // the bit of a frame of a higher counter.
        let initiator = m.spin_bit.is_initiator();
        m.spin_bit.rx_observe(!initiator, (1 << 40) + 1, now_ms());
    }
}

/// [`Seen::of`], with the rows read per pair taken over the pairs in one
/// order. `Seen::of` lists the peer's paths before `also`, so a reading per
/// pair of a peer whose active path changed differs in its order alone.
async fn seen(node: &Node, peer: &NodeAddr, also: &[PathRef]) -> Seen {
    let mut seen = Seen::of(node, peer, also).await;
    let held = node.get_peer(peer);
    let mut sorted = pairs(held, also);
    sorted.sort_by_key(named);
    for (row, reading) in &mut seen.rows {
        *reading = match row {
            Row::Connection => read(node, peer, held, &sorted, *row),
            Row::BleMark => ble_mark(node, &sorted).await,
            _ => continue,
        };
    }
    seen
}

/// Set `peer`'s spin bit and hold its announces on `node`, and read it.
async fn read_before(node: &mut Node, peer: &NodeAddr, also: &[PathRef]) -> Before {
    spin_set(node, peer);
    hold_announce(node, peer);
    Before {
        seen: seen(node, peer, also).await,
        held: held_announces(node),
    }
}

/// The failure count of `peer`'s path at `to` on `node`, and whether it
/// holds a connected socket (`None` off the platforms that have one), or
/// `None` where no path is at `to`.
fn held_at(node: &Node, peer: &NodeAddr, to: &PathRef) -> Option<(u32, Option<bool>)> {
    let p = node.get_peer(peer)?;
    let paths = p.bundle()?.paths();
    let i = paths.find(to.transport, &to.addr)?;
    let fails = paths.get(i)?.live().fails();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let socket = Some(p.socket_at(i));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let socket = None;
    Some((fails, socket))
}

/// Check the path at `to` after a move against what it held before: a path
/// held there keeps its failure count and its socket, and one the renewal
/// made there starts with neither.
fn check_held_at(before: Option<(u32, Option<bool>)>, after: Option<(u32, Option<bool>)>) {
    let want = match before {
        Some(held) => Some(held),
        None => Some((0, after.and_then(|(_, s)| s.map(|_| false)))),
    };
    assert_eq!(
        after, want,
        "defect: the path at the move's pair does not keep what its cells say: before {before:?}"
    );
}

/// Read `peer` on `node` after the site and hold both readings against
/// `t`'s cells, `others` stating the script's outcomes; the site must also
/// have tried to announce the tree.
async fn after(
    node: &Node,
    peer: &NodeAddr,
    also: &[PathRef],
    b: &Before,
    t: &Transition,
    others: &[(Row, Outcome)],
) {
    let seen = seen(node, peer, also).await;
    let held = held_announces(node);
    assert_cells(&b.seen, &seen, t, others);
    assert!(
        held > b.held,
        "defect: the site sent no tree announce at {t:?}: rate-limited before {}, after {held}",
        b.held
    );
}

/// Mark `addr` on `node`'s BLE transport as `peer`'s link, as a frame of
/// the peer's arriving there does, and read the mark back.
#[cfg(ble_available)]
async fn mark(node: &Node, peer: &NodeAddr, addr: &TransportAddr) -> Option<bool> {
    let mut read = None;
    for t in node.transports.values() {
        if let TransportHandle::Ble(ble) = t {
            ble.mark_verified(addr, peer).await;
            read = read.or(ble.is_verified(addr).await);
        }
    }
    read
}

/// No BLE transport is built here, so nothing is marked.
#[cfg(not(ble_available))]
async fn mark(_node: &Node, _peer: &NodeAddr, _addr: &TransportAddr) -> Option<bool> {
    None
}

/// The pairs a site's readings cover: `also` and the spare pair `dirty`
/// writes at.
fn covering(node: &Node, peer: &NodeAddr, also: &[PathRef]) -> Vec<PathRef> {
    let mut pairs = also.to_vec();
    pairs.push(spare(node, peer));
    pairs
}

/// Run a site at `node` for `peer`: dirty the peer, mark `marked` as its
/// BLE link if given, read it over `also` and the spare pair, hand `msg2`,
/// read it again, and hold the readings against `t`'s cells with `others`
/// stating the script's outcomes. Returns the path at the msg2's pair
/// before and after.
#[allow(clippy::too_many_arguments)]
async fn run_site(
    node: &mut Node,
    peer: &NodeAddr,
    msg2: ReceivedPacket,
    also: &[PathRef],
    marked: Option<&TransportAddr>,
    t: Transition,
    others: &[(Row, Outcome)],
) -> [Option<(u32, Option<bool>)>; 2] {
    let to = at(msg2.transport_id, &msg2.remote_addr);
    let pairs = covering(node, peer, also);
    dirty(node, peer).await;
    if let Some(addr) = marked {
        assert_eq!(
            mark(node, peer, addr).await,
            Some(true),
            "precondition: the peer's link at {addr} is marked as its own"
        );
    }
    let b = read_before(node, peer, &pairs).await;
    let held = held_at(node, peer, &to);
    hand(node, msg2).await;
    after(node, peer, &pairs, &b, &t, others).await;
    [held, held_at(node, peer, &to)]
}

/// [`run_site`] for a move, then check the path at the move's pair.
async fn run_move(
    node: &mut Node,
    peer: &NodeAddr,
    msg2: ReceivedPacket,
    also: &[PathRef],
    marked: Option<&TransportAddr>,
    t: Transition,
    script: MoveScript,
) {
    let [before, after] = run_site(node, peer, msg2, also, marked, t, &move_outcomes(script)).await;
    check_held_at(before, after);
}

/// The link of `node`'s one pending dial.
fn dial_link(node: &Node) -> LinkId {
    let dials: Vec<LinkId> = node.pending_outbound.values().copied().collect();
    assert_eq!(dials.len(), 1, "precondition: one dial is pending");
    dials[0]
}

/// Wait, for up to 10 s, for a packet in `want`'s phase at `tn`, keeping
/// every other packet that arrives in `held`.
async fn next_in(tn: &mut TestNode, held: &mut Vec<ReceivedPacket>, want: u8) -> ReceivedPacket {
    for _ in 0..2000 {
        while let Ok(p) = tn.packet_rx.try_recv() {
            held.push(p);
        }
        if let Some(i) = held.iter().position(|p| phase(p) == Some(want)) {
            return held.remove(i);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("precondition: a packet of phase {want} reached the node within 10 s");
}

// ---------------------------------------------------------------------------
// Crossed TCP dials
// ---------------------------------------------------------------------------

/// Two TCP nodes whose dials crossed, each having promoted the other on its
/// msg1, stopped before either takes the msg2 that answers its own dial.
struct TcpCrossed {
    nodes: Vec<TestNode>,
    /// The smaller node, which moves.
    s: usize,
    /// The larger node, which keeps its inbound link.
    l: usize,
    /// What reached each node and was not handed, by node.
    held: [Vec<ReceivedPacket>; 2],
    /// The pair each node's peer sent its msg1 from, by node.
    from: [PathRef; 2],
}

/// Crossed TCP dials, as `crossed_tcp` makes them, stopped once both msg1s
/// are handed: both nodes dial each other through `initiate_connection`,
/// both connects resolve, and each node takes the other's msg1 and promotes
/// it. Index 0 is the smaller node when `zero_smaller`.
async fn tcp_crossed(on: bool, zero_smaller: bool) -> TcpCrossed {
    let mut nodes = tcp_pair(on, zero_smaller).await;
    let (s, l) = if zero_smaller { (0, 1) } else { (1, 0) };
    tcp_dial(&mut nodes, 0, 1).await;
    tcp_dial(&mut nodes, 1, 0).await;
    resolve_connect(&mut nodes[0]).await;
    resolve_connect(&mut nodes[1]).await;
    let mut held = [Vec::new(), Vec::new()];
    let mut from = Vec::new();
    for (i, held) in held.iter_mut().enumerate() {
        let msg1 = next_in(&mut nodes[i], held, PHASE_MSG1).await;
        from.push(at(msg1.transport_id, &msg1.remote_addr));
        hand(&mut nodes[i].node, msg1).await;
    }
    let (s_addr, l_addr) = (*nodes[s].node.node_addr(), *nodes[l].node.node_addr());
    assert!(
        nodes[s].node.get_peer(&l_addr).is_some() && nodes[l].node.get_peer(&s_addr).is_some(),
        "precondition: each node promoted the other on its msg1"
    );
    TcpCrossed {
        nodes,
        s,
        l,
        held,
        from: [from[0].clone(), from[1].clone()],
    }
}

/// The smaller node of crossed TCP dials takes the msg2 that answers its
/// own dial and moves onto that session. No link is capable before the
/// msg2, so the released inbound pair keeps its connection, and the dial's
/// is the one the peer moves onto: nothing is closed, at either setting.
/// That is the connection cell as the code has it today, and it is
/// expected to change.
async fn tcp_crossing_won(on: bool, zero_smaller: bool) {
    let mut x = tcp_crossed(on, zero_smaller).await;
    let (s, l) = (x.s, x.l);
    let l_addr = *x.nodes[l].node.node_addr();
    let dial = dial_link(&x.nodes[s].node);
    let msg2 = next_in(&mut x.nodes[s], &mut x.held[s], PHASE_MSG2).await;
    let t = Transition::Move {
        dial,
        own: false,
        built: true,
    };
    let script = MoveScript {
        on,
        moved: true,
        reseeded: false,
        own: false,
        closed: false,
    };
    let also = [x.from[s].clone(), at(msg2.transport_id, &msg2.remote_addr)];
    run_move(&mut x.nodes[s].node, &l_addr, msg2, &also, None, t, script).await;
    cleanup_nodes(&mut x.nodes).await;
}

/// A crossing won over TCP, index 0 the smaller node.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_smaller_first() {
    tcp_crossing_won(false, true).await;
}

/// [`a_crossing_won_over_tcp_does_what_the_move_cells_say_smaller_first`] with multipath on.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_smaller_first_with_multipath_on() {
    tcp_crossing_won(true, true).await;
}

/// A crossing won over TCP, index 0 the larger node.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_larger_first() {
    tcp_crossing_won(false, false).await;
}

/// [`a_crossing_won_over_tcp_does_what_the_move_cells_say_larger_first`] with multipath on.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_larger_first_with_multipath_on() {
    tcp_crossing_won(true, false).await;
}

// ---------------------------------------------------------------------------
// A crossing won on loopback, on another transport
// ---------------------------------------------------------------------------

/// The smaller node of crossed loopback dials, whose own dial went out on a
/// second transport, takes the msg2 that answers it and moves onto that
/// transport.
async fn loopback_crossing_won(on: bool) {
    let crossed = cross_dials_from(Dial::OtherTransport, with_path(Config::new(), on)).await;
    let (s, l) = (crossed.s, crossed.l);
    let mut nodes = crossed.nodes;
    let l_addr = *nodes[l].node.node_addr();
    let dial = dial_link(&nodes[s].node);
    let t = Transition::Move {
        dial,
        own: false,
        built: true,
    };
    let script = MoveScript {
        on,
        moved: true,
        reseeded: true,
        own: false,
        closed: false,
    };
    let also = [
        at(nodes[s].transport_id, &nodes[l].addr),
        at(crossed.to.0, &crossed.to.1),
    ];
    run_move(
        &mut nodes[s].node,
        &l_addr,
        crossed.msg2,
        &also,
        None,
        t,
        script,
    )
    .await;
    cleanup_nodes(&mut nodes).await;
}

/// A crossing won on loopback, on another transport.
#[tokio::test]
async fn a_crossing_won_on_another_transport_does_what_the_move_cells_say() {
    loopback_crossing_won(false).await;
}

/// [`a_crossing_won_on_another_transport_does_what_the_move_cells_say`] with multipath on.
#[tokio::test]
async fn a_crossing_won_on_another_transport_does_what_the_move_cells_say_with_multipath_on() {
    loopback_crossing_won(true).await;
}

// ---------------------------------------------------------------------------
// A dialer's second dial answered
// ---------------------------------------------------------------------------

/// A dialer that sent two msg1s, the responder having replaced the first
/// peering with the second 1.5 s later, as `second_msg1_late` drives it in
/// order: the dialer holds the responder from the first msg2 and its second
/// dial is pending, its msg2 held.
struct SecondDial {
    nodes: Vec<TestNode>,
    /// The dialer.
    d: usize,
    /// The responder.
    r: usize,
    /// The second msg2, not yet handed to the dialer.
    msg2: ReceivedPacket,
}

/// Drive [`SecondDial`], the dialer the larger node address when
/// `dialer_larger`.
async fn second_dial(on: bool, dialer_larger: bool) -> SecondDial {
    use crate::node::handlers::handshake::UNHEARD_PEERING_MIN_AGE_MS;
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let zero_larger = nodes[0].node.node_addr() > nodes[1].node.node_addr();
    let (d, r) = if zero_larger == dialer_larger {
        (0, 1)
    } else {
        (1, 0)
    };
    let d_addr = *nodes[d].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    initiate_handshake(&mut nodes, d, r).await;
    initiate_handshake(&mut nodes, d, r).await;
    let mut first = nodes[r]
        .packet_rx
        .try_recv()
        .expect("precondition: the first msg1 is queued at the responder");
    let mut second = nodes[r]
        .packet_rx
        .try_recv()
        .expect("precondition: the second msg1 is queued at the responder");
    first.timestamp_ms = Node::now_ms();
    nodes[r].node.handle_msg1(first).await;
    let first_link = nodes[r]
        .node
        .get_peer(&d_addr)
        .map(|p| p.link_id())
        .expect("precondition: the first msg1 promoted the dialer");
    process_available_packets(std::slice::from_mut(&mut nodes[d])).await;
    assert!(
        nodes[d].node.get_peer(&r_addr).is_some(),
        "precondition: the dialer promoted the responder on the first msg2"
    );
    crate::time::advance(Duration::from_millis(UNHEARD_PEERING_MIN_AGE_MS + 500));
    second.timestamp_ms = Node::now_ms();
    nodes[r].node.handle_msg1(second).await;
    assert!(
        nodes[r]
            .node
            .get_peer(&d_addr)
            .is_some_and(|p| p.link_id() != first_link),
        "precondition: the second msg1 replaced the unheard peering"
    );
    let mut held = Vec::new();
    let msg2 = next_in(&mut nodes[d], &mut held, PHASE_MSG2).await;
    assert!(
        held.iter().all(|p| phase(p) != Some(PHASE_MSG2)),
        "precondition: one msg2 at the dialer"
    );
    SecondDial { nodes, d, r, msg2 }
}

/// The dialer takes the msg2 that answers its second dial, on the pair it
/// already holds the responder at, and moves onto that session; the pin
/// ends, and the unpin step drains the queue of closes. The dial's
/// connection is at that same pair, which the moved peer proves, so it is
/// not closed.
async fn second_dial_answered(on: bool, dialer_larger: bool) {
    let mut x = second_dial(on, dialer_larger).await;
    let (d, r) = (x.d, x.r);
    let r_addr = *x.nodes[r].node.node_addr();
    let dial = dial_link(&x.nodes[d].node);
    let t = Transition::Move {
        dial,
        own: true,
        built: true,
    };
    let script = MoveScript {
        on,
        moved: false,
        reseeded: false,
        own: true,
        closed: false,
    };
    let also = [at(x.msg2.transport_id, &x.msg2.remote_addr)];
    run_move(
        &mut x.nodes[d].node,
        &r_addr,
        x.msg2,
        &also,
        None,
        t,
        script,
    )
    .await;
    cleanup_nodes(&mut x.nodes).await;
}

/// A second dial answered, the dialer the smaller node.
#[tokio::test]
async fn a_second_dial_answered_does_what_the_move_cells_say_smaller_dialer() {
    second_dial_answered(false, false).await;
}

/// [`a_second_dial_answered_does_what_the_move_cells_say_smaller_dialer`] with multipath on.
#[tokio::test]
async fn a_second_dial_answered_does_what_the_move_cells_say_smaller_dialer_with_multipath_on() {
    second_dial_answered(true, false).await;
}

/// A second dial answered, the dialer the larger node.
#[tokio::test]
async fn a_second_dial_answered_does_what_the_move_cells_say_larger_dialer() {
    second_dial_answered(false, true).await;
}

/// [`a_second_dial_answered_does_what_the_move_cells_say_larger_dialer`] with multipath on.
#[tokio::test]
async fn a_second_dial_answered_does_what_the_move_cells_say_larger_dialer_with_multipath_on() {
    second_dial_answered(true, true).await;
}

// ---------------------------------------------------------------------------
// An own dial on an aged link, at a second address
// ---------------------------------------------------------------------------

/// The smaller node of a linked pair dials the larger again at a second
/// address once the link is past the rekey age and quiet, as `cross_move`
/// and `cross_move_dead` drive it; the larger answers from the pair the
/// link is on, and the smaller moves. With multipath on the link is
/// capable and holds a second path, a beaconed pair, Live, and the peer is
/// quiet past link-dead, since until then a capable peer's link is live and
/// is not dialled; the renewal releases that path, which is queued to close
/// and closed by the unpin step's drain. With it off no link is capable,
/// and only the dial's connection closes. That is the connection cell as
/// the code has it today, and it is expected to change.
async fn own_dial_on_an_aged_link(on: bool) {
    use super::super::super::control::quieten;
    use super::super::super::paths::{beacon, capable_at, quiet_for, state_at};
    use super::super::super::rekey_parity::{age_link, deliver, linked_pair, pump};
    use crate::peer::PathState;
    let config = || with_path(Config::new(), on);
    let mut nodes = linked_pair(config(), config()).await;
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let l_addr = *nodes[l].node.node_addr();
    let ts = nodes[s].transport_id;
    let first = at(ts, &nodes[l].addr);
    let mut also = vec![first.clone()];
    if on {
        let beaconed = add_loopback_alias(&nodes[l].addr, nodes[l].transport_id);
        beacon(&nodes[s], ts, &beaconed, &nodes[l]);
        nodes[s].node.poll_transport_discovery().await;
        pump(&mut nodes).await;
        assert_eq!(
            state_at(&nodes[s], &l_addr, ts, &beaconed),
            Some(PathState::Live),
            "precondition: the beaconed pair is a path"
        );
        assert!(
            capable_at(&nodes[s], &l_addr),
            "precondition: the link is capable"
        );
        also.push(at(ts, &beaconed));
    }
    age_link(&mut nodes, s, l, Duration::from_secs(31));
    if on {
        quiet_for(&mut nodes[s], &l_addr, 31);
    } else {
        quieten(&mut nodes[s], &l_addr);
    }
    let dialled = add_loopback_alias(&nodes[l].addr, nodes[l].transport_id);
    also.push(at(ts, &dialled));
    let l_npub = nodes[l].node.npub();
    nodes[s]
        .node
        .api_connect(&l_npub, &dialled.to_string(), "loopback")
        .await
        .expect("precondition: a dial on the second address starts");
    assert_eq!(deliver(&mut nodes[l]).await, 1, "precondition: one msg1");
    let mut held = Vec::new();
    let msg2 = next_in(&mut nodes[s], &mut held, PHASE_MSG2).await;
    assert_eq!(
        at(msg2.transport_id, &msg2.remote_addr),
        first,
        "precondition: the msg2 comes from the pair the link is on"
    );
    let dial = dial_link(&nodes[s].node);
    let t = Transition::Move {
        dial,
        own: true,
        built: true,
    };
    // The dial's connection, at the second address no path names, is
    // closed at both settings.
    let script = MoveScript {
        on,
        moved: false,
        reseeded: false,
        own: true,
        closed: true,
    };
    let spare = spare(&nodes[s].node, &l_addr);
    run_move(&mut nodes[s].node, &l_addr, msg2, &also, None, t, script).await;
    // Which closes the connection cell's one reading is made of: the dial's
    // at both settings, and the released paths' only where the link is
    // capable, the spare pair `dirty` admitted and, with multipath on, the
    // beaconed one.
    let closes: Vec<usize> = also[1..]
        .iter()
        .chain([&spare])
        .map(|to| closes_at(&nodes[s].node, to))
        .collect();
    let want = if on { vec![1, 1, 1] } else { vec![1, 0] };
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        closes,
        want,
        "defect: the move closes other connections than its cell says, at {:?}",
        also[1..]
            .iter()
            .chain([&spare])
            .map(named)
            .collect::<Vec<_>>()
    );
}

/// How many times `node` asked its loopback transport to close the
/// connection at `to`.
fn closes_at(node: &Node, to: &PathRef) -> usize {
    match node.transports.get(&to.transport) {
        Some(TransportHandle::Loopback(t)) => t.closed().iter().filter(|a| **a == to.addr).count(),
        _ => panic!("precondition: {} is on a loopback transport", named(to)),
    }
}

/// An own dial answered on an aged link with multipath off.
#[tokio::test]
async fn an_own_dial_answered_on_an_aged_link_does_what_the_move_cells_say() {
    own_dial_on_an_aged_link(false).await;
}

/// [`an_own_dial_answered_on_an_aged_link_does_what_the_move_cells_say`] with multipath on,
/// on a capable link with a second path.
#[tokio::test]
async fn an_own_dial_answered_on_an_aged_link_does_what_the_move_cells_say_with_multipath_on() {
    own_dial_on_an_aged_link(true).await;
}

// ---------------------------------------------------------------------------
// A crossing lost
// ---------------------------------------------------------------------------

/// The larger node of crossed TCP dials takes the msg2 that answers its
/// own dial and keeps its inbound link. The dial's connection is at the
/// smaller node's listening address, which no path of the peer's names, so
/// it is closed: the pool's outbound count falls.
async fn tcp_crossing_lost(on: bool, zero_smaller: bool) {
    let mut x = tcp_crossed(on, zero_smaller).await;
    let (s, l) = (x.s, x.l);
    let s_addr = *x.nodes[s].node.node_addr();
    let dial = dial_link(&x.nodes[l].node);
    let msg2 = next_in(&mut x.nodes[l], &mut x.held[l], PHASE_MSG2).await;
    let also = [x.from[l].clone(), at(msg2.transport_id, &msg2.remote_addr)];
    let t = Transition::Keep { dial };
    let others = keep_outcomes(true, false);
    run_site(&mut x.nodes[l].node, &s_addr, msg2, &also, None, t, &others).await;
    cleanup_nodes(&mut x.nodes).await;
}

/// A crossing lost over TCP, index 0 the smaller node.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_smaller_first() {
    tcp_crossing_lost(false, true).await;
}

/// [`a_crossing_lost_over_tcp_does_what_the_keep_cells_say_smaller_first`] with multipath on.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_smaller_first_with_multipath_on() {
    tcp_crossing_lost(true, true).await;
}

/// A crossing lost over TCP, index 0 the larger node.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_larger_first() {
    tcp_crossing_lost(false, false).await;
}

/// [`a_crossing_lost_over_tcp_does_what_the_keep_cells_say_larger_first`] with multipath on.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_larger_first_with_multipath_on() {
    tcp_crossing_lost(true, false).await;
}

/// The larger node of crossed loopback dials takes the msg2 that answers
/// its own dial and keeps its inbound link. Crossed as `dial` says: on
/// another transport the larger node's dial went to a pair the peer holds
/// no path at, and is closed; from another address on one transport its
/// dial went to the pair the peer's msg1 came from, which the peer proves,
/// so it is left open, and the pair's one index entry is the peer's link's.
async fn loopback_crossing_lost(on: bool, dial: Dial) {
    let crossed = cross_dials_from(dial, with_path(Config::new(), on)).await;
    let (s, l) = (crossed.s, crossed.l);
    let mut nodes = crossed.nodes;
    let s_addr = *nodes[s].node.node_addr();
    let dialled = dial_link(&nodes[l].node);
    let mut held = Vec::new();
    let msg2 = next_in(&mut nodes[l], &mut held, PHASE_MSG2).await;
    let also = [
        at(msg2.transport_id, &msg2.remote_addr),
        at(crossed.to.0, &crossed.source),
    ];
    let t = Transition::Keep { dial: dialled };
    let other = dial == Dial::OtherTransport;
    let others = keep_outcomes(other, !other);
    run_site(&mut nodes[l].node, &s_addr, msg2, &also, None, t, &others).await;
    cleanup_nodes(&mut nodes).await;
}

/// A crossing lost on loopback, the peer's dial on another transport.
#[tokio::test]
async fn a_crossing_lost_on_another_transport_does_what_the_keep_cells_say() {
    loopback_crossing_lost(false, Dial::OtherTransport).await;
}

/// [`a_crossing_lost_on_another_transport_does_what_the_keep_cells_say`] with multipath on.
#[tokio::test]
async fn a_crossing_lost_on_another_transport_does_what_the_keep_cells_say_with_multipath_on() {
    loopback_crossing_lost(true, Dial::OtherTransport).await;
}

/// A crossing lost on loopback, the peer's dial from its own address.
#[tokio::test]
async fn a_crossing_lost_at_a_proven_pair_does_what_the_keep_cells_say() {
    loopback_crossing_lost(false, Dial::OtherAddress).await;
}

/// [`a_crossing_lost_at_a_proven_pair_does_what_the_keep_cells_say`] with multipath on.
#[tokio::test]
async fn a_crossing_lost_at_a_proven_pair_does_what_the_keep_cells_say_with_multipath_on() {
    loopback_crossing_lost(true, Dial::OtherAddress).await;
}

// ---------------------------------------------------------------------------
// A crossing on two BLE links
// ---------------------------------------------------------------------------

/// Crossed dials on two BLE links between one pair, as
/// `a_crossed_dial_won_on_a_second_link_moves_the_peer_and_its_verification_onto_that_link`
/// drives them: node 0, the smaller, dials over L2 and node 1 over L1, and
/// each promotes the other on its msg1. Node 0 holds node 1 on L1 and its
/// mark there, as a frame of node 1's would leave it, and moves onto L2 at
/// the msg2: the mark is relinked from L1 to L2. Node 1 holds node 0 on L2
/// and its mark there, and keeps that link at the msg2: the mark stays.
/// Node 1's reading covers L2 alone: its dial's link, L1, is closed at the
/// msg2, which unpools it and takes its reading of the mark with it; the
/// connection cell of a kept link is held on TCP and loopback.
#[cfg(ble_available)]
async fn ble_crossing(on: bool) {
    use super::super::super::ble::{
        base_config, larger_second, make_test_node_ble_from, two_links,
    };
    use super::super::super::spanning_tree::dial_at;
    let config = with_path(Config::new(), on);
    let mut nodes = vec![
        make_test_node_ble_from(1, base_config(), config.clone()).await,
        make_test_node_ble_from(2, base_config(), config).await,
    ];
    larger_second(&mut nodes);
    let (a0, a1, a0x, a1x) = two_links(&nodes).await;
    let (a0, a1, a0x, a1x) = (
        a0.to_transport_addr(),
        a1.to_transport_addr(),
        a0x.to_transport_addr(),
        a1x.to_transport_addr(),
    );
    let t = nodes[0].transport_id;
    let n0 = *nodes[0].node.node_addr();
    let n1 = *nodes[1].node.node_addr();
    dial_at(&mut nodes, 0, 1, a1x.clone()).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    let dials = [dial_link(&nodes[0].node), dial_link(&nodes[1].node)];
    let mut held = [Vec::new(), Vec::new()];

    let msg1 = next_in(&mut nodes[1], &mut held[1], PHASE_MSG1).await;
    assert_eq!(
        at(msg1.transport_id, &msg1.remote_addr),
        at(t, &a0x),
        "precondition: node 0's msg1 reaches node 1 over L2"
    );
    hand(&mut nodes[1].node, msg1).await;
    let msg1 = next_in(&mut nodes[0], &mut held[0], PHASE_MSG1).await;
    assert_eq!(
        at(msg1.transport_id, &msg1.remote_addr),
        at(t, &a1),
        "precondition: node 1's msg1 reaches node 0 over L1"
    );
    hand(&mut nodes[0].node, msg1).await;

    // Node 0 wins.
    let msg2 = next_in(&mut nodes[0], &mut held[0], PHASE_MSG2).await;
    assert_eq!(
        at(msg2.transport_id, &msg2.remote_addr),
        at(t, &a1x),
        "precondition: node 1's msg2 reaches node 0 over L2"
    );
    let also = [at(t, &a1), at(t, &a1x)];
    let won = Transition::Move {
        dial: dials[0],
        own: false,
        built: true,
    };
    let script = MoveScript {
        on,
        moved: true,
        reseeded: false,
        own: false,
        closed: false,
    };
    run_move(&mut nodes[0].node, &n1, msg2, &also, Some(&a1), won, script).await;

    // Node 1 loses.
    let msg2 = next_in(&mut nodes[1], &mut held[1], PHASE_MSG2).await;
    assert_eq!(
        at(msg2.transport_id, &msg2.remote_addr),
        at(t, &a0),
        "precondition: node 0's msg2 reaches node 1 over L1"
    );
    let also = [at(t, &a0x)];
    let lost = Transition::Keep { dial: dials[1] };
    let others = keep_outcomes(false, false);
    run_site(
        &mut nodes[1].node,
        &n0,
        msg2,
        &also,
        Some(&a0x),
        lost,
        &others,
    )
    .await;
    cleanup_nodes(&mut nodes).await;
}

/// A crossing on two BLE links relinks the winner's mark and leaves the
/// loser's.
#[cfg(ble_available)]
#[tokio::test]
async fn a_crossing_won_on_a_second_ble_link_relinks_the_mark() {
    ble_crossing(false).await;
}

/// [`a_crossing_won_on_a_second_ble_link_relinks_the_mark`] with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn a_crossing_won_on_a_second_ble_link_relinks_the_mark_with_multipath_on() {
    ble_crossing(true).await;
}
