//! Cells at a move and at a kept link: a crossing settled at the msg2 of a
//! node's own dial, by moving onto that dial or keeping the session it holds,
//! and a crossing settled at the peer's msg3, by moving onto the inbound leg
//! it completed or keeping the session held, on TCP, on loopback and on BLE,
//! each test a plain one and its `_with_multipath_on` sibling. A node that
//! answers its own dial over a held peering does what the tie-break says, so
//! its own dial on an aged link is a crossing won here too.
//!
//! Each test stops its driver just before the site: the node holds the peer
//! from the other handshake, and the message that settles the crossing is
//! held. It then dirties the peer's state, reads it, hands the message over,
//! and reads it again before any other packet is delivered, so the two
//! readings differ by what the site did and by nothing a later frame does.
//!
//! The follow-up tree announce of a site at the msg2 is held behind the rate
//! limit: a send writes the record's announce stamp, as any send does, and
//! that is not the transition's cell (the record's cells are "keep" at a move
//! and at a kept link). The test still requires the site to have tried to
//! announce, by the node's count of rate-limited announces. A site at the
//! msg3 sends no announce, and the test requires that it tried none.

use super::super::super::crossed_dial::{Dial, cross_dials_from, hand, phase};
use super::super::super::spanning_tree::add_loopback_alias;
use super::super::{resolve_connect, tcp_dial, tcp_pair, with_path};
use super::*;
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2, PHASE_MSG3};

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
    /// The move is at a dial's msg2, whose site offers the pair the peer
    /// left again: with multipath on, and the pair moved, that step drains
    /// the queue of closes, the one the test planted with it.
    offers: bool,
    /// A connection at a pair the readings cover was asked to close: the
    /// dial's, where no other peer proves its pair, or a released path's.
    closed: bool,
    /// The renewal queued a released path to close: the link was capable.
    queued: bool,
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
    let rows = vec![
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
        (
            Row::PathCloses,
            by(s.queued || (s.offers && s.on && s.moved)),
        ),
        (Row::PathListings, by(s.on)),
    ];
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

/// Hold `peer`'s announces on `node`, and read it.
async fn read_before(node: &mut Node, peer: &NodeAddr, also: &[PathRef]) -> Before {
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
/// `t`'s cells, `others` stating the script's outcomes; a site at a dial's
/// msg2 must also have tried to announce the tree, and one at the msg3 must
/// not have.
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
    let inbound = matches!(
        t,
        Transition::Move { inbound: true, .. } | Transition::Keep { inbound: true, .. }
    );
    assert_eq!(
        held > b.held,
        !inbound,
        "defect: the site's tree announce at {t:?} is not the table's: rate-limited before {}, after {held}",
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
/// the message that settles the crossing, read it again, and hold the
/// readings against `t`'s cells with `others` stating the script's
/// outcomes. Returns the path at the message's pair before and after.
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
// Crossed dials, settled at a msg2 or at a msg3
// ---------------------------------------------------------------------------

/// Two nodes whose dials have both started, each one's msg1 on its way to
/// the other, nothing handed yet.
struct Dialled {
    nodes: Vec<TestNode>,
    /// The smaller node.
    s: usize,
    /// The larger node.
    l: usize,
    /// What reached each node and was not handed, by node.
    held: [Vec<ReceivedPacket>; 2],
}

/// Hand node `i` of `x` the next packet of phase `want` that reaches it.
async fn step(x: &mut Dialled, i: usize, want: u8) {
    let packet = next_in(&mut x.nodes[i], &mut x.held[i], want).await;
    hand(&mut x.nodes[i].node, packet).await;
}

/// Order the crossed handshakes so that node `at` holds its peer from the
/// peer's own dial, completed by the peer's msg3, and stop before `at` takes
/// the msg2 that answers its own dial, which this returns. The link of
/// `at`'s dial is the one pending dial it holds.
async fn to_msg2(x: &mut Dialled, at: usize) -> ReceivedPacket {
    let other = 1 - at;
    step(x, at, PHASE_MSG1).await;
    step(x, other, PHASE_MSG2).await;
    step(x, at, PHASE_MSG3).await;
    step(x, other, PHASE_MSG1).await;
    let peer = *x.nodes[other].node.node_addr();
    assert!(
        x.nodes[at].node.get_peer(&peer).is_some(),
        "precondition: node {at} promoted its peer on the peer's msg3"
    );
    next_in(&mut x.nodes[at], &mut x.held[at], PHASE_MSG2).await
}

/// Order the crossed handshakes so that node `at` holds its peer from its
/// own dial, completed at its msg2, and stop before `at` takes the msg3 that
/// completes the peer's dial, which this returns with the link of the
/// inbound leg it completes.
async fn to_msg3(x: &mut Dialled, at: usize) -> (ReceivedPacket, LinkId) {
    let other = 1 - at;
    step(x, other, PHASE_MSG1).await;
    step(x, at, PHASE_MSG2).await;
    step(x, at, PHASE_MSG1).await;
    step(x, other, PHASE_MSG2).await;
    let peer = *x.nodes[other].node.node_addr();
    assert!(
        x.nodes[at].node.get_peer(&peer).is_some(),
        "precondition: node {at} promoted its peer at its own dial's msg2"
    );
    let legs = orphans(&x.nodes[at].node);
    assert_eq!(
        legs.len(),
        1,
        "precondition: node {at} holds one inbound leg beside the peer's link"
    );
    let msg3 = next_in(&mut x.nodes[at], &mut x.held[at], PHASE_MSG3).await;
    (msg3, legs[0])
}

/// Two TCP nodes, multipath set as `on`, each having dialled the other
/// through `initiate_connection`, both connects resolved and both msg1s
/// sent. Index 0 is the smaller node when `zero_smaller`.
async fn tcp_dialled(on: bool, zero_smaller: bool) -> Dialled {
    let mut nodes = tcp_pair(on, zero_smaller).await;
    let (s, l) = if zero_smaller { (0, 1) } else { (1, 0) };
    tcp_dial(&mut nodes, 0, 1).await;
    tcp_dial(&mut nodes, 1, 0).await;
    resolve_connect(&mut nodes[0]).await;
    resolve_connect(&mut nodes[1]).await;
    Dialled {
        nodes,
        s,
        l,
        held: [Vec::new(), Vec::new()],
    }
}

/// Two loopback nodes on one transport, multipath set as `on`, each having
/// dialled the other.
async fn loopback_dialled(on: bool) -> Dialled {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    Dialled {
        nodes,
        s,
        l,
        held: [Vec::new(), Vec::new()],
    }
}

/// The pair `at` received `packet` from.
fn from(packet: &ReceivedPacket) -> PathRef {
    at(packet.transport_id, &packet.remote_addr)
}

/// The pairs node `i` of `x` holds its peer's link and its legs at.
fn links_of(x: &Dialled, i: usize) -> Vec<PathRef> {
    let node = &x.nodes[i].node;
    let mut pairs: Vec<PathRef> = node
        .links
        .values()
        .map(|l| at(l.transport_id(), l.remote_addr()))
        .collect();
    pairs.sort_by_key(named);
    pairs.dedup();
    pairs
}

/// The smaller node takes the msg2 that answers its own dial, holding the
/// larger from the larger's dial, and moves onto its dial's session. No link
/// is capable before the msg2, so the released pair keeps its connection,
/// and the dial's is the one the peer moves onto: nothing is closed, at
/// either setting. That is the connection cell as the code has it today,
/// and it is expected to change.
async fn crossing_won(mut x: Dialled, on: bool, moved: bool) {
    let (s, l) = (x.s, x.l);
    let l_addr = *x.nodes[l].node.node_addr();
    let msg2 = to_msg2(&mut x, s).await;
    let dial = dial_link(&x.nodes[s].node);
    let t = Transition::Move {
        dial,
        own: false,
        built: true,
        inbound: false,
    };
    let script = MoveScript {
        on,
        moved,
        reseeded: false,
        offers: true,
        closed: false,
        queued: false,
    };
    let mut also = links_of(&x, s);
    also.push(from(&msg2));
    run_move(&mut x.nodes[s].node, &l_addr, msg2, &also, None, t, script).await;
    cleanup_nodes(&mut x.nodes).await;
}

/// The larger node takes the msg2 that answers its own dial, holding the
/// smaller from the smaller's dial, and keeps the session it holds. The
/// dial's link is closed, and its connection with it where it is not the
/// one the peer runs on: `closed` says so, and `shared` that the dial's
/// pair is the peer's own, whose index entry the peer's link holds.
async fn crossing_lost(mut x: Dialled, closed: bool, shared: bool) {
    let (s, l) = (x.s, x.l);
    let s_addr = *x.nodes[s].node.node_addr();
    let msg2 = to_msg2(&mut x, l).await;
    let dial = dial_link(&x.nodes[l].node);
    let mut also = links_of(&x, l);
    also.push(from(&msg2));
    let t = Transition::Keep {
        dial,
        inbound: false,
    };
    let others = keep_outcomes(closed, shared);
    run_site(&mut x.nodes[l].node, &s_addr, msg2, &also, None, t, &others).await;
    cleanup_nodes(&mut x.nodes).await;
}

/// The larger node takes the msg3 that completes the smaller node's dial,
/// holding the smaller from its own dial, and moves onto the inbound leg's
/// session at the msg3's pair. The leg's connection is the one the peer
/// moves onto and stays; no link is capable yet, so the released pair keeps
/// its own: nothing is closed, at either setting.
async fn settled_at_msg3_moved(mut x: Dialled, on: bool, moved: bool) {
    let (s, l) = (x.s, x.l);
    let s_addr = *x.nodes[s].node.node_addr();
    let (msg3, leg) = to_msg3(&mut x, l).await;
    let t = Transition::Move {
        dial: leg,
        own: false,
        built: true,
        inbound: true,
    };
    let script = MoveScript {
        on,
        moved,
        reseeded: false,
        offers: false,
        closed: false,
        queued: false,
    };
    let mut also = links_of(&x, l);
    also.push(from(&msg3));
    let mut others = move_outcomes(script);
    // No dial is answered here: the dials, the filter, the tree and the
    // lookup backoff are the table's to keep.
    others.retain(|(row, _)| {
        !matches!(
            row,
            Row::Dials | Row::FilterSend | Row::Tree | Row::LookupBackoff | Row::Connection
        )
    });
    // No link is capable yet, so the released pair keeps its connection, and
    // the leg's is the one the peer moves onto.
    others.push((Row::Connection, Outcome::Kept));
    let [before, after] =
        run_site(&mut x.nodes[l].node, &s_addr, msg3, &also, None, t, &others).await;
    check_held_at(before, after);
    cleanup_nodes(&mut x.nodes).await;
}

/// The smaller node takes the msg3 that completes the larger node's dial,
/// holding the larger from its own dial, and keeps the session it holds; the
/// inbound leg's link is closed and its connection left open.
async fn settled_at_msg3_kept(mut x: Dialled) {
    let (s, l) = (x.s, x.l);
    let l_addr = *x.nodes[l].node.node_addr();
    let (msg3, leg) = to_msg3(&mut x, s).await;
    let t = Transition::Keep {
        dial: leg,
        inbound: true,
    };
    let mut also = links_of(&x, s);
    also.push(from(&msg3));
    let others = [
        (Row::Link, Outcome::Changed),
        (Row::Index, Outcome::Changed),
        // The leg's index is freed in the allocator, which no reading
        // holds; the peer's machine and its bound indices stay.
        (Row::RekeyMachine, Outcome::Kept),
        (Row::ControlMachine, Outcome::Changed),
    ];
    run_site(&mut x.nodes[s].node, &l_addr, msg3, &also, None, t, &others).await;
    cleanup_nodes(&mut x.nodes).await;
}

/// A crossing won over TCP at the smaller node's msg2, index 0 the smaller
/// node.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_smaller_first() {
    crossing_won(tcp_dialled(false, true).await, false, true).await;
}

/// [`a_crossing_won_over_tcp_does_what_the_move_cells_say_smaller_first`] with multipath on.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_smaller_first_with_multipath_on() {
    crossing_won(tcp_dialled(true, true).await, true, true).await;
}

/// A crossing won over TCP, index 0 the larger node.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_larger_first() {
    crossing_won(tcp_dialled(false, false).await, false, true).await;
}

/// [`a_crossing_won_over_tcp_does_what_the_move_cells_say_larger_first`] with multipath on.
#[tokio::test]
async fn a_crossing_won_over_tcp_does_what_the_move_cells_say_larger_first_with_multipath_on() {
    crossing_won(tcp_dialled(true, false).await, true, true).await;
}

/// A crossing lost over TCP at the larger node's msg2, index 0 the smaller
/// node. The dial's connection is at the smaller node's listening address,
/// which no path of the peer's names, so it is closed.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_smaller_first() {
    crossing_lost(tcp_dialled(false, true).await, true, false).await;
}

/// [`a_crossing_lost_over_tcp_does_what_the_keep_cells_say_smaller_first`] with multipath on.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_smaller_first_with_multipath_on() {
    crossing_lost(tcp_dialled(true, true).await, true, false).await;
}

/// A crossing lost over TCP, index 0 the larger node.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_larger_first() {
    crossing_lost(tcp_dialled(false, false).await, true, false).await;
}

/// [`a_crossing_lost_over_tcp_does_what_the_keep_cells_say_larger_first`] with multipath on.
#[tokio::test]
async fn a_crossing_lost_over_tcp_does_what_the_keep_cells_say_larger_first_with_multipath_on() {
    crossing_lost(tcp_dialled(true, false).await, true, false).await;
}

/// A crossing settled at the msg3 over TCP moves the larger node onto the
/// inbound leg, at the leg's pair.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_over_tcp_moves_the_larger_node_as_the_table_says() {
    settled_at_msg3_moved(tcp_dialled(false, true).await, false, true).await;
}

/// [`a_crossing_settled_at_the_msg3_over_tcp_moves_the_larger_node_as_the_table_says`] with
/// multipath on.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_over_tcp_moves_the_larger_node_as_the_table_says_with_multipath_on()
 {
    settled_at_msg3_moved(tcp_dialled(true, true).await, true, true).await;
}

/// A crossing settled at the msg3 over TCP keeps the smaller node's session.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_over_tcp_keeps_the_smaller_node_as_the_table_says() {
    settled_at_msg3_kept(tcp_dialled(false, true).await).await;
}

/// [`a_crossing_settled_at_the_msg3_over_tcp_keeps_the_smaller_node_as_the_table_says`] with
/// multipath on.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_over_tcp_keeps_the_smaller_node_as_the_table_says_with_multipath_on()
 {
    settled_at_msg3_kept(tcp_dialled(true, true).await).await;
}

/// A crossing lost on loopback, one transport, at the larger node's msg2:
/// its dial went to the pair the peer's msg1 came from, which the peer
/// proves, so the connection is left open, and the pair's one index entry
/// is the peer's link's.
#[tokio::test]
async fn a_crossing_lost_at_a_proven_pair_does_what_the_keep_cells_say() {
    crossing_lost(loopback_dialled(false).await, false, true).await;
}

/// [`a_crossing_lost_at_a_proven_pair_does_what_the_keep_cells_say`] with multipath on.
#[tokio::test]
async fn a_crossing_lost_at_a_proven_pair_does_what_the_keep_cells_say_with_multipath_on() {
    crossing_lost(loopback_dialled(true).await, false, true).await;
}

/// A crossing settled at the msg3 on loopback, one transport, moves the
/// larger node onto the inbound leg at the pair it already holds.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_on_loopback_moves_the_larger_node_as_the_table_says() {
    settled_at_msg3_moved(loopback_dialled(false).await, false, false).await;
}

/// [`a_crossing_settled_at_the_msg3_on_loopback_moves_the_larger_node_as_the_table_says`]
/// with multipath on.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_on_loopback_moves_the_larger_node_as_the_table_says_with_multipath_on()
 {
    settled_at_msg3_moved(loopback_dialled(true).await, true, false).await;
}

/// A crossing settled at the msg3 on loopback, one transport, keeps the
/// smaller node's session.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_on_loopback_keeps_the_smaller_node_as_the_table_says() {
    settled_at_msg3_kept(loopback_dialled(false).await).await;
}

/// [`a_crossing_settled_at_the_msg3_on_loopback_keeps_the_smaller_node_as_the_table_says`]
/// with multipath on.
#[tokio::test]
async fn a_crossing_settled_at_the_msg3_on_loopback_keeps_the_smaller_node_as_the_table_says_with_multipath_on()
 {
    settled_at_msg3_kept(loopback_dialled(true).await).await;
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
        inbound: false,
    };
    let script = MoveScript {
        on,
        moved: true,
        reseeded: true,
        offers: true,
        closed: false,
        queued: false,
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
// An own dial on an aged link, at a second address
// ---------------------------------------------------------------------------

/// The smaller node of a linked pair dials the larger again at a second
/// address once the link is past the rekey age and quiet, as `cross_move`
/// and `cross_move_dead` drive it; the larger answers from the pair the
/// link is on, and the smaller, winning the tie-break, moves. With
/// multipath on the link is capable and holds a second path, a beaconed
/// pair, Live, and the peer is quiet past link-dead, since until then a
/// capable peer's link is live and is not dialled; the renewal releases that
/// path, which is queued to close, and nothing at the site drains the queue,
/// since the pair the peer is held at does not move. With it off no link is
/// capable. At both settings the dial's connection closes. That is the
/// connection cell as the code has it today, and it is expected to change.
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
        own: false,
        built: true,
        inbound: false,
    };
    // The dial's connection, at the second address no path names, is
    // closed at both settings.
    let script = MoveScript {
        on,
        moved: false,
        reseeded: false,
        offers: true,
        closed: true,
        queued: on,
    };
    let spare = spare(&nodes[s].node, &l_addr);
    run_move(&mut nodes[s].node, &l_addr, msg2, &also, None, t, script).await;
    // Which closes the connection cell's one reading is made of: the dial's
    // at both settings; the released paths, the spare pair `dirty` admitted
    // and, with multipath on, the beaconed one, are at most queued.
    let closes: Vec<usize> = also[1..]
        .iter()
        .chain([&spare])
        .map(|to| closes_at(&nodes[s].node, to))
        .collect();
    let want = if on { vec![0, 1, 0] } else { vec![1, 0] };
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
// A crossing on two BLE links
// ---------------------------------------------------------------------------

/// Crossed dials on two BLE links between one pair: node 0, the smaller,
/// dials over L2 and node 1 over L1. Node 1's dial completes first: node 1
/// promotes node 0 on L1 at its msg2, and node 0 promotes node 1 on L1 at
/// the msg3, its mark there as a frame of node 1's would leave it. Node 0
/// then takes the msg2 that answers its own dial over L2 and moves onto L2:
/// the mark is relinked from L1 to L2. Node 1 takes node 0's msg3 over L2,
/// which settles the crossing there, and, the larger node, moves onto the
/// inbound leg on L2: its mark is relinked from L1 to L2 too.
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
    let dial0 = dial_link(&nodes[0].node);
    let mut held = [Vec::new(), Vec::new()];

    // Node 1's dial over L1 completes at both ends.
    let msg1 = next_in(&mut nodes[0], &mut held[0], PHASE_MSG1).await;
    assert_eq!(
        at(msg1.transport_id, &msg1.remote_addr),
        at(t, &a1),
        "precondition: node 1's msg1 reaches node 0 over L1"
    );
    hand(&mut nodes[0].node, msg1).await;
    let msg2 = next_in(&mut nodes[1], &mut held[1], PHASE_MSG2).await;
    hand(&mut nodes[1].node, msg2).await;
    let msg3 = next_in(&mut nodes[0], &mut held[0], PHASE_MSG3).await;
    hand(&mut nodes[0].node, msg3).await;
    assert!(
        nodes[0].node.get_peer(&n1).is_some() && nodes[1].node.get_peer(&n0).is_some(),
        "precondition: each node holds the other on L1"
    );
    let msg1 = next_in(&mut nodes[1], &mut held[1], PHASE_MSG1).await;
    assert_eq!(
        at(msg1.transport_id, &msg1.remote_addr),
        at(t, &a0x),
        "precondition: node 0's msg1 reaches node 1 over L2"
    );
    hand(&mut nodes[1].node, msg1).await;

    // Node 0 wins at the msg2.
    let msg2 = next_in(&mut nodes[0], &mut held[0], PHASE_MSG2).await;
    assert_eq!(
        at(msg2.transport_id, &msg2.remote_addr),
        at(t, &a1x),
        "precondition: node 1's msg2 reaches node 0 over L2"
    );
    let also = [at(t, &a1), at(t, &a1x)];
    let won = Transition::Move {
        dial: dial0,
        own: false,
        built: true,
        inbound: false,
    };
    let script = MoveScript {
        on,
        moved: true,
        reseeded: false,
        offers: true,
        closed: false,
        queued: false,
    };
    run_move(&mut nodes[0].node, &n1, msg2, &also, Some(&a1), won, script).await;

    // Node 1 settles at the msg3 and moves onto the inbound leg.
    let msg3 = next_in(&mut nodes[1], &mut held[1], PHASE_MSG3).await;
    assert_eq!(
        at(msg3.transport_id, &msg3.remote_addr),
        at(t, &a0x),
        "precondition: node 0's msg3 reaches node 1 over L2"
    );
    let legs = orphans(&nodes[1].node);
    assert_eq!(legs.len(), 1, "precondition: node 1 holds one inbound leg");
    let also = [at(t, &a0), at(t, &a0x)];
    let moved = Transition::Move {
        dial: legs[0],
        own: false,
        built: true,
        inbound: true,
    };
    let script = MoveScript {
        on,
        moved: true,
        reseeded: false,
        offers: false,
        closed: false,
        queued: false,
    };
    let mut others = move_outcomes(script);
    others.retain(|(row, _)| {
        !matches!(
            row,
            Row::Dials | Row::FilterSend | Row::Tree | Row::LookupBackoff | Row::Connection
        )
    });
    // No link is capable yet, so the released pair keeps its connection, and
    // the leg's is the one the peer moves onto.
    others.push((Row::Connection, Outcome::Kept));
    let [before, after] = run_site(
        &mut nodes[1].node,
        &n0,
        msg3,
        &also,
        Some(&a0),
        moved,
        &others,
    )
    .await;
    check_held_at(before, after);
    cleanup_nodes(&mut nodes).await;
}

/// A crossing on two BLE links relinks each node's mark onto the link it
/// moves to.
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
