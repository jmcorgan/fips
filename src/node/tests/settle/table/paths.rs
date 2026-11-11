//! Cells at a change of a link's paths: a roam of a link's one path, a path
//! moved, the active path switched, and a path released while the link
//! lives. Roam is a plain test and its `_with_multipath_on` sibling; the
//! others have output only with multipath on, so each is a
//! `_with_multipath_on` test, and the column's plain test runs the same
//! script with multipath off and asserts there is none.

use super::*;
use crate::proto::link::LinkMessageType;
use fips_core::proto::path::wire::{PathAck, PathCaps, PathFlags};

/// The rows a roam's tests leave as built. A frame roams only a link that
/// holds its one original path, and [`dirty`] gives the link a second path,
/// an index entry at that path's pair, which the node's live audit refuses
/// without the path, and, with multipath on, a candidate a capable link may
/// admit as a path. The failure count is left too: the frame that roams the
/// path is authentic, and any authentic frame on a path starts its count
/// again, so a planted count cannot be kept across it.
const ONE_PATH: [Row; 4] = [Row::Paths, Row::Index, Row::Capability, Row::PathFailures];

/// [`dirty`] but for the rows in `skip`, each left as the peering built it.
/// Then close what the dirtying queued to close, as every step of the path
/// machine does at its end, so that the transition's own step does not read
/// as closing it.
async fn dirty_but(node: &mut Node, peer: &NodeAddr, skip: &[Row]) {
    for row in Row::all() {
        if !skip.contains(&row) {
            dirty_row(node, peer, row).await;
        }
    }
    node.drain_closes().await;
}

/// An address on node 0's transport that no node listens at, from which a
/// frame is made to arrive.
fn roamed() -> TransportAddr {
    TransportAddr::from_string("loopback:table-roamed")
}

/// An unmatched `PathAck`: a path message that answers no probe, so the path
/// machine refuses it and it changes nothing but by its frame.
fn stray_ack() -> Vec<u8> {
    PathAck {
        probe_id: 0x0dd,
        flags: PathFlags::default(),
        path_id: 0x0dd,
        echo_path_id: 0x0dd,
        caps: PathCaps::with_aggregate(false),
        rx_time_us: 0,
        rx_frames: 0,
        rx_bytes: 0,
        len: 0,
    }
    .encode()
}

/// The roam's cells the test states: a roam re-addresses the one path, and
/// with it drops the connected socket aimed at the address left and moves
/// the BLE mark, which loopback does not read.
const ROAMED: [(Row, Outcome); 4] = [
    (Row::Index, Outcome::Changed),
    (Row::Paths, Outcome::Changed),
    (Row::ConnectedUdp, Outcome::Changed),
    (Row::BleMark, Outcome::Changed),
];

/// Whether `peer`'s first path on `node` holds a connected socket: `None`
/// off the platforms that have one.
fn first_socket(node: &Node, peer: &NodeAddr) -> Option<bool> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return Some(node.get_peer(peer).is_some_and(|p| p.socket_at(0)));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (node, peer);
        None
    }
}

/// The readings around a transition on a link of one path, and whether its
/// path held a connected socket before and after.
struct Around {
    before: Seen,
    after: Seen,
    socket: (Option<bool>, Option<bool>),
}

impl Around {
    /// Hold a roam of the link's one path: the socket aimed at the address
    /// left is dropped, and every row does what the roam's cells say.
    fn roamed(&self) {
        assert!(
            self.socket.0 != Some(false),
            "precondition: the path held a connected socket before the roam"
        );
        assert!(
            self.socket.1 != Some(true),
            "defect: the roamed path kept the connected socket aimed at the address it left"
        );
        assert_cells(&self.before, &self.after, &Transition::Roam, &ROAMED);
    }
}

/// Node 0 sends `message` to node 1 on its link, and node 1 reads it as
/// arriving from `from` on the same transport. Returns node 1's readings of
/// node 0, over the pair the link was on and `from`, with every row but
/// [`ONE_PATH`] dirtied first.
async fn arrive_from(nodes: &mut [TestNode], message: &[u8], from: &TransportAddr) -> Around {
    let (a, b) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    let t = nodes[1].transport_id;
    let also = [
        PathRef {
            transport: t,
            addr: nodes[0].addr.clone(),
        },
        PathRef {
            transport: t,
            addr: from.clone(),
        },
    ];
    dirty_but(&mut nodes[1].node, &a, &ONE_PATH).await;
    let before = Seen::of(&nodes[1].node, &a, &also).await;
    let held = first_socket(&nodes[1].node, &a);
    nodes[0]
        .node
        .send_encrypted_link_message(&b, message)
        .await
        .expect("precondition: node 0's frame goes out");
    super::super::super::paths::deliver_from(&mut nodes[1], from).await;
    Around {
        before,
        after: Seen::of(&nodes[1].node, &a, &also).await,
        socket: (held, first_socket(&nodes[1].node, &a)),
    }
}

/// A heartbeat from an address the link is not at roams the link's one path
/// there, and does to each row what the roam's cell says.
async fn a_frame_roams(on: bool) {
    let mut nodes = peered(on).await;
    let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
    let around = arrive_from(&mut nodes, &heartbeat, &roamed()).await;
    cleanup_nodes(&mut nodes).await;
    around.roamed();
}

/// With multipath off, a heartbeat from a new address roams the link's one
/// path as the table says.
#[tokio::test]
async fn a_frame_from_a_new_address_roams_the_links_one_path_as_the_table_says() {
    a_frame_roams(false).await;
}

/// [`a_frame_from_a_new_address_roams_the_links_one_path_as_the_table_says`]
/// with multipath on.
#[tokio::test]
async fn a_frame_from_a_new_address_roams_the_links_one_path_as_the_table_says_with_multipath_on() {
    a_frame_roams(true).await;
}

/// With multipath off a path message's frame from a new address roams the
/// link's one path, as any frame does, and does what the roam's cell says.
#[tokio::test]
async fn a_path_messages_frame_from_a_new_address_roams_by_the_multipath_setting() {
    let mut nodes = peered(false).await;
    let around = arrive_from(&mut nodes, &stray_ack(), &roamed()).await;
    cleanup_nodes(&mut nodes).await;
    around.roamed();
}

/// With multipath on a path message's frame from a new address roams
/// nothing: the path, its connected socket and the BLE mark stay as they
/// were.
#[tokio::test]
async fn a_path_messages_frame_from_a_new_address_roams_by_the_multipath_setting_with_multipath_on()
{
    let mut nodes = peered(true).await;
    let Around { before, after, .. } = arrive_from(&mut nodes, &stray_ack(), &roamed()).await;
    cleanup_nodes(&mut nodes).await;
    let moved: Vec<_> = before
        .differing(&after)
        .into_iter()
        .filter(|r| ROAMED.iter().any(|(row, _)| row == r))
        .map(|r| (r, before.get(r).clone(), after.get(r).clone()))
        .collect();
    assert!(
        moved.is_empty(),
        "defect: with multipath on a path message's frame from a new address roamed the path: {moved:#?}"
    );
}

/// On two BLE nodes holding two links, node 1 the larger, node 0 moves its
/// frames from the link node 1 holds it on to the second: node 1 roams the
/// link's one path there, the mark moves from the link left to the link
/// roamed onto, and every row does what the roam's cell says.
#[cfg(ble_available)]
async fn a_ble_roam_relinks_the_mark(on: bool) {
    use super::super::super::ble::{
        base_config, larger_second, make_test_node_ble_from, two_links,
    };
    use super::super::super::rekey_parity::deliver;
    let config = || super::super::with_path(Config::new(), on);
    let mut nodes = vec![
        make_test_node_ble_from(1, base_config(), config()).await,
        make_test_node_ble_from(2, base_config(), config()).await,
    ];
    larger_second(&mut nodes);
    let (a0, _a1, a0x, a1x) = two_links(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let (n0, n1) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    let t = nodes[1].transport_id;
    let (left, onto) = (a0.to_transport_addr(), a0x.to_transport_addr());
    let also = [
        PathRef {
            transport: t,
            addr: left.clone(),
        },
        PathRef {
            transport: t,
            addr: onto.clone(),
        },
    ];
    let marks = |seen: &Seen| seen.get(Row::BleMark).clone();
    let mark = |m: bool, at: &TransportAddr| format!("{}/{at}: {m}", t.as_u32());
    let held = |seen: &Seen, m: bool, at: &TransportAddr| {
        marks(seen).is_some_and(|s| s.contains(&mark(m, at)))
    };
    let mut skip = ONE_PATH.to_vec();
    skip.push(Row::BleMark);
    dirty_but(&mut nodes[1].node, &n0, &skip).await;
    let before = Seen::of(&nodes[1].node, &n0, &also).await;
    let seated = first_socket(&nodes[1].node, &n0);
    assert!(
        held(&before, true, &left) && held(&before, false, &onto),
        "precondition: node 1 marks the link node 0 is on and not the second: {:?}",
        marks(&before)
    );

    // Node 0 sends on the second link, as after a reconnect at a new address.
    let t0 = nodes[0].transport_id;
    nodes[0]
        .node
        .get_peer_mut(&n1)
        .expect("precondition: node 0 holds node 1")
        .set_current_addr(t0, a1x.to_transport_addr());
    nodes[0]
        .node
        .send_encrypted_link_message(&n1, &[LinkMessageType::Heartbeat.to_byte()])
        .await
        .expect("precondition: node 0 sends on the second link");
    let mut arrived = false;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        deliver(&mut nodes[1]).await;
        if nodes[1]
            .node
            .get_peer(&n0)
            .and_then(ActivePeer::current_addr)
            == Some(&onto)
        {
            arrived = true;
            break;
        }
    }
    let around = Around {
        before,
        after: Seen::of(&nodes[1].node, &n0, &also).await,
        socket: (seated, first_socket(&nodes[1].node, &n0)),
    };
    cleanup_nodes(&mut nodes).await;
    assert!(
        arrived,
        "precondition: node 0's frame on the second link reached node 1 within 1 s"
    );
    assert!(
        held(&around.after, false, &left) && held(&around.after, true, &onto),
        "defect: the roam did not move the mark from the link left to the link roamed onto: before {:?}, after {:?}",
        marks(&around.before),
        marks(&around.after)
    );
    around.roamed();
}

/// With multipath off, a roam on a BLE link moves the mark to the link
/// roamed onto.
#[cfg(ble_available)]
#[tokio::test]
async fn a_roam_on_a_ble_link_relinks_the_mark() {
    a_ble_roam_relinks_the_mark(false).await;
}

/// [`a_roam_on_a_ble_link_relinks_the_mark`] with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn a_roam_on_a_ble_link_relinks_the_mark_with_multipath_on() {
    a_ble_roam_relinks_the_mark(true).await;
}

/// A link of two paths: node 0's link to node 1, with multipath set as `on`,
/// each node holding a second loopback transport `t2()` and node 0 offered
/// node 1's address on it. With multipath on node 0 holds `p`, its original
/// path on transport 1, active, and `q` on `t2()`, both Live; with it off,
/// `p` alone. Node 1 dialled; node 0's readings are the ones the tests take.
struct TwoPaths {
    nodes: Vec<TestNode>,
    /// Node 1.
    b: NodeAddr,
    /// Node 0's original path to node 1.
    p: PathRef,
    /// Node 0's path to node 1 on `t2()`.
    q: PathRef,
    /// Node 1's pair for `q`: node 0's address on `t2()`.
    q_at_b: PathRef,
}

/// Build [`TwoPaths`].
async fn two_paths(on: bool) -> TwoPaths {
    use super::super::super::paths::{second_transport, state_at, t2};
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 1, 0).await;
    drain_all_packets(&mut nodes, false).await;
    let a2 = second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let b = *nodes[1].node.node_addr();
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
    super::super::super::rekey_parity::pump(&mut nodes).await;
    let p = PathRef {
        transport: nodes[0].transport_id,
        addr: nodes[1].addr.clone(),
    };
    let held = |tn: &TestNode, to: &PathRef| state_at(tn, &b, to.transport, &to.addr);
    let q = PathRef {
        transport: t2(),
        addr: b2,
    };
    let live = Some(crate::peer::PathState::Live);
    assert_eq!(
        (held(&nodes[0], &p), held(&nodes[0], &q)),
        (live, live.filter(|_| on)),
        "precondition: node 0 holds p Live, and q Live with multipath on only"
    );
    assert_eq!(
        active(&nodes[0], &b),
        Some(p.clone()),
        "precondition: node 0's link is on p"
    );
    TwoPaths {
        nodes,
        b,
        p,
        q,
        q_at_b: PathRef {
            transport: t2(),
            addr: a2,
        },
    }
}

impl TwoPaths {
    /// The pairs node 0's readings cover, `p` and `q`, held or not.
    fn pairs(&self) -> [PathRef; 2] {
        [self.p.clone(), self.q.clone()]
    }

    /// Node 0's reading of node 1.
    async fn seen(&self) -> Seen {
        Seen::of(&self.nodes[0].node, &self.b, &self.pairs()).await
    }

    /// Dirty node 0's state of node 1 but for `skip`, seat a connected
    /// socket on each of its paths, and close what the dirtying queued, so
    /// the queue holds what it holds between steps.
    async fn dirty_but(&mut self, skip: &[Row]) {
        dirty_but(&mut self.nodes[0].node, &self.b, skip).await;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        seat_each(&mut self.nodes[0].node, &self.b);
        self.nodes[0].node.drain_closes().await;
    }

    /// Node 0's own identifier for its path at `to`.
    fn our_id(&self, to: &PathRef) -> u32 {
        let paths = self.nodes[0]
            .node
            .get_peer(&self.b)
            .and_then(ActivePeer::bundle)
            .expect("precondition: node 0 holds a bundle for node 1")
            .paths();
        paths
            .find(to.transport, &to.addr)
            .and_then(|i| paths.get(i))
            .map(|p| p.path_id())
            .expect("precondition: node 0 holds the path")
    }

    /// Node 1 sends `message` to node 0 on `via`, node 1's pair for one of
    /// node 0's paths, or on its active path for `None`, and node 0 handles
    /// what arrives.
    async fn sent_by_b(&mut self, message: &[u8], via: Option<&PathRef>) {
        let a = *self.nodes[0].node.node_addr();
        self.nodes[1]
            .node
            .send_via(&a, message, false, via)
            .await
            .expect("precondition: node 1's frame goes out");
        super::super::super::rekey_parity::deliver(&mut self.nodes[0]).await;
    }

    /// Node 1 sends a heartbeat on `q`, so that node 0's link takes `q` as
    /// the path the peer sends on.
    async fn peer_on_q(&mut self) {
        let via = self.q_at_b.clone();
        self.sent_by_b(&[LinkMessageType::Heartbeat.to_byte()], Some(&via))
            .await;
    }
}

/// The pair node 0's link to `peer` sends on.
fn active(tn: &TestNode, peer: &NodeAddr) -> Option<PathRef> {
    let path = tn.node.get_peer(peer)?.active_path()?;
    Some(PathRef {
        transport: path.transport_id(),
        addr: path.addr().clone(),
    })
}

/// Whether each of `peer`'s paths on `node` holds a connected socket, by
/// pair.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sockets(node: &Node, peer: &NodeAddr) -> Vec<(PathRef, bool)> {
    let Some(p) = node.get_peer(peer) else {
        return Vec::new();
    };
    let Some(bundle) = p.bundle() else {
        return Vec::new();
    };
    bundle
        .paths()
        .paths()
        .iter()
        .enumerate()
        .map(|(i, path)| {
            let to = PathRef {
                transport: path.transport_id(),
                addr: path.addr().clone(),
            };
            (to, p.socket_at(i))
        })
        .collect()
}

/// Seat a real connected socket, aimed at the loopback discard port, on each
/// of `peer`'s paths on `node`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn seat_each(node: &mut Node, peer: &NodeAddr) {
    use crate::transport::udp::{ConnectedPeerSocket, PeerRecvDrain, UdpStats, open_connected_fd};
    let Some(p) = node.get_peer_mut(peer) else {
        return;
    };
    let held: Vec<TransportId> = p
        .bundle()
        .map(|b| b.paths().paths().iter().map(|x| x.transport_id()).collect())
        .unwrap_or_default();
    for (i, t) in held.into_iter().enumerate() {
        let local: std::net::SocketAddr = "0.0.0.0:0".parse().expect("precondition: an address");
        let target: std::net::SocketAddr = "127.0.0.1:9".parse().expect("precondition: an address");
        let fd = open_connected_fd(local, target, 65_536, 65_536, None)
            .expect("precondition: a connected UDP socket opens");
        let socket = std::sync::Arc::new(ConnectedPeerSocket::from_fd(fd, target, local));
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let drain = PeerRecvDrain::spawn(
            socket.clone(),
            t,
            target,
            packet_tx,
            std::sync::Arc::new(UdpStats::new()),
        )
        .expect("precondition: the socket's recv drain starts");
        p.seat_socket(i, socket, drain);
    }
}

/// Hold every row against the cells of `steps`, transitions one step of the
/// path machine made together: a row may change where any of their cells
/// changes it, and must stay where each of them keeps it. `others` states
/// the outcome of every row a cell of any step turns on the script, as for
/// [`assert_cells`], and names no other row.
fn assert_steps(before: &Seen, after: &Seen, steps: &[Transition], others: &[(Row, Outcome)]) {
    for (row, _) in others {
        assert!(
            steps
                .iter()
                .any(|t| expect(cell(*row, t)) == Expect::Stated),
            "precondition: {row:?} turns on the script at none of {steps:?}; the test may not state it"
        );
    }
    let checks: Vec<Checked> = steps
        .iter()
        .map(|t| {
            let mine: Vec<(Row, Outcome)> = others
                .iter()
                .filter(|(r, _)| expect(cell(*r, t)) == Expect::Stated)
                .copied()
                .collect();
            check_cells(before, after, t, &mine)
        })
        .collect();
    let changed = before.differing(after);
    let mut wrong = Vec::new();
    for row in Row::all() {
        let lead = format!("{row:?} ");
        let flagged: Vec<&String> = checks
            .iter()
            .filter_map(|c| c.breaches.iter().find(|b| b.starts_with(&lead)))
            .collect();
        // A changed row breaches only if every step keeps it; a kept row
        // breaches if any step changes it.
        let breach = if changed.contains(&row) {
            flagged.len() == checks.len()
        } else {
            !flagged.is_empty()
        };
        if breach {
            wrong.extend(flagged.into_iter().cloned());
        }
    }
    assert!(
        wrong.is_empty(),
        "defect: the step does not do what the table says of {steps:?}: {wrong:#?}"
    );
}

// ---------------------------------------------------------------- Follow

/// An address on node 0's first transport that no node listens at, which a
/// path is moved to.
fn followed() -> TransportAddr {
    TransportAddr::from_string("loopback:table-followed")
}

/// Node 1 sends a probe naming its identifier for `p`, and node 0 reads it
/// as arriving on `p`'s transport from [`followed`]. Returns the readings
/// before and after, every row dirtied first but the failure count, which
/// the probe's authentic frame starts again on the path it concerns.
async fn probe_from_elsewhere(pair: &mut TwoPaths) -> (Seen, Seen, PathRef) {
    use super::super::super::paths::{deliver_from, probe};
    let to = PathRef {
        transport: pair.p.transport,
        addr: followed(),
    };
    pair.dirty_but(&[Row::PathFailures]).await;
    let mut also = pair.pairs().to_vec();
    also.push(to.clone());
    let before = Seen::of(&pair.nodes[0].node, &pair.b, &also).await;
    let theirs = {
        let paths = pair.nodes[0]
            .node
            .get_peer(&pair.b)
            .and_then(ActivePeer::bundle)
            .expect("precondition: node 0 holds a bundle for node 1")
            .paths();
        paths
            .find(pair.p.transport, &pair.p.addr)
            .and_then(|i| paths.get(i))
            .and_then(|p| p.peer_id())
            .unwrap_or(7)
    };
    let a = *pair.nodes[0].node.node_addr();
    pair.nodes[1]
        .node
        .send_encrypted_link_message(&a, &probe(theirs, 64))
        .await
        .expect("precondition: node 1's probe goes out");
    deliver_from(&mut pair.nodes[0], &to.addr).await;
    let after = Seen::of(&pair.nodes[0].node, &pair.b, &also).await;
    (before, after, to)
}

/// The link's own index entry for `to`, on node 0.
fn entry(pair: &TwoPaths, to: &PathRef) -> Option<LinkId> {
    pair.nodes[0]
        .node
        .links
        .index()
        .get(&(to.transport, to.addr.clone()))
        .copied()
}

/// With multipath off the same probe moves no path: no path is held but
/// `p` and the second path [`dirty`] gives the link, so the frame does not
/// roam either, and the link's paths and index entries stay as they were.
#[tokio::test]
async fn a_probe_from_a_new_address_moves_a_path_of_a_two_path_link_only_with_multipath_on() {
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    let mut pair = two_paths(false).await;
    let (before, after, _) = probe_from_elsewhere(&mut pair).await;
    let moved = logs.lines_with("Path moved to a new address");
    drop(guard);
    cleanup_nodes(&mut pair.nodes).await;
    let changed: Vec<Row> = before
        .differing(&after)
        .into_iter()
        .filter(|r| matches!(r, Row::Paths | Row::Index))
        .collect();
    assert!(
        moved.is_empty() && changed.is_empty(),
        "defect: with multipath off a path was moved: {moved:?}; changed {changed:?}"
    );
}

/// With multipath on, node 1's probe on `p` from a new address moves `p`
/// there: the new pair is named, and so is `p`'s, since the link was set up
/// there; its connected socket goes and `q`'s stays, and every row does what the moved path's cell says.
#[tokio::test]
async fn a_probe_from_a_new_address_moves_a_path_of_a_two_path_link_with_multipath_on() {
    let mut pair = two_paths(true).await;
    let link = pair.nodes[0]
        .node
        .get_peer(&pair.b)
        .map(ActivePeer::link_id)
        .expect("precondition: node 0 holds node 1");
    let p = pair.p.clone();
    assert_eq!(
        entry(&pair, &p),
        Some(link),
        "precondition: p's pair names the link"
    );
    let (before, after, to) = probe_from_elsewhere(&mut pair).await;
    let entries = (entry(&pair, &p), entry(&pair, &to));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let seated = sockets(&pair.nodes[0].node, &pair.b);
    cleanup_nodes(&mut pair.nodes).await;
    assert_eq!(
        entries,
        (Some(link), Some(link)),
        "defect: the moved path's new pair is not named, or p's pair, where the link was set up, no longer is"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(
        seated.contains(&(to.clone(), false)) && seated.contains(&(pair.q.clone(), true)),
        "defect: the moved path kept its socket or q lost its own: {seated:?}"
    );
    assert_cells(
        &before,
        &after,
        &Transition::Follow,
        &[
            (Row::Index, Outcome::Changed),
            (Row::Paths, Outcome::Changed),
            (Row::ConnectedUdp, Outcome::Changed),
        ],
    );
}

// ---------------------------------------------------------------- Switch

/// The ways node 0's link to node 1 is moved off `p`, its active path.
#[derive(Clone, Copy, Debug)]
enum Cause {
    /// Node 1 closes `p`, which goes Dead.
    Mandatory,
    /// `p`'s transport loses its interface, which discards `p`.
    Handover,
    /// `p`'s transport becomes a backup, of a lower tier than `q`'s.
    Discretionary,
    /// The operator pins the link to `q`.
    Pinned,
}

impl Cause {
    /// The rows a test of this cause leaves as built: a pin of `p` holds the
    /// link on `p` against a discretionary change, and the loss of `p`'s
    /// interface lifts a pin of its transport and holds back its candidates,
    /// which are that input's own effects and not a switch's or a release's,
    /// and discards the second path and index entry [`dirty`] puts there.
    fn skip(self) -> &'static [Row] {
        match self {
            Cause::Mandatory | Cause::Pinned => &[],
            Cause::Discretionary => &[Row::Pin],
            Cause::Handover => &[Row::Pin, Row::Capability, Row::Paths, Row::Index],
        }
    }

    /// Carry out the cause on `pair`.
    async fn run(self, pair: &mut TwoPaths) {
        use super::super::super::paths::loopback_mut;
        use fips_core::proto::path::Input;
        use fips_core::proto::path::wire::{PathClose, PathCloseReason};
        let b = pair.b;
        let p = pair.p.clone();
        match self {
            Cause::Mandatory => {
                let close = PathClose {
                    path_id: pair.our_id(&p),
                    reason: PathCloseReason::Operator,
                };
                let via = pair.q_at_b.clone();
                pair.sent_by_b(&close.encode(), Some(&via)).await;
            }
            Cause::Handover => {
                let input = Input::Present {
                    transport: p.transport,
                    present: false,
                };
                pair.nodes[0].node.step_path(&b, input).await;
            }
            Cause::Discretionary => {
                loopback_mut(&mut pair.nodes[0], p.transport)
                    .set_role(crate::config::TransportRole::Backup);
                pair.nodes[0].node.step_path(&b, Input::Poll).await;
            }
            Cause::Pinned => {
                let input = Input::Pin {
                    transport: pair.q.transport,
                    addr: Some(pair.q.addr.clone()),
                };
                pair.nodes[0].node.step_path(&b, input).await;
            }
        }
    }
}

/// The switch's cells the test states, at `p`'s link moved to `q`: the
/// index kept, since `q` is a proven path and so named already, the active
/// path changed, the old active path's socket
/// cleared, the rekey machine's indices kept, the path MTU seeded from `q`,
/// and the cost hold started.
const SWITCHED: [(Row, Outcome); 6] = [
    (Row::Index, Outcome::Kept),
    (Row::Paths, Outcome::Changed),
    (Row::ConnectedUdp, Outcome::Changed),
    (Row::RekeyMachine, Outcome::Kept),
    (Row::PathMtu, Outcome::Changed),
    (Row::Pin, Outcome::Changed),
];

/// With multipath on, `cause` moves node 0's link from `p` to `q`, clears
/// `p`'s socket and keeps `q`'s, and every row does what the switch's cells
/// say, and at a handover the release's of `p` too.
async fn a_switch(cause: Cause) {
    let mut pair = two_paths(true).await;
    pair.dirty_but(cause.skip()).await;
    let before = pair.seen().await;
    cause.run(&mut pair).await;
    let after = pair.seen().await;
    let now = active(&pair.nodes[0], &pair.b);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let seated = sockets(&pair.nodes[0].node, &pair.b);
    cleanup_nodes(&mut pair.nodes).await;
    assert_eq!(
        now,
        Some(pair.q.clone()),
        "defect: {cause:?} did not move the link from p to q"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let p_cleared = !seated.contains(&(pair.p.clone(), true));
        assert!(
            p_cleared && seated.contains(&(pair.q.clone(), true)),
            "defect: at {cause:?} the old active path kept its socket or q lost its own: {seated:?}"
        );
    }
    match cause {
        Cause::Handover => {
            // The release of `p`, the link's setup pair, leaves it named on
            // this line, where the link record's own pair names the link
            // while it lives, so the index is kept at both steps.
            let mut others = SWITCHED.to_vec();
            others.extend([
                (Row::PathFailures, Outcome::Changed),
                (Row::Capability, Outcome::Changed),
            ]);
            assert_steps(
                &before,
                &after,
                &[Transition::Switch, Transition::Release { keep: true }],
                &others,
            );
        }
        Cause::Mandatory | Cause::Discretionary | Cause::Pinned => {
            assert_cells(&before, &after, &Transition::Switch, &SWITCHED);
        }
    }
}

/// The active path closed by the peer moves the link, as the switch's cells
/// say.
#[tokio::test]
async fn the_active_path_closed_by_the_peer_switches_the_link_as_the_table_says_with_multipath_on()
{
    a_switch(Cause::Mandatory).await;
}

/// The active path's interface leaving hands the link over, as the switch's
/// and the release's cells say.
#[tokio::test]
async fn the_active_paths_interface_leaving_hands_the_link_over_as_the_table_says_with_multipath_on()
 {
    a_switch(Cause::Handover).await;
}

/// A path of a higher tier than the active one moves the link at once, as
/// the switch's cells say.
#[tokio::test]
async fn a_path_of_a_higher_tier_switches_the_link_as_the_table_says_with_multipath_on() {
    a_switch(Cause::Discretionary).await;
}

/// The operator's pin of another Live path moves the link at once, as the
/// switch's cells say.
#[tokio::test]
async fn the_operators_pin_switches_the_link_as_the_table_says_with_multipath_on() {
    a_switch(Cause::Pinned).await;
}

/// With multipath off, the scripts that switch the link with it on, each on
/// a fresh pair, switch nothing: no path is held but `p`, and the link stays
/// on it. The loss of `p`'s interface is left out: with one path it orphans
/// the link, which is a removal's cell.
#[tokio::test]
async fn a_closed_a_lower_tier_or_a_pinned_away_active_path_switches_the_link_only_with_multipath_on()
 {
    for cause in [Cause::Mandatory, Cause::Discretionary, Cause::Pinned] {
        let (logs, guard) = crate::testutil::capture_logs_scoped();
        let mut pair = two_paths(false).await;
        pair.dirty_but(cause.skip()).await;
        let before = pair.seen().await;
        cause.run(&mut pair).await;
        let after = pair.seen().await;
        let now = active(&pair.nodes[0], &pair.b);
        let switched = logs.lines_with("Path switched");
        drop(guard);
        cleanup_nodes(&mut pair.nodes).await;
        assert!(
            switched.is_empty() && now == Some(pair.p.clone()),
            "defect: with multipath off {cause:?} switched the link to {now:?}: {switched:?}"
        );
        assert_eq!(
            before.get(Row::Paths),
            after.get(Row::Paths),
            "defect: with multipath off {cause:?} changed the link's paths"
        );
    }
}

// ---------------------------------------------------------------- Release

/// With multipath on, `q`'s transport removed discards `q` while the link
/// lives on `p`. With `peer_on_q`, node 1 last sent on `q`, so its
/// connection is kept; otherwise it is closed in the same step. `q`'s pair
/// is claimed for the link first, as a switch to it would have, so the
/// release has an index entry to drop.
async fn a_release(peer_on_q: bool) {
    use super::super::super::paths::loopback;
    use fips_core::proto::path::Input;
    let mut pair = two_paths(true).await;
    let link = pair.nodes[0]
        .node
        .get_peer(&pair.b)
        .map(ActivePeer::link_id)
        .expect("precondition: node 0 holds node 1");
    let q = pair.q.clone();
    pair.nodes[0]
        .node
        .links
        .claim(link, (q.transport, q.addr.clone()));
    if peer_on_q {
        pair.peer_on_q().await;
    }
    pair.dirty_but(&[]).await;
    let before = pair.seen().await;
    let closed_before = loopback(&pair.nodes[0], q.transport).closed();
    let b = pair.b;
    pair.nodes[0]
        .node
        .step_path(
            &b,
            Input::Removed {
                transport: q.transport,
            },
        )
        .await;
    let after = pair.seen().await;
    let closed = loopback(&pair.nodes[0], q.transport).closed();
    let now = active(&pair.nodes[0], &pair.b);
    cleanup_nodes(&mut pair.nodes).await;
    assert_eq!(
        (now, closed_before.len()),
        (Some(pair.p.clone()), 0),
        "precondition: the link stays on p, and q's connection was not closed before"
    );
    let want: Vec<TransportAddr> = if peer_on_q {
        vec![]
    } else {
        vec![q.addr.clone()]
    };
    assert_eq!(
        closed, want,
        "defect: q's connection closes only when the peer did not last send on it"
    );
    let keep = peer_on_q;
    let mut others = vec![
        (Row::Index, Outcome::Changed),
        (Row::Paths, Outcome::Changed),
        (Row::Capability, Outcome::Changed),
        (Row::PathFailures, Outcome::Changed),
        (Row::ConnectedUdp, Outcome::Changed),
    ];
    if !keep {
        // The close is queued and drained in the release's own step; the
        // BLE mark is not read on loopback.
        others.extend([
            (Row::Connection, Outcome::Changed),
            (Row::BleMark, Outcome::Changed),
            (Row::PathCloses, Outcome::Kept),
        ]);
    }
    assert_cells(&before, &after, &Transition::Release { keep }, &others);
}

/// A path released while the peer sends on another has its connection
/// closed, as the release's cells say.
#[tokio::test]
async fn a_path_released_while_the_peer_sends_on_another_closes_its_connection_as_the_table_says_with_multipath_on()
 {
    a_release(false).await;
}

/// A path released while the peer still sends on it keeps its connection,
/// as the release's cells say.
#[tokio::test]
async fn a_path_released_while_the_peer_sends_on_it_keeps_its_connection_as_the_table_says_with_multipath_on()
 {
    a_release(true).await;
}

/// With multipath off, the scripts that release `q` with it on release
/// nothing: no path but `p` is held, and no connection is closed.
#[tokio::test]
async fn a_path_released_while_the_link_lives_only_with_multipath_on() {
    use super::super::super::paths::loopback;
    use fips_core::proto::path::Input;
    for peer_on_q in [false, true] {
        let mut pair = two_paths(false).await;
        if peer_on_q {
            pair.peer_on_q().await;
        }
        pair.dirty_but(&[]).await;
        let before = pair.seen().await;
        let b = pair.b;
        let t = pair.q.transport;
        pair.nodes[0]
            .node
            .step_path(&b, Input::Removed { transport: t })
            .await;
        let after = pair.seen().await;
        let closed = loopback(&pair.nodes[0], t).closed();
        cleanup_nodes(&mut pair.nodes).await;
        assert!(
            closed.is_empty() && before.get(Row::Paths) == after.get(Row::Paths),
            "defect: with multipath off removing q's transport released a path (peer on q {peer_on_q}): closed {closed:?}, paths before {:?}, after {:?}",
            before.get(Row::Paths),
            after.get(Row::Paths)
        );
    }
}

// ------------------------------------------------- The BLE mark on two paths

/// On [`ble_paths`], with node 1 last sending on the loopback path `q`, node
/// 1 closes the BLE path `p`, sent on `p`, and node 0 handles what arrives
/// until its link has left `p`, for up to a second. Returns `p` and `q`.
#[cfg(ble_available)]
async fn close_the_ble_path(pair: &mut BlePaths) -> (PathRef, PathRef) {
    use super::super::super::rekey_parity::deliver;
    use fips_core::proto::path::wire::{PathClose, PathCloseReason};
    let (a, b) = (
        *pair.nodes[0].node.node_addr(),
        *pair.nodes[1].node.node_addr(),
    );
    let p = PathRef {
        transport: pair.nodes[0].transport_id,
        addr: pair.nodes[1].addr.clone(),
    };
    let q = PathRef {
        transport: pair.t2,
        addr: pair.b2.clone(),
    };
    let path_id = {
        let paths = pair.nodes[0]
            .node
            .get_peer(&b)
            .and_then(ActivePeer::bundle)
            .expect("precondition: node 0 holds a bundle for node 1")
            .paths();
        paths
            .find(p.transport, &p.addr)
            .and_then(|i| paths.get(i))
            .map(|x| x.path_id())
            .expect("precondition: node 0 holds the BLE path")
    };
    let close = PathClose {
        path_id,
        reason: PathCloseReason::Operator,
    };
    // Both ends key the BLE link at node 1's address.
    let on_p = PathRef {
        transport: pair.nodes[1].transport_id,
        addr: pair.nodes[1].addr.clone(),
    };
    pair.nodes[1]
        .node
        .send_via(&a, &close.encode(), false, Some(&on_p))
        .await
        .expect("precondition: node 1's close goes out on the BLE path");
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        deliver(&mut pair.nodes[0]).await;
        if active(&pair.nodes[0], &b).as_ref() == Some(&q) {
            break;
        }
    }
    (p, q)
}

/// Node 1 sends a heartbeat on the loopback path of [`ble_paths`], so that
/// node 0's link takes it as the path the peer sends on.
#[cfg(ble_available)]
async fn peer_on_loopback(pair: &mut BlePaths) {
    let a = *pair.nodes[0].node.node_addr();
    let on_q = PathRef {
        transport: pair.t2,
        addr: pair.a2.clone(),
    };
    pair.nodes[1]
        .node
        .send_via(
            &a,
            &[LinkMessageType::Heartbeat.to_byte()],
            false,
            Some(&on_q),
        )
        .await
        .expect("precondition: node 1's heartbeat goes out on the loopback path");
    pair.shuttle().await;
}

/// Whether `seen` reads the BLE mark at `p` as `mark`.
#[cfg(ble_available)]
fn marked(seen: &Seen, p: &PathRef, mark: bool) -> bool {
    seen.get(Row::BleMark)
        .as_deref()
        .is_some_and(|m| m.contains(&format!("{}/{}: {mark}", p.transport.as_u32(), p.addr)))
}

/// With multipath on, the operator's pin of the loopback path moves node 0's
/// link off the BLE path and leaves the BLE path's mark as it was, and every
/// row does what the switch's cells say. No frame crosses the switch.
#[cfg(ble_available)]
#[tokio::test]
async fn a_switch_off_a_ble_path_leaves_the_mark_with_multipath_on() {
    use fips_core::proto::path::Input;
    let mut pair = ble_paths().await;
    let b = *pair.nodes[1].node.node_addr();
    let (p, q) = (
        PathRef {
            transport: pair.nodes[0].transport_id,
            addr: pair.nodes[1].addr.clone(),
        },
        PathRef {
            transport: pair.t2,
            addr: pair.b2.clone(),
        },
    );
    dirty_but(&mut pair.nodes[0].node, &b, &[Row::BleMark]).await;
    let before = Seen::of(&pair.nodes[0].node, &b, &[p.clone(), q.clone()]).await;
    let was = active(&pair.nodes[0], &b);
    let pin = Input::Pin {
        transport: q.transport,
        addr: Some(q.addr.clone()),
    };
    pair.nodes[0].node.step_path(&b, pin).await;
    let after = Seen::of(&pair.nodes[0].node, &b, &[p.clone(), q.clone()]).await;
    let now = active(&pair.nodes[0], &b);
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        was == Some(p.clone()) && marked(&before, &p, true),
        "precondition: node 0's link is on the BLE path, which is marked: active {was:?}, mark {:?}",
        before.get(Row::BleMark)
    );
    assert_eq!(
        now,
        Some(q),
        "defect: the pin did not move the link off the BLE path"
    );
    assert!(
        marked(&after, &p, true),
        "defect: the switch off the BLE path changed its mark: {:?}",
        after.get(Row::BleMark)
    );
    assert_cells(&before, &after, &Transition::Switch, &SWITCHED);
}

/// With multipath on, the BLE path closed and its link on the loopback path,
/// the BLE transport's removal discards the BLE path, closes its connection,
/// since the peer sends on the other, and so ends its mark, and every row
/// does what the release's cells say.
#[cfg(ble_available)]
#[tokio::test]
async fn a_released_ble_path_loses_its_mark_with_multipath_on() {
    use fips_core::proto::path::Input;
    let mut pair = ble_paths().await;
    let b = *pair.nodes[1].node.node_addr();
    peer_on_loopback(&mut pair).await;
    let (p, q) = close_the_ble_path(&mut pair).await;
    assert_eq!(
        active(&pair.nodes[0], &b),
        Some(q.clone()),
        "precondition: node 0's link left the BLE path"
    );
    dirty_but(&mut pair.nodes[0].node, &b, &[Row::BleMark]).await;
    let before = Seen::of(&pair.nodes[0].node, &b, &[p.clone(), q.clone()]).await;
    pair.nodes[0]
        .node
        .step_path(
            &b,
            Input::Removed {
                transport: p.transport,
            },
        )
        .await;
    let after = Seen::of(&pair.nodes[0].node, &b, &[p.clone(), q.clone()]).await;
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        marked(&before, &p, true),
        "precondition: the BLE path is marked: {:?}",
        before.get(Row::BleMark)
    );
    assert_eq!(
        after.get(Row::BleMark),
        &None,
        "defect: the released BLE path's link is still pooled and marked"
    );
    assert_cells(
        &before,
        &after,
        &Transition::Release { keep: false },
        &[
            // The BLE path is the pair of the link's own record, whose
            // entry keeps naming the link while it lives.
            (Row::Index, Outcome::Kept),
            (Row::Paths, Outcome::Changed),
            (Row::Capability, Outcome::Kept),
            (Row::PathFailures, Outcome::Changed),
            (Row::ConnectedUdp, Outcome::Changed),
            (Row::Connection, Outcome::Changed),
            (Row::BleMark, Outcome::Changed),
            (Row::PathCloses, Outcome::Kept),
        ],
    );
}
