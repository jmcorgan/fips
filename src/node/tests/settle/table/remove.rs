//! Cells at removal: a peer removed with nothing installed in its place, for
//! each cause, each test a plain one and its `_with_multipath_on` sibling.
//!
//! Each cause is driven at the site that takes it: a peer silent past the
//! link-dead timeout by the heartbeat check (`Dead`); a link whose last path
//! loses its interface by a detach stepped into its bundle, whose
//! `Output::Orphaned` removes the peer (`Orphaned`); a Disconnect from the
//! peer, handed to the link-message dispatch (`Disconnect`); the operator's
//! disconnect through the control interface (`Admin`); and the link rekey
//! machine ending the link, as a `Teardown` handed to the step runner, since
//! the send counter's hard limit cannot be waited for (`Ended`).
//!
//! Before each removal the peer is dirtied, the node is told to reconnect
//! to it, so that the reconnect schedule's cells show, a dial of the node's
//! own to the peer is left in flight in place of the one `dirty` notes on
//! the peer's link, and the bootstrap mark `dirty` leaves on the peer's
//! transport is taken off again, since a removal drops a bootstrap transport
//! no one else uses, transport and all. The bootstrap tests keep the mark
//! and start no dial.
//!
//! The plain tests run on a loopback link of one path with multipath off,
//! where no link is capable and every connection is kept. The siblings run
//! on a capable link of two paths, where the removal queues a close for
//! every path but the one the peer is active on; one more test runs with
//! multipath on and a link not known capable, which keeps them all. The BLE
//! tests run on the BLE pair at both settings, for the verified mark.

use super::super::super::paths::{t2, two_transports};
use super::*;
use crate::config::PeerConfig;
use crate::peer::LinkOutput;
use fips_core::proto::path::Input;
use fips_core::proto::rekey::Teardown;

/// A way a peer is removed with nothing installed in its place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    /// Silent past the link-dead timeout, reaped by the heartbeat check.
    Dead,
    /// Its link's last path lost its interface.
    Orphaned,
    /// It sent a Disconnect.
    Disconnect,
    /// The operator disconnected it.
    Admin,
    /// Its link rekey machine ended the link.
    Ended,
}

impl Cause {
    /// The cause as the table names it.
    fn why(self) -> Why {
        match self {
            Cause::Dead => Why::Dead,
            Cause::Orphaned => Why::Orphaned,
            Cause::Disconnect => Why::Disconnect,
            Cause::Admin => Why::Admin,
            Cause::Ended => Why::Ended,
        }
    }

    /// The transition the removal is.
    fn transition(self) -> Transition {
        Transition::Remove { why: self.why() }
    }
}

/// The pairs `peer`'s paths hold on `node` now.
fn held_pairs(node: &Node, peer: &NodeAddr) -> Vec<PathRef> {
    pairs(node.get_peer(peer), &[])
}

/// The peer's current pair on `node`.
fn current(node: &Node, peer: &NodeAddr) -> PathRef {
    let p = node.get_peer(peer).expect("precondition: the peer is held");
    PathRef {
        transport: p.transport_id().expect("precondition: the peer has a path"),
        addr: p
            .current_addr()
            .cloned()
            .expect("precondition: the peer has a path"),
    }
}

/// Configure node `i` to reconnect to node `j`, so that a removal's
/// reconnect cells act on a peer the node is told to keep.
fn reconnect_to(nodes: &mut [TestNode], i: usize, j: usize) {
    let npub = nodes[j].node.npub();
    nodes[i].node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.peers.push(PeerConfig::new(npub, "udp", "127.0.0.1:9"));
        ctx.config = std::sync::Arc::new(cfg);
    });
}

/// Take off the bootstrap mark [`dirty`] leaves on `peer`'s transport.
fn unmark_bootstrap(node: &mut Node, peer: &NodeAddr) {
    let transport = current(node, peer).transport;
    node.supervisor
        .nostr_rendezvous
        .remove_bootstrap_transport(&transport);
}

/// Remove `peer` from `node` by `cause`, at the site that takes it.
async fn remove_by(node: &mut Node, peer: &NodeAddr, cause: Cause) {
    match cause {
        Cause::Dead => {
            node.replace_context(|ctx| {
                let mut cfg = (*ctx.config).clone();
                cfg.node.link_dead_timeout_secs = 0;
                ctx.config = std::sync::Arc::new(cfg);
            });
            node.check_link_heartbeats().await;
        }
        Cause::Orphaned => {
            let transport = current(node, peer).transport;
            assert!(
                held_pairs(node, peer)
                    .iter()
                    .all(|p| p.transport == transport),
                "precondition: every path of the peer is on the transport that goes"
            );
            node.step_path(
                peer,
                Input::Present {
                    transport,
                    present: false,
                },
            )
            .await;
        }
        Cause::Disconnect => {
            let at = current(node, peer);
            let bye = crate::proto::fmp::wire::Disconnect::new(
                crate::proto::fmp::wire::DisconnectReason::Shutdown,
            )
            .encode();
            node.dispatch_link_message(peer, &bye, false, (at.transport, &at.addr), bye.len())
                .await;
        }
        Cause::Admin => {
            let npub = node
                .get_peer(peer)
                .map(ActivePeer::npub)
                .expect("precondition: the peer is held");
            node.api_disconnect(&npub)
                .await
                .expect("precondition: the operator's disconnect is taken");
        }
        Cause::Ended => {
            let out = std::iter::once(LinkOutput::Teardown(Teardown::CounterExhausted)).collect();
            node.run_link_step(peer, out).await;
        }
    }
}

/// What a removal test's script decides of the cells that turn on it.
struct Script {
    cause: Cause,
    /// The pairs the removal must queue a close for: with a capable link,
    /// every path but the one the peer is active on, its original; with a
    /// link not known capable, none.
    unkept: Vec<PathRef>,
    /// Whether the peer's transport still carries the bootstrap mark, so
    /// that the removal of its last user drops it.
    bootstrap: bool,
    /// Whether the unkept pairs are on a transport that records the close
    /// asked of it (loopback does; the BLE mock at a spare address holds no
    /// connection to close).
    recorded: bool,
}

/// What the peer held just before its removal that a stated cell turns on.
struct Facts {
    /// `is_heard`: a frame, or this node initiated.
    heard: bool,
    /// `heard`: a frame since promotion.
    framed: bool,
    /// The peer's link.
    link: LinkId,
    /// The peer's current pair.
    current: PathRef,
}

impl Facts {
    /// Read the facts of `peer` on `node`.
    fn of(node: &Node, peer: &NodeAddr) -> Facts {
        let p = node.get_peer(peer).expect("precondition: the peer is held");
        Facts {
            heard: p.is_heard(),
            framed: p.heard(),
            link: p.link_id(),
            current: current(node, peer),
        }
    }
}

/// The outcome of each cell at the removal that turns on the script.
fn stated(script: &Script, facts: &Facts) -> Vec<(Row, Outcome)> {
    let o = |changed: bool| {
        if changed {
            Outcome::Changed
        } else {
            Outcome::Kept
        }
    };
    let cause = script.cause;
    // The path step that orphans a peer drains the close queue before it
    // returns; no other removal site drains it.
    let drained = cause == Cause::Orphaned;
    let mut out = vec![
        // The operator's disconnect closes the current pair; an orphaning
        // step closes what it queued; a dropped transport is read as gone.
        (
            Row::Connection,
            o(cause == Cause::Admin
                || script.bootstrap
                || (drained && script.recorded && !script.unkept.is_empty())),
        ),
        (Row::Bootstrap, o(script.bootstrap)),
        // The entry `dirty` seeded goes with the peer.
        (Row::PathMtu, Outcome::Changed),
        (Row::FilterSend, Outcome::Changed),
        (Row::Tree, Outcome::Changed),
        // `dirty` opened a session; it ends only with a heard peering.
        (Row::Session, o(facts.heard)),
        (Row::Silent, o(!facts.framed)),
        (Row::PathCloses, o(drained || !script.unkept.is_empty())),
        // Forgotten at the next discovery tick, which no removal runs.
        (Row::PathListings, Outcome::Kept),
        // `dirty` left a connect waited for, which the removal forgets.
        (Row::PathConnects, Outcome::Changed),
        // Gone at the next read, which no removal runs. The reading changes
        // all the same: it covers only the held peer's link and links no
        // held peer names, and the removed link is neither, so
        // `assert_left` checks the reading itself.
        (Row::PathCarrier, Outcome::Changed),
        // The closed machine's record is filed under the peer's epoch.
        (Row::Records, Outcome::Changed),
    ];
    match cause {
        Cause::Dead => {
            // Stepped with the link found dead, then removed.
            out.push((Row::ControlMachine, Outcome::Changed));
        }
        Cause::Disconnect => {}
        // The current pair's connection is closed, and on BLE its pooled
        // mark goes with it.
        Cause::Admin => out.push((Row::BleMark, Outcome::Changed)),
        // Nothing closes the connection or clears the mark: an orphaned
        // link has no active path, so the removal reads no pair to clear,
        // and the paths the detach discarded were kept.
        Cause::Orphaned | Cause::Ended => out.push((Row::BleMark, Outcome::Kept)),
    }
    match cause {
        // A peer the node is told to reconnect to is scheduled again.
        Cause::Dead | Cause::Orphaned | Cause::Disconnect => {
            out.push((Row::Reconnect, Outcome::Changed));
        }
        Cause::Admin | Cause::Ended => {}
    }
    out
}

/// How often a close was asked at each of `pairs` on a loopback transport.
fn closes_asked(node: &Node, pairs: &[PathRef]) -> Vec<(String, usize)> {
    pairs
        .iter()
        .filter_map(|to| match node.transports.get(&to.transport) {
            Some(TransportHandle::Loopback(t)) => Some((
                named(to),
                t.closed().iter().filter(|a| **a == to.addr).count(),
            )),
            _ => None,
        })
        .collect()
}

/// The pairs of `pairs` whose connection the removal of `peer` queued a
/// close for, or asked a loopback transport to close, given the counts
/// [`closes_asked`] read before it.
fn closed_by_removal(
    node: &Node,
    peer: &NodeAddr,
    pairs: &[PathRef],
    asked: &[(String, usize)],
) -> Vec<String> {
    let mut closed: Vec<String> = node
        .paths
        .closes(peer)
        .iter()
        .filter(|(_, removed)| *removed)
        .map(|(to, _)| named(to))
        .collect();
    for (pair, n) in closes_asked(node, pairs) {
        let before = asked
            .iter()
            .find(|(p, _)| *p == pair)
            .map_or(0, |(_, n)| *n);
        if n > before {
            closed.push(pair);
        }
    }
    closed.sort();
    closed.dedup();
    closed
}

/// What a removal left that the readings alone do not show.
struct Left {
    /// The pairs whose connection the removal closed or queued.
    closed: Vec<String>,
    /// The removed link's carrier reading.
    carried: Vec<TransportId>,
}

/// Remove node 1 from node 0 by `script.cause`, with node 1 dirtied on node
/// 0 and node 0 told to reconnect to it, and hold every row against its
/// cell. Returns what the removal left beyond the rows.
async fn removed_as_its_cells_say(nodes: &mut [TestNode], script: &Script) -> Left {
    let b = *nodes[1].node.node_addr();
    let facts = Facts::of(&nodes[0].node, &b);
    let also = held_pairs(&nodes[0].node, &b);
    let before = Seen::of(&nodes[0].node, &b, &also).await;
    let asked = closes_asked(&nodes[0].node, &also);
    let t = script.cause.transition();
    remove_by(&mut nodes[0].node, &b, script.cause).await;
    assert!(
        nodes[0].node.get_peer(&b).is_none(),
        "defect: {t:?} at its site left the peer held"
    );
    let after = Seen::of(&nodes[0].node, &b, &also).await;
    assert_cells(&before, &after, &t, &stated(script, &facts));
    let machine = after.get(Row::RekeyMachine);
    assert!(
        machine.as_deref() == Some("None; bound []"),
        "defect: the machine {t:?} closed leaves an index bound to the peer: {machine:?}"
    );
    let carried = nodes[0].node.paths.carried(facts.link);
    let mut closed = closed_by_removal(&nodes[0].node, &b, &also, &asked);
    if script.cause == Cause::Admin {
        // Closed by the disconnect itself, guard or not.
        closed.retain(|p| *p != named(&facts.current));
    }
    Left { closed, carried }
}

/// Hold what [`removed_as_its_cells_say`] left: exactly the script's unkept
/// pairs closed or queued, the operator's disconnect's current pair apart,
/// and the carrier reading still there until the next read.
fn assert_left(left: &Left, script: &Script) {
    let mut unkept: Vec<String> = script.unkept.iter().map(named).collect();
    unkept.sort();
    assert!(
        left.closed == unkept,
        "defect: at {:?} the removal closes or queues {:?}, not the unkept paths' {unkept:?}",
        script.cause,
        left.closed
    );
    assert!(
        !left.carried.is_empty(),
        "defect: at {:?} the removed link's carrier reading goes before the next read",
        script.cause
    );
}

/// Peer two loopback nodes with multipath set as `on` and [`prepare`] them.
async fn dirtied(on: bool, bootstrap: bool) -> Vec<TestNode> {
    let mut nodes = peered(on).await;
    prepare(&mut nodes, bootstrap).await;
    nodes
}

/// Dirty node 1 on node 0 and tell node 0 to reconnect to it. Unless
/// `bootstrap`, take the bootstrap mark off again and start a dial of node
/// 0's own to node 1, in flight at the removal. With `bootstrap` no dial
/// starts, since its link would keep the transport in use.
async fn prepare(nodes: &mut [TestNode], bootstrap: bool) {
    let b = *nodes[1].node.node_addr();
    dirty(&mut nodes[0].node, &b).await;
    reconnect_to(nodes, 0, 1);
    // The dial `dirty` notes names the peer's own link, which no site does:
    // once the peer is removed it names a link that is gone, and the live
    // audit stops the node. A real dial stands in for it.
    let link = current_link(&nodes[0].node, &b);
    let noted: Vec<(TransportId, u32)> = nodes[0]
        .node
        .pending_outbound
        .iter()
        .filter(|(_, id)| **id == link)
        .map(|(key, _)| *key)
        .collect();
    for key in &noted {
        nodes[0].node.pending_outbound.forget(key);
    }
    if !bootstrap {
        unmark_bootstrap(&mut nodes[0].node, &b);
        let id = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
        let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
        nodes[0]
            .node
            .initiate_connection(tid, addr, id)
            .await
            .expect("precondition: node 0's own dial starts");
    }
}

/// The link `peer` holds on `node`.
fn current_link(node: &Node, peer: &NodeAddr) -> LinkId {
    node.get_peer(peer)
        .map(ActivePeer::link_id)
        .expect("precondition: the peer is held")
}

/// Remove node 1 from a loopback pair, multipath off, by `cause`: the
/// peer's path and `dirty`'s, on a link not capable, so every connection is
/// kept.
async fn plain(cause: Cause) {
    let mut nodes = dirtied(false, false).await;
    let script = Script {
        cause,
        unkept: Vec::new(),
        bootstrap: false,
        recorded: true,
    };
    let left = removed_as_its_cells_say(&mut nodes, &script).await;
    cleanup_nodes(&mut nodes).await;
    assert_left(&left, &script);
}

/// A dead peer, multipath off, is removed as the table says.
#[tokio::test]
async fn a_dead_peer_is_removed_as_its_cells_say() {
    plain(Cause::Dead).await;
}

/// A peer whose one path loses its interface, multipath off, is removed as
/// the table says.
#[tokio::test]
async fn an_orphaned_peer_is_removed_as_its_cells_say() {
    plain(Cause::Orphaned).await;
}

/// A peer that sends a Disconnect, multipath off, is removed as the table
/// says.
#[tokio::test]
async fn a_peer_that_disconnects_is_removed_as_its_cells_say() {
    plain(Cause::Disconnect).await;
}

/// A peer the operator disconnects, multipath off, is removed as the table
/// says, its current pair closed.
#[tokio::test]
async fn a_peer_the_operator_disconnects_is_removed_as_its_cells_say() {
    plain(Cause::Admin).await;
}

/// A peer whose link rekey machine ends the link, multipath off, is removed
/// as the table says.
#[tokio::test]
async fn a_peer_whose_link_machine_ends_the_link_is_removed_as_its_cells_say() {
    plain(Cause::Ended).await;
}

/// Remove node 1 by `Dead` with the bootstrap mark kept on its transport,
/// which nothing else uses: the transport is dropped.
async fn bootstrap_dropped(nodes: &mut [TestNode], unkept: Vec<PathRef>) {
    let b = *nodes[1].node.node_addr();
    let transport = current(&nodes[0].node, &b).transport;
    let script = Script {
        cause: Cause::Dead,
        unkept,
        bootstrap: true,
        recorded: true,
    };
    removed_as_its_cells_say(nodes, &script).await;
    assert!(
        !nodes[0].node.transports.contains_key(&transport)
            && !nodes[0]
                .node
                .supervisor
                .nostr_rendezvous
                .is_bootstrap_transport(&transport),
        "defect: the removal leaves a bootstrap transport no path of any link is on"
    );
}

/// Removing the one peer on a bootstrap transport, multipath off, drops the
/// transport, as the table says.
#[tokio::test]
async fn removing_the_last_peer_on_a_bootstrap_transport_drops_it_as_its_cell_says() {
    let mut nodes = dirtied(false, true).await;
    bootstrap_dropped(&mut nodes, Vec::new()).await;
    cleanup_nodes(&mut nodes).await;
}

/// Remove node 1 from a [`two_transports`] pair by `cause`: multipath on, a
/// capable link of two paths, p on the first transport, the peer's original
/// and active, and q on the second, with `dirty`'s path beside p. The
/// removal queues a close for every path but p. For `Orphaned` the second
/// transport's interface goes first, so that one detach orphans the link.
async fn capable(cause: Cause) {
    let (mut nodes, b, _, _) = two_transports(1280).await;
    if cause == Cause::Orphaned {
        nodes[0]
            .node
            .step_path(
                &b,
                Input::Present {
                    transport: t2(),
                    present: false,
                },
            )
            .await;
        let left = held_pairs(&nodes[0].node, &b);
        assert!(
            left.len() == 1 && left[0].transport == nodes[0].transport_id,
            "precondition: after q's interface goes the peer holds p alone: {left:?}"
        );
    }
    prepare(&mut nodes, false).await;
    let script = Script {
        cause,
        unkept: unkept_of(&nodes[0].node, &b),
        bootstrap: false,
        recorded: true,
    };
    assert!(
        !script.unkept.is_empty(),
        "precondition: the capable link holds a path besides p"
    );
    let left = removed_as_its_cells_say(&mut nodes, &script).await;
    cleanup_nodes(&mut nodes).await;
    assert_left(&left, &script);
}

/// The pairs of `peer` on `node` a removal queues a close for: every path
/// but the current one, on a capable link; none on a link not known capable.
fn unkept_of(node: &Node, peer: &NodeAddr) -> Vec<PathRef> {
    let capable = node
        .get_peer(peer)
        .and_then(ActivePeer::bundle)
        .is_some_and(|bundle| bundle.capable());
    if !capable {
        return Vec::new();
    }
    let at = current(node, peer);
    held_pairs(node, peer)
        .into_iter()
        .filter(|p| *p != at)
        .collect()
}

/// [`a_dead_peer_is_removed_as_its_cells_say`] with multipath on, on a
/// capable link of two paths.
#[tokio::test]
async fn a_dead_peer_is_removed_as_its_cells_say_with_multipath_on() {
    capable(Cause::Dead).await;
}

/// [`an_orphaned_peer_is_removed_as_its_cells_say`] with multipath on, on a
/// capable link whose other path's interface went first.
#[tokio::test]
async fn an_orphaned_peer_is_removed_as_its_cells_say_with_multipath_on() {
    capable(Cause::Orphaned).await;
}

/// [`a_peer_that_disconnects_is_removed_as_its_cells_say`] with multipath
/// on, on a capable link of two paths.
#[tokio::test]
async fn a_peer_that_disconnects_is_removed_as_its_cells_say_with_multipath_on() {
    capable(Cause::Disconnect).await;
}

/// [`a_peer_the_operator_disconnects_is_removed_as_its_cells_say`] with
/// multipath on, on a capable link of two paths.
#[tokio::test]
async fn a_peer_the_operator_disconnects_is_removed_as_its_cells_say_with_multipath_on() {
    capable(Cause::Admin).await;
}

/// [`a_peer_whose_link_machine_ends_the_link_is_removed_as_its_cells_say`]
/// with multipath on, on a capable link of two paths.
#[tokio::test]
async fn a_peer_whose_link_machine_ends_the_link_is_removed_as_its_cells_say_with_multipath_on() {
    capable(Cause::Ended).await;
}

/// With multipath on at node 0 and off at node 1, node 1 never answers a
/// capability probe, so node 0's link is not known capable: a dead peer's
/// removal keeps every connection, `dirty`'s second path's too.
#[tokio::test]
async fn a_dead_peer_on_a_link_not_yet_known_capable_keeps_every_connection_with_multipath_on() {
    let mut nodes = vec![loopback_node(true).await, loopback_node(false).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let b = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "precondition: node 0 holds node 1"
    );
    prepare(&mut nodes, false).await;
    let held = held_pairs(&nodes[0].node, &b);
    assert!(
        unkept_of(&nodes[0].node, &b).is_empty() && held.len() > 1,
        "precondition: a link of more than one path not known capable: {held:?}"
    );
    let script = Script {
        cause: Cause::Dead,
        unkept: Vec::new(),
        bootstrap: false,
        recorded: true,
    };
    let left = removed_as_its_cells_say(&mut nodes, &script).await;
    cleanup_nodes(&mut nodes).await;
    assert_left(&left, &script);
}

/// [`removing_the_last_peer_on_a_bootstrap_transport_drops_it_as_its_cell_says`]
/// with multipath on, on a capable link of two paths.
#[tokio::test]
async fn removing_the_last_peer_on_a_bootstrap_transport_drops_it_as_its_cell_says_with_multipath_on()
 {
    let (mut nodes, b, _, _) = two_transports(1280).await;
    prepare(&mut nodes, true).await;
    let unkept = unkept_of(&nodes[0].node, &b);
    bootstrap_dropped(&mut nodes, unkept).await;
    cleanup_nodes(&mut nodes).await;
}

/// The BLE mark node 0 reads for its link to node 1 after removing it by
/// `cause` on the BLE pair with multipath set as `on`, every row held
/// against its cell.
#[cfg(ble_available)]
async fn ble_mark_after(cause: Cause, on: bool) -> Option<bool> {
    let (mut nodes, _bank) = ble_pair(on).await;
    let b = *nodes[1].node.node_addr();
    prepare(&mut nodes, false).await;
    // `dirty` clears the mark, which the removal is to act on.
    let link = nodes[1].addr.clone();
    nodes[0]
        .node
        .transports
        .get(&nodes[0].transport_id)
        .expect("precondition: node 0 holds its BLE transport")
        .mark_verified(&link, &b)
        .await;
    let marked = initiator_mark(&nodes).await;
    assert!(
        marked == Some(true),
        "precondition: the link is verified before the removal: {marked:?}"
    );
    let capable = nodes[0]
        .node
        .get_peer(&b)
        .and_then(ActivePeer::bundle)
        .is_some_and(|bundle| bundle.capable());
    let at = current(&nodes[0].node, &b);
    let unkept = if capable {
        held_pairs(&nodes[0].node, &b)
            .into_iter()
            .filter(|p| *p != at)
            .collect()
    } else {
        Vec::new()
    };
    let script = Script {
        cause,
        unkept,
        bootstrap: false,
        recorded: false,
    };
    removed_as_its_cells_say(&mut nodes, &script).await;
    let mark = initiator_mark(&nodes).await;
    cleanup_nodes(&mut nodes).await;
    mark
}

/// What the mark of a link whose peer was removed by `cause` reads: cleared
/// and still pooled for a dead or a disconnecting peer; untouched when the
/// link machine ends the link, and when a detach orphans the peer, since an
/// orphaned link has no active path and the removal reads no pair to clear;
/// not pooled once the operator's disconnect has closed the connection.
#[cfg(ble_available)]
fn mark_left(cause: Cause) -> Option<bool> {
    match cause {
        Cause::Dead | Cause::Disconnect => Some(false),
        Cause::Ended | Cause::Orphaned => Some(true),
        Cause::Admin => None,
    }
}

/// Remove the peer on the BLE pair by `cause` and hold the mark to
/// [`mark_left`].
#[cfg(ble_available)]
async fn ble_removed(cause: Cause, on: bool) {
    let mark = ble_mark_after(cause, on).await;
    let want = mark_left(cause);
    assert!(
        mark == want,
        "defect: at {cause:?} the BLE mark reads {mark:?}, not {want:?} as its cell says"
    );
}

/// A dead peer's BLE link loses its mark, multipath off.
#[cfg(ble_available)]
#[tokio::test]
async fn dead_on_a_ble_link_leaves_the_mark_as_its_cell_says() {
    ble_removed(Cause::Dead, false).await;
}

/// [`dead_on_a_ble_link_leaves_the_mark_as_its_cell_says`] with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn dead_on_a_ble_link_leaves_the_mark_as_its_cell_says_with_multipath_on() {
    ble_removed(Cause::Dead, true).await;
}

/// A disconnecting peer's BLE link loses its mark, multipath off.
#[cfg(ble_available)]
#[tokio::test]
async fn disconnect_on_a_ble_link_leaves_the_mark_as_its_cell_says() {
    ble_removed(Cause::Disconnect, false).await;
}

/// [`disconnect_on_a_ble_link_leaves_the_mark_as_its_cell_says`] with
/// multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn disconnect_on_a_ble_link_leaves_the_mark_as_its_cell_says_with_multipath_on() {
    ble_removed(Cause::Disconnect, true).await;
}

/// An orphaned peer's BLE link keeps its mark, multipath off.
#[cfg(ble_available)]
#[tokio::test]
async fn orphaned_on_a_ble_link_leaves_the_mark_as_its_cell_says() {
    ble_removed(Cause::Orphaned, false).await;
}

/// [`orphaned_on_a_ble_link_leaves_the_mark_as_its_cell_says`] with
/// multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn orphaned_on_a_ble_link_leaves_the_mark_as_its_cell_says_with_multipath_on() {
    ble_removed(Cause::Orphaned, true).await;
}

/// A BLE link whose machine ended it keeps its mark, multipath off.
#[cfg(ble_available)]
#[tokio::test]
async fn ended_on_a_ble_link_leaves_the_mark_as_its_cell_says() {
    ble_removed(Cause::Ended, false).await;
}

/// [`ended_on_a_ble_link_leaves_the_mark_as_its_cell_says`] with multipath
/// on.
#[cfg(ble_available)]
#[tokio::test]
async fn ended_on_a_ble_link_leaves_the_mark_as_its_cell_says_with_multipath_on() {
    ble_removed(Cause::Ended, true).await;
}

/// The operator's disconnect leaves a BLE link's mark uncleared but closes
/// the link, multipath off.
#[cfg(ble_available)]
#[tokio::test]
async fn admin_on_a_ble_link_leaves_the_mark_as_its_cell_says() {
    ble_removed(Cause::Admin, false).await;
}

/// [`admin_on_a_ble_link_leaves_the_mark_as_its_cell_says`] with multipath
/// on.
#[cfg(ble_available)]
#[tokio::test]
async fn admin_on_a_ble_link_leaves_the_mark_as_its_cell_says_with_multipath_on() {
    ble_removed(Cause::Admin, true).await;
}
