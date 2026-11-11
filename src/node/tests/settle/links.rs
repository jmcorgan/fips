//! The `(transport, address)` index derived from the settlement core's link
//! records, on real nodes: a link a crossing moves the session of keeps an
//! entry, a roamed path's pair is named beside the setup pair, and a second
//! path proven by the peer's frames is named with no writer of the table's
//! called after the path's state reaches the record.
//!
//! The index names each live link at its setup pair, unless the bundle
//! released the path there, and at each Live or acknowledged path of its
//! record; a pair several links use names the newest. The table's own tests
//! of the writers are in `src/node/settle/tests/`.
//!
//! Each test runs once per setting of `node.path.enabled`, as two tests,
//! where the shape exists at both. Setup checks are marked `precondition:`;
//! the assertion of the behaviour is marked `defect:`.

use super::super::crossed_dial::{Dial, cross_dials_from, hand};
use super::super::paths::{deliver_from, t2, two_transports};
use super::super::spanning_tree::{add_loopback_alias, cleanup_nodes, initiate_handshake};
use super::super::*;
use super::{loopback_node, pump, with_path};

/// The link `tn` holds `peer` on.
fn held(tn: &super::super::spanning_tree::TestNode, peer: &NodeAddr) -> LinkId {
    tn.node
        .get_peer(peer)
        .expect("precondition: the node holds the peer")
        .link_id()
}

/// Cross the dials as `dial` says and hand the smaller node the msg2 that
/// moves it onto its own session: the link it holds the larger node on is
/// named in the index at the pair the msg2 came from, where its bundle now
/// runs.
async fn crossed_entry(on: bool, dial: Dial) {
    let crossed = cross_dials_from(dial, with_path(Config::new(), on)).await;
    let (s, l, to) = (crossed.s, crossed.l, crossed.to.clone());
    let mut nodes = crossed.nodes;
    let l_addr = *nodes[l].node.node_addr();
    hand(&mut nodes[s].node, crossed.msg2).await;
    assert_eq!(
        nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node keeps the larger")
            .our_index(),
        Some(crossed.outbound),
        "precondition: the smaller node moved to its outbound session"
    );
    let link = held(&nodes[s], &l_addr);
    let index = nodes[s].node.links.index().clone();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        index.get(&to).copied(),
        Some(link),
        "defect: after the move the smaller node's link {link:?} has no index entry at the msg2's pair {to:?}: {index:?}"
    );
}

#[tokio::test]
async fn a_crossed_dial_from_another_address_keeps_an_index_entry_for_its_link() {
    crossed_entry(false, Dial::OtherAddress).await;
}

/// [`a_crossed_dial_from_another_address_keeps_an_index_entry_for_its_link`] with multipath on.
#[tokio::test]
async fn a_crossed_dial_from_another_address_keeps_an_index_entry_for_its_link_with_multipath_on() {
    crossed_entry(true, Dial::OtherAddress).await;
}

#[tokio::test]
async fn a_crossed_dial_on_another_transport_keeps_an_index_entry_for_its_link() {
    crossed_entry(false, Dial::OtherTransport).await;
}

/// [`a_crossed_dial_on_another_transport_keeps_an_index_entry_for_its_link`] with multipath on.
#[tokio::test]
async fn a_crossed_dial_on_another_transport_keeps_an_index_entry_for_its_link_with_multipath_on() {
    crossed_entry(true, Dial::OtherTransport).await;
}

/// A heartbeat from a new address of the peer's on the same transport roams
/// the one path of the link the dialer holds it on: the index names the link
/// at the new pair, and still at the pair the link was set up at.
async fn roamed_pair(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let tid = nodes[0].transport_id;
    let setup = (tid, nodes[1].addr.clone());
    let moved = add_loopback_alias(&nodes[1].addr, tid);
    let to = *nodes[0].node.node_addr();
    let peer = *nodes[1].node.node_addr();
    nodes[1]
        .node
        .send_encrypted_link_message(
            &to,
            &[crate::proto::link::LinkMessageType::Heartbeat.to_byte()],
        )
        .await
        .expect("precondition: node 1 sends a heartbeat");
    deliver_from(&mut nodes[0], &moved).await;
    let active = nodes[0]
        .node
        .get_peer(&peer)
        .and_then(|p| p.active_path())
        .map(|p| (p.transport_id(), p.addr().clone()));
    let link = held(&nodes[0], &peer);
    let index = nodes[0].node.links.index().clone();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        active,
        Some((tid, moved.clone())),
        "precondition: the frame roamed the link's path"
    );
    assert_eq!(
        index.get(&(tid, moved)).copied(),
        Some(link),
        "defect: the roamed pair does not name the link: {index:?}"
    );
    assert_eq!(
        index.get(&setup).copied(),
        Some(link),
        "defect: the setup pair the path roamed from no longer names the link: {index:?}"
    );
}

#[tokio::test]
async fn a_roamed_pair_is_named_and_the_setup_pair_stays() {
    roamed_pair(false).await;
}

/// [`a_roamed_pair_is_named_and_the_setup_pair_stays`] with multipath on.
#[tokio::test]
async fn a_roamed_pair_is_named_and_the_setup_pair_stays_with_multipath_on() {
    roamed_pair(true).await;
}

/// A second path offered on a second transport and proven by the peer's
/// answers to its probes, not by a test mutator: the index names the link
/// at that pair, though no writer of the table's ran after the path's state
/// reached the record, and the cache is the index the records give.
#[tokio::test]
async fn a_second_path_proven_through_frames_is_named_in_the_link_index_with_multipath_on() {
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let link = held(&nodes[0], &b);
    let past = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: A holds B")
        .past_feed();
    let named = nodes[0]
        .node
        .links
        .index()
        .get(&(t2(), b2.clone()))
        .copied();
    let stale = crate::node::settle::audit::index_cache(&nodes[0].node);
    cleanup_nodes(&mut nodes).await;
    assert!(!past, "precondition: no test mutator touched the bundle");
    assert_eq!(
        named,
        Some(link),
        "defect: the second path's pair does not name the link"
    );
    assert!(
        stale.is_empty(),
        "defect: the cache differs from the records: {stale:?}"
    );
}
