//! The resync of what a test planted past the node's decision sites into
//! the node's settlement table.

use super::*;
use crate::transport::LinkDirection;

/// A connectionless link `id` on transport 1, dialed by the remote at
/// `addr`.
fn inbound(id: u64, addr: &str) -> crate::transport::Link {
    crate::transport::Link::connectionless(
        LinkId::new(id),
        TransportId::new(1),
        TransportAddr::from_string(addr),
        LinkDirection::Inbound,
        std::time::Duration::from_millis(100),
    )
}

/// The table's record of the node's link `id`: setup pair, direction and
/// holder.
fn shape(node: &Node, id: u64) -> Option<(Pair, Dir, crate::proto::settle::links::Holder)> {
    let rec = node.core.links().get(node.core_no(LinkId::new(id))?)?;
    Some((rec.setup.clone(), rec.dir, rec.holder))
}

/// A link a test put in the node's link map past its writers is, after the
/// next resync, a record of the table's numbered for that link
/// and held as a leg at its setup pair, as its own decision sites would
/// have opened it: the counterpart of the resync of a planted link
/// into the node's records on master.
#[test]
fn a_link_planted_in_the_map_is_a_leg_at_its_setup_pair_in_the_table_after_a_resync() {
    use crate::proto::settle::links::Holder;
    let mut node = crate::node::tests::make_node();
    node.links
        .raw()
        .insert(LinkId::new(1), inbound(1, "10.0.0.1:2121"));
    node.replant();
    let at = pair(
        TransportId::new(1),
        &TransportAddr::from_string("10.0.0.1:2121"),
    );
    assert_eq!(
        shape(&node, 1),
        Some((at, Dir::Inbound, Holder::Leg)),
        "defect: the planted link is not a leg at its setup pair in the table"
    );
}

/// A peer a test planted on a link the node's map lacks is held by the
/// table, after its next resync, on a record of its own set up at the pair
/// the peer is at, which no link of the node's is numbered for; and a link
/// the test puts in the map later, under the id the peer names, gets a
/// record of its own, a leg, while the peer stays held where it was: the
/// counterpart of the resync of a planted peer's link into the
/// node's records on master.
#[test]
fn a_planted_peer_on_a_link_the_map_lacks_is_held_in_the_table_on_a_record_of_its_own_at_its_pair()
{
    use crate::proto::settle::links::Holder;
    let mut node = crate::node::tests::make_node();
    let identity = crate::node::tests::make_peer_identity();
    let addr = *identity.node_addr();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 0);
    let at = TransportAddr::from_string("10.0.0.1:2121");
    let _ = peer.set_current_addr(TransportId::new(1), at.clone());
    node.peers.raw().insert(addr, peer);
    node.replant();
    let held = node.core.held(&addr).map(|h| h.link);
    let rec = held
        .and_then(|no| node.core.links().get(no))
        .map(|r| (r.setup.clone(), r.holder));
    assert_eq!(
        rec,
        Some((pair(TransportId::new(1), &at), Holder::Peer(addr))),
        "defect: the table does not hold the planted peer on a record at its pair"
    );
    assert_eq!(
        node.core_no(LinkId::new(1)),
        None,
        "defect: the planted peer's record is numbered for a link the map lacks"
    );

    node.links
        .raw()
        .insert(LinkId::new(1), inbound(1, "10.0.0.2:2121"));
    node.replant();
    let mapped = pair(
        TransportId::new(1),
        &TransportAddr::from_string("10.0.0.2:2121"),
    );
    assert_eq!(
        shape(&node, 1),
        Some((mapped, Dir::Inbound, Holder::Leg)),
        "defect: the link put in the map later is no leg of its own in the table"
    );
    assert_eq!(
        node.core.held(&addr).map(|h| h.link),
        held,
        "defect: the table moved the planted peer onto the link put in the map"
    );
}
