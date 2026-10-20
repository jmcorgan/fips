//! The session index of a draining previous session at a later cutover.
//!
//! A cutover demotes the current session into the previous slot. If an
//! earlier previous session is still draining there, the cutover must retire
//! it first and release its index, or the index stays registered and
//! allocated with nothing left to free it, past the peer's removal. These
//! tests reach that state over loopback by backdating session ages, and
//! assert on the node's index registrations and allocations.

use super::rekey_parity::{
    age_link, cutover, deliver, heartbeat, linked_pair, rekey_config, rekey_to_pending, trigger_age,
};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;

/// How the second cutover reaches the node that initiated both rekeys.
#[derive(Clone, Copy, Debug)]
enum SecondCutover {
    /// Its own rekey tick cuts over the pending it initiated.
    Tick,
    /// The peer's frame on the pending index promotes the pending first.
    PeerFrame,
}

/// Whether `tn` maps `index` on its link to `peer` to a peer.
fn registered(tn: &TestNode, peer: &NodeAddr, index: SessionIndex) -> bool {
    let tid = tn.node.get_peer(peer).unwrap().transport_id().unwrap();
    tn.node.peers_by_index.contains_key(&(tid, index.as_u32()))
}

/// Node 0 cuts over a first rekey, then a second while the first session
/// still drains, by the tick or by the peer's frame; once the second drain
/// has run out too, the first session's index is neither registered nor
/// allocated.
#[tokio::test]
async fn a_cutover_during_a_drain_releases_the_draining_sessions_index() {
    for second in [SecondCutover::Tick, SecondCutover::PeerFrame] {
        let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
        let addr0 = *nodes[0].node.node_addr();
        let addr1 = *nodes[1].node.node_addr();

        age_link(&mut nodes, 0, 1, trigger_age());
        rekey_to_pending(&mut nodes, 0, 1).await;
        cutover(&mut nodes[0], &addr1).await;
        let first = nodes[0]
            .node
            .get_peer(&addr1)
            .unwrap()
            .previous_our_index()
            .expect("precondition: the first session drains in the previous slot");
        assert!(
            registered(&nodes[0], &addr1, first)
                && nodes[0].node.index_allocator.is_allocated(first),
            "{second:?}: control: a draining previous session's index stays registered and allocated"
        );
        heartbeat(&mut nodes[0], &addr1).await;
        deliver(&mut nodes[1]).await;
        assert!(
            nodes[1]
                .node
                .get_peer(&addr0)
                .unwrap()
                .pending_new_session()
                .is_none(),
            "{second:?}: precondition: node 1 adopted the first rekey"
        );
        // The prompt node 1 sends at its adoption reaches node 0.
        deliver(&mut nodes[0]).await;

        // A second rekey reaches node 0's pending while the first session
        // is still draining.
        age_link(&mut nodes, 0, 1, trigger_age());
        rekey_to_pending(&mut nodes, 0, 1).await;
        assert!(
            nodes[0].node.get_peer(&addr1).unwrap().is_draining(),
            "{second:?}: precondition: the first session is still draining at the second cutover"
        );
        match second {
            SecondCutover::Tick => cutover(&mut nodes[0], &addr1).await,
            SecondCutover::PeerFrame => {
                // A frame node 1 seals under its half of the second rekey's
                // session, as a peer that already moved to it would, names
                // node 0's pending index and reaches node 0 before its tick.
                let pending = nodes[0].node.get_peer(&addr1).unwrap().pending_our_index();
                let kbit = !nodes[0].node.get_peer(&addr1).unwrap().current_k_bit();
                let frame = nodes[1].node.get_peer_mut(&addr0).unwrap().seal_test_frame(
                    fips_core::proto::rekey::Slot::Pending,
                    pending.expect("precondition: node 0 holds a pending"),
                    if kbit {
                        crate::proto::fmp::wire::FLAG_KEY_EPOCH
                    } else {
                        0
                    },
                    &[
                        0,
                        0,
                        0,
                        0,
                        crate::proto::link::LinkMessageType::Heartbeat.to_byte(),
                    ],
                );
                let packet =
                    ReceivedPacket::new(nodes[0].transport_id, nodes[1].addr.clone(), frame);
                nodes[0].node.handle_encrypted_frame(packet).await;
                let p = nodes[0].node.get_peer(&addr1).unwrap();
                assert!(
                    p.pending_new_session().is_none() && p.our_index() == pending,
                    "precondition: node 1's frame promoted node 0's pending"
                );
            }
        }

        // The second session's drain runs out at its ceiling and is
        // completed.
        nodes[0]
            .node
            .get_peer_mut(&addr1)
            .unwrap()
            .test_backdate_drain_started(crate::peer::test_link_params().config().retention);
        nodes[0].node.poll_link_rekeys().await;
        assert!(
            !nodes[0].node.get_peer(&addr1).unwrap().is_draining(),
            "{second:?}: control: the second session's drain completed"
        );

        assert!(
            !registered(&nodes[0], &addr1, first),
            "{second:?}: the first session's index must not stay registered after both drains"
        );
        assert!(
            !nodes[0].node.index_allocator.is_allocated(first),
            "{second:?}: the first session's index must not stay allocated after both drains"
        );
        cleanup_nodes(&mut nodes).await;
    }
}
