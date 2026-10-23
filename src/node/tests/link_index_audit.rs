//! The node's session-index map and allocator against each link's rekey
//! machine.
//!
//! A link's session indices are leased by its rekey machine (current,
//! pending and previous sessions, and its rekey handshake in flight) and by
//! the shell (a link setup's carrier). `peers_by_index` and the decrypt
//! workers change only by the machine's outputs. The test drives two
//! loopback nodes through every rekey step and checks, after each, that the
//! map holds exactly the indices the machines bind, each under the transport
//! recorded at its binding, that the allocator holds exactly the leased
//! indices, and, with a decrypt-worker pool, that the workers hold exactly
//! the sessions the machines recorded as delegated, through a cutover over
//! an open drain and the peer's removal.

use super::rekey_parity::{
    age_link, cutover, deliver, heartbeat, rekey_config, rekey_to_pending, trigger_age,
};
use super::spanning_tree::{
    cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node_with_config,
};
use super::*;

/// Check, at `step`, that `node`'s `peers_by_index` maps exactly the indices
/// its peers' link machines bind, each to the peer that binds it, that its
/// allocator holds those indices and the shell's own leases (a handshake
/// carrier) and nothing else, and, when it
/// runs a decrypt-worker pool, that the workers hold exactly the sessions
/// the machines recorded as delegated, every peer's current session among
/// them.
pub(super) fn audit(node: &Node, step: &str) {
    let mut bound = std::collections::HashMap::new();
    let mut delegated = std::collections::HashSet::new();
    let mut leased = 0;
    for (addr, peer) in node.peers.iter() {
        for (key, held) in peer.link_bindings() {
            assert!(
                bound.insert(key, *addr).is_none(),
                "{step}: index {key:?} bound twice"
            );
            if held {
                delegated.insert(key);
            }
        }
        leased += peer.link_bindings().len();
    }
    leased += node
        .peer_machines
        .values()
        .filter(|machine| machine.our_index().is_some())
        .count();
    let mapped: std::collections::HashMap<_, _> = node
        .peers_by_index
        .iter()
        .map(|(key, addr)| (*key, *addr))
        .collect();
    assert_eq!(
        mapped, bound,
        "{step}: peers_by_index must map exactly the indices the link machines bind"
    );
    assert_eq!(
        node.index_allocator.count(),
        leased,
        "{step}: the allocator must hold exactly the leased indices"
    );
    #[cfg(unix)]
    if node.supervisor.decrypt_workers.is_some() {
        assert_eq!(
            node.decrypt_registered_sessions, delegated,
            "{step}: the workers must hold exactly the sessions the machines delegated"
        );
        for peer in node.peers.values() {
            let current = peer.our_index().unwrap().as_u32();
            assert!(
                delegated.contains(&current),
                "{step}: the workers must hold every current session"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = delegated;
}

/// Every step of two rekeys each way leaves each node's index map equal to
/// its link machines' bindings and its allocator equal to the leases held:
/// link setup, a rekey handshake in flight, the responder's pending, the
/// initiator's pending, the cutover, the adoption, a second cutover while
/// the first session still drains, both drains ending, and the peer's
/// removal.
#[tokio::test]
async fn shell_index_maps_equal_machine_bindings_after_every_step() {
    for workers in [false, cfg!(unix)] {
        steps(workers).await;
    }
}

/// The steps of the audit test, with a decrypt-worker pool at both nodes
/// when `workers` is set.
async fn steps(workers: bool) {
    let mut nodes = vec![
        make_test_node_with_config(rekey_config(60), 1280).await,
        make_test_node_with_config(rekey_config(60), 1280).await,
    ];
    #[cfg(unix)]
    if workers {
        use crate::node::decrypt_worker::DecryptWorkerPool;
        for tn in nodes.iter_mut() {
            tn.node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
        }
    }
    #[cfg(not(unix))]
    let _ = workers;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr1).is_some() && nodes[1].node.get_peer(&addr0).is_some(),
        "precondition: the pair is peered"
    );
    #[cfg(unix)]
    if workers {
        assert_eq!(
            nodes[0].node.decrypt_registered_sessions.len(),
            1,
            "precondition: the promotion offered node 0's current session to the workers"
        );
    }
    audit(&nodes[0].node, "link setup at node 0");
    audit(&nodes[1].node, "link setup at node 1");

    for round in 0..2 {
        age_link(&mut nodes, 0, 1, trigger_age());
        nodes[0].node.poll_link_rekeys().await;
        assert!(
            nodes[0].node.get_peer(&addr1).unwrap().rekey_in_progress(),
            "precondition: round {round}: node 0 started a rekey"
        );
        audit(&nodes[0].node, "a rekey handshake in flight");
        assert_eq!(deliver(&mut nodes[1]).await, 1, "precondition: the msg1");
        audit(&nodes[1].node, "the responder's pending");
        assert_eq!(deliver(&mut nodes[0]).await, 1, "precondition: the msg2");
        audit(&nodes[0].node, "the initiator's pending");
        if round == 1 {
            assert!(
                nodes[0].node.get_peer(&addr1).unwrap().is_draining(),
                "precondition: the first session still drains at the second cutover"
            );
        }
        cutover(&mut nodes[0], &addr1).await;
        audit(&nodes[0].node, "the initiator's cutover");
        heartbeat(&mut nodes[0], &addr1).await;
        deliver(&mut nodes[1]).await;
        assert!(
            nodes[1]
                .node
                .get_peer(&addr0)
                .unwrap()
                .pending_new_session()
                .is_none(),
            "precondition: round {round}: node 1 adopted"
        );
        audit(&nodes[1].node, "the responder's adoption");
        deliver(&mut nodes[0]).await;
        audit(&nodes[0].node, "the adoption's prompt");
    }

    for (i, peer) in [(0, addr1), (1, addr0)] {
        nodes[i]
            .node
            .get_peer_mut(&peer)
            .unwrap()
            .test_backdate_drain_started(crate::peer::test_link_params().config().retention);
        nodes[i].node.poll_link_rekeys().await;
        assert!(
            !nodes[i].node.get_peer(&peer).unwrap().is_draining(),
            "precondition: the drain at node {i} ended"
        );
        audit(&nodes[i].node, "the drain's end");
    }

    // A rekey left in flight is released with the peer.
    age_link(&mut nodes, 0, 1, trigger_age());
    rekey_to_pending(&mut nodes, 0, 1).await;
    nodes[0].node.remove_active_peer(&addr1);
    nodes[1].node.remove_active_peer(&addr0);
    audit(&nodes[0].node, "the peer's removal at node 0");
    audit(&nodes[1].node, "the peer's removal at node 1");
    assert_eq!(
        nodes[0].node.index_allocator.count(),
        0,
        "control: no index outlives the peer"
    );
    cleanup_nodes(&mut nodes).await;
}
