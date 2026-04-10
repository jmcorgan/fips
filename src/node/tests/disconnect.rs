//! Disconnect and peer removal integration tests.
//!
//! Tests that graceful disconnect messages propagate correctly through
//! multi-node networks and trigger proper cascading cleanup: peer removal,
//! tree reconvergence, and bloom filter recomputation.

use super::spanning_tree::*;
use super::*;
use crate::protocol::{Disconnect, DisconnectReason};

/// 3-node chain: middle node disconnects one peer.
///
/// Chain: 0 -- 1 -- 2. Node 1 sends Disconnect to node 0.
/// Verifies:
///   - Node 0 removes node 1 from its peer table
///   - Node 0's tree reconverges (becomes its own root since isolated)
///   - Node 1 still has node 2 as a peer
#[tokio::test]
async fn test_disconnect_chain_peer_removal() {
    // Build 3-node chain: 0 -- 1 -- 2
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    // Verify initial state: node 0 has 1 peer (node 1)
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert!(nodes[0].node.get_peer(&node1_addr).is_some());

    // Node 1 sends Disconnect(Shutdown) to node 0
    let disconnect = Disconnect::new(DisconnectReason::Shutdown);
    let plaintext = disconnect.encode();
    nodes[1]
        .node
        .send_encrypted_link_message(&node0_addr, &plaintext)
        .await
        .expect("Failed to send disconnect");

    // Process the disconnect at node 0
    tokio::time::sleep(Duration::from_millis(50)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should have removed node 1
    assert_eq!(
        nodes[0].node.peer_count(),
        0,
        "Node 0 should have no peers after disconnect"
    );
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_none(),
        "Node 0 should not have node 1 as a peer"
    );

    // Node 0 becomes its own root (isolated)
    assert!(
        nodes[0].node.tree_state().is_root(),
        "Isolated node 0 should be root"
    );

    // Node 1 still has node 2 as a peer (disconnect was only to node 0)
    assert!(
        nodes[1].node.get_peer(&node2_addr).is_some(),
        "Node 1 should still have node 2"
    );

    cleanup_nodes(&mut nodes).await;
}

/// 4-node star: hub disconnects, spokes reconverge.
///
/// Star: 0 is hub, connected to 1, 2, 3. Hub sends Disconnect to all.
/// Verifies:
///   - All spokes remove hub from their peer tables
///   - Each spoke becomes its own root (since there are no spoke-spoke links)
#[tokio::test]
async fn test_disconnect_star_hub_departs() {
    let edges = vec![(0, 1), (0, 2), (0, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let hub_addr = *nodes[0].node.node_addr();

    // Hub sends Disconnect(Shutdown) to all spokes
    let disconnect = Disconnect::new(DisconnectReason::Shutdown);
    let plaintext = disconnect.encode();
    for spoke_idx in 1..4 {
        let spoke_addr = *nodes[spoke_idx].node.node_addr();
        nodes[0]
            .node
            .send_encrypted_link_message(&spoke_addr, &plaintext)
            .await
            .expect("Failed to send disconnect");
    }

    // Process disconnects at all nodes
    tokio::time::sleep(Duration::from_millis(50)).await;
    process_available_packets(&mut nodes).await;

    // All spokes should have removed the hub
    for (spoke_idx, spoke) in nodes[1..4].iter().enumerate() {
        let spoke_idx = spoke_idx + 1; // adjust for slice offset
        assert!(
            spoke.node.get_peer(&hub_addr).is_none(),
            "Spoke {} should have removed hub",
            spoke_idx
        );
        assert_eq!(
            spoke.node.peer_count(),
            0,
            "Spoke {} should have no peers (no spoke-spoke links)",
            spoke_idx
        );
        assert!(
            spoke.node.tree_state().is_root(),
            "Isolated spoke {} should become root",
            spoke_idx
        );
    }

    cleanup_nodes(&mut nodes).await;
}

/// 5-node chain: interior node departs, network splits into two components.
///
/// Chain: 0 -- 1 -- 2 -- 3 -- 4. Node 2 sends Disconnect to nodes 1 and 3.
/// Verifies:
///   - Peers removed correctly on both sides
///   - Bloom filters update so routing no longer bridges the partition
///
/// Note: Tree root reconvergence after partition is not tested here because
/// the tree protocol detects parent loss but not root unreachability. Nodes
/// whose parent is still connected may retain a stale root belief until the
/// root refresh timer fires. This is a known limitation of the current tree
/// protocol — bloom filter routing is the primary mechanism and it updates
/// immediately on peer removal.
#[tokio::test]
async fn test_disconnect_chain_partition() {
    let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node2_addr = *nodes[2].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    // Node 2 sends Disconnect to nodes 1 and 3
    let disconnect = Disconnect::new(DisconnectReason::Shutdown);
    let plaintext = disconnect.encode();
    nodes[2]
        .node
        .send_encrypted_link_message(&node1_addr, &plaintext)
        .await
        .expect("Failed to send disconnect to node 1");
    nodes[2]
        .node
        .send_encrypted_link_message(&node3_addr, &plaintext)
        .await
        .expect("Failed to send disconnect to node 3");

    // Process disconnects and let filters reconverge
    drain_all_packets(&mut nodes, false).await;

    // Nodes 1 and 3 should have removed node 2
    assert!(
        nodes[1].node.get_peer(&node2_addr).is_none(),
        "Node 1 should not have node 2 as peer"
    );
    assert!(
        nodes[3].node.get_peer(&node2_addr).is_none(),
        "Node 3 should not have node 2 as peer"
    );

    // Within each component, peers are still connected
    let node0_addr = *nodes[0].node.node_addr();
    let node4_addr = *nodes[4].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_some(),
        "Node 0 should still have node 1 as peer"
    );
    assert!(
        nodes[3].node.get_peer(&node4_addr).is_some(),
        "Node 3 should still have node 4 as peer"
    );

    // Bloom filter check: node 0 should NOT see node 4 as reachable
    // (bloom filters update immediately on peer removal via split-horizon recomputation)
    let node0_reaches_node4 = nodes[0]
        .node
        .peers()
        .any(|peer| peer.may_reach(&node4_addr));
    assert!(
        !node0_reaches_node4,
        "Node 0 should not see node 4 as reachable after partition"
    );

    // And vice versa
    let node4_reaches_node0 = nodes[4]
        .node
        .peers()
        .any(|peer| peer.may_reach(&node0_addr));
    assert!(
        !node4_reaches_node0,
        "Node 4 should not see node 0 as reachable after partition"
    );

    // Nodes within the same component should still see each other
    let node0_reaches_node1 = nodes[0]
        .node
        .peers()
        .any(|peer| peer.may_reach(&node1_addr));
    assert!(
        node0_reaches_node1,
        "Node 0 should still see node 1 as reachable"
    );

    let node4_reaches_node3 = nodes[4]
        .node
        .peers()
        .any(|peer| peer.may_reach(&node3_addr));
    assert!(
        node4_reaches_node3,
        "Node 4 should still see node 3 as reachable"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Removing a peer via disconnect must also remove the associated end-to-end session.
///
/// Regression test for issue #5: `remove_active_peer` previously left the
/// `SessionEntry` alive in `self.sessions` after evicting the peer from
/// `self.peers`. This caused:
///   1. Stale "MMP session metrics" logs with frozen counters until
///      `purge_idle_sessions` eventually fired (up to idle_timeout_secs later).
///   2. `initiate_session` silently returning `Ok(())` on the stale Established
///      entry's guard check, preventing a new session from being created even
///      after the link layer reconnected successfully.
#[tokio::test]
async fn test_disconnect_clears_session() {
    use crate::identity::Identity;
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::HandshakeState;

    // Two-node topology: 0 -- 1.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Inject a synthetic Established session entry into node 1's session table
    // to simulate the state after a completed XK handshake with node 0.
    let remote_identity = Identity::generate();
    {
        let our_identity = nodes[1].node.identity();

        let mut initiator =
            HandshakeState::new_initiator(our_identity.keypair(), remote_identity.pubkey_full());
        let mut responder = HandshakeState::new_responder(remote_identity.keypair());
        let mut init_epoch = [0u8; 8];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut init_epoch);
        initiator.set_local_epoch(init_epoch);
        let mut resp_epoch = [0u8; 8];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
        responder.set_local_epoch(resp_epoch);
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();
        let session = initiator.into_session().unwrap();

        let entry = SessionEntry::new(
            node0_addr,
            remote_identity.pubkey_full(),
            EndToEndState::Established(session),
            1_000,
            true,
        );
        nodes[1].node.sessions.insert(node0_addr, entry);
    }

    assert_eq!(
        nodes[1].node.session_count(),
        1,
        "Session should exist before disconnect"
    );
    assert_eq!(
        nodes[1].node.peer_count(),
        1,
        "Peer should exist before disconnect"
    );

    // Node 0 sends Disconnect to node 1.
    let disconnect = crate::protocol::Disconnect::new(DisconnectReason::Shutdown);
    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &disconnect.encode())
        .await
        .expect("Failed to send disconnect");

    tokio::time::sleep(Duration::from_millis(50)).await;
    process_available_packets(&mut nodes).await;

    // Peer must be gone.
    assert_eq!(
        nodes[1].node.peer_count(),
        0,
        "Peer should be removed after disconnect"
    );

    // Session must also be gone — core regression check for issue #5.
    // Before the fix, session_count() would still be 1 here because
    // remove_active_peer didn't remove self.sessions[node0_addr].
    assert_eq!(
        nodes[1].node.session_count(),
        0,
        "Session must be cleaned up when peer is removed (regression: issue #5)"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Verify that different disconnect reasons are handled correctly.
///
/// Sends each reason code and verifies the peer is removed regardless.
#[tokio::test]
async fn test_disconnect_all_reason_codes() {
    let reasons = vec![
        DisconnectReason::Shutdown,
        DisconnectReason::Restart,
        DisconnectReason::ProtocolError,
        DisconnectReason::TransportFailure,
        DisconnectReason::ResourceExhaustion,
    ];

    for reason in reasons {
        let edges = vec![(0, 1)];
        let mut nodes = run_tree_test(2, &edges, false).await;
        verify_tree_convergence(&nodes);

        let node0_addr = *nodes[0].node.node_addr();
        let node1_addr = *nodes[1].node.node_addr();

        // Node 0 sends disconnect with this reason
        let disconnect = Disconnect::new(reason);
        let plaintext = disconnect.encode();
        nodes[0]
            .node
            .send_encrypted_link_message(&node1_addr, &plaintext)
            .await
            .expect("Failed to send disconnect");

        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;

        assert!(
            nodes[1].node.get_peer(&node0_addr).is_none(),
            "Node 1 should remove peer for reason {:?}",
            reason
        );

        cleanup_nodes(&mut nodes).await;
    }
}
