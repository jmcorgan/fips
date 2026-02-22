//! End-to-end session establishment tests.

use super::*;
use crate::node::session::EndToEndState;
use crate::node::tests::spanning_tree::{
    cleanup_nodes, generate_random_edges, process_available_packets, run_tree_test,
    verify_tree_convergence, TestNode,
};
use crate::protocol::{SessionAck, SessionDatagram};

/// Populate all nodes' coordinate caches with each other's coords.
///
/// This enables routing between non-adjacent nodes (bloom filter + tree
/// routing both require cached destination coordinates).
fn populate_all_coord_caches(nodes: &mut [TestNode]) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let all_coords: Vec<(NodeAddr, crate::tree::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for tn in nodes.iter_mut() {
        for (addr, coords) in &all_coords {
            if addr != tn.node.node_addr() {
                tn.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }
}

// ============================================================================
// Unit tests: SessionEntry data structure
// ============================================================================

#[test]
fn test_session_entry_new_initiating() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    assert!(entry.state().is_initiating());
    assert!(!entry.state().is_established());
    assert!(!entry.state().is_awaiting_msg3());
    assert_eq!(entry.created_at(), 1000);
    assert_eq!(entry.last_activity(), 1000);
}

#[test]
fn test_session_entry_touch() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.touch(2000);
    assert_eq!(entry.last_activity(), 2000);
    assert_eq!(entry.created_at(), 1000);
}

#[test]
fn test_session_table_operations() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        node.identity().keypair(),
        identity_b.pubkey_full(),
    );

    let dest_addr = *identity_b.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    node.sessions.insert(dest_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&dest_addr).is_some());
    assert!(node.get_session(&make_node_addr(0xFF)).is_none());

    let removed = node.remove_session(&dest_addr);
    assert!(removed.is_some());
    assert_eq!(node.session_count(), 0);
}

// ============================================================================
// Integration tests: 2-node direct session establishment
// ============================================================================

#[tokio::test]
async fn test_session_direct_peer_handshake() {
    // Two directly connected nodes: A initiates a session with B
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Node 0 initiates session with Node 1
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");

    // Node 0 should have a session in Initiating state
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .state()
        .is_initiating());

    // Process packets: SessionSetup arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionSetup packet to arrive");

    // Node 1 should now have a session in AwaitingMsg3 state (XK: identity not yet known)
    assert_eq!(nodes[1].node.session_count(), 1);
    assert!(nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_awaiting_msg3());

    // Process packets: SessionAck arrives at Node 0, Node 0 sends SessionMsg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionAck packet to arrive");

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .state()
        .is_established());

    // Process packets: SessionMsg3 arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionMsg3 packet to arrive");

    // Node 1 should now be Established (transitions after processing msg3)
    assert!(nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_established());

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_direct_peer_data_transfer() {
    // Two nodes: establish session, then send data
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Setup → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Ack → Node 0, Node 0 sends Msg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Msg3 → Node 1

    assert!(nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .state()
        .is_established());
    assert!(nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_established());

    // Send data from Node 0 to Node 1
    let test_data = b"Hello, FIPS session!";
    nodes[0]
        .node
        .send_session_data(&node1_addr, test_data)
        .await
        .expect("send_session_data failed");

    // Process packets: encrypted data arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected encrypted data to arrive");

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: 3-node forwarded session
// ============================================================================

#[tokio::test]
async fn test_session_3node_forwarded_handshake() {
    // A—B—C: Node A initiates session with Node C through transit node B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Node 0 initiates session with Node 2
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .expect("initiate_session failed");

    // Process: SessionSetup: 0→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionSetup: 1→2 (arrives at destination C)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 2 should have an AwaitingMsg3 session (XK: identity not yet known)
    assert!(
        nodes[2].node.get_session(&node0_addr).is_some(),
        "Node 2 should have a session entry for Node 0"
    );
    assert!(nodes[2]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_awaiting_msg3());

    // Process: SessionAck: 2→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionAck: 1→0 (arrives at initiator A, sends SessionMsg3)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(nodes[0]
        .node
        .get_session(&node2_addr)
        .unwrap()
        .state()
        .is_established());

    // Process: SessionMsg3: 0→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionMsg3: 1→2 (arrives at responder C)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 2 should now be Established (transitions after processing msg3)
    assert!(nodes[2]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_established());

    // Transit node B should NOT have a session
    assert_eq!(
        nodes[1].node.session_count(),
        0,
        "Transit node should have no sessions"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_3node_forwarded_data() {
    // A—B—C: Establish session, send data end-to-end
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Establish session (needs more hops)
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .unwrap();

    // Drain packets until handshake completes (multi-hop needs several rounds)
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .map(|s| s.state().is_established())
            .unwrap_or(false),
        "Session should be established after handshake rounds"
    );

    // Send data
    let test_data = b"End-to-end through transit node B";
    nodes[0]
        .node
        .send_session_data(&node2_addr, test_data)
        .await
        .expect("send_session_data failed");

    // Drain data packet through transit node
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node 2 should be Established (transitioned during XK handshake msg3)
    assert!(nodes[2]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_established());

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Edge cases
// ============================================================================

#[tokio::test]
async fn test_session_initiate_idempotent() {
    // Calling initiate_session twice should be idempotent
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // First call
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    // Second call should be a no-op
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_send_data_no_session_fails() {
    let mut node = make_node();
    let fake_addr = make_node_addr(0xAA);

    let result = node.send_session_data(&fake_addr, b"test").await;
    assert!(result.is_err(), "Should fail with no session");
}

#[tokio::test]
async fn test_session_ack_for_unknown_session() {
    // Receiving a SessionAck when we have no Initiating session should be dropped
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Fabricate a SessionAck and deliver directly
    let src_coords = nodes[1].node.tree_state().my_coords().clone();
    let dest_coords = nodes[0].node.tree_state().my_coords().clone();
    let ack = SessionAck::new(src_coords, dest_coords).with_handshake(vec![0u8; 57]);
    let datagram = SessionDatagram::new(node1_addr, node0_addr, ack.encode());

    // Send through link layer
    let encoded = datagram.encode();
    nodes[1]
        .node
        .send_encrypted_link_message(&node0_addr, &encoded)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should have no sessions (ack was for unknown session)
    assert_eq!(nodes[0].node.session_count(), 0);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Large-scale test: 100-node session establishment + bidirectional data
// ============================================================================

/// Drain packets until quiescent (2 consecutive idle rounds).
async fn drain_to_quiescence(nodes: &mut [TestNode]) {
    let mut idle_rounds = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets(nodes).await;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 2 {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }
}

#[tokio::test]
async fn test_session_100_nodes() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::sync::mpsc;
    use std::time::Instant;

    // Same random topology as other 100-node tests
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let start = Instant::now();

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let setup_time = start.elapsed();

    // Collect identities: (node_addr, pubkey) for all nodes
    let all_info: Vec<(NodeAddr, secp256k1::PublicKey)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.identity().pubkey_full(),
            )
        })
        .collect();

    // Each node picks one random target for its outbound session.
    // Use deterministic RNG so failures are reproducible.
    let mut rng = StdRng::seed_from_u64(SEED + 1);
    let mut session_pairs: Vec<(usize, usize)> = Vec::with_capacity(NUM_NODES);
    for src in 0..NUM_NODES {
        let mut dst = rng.gen_range(0..NUM_NODES);
        while dst == src {
            dst = rng.gen_range(0..NUM_NODES);
        }
        session_pairs.push((src, dst));
    }

    // === Phase 1: Establish all sessions ===

    let session_start = Instant::now();

    for &(src, dst) in &session_pairs {
        let (dest_addr, dest_pubkey) = all_info[dst];

        nodes[src]
            .node
            .initiate_session(dest_addr, dest_pubkey)
            .await
            .expect("initiate_session failed");

        drain_to_quiescence(&mut nodes).await;
    }

    drain_to_quiescence(&mut nodes).await;
    let session_time = session_start.elapsed();

    // Verify all initiator sessions reached Established before data phase
    let mut handshake_failures: Vec<(usize, usize)> = Vec::new();
    for &(src, dst) in &session_pairs {
        let dest_addr = all_info[dst].0;
        let ok = nodes[src]
            .node
            .get_session(&dest_addr)
            .map(|e| e.state().is_established())
            .unwrap_or(false);
        if !ok {
            handshake_failures.push((src, dst));
        }
    }
    assert!(
        handshake_failures.is_empty(),
        "Handshake failed for {} pairs (first: {:?})",
        handshake_failures.len(),
        handshake_failures.first()
    );

    // === Phase 2: Inject TUN receivers and snapshot link stats ===

    // Install a tun_tx on every node so delivered datagrams can be counted.
    let mut tun_receivers: Vec<mpsc::Receiver<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for tn in nodes.iter_mut() {
        let (tx, rx) = mpsc::channel();
        tn.node.tun_tx = Some(tx);
        tun_receivers.push(rx);
    }

    // Snapshot per-peer link stats before data phase
    let link_pkts_sent_before: Vec<Vec<(NodeAddr, u64)>> = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers()
                .map(|p| (*p.node_addr(), p.link_stats().packets_sent))
                .collect()
        })
        .collect();

    // === Phase 3: Bidirectional data transfer ===
    //
    // For each session pair:
    //   1. Initiator sends one datagram to responder
    //   2. Responder sends one datagram back to initiator
    //
    // Batched per pair with draining between each.

    let data_start = Instant::now();
    let mut send_forward_ok = 0usize;
    let mut send_forward_err = 0usize;
    let mut send_reverse_ok = 0usize;
    let mut send_reverse_err = 0usize;

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let dest_addr = all_info[dst].0;
        let src_addr = all_info[src].0;

        // Forward: initiator → responder
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        match nodes[src]
            .node
            .send_session_data(&dest_addr, &fwd_payload)
            .await
        {
            Ok(()) => send_forward_ok += 1,
            Err(_) => send_forward_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;

        // Reverse: responder → initiator
        // (Responder should already be Established after XK msg3)
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();
        match nodes[dst]
            .node
            .send_session_data(&src_addr, &rev_payload)
            .await
        {
            Ok(()) => send_reverse_ok += 1,
            Err(_) => send_reverse_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;
    }

    let data_time = data_start.elapsed();

    // === Phase 4: Collect delivered datagrams from TUN receivers ===

    let mut delivered_per_node: Vec<Vec<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for rx in tun_receivers.iter_mut() {
        let mut packets = Vec::new();
        while let Ok(pkt) = rx.try_recv() {
            packets.push(pkt);
        }
        delivered_per_node.push(packets);
    }

    let total_delivered: usize = delivered_per_node.iter().map(|v| v.len()).sum();

    // Verify each pair's forward and reverse datagrams arrived
    let mut fwd_delivered = 0usize;
    let mut rev_delivered = 0usize;
    let mut fwd_missing: Vec<(usize, usize)> = Vec::new();
    let mut rev_missing: Vec<(usize, usize)> = Vec::new();

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();

        if delivered_per_node[dst].contains(&fwd_payload) {
            fwd_delivered += 1;
        } else if fwd_missing.len() < 20 {
            fwd_missing.push((src, dst));
        }

        if delivered_per_node[src].contains(&rev_payload) {
            rev_delivered += 1;
        } else if rev_missing.len() < 20 {
            rev_missing.push((src, dst));
        }
    }

    // === Phase 5: Final session state ===

    let mut total_established = 0usize;
    let mut total_responding = 0usize;
    let mut total_initiating = 0usize;
    let mut fully_established_nodes = 0usize;

    for tn in &nodes {
        let mut all_est = true;
        for (_, entry) in tn.node.sessions.iter() {
            if entry.state().is_established() {
                total_established += 1;
            } else if entry.state().is_awaiting_msg3() {
                total_responding += 1;
                all_est = false;
            } else {
                total_initiating += 1;
                all_est = false;
            }
        }
        if tn.node.session_count() > 0 && all_est {
            fully_established_nodes += 1;
        }
    }

    let session_counts: Vec<usize> = nodes
        .iter()
        .map(|tn| tn.node.session_count())
        .collect();
    let total_sessions: usize = session_counts.iter().sum();
    let min_sessions = *session_counts.iter().min().unwrap();
    let max_sessions = *session_counts.iter().max().unwrap();

    // === Phase 6: Link and routing statistics ===

    // Link stats delta: packets sent during data phase
    let mut data_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_recv: u64 = 0;
    let mut total_link_bytes_sent: u64 = 0;
    let mut total_link_bytes_recv: u64 = 0;

    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers() {
            let stats = peer.link_stats();
            // Delta for this peer since before data phase
            let before = link_pkts_sent_before[i]
                .iter()
                .find(|(addr, _)| addr == peer.node_addr())
                .map(|(_, pkts)| *pkts)
                .unwrap_or(0);
            data_link_pkts_sent += stats.packets_sent.saturating_sub(before);

            // Totals (cumulative since node creation)
            total_link_pkts_sent += stats.packets_sent;
            total_link_pkts_recv += stats.packets_recv;
            total_link_bytes_sent += stats.bytes_sent;
            total_link_bytes_recv += stats.bytes_recv;
        }
    }

    // Estimate average hop count from link packet overhead.
    // Each data datagram traverses N link hops, each producing 1 link send.
    // We sent 200 datagrams total (100 forward + 100 reverse).
    let total_data_datagrams = (send_forward_ok + send_reverse_ok) as u64;
    let avg_hops = if total_data_datagrams > 0 {
        data_link_pkts_sent as f64 / total_data_datagrams as f64
    } else {
        0.0
    };

    // Coord cache stats
    let coord_cache_sizes: Vec<usize> = nodes
        .iter()
        .map(|tn| tn.node.coord_cache().len())
        .collect();
    let total_coord_entries: usize = coord_cache_sizes.iter().sum();
    let min_coord = *coord_cache_sizes.iter().min().unwrap();
    let max_coord = *coord_cache_sizes.iter().max().unwrap();

    // === Report ===

    eprintln!("\n  === Session 100-Node Test ===");
    eprintln!(
        "  Topology: {} nodes, {} edges (seed {})",
        NUM_NODES,
        edges.len(),
        SEED
    );
    eprintln!(
        "  Session pairs: {} (1 outbound per node, random target)",
        session_pairs.len()
    );

    eprintln!("\n  --- Handshake ---");
    eprintln!(
        "  Initiator established: {}/{}",
        session_pairs.len(),
        session_pairs.len()
    );

    eprintln!("\n  --- Data Transfer ---");
    eprintln!(
        "  Forward (initiator->responder): {} sent, {} errors",
        send_forward_ok, send_forward_err
    );
    eprintln!(
        "  Reverse (responder->initiator): {} sent, {} errors",
        send_reverse_ok, send_reverse_err
    );
    eprintln!(
        "  TUN delivery: {} total ({} expected)",
        total_delivered,
        send_forward_ok + send_reverse_ok
    );
    eprintln!(
        "  Forward delivered: {}/{} | Reverse delivered: {}/{}",
        fwd_delivered, send_forward_ok, rev_delivered, send_reverse_ok
    );

    eprintln!("\n  --- Final Session State ---");
    eprintln!(
        "  Entries: {} total ({} established, {} responding, {} initiating)",
        total_sessions, total_established, total_responding, total_initiating
    );
    eprintln!(
        "  Per node: min={} max={} avg={:.1}",
        min_sessions,
        max_sessions,
        total_sessions as f64 / NUM_NODES as f64
    );
    eprintln!(
        "  All-established nodes: {}/{}",
        fully_established_nodes, NUM_NODES
    );

    eprintln!("\n  --- Routing ---");
    eprintln!(
        "  Data-phase link hops: {} ({:.1} avg hops/datagram over {} datagrams)",
        data_link_pkts_sent, avg_hops, total_data_datagrams
    );
    eprintln!(
        "  Lifetime link totals: {} pkts sent, {} pkts recv, {:.1} KB sent, {:.1} KB recv",
        total_link_pkts_sent,
        total_link_pkts_recv,
        total_link_bytes_sent as f64 / 1024.0,
        total_link_bytes_recv as f64 / 1024.0
    );
    eprintln!(
        "  Coord cache: total={} min={} max={} avg={:.1}",
        total_coord_entries,
        min_coord,
        max_coord,
        total_coord_entries as f64 / NUM_NODES as f64
    );

    eprintln!("\n  --- Timing ---");
    eprintln!(
        "  Setup: {:.1}s | Handshake: {:.1}s | Data: {:.1}s | Total: {:.1}s",
        setup_time.as_secs_f64(),
        session_time.as_secs_f64(),
        data_time.as_secs_f64(),
        start.elapsed().as_secs_f64()
    );

    if !fwd_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered forward datagrams:",
            fwd_missing.len()
        );
        for &(src, dst) in &fwd_missing {
            eprintln!("    node {} -> node {}", src, dst);
        }
    }
    if !rev_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered reverse datagrams:",
            rev_missing.len()
        );
        for &(src, dst) in &rev_missing {
            eprintln!("    node {} <- node {}", src, dst);
        }
    }

    // === Assertions ===

    assert_eq!(
        send_forward_err, 0,
        "All forward sends should succeed"
    );
    assert_eq!(
        send_reverse_err, 0,
        "All reverse sends should succeed (responder Established after XK msg3)"
    );
    assert_eq!(
        fwd_delivered, send_forward_ok,
        "All forward datagrams should be delivered to responder TUN"
    );
    assert_eq!(
        rev_delivered, send_reverse_ok,
        "All reverse datagrams should be delivered to initiator TUN"
    );
    assert_eq!(
        total_established, total_sessions,
        "All {} session entries should be Established, \
         but {} responding, {} initiating",
        total_sessions, total_responding, total_initiating
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Data plane integration tests: TUN → session → link → TUN
// ============================================================================

/// Build a minimal valid IPv6 packet with given source and destination addresses.
fn build_ipv6_packet(src: &crate::FipsAddress, dst: &crate::FipsAddress, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut packet = vec![0u8; 40 + payload.len()];
    // Version (6) + traffic class high nibble
    packet[0] = 0x60;
    // Payload length (u16 BE)
    packet[4] = (payload_len >> 8) as u8;
    packet[5] = (payload_len & 0xff) as u8;
    // Next header: 59 = No Next Header
    packet[6] = 59;
    // Hop limit
    packet[7] = 64;
    // Source address (bytes 8-23)
    packet[8..24].copy_from_slice(src.as_bytes());
    // Destination address (bytes 24-39)
    packet[24..40].copy_from_slice(dst.as_bytes());
    // Payload
    packet[40..].copy_from_slice(payload);
    packet
}

#[test]
fn test_identity_cache_populated_on_promote() {
    use crate::peer::PromotionResult;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, peer_identity) = make_completed_connection(
        &mut node,
        link_id,
        transport_id,
        1000,
    );

    node.add_connection(conn).unwrap();

    // Promote
    let result = node.promote_connection(link_id, peer_identity, 2000).unwrap();
    assert!(matches!(result, PromotionResult::Promoted(_)));

    // Identity cache should contain the peer
    let peer_addr = *peer_identity.node_addr();
    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&peer_addr.as_bytes()[0..15]);
    let cached = node.lookup_by_fips_prefix(&prefix);
    assert!(cached.is_some(), "Identity cache should contain promoted peer");
    let (cached_addr, cached_pk) = cached.unwrap();
    assert_eq!(cached_addr, peer_addr);
    assert_eq!(cached_pk, peer_identity.pubkey_full());
}

#[tokio::test]
async fn test_tun_outbound_established_session() {
    // Two directly connected nodes, session established.
    // Inject IPv6 packet via handle_tun_outbound on Node 0,
    // verify plaintext arrives at Node 1's tun_tx.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
    nodes[0].node.initiate_session(node1_addr, node1_pubkey).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Setup → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Ack → Node 0, Node 0 sends Msg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Msg3 → Node 1

    assert!(nodes[0].node.get_session(&node1_addr).unwrap().state().is_established());

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet
    let test_payload = b"data-plane-test-12345";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Process packets: encrypted data → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Verify plaintext arrived at Node 1's TUN
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Exactly one packet should be delivered");
    assert_eq!(delivered[0], ipv6_packet, "Delivered packet should match original");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_triggers_session_initiation() {
    // Two connected nodes, no session yet.
    // Inject a TUN packet — should trigger session initiation,
    // queue the packet, and deliver after handshake completes.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // No session yet
    assert_eq!(nodes[0].node.session_count(), 0);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet (identity cache populated at peer promotion)
    let test_payload = b"trigger-session-test";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Session should now be initiating
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(nodes[0].node.get_session(&node1_addr).unwrap().state().is_initiating());

    // Drain packets until session established and queued packet delivered
    drain_to_quiescence(&mut nodes).await;

    // Session should be established on Node 0
    assert!(nodes[0].node.get_session(&node1_addr).unwrap().state().is_established());

    // Verify the queued packet was delivered to Node 1
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Queued packet should be delivered after handshake");
    assert_eq!(delivered[0], ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_unknown_destination() {
    // Inject a packet for an unknown destination — should get ICMPv6 back
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Install TUN receiver on Node 0 (for ICMPv6 response)
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.tun_tx = Some(tun_tx);

    let src_fips = crate::FipsAddress::from_node_addr(nodes[0].node.node_addr());

    // Build a packet to an unknown FIPS address (not in identity cache)
    let unknown_addr = NodeAddr::from_bytes([0xAA; 16]);
    let unknown_fips = crate::FipsAddress::from_node_addr(&unknown_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &unknown_fips, b"unknown");

    nodes[0].node.handle_tun_outbound(ipv6_packet).await;

    // Should receive ICMPv6 Destination Unreachable back on TUN
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Should receive ICMPv6 Destination Unreachable");
    // Verify it's an ICMPv6 Destination Unreachable (type 1, code 0)
    // ICMPv6 header starts at byte 40, type at byte 40, code at byte 41
    assert!(delivered[0].len() >= 48, "ICMPv6 response too short");
    assert_eq!(delivered[0][6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(delivered[0][40], 1, "ICMPv6 type should be Destination Unreachable (1)");
    assert_eq!(delivered[0][41], 0, "ICMPv6 code should be No Route (0)");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_3node_forwarded() {
    // A—B—C: TUN packet from A destined for C, forwarded through B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node2_addr);

    // Register Node 2's identity in Node 0's cache
    // (In production, this would come from the discovery protocol or DNS priming)
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Install TUN receiver on Node 2
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[2].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet (triggers session initiation to Node 2)
    let test_payload = b"forwarded-data-plane";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Drain packets: handshake + queued data delivery
    drain_to_quiescence(&mut nodes).await;

    // Session should be established
    assert!(nodes[0].node.get_session(&node2_addr).unwrap().state().is_established());

    // Verify packet delivered to Node 2
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Packet should be delivered to Node 2");
    assert_eq!(delivered[0], ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_pending_queue_flush() {
    // Send multiple packets before session exists — all should be delivered
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Send 5 packets before any session exists
    let mut packets = Vec::new();
    for i in 0..5u8 {
        let payload = format!("queued-pkt-{}", i).into_bytes();
        let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &payload);
        packets.push(ipv6_packet.clone());
        nodes[0].node.handle_tun_outbound(ipv6_packet).await;
    }

    // First packet triggers session initiation, rest are queued
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(nodes[0].node.get_session(&node1_addr).unwrap().state().is_initiating());

    // Drain until session established and queued packets flushed
    drain_to_quiescence(&mut nodes).await;

    assert!(nodes[0].node.get_session(&node1_addr).unwrap().state().is_established());

    // All 5 packets should have been delivered
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 5, "All 5 queued packets should be delivered");
    for (i, pkt) in delivered.iter().enumerate() {
        assert_eq!(*pkt, packets[i], "Packet {} should match", i);
    }

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Unit tests: Session idle timeout
// ============================================================================

/// Helper: complete a Noise IK handshake and return the initiator's NoiseSession.
fn make_noise_session(
    our_identity: &Identity,
    remote_identity: &Identity,
) -> crate::noise::NoiseSession {
    use crate::noise::HandshakeState;

    let mut initiator = HandshakeState::new_initiator(
        our_identity.keypair(),
        remote_identity.pubkey_full(),
    );
    let mut responder = HandshakeState::new_responder(remote_identity.keypair());

    // Set epochs for both sides (required for handshake message encryption)
    let mut init_epoch = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut init_epoch);
    initiator.set_local_epoch(init_epoch);
    let mut resp_epoch = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut resp_epoch);
    responder.set_local_epoch(resp_epoch);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    initiator.into_session().unwrap()
}

#[test]
fn test_purge_idle_sessions_removes_expired() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1000ms
        true,
    );

    node.sessions.insert(remote_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&remote_addr).unwrap().is_established());

    // Purge at t=92s — should exceed default 90s idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0, "Idle session should be purged");
}

#[test]
fn test_purge_idle_sessions_keeps_active() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    // Touch at t=80s — recent activity
    entry.touch(81_000);

    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — only 11s since last activity, well within 90s timeout
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 1, "Active session should survive purge");
}

#[test]
fn test_purge_idle_sessions_ignores_initiating() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let handshake = HandshakeState::new_initiator(
        node.identity().keypair(),
        remote.pubkey_full(),
    );
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Purge well past the idle timeout — Initiating sessions should not be touched
    let now_ms = 1000 + 200_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 1, "Initiating session should not be purged by idle timeout");
}

#[test]
fn test_purge_idle_sessions_cleans_pending_packets() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Insert some pending packets for this destination
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(vec![1, 2, 3]);
    node.pending_tun_packets.insert(remote_addr, queue);
    assert!(node.pending_tun_packets.contains_key(&remote_addr));

    // Purge after idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0);
    assert!(!node.pending_tun_packets.contains_key(&remote_addr),
        "Pending packets should be cleaned up with idle session");
}

#[test]
fn test_purge_idle_sessions_disabled_when_zero() {
    let mut node = make_node();
    node.config.node.session.idle_timeout_secs = 0;

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Even way past any timeout, sessions should survive when disabled
    let now_ms = 1000 + 1_000_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 1, "Sessions should not be purged when idle timeout is disabled");
}

#[test]
fn test_purge_idle_sessions_mmp_activity_does_not_prevent_purge() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1s
        true,
    );

    // Do NOT call entry.touch() — simulates a session where only MMP
    // reports have flowed (MMP no longer calls touch). last_activity
    // remains at creation time (1000ms).
    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — 91s since creation, exceeds 90s idle timeout.
    // Even though MMP reports would have been flowing, they no longer
    // reset the idle timer.
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0,
        "Session with MMP-only activity should be purged");
}

// ============================================================================
// Unit tests: COORDS_PRESENT warmup counter
// ============================================================================

#[test]
fn test_coords_warmup_counter_default_zero_on_new() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    assert_eq!(entry.coords_warmup_remaining(), 0,
        "Counter should be 0 for non-Established sessions");
}

#[test]
fn test_coords_warmup_counter_set_and_get() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    assert_eq!(entry.coords_warmup_remaining(), 0);

    entry.set_coords_warmup_remaining(5);
    assert_eq!(entry.coords_warmup_remaining(), 5);

    entry.set_coords_warmup_remaining(0);
    assert_eq!(entry.coords_warmup_remaining(), 0);
}

#[test]
fn test_coords_warmup_counter_decrement() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    entry.set_coords_warmup_remaining(3);

    // Simulate the decrement pattern used in send_session_data
    for expected in (0..3).rev() {
        assert!(entry.coords_warmup_remaining() > 0);
        entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        assert_eq!(entry.coords_warmup_remaining(), expected);
    }

    assert_eq!(entry.coords_warmup_remaining(), 0,
        "Counter should reach 0 after N decrements");
}

#[test]
fn test_coords_warmup_config_default() {
    let config = crate::config::Config::new();
    assert_eq!(config.node.session.coords_warmup_packets, 5,
        "Default coords_warmup_packets should be 5");
}

// ============================================================================
// Unit tests: Identity cache
// ============================================================================

#[test]
fn test_identity_cache_lru_eviction() {
    let mut node = make_node();
    node.config.node.cache.identity_size = 2;

    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let id3 = Identity::generate();

    // Insert first two with explicit timestamps to ensure deterministic ordering
    let mut prefix1 = [0u8; 15];
    prefix1.copy_from_slice(&id1.node_addr().as_bytes()[0..15]);
    node.identity_cache.insert(prefix1, (*id1.node_addr(), id1.pubkey_full(), 1000));

    let mut prefix2 = [0u8; 15];
    prefix2.copy_from_slice(&id2.node_addr().as_bytes()[0..15]);
    node.identity_cache.insert(prefix2, (*id2.node_addr(), id2.pubkey_full(), 2000));

    assert_eq!(node.identity_cache_len(), 2);

    // Adding a third should evict the oldest (id1, timestamp 1000)
    node.register_identity(*id3.node_addr(), id3.pubkey_full());
    assert_eq!(node.identity_cache_len(), 2);

    assert!(node.lookup_by_fips_prefix(&prefix1).is_none(),
        "Oldest entry should have been evicted");

    let mut prefix3 = [0u8; 15];
    prefix3.copy_from_slice(&id3.node_addr().as_bytes()[0..15]);
    assert!(node.lookup_by_fips_prefix(&prefix3).is_some(),
        "Newest entry should be present");
}

#[test]
fn test_identity_cache_lookup() {
    let mut node = make_node();

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    node.register_identity(remote_addr, remote.pubkey_full());

    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&remote_addr.as_bytes()[0..15]);

    let result = node.lookup_by_fips_prefix(&prefix);
    assert!(result.is_some(), "Registered identity should be available");

    let (addr, pk) = result.unwrap();
    assert_eq!(addr, remote_addr);
    assert_eq!(pk, remote.pubkey_full());
}

// ============================================================================
// Session-layer handshake resend tests
// ============================================================================

/// Test that SessionEntry handshake payload storage works correctly.
#[test]
fn test_session_entry_handshake_payload_storage() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    // Initially no handshake payload
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 0);

    // Store a handshake payload
    let payload = vec![0x01, 0x02, 0x03, 0x04];
    entry.set_handshake_payload(payload.clone(), 2000);

    assert_eq!(entry.handshake_payload().unwrap(), &payload);
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 2000);
}

/// Test that resend_count and next_resend_at_ms track correctly on SessionEntry.
#[test]
fn test_session_entry_resend_tracking() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01], 2000);

    // Record first resend
    entry.record_resend(4000);
    assert_eq!(entry.resend_count(), 1);
    assert_eq!(entry.next_resend_at_ms(), 4000);

    // Record second resend
    entry.record_resend(8000);
    assert_eq!(entry.resend_count(), 2);
    assert_eq!(entry.next_resend_at_ms(), 8000);
}

/// Test that clear_handshake_payload clears payload and resets timer.
#[test]
fn test_session_entry_clear_handshake_payload() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01, 0x02], 2000);
    entry.record_resend(4000);
    assert!(entry.handshake_payload().is_some());
    assert_eq!(entry.resend_count(), 1);

    // Clear on Established transition
    entry.clear_handshake_payload();
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.next_resend_at_ms(), 0);
    // resend_count is NOT reset — it's a historical record
    assert_eq!(entry.resend_count(), 1);
}

/// Test that session handshake timeout removes stale Initiating sessions.
#[tokio::test]
async fn test_session_handshake_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_b = Identity::generate();
    let handshake = HandshakeState::new_initiator(
        node.identity.keypair(),
        identity_b.pubkey_full(),
    );

    let dest_addr = *identity_b.node_addr();

    // Create a session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );
    node.sessions.insert(dest_addr, entry);

    assert!(node.sessions.contains_key(&dest_addr));

    // Before timeout: session should remain
    let timeout_secs = node.config.node.rate_limit.handshake_timeout_secs;
    let before_timeout = 1000 + timeout_secs * 1000 - 1;
    node.resend_pending_session_handshakes(before_timeout).await;
    assert!(node.sessions.contains_key(&dest_addr), "Session should survive before timeout");

    // After timeout: session should be removed
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(!node.sessions.contains_key(&dest_addr), "Timed-out session should be removed");
}

/// Test that session handshake timeout removes stale AwaitingMsg3 sessions.
#[tokio::test]
async fn test_session_awaiting_msg3_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_xk_responder(
        identity_b.keypair(),
    );

    let src_addr = *identity_a.node_addr();

    // Create an AwaitingMsg3 session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        src_addr,
        identity_a.pubkey_full(),
        EndToEndState::AwaitingMsg3(handshake),
        1000,
        false,
    );
    node.sessions.insert(src_addr, entry);

    assert!(node.sessions.contains_key(&src_addr));

    // After timeout: session should be removed
    let timeout_secs = node.config.node.rate_limit.handshake_timeout_secs;
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(!node.sessions.contains_key(&src_addr), "Timed-out AwaitingMsg3 session should be removed");
}
