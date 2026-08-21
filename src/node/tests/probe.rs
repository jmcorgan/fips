//! Integration tests for the `probe` diagnostic.
//!
//! Each runs a two-node topology, starts a probe on node 0 toward node 1, then
//! alternates packet delivery with explicit `poll_probes` calls in a bounded
//! loop — the harness has no rx-loop tick, so the driver is invoked by hand.
//!
//! Stated coverage gap, not discharged: a same-process harness has a
//! sub-millisecond path, so `MmpMetrics`'s `rtt_ms > 0` guard can reject every
//! sample and the rtt stage then reports `sub_millisecond` rather than `ok`.
//! A real round-trip measurement is exercisable only on a live multi-host
//! mesh, and the `rtt: ok` path stays unexercised here.

use super::*;
use crate::proto::probe::StageVerdict;
use spanning_tree::{
    TestNode, cleanup_nodes, populate_all_coord_caches, process_available_packets, run_tree_test,
    verify_tree_convergence,
};

/// Two peered nodes with coordinates seeded on both sides.
async fn two_peered_nodes() -> Vec<TestNode> {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    nodes
}

/// Deliver packets, let both nodes emit their MMP reports, and advance node
/// 0's probes. One call is one simulated tick.
async fn pump(nodes: &mut [TestNode]) {
    tokio::time::sleep(Duration::from_millis(10)).await;
    process_available_packets(nodes).await;
    for tn in nodes.iter_mut() {
        tn.node.check_session_mmp_reports().await;
    }
    nodes[0].node.poll_probes().await;
}

/// Pump until the probe reaches a terminal state, or give up. Returns whether
/// it finished, so a caller can assert rather than hang.
async fn pump_until_done(nodes: &mut [TestNode], id: u64, rounds: usize) -> bool {
    for _ in 0..rounds {
        pump(nodes).await;
        if nodes[0]
            .node
            .probe_job(id)
            .is_none_or(|job| job.probe().is_finished())
        {
            return true;
        }
    }
    false
}

fn npub_of(nodes: &[TestNode], idx: usize) -> String {
    nodes[idx].node.identity().npub()
}

async fn start_probe(nodes: &mut [TestNode], target: usize) -> u64 {
    let npub = npub_of(nodes, target);
    let data = nodes[0]
        .node
        .api_probe_start(&npub)
        .await
        .expect("probe admitted");
    data["probe_id"].as_u64().expect("probe_id is a number")
}

#[tokio::test]
async fn a_probe_is_stepped_at_admission_rather_than_waiting_for_the_next_tick() {
    // Nothing here pumps: the assertions are about the state `api_probe_start`
    // leaves behind. Left to the tick driver, the first stage does not begin
    // until the next tick fires, which spends a whole tick period of the
    // probe's budget before a single message is sent.
    let mut nodes = two_peered_nodes().await;
    let id = start_probe(&mut nodes, 1).await;

    let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
    assert_eq!(
        snap.bloom.verdict,
        StageVerdict::Skipped,
        "the bloom stage should have run and skipped a direct peer: {:?}",
        snap.bloom
    );
    assert_eq!(
        snap.discovery.verdict,
        StageVerdict::Skipped,
        "discovery should have been skipped with it: {:?}",
        snap.discovery
    );
    assert_ne!(
        snap.path.verdict,
        StageVerdict::Pending,
        "path should have been computed in the same step: {:?}",
        snap.path
    );
    assert_eq!(
        snap.session.verdict,
        StageVerdict::Running,
        "the session stage should be in flight already: {:?}",
        snap.session
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_reaches_session_stage_against_direct_peer() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let node0_addr = *nodes[0].node.node_addr();
    let id = start_probe(&mut nodes, 1).await;

    for _ in 0..20 {
        pump(&mut nodes).await;
        let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
        if snap.session.verdict == StageVerdict::Ok {
            // The initiator flips to Established on sending msg3; the far end
            // needs one more delivery pass to process it.
            pump(&mut nodes).await;
            pump(&mut nodes).await;
            break;
        }
    }

    let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
    assert_eq!(
        snap.session.verdict,
        StageVerdict::Ok,
        "session stage: {:?}",
        snap.session
    );
    assert!(nodes[0].node.get_session(&node1_addr).is_some());
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.is_established()),
        "the far end must hold an established session too"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_tears_down_the_session_it_opened() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let id = start_probe(&mut nodes, 1).await;

    assert!(
        pump_until_done(&mut nodes, id, 600).await,
        "probe must reach a terminal state"
    );
    let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
    assert!(snap.torn_down, "cleanup: {:?}", snap.left_intact);
    assert!(
        nodes[0].node.get_session(&node1_addr).is_none(),
        "the probe-created session must be gone"
    );

    // The rtt stage must terminate rather than hang, either with a real
    // measurement or with one of the four discriminated failure reasons.
    assert!(
        matches!(snap.rtt.verdict, StageVerdict::Ok | StageVerdict::Failed),
        "rtt stage: {:?}",
        snap.rtt
    );

    // The projection is what a script actually reads, and the tests above all
    // bypass it by reading the core snapshot directly. Assert on the published
    // JSON, including the poll API's remove-on-done behaviour.
    let data = nodes[0].node.api_probe_poll(id).expect("poll accepted");
    assert_eq!(data["state"], "done");
    let report = &data["report"];
    assert_eq!(report["probe_id"].as_u64(), Some(id));
    assert_eq!(report["cleanup"]["session_created_and_torn_down"], true);
    assert_eq!(report["cleanup"]["session_left_intact"], false);
    assert_eq!(
        report["cleanup"]["left_intact_reason"],
        serde_json::Value::Null
    );
    assert_eq!(report["session"]["preexisting"], false);
    assert_eq!(report["session"]["established"], true);
    assert_eq!(report["path"]["computed_locally"], true);
    assert_eq!(report["path"]["observed"], false);
    assert!(
        nodes[0].node.api_probe_poll(id).is_err(),
        "a terminal report is delivered exactly once"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_leaves_a_preexisting_session_intact() {
    let mut nodes = two_peered_nodes().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established())
    );

    let id = start_probe(&mut nodes, 1).await;
    assert!(pump_until_done(&mut nodes, id, 600).await);

    let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
    assert!(!snap.torn_down, "must not remove a session it did not open");
    assert!(snap.session_preexisting);
    assert_eq!(
        snap.left_intact.map(|r| r.name()),
        Some("preexisting"),
        "session stage: {:?}",
        snap.session
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "our end of the pre-existing session must survive"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.is_established()),
        "the far end must survive too"
    );

    let data = nodes[0].node.api_probe_poll(id).expect("poll accepted");
    assert_eq!(data["state"], "done");
    let report = &data["report"];
    assert_eq!(report["cleanup"]["session_created_and_torn_down"], false);
    assert_eq!(report["cleanup"]["session_left_intact"], true);
    assert_eq!(report["cleanup"]["left_intact_reason"], "preexisting");
    assert_eq!(report["session"]["preexisting"], true);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_declines_to_tear_down_a_session_adopted_by_traffic() {
    // The drive-time half of the ownership guard. Cancel drives the terminal
    // actions with no fresh observation, so the core still believes it owns the
    // session and the refusal has to come from the driver's own identity check.
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let id = start_probe(&mut nodes, 1).await;

    for _ in 0..20 {
        pump(&mut nodes).await;
        let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
        if snap.session.verdict == StageVerdict::Ok {
            break;
        }
    }
    assert!(nodes[0].node.get_session(&node1_addr).is_some());

    // Real application traffic moves on the session after the probe's last
    // observation: it is no longer the probe's to remove.
    nodes[0]
        .node
        .get_session_mut(&node1_addr)
        .expect("probe session")
        .record_recv(512);

    nodes[0]
        .node
        .api_probe_cancel(id)
        .await
        .expect("cancel accepted");

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "an adopted session must survive the probe's teardown"
    );
    let data = nodes[0].node.api_probe_poll(id).expect("poll accepted");
    let cleanup = &data["report"]["cleanup"];
    assert_eq!(cleanup["session_created_and_torn_down"], false);
    assert_eq!(cleanup["left_intact_reason"], "adopted_by_traffic");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_names_a_tree_next_hop_for_a_target_two_hops_away() {
    // The two-node topologies above always take the direct-peer short-circuit,
    // so everything past it — candidate selection, the tree-state fallback and
    // the forward classification — goes unrun. A chain exercises it, and a
    // multi-hop target is the case the feature exists to diagnose.
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let wall_ms = Node::now_ms();
    let (hop, reason) = nodes[0].node.preview_next_hop(&node2_addr, wall_ms);

    let hop = hop.unwrap_or_else(|| panic!("no next hop toward a two-hop target: {reason:?}"));
    assert_eq!(reason, None);
    assert_eq!(hop.node_addr, node1_addr, "the relay is the first hop");
    assert!(!hop.direct_peer, "a two-hop target is not a direct peer");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn preview_next_hop_reports_why_it_could_name_no_hop() {
    let mut nodes = two_peered_nodes().await;
    let node0_addr = *nodes[0].node.node_addr();
    let wall_ms = Node::now_ms();

    // The local address routes nowhere.
    let (hop, reason) = nodes[0].node.preview_next_hop(&node0_addr, wall_ms);
    assert!(hop.is_none());
    assert_eq!(reason.map(|r| r.name()), Some("local"));

    // An address that is neither a peer nor in the coord cache.
    let stranger = crate::NodeAddr::from_bytes([0x5a; 16]);
    let (hop, reason) = nodes[0].node.preview_next_hop(&stranger, wall_ms);
    assert!(hop.is_none());
    assert_eq!(reason.map(|r| r.name()), Some("no_coords"));

    // Coordinates under a root nobody here can reach: no peer is closer.
    let alien_root = crate::NodeAddr::from_bytes([0x77; 16]);
    let coords = crate::proto::stp::TreeCoordinate::from_addrs(vec![stranger, alien_root])
        .expect("non-empty coordinate");
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(stranger, coords, wall_ms);
    let (hop, reason) = nodes[0].node.preview_next_hop(&stranger, wall_ms);
    assert!(hop.is_none(), "no peer makes progress toward another tree");
    assert_eq!(reason.map(|r| r.name()), Some("no_closer_peer"));

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_does_not_own_a_session_replaced_after_start() {
    let mut nodes = two_peered_nodes().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node0_pubkey = nodes[0].node.identity().pubkey_full();

    let id = start_probe(&mut nodes, 1).await;
    for _ in 0..20 {
        pump(&mut nodes).await;
        let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
        if snap.session.verdict == StageVerdict::Ok {
            break;
        }
    }
    assert!(nodes[0].node.get_session(&node1_addr).is_some());

    // The probe opens its session at admission, so the entry it must not own
    // is one that arrives in place of its own. Dropping both halves and
    // letting node 1 dial produces exactly what a peer's inbound handshake
    // does under simultaneous initiation — an established entry node 0 did
    // not initiate — without depending on which side wins a tie-break.
    nodes[0].node.remove_session(&node1_addr);
    nodes[1].node.remove_session(&node0_addr);
    nodes[1]
        .node
        .initiate_session(node0_addr, node0_pubkey)
        .await
        .expect("initiate_session failed");
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| !e.is_initiator()),
        "the replacement must be the peer's entry, not ours"
    );

    nodes[0]
        .node
        .api_probe_cancel(id)
        .await
        .expect("cancel accepted");

    let data = nodes[0].node.api_probe_poll(id).expect("poll accepted");
    let cleanup = &data["report"]["cleanup"];
    assert_eq!(cleanup["session_created_and_torn_down"], false);
    assert_eq!(cleanup["left_intact_reason"], "replaced");
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "the peer-driven session must survive the probe"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.is_established()),
        "node 1's own session must survive"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_does_not_discard_queued_tun_packets() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let id = start_probe(&mut nodes, 1).await;

    // Establish the probe's session first. The normal establish and inbound
    // paths legitimately flush anything queued for a destination, so the
    // packet is queued after the last delivery pass and the teardown is driven
    // by cancelling — the queue is then observed across the teardown alone.
    for _ in 0..20 {
        pump(&mut nodes).await;
        let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
        if snap.session.verdict == StageVerdict::Ok {
            break;
        }
    }
    nodes[0]
        .node
        .queue_pending_tun_packet_for_test(node1_addr, vec![0u8; 64]);
    assert_eq!(nodes[0].node.pending_tun_total_packets(), 1);

    nodes[0]
        .node
        .api_probe_cancel(id)
        .await
        .expect("cancel accepted");
    assert!(
        nodes[0].node.get_session(&node1_addr).is_none(),
        "cancel must still tear the probe's own session down"
    );
    assert_eq!(
        nodes[0].node.pending_tun_total_packets(),
        1,
        "the probe must not touch queued user packets"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn probe_terminates_without_a_poller() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let id = start_probe(&mut nodes, 1).await;

    // Never call the poll API: the job must still be driven to terminal on the
    // tick, which is what makes the feature safe when the client goes away.
    assert!(pump_until_done(&mut nodes, id, 600).await);
    assert!(nodes[0].node.probe_job(id).unwrap().probe().is_finished());
    assert!(nodes[0].node.get_session(&node1_addr).is_none());

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn concurrent_probes_to_one_target_do_not_both_own_it() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let first = start_probe(&mut nodes, 1).await;
    let second = start_probe(&mut nodes, 1).await;
    assert_ne!(first, second);

    assert!(pump_until_done(&mut nodes, first, 600).await);
    assert!(pump_until_done(&mut nodes, second, 600).await);

    let a = nodes[0].node.probe_job(first).unwrap().probe().snapshot();
    let b = nodes[0].node.probe_job(second).unwrap().probe().snapshot();
    assert_eq!(
        usize::from(a.torn_down) + usize::from(b.torn_down),
        1,
        "exactly one job may own and tear down the session"
    );
    assert!(a.session_preexisting || b.session_preexisting);
    assert!(nodes[0].node.get_session(&node1_addr).is_none());

    cleanup_nodes(&mut nodes).await;
}
