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

/// Run the idle purge on every node as if `idle_timeout_secs` and a second
/// more had passed since the last application data.
fn purge_idle_everywhere(nodes: &mut [TestNode]) {
    for tn in nodes.iter_mut() {
        let idle_ms = tn.node.config().node.session.idle_timeout_secs * 1000;
        tn.node
            .purge_idle_sessions(Node::now_ms() + idle_ms + 1_000);
    }
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
async fn probe_leaves_the_established_session_it_opened_to_the_idle_timeout() {
    let mut nodes = two_peered_nodes().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let id = start_probe(&mut nodes, 1).await;

    assert!(
        pump_until_done(&mut nodes, id, 600).await,
        "probe must reach a terminal state"
    );
    let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
    assert!(!snap.session_preexisting, "the probe opened the session");
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established() && e.is_initiator()),
        "the probe's own end must stay while the target holds its end"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.is_established()),
        "the target's end is established"
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
    assert_eq!(report["cleanup"]["session_created_and_torn_down"], false);
    assert_eq!(report["cleanup"]["session_left_intact"], true);
    assert_eq!(report["cleanup"]["left_intact_reason"], "idle_timeout");
    assert_eq!(report["session"]["preexisting"], false);
    assert_eq!(report["session"]["established"], true);
    assert_eq!(report["path"]["computed_locally"], true);
    assert_eq!(report["path"]["observed"], false);
    assert!(
        nodes[0].node.api_probe_poll(id).is_err(),
        "a terminal report is delivered exactly once"
    );

    // The idle timeout closes both ends.
    purge_idle_everywhere(&mut nodes);
    assert!(nodes[0].node.get_session(&node1_addr).is_none());
    assert!(nodes[1].node.get_session(&node0_addr).is_none());

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
    let _ = nodes[0]
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
async fn probe_removes_its_unfinished_session_without_discarding_queued_tun_packets() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let id = start_probe(&mut nodes, 1).await;

    // The probe opens its session at admission, and nothing has been
    // delivered yet, so its handshake is still in flight. The establish and
    // inbound paths legitimately flush anything queued for a destination, so
    // the packet is queued with no delivery pass after it and the teardown is
    // driven by cancelling: the queue is observed across the teardown alone.
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| !e.is_established()),
        "precondition: the probe's handshake has not completed"
    );
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
        "cancel must remove the probe's own unfinished session"
    );
    assert_eq!(
        nodes[0].node.pending_tun_total_packets(),
        1,
        "the probe must not touch queued user packets"
    );
    let data = nodes[0].node.api_probe_poll(id).expect("poll accepted");
    let cleanup = &data["report"]["cleanup"];
    assert_eq!(cleanup["session_created_and_torn_down"], true);
    assert_eq!(cleanup["session_left_intact"], false);

    cleanup_nodes(&mut nodes).await;
}

/// A probe whose handshake never completed removes its session, and with it
/// the clamp entry the session holds, restoring the direct peer's link seed.
/// No idle purge will come for a session that is gone, so the teardown is the
/// only event that can release it.
#[tokio::test]
async fn removing_an_unfinished_probe_session_releases_its_clamp_entry() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let node1_fips = crate::FipsAddress::from_node_addr(&node1_addr);
    let seed = nodes[0].node.path_mtu_lookup_get(&node1_fips);
    let id = start_probe(&mut nodes, 1).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| !e.is_established()),
        "precondition: the probe's handshake has not completed"
    );

    let tightened = seed.map_or(1300, |s| s - 100);
    nodes[0].node.path_mtu_lookup_insert(node1_fips, tightened);

    nodes[0]
        .node
        .api_probe_cancel(id)
        .await
        .expect("cancel accepted");
    assert!(
        nodes[0].node.get_session(&node1_addr).is_none(),
        "precondition: cancel removed the probe's unfinished session"
    );

    // Nothing else releases a held entry: the expiry pass skips it.
    nodes[0]
        .node
        .purge_expired_path_mtu(Node::now_ms() + 86_400_000);
    assert_eq!(
        nodes[0].node.path_mtu_lookup_get(&node1_fips),
        seed,
        "defect: the clamp entry the probe's unfinished session tightened (seed {seed:?}, \
         tightened {tightened}) must not outlive the session"
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
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "the established session is left to the idle timeout"
    );

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
        "exactly one job may own the session"
    );
    assert!(a.session_preexisting || b.session_preexisting);
    let reasons: Vec<_> = [first, second]
        .iter()
        .map(|id| {
            nodes[0].node.api_probe_poll(*id).expect("poll accepted")["report"]["cleanup"]
                ["left_intact_reason"]
                .clone()
        })
        .collect();
    assert!(
        reasons.contains(&serde_json::json!("idle_timeout"))
            && reasons.contains(&serde_json::json!("preexisting")),
        "one job opened the session and the other found it: {reasons:?}"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established())
    );

    cleanup_nodes(&mut nodes).await;
}

/// A value written into `path_mtu_lookup` inside a session (a path MTU
/// notification, a reactive MtuExceeded) carries no deadline: it is
/// released by the event that ends the session. The probe leaves its
/// established session to the idle timeout, so the entry stays while the
/// session does and goes with it at the idle purge, restoring the direct
/// peer's link seed.
#[tokio::test]
async fn the_clamp_entry_a_probes_session_tightened_goes_with_the_session() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();
    let node1_fips = crate::FipsAddress::from_node_addr(&node1_addr);
    let seed = nodes[0].node.path_mtu_lookup_get(&node1_fips);
    let id = start_probe(&mut nodes, 1).await;

    for _ in 0..20 {
        pump(&mut nodes).await;
        let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
        if snap.session.verdict == StageVerdict::Ok {
            break;
        }
    }
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "precondition: the probe established its session"
    );

    // The session learns a tighter path MTU than the link seed.
    let tightened = seed.map_or(1300, |s| s - 100);
    nodes[0].node.path_mtu_lookup_insert(node1_fips, tightened);

    nodes[0]
        .node
        .api_probe_cancel(id)
        .await
        .expect("cancel accepted");
    assert_eq!(
        nodes[0].node.path_mtu_lookup_get(&node1_fips),
        Some(tightened),
        "the session the probe left in place keeps the value it learned"
    );

    purge_idle_everywhere(&mut nodes);
    assert!(
        nodes[0].node.get_session(&node1_addr).is_none(),
        "precondition: the idle purge removed the probe's session"
    );

    // Nothing else releases a held entry: the expiry pass skips it.
    nodes[0]
        .node
        .purge_expired_path_mtu(Node::now_ms() + 86_400_000);
    assert_eq!(
        nodes[0].node.path_mtu_lookup_get(&node1_fips),
        seed,
        "defect: the clamp entry the probe's session tightened (seed {seed:?}, tightened \
         {tightened}) must not outlive the session"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Deliver packets, let both nodes emit their MMP reports, and advance node
/// 1's probes: `pump` for a probe started on node 1.
async fn pump_node1(nodes: &mut [TestNode]) {
    tokio::time::sleep(Duration::from_millis(10)).await;
    process_available_packets(nodes).await;
    for tn in nodes.iter_mut() {
        tn.node.check_session_mmp_reports().await;
    }
    nodes[1].node.poll_probes().await;
}

/// Node 0's probe opens a session to node 1 and finishes. Node 1, the
/// responder, still holds an established session, and there is no message
/// that would end it. Everything it then sends on that session, application
/// data and its own probe of node 0 alike, must reach node 0 rather than be
/// dropped there as belonging to an unknown session.
#[tokio::test]
async fn the_target_of_a_probe_that_opened_a_session_can_still_reach_the_prober() {
    let mut nodes = two_peered_nodes().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let id = start_probe(&mut nodes, 1).await;
    assert!(pump_until_done(&mut nodes, id, 600).await);
    let snap = nodes[0].node.probe_job(id).unwrap().probe().snapshot();
    assert!(
        !snap.session_preexisting,
        "node 0's probe opened the session"
    );
    // Let anything still in flight land before reading the state.
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.is_established() && !e.is_initiator()),
        "precondition: node 1 holds an established responder session"
    );

    let unknown_before = nodes[0].node.stats().session.unknown_session;

    nodes[1]
        .node
        .send_session_data(&node0_addr, 0, 0, b"responder speaks first")
        .await
        .expect("node 1 sends on the session it holds");
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node 1's own probe of node 0 runs over the session it holds.
    let npub0 = npub_of(&nodes, 0);
    let id1 = nodes[1]
        .node
        .api_probe_start(&npub0)
        .await
        .expect("probe admitted")["probe_id"]
        .as_u64()
        .expect("probe_id is a number");
    let mut done = false;
    for _ in 0..800 {
        pump_node1(&mut nodes).await;
        if nodes[1]
            .node
            .probe_job(id1)
            .is_none_or(|job| job.probe().is_finished())
        {
            done = true;
            break;
        }
    }
    assert!(done, "node 1's probe must finish");
    let snap1 = nodes[1].node.probe_job(id1).unwrap().probe().snapshot();

    assert_eq!(
        nodes[0].node.stats().session.unknown_session,
        unknown_before,
        "node 0 dropped node 1's frames as belonging to an unknown session"
    );
    assert!(snap1.session_preexisting);
    assert_ne!(
        snap1.rtt.reason.map(|r| r.name()),
        Some("no_report"),
        "node 1's probe of node 0 got no report: {:?}",
        snap1.rtt
    );
    let received = nodes[0]
        .node
        .get_session(&node1_addr)
        .map_or(0, |e| e.traffic_counters().1);
    assert!(received >= 1, "node 1's data frame reached node 0");

    cleanup_nodes(&mut nodes).await;
}

/// The probe loses a simultaneous-initiation tie-break: the target initiates
/// to the prober while the probe's handshake is in flight, and the target has
/// the smaller address. The prober pauses its own leg and answers the
/// target's setup; the target establishes as initiator on that answer. The
/// probe is cancelled before the target's msg3 lands. The prober must keep
/// the target's handshake, so the msg3 completes it and the target's frames
/// are not dropped as belonging to an unknown session.
#[tokio::test]
async fn the_target_can_reach_a_prober_that_lost_the_initiation_tie_break_and_was_cancelled() {
    let mut nodes = two_peered_nodes().await;
    let a0 = *nodes[0].node.node_addr();
    let a1 = *nodes[1].node.node_addr();
    let (p, t) = if crate::proto::fsp::initiation_winner(&a0, &a1) {
        (1, 0)
    } else {
        (0, 1)
    };
    let p_addr = *nodes[p].node.node_addr();
    let t_addr = *nodes[t].node.node_addr();
    let p_pub = nodes[p].node.identity().pubkey_full();
    let npub_t = npub_of(&nodes, t);
    let id = nodes[p]
        .node
        .api_probe_start(&npub_t)
        .await
        .expect("probe admitted")["probe_id"]
        .as_u64()
        .expect("probe_id is a number");
    assert!(
        nodes[p]
            .node
            .get_session(&t_addr)
            .is_some_and(|e| e.has_initiator_leg()),
        "the probe opened its session at admission"
    );
    nodes[t]
        .node
        .initiate_session(p_addr, p_pub)
        .await
        .expect("the target initiates");
    // Both setups land; the prober loses and answers the target's.
    process_available_packets(&mut nodes).await;
    // The target takes the answer, establishes and sends its msg3.
    process_available_packets(&mut nodes).await;
    assert!(
        nodes[t]
            .node
            .get_session(&p_addr)
            .is_some_and(|e| e.is_established())
            && nodes[p]
                .node
                .get_session(&t_addr)
                .is_some_and(|e| !e.is_established() && e.has_candidates()),
        "precondition: the target is established and the prober holds its candidate"
    );

    nodes[p].node.api_probe_cancel(id).await.expect("cancel");
    let cleanup = nodes[p].node.api_probe_poll(id).expect("poll")["report"]["cleanup"].clone();

    let unknown_before = nodes[p].node.stats().session.unknown_session;
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }
    nodes[t]
        .node
        .send_session_data(&p_addr, 0, 0, b"target speaks")
        .await
        .expect("the target sends on the session it holds");
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }

    assert_eq!(
        nodes[p].node.stats().session.unknown_session,
        unknown_before,
        "the prober dropped the target's frames as belonging to an unknown session"
    );
    let entry = nodes[p].node.get_session(&t_addr);
    assert!(
        entry.is_some_and(|e| e.is_established() && !e.is_initiator()),
        "the target's msg3 completed the prober's end as responder"
    );
    assert!(
        entry.map_or(0, |e| e.traffic_counters().1) >= 1,
        "the target's data frame reached the prober"
    );
    assert_eq!(cleanup["session_created_and_torn_down"], false);
    assert_eq!(cleanup["left_intact_reason"], "replaced");

    cleanup_nodes(&mut nodes).await;
}

/// A second probe of the same target, run while the first probe's session
/// is still up, reuses it: the session stage finds it already established
/// and the second probe leaves it as it found it.
#[tokio::test]
async fn a_second_probe_within_the_idle_timeout_finds_the_session_the_first_left() {
    let mut nodes = two_peered_nodes().await;
    let node1_addr = *nodes[1].node.node_addr();

    let first = start_probe(&mut nodes, 1).await;
    assert!(pump_until_done(&mut nodes, first, 600).await);
    let first_snap = nodes[0].node.probe_job(first).unwrap().probe().snapshot();
    assert!(
        !first_snap.session_preexisting,
        "the first probe opened the session"
    );

    let second = start_probe(&mut nodes, 1).await;
    assert!(pump_until_done(&mut nodes, second, 600).await);
    let snap = nodes[0].node.probe_job(second).unwrap().probe().snapshot();
    assert!(
        snap.session_preexisting,
        "the second probe found the first probe's session up"
    );
    assert_ne!(
        snap.rtt.reason.map(|r| r.name()),
        Some("no_report"),
        "the second probe got reports over the session the first left: {:?}",
        snap.rtt
    );
    let cleanup = nodes[0].node.api_probe_poll(second).expect("poll")["report"]["cleanup"].clone();
    assert_eq!(cleanup["left_intact_reason"], "preexisting");
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "the session is still up after the second probe"
    );

    cleanup_nodes(&mut nodes).await;
}
