//! FilterAnnounce sends the link refuses as too large.
//!
//! A v1 FilterAnnounce is a 1,071-byte frame on the link. A link whose MTU is
//! below that refuses every one, and FRC-1402 has the peering come up without
//! filters and the send retried each tick. The operator must still be told,
//! once per peering at warning level, that the peer will not hold this node's
//! filter. The loopback transport the test nodes use enforces its MTU on send
//! as UDP does, and the nodes spawn no encrypt workers, so every send takes
//! the inline path that reports the refusal.

use super::spanning_tree::*;
use super::*;

/// Below the 1,071-byte FilterAnnounce frame, above the handshake and
/// TreeAnnounce frames.
const SMALL_MTU: u16 = 1000;

/// The warnings in `lines` that report a refused FilterAnnounce.
fn refusal_warnings(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|l| l.contains("FilterAnnounce") && l.contains("mtu=1000"))
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_filter_announce_the_link_refuses_as_too_large_is_warned_once_per_peering() {
    // Building the fixture already makes the first refused sends: promotion
    // marks the new peer for a filter update, and convergence flushes the
    // pending announces on every node in each cycle. Capture from the start.
    let (logs, guard) = crate::testutil::capture_logs_scoped();
    let mut nodes = run_tree_test_with_mtus(&[SMALL_MTU, SMALL_MTU], &[(0, 1)]).await;

    for tn in &nodes {
        assert!(
            tn.node.metrics().bloom.send_failed.get() > 0,
            "setup: the link must have refused a FilterAnnounce while the tree converged"
        );
    }

    let warned = refusal_warnings(&logs.warnings());
    assert_eq!(
        warned.len(),
        2,
        "each node must warn once that its peer refused the FilterAnnounce: {warned:?}"
    );
    for (i, j) in [(0, 1), (1, 0)] {
        let peer = nodes[i].node.peer_display_name(nodes[j].node.node_addr());
        assert_eq!(
            warned
                .iter()
                .filter(|l| l.contains(&peer) && l.contains("packet_size=1071"))
                .count(),
            1,
            "one warning naming peer {peer} and the frame size: {warned:?}"
        );
    }

    // The retry continues each tick, and the warning does not repeat.
    let failed_before = nodes[0].node.metrics().bloom.send_failed.get();
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(550)).await;
        nodes[0].node.send_pending_filter_announces().await;
    }
    assert_eq!(
        nodes[0].node.metrics().bloom.send_failed.get(),
        failed_before + 3,
        "the refused announce must still be retried each tick"
    );
    assert_eq!(
        refusal_warnings(&logs.warnings()).len(),
        2,
        "a refused announce must be warned once per peering, not per retry"
    );

    drop(guard);
    cleanup_nodes(&mut nodes).await;
}
