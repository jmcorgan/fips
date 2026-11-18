//! Tests for the consecutive-decrypt-failure threshold.
//!
//! Covers `Node::charge_failure` (in `node/dataplane/encrypted.rs`), which
//! counts each AEAD verification failure on the link's path it arrived on
//! and logs one warning when that path's count reaches
//! `DECRYPT_FAILURE_THRESHOLD`. The peer is kept: a frame that does not
//! authenticate names its peer only by a receiver index sent in clear, so
//! anyone who has seen the index can produce the failures. The warning is
//! what the integration harnesses grep for, so its once-per-run shape is
//! part of the contract.
//!
//! Also covers the drops `handle_encrypted_frame` makes before a frame is
//! authenticated: a frame naming an unknown index, one naming an index left
//! pointing at a removed peer, and one refused by its decrypt worker's full
//! queue. They reach no peer's failure count, so the dataplane counters
//! `show_metrics` serves are their only record.

use super::*;

/// Threshold constant in node/dataplane/encrypted.rs (kept in sync with
/// production code; see DECRYPT_FAILURE_THRESHOLD).
const THRESHOLD: u32 = 20;

/// The prefix of the warning logged when the counter reaches the threshold.
const WARNING: &str = "Excessive decryption failures";

/// Warnings captured so far that carry the threshold message.
fn threshold_warnings(logs: &crate::testutil::LogCapture) -> usize {
    logs.warnings()
        .iter()
        .filter(|line| line.contains(WARNING))
        .count()
}

/// Assert the peer and its index entry are still held, and return its
/// consecutive failure count.
fn held_count(node: &Node, node_addr: &NodeAddr, key: &u32, when: &str) -> u32 {
    let count = node
        .get_peer(node_addr)
        .unwrap_or_else(|| panic!("peer present {when}"))
        .consecutive_decrypt_failures();
    assert_eq!(
        node.peers_by_index.get(key),
        Some(node_addr),
        "peers_by_index still maps the index to the peer {when}"
    );
    count
}

/// Drive a fully-promoted peer to twice the decrypt-failure threshold and
/// verify one warning is logged at the threshold and the peer is kept in both
/// `peers` and `peers_by_index`. A later run of failures, after a reset, warns
/// again.
#[test]
fn reaching_the_decrypt_failure_threshold_logs_one_warning_and_keeps_the_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Build a fully-promoted active peer with our_index/transport_id set
    // so peers_by_index is populated by promote_connection.
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();
    // The original pair `seed_completed_connection` gives the link.
    let addr = TransportAddr::from_string("127.0.0.1:5000");

    node.promote_connection(link_id, identity, 2_000).unwrap();

    assert_eq!(node.peer_count(), 1, "peer should be present after promote");
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("promoted peer must have our_index");
    let key = our_index.as_u32();
    assert_eq!(
        held_count(&node, &node_addr, &key, "after promote"),
        0,
        "fresh peer's failure counter must start at zero"
    );

    let (logs, guard) = crate::testutil::capture_logs_scoped();

    for expected in 1..THRESHOLD {
        node.charge_failure(&node_addr, transport_id, &addr);
        assert_eq!(
            held_count(&node, &node_addr, &key, "below the threshold"),
            expected,
            "counter should track failures below the threshold"
        );
    }
    assert_eq!(
        threshold_warnings(&logs),
        0,
        "no threshold warning before the threshold-th failure"
    );

    node.charge_failure(&node_addr, transport_id, &addr);
    assert_eq!(
        held_count(&node, &node_addr, &key, "at the threshold"),
        THRESHOLD
    );
    assert_eq!(
        threshold_warnings(&logs),
        1,
        "one threshold warning at the threshold-th failure"
    );

    for expected in THRESHOLD + 1..=2 * THRESHOLD {
        node.charge_failure(&node_addr, transport_id, &addr);
        assert_eq!(
            held_count(&node, &node_addr, &key, "past the threshold"),
            expected,
            "counter keeps counting past the threshold"
        );
    }
    assert_eq!(
        threshold_warnings(&logs),
        1,
        "failures past the threshold do not warn again"
    );
    assert_eq!(node.peer_count(), 1, "the peer is kept");

    // An authenticated frame resets the counter; a later run warns again.
    node.get_peer_mut(&node_addr)
        .unwrap()
        .authentic(transport_id, &addr);
    for _ in 0..THRESHOLD {
        node.charge_failure(&node_addr, transport_id, &addr);
    }
    assert_eq!(
        held_count(&node, &node_addr, &key, "after a second run"),
        THRESHOLD
    );
    assert_eq!(
        threshold_warnings(&logs),
        2,
        "a second run of failures warns once more"
    );
    drop(guard);
}

/// The dataplane counters as `show_metrics` serves them:
/// `(unknown_index, orphaned_index)`.
fn dataplane_drops(node: &Node) -> (Option<u64>, Option<u64>) {
    let metrics = crate::control::queries::show_metrics_from_handle(&node.control_read_handle());
    let family = &metrics["dataplane"];
    (
        family["unknown_index"].as_u64(),
        family["orphaned_index"].as_u64(),
    )
}

/// An encrypted frame of a valid length naming `receiver_idx`, whose
/// ciphertext no session will authenticate.
fn frame_naming(transport_id: TransportId, receiver_idx: u32) -> ReceivedPacket {
    use crate::proto::fmp::wire::{build_encrypted, build_established_header};

    let tag = [0u8; 16];
    let header = build_established_header(SessionIndex::new(receiver_idx), 0, 0, tag.len() as u16);
    ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string("192.0.2.9:2121"),
        build_encrypted(&header, &tag),
    )
}

/// A frame naming an index this node never allocated, and one naming an index
/// whose entry still points at a peer no longer held, are each counted once in
/// the dataplane family `show_metrics` serves. Neither reaches the held peer:
/// its decrypt-failure count, its index entry and the peer table are
/// unchanged, and the orphaned entry is removed as before.
#[tokio::test]
async fn frames_naming_unknown_or_orphaned_indices_are_counted_and_served_and_touch_no_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();
    node.promote_connection(link_id, identity, 2_000).unwrap();
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("promoted peer must have our_index");
    let key = our_index.as_u32();
    assert_eq!(dataplane_drops(&node), (Some(0), Some(0)));

    let unknown = our_index.as_u32().wrapping_add(1);
    assert!(!node.peers_by_index.contains_key(&unknown));
    node.handle_encrypted_frame(frame_naming(transport_id, unknown))
        .await;
    assert_eq!(
        dataplane_drops(&node),
        (Some(1), Some(0)),
        "a frame naming an unallocated index must be counted as unknown"
    );

    let orphaned = our_index.as_u32().wrapping_add(2);
    let gone = NodeAddr::from_bytes([0x77; 16]);
    node.peers_by_index.raw().insert(orphaned, gone);
    node.handle_encrypted_frame(frame_naming(transport_id, orphaned))
        .await;
    assert_eq!(
        dataplane_drops(&node),
        (Some(1), Some(1)),
        "a frame naming an index left on a removed peer must be counted as orphaned"
    );
    assert!(
        !node.peers_by_index.contains_key(&orphaned),
        "the orphaned entry is removed with the drop"
    );

    assert_eq!(
        held_count(&node, &node_addr, &key, "after both drops"),
        0,
        "a frame dropped before its peer is resolved must not count as that peer's failure"
    );
    assert_eq!(node.peer_count(), 1, "the peer table is unchanged");
}

/// The dataplane family's `decrypt_queue_full` counter as `show_metrics`
/// serves it.
#[cfg(unix)]
fn decrypt_queue_full(node: &Node) -> Option<u64> {
    let metrics = crate::control::queries::show_metrics_from_handle(&node.control_read_handle());
    metrics["dataplane"]["decrypt_queue_full"].as_u64()
}

/// A decrypt worker that has not started holds what it is sent, so its queue
/// fills: the registration takes one slot and the frames the rest. Each frame
/// past that is dropped at dispatch and counted once in the dataplane family
/// `show_metrics` serves, and a frame that was queued is not counted.
#[cfg(unix)]
#[tokio::test]
async fn a_job_dropped_at_a_full_decrypt_channel_is_counted_in_dataplane_metrics() {
    use super::connected_udp::{PROMOTED_ADDR, promoted_peer_with_the_far_side_session};
    use crate::node::decrypt_worker::{DecryptWorkerPool, HeldRelease, WORKER_CHANNEL_CAP};

    const OVER: usize = 3;
    let tid = TransportId::new(1);
    let (mut node, peer, index, _far_side) = promoted_peer_with_the_far_side_session(tid);
    let (start, held) = std::sync::mpsc::channel();
    node.supervisor.decrypt_workers = Some(DecryptWorkerPool::held(held));
    let release = HeldRelease::arm(start.clone());
    let offer = node.get_peer(&peer).unwrap().offer_to_workers();
    node.run_link_outputs(&peer, offer);
    assert!(
        node.decrypt_registered_sessions.contains(&index.as_u32()),
        "precondition: the session is registered with the worker"
    );
    assert_eq!(decrypt_queue_full(&node), Some(0));

    let from = TransportAddr::from_string(PROMOTED_ADDR);
    let frame = frame_naming(tid, index.as_u32()).data;
    for _ in 0..WORKER_CHANNEL_CAP - 1 {
        node.handle_encrypted_frame(ReceivedPacket::new(tid, from.clone(), frame.clone()))
            .await;
    }
    assert_eq!(
        decrypt_queue_full(&node),
        Some(0),
        "a frame the worker's queue took must not be counted as dropped"
    );
    for _ in 0..OVER {
        node.handle_encrypted_frame(ReceivedPacket::new(tid, from.clone(), frame.clone()))
            .await;
    }
    assert!(
        !release.disarm(),
        "dispatch waited on the held worker's full queue until it was released"
    );
    assert_eq!(
        decrypt_queue_full(&node),
        Some(OVER as u64),
        "each frame refused by the full queue must be counted once"
    );
}
