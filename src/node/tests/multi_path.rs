//! Index-only demux: the first step of multi-path switchover, where one
//! link can be carried over several transports.
//!
//! A session index is unique across transports, so a frame carrying a known
//! `receiver_idx` decrypts no matter which transport delivered it. That opens
//! cross-transport delivery, and two rules keep it closed to a relay:
//!
//! 1. an authentic frame from another transport is delivered but does not
//!    move the peer (`ActivePeer::set_current_addr` freezes the transport);
//! 2. a decrypt failure from a pair that is no path of the link, on another
//!    transport or at another address, is not counted toward the warning's
//!    threshold.

use super::connected_udp::{
    PROMOTED_ADDR, far_side_frame, promoted_peer_with_the_far_side_session,
};
use super::decrypt_forged::forged_frame;
use super::*;
use crate::node::dataplane::DECRYPT_FAILURE_THRESHOLD as THRESHOLD;
use crate::peer::Roam;

/// Where a frame "from the wifi" claims to come from.
const OTHER_ADDR: &str = "10.0.0.7:2121";

#[tokio::test]
async fn an_authentic_frame_on_another_transport_is_delivered_but_does_not_move_the_peer() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);

    // One prior failure on the original pair. The frame below arrives on
    // no path of the link, so it starts no path's count again.
    let promoted = TransportAddr::from_string(PROMOTED_ADDR);
    node.charge_failure(&node_addr, cable, &promoted);
    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.consecutive_decrypt_failures(), 1);
    let received = peer.link_stats().packets_recv;

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        wifi,
        TransportAddr::from_string(OTHER_ADDR),
        frame,
    ))
    .await;

    let peer = node
        .get_peer(&node_addr)
        .expect("an authentic frame never removes a peer");
    assert_eq!(
        peer.link_stats().packets_recv,
        received + 1,
        "the frame must have been found by index and authenticated"
    );
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        1,
        "a frame on no path of the link starts no path's count again"
    );
    assert_eq!(
        peer.transport_id(),
        Some(cable),
        "an authentic frame on another transport must not move the peer's send side"
    );
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(PROMOTED_ADDR)),
        "nor its address"
    );
}

#[tokio::test]
async fn an_authentic_frame_on_the_bound_transport_still_roams_the_address() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        cable,
        TransportAddr::from_string(OTHER_ADDR),
        frame,
    ))
    .await;

    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(OTHER_ADDR)),
        "roaming inside the bound transport is unchanged"
    );
}

#[tokio::test]
async fn garbage_from_a_transport_the_peer_is_not_on_is_not_counted() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    for counter in 0..(THRESHOLD * 2) as u64 {
        node.handle_encrypted_frame(ReceivedPacket::new(
            wifi,
            TransportAddr::from_string(OTHER_ADDR),
            forged_frame(our_index, counter),
        ))
        .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("garbage from a transport the peer is not on must not tear it down");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "off-path failures are dropped, not counted"
    );
}

#[tokio::test]
async fn garbage_on_the_bound_transport_still_counts() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    for counter in 0..THRESHOLD as u64 {
        node.handle_encrypted_frame(ReceivedPacket::new(
            cable,
            TransportAddr::from_string(PROMOTED_ADDR),
            forged_frame(our_index, counter),
        ))
        .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("a peer is kept through decryption failures");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        THRESHOLD,
        "failures on the transport the peer is on are counted"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_worker_failure_report_is_charged_only_on_the_bound_transport() {
    use crate::node::decrypt_worker::DecryptFailureReport;

    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    node.process_decrypt_failure_report(DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id: wifi,
        fmp_counter: 7,
        fmp_replay_highest: 0,
        receiver_idx: our_index.as_u32(),
        remote_addr: TransportAddr::from_string(OTHER_ADDR),
        fmp_flags: 0,
    })
    .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "a worker report from a transport the peer is not on is not counted"
    );

    node.process_decrypt_failure_report(DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id: cable,
        fmp_counter: 8,
        fmp_replay_highest: 0,
        receiver_idx: our_index.as_u32(),
        remote_addr: TransportAddr::from_string(PROMOTED_ADDR),
        fmp_flags: 0,
    })
    .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        1,
        "one from the bound transport is"
    );
}

/// Past the warning threshold the worker report takes an early return; that
/// return keeps the same attribution rule as the logged path below it.
#[cfg(unix)]
#[tokio::test]
async fn a_worker_failure_report_past_the_threshold_on_another_transport_is_not_counted() {
    use crate::node::decrypt_worker::DecryptFailureReport;

    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);
    let count = |node: &Node| {
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures()
    };
    let report = |transport_id, fmp_counter, addr: &str| DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id,
        fmp_counter,
        fmp_replay_highest: 0,
        receiver_idx: our_index.as_u32(),
        remote_addr: TransportAddr::from_string(addr),
        fmp_flags: 0,
    };

    let promoted = TransportAddr::from_string(PROMOTED_ADDR);
    for _ in 0..THRESHOLD {
        node.charge_failure(&node_addr, cable, &promoted);
    }
    assert_eq!(count(&node), THRESHOLD, "the run has reached the threshold");

    node.process_decrypt_failure_report(report(wifi, 100, OTHER_ADDR))
        .await;
    assert_eq!(
        count(&node),
        THRESHOLD,
        "past the threshold, a worker report from a transport the peer is not on is not counted"
    );

    node.process_decrypt_failure_report(report(cable, 101, PROMOTED_ADDR))
        .await;
    assert_eq!(
        count(&node),
        THRESHOLD + 1,
        "past the threshold, one from the bound transport still is"
    );
}

#[test]
fn set_current_addr_roams_inside_the_bound_transport_only() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);

    // Unbound: the first sighting binds.
    assert_eq!(
        peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:1")),
        Roam::Bound
    );
    assert_eq!(peer.transport_id(), Some(cable));

    // Same transport, new address: a roam off the first address.
    assert_eq!(
        peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")),
        Roam::Roamed {
            from: (cable, TransportAddr::from_string("10.0.0.1:1"))
        }
    );
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // Same transport, same address: nothing changed.
    assert_eq!(
        peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")),
        Roam::Unmoved
    );

    // Another transport: refused, nothing moved.
    assert_eq!(
        peer.set_current_addr(wifi, TransportAddr::from_string("10.0.0.7:1")),
        Roam::Unmoved
    );
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // A deliberate rebind onto a pair the peer does not hold admits it as a
    // new path to be probed, and moves nothing yet.
    let wifi_addr = TransportAddr::from_string("10.0.0.7:1");
    assert_eq!(
        peer.rebind_transport(wifi, wifi_addr.clone(), crate::peer::Medium::Other),
        crate::peer::Rebind::Refused
    );
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );
    assert_eq!(
        peer.path_set()
            .find(wifi, &wifi_addr)
            .map(|i| peer.paths()[i].state()),
        Some(crate::peer::PathState::Probing)
    );

    // Held but not yet acked, the pair still does not carry the link.
    assert_eq!(
        peer.rebind_transport(wifi, wifi_addr.clone(), crate::peer::Medium::Other),
        crate::peer::Rebind::Refused
    );
    assert_eq!(peer.transport_id(), Some(cable));

    // Once one of our probes on it is answered, a rebind onto it crosses.
    peer.ack_path(wifi, &wifi_addr);
    assert_eq!(
        peer.rebind_transport(wifi, wifi_addr.clone(), crate::peer::Medium::Other),
        crate::peer::Rebind::Switched
    );
    assert_eq!(peer.transport_id(), Some(wifi));
    assert_eq!(peer.current_addr(), Some(&wifi_addr));
}

#[test]
fn a_promoted_peer_holds_one_path_and_a_rebind_admits_another_without_moving() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (node, node_addr, _our_index, _far_side) = promoted_peer_with_the_far_side_session(cable);
    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.paths().len(), 1, "promotion binds exactly one path");
    assert_eq!(peer.active_path().map(|p| p.transport_id()), Some(cable));
    assert_eq!(
        peer.active_path().map(|p| p.addr()),
        Some(&TransportAddr::from_string(PROMOTED_ADDR))
    );

    // A rebind never re-points a path: the first binds the original path,
    // and one onto a new pair adds a path beside it without moving the send
    // side.
    use crate::peer::Rebind;
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    assert!(peer.paths().is_empty());
    let cable_addr = TransportAddr::from_string("10.0.0.1:1");
    assert_eq!(
        peer.rebind_transport(cable, cable_addr.clone(), crate::peer::Medium::Other),
        Rebind::Switched
    );
    let original = peer.active_path().unwrap().path_id();
    assert_eq!(
        peer.rebind_transport(
            wifi,
            TransportAddr::from_string("10.0.0.7:1"),
            crate::peer::Medium::Other
        ),
        Rebind::Refused
    );
    assert_eq!(peer.paths().len(), 2);
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(peer.active_path().unwrap().path_id(), original);
    assert_eq!(
        peer.rebind_transport(cable, cable_addr, crate::peer::Medium::Other),
        Rebind::Unchanged
    );
}

/// An authentic frame on the original path, then three replays of it on the
/// same pair, decrypted inline. Section 5.3 of the multipath draft: a frame
/// the anti-replay window rejects is not an authentication failure, and
/// neither adds to nor resets a path's count, so the count stays 0.
#[tokio::test]
async fn replays_of_an_authentic_frame_on_the_inline_path_add_nothing_to_the_count() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);
    let from = TransportAddr::from_string(PROMOTED_ADDR);
    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(cable, from.clone(), frame.clone()))
        .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "precondition: the authentic frame counts nothing"
    );
    for _ in 0..3 {
        node.handle_encrypted_frame(ReceivedPacket::new(cable, from.clone(), frame.clone()))
            .await;
    }
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "replays the anti-replay window rejects were counted as authentication failures"
    );
}

/// A replay after `THRESHOLD - 1` real failures on the original path leaves
/// the count at `THRESHOLD - 1`: it neither adds to the count (which would
/// reach the limit) nor resets it (Section 5.3 of the multipath draft).
#[tokio::test]
async fn a_replay_after_failures_one_short_of_the_limit_leaves_the_count_where_it_was() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);
    let from = TransportAddr::from_string(PROMOTED_ADDR);
    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(cable, from.clone(), frame.clone()))
        .await;
    for counter in 0..u64::from(THRESHOLD - 1) {
        node.handle_encrypted_frame(ReceivedPacket::new(
            cable,
            from.clone(),
            forged_frame(our_index, 1_000 + counter),
        ))
        .await;
    }
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        THRESHOLD - 1,
        "precondition: forged frames with fresh counters count"
    );
    node.handle_encrypted_frame(ReceivedPacket::new(cable, from.clone(), frame.clone()))
        .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        THRESHOLD - 1,
        "a replay changed the path's count of authentication failures"
    );
}
