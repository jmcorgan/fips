//! Index-only demux: the first step of the multi-path switchover design
//! (`docs/design/fips-multi-path-switchover.md`, §3).
//!
//! A session index is unique across transports, so a frame carrying a known
//! `receiver_idx` decrypts no matter which transport delivered it. That opens
//! cross-transport delivery, and two rules keep it closed to a relay:
//!
//! 1. an authentic frame from another transport is delivered but does not
//!    move the peer (`ActivePeer::set_current_addr` freezes the transport);
//! 2. a decrypt failure on a transport the peer is not on is not counted
//!    toward the force-removal threshold.

use super::connected_udp::{
    PROMOTED_ADDR, far_side_frame, promoted_peer_with_the_far_side_session,
};
use super::*;
use crate::proto::fmp::wire::{build_encrypted, build_established_header};

/// Where a frame "from the wifi" claims to come from.
const OTHER_ADDR: &str = "10.0.0.7:2121";

/// Threshold constant in node/dataplane/encrypted.rs.
const THRESHOLD: u32 = 20;

/// A well-formed established header over random bytes that no session will
/// authenticate.
fn garbage_frame(receiver_idx: SessionIndex, counter: u64) -> Vec<u8> {
    let junk = [0xA5u8; 48];
    let header = build_established_header(receiver_idx, counter, 0, junk.len() as u16);
    build_encrypted(&header, &junk)
}

#[tokio::test]
async fn an_authentic_frame_on_another_transport_is_delivered_but_does_not_move_the_peer() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);

    // One prior failure, so a successful decrypt is observable as the reset.
    node.handle_decrypt_failure(&node_addr);
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        1
    );

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
        peer.consecutive_decrypt_failures(),
        0,
        "the frame must have been found by index and authenticated"
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
            garbage_frame(our_index, counter),
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
            garbage_frame(our_index, counter),
        ))
        .await;
    }

    assert!(
        node.get_peer(&node_addr).is_none(),
        "the threshold still applies on the transport the peer is on"
    );
    assert!(
        !node.peers_by_index.contains_key(&our_index.as_u32()),
        "and the index entry goes with it"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_worker_failure_report_is_charged_only_on_the_bound_transport() {
    use crate::node::decrypt_worker::DecryptFailureReport;

    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, _our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    node.process_decrypt_failure_report(DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id: wifi,
        fmp_counter: 7,
        fmp_replay_highest: 0,
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

#[test]
fn set_current_addr_roams_inside_the_bound_transport_only() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);

    // Unbound: the first sighting binds.
    assert!(peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:1")));
    assert_eq!(peer.transport_id(), Some(cable));

    // Same transport, new address: a roam.
    assert!(peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // Same transport, same address: nothing changed.
    assert!(!peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")));

    // Another transport: refused, nothing moved.
    assert!(!peer.set_current_addr(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // The deliberate rebind crosses.
    assert!(peer.rebind_transport(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.transport_id(), Some(wifi));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.7:1"))
    );
}

#[test]
fn a_promoted_peer_holds_one_path_and_rebind_repoints_it() {
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

    // Until the probe exchange adds paths, a rebind re-points the single
    // path rather than growing the set.
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    assert!(peer.paths().is_empty());
    assert!(peer.rebind_transport(cable, TransportAddr::from_string("10.0.0.1:1")));
    assert!(peer.rebind_transport(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.paths().len(), 1);
    assert_eq!(peer.transport_id(), Some(wifi));
}

// ============================================================================
// UDP `interface:` binding
// ============================================================================

#[test]
fn udp_interface_config_parses() {
    let cfg: crate::config::UdpConfig = serde_yaml::from_str("interface: en0\n").unwrap();
    assert_eq!(cfg.interface.as_deref(), Some("en0"));
    let cfg: crate::config::UdpConfig = serde_yaml::from_str("bind_addr: 0.0.0.0:1\n").unwrap();
    assert!(cfg.interface.is_none());
}

#[test]
fn binding_udp_to_a_missing_interface_fails_to_start() {
    use crate::transport::udp::io::UdpRawSocket;
    let err = UdpRawSocket::open_on_interface(
        "127.0.0.1:0".parse().unwrap(),
        65_536,
        65_536,
        Some("fips-absent-x0"),
    )
    .err()
    .expect("an absent interface cannot be bound");
    assert!(err.to_string().contains("fips-absent-x0"), "{err}");
}
