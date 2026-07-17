use super::*;
use crate::ReceivedPacket;
use crate::node::acl::PeerAclReloader;
use crate::node::reloadable::HostMapReloadable;
use crate::proto::fmp::wire::{build_msg1, build_msg2};
use crate::upper::hosts::HostMap;
use crate::utils::index::SessionIndex;
use std::path::PathBuf;
use std::time::Duration;

fn make_acl_node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::new(Config::new()).unwrap();
    node.peer_acl = PeerAclReloader::with_paths(
        dir.path().join("peers.allow"),
        dir.path().join("peers.deny"),
    );
    (dir, node)
}

fn allow_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("peers.allow")
}

fn deny_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("peers.deny")
}

#[tokio::test]
async fn test_outbound_connect_denied_by_denylist() {
    let (dir, mut node) = make_acl_node();
    let denied = Identity::generate();
    std::fs::write(deny_path(&dir), format!("{}\n", denied.npub())).unwrap();
    node.reload_peer_acl().await;

    let result = node
        .initiate_connection(
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:9000"),
            PeerIdentity::from_pubkey_full(denied.pubkey_full()),
        )
        .await;

    assert!(matches!(result, Err(NodeError::AccessDenied(_))));
    assert_eq!(node.link_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 0);
}

#[tokio::test]
async fn test_inbound_msg1_denied_by_acl() {
    let (dir, mut node_b) = make_acl_node();
    let node_a = make_node();

    std::fs::write(deny_path(&dir), format!("{}\n", node_a.npub())).unwrap();
    node_b.reload_peer_acl().await;

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let mut conn_a = PeerConnection::outbound(LinkId::new(1), peer_b_identity, 1000);
    let noise_msg1 = conn_a
        .start_handshake(node_a.identity().keypair(), node_a.startup_epoch(), 1000)
        .unwrap();
    let wire_msg1 = build_msg1(SessionIndex::new(7), &noise_msg1);
    let packet = ReceivedPacket::with_timestamp(
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:5000"),
        wire_msg1,
        1000,
    );

    node_b.handle_msg1(packet).await;

    assert_eq!(node_b.peer_count(), 0);
    assert_eq!(node_b.connection_count(), 0);
    assert_eq!(node_b.link_count(), 0);
}

#[tokio::test]
async fn test_outbound_msg2_denied_after_acl_reload() {
    let (dir, mut node_a) = make_acl_node();
    let node_b = make_node();
    let transport_id = TransportId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5001");
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());

    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a, peer_b_identity, 1000);
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let noise_msg1 = conn_a
        .start_handshake(node_a.identity().keypair(), node_a.startup_epoch(), 1000)
        .unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id);
    conn_a.set_source_addr(remote_addr.clone());

    let link_a = Link::connectionless(
        link_id_a,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a
        .addr_to_link
        .insert((transport_id, remote_addr.clone()), link_id_a);
    node_a.add_connection(conn_a).unwrap();
    node_a
        .pending_outbound
        .insert((transport_id, our_index_a.as_u32()), link_id_a);

    let mut conn_b = PeerConnection::inbound(LinkId::new(2), 1000);
    let responder_epoch = [0x11; 8];
    let noise_msg2 = conn_b
        .receive_handshake_init(
            node_b.identity().keypair(),
            responder_epoch,
            &noise_msg1,
            1000,
        )
        .unwrap();
    let our_index_b = SessionIndex::new(9);
    let wire_msg2 = build_msg2(our_index_b, our_index_a, &noise_msg2);

    std::fs::write(deny_path(&dir), format!("{}\n", node_b.npub())).unwrap();
    assert!(node_a.reload_peer_acl().await);

    let packet = ReceivedPacket::with_timestamp(transport_id, remote_addr, wire_msg2, 1100);
    node_a.handle_msg2(packet).await;

    assert_eq!(node_a.peer_count(), 0);
    assert_eq!(node_a.connection_count(), 0);
    assert_eq!(node_a.link_count(), 0);
    assert!(node_a.pending_outbound.is_empty());
}

#[tokio::test]
async fn test_host_map_hot_reloads_from_tick() {
    let dir = tempfile::tempdir().unwrap();
    let hosts_path = dir.path().join("hosts");

    let mut node = Node::new(Config::new()).unwrap();
    node.host_map = HostMapReloadable::new(HostMap::new(), hosts_path.clone());

    let peer = Identity::generate();
    let peer_addr = *PeerIdentity::from_pubkey_full(peer.pubkey_full()).node_addr();

    // No hosts file yet: the display name is not the alias.
    assert_ne!(node.peer_display_name(&peer_addr), "gateway");
    assert!(!node.reload_host_map().await);

    // Write a hosts entry and let the tick-driven reload pick it up.
    std::thread::sleep(Duration::from_millis(50));
    std::fs::write(&hosts_path, format!("gateway   {}\n", peer.npub())).unwrap();

    assert!(node.reload_host_map().await);
    assert_eq!(node.peer_display_name(&peer_addr), "gateway");

    // No further change: reload reports nothing replaced.
    assert!(!node.reload_host_map().await);
}

#[tokio::test]
async fn test_outbound_connect_not_denied_by_allowlist_miss() {
    let (dir, mut node) = make_acl_node();
    let denied = Identity::generate();
    let allowed = Identity::generate();
    std::fs::write(allow_path(&dir), format!("{}\n", allowed.npub())).unwrap();
    node.reload_peer_acl().await;

    let result = node
        .initiate_connection(
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:9000"),
            PeerIdentity::from_pubkey_full(denied.pubkey_full()),
        )
        .await;

    assert!(!matches!(result, Err(NodeError::AccessDenied(_))));
}
