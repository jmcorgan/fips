use super::*;
use crate::PeerIdentity;
use crate::transport::{LinkDirection, ReceivedPacket, TransportAddr, packet_channel};
use crate::utils::index::SessionIndex;
use std::time::Duration;

mod acl;
#[cfg(target_os = "linux")]
mod ble;
mod bloom;
mod bloom_poison;
mod bootstrap;
mod decrypt_failure;
mod disconnect;
mod discovery;
mod establish_chartests;
#[cfg(target_os = "linux")]
mod ethernet;
mod forwarding;
mod handshake;
mod heartbeat;
mod routing;
mod session;
mod spanning_tree;
mod tcp;
mod unit;

pub(super) fn make_node() -> Node {
    make_node_with(Config::new())
}

/// Build a test node from an explicit `Config`. Immutable state lives solely in
/// the shared `NodeContext`, built once at construction — there is no
/// post-construction field to poke, so set limits/config on the `Config` here.
pub(super) fn make_node_with(config: Config) -> Node {
    Node::new(config).unwrap()
}

/// Build a test node with an explicit `max_peers` limit (replaces the removed
/// `set_max_peers` setter; resource limits are immutable post-construction).
pub(super) fn make_node_with_max_peers(max_peers: usize) -> Node {
    let mut config = Config::new();
    config.node.limits.max_peers = max_peers;
    make_node_with(config)
}

/// Build a test node with an explicit `max_links` limit (replaces the removed
/// `set_max_links` setter; resource limits are immutable post-construction).
pub(super) fn make_node_with_max_links(max_links: usize) -> Node {
    let mut config = Config::new();
    config.node.limits.max_links = max_links;
    make_node_with(config)
}

#[allow(dead_code)]
pub(super) fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

pub(super) fn make_peer_identity() -> PeerIdentity {
    let identity = Identity::generate();
    PeerIdentity::from_pubkey(identity.pubkey())
}

/// Create a PeerConnection with a completed Noise IK handshake.
///
/// Returns (connection, peer_identity) where the connection is outbound,
/// in Complete state, with session, indices, and transport info set.
pub(super) fn make_completed_connection(
    node: &mut Node,
    link_id: LinkId,
    transport_id: TransportId,
    current_time_ms: u64,
) -> (PeerConnection, PeerIdentity) {
    let peer_identity_full = Identity::generate();
    // Must use from_pubkey_full to preserve parity for ECDH
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());

    // Create outbound connection
    let mut conn = PeerConnection::outbound(link_id, peer_identity, current_time_ms);

    // Run initiator side of handshake
    let our_keypair = node.identity().keypair();
    let msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch(), current_time_ms)
        .unwrap();

    // Run responder side to generate msg2
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), current_time_ms);
    let peer_keypair = peer_identity_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, current_time_ms)
        .unwrap();

    // Complete initiator handshake
    conn.complete_handshake(&msg2, current_time_ms).unwrap();

    // Set indices and transport info
    let our_index = node.index_allocator.allocate().unwrap();
    conn.set_our_index(our_index);
    conn.set_their_index(SessionIndex::new(42));
    conn.set_transport_id(transport_id);
    conn.set_source_addr(TransportAddr::from_string("127.0.0.1:5000"));

    (conn, peer_identity)
}
