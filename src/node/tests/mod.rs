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
mod mmp_chartests;
mod routing;
mod session;
mod spanning_tree;
mod tcp;
mod unit;

pub(super) fn make_node() -> Node {
    make_node_with(Config::new())
}

/// A test node that reaches `Full` health on `start()`.
///
/// A default [`make_node`] configures no transports, so its `start()` now
/// resolves to `NodeState::Failed` (zero transports up) and
/// returns `NoOperationalTransports`. Lifecycle-state tests that need a running
/// node build one with a single loopback UDP transport (ephemeral port) as the
/// sole configured child — DNS disabled — so bring-up has exactly one
/// configured child and it comes up (`Full`). Mirrors the udp config in
/// `test_node_start_does_not_wait_for_nostr_relay_startup`.
pub(super) fn make_healthy_node() -> Node {
    let mut config = Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = false;
    make_node_with(config)
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

/// Seed a control machine whose leg carries a completed Noise IK handshake.
///
/// Returns the peer identity. The leg is outbound, in Complete state, with
/// session, indices, and transport info set, and is installed on the node
/// through [`Node::seed_handshake_machine`] — the test-surface twin of
/// `Node::add_connection`.
pub(super) fn seed_completed_connection(
    node: &mut Node,
    link_id: LinkId,
    transport_id: TransportId,
    current_time_ms: u64,
) -> PeerIdentity {
    let our_index = node.index_allocator.allocate().unwrap();
    seed_completed_connection_with(node, link_id, current_time_ms, |seed| {
        seed.with_our_index(our_index)
            .with_their_index(SessionIndex::new(42))
            .with_transport_id(transport_id)
            .with_source_addr(TransportAddr::from_string("127.0.0.1:5000"))
    })
}

/// [`seed_completed_connection`] with the seed left to the caller, for tests
/// that need a leg deliberately missing one of the fields promotion requires.
///
/// The Noise exchange runs on the already-seeded leg, where it used to run
/// before the leg was handed over. That reordering is neutral, but not
/// because the handshake leaves the seeded fields alone —
/// `receive_handshake_init` does write `expected_identity`. It is neutral
/// because the only read of `expected_identity` is guarded by `is_outbound`:
/// an inbound leg takes the `new_inbound` arm whether or not the identity has
/// been learned, and an outbound leg never runs that method. The remaining
/// reads (`link_id`, `started_at`, `is_outbound`, `their_index`,
/// `transport_id`) are genuinely untouched by the handshake.
pub(super) fn seed_completed_connection_with(
    node: &mut Node,
    link_id: LinkId,
    current_time_ms: u64,
    shape: impl FnOnce(HandshakeSeed) -> HandshakeSeed,
) -> PeerIdentity {
    let peer_identity_full = Identity::generate();
    // Must use from_pubkey_full to preserve parity for ECDH
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());

    node.seed_handshake_machine(shape(HandshakeSeed::outbound(
        link_id,
        peer_identity,
        current_time_ms,
    )))
    .unwrap();

    // Run initiator side of handshake
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let msg1 = node
        .get_connection_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, current_time_ms)
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
    node.get_connection_mut(&link_id)
        .unwrap()
        .complete_handshake(&msg2, current_time_ms)
        .unwrap();

    peer_identity
}
