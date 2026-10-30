use super::*;
use crate::PeerIdentity;
use crate::peer::machine::HandshakeCrypto;
use crate::transport::{LinkDirection, ReceivedPacket, TransportAddr, packet_channel};
use crate::utils::index::SessionIndex;
use std::time::Duration;

mod acl;
mod app_tun;
#[cfg(ble_available)]
mod ble;
mod bloom;
mod bloom_echo;
mod bloom_hold;
mod bloom_pacing;
mod bloom_poison;
mod bloom_send;
mod bootstrap;
#[cfg(ble_available)]
mod claim_dials;
#[cfg(target_os = "linux")]
mod claim_slots;
mod connected_udp;
mod control;
mod coord_forgery;
mod decrypt_failure;
mod decrypt_forged;
mod disconnect;
mod discovery;
mod discovery_msg1_cap;
mod dns_mesh;
mod establish_chartests;
mod forged_initial_msg2;
mod forwarding;
mod handshake;
mod handshake_lines;
mod heartbeat;
mod host_link;
mod lan_label;
mod link_dead_floor;
mod link_index_audit;
mod link_session_diag;
mod link_setup_diag;
mod lookup_echo;
mod mmp_chartests;
mod netmon;
mod peer_restart;
mod probe;
mod rekey_answer;
mod rekey_attempt_ceiling;
mod rekey_clock;
mod rekey_cutover_index;
mod rekey_parity;
mod restart_dial;
mod routing;
mod rx_stall;
mod second_path_msg1;
mod session;
mod session_peer_coords;
mod silent_backoff;
mod silent_replay;
mod spanning_tree;
#[cfg(unix)]
mod status;
mod stored_msg2;
mod stored_msg2_install;
mod survivors;
mod tcp;
mod traffic_diag;
mod tree_send_failure;
#[cfg(target_os = "linux")]
mod tun_warning;
mod udp_dns;
mod unit;
mod update_peers;

/// Msg1 refusals as `bad_state` counted them before each refusal the msg1
/// classification decides was given a counter of its own: `bad_state` plus
/// those counters. A test asserting that a msg1 was refused, for whatever
/// reason, reads this.
pub(super) fn refusals(node: &Node) -> u64 {
    let h = &node.stats().handshake;
    h.bad_state + h.max_peers + h.rekey_pending + h.rekey_tiebreak + h.answered_before + h.off_link
}

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

/// Install a real `connect()`-ed UDP socket on a peer, the way the tick-driven
/// activation in `dataplane::connected_udp` does.
///
/// The socket is opened against the loopback discard port: nothing is ever sent
/// through it, and the callers only care whether the handle is still installed
/// afterwards.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn install_connected_udp(
    node: &mut Node,
    addr: &NodeAddr,
    transport_id: crate::transport::TransportId,
) {
    let local: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let peer_sa: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

    let owned = crate::transport::udp::open_connected_fd(local, peer_sa, 65_536, 65_536, None)
        .expect("open a connected UDP socket");
    let bound = crate::transport::udp::ConnectedPeerSocket::from_fd(owned, peer_sa, local);
    let socket = std::sync::Arc::new(bound);
    let (packet_tx, _packet_rx) = packet_channel(8);
    let drain = crate::transport::udp::PeerRecvDrain::spawn(
        socket.clone(),
        transport_id,
        peer_sa,
        packet_tx,
        std::sync::Arc::new(crate::transport::udp::UdpStats::new()),
    )
    .expect("spawn the peer recv drain");

    node.get_peer_mut(addr)
        .expect("peer present")
        .set_connected_udp(socket, drain);
}

/// An encrypt pool of two whose worker for `dest` has exited. Where the worker
/// for a destination is not a function of the address alone (macOS), both
/// have.
#[cfg(unix)]
pub(super) fn pool_with_dead_worker_for(
    dest: std::net::SocketAddr,
) -> crate::node::encrypt_worker::EncryptWorkerPool {
    use crate::node::encrypt_worker::EncryptWorkerPool;
    use crate::node::worker_set::TestWorker;

    let dead = EncryptWorkerPool::for_test(vec![TestWorker::FailSpawn, TestWorker::FailSpawn])
        .worker_index_for_dest(dest);
    EncryptWorkerPool::for_test(
        (0..2)
            .map(|idx| {
                if dead.is_none_or(|d| d == idx) {
                    TestWorker::FailSpawn
                } else {
                    TestWorker::Run
                }
            })
            .collect(),
    )
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

/// A control machine carrying a fresh outbound connection, for tests that
/// drive one end of a handshake without a whole node behind it. The machine
/// owns the handshake operations, so it is what the crypto runs on.
/// A peer for `remote` with a live link session: the node's half of an IK
/// handshake it completed toward `remote`, under our index 1 and their index
/// 2 on transport 1, authenticated at `authenticated_at`. A link's peer
/// epoch, replay record and timestamp base live in its rekey machine, which
/// exists only with keys, so a test that sets them stands up a keyed peer.
/// The index binding is not executed: `peers_by_index` stays as it was.
pub(super) fn keyed_peer(
    node: &Node,
    remote: &Identity,
    link_id: LinkId,
    authenticated_at: u64,
) -> crate::peer::ActivePeer {
    let mut initiator = crate::noise::HandshakeState::new_initiator(
        node.identity().keypair(),
        remote.pubkey_full(),
    );
    initiator.set_local_epoch(node.startup_epoch());
    let mut responder = crate::noise::HandshakeState::new_responder(remote.keypair());
    responder.set_local_epoch([0x5E; 8]);
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    crate::peer::ActivePeer::with_test_session(
        PeerIdentity::from_pubkey_full(remote.pubkey_full()),
        link_id,
        authenticated_at,
        initiator.into_session().unwrap(),
        SessionIndex::new(1),
        SessionIndex::new(2),
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:1"),
        crate::transport::LinkStats::new(),
        true,
        &crate::config::MmpConfig::default(),
        None,
    )
}

/// Start `node`'s own rekey of its link to `peer` now, as a trigger that
/// has come would whatever the link's age, and carry out what its link
/// machine asks for: the attempt index is bound for msg2 dispatch and the
/// msg1 goes out on the link. Returns the attempt's index.
pub(super) async fn start_link_rekey(node: &mut Node, peer: &NodeAddr) -> SessionIndex {
    let local = node.session_node_keys();
    let out = node
        .peers
        .get_mut(peer)
        .expect("a held peer")
        .start_rekey_now(crate::peer::peer_now(), &mut node.index_allocator, &local);
    node.run_link_step(peer, out).await;
    node.get_peer(peer)
        .unwrap()
        .rekey_our_index()
        .expect("the link machine started a rekey")
}

pub(super) fn outbound_leg(
    link_id: LinkId,
    expected_identity: PeerIdentity,
    current_time_ms: u64,
) -> PeerMachine {
    let mut machine = PeerMachine::new_outbound(link_id, expected_identity, current_time_ms);
    machine.set_leg(HandshakeCrypto::new());
    machine
}

/// The responder twin of [`outbound_leg`].
pub(super) fn inbound_leg(link_id: LinkId, current_time_ms: u64) -> PeerMachine {
    let mut machine = PeerMachine::new_inbound(link_id, current_time_ms);
    machine.set_leg(HandshakeCrypto::new());
    machine
}

/// Seed a control machine whose leg carries a completed Noise IK handshake.
///
/// Returns the peer identity. The leg is outbound, in Complete state, with
/// session, indices, and transport info set, and is installed on the node
/// through [`Node::seed_handshake_machine`].
pub(super) fn seed_completed_connection(
    node: &mut Node,
    link_id: LinkId,
    transport_id: TransportId,
    current_time_ms: u64,
) -> PeerIdentity {
    let our_index = fips_core::proto::rekey::allocate(&mut node.index_allocator).unwrap();
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
        .peer_machines
        .get_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, current_time_ms)
        .unwrap();

    // Run responder side to generate msg2
    let mut resp_conn = inbound_leg(LinkId::new(999), current_time_ms);
    let peer_keypair = peer_identity_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, current_time_ms)
        .unwrap();

    // Complete initiator handshake
    node.peer_machines
        .get_mut(&link_id)
        .unwrap()
        .complete_handshake(&msg2, current_time_ms)
        .unwrap();

    peer_identity
}
