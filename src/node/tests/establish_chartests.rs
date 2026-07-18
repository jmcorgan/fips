//! Characterization tests for the inbound-handshake (`handle_msg1`) establish
//! branches.
//!
//! These lock in the *current* observable behavior of the undertested inbound
//! classification paths by driving a REAL framed msg1 into `handle_msg1`
//! (constructing a genuine Noise IK msg1 and delivering it as a
//! `ReceivedPacket`), rather than poking rekey state directly the way the
//! `arm_rekey` helper does. They are an oracle for a later behavior-neutral
//! refactor: assertions capture what happens today, surprising or not.
//!
//! Coverage map (branch → test):
//!   * epoch-restart              → `chartest_msg1_epoch_restart_replaces_active_peer`
//!   * duplicate (pre-crypto)     → `chartest_msg1_duplicate_pending_resends_stored_msg2`
//!   * duplicate (post-crypto)    → `chartest_msg1_duplicate_active_same_epoch_resends_stored_msg2`
//!   * cross-connection precedence→ `chartest_msg1_inbound_promote_defers_pending_outbound_to_same_identity`
//!   * max-peers cap (bypass)     → `chartest_msg1_at_cap_with_pending_outbound_bypasses_early_gate`
//!   * tie-break (winner+loser)   → `chartest_cross_connection_tiebreak_winner_and_loser`
//!   * rekey-responder            → `chartest_msg1_rekey_responder_stores_pending_session`
//!   * rekey dual-init (we win)   → `chartest_msg1_rekey_dual_init_we_win_drops_their_msg1`
//!   * rekey dual-init (we lose)  → `chartest_msg1_rekey_dual_init_we_lose_becomes_responder`
//!
//! The three rekey branches sit behind the hardcoded
//! `existing_session_age_secs >= 30` guard in `handle_msg1`, resolved from
//! `ActivePeer::session_established_at()` (a monotonic `std::time::Instant`
//! with no natural test seam — the field is private and `tokio::time` cannot
//! advance a std `Instant`). They are unblocked by the sole `#[cfg(test)]`
//! production seam `ActivePeer::test_backdate_session_established(age)`, which
//! only shifts that private timestamp — it changes no decision logic and no
//! threshold, and is compiled out of release builds.

use super::*;
use crate::config::UdpConfig;
use crate::noise::HandshakeState;
use crate::peer::ActivePeer;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportHandle, packet_channel};
use tokio::time::timeout;

/// Build a genuine wire-format Noise IK msg1 addressed to `node`, carrying a
/// chosen startup `epoch` and `sender_index`, from `sender`'s identity. Returns
/// the opaque wire bytes ready to place in a `ReceivedPacket`.
fn craft_msg1_wire(
    node: &Node,
    sender: &Identity,
    epoch: [u8; 8],
    sender_index: SessionIndex,
    ts: u64,
) -> Vec<u8> {
    use crate::proto::fmp::wire::build_msg1;
    let peer_b_identity = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
    let link_id = LinkId::new(0x0BAD_C0DE);
    let mut conn = PeerConnection::outbound(link_id, peer_b_identity, ts);
    let noise_msg1 = conn
        .start_handshake(sender.keypair(), epoch, ts)
        .expect("start_handshake produces noise msg1");
    build_msg1(sender_index, &noise_msg1)
}

/// Register a real UDP transport on `node` and return an independent socket
/// (plus its addr) that plays the peer: the node's msg2 responses are sent to
/// this addr, so a test can observe wire-level output.
async fn register_udp_with_peer_socket(
    node: &mut Node,
    transport_id: TransportId,
) -> (tokio::net::UdpSocket, TransportAddr) {
    let peer_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind peer socket");
    let peer_addr = TransportAddr::from_string(&peer_sock.local_addr().unwrap().to_string());

    let cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let mut transport = UdpTransport::new(transport_id, None, cfg, tx);
    transport.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));
    (peer_sock, peer_addr)
}

/// Local re-impl of the `unit.rs` dummy-peer injector (that one is private to
/// its module). Fills the peer table with distinct identities so cap tests can
/// reach saturation.
fn inject_dummy_peers(node: &mut Node, count: usize) {
    for i in 0..count {
        let identity = make_peer_identity();
        let addr = *identity.node_addr();
        let peer = ActivePeer::new(identity, LinkId::new((i + 1) as u64), 0);
        node.peers.insert(addr, peer);
    }
}

/// Epoch-restart: an inbound msg1 from an already-active peer that carries a
/// DIFFERENT startup epoch is treated as a peer restart. The stale peer is torn
/// down and the fresh handshake is promoted in its place.
///
/// Oracle: after the push, the identity is still present but is a NEW peer —
/// it now holds a live Noise session (the stale one had none), its stored
/// remote epoch has advanced to the restart value, and it occupies a fresh link
/// and session index. `schedule_reconnect` is a no-op under a bare test config
/// (no auto-connect peer configured), so `retry_pending` stays empty.
#[tokio::test]
async fn chartest_msg1_epoch_restart_replaces_active_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (peer_sock, peer_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    let sender = Identity::generate();
    let sender_pid = PeerIdentity::from_pubkey_full(sender.pubkey_full());
    let sender_addr = *sender_pid.node_addr();

    let old_epoch = [1u8; 8];
    let new_epoch = [2u8; 8];
    let old_link = LinkId::new(4242);

    // Pre-existing active peer at the OLD epoch, sessionless. `current_addr`
    // makes `should_admit_msg1` recognize the source as an established peer.
    let mut old_peer = ActivePeer::new(sender_pid, old_link, 1000);
    old_peer.set_remote_epoch(Some(old_epoch));
    old_peer.set_current_addr(transport_id, peer_addr.clone());
    node.peers.insert(sender_addr, old_peer);
    assert!(!node.get_peer(&sender_addr).unwrap().has_session());
    assert_eq!(
        node.get_peer(&sender_addr).unwrap().remote_epoch(),
        Some(old_epoch)
    );

    // Real msg1 carrying the NEW (restart) epoch.
    let data = craft_msg1_wire(&node, &sender, new_epoch, SessionIndex::new(0x77), 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    let peer = node
        .get_peer(&sender_addr)
        .expect("restarted peer must remain present (replaced, not dropped)");
    assert!(
        peer.has_session(),
        "restart promotes a fresh handshake, so the new peer holds a session"
    );
    assert_eq!(
        peer.remote_epoch(),
        Some(new_epoch),
        "stored remote epoch advances to the restart value"
    );
    assert_ne!(
        peer.link_id(),
        old_link,
        "restart replaces the link with the freshly allocated one"
    );
    let our_index = peer.our_index().expect("promoted peer has our_index");
    assert!(
        node.peers_by_index
            .contains_key(&(transport_id, our_index.as_u32())),
        "fresh session index registered in peers_by_index"
    );
    assert_eq!(node.peer_count(), 1, "old peer removed, new peer added");
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "schedule_reconnect is a no-op with no auto-connect config"
    );

    // A msg2 response was emitted to the restarting peer.
    let mut buf = [0u8; 2048];
    let got = timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf)).await;
    assert!(
        got.is_ok(),
        "restart path must emit a msg2 response to the peer"
    );
}

/// Duplicate msg1, pre-crypto short-circuit: a second msg1 from an address that
/// already has a genuinely-pending (not yet promoted) inbound link resends the
/// stored msg2 without paying the crypto cost or touching registry state.
///
/// Oracle: the exact stored msg2 bytes are resent verbatim, nothing is
/// promoted, the pending connection is left intact, and the msg1 rate limiter
/// rebalances (start then complete) to baseline.
#[tokio::test]
async fn chartest_msg1_duplicate_pending_resends_stored_msg2() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (peer_sock, peer_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    // A pending inbound connection with a stored msg2, keyed in addr_to_link,
    // NOT promoted to an active peer.
    let link_id = node.allocate_link_id();
    let stored_msg2 = vec![0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
    let link = Link::connectionless(
        link_id,
        transport_id,
        peer_addr.clone(),
        LinkDirection::Inbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.addr_to_link
        .insert((transport_id, peer_addr.clone()), link_id);
    node.seed_handshake_machine(
        HandshakeSeed::inbound(link_id, 1000)
            .with_transport_id(transport_id)
            .with_source_addr(peer_addr.clone()),
    )
    .unwrap();
    // The stored msg2 lives on the control machine's carrier (the resend source
    // for a duplicate msg1 while pending), mirroring the inbound establish path.
    node.peer_machines
        .get_mut(&link_id)
        .unwrap()
        .set_conn_handshake_msg2(stored_msg2.clone());
    assert_eq!(node.peer_count(), 0);

    let before_pending = node.msg1_rate_limiter.pending_count();

    // Duplicate msg1 from the same address. Content is irrelevant past a valid
    // header — the pre-crypto branch fires before any decrypt.
    let sender = Identity::generate();
    let data = craft_msg1_wire(&node, &sender, [9u8; 8], SessionIndex::new(5), 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf))
        .await
        .expect("stored msg2 must be resent")
        .expect("recv_from");
    assert_eq!(
        &buf[..n],
        &stored_msg2[..],
        "the exact stored msg2 is resent for a duplicate msg1"
    );
    assert_eq!(node.peer_count(), 0, "duplicate msg1 promotes nothing");
    assert!(
        node.get_connection(&link_id).is_some(),
        "pending connection is left intact"
    );
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        before_pending,
        "rate limiter rebalances to baseline"
    );
}

/// Duplicate msg1, post-crypto same-epoch path: an inbound msg1 from an active
/// peer at the SAME epoch, on a session too young (< 30s) to be a rekey, is a
/// duplicate. The peer's stored msg2 is resent.
///
/// Oracle: the active peer's stored msg2 is resent, no new peer or session
/// index is allocated, and the existing peer is untouched.
#[tokio::test]
async fn chartest_msg1_duplicate_active_same_epoch_resends_stored_msg2() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (peer_sock, peer_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    let sender = Identity::generate();
    let sender_pid = PeerIdentity::from_pubkey_full(sender.pubkey_full());
    let sender_addr = *sender_pid.node_addr();

    let epoch = [7u8; 8];
    let stored_msg2 = vec![0xD0, 0xD1, 0xD2, 0xD3];
    let link_id = LinkId::new(555);
    let mut peer = ActivePeer::new(sender_pid, link_id, 1000);
    peer.set_remote_epoch(Some(epoch));
    peer.set_current_addr(transport_id, peer_addr.clone());
    peer.set_handshake_msg2(stored_msg2.clone());
    node.peers.insert(sender_addr, peer);
    // Session age is ~0 (< 30s) → the rekey gate is false → a same-epoch msg1
    // classifies as a duplicate, not a rekey initiation.
    assert!(!node.get_peer(&sender_addr).unwrap().has_session());

    let data = craft_msg1_wire(&node, &sender, epoch, SessionIndex::new(0x33), 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf))
        .await
        .expect("stored msg2 must be resent")
        .expect("recv_from");
    assert_eq!(&buf[..n], &stored_msg2[..]);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.get_peer(&sender_addr).unwrap().link_id(),
        link_id,
        "existing peer untouched by a duplicate msg1"
    );
    assert!(
        node.peers_by_index.is_empty(),
        "no new session index allocated on the duplicate path"
    );
}

/// Cross-connection precedence: an inbound establish that promotes a peer while
/// a concurrent PENDING OUTBOUND connection to the SAME identity exists must NOT
/// tear that outbound down — it is deferred (kept alive so its later msg2 can
/// update `their_index` on the promoted peer).
///
/// Oracle: the inbound msg1 promotes the peer (with a live session), and both
/// the pending outbound connection and its `pending_outbound` index entry are
/// preserved.
#[tokio::test]
async fn chartest_msg1_inbound_promote_defers_pending_outbound_to_same_identity() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (_peer_sock, inbound_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    let sender = Identity::generate();
    let sender_pid = PeerIdentity::from_pubkey_full(sender.pubkey_full());
    let sender_addr = *sender_pid.node_addr();

    // A concurrent pending OUTBOUND connection to the same identity, at a
    // different source address.
    let out_link = node.allocate_link_id();
    let out_addr = TransportAddr::from_string("10.0.0.9:2121");
    let out_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(out_link, sender_pid, 1000)
            .with_our_index(out_index)
            .with_transport_id(transport_id)
            .with_source_addr(out_addr.clone()),
    )
    .unwrap();
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let _ = node
        .get_connection_mut(&out_link)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, 1000)
        .unwrap();
    let out_l = Link::connectionless(
        out_link,
        transport_id,
        out_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(out_link, out_l);
    node.addr_to_link
        .insert((transport_id, out_addr.clone()), out_link);
    node.pending_outbound
        .insert((transport_id, out_index.as_u32()), out_link);
    assert_eq!(node.peer_count(), 0);

    // Inbound msg1 from the same identity, different source addr.
    let data = craft_msg1_wire(&node, &sender, [3u8; 8], SessionIndex::new(0x22), 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: inbound_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    let peer = node
        .get_peer(&sender_addr)
        .expect("inbound establish must promote the peer");
    assert!(peer.has_session());
    assert_eq!(node.peer_count(), 1);
    assert!(
        node.get_connection(&out_link).is_some(),
        "pending outbound to the same identity must be preserved (deferred cleanup)"
    );
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, out_index.as_u32())),
        "the outbound pending_outbound entry is preserved for msg2 index-learning"
    );
}

/// Max-peers cap, pending-outbound bypass: at saturation, a msg1 from a NEW
/// identity that already has a pending outbound to it is NOT silent-dropped by
/// the early cap gate — it proceeds far enough to emit a msg2, then the late gate
/// inside `promote_connection` rejects it (peer table is full).
///
/// Oracle discriminator vs. the plain new-peer silent-drop: a msg2 IS observed
/// on the wire (the early gate was bypassed), yet the peer is NOT promoted (the
/// late gate rejects). This locks in the asymmetry between the two cap gates.
#[tokio::test]
async fn chartest_msg1_at_cap_with_pending_outbound_bypasses_early_gate() {
    let mut node = make_node_with_max_peers(2);
    let transport_id = TransportId::new(1);
    let (peer_sock, peer_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    inject_dummy_peers(&mut node, 2);
    assert_eq!(node.peer_count(), 2, "precondition: at cap");

    let sender = Identity::generate();
    let sender_pid = PeerIdentity::from_pubkey_full(sender.pubkey_full());
    let sender_addr = *sender_pid.node_addr();

    // A pending outbound to the (new) sender identity — this sets
    // `has_pending_outbound_to_peer`, which turns off the early silent-drop.
    let out_link = node.allocate_link_id();
    let out_addr = TransportAddr::from_string("10.0.0.9:2121");
    let out_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(out_link, sender_pid, 1000)
            .with_our_index(out_index)
            .with_transport_id(transport_id)
            .with_source_addr(out_addr.clone()),
    )
    .unwrap();
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let _ = node
        .get_connection_mut(&out_link)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, 1000)
        .unwrap();
    node.pending_outbound
        .insert((transport_id, out_index.as_u32()), out_link);

    let data = craft_msg1_wire(&node, &sender, [4u8; 8], SessionIndex::new(0x44), 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    // Late gate rejects: still at cap, sender not promoted.
    assert_eq!(
        node.peer_count(),
        2,
        "late cap gate rejects the new identity"
    );
    assert!(
        !node.peers.contains_key(&sender_addr),
        "new identity is not adopted at capacity"
    );

    // But the early gate was bypassed: a msg2 WAS put on the wire before the
    // late-gate rejection (the discriminator against the plain silent-drop).
    let mut buf = [0u8; 2048];
    let got = timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf)).await;
    assert!(
        got.is_ok() && got.unwrap().is_ok(),
        "pending-outbound identity bypasses the early silent-drop, so a msg2 \
         is emitted before the late cap gate rejects"
    );
}

/// Cross-connection tie-break, winner AND loser in one deterministic run: both
/// nodes initiate to each other (simultaneous cross-connection). The rule is
/// "the smaller node_addr's OUTBOUND wins" (`cross_connection_winner`). After
/// both sides exchange msg1 (promote inbound) and msg2 (resolve), the winner has
/// swapped to its outbound session index while the loser keeps the inbound index
/// it assigned during its own msg1 handling.
///
/// Oracle: the smaller-addr node's peer.our_index equals the OUTBOUND index it
/// allocated at setup; the larger-addr node's peer.our_index equals the INBOUND
/// index it assigned while promoting the peer's msg1.
#[tokio::test]
async fn chartest_cross_connection_tiebreak_winner_and_loser() {
    use crate::proto::fmp::wire::build_msg1;

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);
    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_a = transport_a.local_addr().unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());
    let remote_addr_a = TransportAddr::from_string(&addr_a.to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let peer_a_identity = PeerIdentity::from_pubkey_full(node_a.identity().pubkey_full());
    let node_a_addr = *node_a.node_addr();
    let node_b_addr = *node_b.node_addr();

    // A initiates to B.
    let link_a_out = node_a.allocate_link_id();
    let out_index_a = node_a.index_allocator.allocate().unwrap();
    node_a
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_a_out, peer_b_identity, 1000)
                .with_our_index(out_index_a)
                .with_transport_id(transport_id_a)
                .with_source_addr(remote_addr_b.clone()),
        )
        .unwrap();
    let keypair_a = node_a.identity().keypair();
    let epoch_a = node_a.startup_epoch();
    let noise_msg1_a = node_a
        .get_connection_mut(&link_a_out)
        .unwrap()
        .start_handshake(keypair_a, epoch_a, 1000)
        .unwrap();
    let wire_msg1_a = build_msg1(out_index_a, &noise_msg1_a);
    node_a.links.insert(
        link_a_out,
        Link::connectionless(
            link_a_out,
            transport_id_a,
            remote_addr_b.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node_a
        .addr_to_link
        .insert((transport_id_a, remote_addr_b.clone()), link_a_out);
    node_a
        .pending_outbound
        .insert((transport_id_a, out_index_a.as_u32()), link_a_out);

    // B initiates to A.
    let link_b_out = node_b.allocate_link_id();
    let out_index_b = node_b.index_allocator.allocate().unwrap();
    node_b
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_b_out, peer_a_identity, 1000)
                .with_our_index(out_index_b)
                .with_transport_id(transport_id_b)
                .with_source_addr(remote_addr_a.clone()),
        )
        .unwrap();
    let keypair_b = node_b.identity().keypair();
    let epoch_b = node_b.startup_epoch();
    let noise_msg1_b = node_b
        .get_connection_mut(&link_b_out)
        .unwrap()
        .start_handshake(keypair_b, epoch_b, 1000)
        .unwrap();
    let wire_msg1_b = build_msg1(out_index_b, &noise_msg1_b);
    node_b.links.insert(
        link_b_out,
        Link::connectionless(
            link_b_out,
            transport_id_b,
            remote_addr_a.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node_b
        .addr_to_link
        .insert((transport_id_b, remote_addr_a.clone()), link_b_out);
    node_b
        .pending_outbound
        .insert((transport_id_b, out_index_b.as_u32()), link_b_out);

    // Both put msg1 on the wire.
    node_a
        .transports
        .get(&transport_id_a)
        .unwrap()
        .send(&remote_addr_b, &wire_msg1_a)
        .await
        .unwrap();
    node_b
        .transports
        .get(&transport_id_b)
        .unwrap()
        .send(&remote_addr_a, &wire_msg1_b)
        .await
        .unwrap();

    // Each processes the other's msg1 (promotes inbound, assigns an inbound index).
    let pkt_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    node_b.handle_msg1(pkt_at_b).await;
    let pkt_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .unwrap()
        .unwrap();
    node_a.handle_msg1(pkt_at_a).await;

    // Inbound indices assigned during promotion (before resolution).
    let inbound_index_a = node_a.get_peer(&node_b_addr).unwrap().our_index().unwrap();
    let inbound_index_b = node_b.get_peer(&node_a_addr).unwrap().our_index().unwrap();

    // Each processes the other's msg2 (cross-connection resolution).
    let msg2_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .unwrap()
        .unwrap();
    node_a.handle_msg2(msg2_at_a).await;
    let msg2_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    node_b.handle_msg2(msg2_at_b).await;

    // Rule: smaller node_addr's OUTBOUND wins → that node swaps to its outbound
    // index; the larger node keeps the inbound index from its own msg1 handling.
    let a_is_winner = node_a_addr < node_b_addr;
    let final_our_index_a = node_a.get_peer(&node_b_addr).unwrap().our_index().unwrap();
    let final_our_index_b = node_b.get_peer(&node_a_addr).unwrap().our_index().unwrap();

    if a_is_winner {
        assert_eq!(
            final_our_index_a, out_index_a,
            "winner (smaller addr) swaps to its outbound session index"
        );
        assert_eq!(
            final_our_index_b, inbound_index_b,
            "loser (larger addr) keeps the inbound index from its msg1 handling"
        );
    } else {
        assert_eq!(
            final_our_index_b, out_index_b,
            "winner (smaller addr) swaps to its outbound session index"
        );
        assert_eq!(
            final_our_index_a, inbound_index_a,
            "loser (larger addr) keeps the inbound index from its msg1 handling"
        );
    }

    // Both remain single, sendable peers after resolution.
    assert_eq!(node_a.peer_count(), 1);
    assert_eq!(node_b.peer_count(), 1);
    assert!(node_a.get_peer(&node_b_addr).unwrap().can_send());
    assert!(node_b.get_peer(&node_a_addr).unwrap().can_send());

    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

// ===========================================================================
// Rekey establish branches (unblocked by the `#[cfg(test)]`
// `ActivePeer::test_backdate_session_established` seam that lets a test age a
// real session past the hardcoded 30s rekey gate in `handle_msg1`).
// ===========================================================================

/// Drive a real inbound msg1 through `handle_msg1` so `node` promotes an active
/// peer for `sender` at startup `epoch`, draining the msg2 the promotion emits.
/// Returns the sender's NodeAddr.
async fn establish_active_peer_via_msg1(
    node: &mut Node,
    sender: &Identity,
    epoch: [u8; 8],
    transport_id: TransportId,
    peer_addr: &TransportAddr,
    peer_sock: &tokio::net::UdpSocket,
    ts: u64,
) -> NodeAddr {
    let sender_addr = *PeerIdentity::from_pubkey_full(sender.pubkey_full()).node_addr();
    let data = craft_msg1_wire(node, sender, epoch, SessionIndex::new(0x01), ts);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: ts,
    };
    node.handle_msg1(packet).await;
    // Promotion emits a msg2 AND an initial TreeAnnounce; drain every queued
    // datagram so a later recv observes only the rekey response (or its
    // absence), never a leftover from establishment.
    let mut buf = [0u8; 2048];
    while timeout(Duration::from_millis(150), peer_sock.recv_from(&mut buf))
        .await
        .is_ok()
    {}
    sender_addr
}

/// Draw a fresh sender identity whose NodeAddr is greater-than (`want_greater`)
/// or less-than the node's own NodeAddr, so the dual-init tie-break outcome is
/// deterministic. The comparison invariant is enforced, so the test outcome is
/// deterministic even though the identity draw is random.
fn sender_with_addr_relation(node: &Node, want_greater: bool) -> Identity {
    let node_addr = *node.node_addr();
    loop {
        let s = Identity::generate();
        let a = *PeerIdentity::from_pubkey_full(s.pubkey_full()).node_addr();
        if a != node_addr && (a > node_addr) == want_greater {
            return s;
        }
    }
}

/// Arm a local in-flight (initiator) rekey on `node`'s peer for `sender`, with a
/// real allocated index registered in `peers_by_index`/`pending_outbound` (as a
/// genuine in-flight rekey would be). Returns the armed rekey index.
fn arm_local_rekey(
    node: &mut Node,
    sender: &Identity,
    sender_addr: &NodeAddr,
    transport_id: TransportId,
) -> SessionIndex {
    let rekey_index = node.index_allocator.allocate().unwrap();
    node.peers_by_index
        .insert((transport_id, rekey_index.as_u32()), *sender_addr);
    node.pending_outbound
        .insert((transport_id, rekey_index.as_u32()), LinkId::new(0xF00D));
    let local = Identity::generate();
    let hs = HandshakeState::new_initiator(local.keypair(), sender.pubkey_full());
    node.get_peer_mut(sender_addr)
        .unwrap()
        .set_rekey_state(hs, rekey_index, vec![0xAB; 64], 0);
    rekey_index
}

/// Rekey-responder: a genuine rekey msg1 (a fresh IK handshake at the SAME
/// epoch) arriving for an active peer whose session is past the 30s gate is
/// processed as a rekey. The responder extracts the new session and holds it as
/// PENDING (awaiting K-bit cutover) without disturbing the live session.
///
/// Oracle: the new session lands in `pending_new_session` with a freshly
/// allocated `pending_our_index` and `pending_their_index` == the rekey msg1
/// sender index; the current session/index stay live and registered; the new
/// index is additionally registered in `peers_by_index`; and a rekey msg2 is
/// emitted. The peer is neither replaced nor left `rekey_in_progress`.
#[tokio::test]
async fn chartest_msg1_rekey_responder_stores_pending_session() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (peer_sock, peer_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    let sender = Identity::generate();
    let epoch = [5u8; 8];
    let sender_addr = establish_active_peer_via_msg1(
        &mut node,
        &sender,
        epoch,
        transport_id,
        &peer_addr,
        &peer_sock,
        1000,
    )
    .await;

    let old_index = {
        let p = node.get_peer(&sender_addr).expect("peer established");
        assert!(p.has_session());
        assert!(p.is_healthy());
        assert_eq!(p.remote_epoch(), Some(epoch));
        assert!(!p.rekey_in_progress());
        assert!(p.pending_new_session().is_none());
        p.our_index().unwrap()
    };
    assert!(
        node.peers_by_index
            .contains_key(&(transport_id, old_index.as_u32()))
    );
    let index_count_before = node.index_allocator.count();

    // Age the live session past the 30s rekey gate (test-only seam).
    node.get_peer_mut(&sender_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));

    // A genuine rekey msg1 (fresh IK handshake, SAME epoch) arrives.
    let rekey_sender_index = SessionIndex::new(0xBEEF);
    let data = craft_msg1_wire(&node, &sender, epoch, rekey_sender_index, 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    let p = node
        .get_peer(&sender_addr)
        .expect("peer still present (not replaced)");
    assert_eq!(
        node.peer_count(),
        1,
        "rekey neither adds nor replaces the peer"
    );
    assert!(
        p.pending_new_session().is_some(),
        "new session held as pending"
    );
    let new_index = p.pending_our_index().expect("pending our_index allocated");
    assert_eq!(
        p.pending_their_index(),
        Some(rekey_sender_index),
        "pending their_index = the rekey msg1 sender index"
    );
    assert!(
        !p.rekey_in_progress(),
        "set_pending_session clears rekey_in_progress"
    );
    assert_eq!(
        p.our_index(),
        Some(old_index),
        "current session index stays live until cutover"
    );
    assert!(p.has_session(), "current session remains live");

    assert!(
        node.peers_by_index
            .contains_key(&(transport_id, old_index.as_u32())),
        "current index still registered"
    );
    assert!(
        node.peers_by_index
            .contains_key(&(transport_id, new_index.as_u32())),
        "new pending index registered"
    );
    assert_eq!(
        node.index_allocator.count(),
        index_count_before + 1,
        "exactly one extra index allocated for the pending session"
    );

    let mut buf = [0u8; 2048];
    let got = timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf)).await;
    assert!(
        got.is_ok() && got.unwrap().is_ok(),
        "rekey responder emits a rekey msg2"
    );
}

/// Rekey dual-init, WE WIN: with a local rekey in flight, a simultaneous rekey
/// msg1 arrives from a peer whose NodeAddr is larger than ours. The tie-break
/// ("smaller NodeAddr wins as initiator") makes us the winner, so we DROP their
/// msg1 and keep driving our own rekey.
///
/// Oracle: our in-flight rekey is untouched (`rekey_in_progress` stays true, our
/// rekey index retained and still registered), no responder session is stored,
/// no responder index is allocated, and no rekey msg2 is emitted.
#[tokio::test]
async fn chartest_msg1_rekey_dual_init_we_win_drops_their_msg1() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (peer_sock, peer_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    // We win when our node_addr < peer's → pick a sender greater than us.
    let sender = sender_with_addr_relation(&node, true);
    let epoch = [6u8; 8];
    let sender_addr = establish_active_peer_via_msg1(
        &mut node,
        &sender,
        epoch,
        transport_id,
        &peer_addr,
        &peer_sock,
        1000,
    )
    .await;
    assert!(
        *node.node_addr() < sender_addr,
        "precondition: node wins the tie-break"
    );

    node.get_peer_mut(&sender_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));
    let rekey_index = arm_local_rekey(&mut node, &sender, &sender_addr, transport_id);
    assert!(node.get_peer(&sender_addr).unwrap().rekey_in_progress());
    let index_count_before = node.index_allocator.count();

    // Their simultaneous rekey msg1 arrives.
    let data = craft_msg1_wire(&node, &sender, epoch, SessionIndex::new(0xAAAA), 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    let p = node.get_peer(&sender_addr).expect("peer present");
    assert!(
        p.rekey_in_progress(),
        "our rekey survives; the winner does not abandon it"
    );
    assert!(
        p.pending_new_session().is_none(),
        "no responder session stored on the winner path"
    );
    assert_eq!(
        p.rekey_our_index(),
        Some(rekey_index),
        "our rekey index retained"
    );
    assert!(
        node.peers_by_index
            .contains_key(&(transport_id, rekey_index.as_u32())),
        "our rekey index still registered in peers_by_index"
    );
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, rekey_index.as_u32())),
        "our rekey pending_outbound entry retained"
    );
    assert_eq!(
        node.index_allocator.count(),
        index_count_before,
        "no responder index allocated on the winner path"
    );

    let mut buf = [0u8; 2048];
    let got = timeout(Duration::from_millis(300), peer_sock.recv_from(&mut buf)).await;
    assert!(
        got.is_err(),
        "winner emits no msg2 in response to the dropped rekey msg1"
    );
}

/// Rekey dual-init, WE LOSE: with a local rekey in flight, a simultaneous rekey
/// msg1 arrives from a peer whose NodeAddr is smaller than ours. The tie-break
/// makes us the loser, so we ABANDON our own rekey and respond as the rekey
/// responder.
///
/// Oracle: our in-flight rekey is abandoned (`rekey_in_progress` cleared, the
/// abandoned index freed and unregistered from `pending_outbound`), the new
/// session is stored as pending with `pending_their_index` == the rekey msg1
/// sender index, the pending index is registered, and a rekey msg2 is emitted.
#[tokio::test]
async fn chartest_msg1_rekey_dual_init_we_lose_becomes_responder() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let (peer_sock, peer_addr) = register_udp_with_peer_socket(&mut node, transport_id).await;

    // We lose when our node_addr > peer's → pick a sender smaller than us.
    let sender = sender_with_addr_relation(&node, false);
    let epoch = [6u8; 8];
    let sender_addr = establish_active_peer_via_msg1(
        &mut node,
        &sender,
        epoch,
        transport_id,
        &peer_addr,
        &peer_sock,
        1000,
    )
    .await;
    assert!(
        *node.node_addr() > sender_addr,
        "precondition: node loses the tie-break"
    );

    node.get_peer_mut(&sender_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));
    let rekey_index = arm_local_rekey(&mut node, &sender, &sender_addr, transport_id);
    assert!(node.get_peer(&sender_addr).unwrap().rekey_in_progress());

    // Their simultaneous rekey msg1 arrives.
    let rekey_sender_index = SessionIndex::new(0xCCCC);
    let data = craft_msg1_wire(&node, &sender, epoch, rekey_sender_index, 2000);
    let packet = ReceivedPacket {
        transport_id,
        remote_addr: peer_addr.clone(),
        data,
        timestamp_ms: 2000,
    };
    node.handle_msg1(packet).await;

    let p = node.get_peer(&sender_addr).expect("peer present");
    assert!(
        !p.rekey_in_progress(),
        "we abandoned our rekey and became responder"
    );
    assert!(
        p.pending_new_session().is_some(),
        "responder stores the new session as pending"
    );
    assert_eq!(
        p.pending_their_index(),
        Some(rekey_sender_index),
        "pending their_index = the rekey msg1 sender index"
    );
    let new_index = p
        .pending_our_index()
        .expect("responder allocated a pending index");

    assert!(
        !node
            .pending_outbound
            .contains_key(&(transport_id, rekey_index.as_u32())),
        "abandoned rekey pending_outbound entry removed"
    );
    assert!(
        node.peers_by_index
            .contains_key(&(transport_id, new_index.as_u32())),
        "new pending index registered"
    );

    let mut buf = [0u8; 2048];
    let got = timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf)).await;
    assert!(
        got.is_ok() && got.unwrap().is_ok(),
        "loser (now responder) emits a rekey msg2"
    );
}
