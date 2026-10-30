//! A responder that could not send the msg2 it built, and later sends it in
//! answer to the initiator's resent msg1, must install the peer once that
//! send succeeds, and finish the install as a first successful send would:
//! the peer carries the stored msg2 and the msg1 it was set up by, and the
//! initial tree announce goes out.
//!
//! The first send is made to fail the way an interface between rebinds
//! fails: B's transport is swapped for an Ethernet transport on an interface
//! no host has, whose sends report `InterfaceUnavailable`, which the msg2
//! executor treats as transient and so leaves the handshake pending. The
//! loopback transport is then put back, so the stored msg2 sent in answer to
//! the resend reaches A.

use super::rekey_parity::{deliver, heartbeat, linked_pair};
use super::spanning_tree::cleanup_nodes;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::spanning_tree::{TestNode, initiate_handshake, make_test_node};
use super::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::proto::fmp::EphemeralDigest;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::proto::fmp::wire::{CommonPrefix, Msg1Header, PHASE_MSG1};

/// An Ethernet transport on an interface no host has, started, under `id`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn absent_ethernet(id: TransportId) -> crate::transport::TransportHandle {
    use crate::config::EthernetConfig;
    use crate::transport::ethernet::EthernetTransport;

    let config = EthernetConfig {
        interface: "fips-absent-x0".to_string(),
        ethertype: None,
        mtu: None,
        recv_buf_size: None,
        send_buf_size: None,
        listen: Some(true),
        announce: Some(false),
        auto_connect: None,
        accept_connections: Some(true),
        beacon_interval_secs: None,
        optional: Some(true),
    };
    let (tx, _rx) = crate::transport::packet_channel(8);
    let mut eth = EthernetTransport::new(id, Some("lab".into()), config, tx);
    eth.start_async()
        .await
        .expect("an absent interface is not a start failure");
    crate::transport::TransportHandle::Ethernet(eth)
}

/// Swap `tn`'s loopback transport for one whose sends fail transiently, and
/// return the loopback for [`replug`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn unplug(tn: &mut TestNode) -> crate::transport::TransportHandle {
    let tid = tn.transport_id;
    let loopback = tn
        .node
        .transports
        .remove(&tid)
        .expect("the node has its loopback transport");
    tn.node.transports.insert(tid, absent_ethernet(tid).await);
    loopback
}

/// Put `loopback` back on `tn` and stop the transport it replaces.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn replug(tn: &mut TestNode, loopback: crate::transport::TransportHandle) {
    if let Some(mut eth) = tn.node.transports.insert(tn.transport_id, loopback) {
        eth.stop().await.ok();
    }
}

/// The msg1 queued at `tn`, taken off its queue.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn queued_msg1(tn: &mut TestNode) -> ReceivedPacket {
    let packet = tn.packet_rx.try_recv().expect("a packet is queued");
    assert!(
        CommonPrefix::parse(&packet.data).is_some_and(|p| p.phase == PHASE_MSG1),
        "precondition: the queued packet is a msg1"
    );
    packet
}

/// The digest of the ephemeral a framed msg1 carries.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ephemeral_of(msg1: &[u8]) -> Option<EphemeralDigest> {
    let header = Msg1Header::parse(msg1)?;
    EphemeralDigest::of_noise_msg1(msg1.get(header.noise_msg1_offset..)?)
}

/// The msg2 B stored for the pending leg it could not answer.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stored_msg2(tn: &TestNode) -> Vec<u8> {
    tn.node
        .peer_machines
        .values()
        .find_map(|m| m.conn_handshake_msg2())
        .map(<[u8]>::to_vec)
        .expect("precondition: B stored the msg2 it could not send")
}

/// Two nodes where A dialled B and B's first msg2 send failed transiently:
/// B holds no peer and keeps the pending leg, nothing reached A, and B's
/// loopback transport is back. Returns the nodes and A's msg1.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn deferred_pair() -> (Vec<TestNode>, ReceivedPacket) {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let a = *nodes[0].node.node_addr();
    let loopback = unplug(&mut nodes[1]).await;

    initiate_handshake(&mut nodes, 0, 1).await;
    let msg1 = queued_msg1(&mut nodes[1]);
    nodes[1].node.handle_msg1(msg1.clone()).await;
    assert!(
        nodes[1].node.get_peer(&a).is_none() && nodes[1].node.link_count() == 1,
        "precondition: B kept the handshake pending after a transient msg2 failure"
    );
    assert_eq!(
        deliver(&mut nodes[0]).await,
        0,
        "precondition: no msg2 reached A"
    );

    replug(&mut nodes[1], loopback).await;
    (nodes, msg1)
}

/// Whether A's heartbeat authenticates at B, given B holds A.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn heard_at_b(nodes: &mut [TestNode]) -> bool {
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    if nodes[1].node.get_peer(&a).is_none() {
        return false;
    }
    heartbeat(&mut nodes[0], &b).await;
    deliver(&mut nodes[1]).await;
    nodes[1].node.get_peer(&a).is_some_and(|p| p.is_heard())
}

/// B's first msg2 send fails transiently; A resends its msg1 byte for byte,
/// B answers it with the stored msg2, which reaches A, and A completes and
/// installs B. B must then hold A as a peer carrying the stored msg2 and the
/// msg1's ephemeral, B's initial tree announce must reach A, and A's frames
/// must authenticate at B.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_responder_whose_stored_msg2_send_succeeds_installs_the_peer() {
    let (mut nodes, msg1) = deferred_pair().await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let stored = stored_msg2(&nodes[1]);

    // A's resend: the same bytes from the same address.
    nodes[1].node.handle_msg1(msg1.clone()).await;
    // The msg2 and, once B installs A, B's initial tree announce.
    assert!(
        deliver(&mut nodes[0]).await >= 1,
        "control: B's stored msg2 reached A"
    );
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "control: A completed on the stored msg2 and installed B"
    );
    let announced = nodes[0].node.tree_state().peer_declaration(&b).is_some();

    let installed = nodes[1].node.get_peer(&a).is_some();
    let carries_msg2 =
        nodes[1].node.get_peer(&a).and_then(|p| p.handshake_msg2()) == Some(stored.as_slice());
    let records_setup =
        nodes[1].node.get_peer(&a).and_then(|p| p.setup_ephemeral()) == ephemeral_of(&msg1.data);
    let heard = heard_at_b(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        installed,
        "B sent its stored msg2 successfully but did not install A, so A's frames go \
         unanswered until A's link-dead timeout"
    );
    assert!(heard, "A's heartbeat must authenticate at B");
    assert!(
        announced,
        "B's initial tree announce must reach A when it installs A on the resend"
    );
    assert!(
        carries_msg2,
        "the peer installed on the resend must carry the stored msg2, for a later copy of the msg1"
    );
    assert!(
        records_setup,
        "the peer installed on the resend must record the msg1 it was set up by"
    );
}

/// A msg1 from A's address that differs from the one B's stored msg2
/// answers (here in its ephemeral) still draws the stored msg2, and B
/// installs A. The peer must record the msg1 the stored msg2 answers, the
/// one its session was built from, not the msg1 that drew the resend.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_responder_installs_the_peer_with_the_msg1_its_stored_msg2_answers_when_another_msg1_draws_it()
 {
    let (mut nodes, msg1) = deferred_pair().await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();

    let mut other = msg1.clone();
    let offset = Msg1Header::parse(&other.data)
        .expect("a framed msg1")
        .noise_msg1_offset;
    // Byte 0 of the ephemeral is its point prefix; byte 1 is key material.
    other.data[offset + 1] ^= 0x01;
    assert_ne!(
        ephemeral_of(&other.data),
        ephemeral_of(&msg1.data),
        "precondition: the drawing msg1 carries another ephemeral"
    );

    nodes[1].node.handle_msg1(other.clone()).await;
    assert!(
        deliver(&mut nodes[0]).await >= 1,
        "control: B's stored msg2 reached A"
    );
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "control: A completed on the stored msg2 and installed B"
    );

    let installed = nodes[1].node.get_peer(&a).is_some();
    let recorded = nodes[1].node.get_peer(&a).and_then(|p| p.setup_ephemeral());
    let heard = heard_at_b(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        installed,
        "B sent its stored msg2 successfully but did not install A"
    );
    assert_eq!(
        recorded,
        ephemeral_of(&msg1.data),
        "the peer must record the msg1 the stored msg2 answers"
    );
    assert_ne!(
        recorded,
        ephemeral_of(&other.data),
        "the peer must not record the msg1 that drew the resend"
    );
    assert!(heard, "A's heartbeat must authenticate at B");
}

/// The restart route: B holds a peering with A at another epoch, idle long
/// enough to be replaced, and A dials again. B tears the old peering down and
/// its msg2 for the fresh leg fails transiently; A's resend draws the stored
/// msg2, and B must install A on the fresh leg.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_responder_restarting_a_peering_installs_the_peer_when_its_stored_msg2_is_resent() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let tid = nodes[1].transport_id;
    let loopback = unplug(&mut nodes[1]).await;

    initiate_handshake(&mut nodes, 0, 1).await;
    let msg1 = queued_msg1(&mut nodes[1]);

    // B's old peering with A: keyed, at an epoch other than the one A's msg1
    // carries, at the address A's msg1 comes from, and idle for a minute so
    // the liveness gate lets the restart through.
    let stale_link = nodes[1].node.allocate_link_id();
    let idle_since = Node::now_ms().saturating_sub(60_000);
    let mut old = keyed_peer(
        &nodes[1].node,
        nodes[0].node.identity(),
        stale_link,
        idle_since,
    );
    old.set_current_addr(tid, msg1.remote_addr.clone());
    old.set_remote_epoch(Some([0xAA; 8]));
    nodes[1].node.peers.insert(a, old);
    nodes[1]
        .node
        .addr_to_link
        .insert((tid, msg1.remote_addr.clone()), stale_link);

    nodes[1].node.handle_msg1(msg1.clone()).await;
    let fresh_link = nodes[1]
        .node
        .addr_to_link
        .get(&(tid, msg1.remote_addr.clone()))
        .copied();
    assert!(
        nodes[1].node.get_peer(&a).is_none()
            && fresh_link.is_some_and(|l| l != stale_link && nodes[1].node.has_pending_leg(&l)),
        "precondition: B tore down the old peering and kept the fresh leg pending"
    );
    assert_eq!(
        deliver(&mut nodes[0]).await,
        0,
        "precondition: no msg2 reached A"
    );

    replug(&mut nodes[1], loopback).await;
    nodes[1].node.handle_msg1(msg1).await;
    assert!(
        deliver(&mut nodes[0]).await >= 1,
        "control: B's stored msg2 reached A"
    );
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "control: A completed on the stored msg2 and installed B"
    );

    let on_fresh = nodes[1]
        .node
        .get_peer(&a)
        .is_some_and(|p| Some(p.link_id()) == fresh_link);
    let heard = heard_at_b(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        on_fresh,
        "B sent its stored msg2 for the restarted peering successfully but did not install A \
         on the fresh leg"
    );
    assert!(heard, "A's heartbeat must authenticate at B");
}

/// Healthy path: with no send failure, B installs A on the first msg1 and
/// A's frames authenticate at B.
#[tokio::test]
async fn a_responder_whose_first_msg2_send_succeeds_installs_the_peer() {
    let mut nodes = linked_pair(Config::new(), Config::new()).await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    heartbeat(&mut nodes[0], &b).await;
    deliver(&mut nodes[1]).await;
    let heard = nodes[1].node.get_peer(&a).is_some_and(|p| p.is_heard());
    cleanup_nodes(&mut nodes).await;
    assert!(heard, "B installs A and authenticates its frames");
}
