//! A same-epoch msg1 from an established peer that arrives off the peer's
//! established link, and copies of the msg1 a peering was set up from.
//!
//! Once a link is 30 s old, and 10 s have passed since its last rekey
//! cutover, a same-epoch msg1 from the peer is classified as a rekey. A peer
//! that is already linked and dials a second path sends a link-setup msg1
//! there; answered as a rekey on the established link, it arms a responder
//! pending the dialing peer never adopts, which refuses the peer's genuine
//! rekeys for the whole hold. These tests drive real msg1s through
//! `handle_msg1` from a second address or transport while the established
//! UDP link works, and replay a peering's own setup msg1 after the session
//! has aged.

use super::establish_chartests::{
    arm_local_rekey, craft_msg1_wire, establish_active_peer_via_msg1,
    register_udp_with_peer_socket, sender_with_addr_relation,
};
use super::*;
use tokio::time::timeout;

/// Whether a datagram reaches `sock` within 300 ms.
async fn receives(sock: &tokio::net::UdpSocket) -> bool {
    let mut buf = [0u8; 2048];
    timeout(Duration::from_millis(300), sock.recv_from(&mut buf))
        .await
        .is_ok()
}

/// Discard every datagram queued at `sock`.
async fn drain(sock: &tokio::net::UdpSocket) {
    let mut buf = [0u8; 2048];
    while timeout(Duration::from_millis(150), sock.recv_from(&mut buf))
        .await
        .is_ok()
    {}
}

/// A UDP socket standing in for a second address of the peer, and its
/// address.
async fn second_address() -> (tokio::net::UdpSocket, TransportAddr) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind second-address socket");
    let addr = TransportAddr::from_string(&sock.local_addr().unwrap().to_string());
    (sock, addr)
}

/// Deliver `data` to `node` as a msg1 that arrived on `transport_id` from
/// `remote_addr`.
async fn deliver_msg1(
    node: &mut Node,
    transport_id: TransportId,
    remote_addr: &TransportAddr,
    data: Vec<u8>,
    ts: u64,
) {
    node.handle_msg1(ReceivedPacket {
        transport_id,
        remote_addr: remote_addr.clone(),
        data,
        timestamp_ms: ts,
    })
    .await;
}

/// The node's count of handshake msg1s refused as `BadState`.
fn bad_state(node: &Node) -> u64 {
    node.stats().handshake.bad_state
}

/// A node peered over UDP transport 1 with a fresh sender at socket A, the
/// link and session aged past the 30 s rekey floor, and a second socket B
/// reachable on `second_transport`: transport 1 itself, or a second UDP
/// transport the node also runs.
struct SecondPath {
    node: Node,
    sender: Identity,
    sender_addr: NodeAddr,
    epoch: [u8; 8],
    link_transport: TransportId,
    sock_a: tokio::net::UdpSocket,
    addr_a: TransportAddr,
    second_transport: TransportId,
    sock_b: tokio::net::UdpSocket,
    addr_b: TransportAddr,
}

/// Build a [`SecondPath`] whose sender is drawn by `sender_for` and whose
/// second address is on another transport when `other_transport` holds.
async fn second_path(
    other_transport: bool,
    sender_for: impl FnOnce(&Node) -> Identity,
) -> SecondPath {
    let mut node = make_node();
    let link_transport = TransportId::new(1);
    let (sock_a, addr_a) = register_udp_with_peer_socket(&mut node, link_transport).await;
    let (second_transport, (sock_b, addr_b)) = if other_transport {
        let tid = TransportId::new(2);
        (tid, register_udp_with_peer_socket(&mut node, tid).await)
    } else {
        (link_transport, second_address().await)
    };
    let sender = sender_for(&node);
    let epoch = [9u8; 8];
    let sender_addr = establish_active_peer_via_msg1(
        &mut node,
        &sender,
        epoch,
        link_transport,
        &addr_a,
        &sock_a,
        1000,
    )
    .await;
    {
        let p = node
            .get_peer(&sender_addr)
            .expect("precondition: peer established");
        assert_eq!(
            p.transport_id(),
            Some(link_transport),
            "precondition: the link is on transport 1"
        );
        assert_eq!(
            p.current_addr(),
            Some(&addr_a),
            "precondition: the link is at socket A"
        );
    }
    node.get_peer_mut(&sender_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));
    SecondPath {
        node,
        sender,
        sender_addr,
        epoch,
        link_transport,
        sock_a,
        addr_a,
        second_transport,
        sock_b,
        addr_b,
    }
}

/// Stop every transport the node holds.
async fn stop_all(node: &mut Node) {
    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Send a same-epoch msg1 from the second address, then a fresh msg1 on the
/// established link, and check the first is refused outright and the second
/// still completes as a rekey.
async fn second_path_then_genuine_rekey(other_transport: bool) {
    let mut s = second_path(other_transport, |_| Identity::generate()).await;

    let bad_before = bad_state(&s.node);
    let data = craft_msg1_wire(&s.node, &s.sender, s.epoch, SessionIndex::new(0x2222), 2000);
    deliver_msg1(&mut s.node, s.second_transport, &s.addr_b, data, 2000).await;

    assert!(
        s.node
            .get_peer(&s.sender_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "a msg1 off the established link must arm no pending"
    );
    assert!(
        !receives(&s.sock_a).await,
        "nothing may answer the second-path msg1 on the established link"
    );
    assert!(
        !receives(&s.sock_b).await,
        "nothing may answer the second-path msg1 at its source"
    );
    assert_eq!(
        bad_state(&s.node),
        bad_before + 1,
        "the second-path msg1 must be admitted and refused at classification"
    );

    let genuine = SessionIndex::new(0x3333);
    let data = craft_msg1_wire(&s.node, &s.sender, s.epoch, genuine, 3000);
    deliver_msg1(&mut s.node, s.link_transport, &s.addr_a, data, 3000).await;
    assert_eq!(
        s.node
            .get_peer(&s.sender_addr)
            .unwrap()
            .pending_their_index(),
        Some(genuine),
        "the peer's genuine rekey on the link must arm the pending"
    );
    assert!(
        receives(&s.sock_a).await,
        "the genuine rekey must be answered on the established link"
    );

    stop_all(&mut s.node).await;
}

/// A peer linked over UDP that also reaches us on another transport sends a
/// link-setup msg1 there after the session is 30 s old. It must arm no
/// pending and draw nothing, and the peer's next genuine rekey on the link
/// must still complete.
#[tokio::test]
async fn a_second_path_msg1_on_an_aged_session_arms_no_pending_and_a_genuine_rekey_then_completes()
{
    second_path_then_genuine_rekey(true).await;
}

/// The same from a second address on the link's own transport.
#[tokio::test]
async fn a_second_address_msg1_on_the_same_transport_arms_no_pending_and_a_genuine_rekey_then_completes()
 {
    second_path_then_genuine_rekey(false).await;
}

/// With our own rekey in flight and the sender on the winning side of the
/// dual-initiation tie-break, a second-path msg1 must not make us abandon
/// ours: it is not a rekey of this link.
#[tokio::test]
async fn a_second_path_msg1_does_not_make_us_abandon_our_own_rekey() {
    let mut s = second_path(true, |node| sender_with_addr_relation(node, false)).await;
    assert!(
        *s.node.node_addr() > s.sender_addr,
        "precondition: the sender wins the tie-break"
    );
    let sender_addr = s.sender_addr;
    let rekey_index = arm_local_rekey(&mut s.node, &s.sender, &sender_addr);
    assert!(
        s.node.get_peer(&sender_addr).unwrap().rekey_in_progress(),
        "precondition: our rekey is in flight"
    );

    let bad_before = bad_state(&s.node);
    let data = craft_msg1_wire(&s.node, &s.sender, s.epoch, SessionIndex::new(0x2222), 2000);
    deliver_msg1(&mut s.node, s.second_transport, &s.addr_b, data, 2000).await;

    let p = s.node.get_peer(&sender_addr).unwrap();
    assert!(
        p.rekey_in_progress(),
        "our own rekey must survive a second-path msg1"
    );
    let key = rekey_index.as_u32();
    assert!(
        s.node.peers_by_index.contains_key(&key) && s.node.pending_outbound.contains_key(&key),
        "our rekey's index must stay registered"
    );
    assert!(
        p.pending_new_session().is_none(),
        "a msg1 off the established link must arm no pending"
    );
    assert_eq!(
        bad_state(&s.node),
        bad_before + 1,
        "the second-path msg1 must be admitted and refused at classification"
    );

    stop_all(&mut s.node).await;
}

/// A copy of the rekey msg1 that armed the pending we hold, arriving from a
/// second address on the link's transport, draws nothing anywhere and leaves
/// the pending as it was.
#[tokio::test]
async fn a_copy_of_a_held_rekey_msg1_from_a_second_address_draws_nothing_and_keeps_the_pending() {
    let mut s = second_path(false, |_| Identity::generate()).await;

    let data = craft_msg1_wire(&s.node, &s.sender, s.epoch, SessionIndex::new(0x4444), 2000);
    deliver_msg1(&mut s.node, s.link_transport, &s.addr_a, data.clone(), 2000).await;
    let held = s
        .node
        .get_peer(&s.sender_addr)
        .unwrap()
        .pending_our_index()
        .expect("precondition: the rekey msg1 on the link arms a pending");
    assert!(
        receives(&s.sock_a).await,
        "precondition: the rekey msg2 goes out on the link"
    );
    drain(&s.sock_a).await;

    let bad_before = bad_state(&s.node);
    deliver_msg1(&mut s.node, s.second_transport, &s.addr_b, data, 2000).await;

    assert!(
        !receives(&s.sock_a).await,
        "a copy off the established link must not draw the held msg2 on the link"
    );
    assert!(
        !receives(&s.sock_b).await,
        "a copy must draw nothing at its source"
    );
    assert_eq!(
        s.node.get_peer(&s.sender_addr).unwrap().pending_our_index(),
        Some(held),
        "the held pending must be unchanged"
    );
    assert_eq!(
        bad_state(&s.node),
        bad_before + 1,
        "the copy must be refused at classification"
    );

    stop_all(&mut s.node).await;
}

/// How the peering whose setup msg1 is replayed was formed.
#[derive(Clone, Copy, Debug)]
enum Setup {
    /// A net-new inbound promotion.
    Promote,
    /// A promotion at one epoch, then the peer's restart msg1 at another,
    /// which replaces the peering.
    Restart,
}

/// Form the peering as `setup` says, age it 31 s, replay its setup msg1 on
/// the link, and report what went wrong, if anything.
async fn replay_setup_msg1(setup: Setup) -> Vec<String> {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (sock_a, addr_a) = register_udp_with_peer_socket(&mut node, tid).await;
    let sender = Identity::generate();
    let sender_addr = *PeerIdentity::from_pubkey_full(sender.pubkey_full()).node_addr();
    let first_epoch = [1u8; 8];
    let restart_epoch = [2u8; 8];

    // The chartest timestamps (1000, 2000) are far older than the node's
    // clock, so the peering an epoch restart replaces counts as idle and the
    // restart is accepted.
    let setup_msg1 = match setup {
        Setup::Promote => {
            let data = craft_msg1_wire(&node, &sender, first_epoch, SessionIndex::new(0x01), 1000);
            deliver_msg1(&mut node, tid, &addr_a, data.clone(), 1000).await;
            data
        }
        Setup::Restart => {
            establish_active_peer_via_msg1(
                &mut node,
                &sender,
                first_epoch,
                tid,
                &addr_a,
                &sock_a,
                1000,
            )
            .await;
            let link_before = node.get_peer(&sender_addr).unwrap().link_id();
            let data =
                craft_msg1_wire(&node, &sender, restart_epoch, SessionIndex::new(0x02), 2000);
            deliver_msg1(&mut node, tid, &addr_a, data.clone(), 2000).await;
            let p = node
                .get_peer(&sender_addr)
                .expect("precondition: the restart re-peers");
            assert_eq!(
                p.remote_epoch(),
                Some(restart_epoch),
                "precondition: the restart msg1 replaced the peering"
            );
            assert_ne!(
                p.link_id(),
                link_before,
                "precondition: the restart formed a new link"
            );
            data
        }
    };
    assert!(
        node.get_peer(&sender_addr).is_some(),
        "precondition: {setup:?} formed the peering"
    );
    drain(&sock_a).await;
    node.get_peer_mut(&sender_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));

    deliver_msg1(&mut node, tid, &addr_a, setup_msg1, 3000).await;

    let mut found = Vec::new();
    if node
        .get_peer(&sender_addr)
        .is_some_and(|p| p.pending_new_session().is_some())
    {
        found.push(format!(
            "{setup:?}: the replayed link-setup msg1 armed a pending"
        ));
    }
    if receives(&sock_a).await {
        found.push(format!(
            "{setup:?}: the replayed link-setup msg1 drew an answer"
        ));
    }
    stop_all(&mut node).await;
    found
}

/// A copy of the msg1 a peering was set up from, replayed on the link once
/// the session is past the 30 s rekey floor, is refused: it arms no pending
/// and draws nothing. Both promotion paths, the net-new one and the restart
/// one, record it.
#[tokio::test]
async fn a_link_setup_msg1_replayed_on_the_link_after_30_s_is_refused_and_arms_no_pending() {
    let mut found = Vec::new();
    for setup in [Setup::Promote, Setup::Restart] {
        found.extend(replay_setup_msg1(setup).await);
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// Form the peering as `setup` says, with the peering a restart replaces
/// aged 31 s, then backdate the new peering 12 s and resend its setup msg1
/// on the link. Report what went wrong, if anything.
async fn resend_setup_msg1_12_s_after_promotion(setup: Setup) -> Vec<String> {
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (sock_a, addr_a) = register_udp_with_peer_socket(&mut node, tid).await;
    let sender = Identity::generate();
    let sender_addr = *PeerIdentity::from_pubkey_full(sender.pubkey_full()).node_addr();
    let first_epoch = [1u8; 8];
    let restart_epoch = [2u8; 8];

    let setup_msg1 = match setup {
        Setup::Promote => {
            let data = craft_msg1_wire(&node, &sender, first_epoch, SessionIndex::new(0x01), 1000);
            deliver_msg1(&mut node, tid, &addr_a, data.clone(), 1000).await;
            data
        }
        Setup::Restart => {
            establish_active_peer_via_msg1(
                &mut node,
                &sender,
                first_epoch,
                tid,
                &addr_a,
                &sock_a,
                1000,
            )
            .await;
            node.get_peer_mut(&sender_addr)
                .unwrap()
                .test_backdate_session_established(Duration::from_secs(31));
            let link_before = node.get_peer(&sender_addr).unwrap().link_id();
            let data =
                craft_msg1_wire(&node, &sender, restart_epoch, SessionIndex::new(0x02), 2000);
            deliver_msg1(&mut node, tid, &addr_a, data.clone(), 2000).await;
            assert_ne!(
                node.get_peer(&sender_addr)
                    .expect("precondition: the restart re-peers")
                    .link_id(),
                link_before,
                "precondition: the restart formed a new link"
            );
            data
        }
    };
    drain(&sock_a).await;
    node.get_peer_mut(&sender_addr)
        .expect("precondition: the peering was formed")
        .test_backdate_session_established(Duration::from_secs(12));
    let bad_before = bad_state(&node);

    deliver_msg1(&mut node, tid, &addr_a, setup_msg1, 3000).await;

    let mut found = Vec::new();
    if node
        .get_peer(&sender_addr)
        .is_some_and(|p| p.pending_new_session().is_some())
    {
        found.push(format!("{setup:?}: the setup msg1 resend armed a pending"));
    }
    if !receives(&sock_a).await {
        found.push(format!(
            "{setup:?}: the setup msg1 resend drew no stored msg2"
        ));
    }
    if bad_state(&node) != bad_before {
        found.push(format!("{setup:?}: the setup msg1 resend was refused"));
    }
    stop_all(&mut node).await;
    found
}

/// Within 30 s of a promotion, a resend of the setup msg1 draws the stored
/// msg2, on a net-new peering and on one that replaced an aged peering at
/// the peer's restart: the new peering's link is as young as it is.
#[tokio::test]
async fn a_resend_of_the_setup_msg1_within_30_s_of_a_net_new_or_restart_promotion_draws_the_stored_msg2_even_when_the_replaced_peering_was_aged()
 {
    let mut found = Vec::new();
    for setup in [Setup::Promote, Setup::Restart] {
        found.extend(resend_setup_msg1_12_s_after_promotion(setup).await);
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}
