//! A peer restart clears the end-to-end session with that peer, and the
//! clamp entry (`path_mtu_lookup`) that session tightened goes with it,
//! leaving the link seed, as when the idle purge or the handshake timeout
//! removes a session. A held entry has no deadline, so nothing else would
//! release it. Two paths detect a restart: our rekey msg2 revealing a new
//! startup epoch, and a promotion that replaces the active peer at one.

use super::*;
use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::tests::rekey_parity::{deliver, linked_pair, rekey_config, trigger_age};
use crate::node::tests::spanning_tree::{cleanup_nodes, restarted_node};
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG2};

/// Rekey interval for both ends of the pair.
const REKEY_AFTER_SECS: u64 = 60;

/// Seed a completed outbound leg on `link` to the known peer `peer`, whose
/// msg2 carries startup epoch `epoch`.
fn seedleg(
    node: &mut Node,
    link: LinkId,
    peer: &Identity,
    epoch: [u8; 8],
    at: u64,
) -> PeerIdentity {
    let identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let our_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(link, identity, at)
            .with_our_index(our_index)
            .with_their_index(SessionIndex::new(42 + link.as_u64() as u32))
            .with_transport_id(TransportId::new(1))
            .with_source_addr(TransportAddr::from_string("127.0.0.1:5000")),
    )
    .unwrap();
    let keypair = node.identity().keypair();
    let ours = node.startup_epoch();
    let msg1 = node
        .peer_machines
        .get_mut(&link)
        .unwrap()
        .start_handshake(keypair, ours, at)
        .unwrap();
    let mut responder = inbound_leg(LinkId::new(999), at);
    let msg2 = responder
        .receive_handshake_init(peer.keypair(), epoch, &msg1, at)
        .unwrap();
    node.peer_machines
        .get_mut(&link)
        .unwrap()
        .complete_handshake(&msg2, at)
        .unwrap();
    identity
}

#[tokio::test]
async fn a_peer_restart_revealed_by_our_rekey_releases_the_clamp_entry_of_the_session_it_clears() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let b_addr = *nodes[1].node.node_addr();
    let b_fips = crate::FipsAddress::from_node_addr(&b_addr);
    let seed = nodes[0].node.path_mtu_lookup_get(&b_fips);

    // A holds an end-to-end session with B, which tightened the clamp entry.
    let b_identity = nodes[1].node.identity().clone();
    let session = super::session::make_noise_session(nodes[0].node.identity(), &b_identity);
    nodes[0].node.sessions.insert(
        b_addr,
        SessionEntry::new(
            b_addr,
            b_identity.pubkey_full(),
            EndToEndState::Established(session),
            Node::now_ms(),
            true,
        ),
    );
    let tightened = seed.map_or(1200, |s| s - 100);
    nodes[0].node.path_mtu_lookup_insert(b_fips, tightened);

    let restarted = restarted_node(&nodes[1], rekey_config(REKEY_AFTER_SECS));
    drop(std::mem::replace(&mut nodes[1], restarted));
    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .test_backdate_session_established(trigger_age());
    nodes[0].node.check_rekey().await;
    assert!(
        nodes[0].node.get_peer(&b_addr).unwrap().rekey_in_progress(),
        "precondition: A started a rekey to the restarted B"
    );
    deliver(&mut nodes[1]).await;
    let mut queued: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    let at = queued
        .iter()
        .position(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG2))
        .expect("precondition: the restarted B's msg2 is queued at A");
    nodes[0].node.handle_msg2(queued.remove(at)).await;

    assert!(
        nodes[0].node.get_session(&b_addr).is_none(),
        "precondition: the restart detected at the rekey msg2 cleared the session"
    );
    assert_eq!(
        nodes[0].node.path_mtu_lookup_get(&b_fips),
        seed,
        "defect: the clamp entry the cleared session tightened (seed {seed:?}, tightened \
         {tightened}) must not outlive it"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn a_restart_promotion_releases_the_clamp_entry_of_the_session_it_clears() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_addr = *peer_full.node_addr();
    let peer_fips = crate::FipsAddress::from_node_addr(&peer_addr);

    let identity = seedleg(&mut node, LinkId::new(1), &peer_full, [1; 8], 1000);
    node.promote_connection(LinkId::new(1), identity, 1500)
        .unwrap();
    assert!(
        node.get_peer(&peer_addr).is_some(),
        "precondition: promoted"
    );

    let session = super::session::make_noise_session(node.identity(), &peer_full);
    node.sessions.insert(
        peer_addr,
        SessionEntry::new(
            peer_addr,
            peer_full.pubkey_full(),
            EndToEndState::Established(session),
            1000,
            true,
        ),
    );
    node.path_mtu_lookup_insert(peer_fips, 1180);
    assert_eq!(
        node.path_mtu_lookup_get(&peer_fips),
        Some(1180),
        "precondition: the session's tightened clamp entry is held"
    );

    // The peer restarts: a new link at a new startup epoch.
    let identity = seedleg(&mut node, LinkId::new(2), &peer_full, [2; 8], 2000);
    node.promote_connection(LinkId::new(2), identity, 2500)
        .unwrap();
    assert_eq!(
        node.get_peer(&peer_addr).map(|p| p.link_id()),
        Some(LinkId::new(2)),
        "precondition: the restarted link replaced the active peer"
    );
    assert!(
        node.get_session(&peer_addr).is_none(),
        "precondition: the restart promotion cleared the session"
    );

    // This node has no transport, so there is no link seed to restore.
    assert_eq!(
        node.path_mtu_lookup_get(&peer_fips),
        None,
        "defect: the clamp entry the cleared session tightened must not outlive it"
    );
}
