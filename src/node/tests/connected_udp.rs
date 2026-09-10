//! Per-peer connected UDP sockets against the in-line decrypt path.
//!
//! A `connect(2)`-ed UDP socket is pinned to one 5-tuple. When the peer
//! moves, the address the socket was opened against is gone, but the
//! socket is still installed and the send path prefers it over the
//! wildcard listen socket. `ActivePeer::set_current_addr` returns
//! whether the address actually changed precisely so the caller can
//! drop the stale socket, and both post-decrypt paths have to act on
//! that return: the decrypt-worker completion path
//! (`process_authentic_fmp_plaintext`) and the in-line one
//! (`handle_encrypted_frame`). These tests cover the in-line path,
//! which is the one the worker path's own coverage does not reach.
//!
//! `bool` carries no `#[must_use]`, so discarding the return here is
//! silent under `-D warnings`; the assertions below are what makes the
//! difference between binding it and dropping it observable.

use super::*;
use crate::noise::NoiseSession;
use crate::proto::fmp::wire::{build_encrypted, build_established_header, prepend_inner_header};

/// The address `seed_completed_connection` promotes a peer on, and so
/// the peer's `current_addr` before anything rotates it.
const PROMOTED_ADDR: &str = "127.0.0.1:5000";

/// The address the peer is made to move to.
const ROAMED_ADDR: &str = "127.0.0.1:5001";

/// Build a promoted peer and hand back the far side's Noise session.
///
/// [`seed_completed_connection`] runs every leg of the handshake and
/// then drops the responder, so nothing outside it can produce a frame
/// the node will actually authenticate. This is the same seeding with
/// the responder's session kept, which is what lets these tests reach
/// the post-decrypt side effects rather than stopping at the AEAD.
///
/// Returns the node, the peer's `NodeAddr`, the session index an
/// inbound frame must name to be routed to that peer, and the session
/// to encrypt those frames with.
fn promoted_peer_with_the_far_side_session(
    transport_id: TransportId,
) -> (Node, NodeAddr, SessionIndex, NoiseSession) {
    let mut node = make_node();
    let link_id = LinkId::new(1);

    let peer_identity_full = Identity::generate();
    // from_pubkey_full, not from_pubkey: the ECDH needs the parity bit.
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());

    let our_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(link_id, peer_identity, 1_000)
            .with_our_index(our_index)
            .with_their_index(SessionIndex::new(42))
            .with_transport_id(transport_id)
            .with_source_addr(TransportAddr::from_string(PROMOTED_ADDR)),
    )
    .unwrap();

    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let msg1 = node
        .peer_machines
        .get_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, 1_000)
        .unwrap();

    let mut responder = inbound_leg(LinkId::new(999), 1_000);
    let mut responder_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut responder_epoch);
    let msg2 = responder
        .receive_handshake_init(
            peer_identity_full.keypair(),
            responder_epoch,
            &msg1,
            None,
            1_000,
        )
        .unwrap();

    // XX, so msg2 does not finish the responder: it holds no session until it
    // has processed msg3. The line this came from ran IK, where the responder
    // was done at msg2 and the third leg did not exist.
    let (msg3, _negotiation) = node
        .peer_machines
        .get_mut(&link_id)
        .unwrap()
        .complete_handshake(&msg2, None, 1_000)
        .unwrap();

    responder
        .complete_handshake_msg3(&msg3, 1_000)
        .expect("the responder must accept a genuine msg3");

    let far_side_session = responder
        .take_session()
        .expect("the responder holds a session once it has processed msg3");

    node.promote_connection(link_id, peer_identity, 2_000)
        .unwrap();
    let node_addr = *peer_identity.node_addr();
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("a promoted peer carries the index it was allocated");

    (node, node_addr, our_index, far_side_session)
}

/// Encrypt one well-formed established frame from the far side.
///
/// The link message is a heartbeat (`0x51`), which the dispatcher
/// handles as a no-op — these tests are about the side effects that run
/// before the dispatch, so the message must not have any of its own.
fn far_side_frame(session: &mut NoiseSession, receiver_idx: SessionIndex) -> Vec<u8> {
    let inner = prepend_inner_header(0, &[0x51]);
    let counter = session.current_send_counter();
    let header = build_established_header(receiver_idx, counter, 0, inner.len() as u16);
    let ciphertext = session.encrypt_with_aad(&inner, &header).unwrap();
    build_encrypted(&header, &ciphertext)
}

/// **The defect.**
///
/// The in-line decrypt path called `set_current_addr` as a bare
/// statement and dropped its return, so a peer could roam, have its
/// `current_addr` updated, and keep a connected socket pinned to the
/// 5-tuple it had just left. The send path prefers that socket while it
/// is installed, so every frame after the move goes out to an address
/// the peer is no longer at.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_peer_that_roams_loses_the_connected_socket_pinned_to_the_address_it_left() {
    let transport_id = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(transport_id);

    install_connected_udp(&mut node, &node_addr, transport_id);
    assert!(
        node.get_peer(&node_addr).unwrap().connected_udp().is_some(),
        "precondition: the peer holds a connected socket before it moves"
    );

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string(ROAMED_ADDR),
        frame,
    ))
    .await;

    let peer = node
        .get_peer(&node_addr)
        .expect("the peer survives an authentic frame");
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(ROAMED_ADDR)),
        "precondition for the assertion below: the frame must have been \
         authenticated and the rotation recorded, or the test proves nothing"
    );
    assert!(
        peer.connected_udp().is_none(),
        "a socket pinned to the address the peer has left must not survive \
         the rotation"
    );
}

/// **The healthy path.**
///
/// A frame from the address the peer is already on changes nothing, so
/// the connected socket has to stay. A fix that cleared unconditionally
/// would tear down and reopen the socket on every single frame.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_frame_from_the_address_the_peer_is_already_on_keeps_the_connected_socket() {
    let transport_id = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(transport_id);

    install_connected_udp(&mut node, &node_addr, transport_id);

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        transport_id,
        TransportAddr::from_string(PROMOTED_ADDR),
        frame,
    ))
    .await;

    let peer = node
        .get_peer(&node_addr)
        .expect("the peer survives an authentic frame");
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(PROMOTED_ADDR)),
        "the peer has not moved"
    );
    assert!(
        peer.connected_udp().is_some(),
        "a frame from the address already in use must leave the socket alone"
    );
}
