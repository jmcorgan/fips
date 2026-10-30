//! A msg2 that does not authenticate leaves an initial (IK) dial's handshake
//! where it was, so the genuine msg2 can still complete it.
//!
//! The index a msg2 names travels in cleartext in our msg1, so anyone who saw
//! the msg1 can send a msg2 under it. These tests drive
//! [`PeerMachine::complete_handshake`] directly because the wire parser drops a
//! msg2 of the wrong length before it reaches the machine, so a short one
//! cannot be delivered from the node.
//!
//! An inbound leg whose first msg2 send failed transiently stays at
//! `ReceivedMsg1` with its index allocated. When a later send of its stored
//! msg2 succeeds the machine asks for the promotion a first send would have
//! asked for, unless the leg was never authorized, is already established,
//! or its identity is held on another link.

use super::*;
use crate::noise::HANDSHAKE_MSG2_SIZE;
use crate::{Identity, PeerIdentity};

/// An initiator that has sent msg1, and the genuine msg2 the responder answered
/// it with.
fn dial_with_genuine_msg2() -> (PeerMachine, Vec<u8>) {
    let initiator = Identity::generate();
    let responder = Identity::generate();
    let responder_id = PeerIdentity::from_pubkey_full(responder.pubkey_full());

    let mut ini = PeerMachine::new_outbound(LinkId::new(1), responder_id, 1000);
    ini.set_leg(HandshakeCrypto::new());
    let mut res = PeerMachine::new_inbound(LinkId::new(2), 1000);
    res.set_leg(HandshakeCrypto::new());

    let msg1 = ini
        .start_handshake(initiator.keypair(), [1; 8], 1100)
        .expect("msg1 is written");
    let msg2 = res
        .receive_handshake_init(responder.keypair(), [2; 8], &msg1, 1200)
        .expect("the responder answers msg1");
    (ini, msg2)
}

/// True when the leg still holds the handshake handle, i.e. the attempt can
/// still read a msg2.
fn handle_kept(machine: &PeerMachine) -> bool {
    machine
        .leg()
        .is_some_and(|leg| leg.noise_handshake.is_some())
}

/// Deliver `forged`, check it is refused with the handshake kept and nothing
/// else changed, then check the genuine msg2 still completes the session.
fn forged_then_genuine(forged: &[u8]) {
    let (mut ini, genuine) = dial_with_genuine_msg2();
    let activity = ini.conn_last_activity();

    assert!(
        ini.complete_handshake(forged, 1300).is_err(),
        "a msg2 that does not authenticate must be refused"
    );
    assert!(
        handle_kept(&ini),
        "a refused msg2 must leave the handshake in the leg"
    );
    assert!(!ini.has_session(), "a refused msg2 must not make a session");
    assert_eq!(
        ini.conn_remote_epoch(),
        None,
        "a refused msg2 must not set the remote epoch"
    );
    assert_eq!(
        ini.conn_last_activity(),
        activity,
        "a refused msg2 must not count as activity on the attempt"
    );

    ini.complete_handshake(&genuine, 1400)
        .expect("the genuine msg2 must still complete the handshake");
    assert!(ini.has_session(), "the genuine msg2 makes the session");
    assert_eq!(ini.conn_remote_epoch(), Some([2; 8]));
}

#[test]
fn a_too_short_msg2_keeps_the_handshake_for_the_genuine_one() {
    let (_, genuine) = dial_with_genuine_msg2();
    forged_then_genuine(&genuine[..HANDSHAKE_MSG2_SIZE - 1]);
}

#[test]
fn a_msg2_with_an_invalid_ephemeral_keeps_the_handshake_for_the_genuine_one() {
    // 0xFF is not a valid compressed-point prefix.
    forged_then_genuine(&[0xFF; HANDSHAKE_MSG2_SIZE]);
}

#[test]
fn a_garbage_full_length_msg2_keeps_the_handshake_for_the_genuine_one() {
    // A valid point followed by bytes that do not authenticate: the read gets
    // as far as both DH operations before the AEAD check fails.
    let mut forged = Identity::generate().pubkey_full().serialize().to_vec();
    forged.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
    forged_then_genuine(&forged);
}

#[test]
fn several_forged_msg2s_in_a_row_still_leave_the_genuine_one_readable() {
    let (mut ini, genuine) = dial_with_genuine_msg2();
    let mut garbage = Identity::generate().pubkey_full().serialize().to_vec();
    garbage.resize(HANDSHAKE_MSG2_SIZE, 0x5A);
    for forged in [
        &garbage[..],
        &[0xFF; HANDSHAKE_MSG2_SIZE][..],
        &[0u8; 3][..],
    ] {
        assert!(ini.complete_handshake(forged, 1300).is_err());
        assert!(handle_kept(&ini));
    }
    ini.complete_handshake(&genuine, 1400)
        .expect("the genuine msg2 must still complete the handshake");
    assert!(ini.has_session());
}

/// The inbound msg1 outcome of a fresh identity, as the shell's wire step
/// builds it.
fn wire_outcome(peer: PeerIdentity) -> WireOutcome {
    WireOutcome {
        peer_identity: peer,
        remote_epoch: Some([4; 8]),
        their_index: SessionIndex::new(0x77),
        msg2_payload: vec![0xAB; 8],
        msg1_digest: Msg1Digest::of(&[0xCD; 8]),
    }
}

/// The registry snapshot for an identity the node holds nothing for.
fn est_new_peer() -> EstablishSnapshot {
    EstablishSnapshot {
        has_existing_peer: false,
        existing_peer_epoch: None,
        replace: false,
        at_max_peers: false,
        has_pending_outbound_to_peer: false,
        silent_backoff: None,
    }
}

/// An inbound leg that has read a fresh identity's msg1, and that identity's
/// node address. With `authorize`, the late-ACL gate also passed, so the leg
/// holds its index and has asked for its first msg2 send.
fn inbound_leg(alloc: &mut IndexAllocator, authorize: bool) -> (PeerMachine, NodeAddr) {
    let peer = PeerIdentity::from_pubkey(Identity::generate().pubkey());
    let addr = *peer.node_addr();
    let link = LinkId::new(1);
    let mut m = PeerMachine::new_inbound(link, 0);
    let classified = m.step(
        PeerEvent::InboundMsg1 {
            link,
            wire: wire_outcome(peer),
            est: est_new_peer(),
        },
        100,
        alloc,
    );
    assert!(classified.is_empty(), "precondition: a new peer classifies");
    if authorize {
        let first = m.step(PeerEvent::Authorized, 100, alloc);
        assert_eq!(
            first.last(),
            Some(&PeerAction::PromoteToActive { link }),
            "precondition: the first send asks for promotion"
        );
    }
    (m, addr)
}

/// The state an inbound leg waits in for its msg2 to be sent.
fn received_msg1() -> PeerState {
    PeerState::Handshaking {
        link: LinkId::new(1),
        phase: HandshakePhase::ReceivedMsg1,
    }
}

#[test]
fn an_authorized_inbound_leg_asks_for_promotion_when_its_stored_msg2_is_resent() {
    let mut alloc = IndexAllocator::new();
    let (mut m, _) = inbound_leg(&mut alloc, true);
    let actions = m.step(PeerEvent::Msg2Resent { peer_held: false }, 200, &mut alloc);
    assert_eq!(
        actions,
        [PeerAction::PromoteToActive {
            link: LinkId::new(1)
        }]
    );
    assert_eq!(
        m.state(),
        received_msg1(),
        "the promotion feedback, not the resend, moves the state"
    );
}

#[test]
fn a_resent_msg2_does_not_promote_a_leg_that_holds_no_index() {
    let mut alloc = IndexAllocator::new();
    let (mut m, _) = inbound_leg(&mut alloc, false);
    let actions = m.step(PeerEvent::Msg2Resent { peer_held: false }, 200, &mut alloc);
    assert!(actions.is_empty(), "an unauthorized leg has sent nothing");
    assert_eq!(m.state(), received_msg1());
}

#[test]
fn a_resent_msg2_does_not_promote_while_the_peer_is_held_on_another_link() {
    let mut alloc = IndexAllocator::new();
    let (mut m, _) = inbound_leg(&mut alloc, true);
    let actions = m.step(PeerEvent::Msg2Resent { peer_held: true }, 200, &mut alloc);
    assert!(
        actions.is_empty(),
        "a held peer would turn the promotion into a cross-connection"
    );
    assert_eq!(m.state(), received_msg1());
}

#[test]
fn a_resent_msg2_does_not_promote_an_established_machine() {
    let mut alloc = IndexAllocator::new();
    let (mut m, addr) = inbound_leg(&mut alloc, true);
    m.step(
        PeerEvent::PromotionResolved {
            result: PromotionResult::Promoted(addr),
        },
        200,
        &mut alloc,
    );
    assert_eq!(m.state(), PeerState::Established { addr });
    let actions = m.step(PeerEvent::Msg2Resent { peer_held: false }, 300, &mut alloc);
    assert!(
        actions.is_empty(),
        "an established machine is not promoted again"
    );
}
