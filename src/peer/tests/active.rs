//! Tests for how a cross-connection swap in `ActivePeer::replace_session`
//! (`src/peer/active.rs`) treats the link's MMP state.

use super::*;
use crate::Identity;
use crate::noise::HandshakeState;

/// Complete an IK handshake and return the (initiator, responder) sessions.
fn ik_session_pair() -> (NoiseSession, NoiseSession) {
    let initiator_id = Identity::generate();
    let responder_id = Identity::generate();
    let mut initiator =
        HandshakeState::new_initiator(initiator_id.keypair(), responder_id.pubkey_full());
    initiator.set_local_epoch([0xA1; 8]);
    let mut responder = HandshakeState::new_responder(responder_id.keypair());
    responder.set_local_epoch([0xB2; 8]);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    (
        initiator.into_session().unwrap(),
        responder.into_session().unwrap(),
    )
}

/// Record `frames` link frames at counters `from..from + frames` on `peer`'s
/// receiver-side MMP observer.
fn record_link_frames(peer: &mut ActivePeer, from: u64, frames: u64) {
    let now = crate::time::mono_ms();
    let mmp = peer.mmp_mut().expect("the test peer holds link MMP state");
    for counter in from..from + frames {
        mmp.receiver
            .record_recv(counter, counter as u32, 100, false, now);
    }
}

/// When FMP resolves crossed dials by moving the link onto another session,
/// the node resets the link's counter-derived MMP state as at a cutover
/// (FRC-1202 Section 4.7). The new session's counter starts at 0, so a report
/// built after the swap must count from the new session alone.
#[test]
fn a_cross_connection_swap_resets_the_link_mmp_observer_as_a_cutover_does() {
    let (_send, current) = ik_session_pair();
    let identity = PeerIdentity::from_pubkey(Identity::generate().pubkey());
    let mut peer = ActivePeer::with_session(
        identity,
        LinkId::new(1),
        1_000,
        current,
        SessionIndex::new(1),
        SessionIndex::new(2),
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:9000"),
        LinkStats::new(),
        true,
        &MmpConfig::default(),
        None,
    );
    record_link_frames(&mut peer, 0, 200);

    let (_send, swap) = ik_session_pair();
    peer.replace_session(swap, SessionIndex::new(7), SessionIndex::new(8));
    assert_eq!(
        peer.our_index(),
        Some(SessionIndex::new(7)),
        "setup: swapped"
    );

    record_link_frames(&mut peer, 0, 5);
    let report = peer
        .mmp_mut()
        .expect("link MMP state")
        .receiver
        .build_report(crate::time::mono_ms())
        .expect("frames were recorded");
    assert_eq!(
        report.highest_counter, 4,
        "highest_counter counts from the new session"
    );
    assert_eq!(
        report.cumulative_reorder_count, 0,
        "the new session's frames are not counted as reordered"
    );
}
