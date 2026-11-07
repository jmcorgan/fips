//! A msg2 that does not complete an initial (XX) dial leaves the dial's
//! handshake and carrier where they were, so the genuine msg2 can still
//! complete it.
//!
//! The index a msg2 names travels in cleartext in our msg1, so anyone who saw
//! the msg1 can send a msg2 under it, and under XX any keyed node that saw it
//! can answer with a msg2 that reads correctly under its own static. These
//! tests drive [`PeerMachine::complete_handshake`] directly: the wire parser
//! drops a msg2 shorter than the wire minimum before it reaches the machine,
//! so a short one cannot be delivered from the node.

use super::*;
use crate::noise::HANDSHAKE_MSG2_SIZE;
use crate::proto::fmp::DialMsg2Snapshot;
use crate::{Identity, PeerIdentity};

/// A named dial that has sent msg1: the initiator's machine, the msg1, the
/// identity it dialed, and that peer's keys.
struct Dial {
    ini: PeerMachine,
    msg1: Vec<u8>,
    dialed: PeerIdentity,
    responder: Identity,
}

fn dial() -> Dial {
    let initiator = Identity::generate();
    let responder = Identity::generate();
    let dialed = PeerIdentity::from_pubkey_full(responder.pubkey_full());

    let mut ini = PeerMachine::new_outbound(LinkId::new(1), Some(dialed), LegStamp::at(1000));
    ini.set_leg(HandshakeCrypto::new());
    let msg1 = ini
        .start_handshake(initiator.keypair(), [1; 8], LegStamp::at(1100))
        .expect("msg1 is written");
    Dial {
        ini,
        msg1,
        dialed,
        responder,
    }
}

/// The msg2 `answerer` sends in reply to `msg1`, with epoch `epoch`.
fn answer(answerer: &Identity, msg1: &[u8], epoch: [u8; 8]) -> Vec<u8> {
    let mut res = PeerMachine::new_inbound(LinkId::new(2), LegStamp::at(1000));
    res.set_leg(HandshakeCrypto::new());
    res.receive_handshake_init(answerer.keypair(), epoch, msg1, None, LegStamp::at(1200))
        .expect("the answerer reads msg1 and writes msg2")
}

/// The node's own dial-identity decision for a dial that named `dialed`.
fn gate(dialed: &PeerIdentity) -> impl FnOnce(NodeAddr) -> DialMsg2Decision {
    let dialed_peer = Some(*dialed.node_addr());
    move |learned_peer| {
        Fmp::new().dial_outbound(&DialMsg2Snapshot {
            dialed_peer,
            learned_peer,
        })
    }
}

/// What the attempt looks like, for comparing before and after a refused msg2.
fn snapshot(ini: &PeerMachine) -> (bool, bool, Option<NodeAddr>, Option<[u8; 8]>, u64) {
    (
        ini.leg().is_some_and(|leg| leg.noise_handshake.is_some()),
        ini.has_session(),
        ini.conn_expected_identity().map(|id| *id.node_addr()),
        ini.conn_remote_epoch(),
        ini.conn_last_activity(),
    )
}

/// Deliver the msg2 `refused` builds, check it comes back as `Unreadable`
/// with the attempt unchanged, then check the genuine msg2 still completes the
/// session.
fn unreadable_then_genuine(refused: impl FnOnce(&[u8]) -> Vec<u8>) {
    let mut d = dial();
    let genuine = answer(&d.responder, &d.msg1, [2; 8]);
    let refused = refused(&genuine);
    let before = snapshot(&d.ini);

    let step = d
        .ini
        .complete_handshake(&refused, None, LegStamp::at(1300), gate(&d.dialed))
        .expect("a refused msg2 leaves the leg able to continue");
    assert!(
        matches!(step, DialMsg2Step::Unreadable(_)),
        "a msg2 that does not read must be Unreadable, got {step:?}"
    );
    assert_eq!(
        snapshot(&d.ini),
        before,
        "a refused msg2 must leave the handshake in the leg and the carrier untouched"
    );

    genuine_completes(&mut d, &genuine);
}

/// The genuine msg2 completes the session under the dialed identity.
fn genuine_completes(d: &mut Dial, genuine: &[u8]) {
    let step = d
        .ini
        .complete_handshake(genuine, None, LegStamp::at(1400), gate(&d.dialed))
        .expect("the genuine msg2 completes the handshake");
    assert!(
        matches!(step, DialMsg2Step::Completed(..)),
        "the genuine msg2 must complete, got {step:?}"
    );
    assert!(d.ini.has_session(), "the genuine msg2 makes the session");
    assert_eq!(
        d.ini.conn_expected_identity().map(|id| *id.node_addr()),
        Some(*d.dialed.node_addr())
    );
    assert_eq!(d.ini.conn_remote_epoch(), Some([2; 8]));
    assert_eq!(d.ini.conn_last_activity(), 1400);
}

#[test]
fn a_too_short_msg2_is_unreadable_and_keeps_the_handshake() {
    unreadable_then_genuine(|genuine| genuine[..HANDSHAKE_MSG2_SIZE - 1].to_vec());
}

#[test]
fn a_msg2_with_an_invalid_ephemeral_is_unreadable_and_keeps_the_handshake() {
    // 0xFF is not a valid compressed-point prefix.
    unreadable_then_genuine(|_| vec![0xFF; HANDSHAKE_MSG2_SIZE]);
}

#[test]
fn a_garbage_full_length_msg2_is_unreadable_and_keeps_the_handshake() {
    // A valid point followed by bytes that do not authenticate: the read gets
    // as far as both DH operations before the AEAD check fails.
    unreadable_then_genuine(|_| {
        let mut forged = Identity::generate().pubkey_full().serialize().to_vec();
        forged.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
        forged
    });
}

#[test]
fn a_msg2_whose_negotiation_payload_does_not_decrypt_is_unreadable_and_keeps_the_handshake() {
    // The genuine base msg2 reads; the appended payload does not. The read
    // that succeeded has to be undone as well.
    unreadable_then_genuine(|genuine| {
        let mut forged = genuine.to_vec();
        forged.extend_from_slice(&[0x5A; 40]);
        forged
    });
}

#[test]
fn an_impostor_msg2_is_rejected_and_keeps_the_dialed_identity() {
    let mut d = dial();
    let genuine = answer(&d.responder, &d.msg1, [2; 8]);
    let impostor = Identity::generate();
    let impostor_addr = *PeerIdentity::from_pubkey_full(impostor.pubkey_full()).node_addr();
    let forged = answer(&impostor, &d.msg1, [3; 8]);
    let before = snapshot(&d.ini);

    let step = d
        .ini
        .complete_handshake(&forged, None, LegStamp::at(1300), gate(&d.dialed))
        .expect("a rejected msg2 leaves the leg able to continue");
    match step {
        DialMsg2Step::Rejected {
            reason: DialMsg2Reject::StaticMismatch,
            learned_peer,
        } => assert_eq!(learned_peer, impostor_addr, "the reject names the impostor"),
        other => panic!("an impostor's msg2 must be Rejected, got {other:?}"),
    }
    assert_eq!(
        snapshot(&d.ini),
        before,
        "a rejected msg2 must leave the handshake in the leg, the expected \
         identity at the dialed peer, and no session, epoch or activity"
    );

    genuine_completes(&mut d, &genuine);
}

#[test]
fn several_refused_msg2s_in_a_row_still_leave_the_genuine_one_readable() {
    let mut d = dial();
    let genuine = answer(&d.responder, &d.msg1, [2; 8]);
    let impostor = answer(&Identity::generate(), &d.msg1, [3; 8]);
    let mut garbage = Identity::generate().pubkey_full().serialize().to_vec();
    garbage.resize(HANDSHAKE_MSG2_SIZE, 0x5A);
    for refused in [&impostor[..], &garbage[..], &[0u8; 3][..], &impostor[..]] {
        let step = d
            .ini
            .complete_handshake(refused, None, LegStamp::at(1300), gate(&d.dialed))
            .expect("a refused msg2 leaves the leg able to continue");
        assert!(!matches!(step, DialMsg2Step::Completed(..)));
        assert!(d.ini.leg().is_some_and(|leg| leg.noise_handshake.is_some()));
    }
    genuine_completes(&mut d, &genuine);
}

#[test]
fn an_anonymous_dial_accepts_whoever_answers() {
    let initiator = Identity::generate();
    let answerer = Identity::generate();
    let answerer_addr = *PeerIdentity::from_pubkey_full(answerer.pubkey_full()).node_addr();
    let mut ini = PeerMachine::new_outbound(LinkId::new(1), None, LegStamp::at(1000));
    ini.set_leg(HandshakeCrypto::new());
    let msg1 = ini
        .start_handshake(initiator.keypair(), [1; 8], LegStamp::at(1100))
        .expect("msg1 is written");
    let msg2 = answer(&answerer, &msg1, [2; 8]);

    let step = ini
        .complete_handshake(&msg2, None, LegStamp::at(1300), move |learned_peer| {
            Fmp::new().dial_outbound(&DialMsg2Snapshot {
                dialed_peer: None,
                learned_peer,
            })
        })
        .expect("the answer completes the handshake");
    assert!(matches!(step, DialMsg2Step::Completed(..)));
    assert_eq!(
        ini.conn_expected_identity().map(|id| *id.node_addr()),
        Some(answerer_addr),
        "an anonymous leg learns its identity from the msg2"
    );
}
