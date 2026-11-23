//! Tests for the handshake entry (`src/peer/handshake.rs`): the Noise
//! handshake operations on an entry with its crypto attached, and the msg2
//! that does not complete an initial (XX) dial.
//!
//! A msg2 that does not complete an initial dial leaves the dial's handshake
//! and carrier where they were, so the genuine msg2 can still complete it.
//!
//! The index a msg2 names travels in cleartext in our msg1, so anyone who saw
//! the msg1 can send a msg2 under it, and under XX any keyed node that saw it
//! can answer with a msg2 that reads correctly under its own static. These
//! tests drive [`Handshake::complete_handshake`] directly: the wire parser
//! drops a msg2 shorter than the wire minimum before it reaches the entry,
//! so a short one cannot be delivered from the node.

use super::*;
use crate::noise::HANDSHAKE_MSG2_SIZE;
use crate::proto::fmp::{DialMsg2Snapshot, Fmp};
use crate::{Identity, PeerIdentity};

/// A named dial that has sent msg1: the initiator's entry, the msg1, the
/// identity it dialed, and that peer's keys.
struct Dial {
    ini: Handshake,
    msg1: Vec<u8>,
    dialed: PeerIdentity,
    responder: Identity,
}

fn dial() -> Dial {
    let initiator = Identity::generate();
    let responder = Identity::generate();
    let dialed = PeerIdentity::from_pubkey_full(responder.pubkey_full());

    let mut ini = Handshake::new_outbound(LinkId::new(1), Some(dialed), LegStamp::at(1000));
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
    let mut res = Handshake::new_inbound(LinkId::new(2), LegStamp::at(1000));
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
fn snapshot(ini: &Handshake) -> (bool, bool, Option<NodeAddr>, Option<[u8; 8]>, u64) {
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
    let mut ini = Handshake::new_outbound(LinkId::new(1), None, LegStamp::at(1000));
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

// The Noise handshake operations on an entry with its crypto attached.

fn make_peer_identity() -> PeerIdentity {
    let identity = Identity::generate();
    PeerIdentity::from_pubkey(identity.pubkey())
}

fn make_keypair() -> Keypair {
    let identity = Identity::generate();
    identity.keypair()
}

fn make_epoch() -> [u8; 8] {
    let mut epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut epoch);
    epoch
}

fn outbound_leg(
    link_id: LinkId,
    expected_identity: PeerIdentity,
    current_time_ms: u64,
) -> Handshake {
    let mut entry = Handshake::new_outbound(
        link_id,
        Some(expected_identity),
        LegStamp::at(current_time_ms),
    );
    entry.set_leg(HandshakeCrypto::new());
    entry
}

fn inbound_leg(link_id: LinkId, current_time_ms: u64) -> Handshake {
    let mut entry = Handshake::new_inbound(link_id, LegStamp::at(current_time_ms));
    entry.set_leg(HandshakeCrypto::new());
    entry
}

#[test]
fn test_outbound_connection() {
    let identity = make_peer_identity();
    let conn = outbound_leg(LinkId::new(1), identity, 1000);

    assert!(conn.conn_is_outbound());
    assert!(!conn.conn_is_inbound());
    assert!(!conn.has_session());
    assert!(conn.conn_expected_identity().is_some());
    assert_eq!(conn.conn_started_at(), 1000);
}

#[test]
fn test_inbound_connection() {
    let conn = inbound_leg(LinkId::new(2), 2000);

    assert!(conn.conn_is_inbound());
    assert!(!conn.conn_is_outbound());
    assert!(!conn.has_session());
    assert!(conn.conn_expected_identity().is_none());
    assert_eq!(conn.conn_started_at(), 2000);
}

#[test]
fn test_full_handshake_flow() {
    // Create identities
    let initiator_identity = Identity::generate();
    let responder_identity = Identity::generate();

    let initiator_keypair = initiator_identity.keypair();
    let responder_keypair = responder_identity.keypair();
    let initiator_epoch = make_epoch();
    let responder_epoch = make_epoch();

    // Use from_pubkey_full to preserve parity for ECDH
    let responder_peer_id = PeerIdentity::from_pubkey_full(responder_identity.pubkey_full());

    // Create connections
    let mut initiator_conn = outbound_leg(LinkId::new(1), responder_peer_id, 1000);
    let mut responder_conn = inbound_leg(LinkId::new(2), 1000);

    // Initiator starts XX handshake
    let msg1 = initiator_conn
        .start_handshake(initiator_keypair, initiator_epoch, LegStamp::at(1100))
        .unwrap();
    // Post-msg1 the initiator holds an in-flight handshake, not yet a session.
    assert!(!initiator_conn.has_session());

    // Responder processes msg1 and sends msg2 (XX: does NOT complete yet)
    let msg2 = responder_conn
        .receive_handshake_init(
            responder_keypair,
            responder_epoch,
            &msg1,
            None,
            LegStamp::at(1200),
        )
        .unwrap();
    // XX: the responder parks awaiting msg3 — it holds an in-flight
    // handshake, not yet a session (the deleted phase was `ReceivedMsg1`).
    assert!(!responder_conn.has_session());
    // Responder does NOT know initiator's identity yet (XX property)
    assert!(responder_conn.conn_expected_identity().is_none());

    // Initiator processes msg2 and generates msg3
    let (msg3, _neg) = initiator_conn
        .complete_handshake_accepting(&msg2, None, LegStamp::at(1300))
        .unwrap();
    // The initiator completes at msg3 generation: it now holds a session.
    assert!(initiator_conn.has_session());

    // Initiator learned responder's identity from msg2
    let discovered = initiator_conn.conn_expected_identity().unwrap();
    assert_eq!(discovered.pubkey(), responder_identity.pubkey());
    assert_eq!(initiator_conn.conn_remote_epoch(), Some(responder_epoch));

    // Responder processes msg3 (completes handshake): it now holds a session.
    let _neg = responder_conn
        .complete_handshake_msg3(&msg3, LegStamp::at(1400))
        .unwrap();
    assert!(responder_conn.has_session());

    // Responder learned initiator's identity from msg3
    let discovered = responder_conn.conn_expected_identity().unwrap();
    assert_eq!(discovered.pubkey(), initiator_identity.pubkey());
    assert_eq!(responder_conn.conn_remote_epoch(), Some(initiator_epoch));

    // Both have sessions
    assert!(initiator_conn.has_session());
    assert!(responder_conn.has_session());

    // Take and verify sessions work
    let mut init_session = initiator_conn.take_session().unwrap();
    let mut resp_session = responder_conn.take_session().unwrap();

    // Encrypt/decrypt test
    let plaintext = b"test message";
    let ciphertext = init_session.encrypt(plaintext).unwrap();
    let decrypted = resp_session.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Non-zero bytes left in a leg slot, read in place.
#[cfg(not(debug_assertions))]
fn leg_slot_nonzero_bytes(slot: &Option<HandshakeCrypto>) -> usize {
    let base = (slot as *const Option<HandshakeCrypto>).cast::<u8>();
    (0..std::mem::size_of::<Option<HandshakeCrypto>>())
        // SAFETY: `base` comes from a live reference, so every byte of the
        // slot is in bounds; volatile so the read is of memory as it is.
        .filter(|&i| unsafe { std::ptr::read_volatile(base.add(i)) } != 0)
        .count()
}

/// Release only: in a debug build `Option::take` leaves stack garbage in
/// the payload of the `None` it writes, so the count means nothing there.
#[cfg(not(debug_assertions))]
#[test]
fn take_leg_leaves_no_session_keys_in_the_slot_it_empties() {
    let initiator = Identity::generate();
    let responder = Identity::generate();
    let responder_id = PeerIdentity::from_pubkey_full(responder.pubkey_full());
    let mut ini = outbound_leg(LinkId::new(1), responder_id, 1000);
    let mut res = Box::new(inbound_leg(LinkId::new(2), 1000));
    let msg1 = ini
        .start_handshake(initiator.keypair(), make_epoch(), LegStamp::at(1100))
        .unwrap();
    let msg2 = res
        .receive_handshake_init(
            responder.keypair(),
            make_epoch(),
            &msg1,
            None,
            LegStamp::at(1200),
        )
        .unwrap();
    let (msg3, _) = ini
        .complete_handshake_accepting(&msg2, None, LegStamp::at(1300))
        .unwrap();
    res.complete_handshake_msg3(&msg3, LegStamp::at(1400))
        .unwrap();
    assert!(res.has_session(), "the responder's leg holds the session");
    assert!(leg_slot_nonzero_bytes(&res.leg) > 64);

    let leg = res.take_leg().expect("the leg was attached");
    assert!(leg.noise_session.is_some(), "the session left with the leg");
    let left = leg_slot_nonzero_bytes(&res.leg);
    assert!(
        left <= 8,
        "{left} non-zero bytes of the session stayed in the emptied leg slot"
    );
}

#[test]
fn test_connection_failure() {
    // `mark_failed` releases the leg's Noise handshake handle. The failure
    // *state* lives on the entry, but the leg-local effect is
    // still observable: a completion attempt afterward reports `WrongState`
    // (the handle-presence gate) and no session is produced.
    let identity = make_peer_identity();
    let keypair = make_keypair();
    let mut conn = outbound_leg(LinkId::new(1), identity, 1000);
    conn.start_handshake(keypair, make_epoch(), LegStamp::at(1100))
        .unwrap();

    conn.mark_failed();

    assert!(!conn.has_session());
    assert!(
        conn.complete_handshake_accepting(&[0u8; 96], None, LegStamp::at(1200))
            .is_err()
    );
}

#[test]
fn test_wrong_direction_errors() {
    let identity = make_peer_identity();
    let keypair = make_keypair();

    // Outbound can't receive_handshake_init
    let mut outbound = outbound_leg(LinkId::new(1), identity, 1000);
    assert!(
        outbound
            .receive_handshake_init(keypair, make_epoch(), &[0u8; 33], None, LegStamp::at(1100))
            .is_err()
    );

    // Inbound can't start_handshake
    let mut inbound = inbound_leg(LinkId::new(2), 1000);
    assert!(
        inbound
            .start_handshake(keypair, make_epoch(), LegStamp::at(1100))
            .is_err()
    );
}

#[test]
fn a_failed_dial_keeps_its_crypto_carrier_shows_failed_and_stays_due_its_msg1_resends() {
    let mut entry = outbound_leg(LinkId::new(1), make_peer_identity(), 1000);
    assert!(
        entry.sending_msg1(false),
        "a connectionless dial sends msg1"
    );
    assert!(entry.is_handshaking_sent_msg1());
    assert!(!entry.is_failed());
    assert_eq!(entry.displayed_handshake_state(), "sent_msg1");

    entry.send_failed();
    assert!(
        entry.is_failed(),
        "the entry carries the failed mark the sweep reads"
    );
    assert!(
        entry.leg().is_some(),
        "the carrier stays, so the sweep can reclaim it"
    );
    assert!(
        entry.is_handshaking_sent_msg1(),
        "msg1 resends stay due after a send failure"
    );
    assert_eq!(
        entry.displayed_handshake_state(),
        "failed",
        "a failed dial shows as failed"
    );

    let _ = entry.take_leg();
    entry.send_failed();
    assert!(entry.is_failed());
    assert!(entry.leg().is_none());
    assert!(entry.is_handshaking_sent_msg1());
}

#[test]
fn the_shown_handshake_state_of_each_phase_is_the_string_the_pending_view_showed() {
    for (phase, shown) in [
        (Phase::Dialing, "sent_msg1"),
        (Phase::Connecting, "initial"),
        (Phase::SentMsg1, "sent_msg1"),
        (Phase::Answering, "initial"),
        (Phase::SentMsg2, "received_msg1"),
        (Phase::Established, "complete"),
        (Phase::Closed, "initial"),
    ] {
        assert_eq!(phase.shown(), shown, "{phase:?}");
    }

    let mut entry = outbound_leg(LinkId::new(2), make_peer_identity(), 1000);
    assert_eq!(entry.displayed_handshake_state(), "sent_msg1");
    assert!(entry.connecting());
    assert_eq!(entry.displayed_handshake_state(), "initial");
    assert!(entry.sending_msg1(true));
    assert_eq!(entry.displayed_handshake_state(), "sent_msg1");
    entry.established();
    assert_eq!(entry.displayed_handshake_state(), "complete");
    entry.closed();
    assert_eq!(entry.displayed_handshake_state(), "initial");

    let answer = inbound_leg(LinkId::new(3), 1000);
    assert_eq!(answer.displayed_handshake_state(), "initial");
}
