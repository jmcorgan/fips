//! Tests for the node's entry for one handshake: its Noise operations, the
//! failure it records, and the handshake state the control API shows.
//!
//! A msg2 that does not authenticate leaves an initial (IK) dial's handshake
//! where it was, so the genuine msg2 can still complete it. The index a msg2
//! names travels in cleartext in our msg1, so anyone who saw the msg1 can
//! send a msg2 under it. These tests drive [`Handshake::complete_handshake`]
//! directly because the wire parser drops a msg2 of the wrong length before
//! it reaches the entry, so a short one cannot be delivered from the node.

use super::*;
use crate::noise::HANDSHAKE_MSG2_SIZE;
use crate::{Identity, PeerIdentity};

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

/// A dial's entry to `expected_identity` on `link_id`, its crypto attached.
fn outbound_leg(
    link_id: LinkId,
    expected_identity: PeerIdentity,
    current_time_ms: u64,
) -> Handshake {
    let mut entry =
        Handshake::new_outbound(link_id, expected_identity, LegStamp::at(current_time_ms));
    entry.set_leg(HandshakeCrypto::new());
    entry
}

/// The peer's handshake on `link_id`, its crypto attached.
fn inbound_leg(link_id: LinkId, current_time_ms: u64) -> Handshake {
    let mut entry = Handshake::new_inbound(link_id, LegStamp::at(current_time_ms));
    entry.set_leg(HandshakeCrypto::new());
    entry
}

/// An initiator that has sent msg1, the responder that answered it, and the
/// genuine msg2 the responder answered it with.
fn dial_answered() -> (Handshake, Handshake, Vec<u8>) {
    let initiator = Identity::generate();
    let responder = Identity::generate();
    let responder_id = PeerIdentity::from_pubkey_full(responder.pubkey_full());

    let mut ini = outbound_leg(LinkId::new(1), responder_id, 1000);
    let mut res = inbound_leg(LinkId::new(2), 1000);

    let msg1 = ini
        .start_handshake(initiator.keypair(), [1; 8], LegStamp::at(1100))
        .expect("msg1 is written");
    let msg2 = res
        .receive_handshake_init(responder.keypair(), [2; 8], &msg1, LegStamp::at(1200))
        .expect("the responder answers msg1");
    (ini, res, msg2)
}

/// An initiator that has sent msg1, and the genuine msg2 the responder
/// answered it with.
fn dial_with_genuine_msg2() -> (Handshake, Vec<u8>) {
    let (ini, _, msg2) = dial_answered();
    (ini, msg2)
}

/// True when the leg still holds the handshake handle, i.e. the attempt can
/// still read a msg2.
fn handle_kept(entry: &Handshake) -> bool {
    entry.leg().is_some_and(|leg| leg.noise_handshake.is_some())
}

/// Deliver `forged`, check it is refused with the handshake kept and nothing
/// else changed, then check the genuine msg2 still completes the session.
fn forged_then_genuine(forged: &[u8]) {
    let (mut ini, genuine) = dial_with_genuine_msg2();
    let activity = ini.conn_last_activity();

    assert!(
        ini.complete_handshake(forged, LegStamp::at(1300)).is_err(),
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

    ini.complete_handshake(&genuine, LegStamp::at(1400))
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
        assert!(ini.complete_handshake(forged, LegStamp::at(1300)).is_err());
        assert!(handle_kept(&ini));
    }
    ini.complete_handshake(&genuine, LegStamp::at(1400))
        .expect("the genuine msg2 must still complete the handshake");
    assert!(ini.has_session());
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

    // Initiator starts handshake
    let msg1 = initiator_conn
        .start_handshake(initiator_keypair, initiator_epoch, LegStamp::at(1100))
        .unwrap();
    // Post-msg1 the initiator holds an in-flight handshake, not yet a session.
    assert!(!initiator_conn.has_session());

    // Responder processes msg1 and sends msg2
    let msg2 = responder_conn
        .receive_handshake_init(
            responder_keypair,
            responder_epoch,
            &msg1,
            LegStamp::at(1200),
        )
        .unwrap();
    // The IK responder completes in one step: it now holds a session.
    assert!(responder_conn.has_session());

    // Responder learned initiator's identity
    let discovered = responder_conn.conn_expected_identity().unwrap();
    assert_eq!(discovered.pubkey(), initiator_identity.pubkey());

    // Responder learned initiator's epoch
    assert_eq!(responder_conn.conn_remote_epoch(), Some(initiator_epoch));

    // Initiator completes handshake
    initiator_conn
        .complete_handshake(&msg2, LegStamp::at(1300))
        .unwrap();
    assert!(initiator_conn.has_session());

    // Initiator learned responder's epoch
    assert_eq!(initiator_conn.conn_remote_epoch(), Some(responder_epoch));

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
    res.receive_handshake_init(responder.keypair(), make_epoch(), &msg1, LegStamp::at(1200))
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
    // `fail` releases the leg's Noise handshake handle: a completion attempt
    // afterward reports `WrongState` (the handle-presence gate) and no
    // session is produced.
    let identity = make_peer_identity();
    let keypair = make_keypair();
    let mut conn = outbound_leg(LinkId::new(1), identity, 1000);
    conn.start_handshake(keypair, make_epoch(), LegStamp::at(1100))
        .unwrap();

    conn.fail();

    assert!(!conn.has_session());
    assert!(
        conn.complete_handshake(&[0u8; 96], LegStamp::at(1200))
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
            .receive_handshake_init(keypair, make_epoch(), &[0u8; 106], LegStamp::at(1100))
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

/// A stored msg1 that cannot be sent marks the dial's entry failed, which
/// the stale-connection sweep reads, and the entry keeps its crypto carrier
/// so the sweep can reclaim it; the control API then shows it `"failed"`.
/// An entry with no carrier takes the mark too.
#[test]
fn a_failed_dial_keeps_its_crypto_carrier_and_shows_failed() {
    let (mut ini, _, _) = dial_answered();
    assert!(!ini.is_failed());
    assert_eq!(ini.shown_state(), "sent_msg1");

    ini.fail();
    assert!(
        ini.is_failed(),
        "defect: the entry does not carry the mark the sweep reads"
    );
    assert!(
        ini.leg().is_some(),
        "defect: the carrier went, so the sweep cannot reclaim it"
    );
    assert!(!handle_kept(&ini), "the Noise handshake handle is dropped");
    assert_eq!(
        ini.shown_state(),
        "failed",
        "defect: a failed dial does not show as failed"
    );

    let _ = ini.take_leg();
    ini.fail();
    assert!(ini.is_failed());
    assert!(ini.leg().is_none());
}

/// The handshake state the control API shows: `"initial"` before either
/// side's msg1 is handled, `"sent_msg1"` once this node's msg1 is written,
/// `"received_msg1"` once the peer's msg1 is read and answered, and
/// `"failed"` once the handshake failed past recovery, whatever it reached.
/// The strings are the ones the operator has always been shown.
#[test]
fn the_shown_handshake_state_follows_each_step_of_a_handshake() {
    let responder = Identity::generate();
    let responder_id = PeerIdentity::from_pubkey_full(responder.pubkey_full());
    let mut ini = outbound_leg(LinkId::new(1), responder_id, 1000);
    let mut res = inbound_leg(LinkId::new(2), 1000);
    assert_eq!(ini.shown_state(), "initial", "a dial before its msg1");
    assert_eq!(res.shown_state(), "initial", "a handshake before its msg1");

    let msg1 = ini
        .start_handshake(make_keypair(), [1; 8], LegStamp::at(1100))
        .unwrap();
    assert_eq!(
        ini.shown_state(),
        "sent_msg1",
        "defect: a dial whose msg1 is written does not show sent_msg1"
    );
    res.receive_handshake_init(responder.keypair(), [2; 8], &msg1, LegStamp::at(1200))
        .unwrap();
    assert_eq!(
        res.shown_state(),
        "received_msg1",
        "defect: an answered msg1 does not show received_msg1"
    );

    res.fail();
    assert_eq!(res.shown_state(), "failed");
    let mut fresh = outbound_leg(LinkId::new(3), make_peer_identity(), 1000);
    fresh.fail();
    assert_eq!(fresh.shown_state(), "failed", "failed before its msg1");
}
