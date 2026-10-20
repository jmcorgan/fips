//! Tests for `../fork.rs`: a read on a fork never changes the handshake it
//! was forked from.

use super::*;
use crate::noise::handshake::SymmetricState;
use crate::noise::{HANDSHAKE_MSG2_SIZE, HANDSHAKE_MSG3_SIZE, PUBKEY_SIZE};
use crate::testutil::{TestEntropy, make_keypair};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

type Hs = HandshakeState<TestEntropy>;

/// The reads a caller makes on a message nothing has authenticated: XX
/// msg2 at the initiator and XX msg3 at the responder, each bare or with a
/// negotiation payload after it.
#[derive(Clone, Copy, Debug)]
enum Read {
    /// XX message 2, at the initiator.
    Msg2,
    /// XX message 2 with a negotiation payload, at the initiator.
    Msg2Payload,
    /// XX message 3, at the responder.
    Msg3,
    /// XX message 3 with a negotiation payload, at the responder.
    Msg3Payload,
}

impl Read {
    /// Every read.
    const ALL: [Read; 4] = [Read::Msg2, Read::Msg2Payload, Read::Msg3, Read::Msg3Payload];

    /// Whether the message carries a payload.
    fn payload(self) -> bool {
        matches!(self, Read::Msg2Payload | Read::Msg3Payload)
    }

    /// Whether the message is a msg2.
    fn msg2(self) -> bool {
        matches!(self, Read::Msg2 | Read::Msg2Payload)
    }
}

/// The negotiation payload the tests send.
const PAYLOAD: &[u8] = b"negotiation payload";

/// Every field of `hs` as bytes, so two states compare equal only when
/// every field does.
///
/// The destructuring names every field, so a field added to either struct
/// fails to compile here until it is compared. The cipher's key cannot be
/// read, so it enters through what the cipher seals at its current nonce.
fn fingerprint(hs: &Hs) -> Vec<u8> {
    let HandshakeState {
        pattern,
        role,
        progress,
        symmetric,
        static_keypair,
        ephemeral_keypair,
        remote_static,
        remote_ephemeral,
        entropy: _,
        local_epoch,
        remote_epoch,
    } = hs;
    let SymmetricState { ck, h, cipher } = symmetric;
    let mut out = format!("{pattern:?} {role:?} {progress:?}").into_bytes();
    out.extend_from_slice(ck);
    out.extend_from_slice(h);
    out.extend_from_slice(&cipher.nonce.to_le_bytes());
    out.extend(cipher.clone().encrypt(b"fingerprint").expect("probe seals"));
    out.extend_from_slice(&static_keypair.secret_bytes());
    let keys = [
        ephemeral_keypair.map(|k| k.secret_bytes().to_vec()),
        remote_static.map(|k| k.serialize().to_vec()),
        remote_ephemeral.map(|k| k.serialize().to_vec()),
        local_epoch.map(|e| e.to_vec()),
        remote_epoch.map(|e| e.to_vec()),
    ];
    for key in keys {
        match key {
            Some(bytes) => {
                out.push(1);
                out.extend(bytes);
            }
            None => out.push(0),
        }
    }
    out
}

/// A handshake waiting for `read`'s message, the genuine message, and a
/// message of the same kind written for a different handshake.
fn waiting(read: Read) -> (Hs, Vec<u8>, Vec<u8>) {
    let seal = |hs: &mut Hs, mut msg: Vec<u8>| -> Vec<u8> {
        if read.payload() {
            msg.extend(hs.encrypt_payload(PAYLOAD).expect("the payload seals"));
        }
        msg
    };
    let pair = || -> (Hs, Vec<u8>) {
        let mut initiator = Hs::new_initiator(make_keypair());
        let mut responder = Hs::new_responder(make_keypair());
        initiator.set_local_epoch([1; 8]);
        responder.set_local_epoch([2; 8]);
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        let msg2 = seal(&mut responder, msg2);
        if read.msg2() {
            return (initiator, msg2);
        }
        let (mut initiator, _) = initiator.fork_msg2(&msg2).unwrap();
        let msg3 = initiator.write_message_3().unwrap();
        (responder, seal(&mut initiator, msg3))
    };
    let (hs, genuine) = pair();
    let (_, stranger) = pair();
    (hs, genuine, stranger)
}

/// Read `msg` on a fork of `hs`, the way the callers do.
///
/// Takes the handshake mutably, as a caller holding it in its slot does, so
/// that a read able to change it in place would still compile here and be
/// caught by the comparison.
fn read_on_fork(read: Read, hs: &mut Hs, msg: &[u8]) -> Result<ForkRead<TestEntropy>, NoiseError> {
    if read.msg2() {
        hs.fork_msg2(msg)
    } else {
        hs.fork_msg3(msg)
    }
}

/// Read `msg` and any payload after it on `hs` itself, as the reads under
/// the forks do.
fn read_in_place(read: Read, hs: &mut Hs, msg: &[u8]) -> Result<Option<Vec<u8>>, NoiseError> {
    let base = if read.msg2() {
        HANDSHAKE_MSG2_SIZE
    } else {
        HANDSHAKE_MSG3_SIZE
    };
    let (head, rest) = msg.split_at(base.min(msg.len()));
    if read.msg2() {
        hs.read_message_2(head)?;
    } else {
        hs.read_message_3(head)?;
    }
    if rest.is_empty() {
        return Ok(None);
    }
    hs.decrypt_payload(rest).map(Some)
}

/// The same message with byte `at` flipped.
fn flipped(msg: &[u8], at: usize) -> Vec<u8> {
    let mut out = msg.to_vec();
    out[at] ^= 0x01;
    out
}

#[test]
fn every_read_on_garbage_leaves_the_handshake_byte_identical() {
    for read in Read::ALL {
        let (mut hs, genuine, stranger) = waiting(read);
        let before = fingerprint(&hs);
        let reference = hs.fork();
        assert_eq!(
            fingerprint(&reference),
            before,
            "{read:?}: a fork copies every field"
        );

        // Byte 1 rather than byte 0 of an ephemeral: byte 0 is its parity,
        // which the x-only DH ignores and no AEAD binds, so a msg2 with it
        // flipped still reads. The last byte is the payload's tag when
        // there is a payload, so that message fails after the base message
        // has read, the deepest a read gets before failing.
        let last = genuine.len() - 1;
        let garbage = [
            Vec::new(),
            genuine[..last].to_vec(),
            [genuine.as_slice(), &[0]].concat(),
            vec![0; genuine.len()],
            stranger,
            flipped(&genuine, 1),
            flipped(&genuine, PUBKEY_SIZE),
            flipped(&genuine, last),
        ];
        for (i, msg) in garbage.iter().enumerate() {
            assert!(
                read_on_fork(read, &mut hs, msg).is_err(),
                "{read:?}: garbage {i} must not read"
            );
            assert_eq!(
                fingerprint(&hs),
                before,
                "{read:?}: garbage {i} changed the handshake"
            );
        }

        // The garbage discriminates: read in place, the deepest-failing
        // message spoils the state, and the genuine message no longer reads.
        let mut spoiled = hs.fork();
        assert!(read_in_place(read, &mut spoiled, &garbage[7]).is_err());
        assert_ne!(fingerprint(&spoiled), before, "{read:?}: control");
        assert!(read_in_place(read, &mut spoiled, &genuine).is_err());

        // After every failure the genuine message reads, to exactly the state
        // an untouched handshake reaches by reading it in place, and hands
        // back the payload it carried.
        let mut expected = reference;
        let want = read_in_place(read, &mut expected, &genuine).expect("the untouched copy reads");
        let (committed, payload) =
            read_on_fork(read, &mut hs, &genuine).expect("the genuine message reads");
        assert_eq!(fingerprint(&committed), fingerprint(&expected), "{read:?}");
        assert_eq!(payload, want, "{read:?}");
        assert_eq!(
            payload.as_deref(),
            read.payload().then_some(PAYLOAD),
            "{read:?}: the payload comes back decrypted"
        );
        assert_eq!(
            fingerprint(&hs),
            before,
            "{read:?}: a success also reads on the fork"
        );
    }
}

/// A fork that read msg2 and its payload writes a msg3 the responder reads,
/// payload and all, and the two ends agree on the handshake hash; a fork
/// that read msg2 but not its payload writes one the responder cannot read.
#[test]
fn a_msg2_payload_read_on_the_fork_keeps_msg3_readable() {
    let mut initiator = Hs::new_initiator(make_keypair());
    let mut responder = Hs::new_responder(make_keypair());
    initiator.set_local_epoch([1; 8]);
    responder.set_local_epoch([2; 8]);
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let mut msg2 = responder.write_message_2().unwrap();
    msg2.extend(responder.encrypt_payload(PAYLOAD).unwrap());

    let mut skipped = initiator.fork();
    skipped
        .read_message_2(&msg2[..HANDSHAKE_MSG2_SIZE])
        .unwrap();
    let stale = skipped.write_message_3().unwrap();
    assert!(
        responder.fork().read_message_3(&stale).is_err(),
        "a msg3 written past an unread payload is one nonce behind"
    );

    let (mut fork, payload) = initiator.fork_msg2(&msg2).expect("msg2 reads");
    assert_eq!(payload.as_deref(), Some(PAYLOAD));
    let mut msg3 = fork.write_message_3().unwrap();
    msg3.extend(fork.encrypt_payload(PAYLOAD).unwrap());
    let (done, payload) = responder.fork_msg3(&msg3).expect("msg3 reads");
    assert_eq!(payload.as_deref(), Some(PAYLOAD));
    assert_eq!(done.handshake_hash(), fork.handshake_hash());
}
