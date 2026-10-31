//! Tests for `../fork.rs`: a read on a fork never changes the handshake it
//! was forked from.

use super::*;
use crate::noise::PUBKEY_SIZE;
use crate::noise::handshake::SymmetricState;
use crate::testutil::{TestEntropy, make_keypair};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

type Hs = HandshakeState<TestEntropy>;

/// The three reads a caller makes on a message nothing has authenticated.
#[derive(Clone, Copy, Debug)]
enum Read {
    /// IK message 2, at the initiator.
    Msg2,
    /// XK message 2, at the initiator.
    Xk2,
    /// XK message 3, at the responder.
    Xk3,
}

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
        es,
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
        es.map(|e| e.to_vec()),
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
    let pair = |read: Read| -> (Hs, Vec<u8>) {
        let initiator_keys = make_keypair();
        let responder_keys = make_keypair();
        let responder_pub = responder_keys.public_key();
        let (mut initiator, mut responder) = match read {
            Read::Msg2 => (
                Hs::new_initiator(initiator_keys, responder_pub),
                Hs::new_responder(responder_keys),
            ),
            Read::Xk2 | Read::Xk3 => (
                Hs::new_xk_initiator(initiator_keys, responder_pub),
                Hs::new_xk_responder(responder_keys),
            ),
        };
        initiator.set_local_epoch([1; 8]);
        responder.set_local_epoch([2; 8]);
        match read {
            Read::Msg2 => {
                let msg1 = initiator.write_message_1().unwrap();
                responder.read_message_1(&msg1).unwrap();
                (initiator, responder.write_message_2().unwrap())
            }
            Read::Xk2 => {
                let msg1 = initiator.write_xk_message_1().unwrap();
                responder.read_xk_message_1(&msg1).unwrap();
                (initiator, responder.write_xk_message_2().unwrap())
            }
            Read::Xk3 => {
                let msg1 = initiator.write_xk_message_1().unwrap();
                responder.read_xk_message_1(&msg1).unwrap();
                let msg2 = responder.write_xk_message_2().unwrap();
                initiator.read_xk_message_2(&msg2).unwrap();
                (responder, initiator.write_xk_message_3().unwrap())
            }
        }
    };
    let (hs, genuine) = pair(read);
    let (_, stranger) = pair(read);
    (hs, genuine, stranger)
}

/// Read `msg` on a fork of `hs`, the way the callers do.
///
/// Takes the handshake mutably, as a caller holding it in its slot does, so
/// that a read able to change it in place would still compile here and be
/// caught by the comparison.
fn read_on_fork(read: Read, hs: &mut Hs, msg: &[u8]) -> Result<Hs, NoiseError> {
    match read {
        Read::Msg2 => hs.fork_msg2(msg),
        Read::Xk2 => hs.fork_xk2(msg),
        Read::Xk3 => hs.fork_xk3(msg),
    }
}

/// Read `msg` on `hs` itself, as the reads under the forks do.
fn read_in_place(read: Read, hs: &mut Hs, msg: &[u8]) -> Result<(), NoiseError> {
    match read {
        Read::Msg2 => hs.read_message_2(msg),
        Read::Xk2 => hs.read_xk_message_2(msg),
        Read::Xk3 => hs.read_xk_message_3(msg),
    }
}

/// The same message with byte `at` flipped.
fn flipped(msg: &[u8], at: usize) -> Vec<u8> {
    let mut out = msg.to_vec();
    out[at] ^= 0x01;
    out
}

#[test]
fn every_read_on_garbage_leaves_the_handshake_byte_identical() {
    for read in [Read::Msg2, Read::Xk2, Read::Xk3] {
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
        // flipped still reads.
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
        // an untouched handshake reaches by reading it in place.
        let mut expected = reference;
        read_in_place(read, &mut expected, &genuine).expect("the untouched copy reads");
        let committed = read_on_fork(read, &mut hs, &genuine).expect("the genuine message reads");
        assert_eq!(fingerprint(&committed), fingerprint(&expected), "{read:?}");
        assert_eq!(
            fingerprint(&hs),
            before,
            "{read:?}: a success also reads on the fork"
        );
    }
}
