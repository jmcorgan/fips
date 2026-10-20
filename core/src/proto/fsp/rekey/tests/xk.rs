//! Conformance of the session rekey profile to the deployed session: the XK
//! messages and frames it writes are what the deployed handshake and codec
//! write and read. The interop simulation (`proto::rekey::tests::legacy`)
//! runs whole rekeys and first handshakes against the deployed releases;
//! this checks the profile's pieces against the deployed code directly.

use crate::noise::aead::{Aead, nonce};
use crate::noise::{
    HandshakeState, XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE, XK_HANDSHAKE_MSG3_SIZE,
};
use crate::proto::fsp::wire::{
    FSP_FLAG_CP, FSP_FLAG_K, SessionMessageType, build_fsp_header, fsp_prepend_inner_header,
    fsp_strip_inner_header,
};
use crate::proto::rekey::{FrameHint, NodeKeys, PeerKey, Profile, SessionKeys};
use crate::proto::stp::{TreeCoordinate, encode_coords};
use crate::testutil::{SeededEntropy, make_node_addr, seed_entropy, seeded_keypair};
use crate::time::Duration;

use super::FspXk;

type Xk = FspXk<SeededEntropy>;

/// The x-only key of a keypair, as the machine holds keys.
fn key(k: &secp256k1::Keypair) -> PeerKey {
    PeerKey::from_xonly(&k.x_only_public_key().0)
}

#[test]
fn xk_profile_writes_and_reads_the_deployed_handshake_and_frames_byte_for_byte() {
    seed_entropy(2);
    let (ik, rk) = (seeded_keypair(4), seeded_keypair(5));
    let (ie, re) = ([0xc3; 8], [0xd4; 8]);
    let init = NodeKeys::new(ik, ie);
    let resp = NodeKeys::new(rk, re);

    // The setup is a bare 33-byte XK msg1 a deployed responder reads; a
    // malformed one fails the deployed checks.
    let (ihs, setup) = Xk::initiate(&init, &key(&rk), None).expect("msg1");
    assert_eq!(setup.len(), XK_HANDSHAKE_MSG1_SIZE);
    assert!(Xk::valid(&setup));
    assert!(!Xk::valid(&setup[..32]), "a short msg1 is invalid");
    assert!(
        !Xk::valid(&[0u8; XK_HANDSHAKE_MSG1_SIZE]),
        "a non-point is invalid"
    );
    let mut deployed_resp = HandshakeState::<SeededEntropy>::new_xk_responder(rk);
    deployed_resp.set_local_epoch(re);
    deployed_resp
        .read_xk_message_1(&setup)
        .expect("a deployed responder reads it");

    // The profile's responder answers the same setup with a 57-byte ack
    // carrying its epoch; the profile's initiator reads it on a fork and
    // writes a 73-byte msg3 carrying its own epoch and static key.
    let (rhs, ack) = Xk::answer(&resp, &setup).expect("ack");
    assert_eq!(ack.len(), XK_HANDSHAKE_MSG2_SIZE);
    let mut bad = ack.clone();
    bad[40] ^= 1;
    assert!(Xk::reply(&ihs, &init, &bad).is_err());
    let read = Xk::reply(&ihs, &init, &ack).expect("the failed read left it readable");
    assert_eq!(read.done.epoch, re, "msg2 carries the startup epoch");
    assert_eq!(read.done.remote, key(&rk));
    let fin = read.fin.expect("XK has a msg3");
    assert_eq!(fin.len(), XK_HANDSHAKE_MSG3_SIZE);
    let rdone = Xk::complete(&rhs, &fin).expect("the responder completes on msg3");
    assert_eq!(rdone.epoch, ie, "msg3 carries the startup epoch");
    assert_eq!(
        rdone.remote,
        key(&ik),
        "msg3 authenticates the initiator's static"
    );
    let mut tampered_fin = fin.clone();
    tampered_fin[10] ^= 1;
    assert!(Xk::complete(&rhs, &tampered_fin).is_err());

    // Frames: authenticated over the 12-byte header only, so coordinates a
    // frame carries between the header and the ciphertext (the CP flag)
    // are outside the AEAD, as deployed.
    let mut ikeys = read.done.session;
    let rkeys = rdone.session;
    let (counter, send) = ikeys.reserve();
    assert_eq!(counter, 0, "counters start at 0 in every session");
    let plaintext =
        fsp_prepend_inner_header(5, SessionMessageType::DataPacket.to_byte(), 0, &[9, 9]);
    let header = build_fsp_header(counter, FSP_FLAG_CP | FSP_FLAG_K, plaintext.len() as u16);
    let mut buf = plaintext.clone();
    let tag = send
        .key()
        .expect("keyed")
        .seal(&nonce(counter), &header, &mut buf)
        .expect("seals");
    let mut frame = header.to_vec();
    encode_coords(&TreeCoordinate::root(make_node_addr(1)), &mut frame);
    encode_coords(&TreeCoordinate::root(make_node_addr(2)), &mut frame);
    let body = frame.len();
    frame.extend_from_slice(&buf);
    frame.extend_from_slice(&tag);
    let hint = FrameHint {
        counter,
        k: true,
        index: 0,
        body,
    };
    let mut out = alloc::vec::Vec::new();
    assert!(
        rkeys.open(&hint, &frame, &mut out),
        "the responder opens it past the coordinates"
    );
    assert_eq!(out, plaintext);
    assert!(
        !ikeys.open(&hint, &frame, &mut out),
        "each direction has its own key"
    );

    // The prompt is a CoordsWarmup inner header with an empty body: a probe
    // under a pending epoch, and nothing else is.
    let mut prompt = alloc::vec::Vec::new();
    Xk::prompt(Duration::from_millis(3_000), &mut prompt);
    let (ts, msg_type, flags, rest) =
        fsp_strip_inner_header(&prompt).expect("the deployed parser takes it");
    assert_eq!(
        (ts, msg_type, flags),
        (3_000, SessionMessageType::CoordsWarmup.to_byte(), 0)
    );
    assert!(rest.is_empty());
    assert!(prompt.len() >= Xk::FLOOR);
    assert!(Xk::is_probe(&prompt));
    assert!(!Xk::is_probe(&plaintext), "data is not a probe");
    assert!(
        !Xk::is_probe(&prompt[..5]),
        "a plaintext too short for the inner header is not a probe"
    );
}
