use super::*;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use rand::Rng;
use secp256k1::Parity;

type HandshakeState = handshake::HandshakeState<crate::testutil::TestEntropy>;

fn generate_keypair() -> secp256k1::Keypair {
    let secp = secp256k1::Secp256k1::new();
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
        .expect("32 random bytes is a valid secret key");
    secp256k1::Keypair::from_secret_key(&secp, &secret_key)
}

fn generate_epoch() -> [u8; 8] {
    let mut epoch = [0u8; 8];
    rand::rng().fill_bytes(&mut epoch);
    epoch
}

#[test]
fn test_full_handshake() {
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();
    let initiator_epoch = generate_epoch();
    let responder_epoch = generate_epoch();

    let responder_pub = responder_keypair.public_key();

    // Initiator knows responder's static key
    // Responder does NOT know initiator's static key (IK pattern)
    let mut initiator = HandshakeState::new_initiator(initiator_keypair, responder_pub);
    initiator.set_local_epoch(initiator_epoch);
    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(responder_epoch);

    assert_eq!(initiator.role(), HandshakeRole::Initiator);
    assert_eq!(responder.role(), HandshakeRole::Responder);

    // Initially, responder doesn't know initiator's identity
    assert!(responder.remote_static().is_none());

    // Message 1: Initiator -> Responder
    let msg1 = initiator.write_message_1().unwrap();
    assert_eq!(msg1.len(), HANDSHAKE_MSG1_SIZE);

    responder.read_message_1(&msg1).unwrap();

    // Now responder knows initiator's identity!
    assert!(responder.remote_static().is_some());
    assert_eq!(
        responder.remote_static().unwrap(),
        &initiator_keypair.public_key()
    );

    // Responder learned initiator's epoch
    assert_eq!(responder.remote_epoch(), Some(initiator_epoch));

    // Message 2: Responder -> Initiator
    let msg2 = responder.write_message_2().unwrap();
    assert_eq!(msg2.len(), HANDSHAKE_MSG2_SIZE);

    initiator.read_message_2(&msg2).unwrap();

    // Both should be complete
    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    // Initiator learned responder's epoch
    assert_eq!(initiator.remote_epoch(), Some(responder_epoch));

    // Handshake hashes should match
    assert_eq!(initiator.handshake_hash(), responder.handshake_hash());

    // Convert to sessions
    let mut initiator_session = initiator.into_session().unwrap();
    let mut responder_session = responder.into_session().unwrap();

    // Test encryption/decryption
    let plaintext = b"Hello, secure world!";

    let ciphertext = initiator_session.encrypt(plaintext).unwrap();
    let decrypted = responder_session.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);

    // Test reverse direction
    let plaintext2 = b"Hello back!";
    let ciphertext2 = responder_session.encrypt(plaintext2).unwrap();
    let decrypted2 = initiator_session.decrypt(&ciphertext2).unwrap();
    assert_eq!(decrypted2, plaintext2);
}

#[test]
fn test_multiple_messages() {
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();

    let mut initiator =
        HandshakeState::new_initiator(initiator_keypair, responder_keypair.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    let mut initiator_session = initiator.into_session().unwrap();
    let mut responder_session = responder.into_session().unwrap();

    // Send many messages to test nonce increment
    for i in 0..100 {
        let msg = format!("Message {}", i);
        let ct = initiator_session.encrypt(msg.as_bytes()).unwrap();
        let pt = responder_session.decrypt(&ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    assert_eq!(initiator_session.send_nonce(), 100);
    assert_eq!(responder_session.recv_nonce(), 100);
}

#[test]
fn test_wrong_role_errors() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut initiator = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());

    // Initiator can't read message 1
    assert!(
        initiator
            .read_message_1(&[0u8; HANDSHAKE_MSG1_SIZE])
            .is_err()
    );

    // Initiator can't write message 2 before message 1
    assert!(initiator.write_message_2().is_err());
}

#[test]
fn test_invalid_pubkey_in_msg1() {
    let keypair = generate_keypair();
    let mut responder = HandshakeState::new_responder(keypair);
    responder.set_local_epoch(generate_epoch());

    // Invalid pubkey bytes (first 33 bytes are zero)
    let invalid_msg = [0u8; HANDSHAKE_MSG1_SIZE];
    assert!(responder.read_message_1(&invalid_msg).is_err());
}

#[test]
fn test_decryption_failure_wrong_key() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();

    // Session between 1 and 2
    let mut init1 = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    init1.set_local_epoch(generate_epoch());
    let mut resp1 = HandshakeState::new_responder(keypair2);
    resp1.set_local_epoch(generate_epoch());

    let msg1 = init1.write_message_1().unwrap();
    resp1.read_message_1(&msg1).unwrap();
    let msg2 = resp1.write_message_2().unwrap();
    init1.read_message_2(&msg2).unwrap();

    let mut session1 = init1.into_session().unwrap();

    // Session between 1 and 3
    let mut init2 = HandshakeState::new_initiator(keypair1, keypair3.public_key());
    init2.set_local_epoch(generate_epoch());
    let mut resp2 = HandshakeState::new_responder(keypair3);
    resp2.set_local_epoch(generate_epoch());

    let msg1 = init2.write_message_1().unwrap();
    resp2.read_message_1(&msg1).unwrap();
    let msg2 = resp2.write_message_2().unwrap();
    init2.read_message_2(&msg2).unwrap();

    let mut session2 = resp2.into_session().unwrap();

    // Encrypt with session 1, try to decrypt with session 2
    let ciphertext = session1.encrypt(b"test").unwrap();
    assert!(session2.decrypt(&ciphertext).is_err());
}

#[test]
fn test_cipher_state_nonce_sequence() {
    let key = [0u8; 32];
    let mut cipher = CipherState::new(key);

    assert_eq!(cipher.nonce(), 0);

    let _ = cipher.encrypt(b"test").unwrap();
    assert_eq!(cipher.nonce(), 1);

    let _ = cipher.encrypt(b"test").unwrap();
    assert_eq!(cipher.nonce(), 2);
}

#[test]
fn cipher_state_still_implements_zeroize_on_drop() {
    // `CipherState` keeps no key bytes of its own, but keeps its
    // `ZeroizeOnDrop` impl. On RustCrypto the key material is inside the
    // cached `AeadKey`, which clears itself on drop; `ring`'s key has no
    // clearing route, so there is nothing to assert for it.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<CipherState>();
    #[cfg(not(feature = "ring"))]
    assert_zeroize_on_drop::<aead::AeadKey>();
}

#[test]
fn cipher_state_clone_and_handed_out_key_seal_like_the_original() {
    let plaintext = b"cloned and handed-out keys";
    let mut original = CipherState::new([0x5a; 32]);
    let mut cloned = original.clone();
    let handed = original
        .cipher_clone()
        .expect("a keyed state hands out a key");

    let expected = original.encrypt(plaintext).unwrap();
    assert_eq!(cloned.encrypt(plaintext).unwrap(), expected);

    let mut sealed = plaintext.to_vec();
    let tag = aead::Aead::seal(&handed, &aead::nonce(0), &[], &mut sealed).unwrap();
    sealed.extend_from_slice(&tag);
    assert_eq!(sealed, expected);

    assert!(CipherState::empty().cipher_clone().is_none());
}

#[test]
fn test_session_remote_static() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut init = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    init.set_local_epoch(generate_epoch());
    let mut resp = HandshakeState::new_responder(keypair2);
    resp.set_local_epoch(generate_epoch());

    let msg1 = init.write_message_1().unwrap();
    resp.read_message_1(&msg1).unwrap();
    let msg2 = resp.write_message_2().unwrap();
    init.read_message_2(&msg2).unwrap();

    let session1 = init.into_session().unwrap();
    let session2 = resp.into_session().unwrap();

    // Each session should know the other's static key
    assert_eq!(session1.remote_static(), &keypair2.public_key());
    assert_eq!(session2.remote_static(), &keypair1.public_key());
}

#[test]
fn test_message_sizes() {
    // Verify our size constants are correct
    assert_eq!(EPOCH_SIZE, 8);
    assert_eq!(EPOCH_ENCRYPTED_SIZE, 8 + 16); // epoch + AEAD tag
    assert_eq!(HANDSHAKE_MSG1_SIZE, 33 + 33 + 16 + 24); // e + encrypted_s + encrypted_epoch
    assert_eq!(HANDSHAKE_MSG2_SIZE, 33 + 24); // e + encrypted_epoch
}

#[test]
fn test_responder_identity_discovery() {
    // This test verifies the key IK property: responder learns initiator's identity
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();

    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(generate_epoch());

    // Before message 1: responder has no idea who's connecting
    assert!(responder.remote_static().is_none());

    let mut initiator =
        HandshakeState::new_initiator(initiator_keypair, responder_keypair.public_key());
    initiator.set_local_epoch(generate_epoch());
    let msg1 = initiator.write_message_1().unwrap();

    // After processing message 1: responder knows initiator's identity
    responder.read_message_1(&msg1).unwrap();
    let discovered_initiator = responder.remote_static().unwrap();
    assert_eq!(discovered_initiator, &initiator_keypair.public_key());

    // The discovered key can be used to look up peer config, verify against allow-list, etc.
}

// ===== ReplayWindow Tests =====

#[test]
fn test_replay_window_basic() {
    let mut window = ReplayWindow::new();

    // First packet is always acceptable
    assert!(window.check(0));
    window.accept(0);
    assert_eq!(window.highest(), 0);

    // Replay of 0 should fail
    assert!(!window.check(0));

    // New higher counter is acceptable
    assert!(window.check(1));
    window.accept(1);
    assert_eq!(window.highest(), 1);

    // Out-of-order within window is acceptable
    // (after accepting 10, 2 is still in window)
    window.accept(10);
    assert!(window.check(5));
    window.accept(5);

    // Replay of 5 should now fail
    assert!(!window.check(5));
}

#[test]
fn test_replay_window_large_jump() {
    let mut window = ReplayWindow::new();

    // Accept counter 0
    window.accept(0);

    // Jump to a large counter
    window.accept(REPLAY_WINDOW_SIZE as u64 + 100);

    // Old counter should be outside window
    assert!(!window.check(0));
    assert!(!window.check(50));

    // Counters within window should work
    assert!(window.check(REPLAY_WINDOW_SIZE as u64 + 99));
    assert!(window.check(REPLAY_WINDOW_SIZE as u64 + 50));
}

#[test]
fn test_replay_window_boundary() {
    let mut window = ReplayWindow::new();

    // Accept at boundary
    window.accept(REPLAY_WINDOW_SIZE as u64 - 1);

    // Counter 0 should be exactly at the edge of the window
    assert!(window.check(0));
    window.accept(0);

    // Move window forward by 1
    window.accept(REPLAY_WINDOW_SIZE as u64);

    // Counter 0 is now outside the window
    assert!(!window.check(0));

    // Counter 1 is still in the window
    assert!(window.check(1));
}

#[test]
fn test_replay_window_sequential() {
    let mut window = ReplayWindow::new();

    // Accept counters 0-999 in order
    for i in 0..1000 {
        assert!(window.check(i), "Counter {} should be acceptable", i);
        window.accept(i);
    }

    // All should be marked as seen
    for i in 0..1000 {
        assert!(
            !window.check(i),
            "Counter {} should be rejected as replay",
            i
        );
    }

    assert_eq!(window.highest(), 999);
}

#[test]
fn test_replay_window_reset() {
    let mut window = ReplayWindow::new();

    window.accept(100);
    assert_eq!(window.highest(), 100);
    assert!(!window.check(100));

    window.reset();

    assert_eq!(window.highest(), 0);
    assert!(window.check(100));
}

#[test]
fn test_replay_window_max_counter_does_not_wedge_the_window() {
    let mut window = ReplayWindow::new();

    window.accept(100);
    // Mirror the real receive path: check, and accept only if the check passed.
    if window.check(u64::MAX) {
        window.accept(u64::MAX);
    }

    // The honest peer's next frame must still be acceptable.
    assert!(window.check(101), "ceiling frame wedged the window");
}

#[test]
fn test_replay_window_rejects_max_counter() {
    let window = ReplayWindow::new();
    assert!(!window.check(u64::MAX));
}

#[test]
fn test_replay_window_accepts_highest_counter_an_honest_peer_can_send() {
    // take_send_counter refuses u64::MAX, so u64::MAX - 1 is the highest
    // counter a conforming peer emits. The ceiling guard must be exactly one
    // value wide and leave that one alone.
    let mut window = ReplayWindow::new();
    assert!(window.check(u64::MAX - 1));

    window.accept(u64::MAX - 1);
    assert!(
        !window.check(u64::MAX - 1),
        "replay should still be rejected"
    );
}

#[test]
fn test_session_replay_protection() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut init = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    init.set_local_epoch(generate_epoch());
    let mut resp = HandshakeState::new_responder(keypair2);
    resp.set_local_epoch(generate_epoch());

    let msg1 = init.write_message_1().unwrap();
    resp.read_message_1(&msg1).unwrap();
    let msg2 = resp.write_message_2().unwrap();
    init.read_message_2(&msg2).unwrap();

    let mut sender = init.into_session().unwrap();
    let mut receiver = resp.into_session().unwrap();

    // Encrypt a message
    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt(b"test message").unwrap();

    // First decryption should succeed
    let plaintext = receiver
        .decrypt_with_replay_check(&ciphertext, counter)
        .unwrap();
    assert_eq!(plaintext, b"test message");

    // Replay should fail
    let result = receiver.decrypt_with_replay_check(&ciphertext, counter);
    assert!(matches!(result, Err(NoiseError::ReplayDetected(_))));

    // Check method alone also detects replay
    assert!(receiver.check_replay(counter).is_err());
}

#[test]
fn test_handshake_with_odd_parity_responder() {
    // Node B's secret key produces an odd-parity public key (0x03 prefix).
    // When the initiator only has the npub (x-only), PeerIdentity::pubkey_full()
    // returns even parity (0x02). The pre-message mix_hash must normalize
    // parity so both sides produce matching hash chains.
    let secp = secp256k1::Secp256k1::new();

    // Node B (responder) - odd parity key
    let sk_b = secp256k1::SecretKey::from_slice(
        &hex::decode("b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0").unwrap(),
    )
    .unwrap();
    let kp_b = secp256k1::Keypair::from_secret_key(&secp, &sk_b);
    let (xonly_b, parity_b) = kp_b.public_key().x_only_public_key();
    assert_eq!(
        parity_b,
        Parity::Odd,
        "Test requires odd-parity responder key"
    );

    // Node A (initiator) - even parity key
    let sk_a = secp256k1::SecretKey::from_slice(
        &hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap(),
    )
    .unwrap();
    let kp_a = secp256k1::Keypair::from_secret_key(&secp, &sk_a);

    // Simulate the production path: initiator gets responder's key via npub
    // (x-only -> assumed even parity)
    let assumed_even_b = xonly_b.public_key(Parity::Even);
    assert_ne!(
        assumed_even_b,
        kp_b.public_key(),
        "Even assumption should differ from actual odd key"
    );

    // Handshake using assumed-even key (as production code does)
    let mut initiator = HandshakeState::new_initiator(kp_a, assumed_even_b);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(kp_b);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();

    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    // Verify sessions can communicate
    let mut sender = initiator.into_session().unwrap();
    let mut receiver = responder.into_session().unwrap();

    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt(b"parity test").unwrap();
    let plaintext = receiver
        .decrypt_with_replay_check(&ciphertext, counter)
        .unwrap();
    assert_eq!(plaintext, b"parity test");
}

// ===== XK Handshake Tests =====

#[test]
fn test_xk_full_handshake() {
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();
    let initiator_epoch = generate_epoch();
    let responder_epoch = generate_epoch();

    let responder_pub = responder_keypair.public_key();

    // XK: initiator knows responder's static, responder learns initiator's in msg3
    let mut initiator = HandshakeState::new_xk_initiator(initiator_keypair, responder_pub);
    initiator.set_local_epoch(initiator_epoch);
    let mut responder = HandshakeState::new_xk_responder(responder_keypair);
    responder.set_local_epoch(responder_epoch);

    assert_eq!(initiator.role(), HandshakeRole::Initiator);
    assert_eq!(responder.role(), HandshakeRole::Responder);

    // Initially, responder doesn't know initiator's identity
    assert!(responder.remote_static().is_none());

    // Message 1: Initiator -> Responder (e, es)
    let msg1 = initiator.write_xk_message_1().unwrap();
    assert_eq!(msg1.len(), XK_HANDSHAKE_MSG1_SIZE);
    assert_eq!(msg1.len(), 33); // ephemeral only

    responder.read_xk_message_1(&msg1).unwrap();

    // After msg1: responder still doesn't know initiator's identity (XK property)
    assert!(responder.remote_static().is_none());
    assert!(responder.remote_epoch().is_none());

    // Message 2: Responder -> Initiator (e, ee + epoch)
    let msg2 = responder.write_xk_message_2().unwrap();
    assert_eq!(msg2.len(), XK_HANDSHAKE_MSG2_SIZE);
    assert_eq!(msg2.len(), 57); // 33 ephemeral + 24 encrypted epoch

    initiator.read_xk_message_2(&msg2).unwrap();

    // After msg2: initiator learned responder's epoch
    assert_eq!(initiator.remote_epoch(), Some(responder_epoch));
    // Neither side is complete yet
    assert!(!initiator.is_complete());
    assert!(!responder.is_complete());

    // Message 3: Initiator -> Responder (s, se + epoch)
    let msg3 = initiator.write_xk_message_3().unwrap();
    assert_eq!(msg3.len(), XK_HANDSHAKE_MSG3_SIZE);
    assert_eq!(msg3.len(), 73); // 49 encrypted static + 24 encrypted epoch

    responder.read_xk_message_3(&msg3).unwrap();

    // Both should be complete now
    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    // After msg3: responder now knows initiator's identity
    assert!(responder.remote_static().is_some());
    assert_eq!(
        responder.remote_static().unwrap(),
        &initiator_keypair.public_key()
    );

    // Responder learned initiator's epoch from msg3
    assert_eq!(responder.remote_epoch(), Some(initiator_epoch));

    // Handshake hashes should match
    assert_eq!(initiator.handshake_hash(), responder.handshake_hash());

    // Convert to sessions
    let mut initiator_session = initiator.into_session().unwrap();
    let mut responder_session = responder.into_session().unwrap();

    // Test bidirectional encryption
    let plaintext = b"Hello via XK!";
    let ciphertext = initiator_session.encrypt(plaintext).unwrap();
    let decrypted = responder_session.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);

    let plaintext2 = b"XK reply!";
    let ciphertext2 = responder_session.encrypt(plaintext2).unwrap();
    let decrypted2 = initiator_session.decrypt(&ciphertext2).unwrap();
    assert_eq!(decrypted2, plaintext2);
}

#[test]
fn test_xk_message_sizes() {
    assert_eq!(XK_HANDSHAKE_MSG1_SIZE, 33); // ephemeral only
    assert_eq!(XK_HANDSHAKE_MSG2_SIZE, 33 + 24); // ephemeral + encrypted epoch
    assert_eq!(XK_HANDSHAKE_MSG3_SIZE, 33 + 16 + 24); // encrypted static + encrypted epoch
}

#[test]
fn test_xk_identity_timing() {
    // XK property: responder doesn't learn initiator identity until msg3
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();

    let mut initiator =
        HandshakeState::new_xk_initiator(initiator_keypair, responder_keypair.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(responder_keypair);
    responder.set_local_epoch(generate_epoch());

    // Before any messages
    assert!(responder.remote_static().is_none());

    // After msg1
    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    assert!(
        responder.remote_static().is_none(),
        "XK: responder should NOT know identity after msg1"
    );

    // After msg2
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    assert!(
        responder.remote_static().is_none(),
        "XK: responder should NOT know identity after msg2"
    );

    // After msg3
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();
    assert!(
        responder.remote_static().is_some(),
        "XK: responder should know identity after msg3"
    );
    assert_eq!(
        responder.remote_static().unwrap(),
        &initiator_keypair.public_key()
    );
}

#[test]
fn test_xk_wrong_state_errors() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    // Initiator can't read XK msg1
    let mut initiator = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());
    assert!(
        initiator
            .read_xk_message_1(&[0u8; XK_HANDSHAKE_MSG1_SIZE])
            .is_err()
    );

    // Initiator can't write msg2
    assert!(initiator.write_xk_message_2().is_err());

    // Initiator can't write msg3 before msg2
    assert!(initiator.write_xk_message_3().is_err());

    // Responder can't write msg1
    let mut responder = HandshakeState::new_xk_responder(keypair2);
    responder.set_local_epoch(generate_epoch());
    assert!(responder.write_xk_message_1().is_err());

    // Responder can't read msg3 before msg2
    assert!(
        responder
            .read_xk_message_3(&[0u8; XK_HANDSHAKE_MSG3_SIZE])
            .is_err()
    );
}

#[test]
fn test_xk_handshake_hash_differs_from_ik() {
    // XK and IK should produce different handshake hashes (different protocol names)
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let epoch1 = generate_epoch();
    let epoch2 = generate_epoch();

    // Complete an IK handshake
    let mut ik_init = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    ik_init.set_local_epoch(epoch1);
    let mut ik_resp = HandshakeState::new_responder(keypair2);
    ik_resp.set_local_epoch(epoch2);
    let msg1 = ik_init.write_message_1().unwrap();
    ik_resp.read_message_1(&msg1).unwrap();
    let msg2 = ik_resp.write_message_2().unwrap();
    ik_init.read_message_2(&msg2).unwrap();
    let ik_hash = ik_init.handshake_hash();

    // Complete an XK handshake with the same keys
    let mut xk_init = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    xk_init.set_local_epoch(epoch1);
    let mut xk_resp = HandshakeState::new_xk_responder(keypair2);
    xk_resp.set_local_epoch(epoch2);
    let msg1 = xk_init.write_xk_message_1().unwrap();
    xk_resp.read_xk_message_1(&msg1).unwrap();
    let msg2 = xk_resp.write_xk_message_2().unwrap();
    xk_init.read_xk_message_2(&msg2).unwrap();
    let msg3 = xk_init.write_xk_message_3().unwrap();
    xk_resp.read_xk_message_3(&msg3).unwrap();
    let xk_hash = xk_init.handshake_hash();

    assert_ne!(
        ik_hash, xk_hash,
        "IK and XK should produce different handshake hashes"
    );
}

#[test]
fn test_xk_multiple_messages_after_handshake() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut initiator = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(keypair2);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();

    let mut init_session = initiator.into_session().unwrap();
    let mut resp_session = responder.into_session().unwrap();

    // Send many messages
    for i in 0..100 {
        let msg = format!("XK message {}", i);
        let ct = init_session.encrypt(msg.as_bytes()).unwrap();
        let pt = resp_session.decrypt(&ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    assert_eq!(init_session.send_nonce(), 100);
    assert_eq!(resp_session.recv_nonce(), 100);
}

#[test]
fn test_xk_with_odd_parity_responder() {
    let secp = secp256k1::Secp256k1::new();

    // Node B (responder) - odd parity key
    let sk_b = secp256k1::SecretKey::from_slice(
        &hex::decode("b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0").unwrap(),
    )
    .unwrap();
    let kp_b = secp256k1::Keypair::from_secret_key(&secp, &sk_b);
    let (xonly_b, parity_b) = kp_b.public_key().x_only_public_key();
    assert_eq!(
        parity_b,
        Parity::Odd,
        "Test requires odd-parity responder key"
    );

    // Node A (initiator)
    let sk_a = secp256k1::SecretKey::from_slice(
        &hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap(),
    )
    .unwrap();
    let kp_a = secp256k1::Keypair::from_secret_key(&secp, &sk_a);

    // Simulate npub path: x-only → assumed even parity
    let assumed_even_b = xonly_b.public_key(Parity::Even);

    let mut initiator = HandshakeState::new_xk_initiator(kp_a, assumed_even_b);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(kp_b);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();

    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    let mut sender = initiator.into_session().unwrap();
    let mut receiver = responder.into_session().unwrap();

    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt(b"xk parity test").unwrap();
    let plaintext = receiver
        .decrypt_with_replay_check(&ciphertext, counter)
        .unwrap();
    assert_eq!(plaintext, b"xk parity test");
}

#[test]
fn test_xk_invalid_msg1_size() {
    let keypair = generate_keypair();
    let mut responder = HandshakeState::new_xk_responder(keypair);
    responder.set_local_epoch(generate_epoch());

    // Wrong size (IK msg1 size instead of XK)
    assert!(
        responder
            .read_xk_message_1(&[0u8; HANDSHAKE_MSG1_SIZE])
            .is_err()
    );
    // Too short
    assert!(responder.read_xk_message_1(&[0u8; 10]).is_err());
}

#[test]
fn test_xk_invalid_msg3_size() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut initiator = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(keypair2);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let _msg2 = responder.write_xk_message_2().unwrap();

    // Responder is now in Message2Done, try wrong-size msg3
    assert!(responder.read_xk_message_3(&[0u8; 10]).is_err());
    assert!(
        responder
            .read_xk_message_3(&[0u8; XK_HANDSHAKE_MSG3_SIZE + 1])
            .is_err()
    );
}

/// The `zeroize` features of `sha2` and `hmac` are on, so the SHA-256 state
/// that hashes each Diffie-Hellman result, and the two SHA-256 cores inside
/// the HMAC that HKDF runs on, are cleared when dropped. Without `sha2`'s
/// feature this does not compile; `hmac`'s forwards to the same `digest`
/// feature, so dropping it alone changes nothing while `sha2`'s is on.
#[test]
fn test_sha256_states_used_by_hashing_and_hkdf_are_cleared_on_drop() {
    fn clears_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    clears_on_drop::<sha2::Sha256>();
    clears_on_drop::<<sha2::Sha256 as hmac::EagerHash>::Core>();
}

/// A value that counts its drops, so a test can tell a value dropped once
/// from one dropped twice or leaked.
struct DropCounter<'a> {
    bytes: [u8; 48],
    heap: Vec<u8>,
    drops: &'a std::cell::Cell<usize>,
}

impl Drop for DropCounter<'_> {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn test_take_cleared_moves_the_value_out_intact_and_leaves_the_slot_none() {
    let drops = std::cell::Cell::new(0);
    let mut slot = Some(DropCounter {
        bytes: [0xa5; 48],
        heap: vec![7u8; 100],
        drops: &drops,
    });

    let taken = take_cleared(&mut slot).expect("the slot held a value");

    assert!(slot.is_none());
    assert_eq!(taken.bytes, [0xa5; 48]);
    assert_eq!(taken.heap, vec![7u8; 100]);
    assert_eq!(drops.get(), 0, "clearing the slot must not drop the value");
    drop(taken);
    assert_eq!(drops.get(), 1);
}

#[test]
fn test_take_cleared_slot_is_reusable_and_an_empty_slot_stays_empty() {
    let drops = std::cell::Cell::new(0);
    let mut slot: Option<DropCounter<'_>> = None;
    assert!(take_cleared(&mut slot).is_none());
    assert!(slot.is_none());

    slot = Some(DropCounter {
        bytes: [1; 48],
        heap: vec![2; 3],
        drops: &drops,
    });
    let first = take_cleared(&mut slot).expect("first value");
    slot = Some(DropCounter {
        bytes: [3; 48],
        heap: vec![4; 5],
        drops: &drops,
    });
    let second = take_cleared(&mut slot).expect("second value");
    assert_eq!((first.bytes[0], second.bytes[0]), (1, 3));
    assert!(slot.is_none());
    drop((first, second));
    assert_eq!(drops.get(), 2);
}

/// For `Option<bool>`, all-zero bytes read as `Some(false)`, not `None`.
/// The slot must still come out as `None`, so zeroing alone is not enough.
#[test]
fn test_take_cleared_leaves_none_where_zero_bytes_would_read_as_some() {
    let mut slot = Some(true);
    assert_eq!(take_cleared(&mut slot), Some(true));
    assert_eq!(slot, None);

    let mut slot = Some((true, [9u8; 32]));
    assert_eq!(take_cleared(&mut slot), Some((true, [9u8; 32])));
    assert_eq!(slot, None);
}

#[test]
fn test_take_cleared_session_still_decrypts_what_its_peer_encrypts() {
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();
    let mut initiator =
        HandshakeState::new_initiator(initiator_keypair, responder_keypair.public_key());
    let mut responder = HandshakeState::new_responder(responder_keypair);
    initiator.set_local_epoch(generate_epoch());
    responder.set_local_epoch(generate_epoch());
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();

    let mut handshake_slot = Some(initiator);
    let mut initiator = take_cleared(&mut handshake_slot).expect("handshake in slot");
    assert!(handshake_slot.is_none());
    initiator.read_message_2(&msg2).unwrap();

    let mut session_slot = Some(initiator.into_session().unwrap());
    let mut sender = take_cleared(&mut session_slot).expect("session in slot");
    assert!(session_slot.is_none());
    let mut receiver = responder.into_session().unwrap();
    let ciphertext = sender.encrypt(b"after the move").unwrap();
    assert_eq!(receiver.decrypt(&ciphertext).unwrap(), b"after the move");
}

#[test]
fn test_clear_slot_drops_a_present_value_once_and_leaves_none() {
    let drops = std::cell::Cell::new(0);
    let mut slot = Some(DropCounter {
        bytes: [5; 48],
        heap: vec![6; 7],
        drops: &drops,
    });
    clear_slot(&mut slot);
    assert!(slot.is_none());
    assert_eq!(drops.get(), 1);

    clear_slot(&mut slot);
    assert!(slot.is_none());
    assert_eq!(drops.get(), 1, "an empty slot has nothing to drop");

    let mut flag = Some(true);
    flag.take();
    clear_slot(&mut flag);
    assert_eq!(flag, None);
}

/// The transport's bytes on the wire, pinned: the nonce layout (four zero
/// bytes, then the counter little-endian), the counter advancing per message,
/// the AAD bound to the tag, and the tag after the ciphertext. Computed with
/// the `ring` code these replaced; every backend must produce them.
#[test]
fn test_cipher_state_output_is_pinned() {
    let mut cipher = CipherState::new([0x42; 32]);
    let a = cipher
        .encrypt_with_aad(b"fips wire vector", &[0x11; 16])
        .unwrap();
    let b = cipher.encrypt_with_aad(b"", &[0x22; 12]).unwrap();
    let c = cipher.encrypt(b"handshake payload").unwrap();
    assert_eq!(
        hex::encode(&a),
        "3f0f94583dc35abf898122519c5bc7ca1c821a009610f403d5ef09d65d2f30e3"
    );
    assert_eq!(hex::encode(&b), "d4cce26bcf9b6a41c82f4acf35e5dddf");
    assert_eq!(
        hex::encode(&c),
        "ab9695a696e42e1c095456a27767b6aceea57c728fc676fc57205b2f44791a8ef2"
    );

    let opened = CipherState::new([0x42; 32])
        .decrypt_with_counter_and_aad(&a, 0, &[0x11; 16])
        .unwrap();
    assert_eq!(opened, b"fips wire vector");
}

/// The ephemeral key comes from the handshake's entropy source: two
/// initiators under the same fixed source send the same ephemeral public
/// key, the first 33 bytes of message 1, and one under another source sends
/// a different one. Without this, nothing ties `generate_ephemeral` to `E`.
#[test]
fn test_handshake_ephemeral_draws_from_the_entropy_source() {
    use crate::testutil::FixedEntropy;

    let static_keypair = generate_keypair();
    let remote_static = generate_keypair().public_key();
    let epoch = generate_epoch();

    let mut first =
        handshake::HandshakeState::<FixedEntropy<1>>::new_initiator(static_keypair, remote_static);
    first.set_local_epoch(epoch);
    let mut second =
        handshake::HandshakeState::<FixedEntropy<1>>::new_initiator(static_keypair, remote_static);
    second.set_local_epoch(epoch);
    let mut other =
        handshake::HandshakeState::<FixedEntropy<2>>::new_initiator(static_keypair, remote_static);
    other.set_local_epoch(epoch);

    let first = first.write_message_1().unwrap();
    let second = second.write_message_1().unwrap();
    let other = other.write_message_1().unwrap();

    assert_eq!(first[..PUBKEY_SIZE], second[..PUBKEY_SIZE]);
    assert_ne!(first[..PUBKEY_SIZE], other[..PUBKEY_SIZE]);
}
