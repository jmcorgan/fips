use super::*;
use rand::Rng;
use secp256k1::Parity;

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

    // XX: neither side knows the other's static key
    let mut initiator = HandshakeState::new_initiator(initiator_keypair);
    initiator.set_local_epoch(initiator_epoch);
    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(responder_epoch);

    assert_eq!(initiator.role(), HandshakeRole::Initiator);
    assert_eq!(responder.role(), HandshakeRole::Responder);

    // Neither side knows the other's identity
    assert!(initiator.remote_static().is_none());
    assert!(responder.remote_static().is_none());

    // Message 1: Initiator -> Responder (e only)
    let msg1 = initiator.write_message_1().unwrap();
    assert_eq!(msg1.len(), HANDSHAKE_MSG1_SIZE);
    assert_eq!(msg1.len(), 33);

    responder.read_message_1(&msg1).unwrap();

    // After msg1: still no identities known
    assert!(initiator.remote_static().is_none());
    assert!(responder.remote_static().is_none());

    // Message 2: Responder -> Initiator (e, ee, s, es + epoch)
    let msg2 = responder.write_message_2().unwrap();
    assert_eq!(msg2.len(), HANDSHAKE_MSG2_SIZE);
    assert_eq!(msg2.len(), 106);

    initiator.read_message_2(&msg2).unwrap();

    // After msg2: initiator knows responder's identity
    assert!(initiator.remote_static().is_some());
    assert_eq!(
        initiator.remote_static().unwrap(),
        &responder_keypair.public_key()
    );
    assert_eq!(initiator.remote_epoch(), Some(responder_epoch));
    // Responder still doesn't know initiator
    assert!(responder.remote_static().is_none());

    // Neither side is complete yet
    assert!(!initiator.is_complete());
    assert!(!responder.is_complete());

    // Message 3: Initiator -> Responder (s, se + epoch)
    let msg3 = initiator.write_message_3().unwrap();
    assert_eq!(msg3.len(), HANDSHAKE_MSG3_SIZE);
    assert_eq!(msg3.len(), 73);

    responder.read_message_3(&msg3).unwrap();

    // Both should be complete now
    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    // After msg3: responder knows initiator's identity
    assert!(responder.remote_static().is_some());
    assert_eq!(
        responder.remote_static().unwrap(),
        &initiator_keypair.public_key()
    );
    assert_eq!(responder.remote_epoch(), Some(initiator_epoch));

    // Handshake hashes should match
    assert_eq!(initiator.handshake_hash(), responder.handshake_hash());

    // Convert to sessions
    let mut initiator_session = initiator.into_session().unwrap();
    let mut responder_session = responder.into_session().unwrap();

    // Test bidirectional encryption
    let plaintext = b"Hello via XX!";
    let ciphertext = initiator_session.encrypt(plaintext).unwrap();
    let decrypted = responder_session.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);

    let plaintext2 = b"XX reply!";
    let ciphertext2 = responder_session.encrypt(plaintext2).unwrap();
    let decrypted2 = initiator_session.decrypt(&ciphertext2).unwrap();
    assert_eq!(decrypted2, plaintext2);
}

#[test]
fn test_message_sizes() {
    assert_eq!(HANDSHAKE_MSG1_SIZE, 33); // ephemeral only
    assert_eq!(HANDSHAKE_MSG2_SIZE, 33 + 33 + 16 + 24); // e + encrypted static + encrypted epoch
    assert_eq!(HANDSHAKE_MSG3_SIZE, 33 + 16 + 24); // encrypted static + encrypted epoch
}

#[test]
fn test_identity_timing() {
    // XX property: initiator learns responder in msg2, responder learns initiator in msg3
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();

    let mut initiator = HandshakeState::new_initiator(initiator_keypair);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(generate_epoch());

    // Before any messages: neither side knows
    assert!(initiator.remote_static().is_none());
    assert!(responder.remote_static().is_none());

    // After msg1
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    assert!(initiator.remote_static().is_none(), "XX: initiator should NOT know identity after msg1");
    assert!(responder.remote_static().is_none(), "XX: responder should NOT know identity after msg1");

    // After msg2: initiator learns responder
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    assert!(initiator.remote_static().is_some(), "XX: initiator should know responder after msg2");
    assert_eq!(initiator.remote_static().unwrap(), &responder_keypair.public_key());
    assert!(responder.remote_static().is_none(), "XX: responder should NOT know initiator after msg2");

    // After msg3: responder learns initiator
    let msg3 = initiator.write_message_3().unwrap();
    responder.read_message_3(&msg3).unwrap();
    assert!(responder.remote_static().is_some(), "XX: responder should know initiator after msg3");
    assert_eq!(responder.remote_static().unwrap(), &initiator_keypair.public_key());
}

#[test]
fn test_wrong_state_errors() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    // Initiator can't read msg1
    let mut initiator = HandshakeState::new_initiator(keypair1);
    initiator.set_local_epoch(generate_epoch());
    assert!(initiator.read_message_1(&[0u8; HANDSHAKE_MSG1_SIZE]).is_err());

    // Initiator can't write msg2
    assert!(initiator.write_message_2().is_err());

    // Initiator can't write msg3 before msg2
    assert!(initiator.write_message_3().is_err());

    // Responder can't write msg1
    let mut responder = HandshakeState::new_responder(keypair2);
    responder.set_local_epoch(generate_epoch());
    assert!(responder.write_message_1().is_err());

    // Responder can't read msg3 before msg2
    assert!(responder.read_message_3(&[0u8; HANDSHAKE_MSG3_SIZE]).is_err());
}

#[test]
fn test_multiple_messages_after_handshake() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut initiator = HandshakeState::new_initiator(keypair1);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(keypair2);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    let msg3 = initiator.write_message_3().unwrap();
    responder.read_message_3(&msg3).unwrap();

    let mut init_session = initiator.into_session().unwrap();
    let mut resp_session = responder.into_session().unwrap();

    // Send many messages
    for i in 0..100 {
        let msg = format!("XX message {}", i);
        let ct = init_session.encrypt(msg.as_bytes()).unwrap();
        let pt = resp_session.decrypt(&ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    assert_eq!(init_session.send_nonce(), 100);
    assert_eq!(resp_session.recv_nonce(), 100);
}

#[test]
fn test_with_odd_parity() {
    // XX: no pre-message normalization needed, but ECDH x-only hashing
    // must still produce matching shared secrets regardless of parity.
    let secp = secp256k1::Secp256k1::new();

    // Node A (initiator) - even parity key
    let sk_a = secp256k1::SecretKey::from_slice(
        &hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
            .unwrap(),
    )
    .unwrap();
    let kp_a = secp256k1::Keypair::from_secret_key(&secp, &sk_a);

    // Node B (responder) - odd parity key
    let sk_b = secp256k1::SecretKey::from_slice(
        &hex::decode("b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0")
            .unwrap(),
    )
    .unwrap();
    let kp_b = secp256k1::Keypair::from_secret_key(&secp, &sk_b);
    let (_, parity_b) = kp_b.public_key().x_only_public_key();
    assert_eq!(parity_b, Parity::Odd, "Test requires odd-parity responder key");

    let mut initiator = HandshakeState::new_initiator(kp_a);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(kp_b);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    let msg3 = initiator.write_message_3().unwrap();
    responder.read_message_3(&msg3).unwrap();

    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    let mut sender = initiator.into_session().unwrap();
    let mut receiver = responder.into_session().unwrap();

    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt(b"xx parity test").unwrap();
    let plaintext = receiver.decrypt_with_replay_check(&ciphertext, counter).unwrap();
    assert_eq!(plaintext, b"xx parity test");
}

#[test]
fn test_invalid_msg_sizes() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    // Wrong size for msg1
    let mut responder = HandshakeState::new_responder(keypair1);
    responder.set_local_epoch(generate_epoch());
    assert!(responder.read_message_1(&[0u8; 10]).is_err());

    // Wrong size for msg3
    let mut initiator = HandshakeState::new_initiator(keypair1);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(keypair2);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let _msg2 = responder.write_message_2().unwrap();

    // Responder is now in Message2Done, try wrong-size msg3
    assert!(responder.read_message_3(&[0u8; 10]).is_err());
    assert!(responder.read_message_3(&[0u8; HANDSHAKE_MSG3_SIZE + 1]).is_err());
}

#[test]
fn test_decryption_failure_wrong_key() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();

    // Session between 1 and 2
    let mut init1 = HandshakeState::new_initiator(keypair1);
    init1.set_local_epoch(generate_epoch());
    let mut resp1 = HandshakeState::new_responder(keypair2);
    resp1.set_local_epoch(generate_epoch());

    let msg1 = init1.write_message_1().unwrap();
    resp1.read_message_1(&msg1).unwrap();
    let msg2 = resp1.write_message_2().unwrap();
    init1.read_message_2(&msg2).unwrap();
    let msg3 = init1.write_message_3().unwrap();
    resp1.read_message_3(&msg3).unwrap();

    let mut session1 = init1.into_session().unwrap();

    // Session between 1 and 3
    let mut init2 = HandshakeState::new_initiator(keypair1);
    init2.set_local_epoch(generate_epoch());
    let mut resp2 = HandshakeState::new_responder(keypair3);
    resp2.set_local_epoch(generate_epoch());

    let msg1 = init2.write_message_1().unwrap();
    resp2.read_message_1(&msg1).unwrap();
    let msg2 = resp2.write_message_2().unwrap();
    init2.read_message_2(&msg2).unwrap();
    let msg3 = init2.write_message_3().unwrap();
    resp2.read_message_3(&msg3).unwrap();

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
fn test_session_remote_static() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut init = HandshakeState::new_initiator(keypair1);
    init.set_local_epoch(generate_epoch());
    let mut resp = HandshakeState::new_responder(keypair2);
    resp.set_local_epoch(generate_epoch());

    let msg1 = init.write_message_1().unwrap();
    resp.read_message_1(&msg1).unwrap();
    let msg2 = resp.write_message_2().unwrap();
    init.read_message_2(&msg2).unwrap();
    let msg3 = init.write_message_3().unwrap();
    resp.read_message_3(&msg3).unwrap();

    let session1 = init.into_session().unwrap();
    let session2 = resp.into_session().unwrap();

    // Each session should know the other's static key
    assert_eq!(session1.remote_static(), &keypair2.public_key());
    assert_eq!(session2.remote_static(), &keypair1.public_key());
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
        assert!(!window.check(i), "Counter {} should be rejected as replay", i);
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
fn test_session_replay_protection() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut init = HandshakeState::new_initiator(keypair1);
    init.set_local_epoch(generate_epoch());
    let mut resp = HandshakeState::new_responder(keypair2);
    resp.set_local_epoch(generate_epoch());

    let msg1 = init.write_message_1().unwrap();
    resp.read_message_1(&msg1).unwrap();
    let msg2 = resp.write_message_2().unwrap();
    init.read_message_2(&msg2).unwrap();
    let msg3 = init.write_message_3().unwrap();
    resp.read_message_3(&msg3).unwrap();

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
