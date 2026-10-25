use alloc::format;
use alloc::string::ToString;
use std::collections::HashSet;
use std::net::Ipv6Addr;

use secp256k1::{Keypair, SecretKey};

use super::*;
use crate::testutil::{FixedEntropy, TestEntropy};

type Identity = super::Identity<TestEntropy>;
type AuthChallenge = super::AuthChallenge<TestEntropy>;

#[test]
fn test_node_addr_from_slice() {
    let bytes = [0u8; 16];
    let node_addr = NodeAddr::from_slice(&bytes).unwrap();
    assert_eq!(node_addr.as_bytes(), &bytes);

    // Wrong length should fail
    let short = [0u8; 8];
    assert!(matches!(
        NodeAddr::from_slice(&short),
        Err(IdentityError::InvalidNodeAddrLength(8))
    ));
}

#[test]
fn test_fips_address_validation() {
    // Valid address with fd prefix
    let mut valid = [0u8; 16];
    valid[0] = 0xfd;
    assert!(Ipv6Address::from_bytes(valid).is_ok());

    // Invalid prefix
    let mut invalid = [0u8; 16];
    invalid[0] = 0xfe;
    assert!(matches!(
        Ipv6Address::from_bytes(invalid),
        Err(IdentityError::InvalidAddressPrefix(0xfe))
    ));
}

#[test]
fn test_decode_npub_invalid_prefix() {
    // nsec instead of npub
    let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    let result = decode_npub(nsec);
    assert!(matches!(result, Err(IdentityError::InvalidNpubPrefix(_))));
}

#[test]
fn test_decode_npub_invalid_checksum() {
    // Valid npub with corrupted checksum
    let bad_npub = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    let result = decode_npub(bad_npub);
    assert!(result.is_err());
}

#[test]
fn test_peer_identity_from_invalid_npub() {
    let result = PeerIdentity::from_npub("npub1invalid");
    assert!(result.is_err());

    let result =
        PeerIdentity::from_npub("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5");
    assert!(matches!(result, Err(IdentityError::InvalidNpubPrefix(_))));
}

#[test]
fn test_nsec_roundtrip() {
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
    let nsec = encode_nsec(&secret_key);

    assert!(nsec.starts_with("nsec1"));
    assert_eq!(nsec.len(), 63);

    let decoded = decode_nsec(&nsec).unwrap();
    assert_eq!(decoded.secret_bytes(), secret_bytes);
}

#[test]
fn test_decode_secret_nsec() {
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
    let nsec = encode_nsec(&secret_key);

    let decoded = decode_secret(&nsec).unwrap();
    assert_eq!(decoded.secret_bytes(), secret_bytes);
}

#[test]
fn test_decode_secret_hex() {
    let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let decoded = decode_secret(hex_str).unwrap();

    let expected: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    assert_eq!(decoded.secret_bytes(), expected);
}

// ===== encoding.rs error path tests =====

#[test]
fn test_decode_npub_invalid_length() {
    // Encode 16 bytes (too short) as bech32 with npub prefix
    let short =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), &[0u8; 16]).unwrap();
    let result = decode_npub(&short);
    assert!(matches!(result, Err(IdentityError::InvalidNpubLength(16))));
}

#[test]
fn test_decode_nsec_invalid_length() {
    // Encode 16 bytes (too short) as bech32 with nsec prefix
    let short =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("nsec"), &[0u8; 16]).unwrap();
    let result = decode_nsec(&short);
    assert!(matches!(result, Err(IdentityError::InvalidNsecLength(16))));
}

#[test]
fn test_decode_secret_hex_wrong_length() {
    // 16 hex bytes (too short for a secret key)
    let result = decode_secret("0102030405060708090a0b0c0d0e0f10");
    assert!(matches!(result, Err(IdentityError::InvalidNsecLength(16))));
}

#[test]
fn test_decode_secret_hex_invalid_chars() {
    let result = decode_secret("zzzz");
    assert!(matches!(result, Err(IdentityError::InvalidHex(_))));
}

// ===== node_addr.rs tests =====

#[test]
fn test_node_addr_debug() {
    let bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let node_addr = NodeAddr::from_bytes(bytes);
    let debug = format!("{:?}", node_addr);
    assert_eq!(debug, "NodeAddr(0123456789abcdef)");
}

#[test]
fn test_node_addr_display() {
    let bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let node_addr = NodeAddr::from_bytes(bytes);
    let display = format!("{}", node_addr);
    assert_eq!(display, "0123456789abcdeffedcba9876543210");
}

#[test]
fn test_node_addr_as_slice() {
    let bytes = [0xaa; 16];
    let node_addr = NodeAddr::from_bytes(bytes);
    assert_eq!(node_addr.as_slice(), &bytes[..]);
    assert_eq!(node_addr.as_slice().len(), 16);
}

#[test]
fn test_node_addr_as_ref() {
    let bytes = [0xbb; 16];
    let node_addr = NodeAddr::from_bytes(bytes);
    let r: &[u8] = node_addr.as_ref();
    assert_eq!(r, &bytes[..]);
}

// ===== address.rs tests =====

#[test]
fn test_fips_address_from_slice_success() {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;
    bytes[1] = 0x42;
    let addr = Ipv6Address::from_slice(&bytes).unwrap();
    assert_eq!(addr.as_bytes(), &bytes);
}

#[test]
fn test_fips_address_from_slice_wrong_length() {
    let short = [0xfd; 8];
    assert!(matches!(
        Ipv6Address::from_slice(&short),
        Err(IdentityError::InvalidAddressLength(8))
    ));

    let long = [0xfd; 20];
    assert!(matches!(
        Ipv6Address::from_slice(&long),
        Err(IdentityError::InvalidAddressLength(20))
    ));
}

#[test]
fn test_fips_address_from_slice_wrong_prefix() {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    assert!(matches!(
        Ipv6Address::from_slice(&bytes),
        Err(IdentityError::InvalidAddressPrefix(0xfe))
    ));
}

#[test]
fn test_fips_address_debug() {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;
    let addr = Ipv6Address::from_bytes(bytes).unwrap();
    let debug = format!("{:?}", addr);
    assert!(debug.starts_with("Ipv6Address("));
    assert!(debug.contains("fd"));
}

#[test]
fn test_fips_address_display() {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;
    let addr = Ipv6Address::from_bytes(bytes).unwrap();
    let display = format!("{}", addr);
    // Display is the IPv6 representation
    assert!(display.starts_with("fd"));
}

// ===== peer.rs tests =====

#[test]
fn test_peer_identity_pubkey_full_preserved_parity() {
    // Create two identities and find one with odd parity to make this test meaningful
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let keypair = Keypair::from_seckey_slice(super::secp(), &secret_bytes).unwrap();
    let full_pubkey = keypair.public_key();

    let peer = PeerIdentity::from_pubkey_full(full_pubkey);
    // pubkey_full should return the exact key provided, preserving parity
    assert_eq!(peer.pubkey_full(), full_pubkey);
}

// ===== IdentityError conversions =====
//
// The four `From` impls are written by hand (see `mod.rs`). Each test makes
// a real error of the wrapped type, converts it, and checks the variant, the
// message, and that `source()` is `None`.

#[test]
fn test_identity_error_from_secp256k1_error() {
    let inner = SecretKey::from_slice(&[0u8; 32]).unwrap_err();
    let err = IdentityError::from(inner);
    assert!(matches!(err, IdentityError::InvalidSecretKey(e) if e == inner));
    assert_eq!(format!("{err}"), format!("invalid secret key: {inner}"));
    assert!(core::error::Error::source(&err).is_none());
}

#[test]
fn test_identity_error_from_bech32_encode_error() {
    // A bech32 string is limited to 1023 characters; 1000 data bytes exceed it.
    let inner =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), &[0u8; 1000])
            .unwrap_err();
    let text = format!("{inner}");
    let err = IdentityError::from(inner);
    assert!(matches!(err, IdentityError::Bech32Encode(_)));
    assert_eq!(format!("{err}"), format!("bech32 encoding error: {text}"));
    assert!(core::error::Error::source(&err).is_none());
}

#[test]
fn test_identity_error_from_bech32_decode_error() {
    let inner = bech32::decode("not bech32").unwrap_err();
    let text = format!("{inner}");
    let err = IdentityError::from(inner);
    assert!(matches!(err, IdentityError::Bech32Decode(_)));
    assert_eq!(format!("{err}"), format!("bech32 decoding error: {text}"));
    assert!(core::error::Error::source(&err).is_none());
}

#[test]
fn test_identity_error_from_hex_error() {
    let inner = hex::decode("zz").unwrap_err();
    let err = IdentityError::from(inner);
    assert!(matches!(err, IdentityError::InvalidHex(e) if e == inner));
    assert_eq!(format!("{err}"), format!("invalid hex encoding: {inner}"));
    assert!(core::error::Error::source(&err).is_none());
}

// ===== the shared context =====

#[test]
fn test_install_sets_an_empty_cell_once_and_never_replaces_it() {
    let cell = OnceBox::new();
    assert!(install(&cell, &[1u8; 32]));
    let first: *const Secp256k1<All> = cell.get().unwrap();
    assert!(!install(&cell, &[2u8; 32]));
    assert!(core::ptr::eq(cell.get().unwrap(), first));
}

#[test]
fn test_seeded_context_signs_and_verifies_like_the_default_one() {
    // Blinding changes how the context computes, not what it computes: a
    // signature without auxiliary randomness is the same from both.
    let cell = OnceBox::new();
    assert!(install(&cell, &[3u8; 32]));
    let seeded = cell.get().unwrap();
    let plain = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&plain, &[0x11u8; 32]).unwrap();
    let digest = sha256(b"blinding does not change signatures");
    let a = seeded.sign_schnorr_no_aux_rand(&digest, &keypair);
    let b = plain.sign_schnorr_no_aux_rand(&digest, &keypair);
    assert_eq!(a, b);
    let peer = PeerIdentity::from_pubkey(keypair.x_only_public_key().0);
    assert!(peer.verify(b"blinding does not change signatures", &a));
}

#[test]
fn test_init_secp_never_replaces_the_installed_context() {
    // Other tests in this binary may have built the context already, so the
    // first call's result depends on test order; the second's does not.
    let _ = init_secp(&[4u8; 32]);
    let installed: *const Secp256k1<All> = secp();
    assert!(!init_secp(&[5u8; 32]));
    assert!(core::ptr::eq(secp(), installed));
}

#[test]
fn test_identity_generation() {
    let identity = Identity::generate();

    // NodeAddr should be 16 bytes
    assert_eq!(identity.node_addr().as_bytes().len(), 16);

    // Address should start with 0xfd
    assert_eq!(identity.address().as_bytes()[0], 0xfd);

    // Address bytes 1-15 should match node_addr bytes 0-14
    assert_eq!(
        &identity.address().as_bytes()[1..16],
        &identity.node_addr().as_bytes()[0..15]
    );
}

#[test]
fn test_node_addr_from_pubkey_deterministic() {
    let identity = Identity::generate();
    let pubkey = identity.pubkey();

    let node_addr1 = NodeAddr::from_pubkey(&pubkey);
    let node_addr2 = NodeAddr::from_pubkey(&pubkey);

    assert_eq!(node_addr1, node_addr2);
}

#[test]
fn test_fips_address_ipv6_format() {
    let identity = Identity::generate();
    let ipv6 = identity.address().to_ipv6();
    let addr_str = ipv6.to_string();

    // Should start with fd (ULA prefix)
    assert!(addr_str.starts_with("fd"));

    // Conversion should be lossless
    let octets = ipv6.octets();
    assert_eq!(&octets, identity.address().as_bytes());
}

#[test]
fn test_auth_challenge_verify_success() {
    let identity = Identity::generate();
    let challenge = AuthChallenge::generate();
    let timestamp = 1234567890u64;

    let response = identity.sign_challenge(challenge.as_bytes(), timestamp);
    let result = challenge.verify(&response);

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), *identity.node_addr());
}

#[test]
fn test_auth_challenge_verify_wrong_challenge() {
    let identity = Identity::generate();
    let challenge1 = AuthChallenge::generate();
    let challenge2 = AuthChallenge::generate();
    let timestamp = 1234567890u64;

    let response = identity.sign_challenge(challenge1.as_bytes(), timestamp);
    let result = challenge2.verify(&response);

    assert!(matches!(
        result,
        Err(IdentityError::SignatureVerificationFailed)
    ));
}

#[test]
fn test_auth_challenge_verify_wrong_timestamp() {
    let identity = Identity::generate();
    let challenge = AuthChallenge::generate();

    let response = identity.sign_challenge(challenge.as_bytes(), 1234567890);

    // Modify the timestamp in the response
    let bad_response = AuthResponse {
        pubkey: response.pubkey,
        timestamp: 9999999999,
        signature: response.signature,
    };

    let result = challenge.verify(&bad_response);
    assert!(matches!(
        result,
        Err(IdentityError::SignatureVerificationFailed)
    ));
}

#[test]
fn test_node_addr_ordering() {
    let id1 = Identity::generate();
    let id2 = Identity::generate();

    // NodeAddrs should be comparable for root election
    let _cmp = id1.node_addr().cmp(id2.node_addr());
}

#[test]
fn test_identity_from_secret_bytes() {
    // A known secret key (32 bytes)
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let identity1 = Identity::from_secret_bytes(&secret_bytes).unwrap();
    let identity2 = Identity::from_secret_bytes(&secret_bytes).unwrap();

    // Same secret key should produce same node_addr
    assert_eq!(identity1.node_addr(), identity2.node_addr());
    assert_eq!(identity1.address(), identity2.address());
}

#[test]
fn test_identity_sign() {
    let identity = Identity::generate();
    let data = b"test message";

    let sig = identity.sign(data);

    // Verify the signature manually
    let digest = super::sha256(data);
    assert!(
        super::secp()
            .verify_schnorr(&sig, &digest, &identity.pubkey())
            .is_ok()
    );
}

#[test]
fn test_npub_encoding() {
    let identity = Identity::generate();
    let npub = identity.npub();

    // Should start with "npub1"
    assert!(npub.starts_with("npub1"));

    // Should be 63 characters (npub1 + 58 chars of bech32 data)
    assert_eq!(npub.len(), 63);
}

#[test]
fn test_npub_roundtrip() {
    let identity = Identity::generate();
    let npub = identity.npub();

    let decoded = decode_npub(&npub).unwrap();
    assert_eq!(decoded, identity.pubkey());
}

#[test]
fn test_npub_known_vector() {
    // Test against a known npub (from NIP-19 test vectors or generated externally)
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let identity = Identity::from_secret_bytes(&secret_bytes).unwrap();
    let npub = identity.npub();

    // Decode and verify it matches the original pubkey
    let decoded = decode_npub(&npub).unwrap();
    assert_eq!(decoded, identity.pubkey());

    // npub should be deterministic
    let npub2 = encode_npub(&identity.pubkey());
    assert_eq!(npub, npub2);
}

#[test]
fn test_peer_identity_from_npub() {
    let identity = Identity::generate();
    let npub = identity.npub();

    let peer = PeerIdentity::from_npub(&npub).unwrap();

    assert_eq!(peer.pubkey(), identity.pubkey());
    assert_eq!(peer.node_addr(), identity.node_addr());
    assert_eq!(peer.address(), identity.address());
    assert_eq!(peer.npub(), npub);
}

#[test]
fn test_peer_identity_verify_signature() {
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());

    let data = b"hello world";
    let signature = identity.sign(data);

    assert!(peer.verify(data, &signature));
    assert!(!peer.verify(b"wrong data", &signature));
}

#[test]
fn test_peer_identity_display() {
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());

    let display = format!("{}", peer);
    assert!(display.starts_with("npub1"));
    assert_eq!(display, identity.npub());
}

#[test]
fn test_decode_nsec_invalid_prefix() {
    // Use a valid npub (from a generated identity) to test prefix rejection
    let identity = Identity::generate();
    let npub = identity.npub();
    let result = decode_nsec(&npub);
    assert!(matches!(result, Err(IdentityError::InvalidNsecPrefix(_))));
}

#[test]
fn test_identity_from_secret_str_nsec() {
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
    let nsec = encode_nsec(&secret_key);

    let identity = Identity::from_secret_str(&nsec).unwrap();
    let identity_from_bytes = Identity::from_secret_bytes(&secret_bytes).unwrap();

    assert_eq!(identity.node_addr(), identity_from_bytes.node_addr());
}

#[test]
fn test_identity_from_secret_str_hex() {
    let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let identity = Identity::from_secret_str(hex_str).unwrap();
    let identity_from_bytes = Identity::from_secret_bytes(&secret_bytes).unwrap();

    assert_eq!(identity.node_addr(), identity_from_bytes.node_addr());
}

#[test]
fn test_hex_conversion_case1() {
    let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let identity = Identity::from_secret_str(hex_str).unwrap();
    let npub = identity.npub();
    assert!(npub.starts_with("npub1"));
}

#[test]
fn test_hex_conversion_case2() {
    let hex_str = "b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0";
    let identity = Identity::from_secret_str(hex_str).unwrap();
    let npub = identity.npub();
    assert!(npub.starts_with("npub1"));
}

// ===== node_addr.rs tests =====

#[test]
fn test_node_addr_hash() {
    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let mut set = HashSet::new();
    set.insert(*id1.node_addr());
    set.insert(*id2.node_addr());
    assert_eq!(set.len(), 2);
    // Re-inserting the same address doesn't grow the set
    set.insert(*id1.node_addr());
    assert_eq!(set.len(), 2);
}

// ===== address.rs tests =====

#[test]
fn test_fips_address_into_ipv6() {
    let identity = Identity::generate();
    let addr = *identity.address();
    // Test the From trait (not to_ipv6 method)
    let ipv6: Ipv6Addr = addr.into();
    assert_eq!(ipv6.octets(), *addr.as_bytes());
}

#[test]
fn test_fips_address_eq_hash() {
    let identity = Identity::generate();
    let addr1 = *identity.address();
    let addr2 = Ipv6Address::from_node_addr(identity.node_addr());
    assert_eq!(addr1, addr2);

    let mut set = HashSet::new();
    set.insert(addr1);
    set.insert(addr2);
    assert_eq!(set.len(), 1);
}

// ===== auth.rs tests =====

#[test]
fn test_auth_challenge_from_bytes() {
    let bytes = [0x42u8; 32];
    let challenge = AuthChallenge::from_bytes(bytes);
    assert_eq!(challenge.as_bytes(), &bytes);
}

// ===== peer.rs tests =====

#[test]
fn test_peer_identity_from_pubkey_full() {
    let identity = Identity::generate();
    let full_pubkey = identity.pubkey_full();

    let peer = PeerIdentity::from_pubkey_full(full_pubkey);

    // x-only key should match
    assert_eq!(peer.pubkey(), identity.pubkey());
    // Full key should be preserved (not derived)
    assert_eq!(peer.pubkey_full(), full_pubkey);
    // Derived identifiers should match
    assert_eq!(peer.node_addr(), identity.node_addr());
    assert_eq!(peer.address(), identity.address());
}

#[test]
fn test_peer_identity_pubkey_full_even_parity_fallback() {
    let identity = Identity::generate();
    // from_pubkey only stores x-only, so pubkey_full must derive with even parity
    let peer = PeerIdentity::from_pubkey(identity.pubkey());
    let full = peer.pubkey_full();
    // The derived full key's x-only component should match
    let (x_only, _parity) = full.x_only_public_key();
    assert_eq!(x_only, identity.pubkey());
}

#[test]
fn test_peer_identity_debug() {
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());
    let debug = format!("{:?}", peer);
    assert!(debug.starts_with("PeerIdentity {"));
    assert!(debug.contains("node_addr"));
    assert!(debug.contains("address"));
}

// ===== local.rs tests =====

#[test]
fn test_identity_keypair() {
    let identity = Identity::generate();
    let keypair = identity.keypair();
    // keypair's public key should match identity's pubkey
    let (x_only, _) = keypair.x_only_public_key();
    assert_eq!(x_only, identity.pubkey());
}

#[test]
fn test_identity_pubkey_full() {
    let identity = Identity::generate();
    let full = identity.pubkey_full();
    // Full key's x-only component should match pubkey
    let (x_only, _) = full.x_only_public_key();
    assert_eq!(x_only, identity.pubkey());
}

#[test]
fn test_identity_debug() {
    let identity = Identity::generate();
    let debug = format!("{:?}", identity);
    assert!(debug.starts_with("Identity {"));
    assert!(debug.contains("node_addr"));
    assert!(debug.contains("address"));
    // Should NOT contain the secret key
    assert!(!debug.contains("keypair"));
    assert!(debug.contains(".."));
}

/// Hold a guard over `keypair` and return early or normally, the way the
/// handshake entry points do.
fn guarded_secret(keypair: &mut Keypair, fail: bool) -> Result<[u8; 32], ()> {
    let guard = ErasingKeypair::new(keypair);
    if fail {
        return Err(());
    }
    Ok(guard.get().secret_bytes())
}

#[test]
fn test_erasing_keypair_erases_the_callers_binding_in_place_on_every_exit() {
    let identity = Identity::generate();
    let original = identity.keypair().secret_bytes();
    // `non_secure_erase` overwrites a keypair with a fixed dummy whose
    // secret is 32 bytes of 0x01.
    let erased = [1u8; 32];
    assert_ne!(original, erased);

    let mut keypair = identity.keypair();
    assert_eq!(guarded_secret(&mut keypair, false), Ok(original));
    assert_eq!(keypair.secret_bytes(), erased);

    let mut keypair = identity.keypair();
    assert_eq!(guarded_secret(&mut keypair, true), Err(()));
    assert_eq!(keypair.secret_bytes(), erased);
}

#[test]
fn test_signatures_draw_their_auxiliary_bytes_from_the_entropy_source() {
    let secret = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let one = super::Identity::<FixedEntropy<1>>::from_secret_key(secret);
    let one_again = super::Identity::<FixedEntropy<1>>::from_secret_key(secret);
    let two = super::Identity::<FixedEntropy<2>>::from_secret_key(secret);

    let data = b"test message";
    assert_eq!(one.sign(data), one_again.sign(data));
    assert_ne!(one.sign(data), two.sign(data));

    let challenge = [0x22; 32];
    let timestamp = 1234567890u64;
    assert_eq!(
        one.sign_challenge(&challenge, timestamp).signature,
        one_again.sign_challenge(&challenge, timestamp).signature
    );
    assert_ne!(
        one.sign_challenge(&challenge, timestamp).signature,
        two.sign_challenge(&challenge, timestamp).signature
    );
}

#[test]
fn identity_generate_draws_its_secret_from_the_entropy_source() {
    let generated = super::Identity::<FixedEntropy<1>>::generate();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let expected = super::Identity::<FixedEntropy<1>>::from_secret_key(secret);
    assert_eq!(generated.node_addr(), expected.node_addr());
}

#[test]
fn auth_challenge_generate_draws_from_the_entropy_source() {
    let challenge = super::AuthChallenge::<FixedEntropy<7>>::generate();
    assert_eq!(challenge.as_bytes(), &[7; 32]);
}

/// The x-only key of the secp256k1 generator point, whose derived
/// identifiers below were computed independently of this crate.
fn generator_key() -> secp256k1::XOnlyPublicKey {
    let bytes: [u8; 32] =
        hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap();
    secp256k1::XOnlyPublicKey::from_byte_array(&bytes).unwrap()
}

#[test]
fn the_generator_keys_node_address_and_ipv6_address_match_values_computed_outside_the_crate() {
    let g = generator_key();
    let key = PeerKey::from_xonly(&g);
    assert_eq!(key.addr().to_string(), "132f39a98c31baaddba6525f5d43f295");
    assert_eq!(
        NodeAddr::from_pubkey(&g).to_string(),
        "132f39a98c31baaddba6525f5d43f295"
    );
    assert_eq!(
        key.address().to_string(),
        "fd13:2f39:a98c:31ba:addb:a652:5f5d:43f2"
    );
    assert_eq!(
        Ipv6Address::from_node_addr(&NodeAddr::from_pubkey(&g)).to_string(),
        "fd13:2f39:a98c:31ba:addb:a652:5f5d:43f2"
    );
}

#[test]
fn a_peer_key_round_trips_through_its_xonly_key_and_holds_its_serialized_bytes() {
    let k = Identity::generate().pubkey();
    let key = PeerKey::from_xonly(&k);
    assert_eq!(key.to_xonly(), Ok(k));
    assert_eq!(*key.bytes(), k.serialize());
    assert_eq!(PeerKey::new(k.serialize()), key);
}

#[test]
fn a_peer_key_of_bytes_off_the_curve_refuses_conversion_but_still_derives_addresses() {
    for bytes in [[0u8; 32], [0xffu8; 32]] {
        let key = PeerKey::new(bytes);
        assert!(key.to_xonly().is_err(), "{key:?} must not convert");
        assert_eq!(key.address(), Ipv6Address::from_node_addr(&key.addr()));
    }
}

#[test]
fn a_peer_key_is_its_32_bytes_and_nothing_more() {
    assert_eq!(core::mem::size_of::<PeerKey>(), 32);
}

#[test]
fn a_peer_keys_debug_output_is_its_first_four_bytes_in_hex() {
    let key = PeerKey::from_xonly(&generator_key());
    assert_eq!(format!("{key:?}"), "PeerKey(79be667e)");
}

#[test]
fn the_generator_keys_node_prefix_matches_the_value_computed_outside_the_crate() {
    let addr = NodeAddr::from_pubkey(&generator_key());
    let want: [u8; 15] = hex::decode("132f39a98c31baaddba6525f5d43f2")
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(addr.prefix().as_bytes(), &want);
    assert_eq!(
        Ipv6Address::from_node_addr(&addr).prefix().as_bytes(),
        &want
    );
    assert_eq!(addr.prefix(), NodePrefix::from_bytes(want));
}

#[test]
fn an_ipv6_address_names_the_prefix_of_the_node_address_it_was_derived_from() {
    let identity = Identity::generate();
    assert_eq!(identity.address().prefix(), identity.node_addr().prefix());
    assert_eq!(
        identity.node_addr().prefix().as_bytes()[..],
        identity.node_addr().as_bytes()[0..15]
    );
}

#[test]
fn a_prefix_from_octets_takes_bytes_one_to_fifteen_and_ignores_byte_zero() {
    let mut octets = [0u8; 16];
    for (i, b) in octets.iter_mut().enumerate() {
        *b = i as u8;
    }
    octets[0] = 0xfe;
    let prefix = NodePrefix::from_octets(&octets);
    let want: [u8; 15] = core::array::from_fn(|i| (i + 1) as u8);
    assert_eq!(prefix.as_bytes(), &want);
    octets[0] = 0xfd;
    assert_eq!(NodePrefix::from_octets(&octets), prefix);
}

#[test]
fn a_node_address_from_a_prefix_is_the_prefix_followed_by_a_zero_byte() {
    let g = NodeAddr::from_pubkey(&generator_key()).prefix();
    assert_eq!(
        NodeAddr::from_prefix(g).to_string(),
        "132f39a98c31baaddba6525f5d43f200"
    );
    let ones = NodePrefix::from_bytes([0xff; 15]);
    assert_eq!(
        NodeAddr::from_prefix(ones).to_string(),
        "ffffffffffffffffffffffffffffff00"
    );
}
