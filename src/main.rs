use fips::{AuthChallenge, Identity, PeerIdentity};

fn main() {
    println!("FIPS Identity Module Demo");
    println!("=========================\n");

    // Generate a new identity
    println!("1. Generating a new identity...");
    let alice = Identity::generate();
    println!("   npub:    {}", alice.npub());
    println!("   node_id: {}", alice.node_id());
    println!("   address: {}", alice.address());

    // Create a peer identity from an npub
    println!("\n2. Creating PeerIdentity from npub...");
    let alice_peer = PeerIdentity::from_npub(&alice.npub()).unwrap();
    println!("   Parsed:  {}", alice_peer);
    println!("   Match:   {}", alice_peer.node_id() == alice.node_id());

    // Sign and verify data
    println!("\n3. Signing and verifying data...");
    let message = b"Hello, FIPS network!";
    let signature = alice.sign(message);
    println!("   Message: {:?}", String::from_utf8_lossy(message));
    println!("   Signed by Alice");

    let valid = alice_peer.verify(message, &signature);
    println!("   Verified by peer: {}", valid);

    let tampered = alice_peer.verify(b"Tampered message", &signature);
    println!("   Tampered message: {}", tampered);

    // Authentication challenge-response
    // This simulates the mutual authentication that occurs when two FIPS nodes
    // establish a connection. Unlike TLS which binds identity at the transport
    // layer, FIPS authentication works over any transport (including radio/serial).
    println!("\n4. Authentication challenge-response...");
    println!("   Scenario: Alice wants to verify that Bob controls his claimed npub");
    println!();

    let bob = Identity::generate();
    println!("   Bob claims to be: {}", bob.npub());
    println!("   (Bob's node_id would be: {})", bob.node_id());
    println!();

    // Step 1: Alice generates a random 32-byte challenge
    // This nonce ensures Bob can't pre-compute responses
    let challenge = AuthChallenge::generate();
    println!("   [Alice] Generated 32-byte random challenge");
    println!("           Challenge: {:02x}{:02x}{:02x}{:02x}...",
        challenge.as_bytes()[0], challenge.as_bytes()[1],
        challenge.as_bytes()[2], challenge.as_bytes()[3]);
    println!();

    // Step 2: Bob signs the challenge with his private key
    // The signature covers: SHA256("fips-auth-v1" || challenge || timestamp)
    // - Domain prefix prevents cross-protocol signature reuse
    // - Timestamp enables replay attack detection
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("   [Bob]   Signing challenge with timestamp {}", timestamp);
    println!("           Digest = SHA256(\"fips-auth-v1\" || challenge || timestamp)");

    let response = bob.sign_challenge(challenge.as_bytes(), timestamp);
    println!("           Signature created (64 bytes)");
    println!();

    // Step 3: Alice verifies the response
    // If valid, she now knows Bob controls the private key for his claimed npub
    println!("   [Alice] Verifying Bob's response...");
    println!("           - Checking signature against claimed npub");
    println!("           - Checking timestamp is within acceptable window");

    match challenge.verify(&response) {
        Ok(node_id) => {
            println!();
            println!("   [Alice] SUCCESS: Bob proved ownership of his npub");
            println!("           Verified node_id: {}", node_id);
            println!("           Bob is now an authenticated peer");
        }
        Err(e) => {
            println!();
            println!("   [Alice] FAILED: {}", e);
            println!("           Connection would be terminated");
        }
    }

    // Deterministic identity from secret
    println!("\n5. Deterministic identity from secret bytes...");
    let secret: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let fixed = Identity::from_secret_bytes(&secret).unwrap();
    println!("   npub: {}", fixed.npub());

    let fixed2 = Identity::from_secret_bytes(&secret).unwrap();
    println!("   Same secret produces same npub: {}", fixed.npub() == fixed2.npub());

    println!("\nDone.");
}
