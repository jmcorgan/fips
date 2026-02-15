use super::{
    CipherState, HandshakeProgress, HandshakeRole, NoiseError, NoiseSession,
    HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, PROTOCOL_NAME, PUBKEY_SIZE,
};
use hkdf::Hkdf;
use rand::RngCore;
use secp256k1::{ecdh::shared_secret_point, Keypair, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// Symmetric state during handshake.
///
/// Maintains the chaining key (ck), handshake hash (h), and current cipher.
struct SymmetricState {
    /// Chaining key for key derivation.
    ck: [u8; 32],
    /// Handshake hash for transcript binding.
    h: [u8; 32],
    /// Current cipher state for encrypting handshake payloads.
    cipher: CipherState,
}

impl SymmetricState {
    /// Initialize with protocol name.
    fn initialize() -> Self {
        // If protocol name <= 32 bytes, pad with zeros
        // If > 32 bytes, hash it
        let h = if PROTOCOL_NAME.len() <= 32 {
            let mut h = [0u8; 32];
            h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
            h
        } else {
            let mut hasher = Sha256::new();
            hasher.update(PROTOCOL_NAME);
            hasher.finalize().into()
        };

        Self {
            ck: h,
            h,
            cipher: CipherState::empty(),
        }
    }

    /// Mix data into the handshake hash.
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// Mix key material into the chaining key.
    fn mix_key(&mut self, input_key_material: &[u8]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), input_key_material);
        let mut output = [0u8; 64];
        hk.expand(&[], &mut output)
            .expect("64 bytes is valid output length");

        self.ck.copy_from_slice(&output[..32]);

        // Initialize cipher with derived key for handshake encryption
        let mut key = [0u8; 32];
        key.copy_from_slice(&output[32..64]);
        self.cipher.initialize_key(key);
    }

    /// Encrypt and mix into hash.
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = self.cipher.encrypt(plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt and mix ciphertext into hash.
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = self.cipher.decrypt(ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Split into two cipher states for transport.
    fn split(&self) -> (CipherState, CipherState) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut output = [0u8; 64];
        hk.expand(&[], &mut output)
            .expect("64 bytes is valid output length");

        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&output[..32]);
        k2.copy_from_slice(&output[32..64]);

        (CipherState::new(k1), CipherState::new(k2))
    }

    /// Get the handshake hash (for channel binding).
    fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }
}

/// Handshake state for Noise IK.
pub struct HandshakeState {
    /// Our role in the handshake.
    role: HandshakeRole,
    /// Current progress.
    progress: HandshakeProgress,
    /// Symmetric state.
    symmetric: SymmetricState,
    /// Our static keypair.
    static_keypair: Keypair,
    /// Our ephemeral keypair (generated at handshake start).
    ephemeral_keypair: Option<Keypair>,
    /// Remote static public key.
    /// For initiator: known before handshake (from config).
    /// For responder: learned from message 1.
    remote_static: Option<PublicKey>,
    /// Remote ephemeral public key (learned during handshake).
    remote_ephemeral: Option<PublicKey>,
    /// Secp256k1 context.
    secp: Secp256k1<secp256k1::All>,
}

impl HandshakeState {
    /// Normalize a compressed public key to even parity for pre-message hashing.
    ///
    /// Nostr npubs encode x-only keys (no parity). The Noise IK pre-message
    /// mixes the responder's static key into the hash before any messages.
    /// Both sides must mix identical bytes. Since the initiator may only have
    /// the x-only key (from an npub), we normalize to even parity (0x02 prefix)
    /// so the hash chain matches regardless of the key's actual parity.
    ///
    /// This does NOT affect ECDH operations (which use x-coordinate-only output)
    /// or the keys sent in handshake messages (which use actual parity).
    fn normalize_for_premessage(pubkey: &PublicKey) -> [u8; PUBKEY_SIZE] {
        let mut bytes = pubkey.serialize();
        bytes[0] = 0x02; // Force even parity
        bytes
    }

    /// Create a new handshake as initiator.
    ///
    /// The initiator knows the responder's static key and will send first.
    pub fn new_initiator(static_keypair: Keypair, remote_static: PublicKey) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            role: HandshakeRole::Initiator,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: Some(remote_static),
            remote_ephemeral: None,
            secp,
        };

        // Mix in pre-message: <- s (responder's static is known)
        // Normalize to even parity so initiator and responder hash chains match
        // even when the initiator only has the x-only key (from npub).
        let normalized = Self::normalize_for_premessage(&remote_static);
        state.symmetric.mix_hash(&normalized);

        state
    }

    /// Create a new handshake as responder.
    ///
    /// The responder does NOT know the initiator's static key - it will be
    /// learned from message 1.
    pub fn new_responder(static_keypair: Keypair) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            role: HandshakeRole::Responder,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: None, // Will learn from message 1
            remote_ephemeral: None,
            secp,
        };

        // Mix in pre-message: <- s (our static, since we're responder)
        // Normalize to even parity to match initiator's hash chain.
        let normalized = Self::normalize_for_premessage(&state.static_keypair.public_key());
        state.symmetric.mix_hash(&normalized);

        state
    }

    /// Get our role.
    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Get current progress.
    pub fn progress(&self) -> HandshakeProgress {
        self.progress
    }

    /// Check if handshake is complete.
    pub fn is_complete(&self) -> bool {
        self.progress == HandshakeProgress::Complete
    }

    /// Get the remote static key (available after message 1 for responder).
    pub fn remote_static(&self) -> Option<&PublicKey> {
        self.remote_static.as_ref()
    }

    /// Generate ephemeral keypair.
    fn generate_ephemeral(&mut self) {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);

        let secret_key =
            SecretKey::from_slice(&secret_bytes).expect("32 random bytes is valid secret key");
        self.ephemeral_keypair = Some(Keypair::from_secret_key(&self.secp, &secret_key));
    }

    /// Perform ECDH between our secret and their public key.
    ///
    /// Uses x-only hashing (SHA-256 of just the x-coordinate) to produce
    /// a parity-independent shared secret. This is necessary because Nostr
    /// npubs encode x-only keys without parity information, so the initiator
    /// may have the wrong parity for the responder's static key. Since P and
    /// -P produce ECDH result points with the same x-coordinate, hashing
    /// only x ensures both sides derive the same shared secret.
    fn ecdh(&self, our_secret: &SecretKey, their_public: &PublicKey) -> [u8; 32] {
        // Get raw (x, y) coordinates (64 bytes) without any hashing
        let point = shared_secret_point(their_public, our_secret);
        // Hash only the x-coordinate (first 32 bytes), ignoring y/parity
        let mut hasher = Sha256::new();
        hasher.update(&point[..32]);
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Write message 1 (initiator only).
    ///
    /// Message 1 contains:
    /// - e: ephemeral public key (33 bytes)
    /// - encrypted s: our static public key encrypted (33 + 16 = 49 bytes)
    ///
    /// Total: 82 bytes
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.role != HandshakeRole::Initiator {
            return Err(NoiseError::WrongState {
                expected: "initiator".to_string(),
                got: "responder".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Initial {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Initial.to_string(),
                got: self.progress.to_string(),
            });
        }

        let remote_static = self.remote_static.expect("initiator must have remote static");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        let mut message = Vec::with_capacity(HANDSHAKE_MSG1_SIZE);

        // -> e: send ephemeral, mix into hash
        message.extend_from_slice(&e_pub);
        self.symmetric.mix_hash(&e_pub);

        // -> es: DH(e, rs), mix into key
        let es = self.ecdh(&ephemeral.secret_key(), &remote_static);
        self.symmetric.mix_key(&es);

        // -> s: encrypt our static and send
        let our_static = self.static_keypair.public_key().serialize();
        let encrypted_static = self.symmetric.encrypt_and_hash(&our_static)?;
        message.extend_from_slice(&encrypted_static);

        // -> ss: DH(s, rs), mix into key
        let ss = self.ecdh(&self.static_keypair.secret_key(), &remote_static);
        self.symmetric.mix_key(&ss);

        self.progress = HandshakeProgress::Message1Done;

        Ok(message)
    }

    /// Read message 1 (responder only).
    ///
    /// Processes the initiator's first message and learns their identity.
    pub fn read_message_1(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        if self.role != HandshakeRole::Responder {
            return Err(NoiseError::WrongState {
                expected: "responder".to_string(),
                got: "initiator".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Initial {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Initial.to_string(),
                got: self.progress.to_string(),
            });
        }
        if message.len() != HANDSHAKE_MSG1_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: HANDSHAKE_MSG1_SIZE,
                got: message.len(),
            });
        }

        // -> e: parse remote ephemeral, mix into hash
        let re = PublicKey::from_slice(&message[..PUBKEY_SIZE])
            .map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_ephemeral = Some(re);
        self.symmetric.mix_hash(&message[..PUBKEY_SIZE]);

        // -> es: DH(s, re), mix into key
        // (responder uses their static with initiator's ephemeral)
        let es = self.ecdh(&self.static_keypair.secret_key(), &re);
        self.symmetric.mix_key(&es);

        // -> s: decrypt initiator's static
        let encrypted_static = &message[PUBKEY_SIZE..];
        let decrypted_static = self.symmetric.decrypt_and_hash(encrypted_static)?;
        let rs =
            PublicKey::from_slice(&decrypted_static).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_static = Some(rs);

        // -> ss: DH(s, rs), mix into key
        let ss = self.ecdh(&self.static_keypair.secret_key(), &rs);
        self.symmetric.mix_key(&ss);

        self.progress = HandshakeProgress::Message1Done;

        Ok(())
    }

    /// Write message 2 (responder only).
    ///
    /// Message 2 contains:
    /// - e: ephemeral public key (33 bytes)
    ///
    /// Total: 33 bytes
    pub fn write_message_2(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.role != HandshakeRole::Responder {
            return Err(NoiseError::WrongState {
                expected: "responder".to_string(),
                got: "initiator".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Message1Done {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Message1Done.to_string(),
                got: self.progress.to_string(),
            });
        }

        let re = self.remote_ephemeral.expect("should have remote ephemeral");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        // <- e: send ephemeral, mix into hash
        self.symmetric.mix_hash(&e_pub);

        // <- ee: DH(e, re), mix into key
        let ee = self.ecdh(&ephemeral.secret_key(), &re);
        self.symmetric.mix_key(&ee);

        // <- se: DH(s, re), mix into key
        let se = self.ecdh(&self.static_keypair.secret_key(), &re);
        self.symmetric.mix_key(&se);

        self.progress = HandshakeProgress::Complete;

        Ok(e_pub.to_vec())
    }

    /// Read message 2 (initiator only).
    ///
    /// Processes the responder's message and completes the handshake.
    pub fn read_message_2(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        if self.role != HandshakeRole::Initiator {
            return Err(NoiseError::WrongState {
                expected: "initiator".to_string(),
                got: "responder".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Message1Done {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Message1Done.to_string(),
                got: self.progress.to_string(),
            });
        }
        if message.len() != HANDSHAKE_MSG2_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: HANDSHAKE_MSG2_SIZE,
                got: message.len(),
            });
        }

        // <- e: parse remote ephemeral, mix into hash
        let re = PublicKey::from_slice(message).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_ephemeral = Some(re);
        self.symmetric.mix_hash(message);

        // <- ee: DH(e, re), mix into key
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let ee = self.ecdh(&ephemeral.secret_key(), &re);
        self.symmetric.mix_key(&ee);

        // <- se: DH(e, rs), mix into key
        // (initiator uses their ephemeral with responder's static)
        let rs = self.remote_static.expect("initiator has remote static");
        let se = self.ecdh(&ephemeral.secret_key(), &rs);
        self.symmetric.mix_key(&se);

        self.progress = HandshakeProgress::Complete;

        Ok(())
    }

    /// Complete the handshake and return a NoiseSession.
    ///
    /// Must be called after the handshake is complete.
    pub fn into_session(self) -> Result<NoiseSession, NoiseError> {
        if !self.is_complete() {
            return Err(NoiseError::HandshakeNotComplete);
        }

        let (c1, c2) = self.symmetric.split();
        let handshake_hash = self.symmetric.handshake_hash();
        let remote_static = self
            .remote_static
            .expect("remote static must be known after handshake");

        // Initiator sends with c1, receives with c2
        // Responder sends with c2, receives with c1
        let (send_cipher, recv_cipher) = match self.role {
            HandshakeRole::Initiator => (c1, c2),
            HandshakeRole::Responder => (c2, c1),
        };

        Ok(NoiseSession::from_handshake(
            self.role,
            send_cipher,
            recv_cipher,
            handshake_hash,
            remote_static,
        ))
    }

    /// Get the handshake hash (for channel binding, available after complete).
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.symmetric.handshake_hash()
    }
}

impl fmt::Debug for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeState")
            .field("role", &self.role)
            .field("progress", &self.progress)
            .field("has_ephemeral", &self.ephemeral_keypair.is_some())
            .field("has_remote_static", &self.remote_static.is_some())
            .field("has_remote_ephemeral", &self.remote_ephemeral.is_some())
            .finish()
    }
}
