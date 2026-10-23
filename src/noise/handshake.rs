use super::{
    CipherState, EPOCH_ENCRYPTED_SIZE, EPOCH_SIZE, HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE,
    HandshakeProgress, HandshakeRole, NoiseError, NoisePattern, NoiseSession, PROTOCOL_NAME_IK,
    PROTOCOL_NAME_XK, PUBKEY_SIZE, XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE,
    XK_HANDSHAKE_MSG3_SIZE,
};
use hkdf::Hkdf;
use rand::Rng;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, ecdh::shared_secret_point};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric state during handshake.
///
/// Maintains the chaining key (ck), handshake hash (h), and current cipher.
///
/// `Clone` exists for [`HandshakeState::try_read_message_2`],
/// [`HandshakeState::try_read_xk_message_2`] and
/// [`HandshakeState::try_read_xk_message_3`], which have to put the pre-read
/// state back after a message that advanced it before failing to
/// authenticate.
///
/// `ck` and `h` are cleared on drop, including on the clone above once it
/// goes out of scope. `cipher` is skipped because [`CipherState`] clears its
/// own retained key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SymmetricState {
    /// Chaining key for key derivation.
    ck: [u8; 32],
    /// Running SHA-256 accumulator over the handshake transcript.
    ///
    /// Maintained by `mix_hash` at every step, but never fed to the AEAD:
    /// `encrypt_and_hash` passes an empty associated-data field. Nothing in
    /// production reads it, so it provides no transcript binding today, and
    /// anything built on `handshake_hash()` (channel binding, an exporter,
    /// cookie binding) will silently not work until the AAD carries `h`.
    h: [u8; 32],
    /// Current cipher state for encrypting handshake payloads.
    #[zeroize(skip)]
    cipher: CipherState,
}

impl SymmetricState {
    /// Initialize with protocol name.
    fn initialize(protocol_name: &[u8]) -> Self {
        // If protocol name <= 32 bytes, pad with zeros
        // If > 32 bytes, hash it
        let h = if protocol_name.len() <= 32 {
            let mut h = [0u8; 32];
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            let mut hasher = Sha256::new();
            hasher.update(protocol_name);
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
        key.zeroize();

        output.zeroize();
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

        let ciphers = (CipherState::new(k1), CipherState::new(k2));

        output.zeroize();
        k1.zeroize();
        k2.zeroize();

        ciphers
    }

    /// Get the handshake hash.
    fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }
}

/// Handshake state for Noise IK and XK patterns.
pub struct HandshakeState {
    /// Which Noise pattern is being used.
    pattern: NoisePattern,
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
    /// For IK initiator: known before handshake (from config).
    /// For IK responder: learned from message 1.
    /// For XK initiator: known before handshake (from config).
    /// For XK responder: learned from message 3.
    remote_static: Option<PublicKey>,
    /// Remote ephemeral public key (learned during handshake).
    remote_ephemeral: Option<PublicKey>,
    /// Secp256k1 context.
    secp: Secp256k1<secp256k1::All>,
    /// Our startup epoch for restart detection.
    local_epoch: Option<[u8; 8]>,
    /// Remote peer's startup epoch (learned during handshake).
    remote_epoch: Option<[u8; 8]>,
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

    /// Create a new IK handshake as initiator.
    ///
    /// The initiator knows the responder's static key and will send first.
    /// Used by FMP (link layer).
    pub fn new_initiator(mut static_keypair: Keypair, remote_static: PublicKey) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            pattern: NoisePattern::Ik,
            role: HandshakeRole::Initiator,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(PROTOCOL_NAME_IK),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: Some(remote_static),
            remote_ephemeral: None,
            secp,
            local_epoch: None,
            remote_epoch: None,
        };

        // Mix in pre-message: <- s (responder's static is known)
        // Normalize to even parity so initiator and responder hash chains match
        // even when the initiator only has the x-only key (from npub).
        let normalized = Self::normalize_for_premessage(&remote_static);
        state.symmetric.mix_hash(&normalized);

        // The struct now holds its own copy of the long-term private key and
        // clears it on drop, so this frame's parameter copy is erased here.
        static_keypair.non_secure_erase();

        state
    }

    /// Create a new IK handshake as responder.
    ///
    /// The responder does NOT know the initiator's static key - it will be
    /// learned from message 1. Used by FMP (link layer).
    pub fn new_responder(mut static_keypair: Keypair) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            pattern: NoisePattern::Ik,
            role: HandshakeRole::Responder,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(PROTOCOL_NAME_IK),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: None, // Will learn from message 1
            remote_ephemeral: None,
            secp,
            local_epoch: None,
            remote_epoch: None,
        };

        // Mix in pre-message: <- s (our static, since we're responder)
        // Normalize to even parity to match initiator's hash chain.
        let normalized = Self::normalize_for_premessage(&state.static_keypair.public_key());
        state.symmetric.mix_hash(&normalized);

        // The struct now holds its own copy of the long-term private key and
        // clears it on drop, so this frame's parameter copy is erased here.
        static_keypair.non_secure_erase();

        state
    }

    /// Create a new XK handshake as initiator.
    ///
    /// The initiator knows the responder's static key. XK defers the
    /// initiator's static key reveal to msg3. Used by FSP (session layer).
    pub fn new_xk_initiator(mut static_keypair: Keypair, remote_static: PublicKey) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            pattern: NoisePattern::Xk,
            role: HandshakeRole::Initiator,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(PROTOCOL_NAME_XK),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: Some(remote_static),
            remote_ephemeral: None,
            secp,
            local_epoch: None,
            remote_epoch: None,
        };

        // Mix in pre-message: <- s (responder's static is known)
        let normalized = Self::normalize_for_premessage(&remote_static);
        state.symmetric.mix_hash(&normalized);

        // The struct now holds its own copy of the long-term private key and
        // clears it on drop, so this frame's parameter copy is erased here.
        static_keypair.non_secure_erase();

        state
    }

    /// Create a new XK handshake as responder.
    ///
    /// The responder does NOT know the initiator's static key - it will be
    /// learned from message 3. Used by FSP (session layer).
    pub fn new_xk_responder(mut static_keypair: Keypair) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            pattern: NoisePattern::Xk,
            role: HandshakeRole::Responder,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(PROTOCOL_NAME_XK),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: None, // Will learn from message 3
            remote_ephemeral: None,
            secp,
            local_epoch: None,
            remote_epoch: None,
        };

        // Mix in pre-message: <- s (our static, since we're responder)
        let normalized = Self::normalize_for_premessage(&state.static_keypair.public_key());
        state.symmetric.mix_hash(&normalized);

        // The struct now holds its own copy of the long-term private key and
        // clears it on drop, so this frame's parameter copy is erased here.
        static_keypair.non_secure_erase();

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

    /// Set the local startup epoch for restart detection.
    pub fn set_local_epoch(&mut self, epoch: [u8; 8]) {
        self.local_epoch = Some(epoch);
    }

    /// Get the remote peer's startup epoch (available after processing their message).
    pub fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.remote_epoch
    }

    /// Generate ephemeral keypair.
    fn generate_ephemeral(&mut self) {
        let mut rng = rand::rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);

        let mut secret_key =
            SecretKey::from_slice(&secret_bytes).expect("32 random bytes is valid secret key");
        self.ephemeral_keypair = Some(Keypair::from_secret_key(&self.secp, &secret_key));
        secret_bytes.zeroize();
        // This clears the copy this frame owns, with a volatile write the
        // optimiser keeps; a copy made before it, such as one a call above
        // left in a register or a stack slot, is not reached. The keypair the
        // key was just stored in is cleared by `Drop for HandshakeState`.
        secret_key.non_secure_erase();
    }

    /// Perform ECDH between our secret and their public key.
    ///
    /// Uses x-only hashing (SHA-256 of just the x-coordinate) to produce
    /// a parity-independent shared secret. This is necessary because Nostr
    /// npubs encode x-only keys without parity information, so the initiator
    /// may have the wrong parity for the responder's static key. Since P and
    /// -P produce ECDH result points with the same x-coordinate, hashing
    /// only x ensures both sides derive the same shared secret.
    ///
    /// `our_secret` is borrowed, so this frame makes no copy of it. Every
    /// caller below binds the value `Keypair::secret_key` hands back and
    /// erases that binding once the DH is done, because the returned
    /// `SecretKey` is a whole private key rather than a handle to one. Those
    /// erases clear the copies this crate owns. Each is a volatile write the
    /// optimiser keeps, but a copy the compiler made before it runs, in a
    /// register or a stack slot, is not reached.
    fn ecdh(&self, our_secret: &SecretKey, their_public: &PublicKey) -> [u8; 32] {
        // Get raw (x, y) coordinates (64 bytes) without any hashing
        let mut point = shared_secret_point(their_public, our_secret);
        // Hash only the x-coordinate (first 32 bytes), ignoring y/parity
        let mut hasher = Sha256::new();
        hasher.update(&point[..32]);
        let mut hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        hash.as_mut_slice().zeroize();
        point.zeroize();
        // `result` is moved out, so clearing it belongs to the caller.
        result
    }

    /// Write message 1 (initiator only).
    ///
    /// Message 1 contains:
    /// - e: ephemeral public key (33 bytes)
    /// - encrypted s: our static public key encrypted (33 + 16 = 49 bytes)
    /// - encrypted epoch: startup epoch for restart detection (8 + 16 = 24 bytes)
    ///
    /// Total: 106 bytes
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

        let remote_static = self
            .remote_static
            .expect("initiator must have remote static");
        let epoch = self
            .local_epoch
            .expect("local epoch must be set before write_message_1");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        let mut message = Vec::with_capacity(HANDSHAKE_MSG1_SIZE);

        // -> e: send ephemeral, mix into hash
        message.extend_from_slice(&e_pub);
        self.symmetric.mix_hash(&e_pub);

        // -> es: DH(e, rs), mix into key
        let mut sk = ephemeral.secret_key();
        let mut es = self.ecdh(&sk, &remote_static);
        self.symmetric.mix_key(&es);
        es.zeroize();
        sk.non_secure_erase();

        // -> s: encrypt our static and send
        let our_static = self.static_keypair.public_key().serialize();
        let encrypted_static = self.symmetric.encrypt_and_hash(&our_static)?;
        message.extend_from_slice(&encrypted_static);

        // -> ss: DH(s, rs), mix into key
        let mut sk = self.static_keypair.secret_key();
        let mut ss = self.ecdh(&sk, &remote_static);
        self.symmetric.mix_key(&ss);
        ss.zeroize();
        sk.non_secure_erase();

        // -> epoch: encrypt startup epoch for restart detection
        let encrypted_epoch = self.symmetric.encrypt_and_hash(&epoch)?;
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        message.extend_from_slice(&encrypted_epoch);

        self.progress = HandshakeProgress::Message1Done;

        Ok(message)
    }

    /// Read message 1 (responder only).
    ///
    /// Processes the initiator's first message and learns their identity and epoch.
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
        let mut sk = self.static_keypair.secret_key();
        let mut es = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&es);
        es.zeroize();
        sk.non_secure_erase();

        // -> s: decrypt initiator's static
        let encrypted_static_end = PUBKEY_SIZE + PUBKEY_SIZE + super::TAG_SIZE;
        let encrypted_static = &message[PUBKEY_SIZE..encrypted_static_end];
        let decrypted_static = self.symmetric.decrypt_and_hash(encrypted_static)?;
        let rs =
            PublicKey::from_slice(&decrypted_static).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_static = Some(rs);

        // -> ss: DH(s, rs), mix into key
        let mut sk = self.static_keypair.secret_key();
        let mut ss = self.ecdh(&sk, &rs);
        self.symmetric.mix_key(&ss);
        ss.zeroize();
        sk.non_secure_erase();

        // -> epoch: decrypt initiator's startup epoch
        let encrypted_epoch = &message[encrypted_static_end..];
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        let decrypted_epoch = self.symmetric.decrypt_and_hash(encrypted_epoch)?;
        debug_assert_eq!(decrypted_epoch.len(), EPOCH_SIZE);
        let mut epoch = [0u8; EPOCH_SIZE];
        epoch.copy_from_slice(&decrypted_epoch);
        self.remote_epoch = Some(epoch);

        self.progress = HandshakeProgress::Message1Done;

        Ok(())
    }

    /// Write message 2 (responder only).
    ///
    /// Message 2 contains:
    /// - e: ephemeral public key (33 bytes)
    /// - encrypted epoch: startup epoch for restart detection (8 + 16 = 24 bytes)
    ///
    /// Total: 57 bytes
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
        let epoch = self
            .local_epoch
            .expect("local epoch must be set before write_message_2");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        let mut message = Vec::with_capacity(HANDSHAKE_MSG2_SIZE);

        // <- e: send ephemeral, mix into hash
        message.extend_from_slice(&e_pub);
        self.symmetric.mix_hash(&e_pub);

        // <- ee: DH(e, re), mix into key
        let mut sk = ephemeral.secret_key();
        let mut ee = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&ee);
        ee.zeroize();
        sk.non_secure_erase();

        // <- es again: DH(s, re), mix into key
        // This pairs the same keys as msg1's es (responder static, initiator
        // ephemeral), so it mixes the msg1 es value a second time. It is not
        // Noise IK's se, DH(initiator static, responder ephemeral), which
        // nothing here computes; the initiator's static key enters the keys
        // only through ss. This is the FMP v1 wire format: changing it breaks
        // every v1 peer. It leaves FMP v1 open to key compromise
        // impersonation (FRC-1201 Section 9.3).
        let mut sk = self.static_keypair.secret_key();
        let mut es2 = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&es2);
        es2.zeroize();
        sk.non_secure_erase();

        // <- epoch: encrypt startup epoch for restart detection
        let encrypted_epoch = self.symmetric.encrypt_and_hash(&epoch)?;
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        message.extend_from_slice(&encrypted_epoch);

        self.progress = HandshakeProgress::Complete;

        Ok(message)
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
        let e_pub = &message[..PUBKEY_SIZE];
        let re = PublicKey::from_slice(e_pub).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_ephemeral = Some(re);
        self.symmetric.mix_hash(e_pub);

        // <- ee: DH(e, re), mix into key
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let mut sk = ephemeral.secret_key();
        let mut ee = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&ee);
        ee.zeroize();
        sk.non_secure_erase();

        // <- es again: DH(e, rs), mix into key
        // The initiator's ephemeral with the responder's static is msg1's es
        // pairing, so this mixes the msg1 es value a second time. It is not
        // Noise IK's se; see write_message_2 for why the FMP v1 wire format
        // keeps it.
        let rs = self.remote_static.expect("initiator has remote static");
        let mut sk = ephemeral.secret_key();
        let mut es2 = self.ecdh(&sk, &rs);
        self.symmetric.mix_key(&es2);
        es2.zeroize();
        sk.non_secure_erase();

        // <- epoch: decrypt responder's startup epoch
        let encrypted_epoch = &message[PUBKEY_SIZE..];
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        let decrypted_epoch = self.symmetric.decrypt_and_hash(encrypted_epoch)?;
        debug_assert_eq!(decrypted_epoch.len(), EPOCH_SIZE);
        let mut epoch = [0u8; EPOCH_SIZE];
        epoch.copy_from_slice(&decrypted_epoch);
        self.remote_epoch = Some(epoch);

        self.progress = HandshakeProgress::Complete;

        Ok(())
    }

    /// Read message 2, leaving the handshake untouched when the message
    /// does not authenticate.
    ///
    /// `read_message_2` mixes the sender's ephemeral into the symmetric state,
    /// and both DH results into the key, before it authenticates the encrypted
    /// epoch, so a message that fails partway leaves a handshake that can
    /// never read the genuine msg2 afterwards. A caller that keeps its rekey
    /// cycle across a failed read — because the message may be a forgery
    /// rather than the responder's corrupt reply — needs the pre-read state
    /// back.
    ///
    /// The saved set is exactly what `read_message_2` writes: `symmetric`,
    /// `remote_ephemeral`, `remote_epoch` and `progress`. `remote_static` is
    /// not in it, because IK pins the responder's static before msg1 and the
    /// read only uses it. **That mirror is manual.** A later edit that adds a
    /// write to `read_message_2` without adding it here silently reintroduces
    /// the poisoning, and no caller can detect it.
    pub fn try_read_message_2(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        let symmetric = self.symmetric.clone();
        let remote_ephemeral = self.remote_ephemeral;
        let remote_epoch = self.remote_epoch;
        let progress = self.progress;

        match self.read_message_2(message) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.symmetric = symmetric;
                self.remote_ephemeral = remote_ephemeral;
                self.remote_epoch = remote_epoch;
                self.progress = progress;
                Err(e)
            }
        }
    }

    // ========================================================================
    // XK Pattern Methods (Session Layer)
    // ========================================================================

    /// Write XK message 1 (initiator only).
    ///
    /// XK msg1: `-> e, es`
    /// - e: ephemeral public key (33 bytes)
    /// - es: DH(e_priv, rs_pub), mix_key
    ///
    /// Total: 33 bytes (ephemeral only — no static, no epoch)
    pub fn write_xk_message_1(&mut self) -> Result<Vec<u8>, NoiseError> {
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

        let remote_static = self
            .remote_static
            .expect("initiator must have remote static");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        let mut message = Vec::with_capacity(XK_HANDSHAKE_MSG1_SIZE);

        // -> e: send ephemeral, mix into hash
        message.extend_from_slice(&e_pub);
        self.symmetric.mix_hash(&e_pub);

        // -> es: DH(e, rs), mix into key
        let mut sk = ephemeral.secret_key();
        let mut es = self.ecdh(&sk, &remote_static);
        self.symmetric.mix_key(&es);
        es.zeroize();
        sk.non_secure_erase();

        self.progress = HandshakeProgress::Message1Done;

        Ok(message)
    }

    /// Read XK message 1 (responder only).
    ///
    /// Processes the initiator's first message. Does NOT learn initiator's
    /// identity (that comes in msg3).
    pub fn read_xk_message_1(&mut self, message: &[u8]) -> Result<(), NoiseError> {
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
        if message.len() != XK_HANDSHAKE_MSG1_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: XK_HANDSHAKE_MSG1_SIZE,
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
        let mut sk = self.static_keypair.secret_key();
        let mut es = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&es);
        es.zeroize();
        sk.non_secure_erase();

        self.progress = HandshakeProgress::Message1Done;

        Ok(())
    }

    /// Write XK message 2 (responder only).
    ///
    /// XK msg2: `<- e, ee` + encrypted epoch
    /// - e: ephemeral public key (33 bytes)
    /// - ee: DH(e_priv, re_pub), mix_key
    /// - encrypted epoch (24 bytes)
    ///
    /// Total: 57 bytes
    pub fn write_xk_message_2(&mut self) -> Result<Vec<u8>, NoiseError> {
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
        let epoch = self
            .local_epoch
            .expect("local epoch must be set before write_xk_message_2");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        let mut message = Vec::with_capacity(XK_HANDSHAKE_MSG2_SIZE);

        // <- e: send ephemeral, mix into hash
        message.extend_from_slice(&e_pub);
        self.symmetric.mix_hash(&e_pub);

        // <- ee: DH(e, re), mix into key
        let mut sk = ephemeral.secret_key();
        let mut ee = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&ee);
        ee.zeroize();
        sk.non_secure_erase();

        // <- epoch: encrypt startup epoch (FSP carries it but does not act on it)
        let encrypted_epoch = self.symmetric.encrypt_and_hash(&epoch)?;
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        message.extend_from_slice(&encrypted_epoch);

        self.progress = HandshakeProgress::Message2Done;

        Ok(message)
    }

    /// Read XK message 2 (initiator only).
    ///
    /// Processes the responder's message and extracts the responder's epoch.
    /// Does NOT complete the handshake — msg3 still needed.
    pub fn read_xk_message_2(&mut self, message: &[u8]) -> Result<(), NoiseError> {
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
        if message.len() != XK_HANDSHAKE_MSG2_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: XK_HANDSHAKE_MSG2_SIZE,
                got: message.len(),
            });
        }

        // <- e: parse remote ephemeral, mix into hash
        let e_pub = &message[..PUBKEY_SIZE];
        let re = PublicKey::from_slice(e_pub).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_ephemeral = Some(re);
        self.symmetric.mix_hash(e_pub);

        // <- ee: DH(e, re), mix into key
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let mut sk = ephemeral.secret_key();
        let mut ee = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&ee);
        ee.zeroize();
        sk.non_secure_erase();

        // <- epoch: decrypt responder's startup epoch
        let encrypted_epoch = &message[PUBKEY_SIZE..];
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        let decrypted_epoch = self.symmetric.decrypt_and_hash(encrypted_epoch)?;
        debug_assert_eq!(decrypted_epoch.len(), EPOCH_SIZE);
        let mut epoch = [0u8; EPOCH_SIZE];
        epoch.copy_from_slice(&decrypted_epoch);
        self.remote_epoch = Some(epoch);

        self.progress = HandshakeProgress::Message2Done;

        Ok(())
    }

    /// Read XK message 2, leaving the handshake untouched when the message
    /// does not authenticate.
    ///
    /// `read_xk_message_2` mixes the sender's ephemeral into the symmetric
    /// state before it authenticates the encrypted epoch, so a message that
    /// fails partway leaves a handshake that can never read the genuine msg2
    /// afterwards. A caller that keeps its session entry across a failed read
    /// — because the message may be a forgery rather than a real peer's
    /// corrupt reply — needs the pre-read state back.
    ///
    /// The saved set is exactly what `read_xk_message_2` writes:
    /// `symmetric`, `remote_ephemeral`, `remote_epoch` and `progress`. **That
    /// mirror is manual.** A later edit that adds a write to
    /// `read_xk_message_2` without adding it here silently reintroduces the
    /// poisoning, and no caller can detect it.
    pub fn try_read_xk_message_2(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        let symmetric = self.symmetric.clone();
        let remote_ephemeral = self.remote_ephemeral;
        let remote_epoch = self.remote_epoch;
        let progress = self.progress;

        match self.read_xk_message_2(message) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.symmetric = symmetric;
                self.remote_ephemeral = remote_ephemeral;
                self.remote_epoch = remote_epoch;
                self.progress = progress;
                Err(e)
            }
        }
    }

    /// Write XK message 3 (initiator only).
    ///
    /// XK msg3: `-> s, se` + encrypted epoch
    /// - s: encrypt_and_hash(s_pub) — encrypted static (49 bytes)
    /// - se: DH(s_priv, re_pub), mix_key
    /// - encrypted epoch (24 bytes)
    ///
    /// Total: 73 bytes
    pub fn write_xk_message_3(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.role != HandshakeRole::Initiator {
            return Err(NoiseError::WrongState {
                expected: "initiator".to_string(),
                got: "responder".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Message2Done {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Message2Done.to_string(),
                got: self.progress.to_string(),
            });
        }

        let re = self
            .remote_ephemeral
            .expect("should have remote ephemeral after msg2");
        let epoch = self
            .local_epoch
            .expect("local epoch must be set before write_xk_message_3");

        let mut message = Vec::with_capacity(XK_HANDSHAKE_MSG3_SIZE);

        // -> s: encrypt our static and send
        let our_static = self.static_keypair.public_key().serialize();
        let encrypted_static = self.symmetric.encrypt_and_hash(&our_static)?;
        message.extend_from_slice(&encrypted_static);

        // -> se: DH(s, re), mix into key
        let mut sk = self.static_keypair.secret_key();
        let mut se = self.ecdh(&sk, &re);
        self.symmetric.mix_key(&se);
        se.zeroize();
        sk.non_secure_erase();

        // -> epoch: encrypt startup epoch (FSP carries it but does not act on it)
        let encrypted_epoch = self.symmetric.encrypt_and_hash(&epoch)?;
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        message.extend_from_slice(&encrypted_epoch);

        self.progress = HandshakeProgress::Complete;

        Ok(message)
    }

    /// Read XK message 3 (responder only).
    ///
    /// Processes the initiator's encrypted static key and epoch.
    /// After this, the responder learns the initiator's identity.
    pub fn read_xk_message_3(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        if self.role != HandshakeRole::Responder {
            return Err(NoiseError::WrongState {
                expected: "responder".to_string(),
                got: "initiator".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Message2Done {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Message2Done.to_string(),
                got: self.progress.to_string(),
            });
        }
        if message.len() != XK_HANDSHAKE_MSG3_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: XK_HANDSHAKE_MSG3_SIZE,
                got: message.len(),
            });
        }

        // -> s: decrypt initiator's static
        let encrypted_static_end = PUBKEY_SIZE + super::TAG_SIZE;
        let encrypted_static = &message[..encrypted_static_end];
        let decrypted_static = self.symmetric.decrypt_and_hash(encrypted_static)?;
        let rs =
            PublicKey::from_slice(&decrypted_static).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_static = Some(rs);

        // -> se: DH(e, rs), mix into key
        // (responder uses their ephemeral with initiator's now-known static)
        let ephemeral = self
            .ephemeral_keypair
            .as_ref()
            .expect("should have ephemeral after msg2");
        let mut sk = ephemeral.secret_key();
        let mut se = self.ecdh(&sk, &rs);
        self.symmetric.mix_key(&se);
        se.zeroize();
        sk.non_secure_erase();

        // -> epoch: decrypt initiator's startup epoch
        let encrypted_epoch = &message[encrypted_static_end..];
        debug_assert_eq!(encrypted_epoch.len(), EPOCH_ENCRYPTED_SIZE);
        let decrypted_epoch = self.symmetric.decrypt_and_hash(encrypted_epoch)?;
        debug_assert_eq!(decrypted_epoch.len(), EPOCH_SIZE);
        let mut epoch = [0u8; EPOCH_SIZE];
        epoch.copy_from_slice(&decrypted_epoch);
        self.remote_epoch = Some(epoch);

        self.progress = HandshakeProgress::Complete;

        Ok(())
    }

    /// Read XK message 3, leaving the handshake untouched when the message
    /// does not authenticate.
    ///
    /// `read_xk_message_3` advances the symmetric state's nonce before the
    /// first AEAD opens, and a message that fails later has already mixed a
    /// DH result into the key, so a failed read leaves a handshake that can
    /// never read the genuine msg3 afterwards. A responder that keeps its
    /// handshake across a failed read, because the message may be a forgery
    /// rather than the initiator's corrupt msg3, needs the pre-read state
    /// back.
    ///
    /// The saved set is exactly what `read_xk_message_3` writes:
    /// `symmetric`, `remote_static`, `remote_epoch` and `progress`. **That
    /// mirror is manual.** A later edit that adds a write to
    /// `read_xk_message_3` without adding it here silently reintroduces the
    /// poisoning, and no caller can detect it.
    pub fn try_read_xk_message_3(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        let symmetric = self.symmetric.clone();
        let remote_static = self.remote_static;
        let remote_epoch = self.remote_epoch;
        let progress = self.progress;

        match self.read_xk_message_3(message) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.symmetric = symmetric;
                self.remote_static = remote_static;
                self.remote_epoch = remote_epoch;
                self.progress = progress;
                Err(e)
            }
        }
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

    /// Get the handshake hash (available after complete).
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.symmetric.handshake_hash()
    }
}

impl Drop for HandshakeState {
    /// Erase the two private keys this state holds.
    ///
    /// `static_keypair` is the node's long-term private key and
    /// `ephemeral_keypair` is the handshake's own. Both live here for the
    /// whole handshake, which is longer than in any other frame, so this is
    /// where clearing them matters most. `Keypair` is `Copy` and so cannot
    /// clear itself on drop; `HandshakeState` is not, so it does it for both.
    ///
    /// This clears the copy being dropped, not every copy that ever existed.
    /// Each erase is a volatile write, so the optimiser keeps it, but a
    /// `HandshakeState` is built on the stack and moved several times before
    /// it is dropped, and every move leaves the old bytes, both private keys
    /// included, where the value used to be. A plain `take()` out of an
    /// `Option` leaves its full contents in the slot. When a connection's
    /// handshake completes, the connection's heap slot is cleared with
    /// `clear_slot` once the handshake has left it; a move of the whole
    /// connection state out of its machine does not clear anything.
    fn drop(&mut self) {
        self.static_keypair.non_secure_erase();
        if let Some(ephemeral) = self.ephemeral_keypair.as_mut() {
            ephemeral.non_secure_erase();
        }
    }
}

impl fmt::Debug for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeState")
            .field("pattern", &self.pattern)
            .field("role", &self.role)
            .field("progress", &self.progress)
            .field("has_ephemeral", &self.ephemeral_keypair.is_some())
            .field("has_remote_static", &self.remote_static.is_some())
            .field("has_remote_ephemeral", &self.remote_ephemeral.is_some())
            .field("has_local_epoch", &self.local_epoch.is_some())
            .field("has_remote_epoch", &self.remote_epoch.is_some())
            .finish()
    }
}
