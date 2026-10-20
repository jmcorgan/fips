//! The production profiles' session and key types, over the Noise code in
//! `crate::noise`.
//!
//! The machine never names Noise: it reaches an epoch's keys only through
//! [`SessionKeys`]. The link profile (`proto::fmp::rekey::xx`) and the
//! session profile (`proto::fsp::rekey::xx`) both bind it to a Noise
//! transport session, and differ only in how much of a frame's cleartext
//! header the AEAD authenticates: the 16-byte link header, or the 12-byte
//! session header. That length is the type parameter of [`NoiseKeys`], so
//! the two profiles share one implementation.

use alloc::vec::Vec;
use core::fmt;

use secp256k1::Keypair;

use super::profile::{FrameHint, HsError, SessionKeys};
use super::proof::PeerKey;
use crate::noise::aead::AeadKey;
use crate::noise::{HandshakeState, NoiseSession, ReplayWindow};

/// A Noise transport session as an epoch's keys, authenticating the first
/// `AAD` bytes of every frame as associated data.
pub struct NoiseKeys<const AAD: usize> {
    session: NoiseSession,
}

impl<const AAD: usize> NoiseKeys<AAD> {
    /// The keys of a completed handshake's session.
    pub fn new(session: NoiseSession) -> Self {
        Self { session }
    }

    /// The session, read-only.
    pub fn session(&self) -> &NoiseSession {
        &self.session
    }
}

impl<const AAD: usize> fmt::Debug for NoiseKeys<AAD> {
    /// The session's counters and handshake-hash prefix; never a key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NoiseKeys").field(&self.session).finish()
    }
}

/// The receive half a decrypt worker takes over: the keyed AEAD, the
/// replay window as it stood when the copy was made, and the counter at or
/// below which the copy must refuse every frame (the highest an earlier
/// worker reported).
pub struct RecvCopy {
    /// The receive key.
    pub key: Option<AeadKey>,
    /// The replay window.
    pub window: ReplayWindow,
    /// Refuse every counter at or below this one.
    pub floor: Option<u64>,
}

impl fmt::Debug for RecvCopy {
    /// The window and the floor; never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvCopy")
            .field("keyed", &self.key.is_some())
            .field("window", &self.window)
            .field("floor", &self.floor)
            .finish()
    }
}

/// The send key handed out for one frame (or a batch of frames sealed off
/// the machine's task), with the counter reserved beside it.
pub struct SendCopy(Option<AeadKey>);

impl SendCopy {
    /// The keyed AEAD, for the sender to seal with.
    pub fn key(&self) -> Option<&AeadKey> {
        self.0.as_ref()
    }
}

impl fmt::Debug for SendCopy {
    /// Whether a key is present; never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SendCopy").field(&self.0.is_some()).finish()
    }
}

impl<const AAD: usize> SessionKeys for NoiseKeys<AAD> {
    type RecvCopy = RecvCopy;
    type SendCopy = SendCopy;

    fn open(&self, hint: &FrameHint, frame: &[u8], out: &mut Vec<u8>) -> bool {
        let (Some(aad), Some(body)) = (frame.get(..AAD), frame.get(hint.body..)) else {
            return false;
        };
        match self.session.open_unmarked(body, hint.counter, aad) {
            Ok(plaintext) => {
                // The open already made a buffer of its own; taking it saves
                // a copy of every frame on the inline session path.
                *out = plaintext;
                true
            }
            Err(_) => false,
        }
    }

    fn fresh(&self, counter: u64) -> bool {
        self.session.check_replay(counter).is_ok()
    }

    fn mark(&mut self, counter: u64) {
        self.session.accept_replay(counter);
    }

    fn sent(&self) -> u64 {
        self.session.current_send_counter()
    }

    fn reserve(&mut self) -> (u64, Self::SendCopy) {
        // The machine stops sealing at its hard limit, far below the counter
        // at which the session refuses to advance; past it the reserved
        // counter is the one no window accepts.
        let counter = self.session.take_send_counter().unwrap_or(u64::MAX);
        (counter, SendCopy(self.session.send_cipher_clone()))
    }

    fn copy(&self, floor: Option<u64>) -> RecvCopy {
        RecvCopy {
            key: self.session.recv_cipher_clone(),
            window: self.session.recv_replay_snapshot_owned(),
            floor,
        }
    }
}

/// This node's static keypair and startup epoch, which every handshake a
/// production profile starts or answers carries.
pub struct NodeKeys {
    keypair: Keypair,
    epoch: [u8; 8],
}

impl NodeKeys {
    /// The keys of a node with static `keypair` in startup epoch `epoch`.
    pub fn new(keypair: Keypair, epoch: [u8; 8]) -> Self {
        Self { keypair, epoch }
    }

    /// The static keypair.
    pub(crate) fn keypair(&self) -> Keypair {
        self.keypair
    }

    /// The startup epoch.
    pub fn epoch(&self) -> [u8; 8] {
        self.epoch
    }
}

impl fmt::Debug for NodeKeys {
    /// The public half and the epoch; never the secret key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKeys")
            .field("public", &self.keypair.x_only_public_key().0)
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl Drop for NodeKeys {
    /// Erase this copy of the long-term private key.
    fn drop(&mut self) {
        self.keypair.non_secure_erase();
    }
}

/// The static key a handshake authenticated, as the machine compares keys:
/// by X coordinate.
pub(crate) fn peer_key<E: crate::entropy::EntropySource>(
    hs: &HandshakeState<E>,
) -> Result<PeerKey, HsError> {
    let remote = hs.remote_static().ok_or(HsError)?;
    Ok(PeerKey::from_xonly(&remote.x_only_public_key().0))
}
