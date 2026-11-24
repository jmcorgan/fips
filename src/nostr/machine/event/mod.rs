//! The Nostr events a node signs and opens: the node's signer, and a codec
//! per event kind FRC-1601 has a node publish or send.
//!
//! Every event here is built with `UnsignedEvent::new`, from a `created_at`
//! the caller read off its clock, and signed with
//! `sign_schnorr_with_aux_rand`, over aux bytes the caller drew. Nothing here
//! reads a clock or draws randomness of its own; a codec that needs more than
//! one draw takes the caller's `EntropySource` as a type parameter. The root
//! `clippy.toml` bans the `nostr` items that would read the clock or the OS
//! random source, so a codec cannot reach one by accident.

pub mod advert;
pub mod auth;
pub mod inbox;
pub mod signal;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fips_core::identity::secp;
use nostr::event::{Event, Kind, Tag, UnsignedEvent};
use nostr::key::{Keys, PublicKey, SecretKey};
use nostr::types::Timestamp;

use super::error::Error;
use super::types::ADVERT_KIND;

/// The kinds of event FRC-1601 Section 3.2 lets the node key sign. The node
/// key signs nothing else, because [`NodeSigner::sign`] takes only these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedKind {
    /// The overlay advert, kind 37195.
    Advert,
    /// The inbox relay list, kind 10050.
    InboxRelays,
    /// The seal inside a traversal signal, kind 13.
    Seal,
    /// A NIP-42 relay authentication, kind 22242.
    Auth,
}

impl SignedKind {
    /// The event kind this is.
    fn kind(self) -> Kind {
        match self {
            SignedKind::Advert => Kind::Custom(ADVERT_KIND),
            SignedKind::InboxRelays => Kind::InboxRelays,
            SignedKind::Seal => Kind::Seal,
            SignedKind::Auth => Kind::Authentication,
        }
    }
}

/// The only holder of the node key in FIPS's Nostr code. It signs the kinds
/// of [`SignedKind`] and opens the signals sealed to the node.
#[derive(Debug)]
pub struct NodeSigner {
    keys: Keys,
}

impl NodeSigner {
    /// A signer for `secret`, built on the core's secp256k1 context.
    pub fn new(secret: SecretKey) -> Self {
        Self {
            keys: Keys::new_with_ctx(secp(), secret),
        }
    }

    /// The node's public key.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// The node key, for the NIP-44 encryption of a seal and the opening of
    /// a signal.
    fn secret_key(&self) -> &SecretKey {
        self.keys.secret_key()
    }

    /// An event of `kind` signed by the node key, created at `created_at`,
    /// with `aux` as the signature's auxiliary randomness.
    pub fn sign(
        &self,
        kind: SignedKind,
        created_at: Timestamp,
        tags: Vec<Tag>,
        content: String,
        aux: [u8; 32],
    ) -> Result<Event, Error> {
        sign_with(&self.keys, kind.kind(), created_at, tags, content, aux)
    }
}

/// An event of `kind` signed by `keys`: the node key, through
/// [`NodeSigner::sign`], or a signal's one-time key.
fn sign_with(
    keys: &Keys,
    kind: Kind,
    created_at: Timestamp,
    tags: Vec<Tag>,
    content: String,
    aux: [u8; 32],
) -> Result<Event, Error> {
    let mut unsigned = UnsignedEvent::new(keys.public_key(), created_at, kind, tags, content);
    let id = unsigned.id();
    let sig = keys.sign_schnorr_with_aux_rand(secp(), id.as_bytes(), &aux);
    unsigned
        .add_signature_with_ctx(secp(), sig)
        .map_err(nostr_error)
}

/// A Unix time in milliseconds as an event's `created_at`, in whole seconds.
fn at(unix_ms: u64) -> Timestamp {
    Timestamp::from(unix_ms / 1000)
}

/// A `nostr` error as the machine's, with the text `BootstrapError::Nostr`
/// gives it.
fn nostr_error(e: nostr::error::Error) -> Error {
    Error::Nostr(e.to_string())
}

#[cfg(test)]
mod tests;
