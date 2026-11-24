//! The traversal signal (FRC-1601 Section 5.1): a private message rumor,
//! kind 14, sealed by the node key, kind 13, and gift-wrapped by a one-time
//! key as kind 21059, each layer NIP-44 encrypted to the receiver. Composed
//! here rather than with nostr's NIP-59 builders, which emit kind 1059 and
//! read the clock and the OS random source.

use alloc::string::String;

use fips_core::entropy::EntropySource;
use fips_core::identity::secp;
use nostr::event::{Event, Kind, Tag, UnsignedEvent};
use nostr::key::{Keys, PublicKey, SecretKey};
use nostr::nips::nip44::{self, Nonce};
use nostr::types::Timestamp;

use super::super::error::Error;
use super::super::types::SIGNAL_KIND;
use super::{NodeSigner, SignedKind, at, nostr_error, sign_with};

/// How far back a seal's `created_at` may be set, exclusive: two days, as
/// nostr 0.44's seal builder did (`Timestamp::tweaked(0..172800)`), so a
/// relay cannot tell when a signal was sealed.
const SEAL_BACKDATE_RANGE_SECS: u64 = 172_800;

/// An opened traversal signal: who sealed it, and the rumor inside.
#[derive(Debug)]
pub struct Opened {
    /// The key that signed the seal: the sender's node key.
    pub sender: PublicKey,
    /// The rumor, whose content is the signal body.
    pub rumor: UnsignedEvent,
}

/// The rumor carrying `body` from `sender` to `receiver`, created at
/// `unix_ms`: kind 14, tagged with the receiver.
pub fn rumor(sender: PublicKey, receiver: PublicKey, body: String, unix_ms: u64) -> UnsignedEvent {
    UnsignedEvent::new(
        sender,
        at(unix_ms),
        Kind::PrivateDirectMessage,
        [Tag::public_key(receiver)],
        body,
    )
}

/// How many seconds a seal is backdated by for a random `draw`: from 0 to
/// 172,799.
pub fn seal_backdate(draw: u64) -> u64 {
    draw % SEAL_BACKDATE_RANGE_SECS
}

/// `rumor` sealed by `signer` and wrapped for `receiver`, at `unix_ms`,
/// expiring at `expiration`. Every random value (the two NIP-44 nonces, the
/// seal's backdating, the one-time wrap key and both signatures' aux bytes)
/// is drawn from `E`.
pub fn seal_and_wrap<E: EntropySource>(
    signer: &NodeSigner,
    receiver: PublicKey,
    mut rumor: UnsignedEvent,
    unix_ms: u64,
    expiration: Timestamp,
) -> Result<Event, Error> {
    rumor.ensure_id();
    let sealed = nip44::encrypt_with_nonce(
        signer.secret_key(),
        &receiver,
        rumor.as_json(),
        Nonce::V2(draw::<E, 32>()),
    )
    .map_err(nostr_error)?;
    let now_secs = unix_ms / 1000;
    let backdate = seal_backdate(u64::from_le_bytes(draw::<E, 8>()));
    let seal = signer.sign(
        SignedKind::Seal,
        Timestamp::from(now_secs.saturating_sub(backdate)),
        alloc::vec::Vec::new(),
        sealed,
        draw::<E, 32>(),
    )?;

    let one_time = Keys::new_with_ctx(secp(), one_time_key::<E>());
    let wrapped = nip44::encrypt_with_nonce(
        one_time.secret_key(),
        &receiver,
        seal.as_json(),
        Nonce::V2(draw::<E, 32>()),
    )
    .map_err(nostr_error)?;
    sign_with(
        &one_time,
        Kind::Custom(SIGNAL_KIND),
        Timestamp::from(now_secs),
        alloc::vec![Tag::public_key(receiver), Tag::expiration(expiration)],
        wrapped,
        draw::<E, 32>(),
    )
}

/// Open a traversal signal sealed to `signer`'s key: check its kind and its
/// signature, decrypt the seal, check the seal's signature, and decrypt the
/// rumor. The relay client has already checked a delivered wrap's signature;
/// it is checked again here so that what is opened does not depend on which
/// client delivered it.
pub fn open_signal(signer: &NodeSigner, event: &Event) -> Result<Opened, Error> {
    if event.kind != Kind::Custom(SIGNAL_KIND) {
        return Err(Error::Protocol(String::from("not a traversal signal")));
    }
    event.verify_with_ctx(secp()).map_err(nostr_error)?;
    let seal_json =
        nip44::decrypt(signer.secret_key(), &event.pubkey, &event.content).map_err(nostr_error)?;
    let seal = Event::from_json(seal_json).map_err(parse_error)?;
    seal.verify_with_ctx(secp()).map_err(nostr_error)?;
    let rumor_json =
        nip44::decrypt(signer.secret_key(), &seal.pubkey, &seal.content).map_err(nostr_error)?;
    let rumor = UnsignedEvent::from_json(rumor_json).map_err(parse_error)?;
    Ok(Opened {
        sender: seal.pubkey,
        rumor,
    })
}

/// `N` bytes drawn from `E`.
fn draw<E: EntropySource, const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    E::fill(&mut bytes);
    bytes
}

/// A one-time secret key drawn from `E`, drawing again while the bytes are
/// not a valid key (zero, or not below the curve order).
fn one_time_key<E: EntropySource>() -> SecretKey {
    loop {
        if let Ok(key) = SecretKey::from_slice(&draw::<E, 32>()) {
            return key;
        }
    }
}

/// A JSON parse failure inside a signal, with the text
/// `BootstrapError::EventParse` gives it.
fn parse_error(e: nostr::error::Error) -> Error {
    use alloc::string::ToString;
    Error::EventParse(e.to_string())
}

#[cfg(test)]
#[path = "tests/signal.rs"]
mod tests;
