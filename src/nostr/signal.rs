use nostr::event::{Event, UnsignedEvent};
use nostr::key::PublicKey;
use nostr::types::Timestamp;

use super::machine::NodeSigner;
pub(super) use super::machine::event::signal::rumor;
use super::machine::event::signal::{open_signal, seal_and_wrap};
pub(super) use super::machine::signal::{
    FreshnessOutcome, create_traversal_answer, create_traversal_offer, estimate_clock_skew,
    validate_offer_freshness, validate_traversal_answer_for_offer,
};
use super::traversal::now_ms;
use super::types::BootstrapError;

pub(super) struct SignalEnvelope<T> {
    pub(super) payload: T,
    pub(super) sender_npub: String,
}

pub(super) struct UnwrappedSignal {
    pub(super) sender: PublicKey,
    pub(super) rumor: UnsignedEvent,
}

/// `rumor` sealed by `signer` and gift-wrapped for `receiver` now, expiring at
/// `expiration`, with fresh randomness from the host's source.
pub(super) fn build_signal_event(
    signer: &NodeSigner,
    receiver: PublicKey,
    rumor: UnsignedEvent,
    expiration: Timestamp,
) -> Result<Event, BootstrapError> {
    Ok(seal_and_wrap::<crate::identity::OsEntropy>(
        signer,
        receiver,
        rumor,
        now_ms(),
        expiration,
    )?)
}

/// Open a traversal signal sealed to `signer`'s key, checking the wrap's and
/// the seal's signatures.
pub(super) async fn unwrap_signal_event(
    signer: &NodeSigner,
    event: &Event,
) -> Result<UnwrappedSignal, BootstrapError> {
    let opened = open_signal(signer, event)?;
    Ok(UnwrappedSignal {
        sender: opened.sender,
        rumor: opened.rumor,
    })
}
