use nostr::nips::{nip44, nip59};
use nostr::prelude::{
    Event, EventBuilder, JsonUtil, Kind, NostrSigner, PublicKey, Tag, Timestamp, UnsignedEvent,
};

pub(super) use super::machine::signal::{
    FreshnessOutcome, create_traversal_answer, create_traversal_offer, estimate_clock_skew,
    validate_offer_freshness, validate_traversal_answer_for_offer,
};
use super::types::{BootstrapError, SIGNAL_KIND};

pub(super) struct SignalEnvelope<T> {
    pub(super) payload: T,
    pub(super) sender_npub: String,
}

pub(super) struct UnwrappedSignal {
    pub(super) sender: PublicKey,
    pub(super) rumor: UnsignedEvent,
}

pub(super) async fn build_signal_event(
    signer: &nostr::Keys,
    receiver: PublicKey,
    rumor: UnsignedEvent,
    expiration: Timestamp,
) -> Result<Event, BootstrapError> {
    let seal = nip59::make_seal(signer, &receiver, rumor)
        .await
        .map_err(|e| BootstrapError::Nostr(e.to_string()))?
        .sign(signer)
        .await
        .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

    let ephemeral = nostr::Keys::generate();
    let content = nip44::encrypt(
        ephemeral.secret_key(),
        &receiver,
        seal.as_json(),
        nip44::Version::default(),
    )
    .map_err(|e| BootstrapError::Nostr(e.to_string()))?;

    EventBuilder::new(Kind::Custom(SIGNAL_KIND), content)
        .tags([Tag::public_key(receiver), Tag::expiration(expiration)])
        .sign_with_keys(&ephemeral)
        .map_err(|e| BootstrapError::Nostr(e.to_string()))
}

pub(super) async fn unwrap_signal_event(
    signer: &nostr::Keys,
    event: &Event,
) -> Result<UnwrappedSignal, BootstrapError> {
    if event.kind != Kind::Custom(SIGNAL_KIND) {
        return Err(BootstrapError::Protocol(
            "not a traversal signal".to_string(),
        ));
    }

    let seal_json = signer
        .nip44_decrypt(&event.pubkey, &event.content)
        .await
        .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
    let seal =
        Event::from_json(seal_json).map_err(|e| BootstrapError::EventParse(e.to_string()))?;
    seal.verify()
        .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
    let rumor_json = signer
        .nip44_decrypt(&seal.pubkey, &seal.content)
        .await
        .map_err(|e| BootstrapError::Nostr(e.to_string()))?;
    let rumor = UnsignedEvent::from_json(rumor_json)
        .map_err(|e| BootstrapError::EventParse(e.to_string()))?;
    Ok(UnwrappedSignal {
        sender: seal.pubkey,
        rumor,
    })
}
