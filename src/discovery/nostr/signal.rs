use nostr::EventId;
use nostr::nips::{nip44, nip59};
use nostr::prelude::{
    Event, EventBuilder, JsonUtil, Kind, NostrSigner, PublicKey, Tag, Timestamp, UnsignedEvent,
};

use super::types::{BootstrapError, PunchHint, SIGNAL_KIND, TraversalAnswer, TraversalOffer};

pub(super) struct SignalEnvelope<T> {
    pub(super) payload: T,
    pub(super) event_id: EventId,
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

pub(super) fn validate_offer_freshness(
    offer: &TraversalOffer,
    now: u64,
    signal_ttl_ms: u64,
    actual_sender_npub: &str,
    local_npub: &str,
) -> Result<(), BootstrapError> {
    if offer.message_type != "offer" {
        return Err(BootstrapError::Protocol("invalid-offer".to_string()));
    }
    if offer.expires_at <= now || now.saturating_sub(offer.issued_at) > signal_ttl_ms {
        return Err(BootstrapError::Protocol("expired-offer".to_string()));
    }
    if offer.sender_npub != actual_sender_npub || offer.recipient_npub != local_npub {
        return Err(BootstrapError::Protocol("identity-mismatch".to_string()));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn create_traversal_offer(
    session_id: String,
    issued_at: u64,
    ttl_ms: u64,
    nonce: String,
    sender_npub: String,
    recipient_npub: String,
    reflexive_address: Option<super::TraversalAddress>,
    local_addresses: Vec<super::TraversalAddress>,
    stun_server: Option<String>,
) -> TraversalOffer {
    TraversalOffer {
        message_type: "offer".to_string(),
        session_id,
        issued_at,
        expires_at: issued_at + ttl_ms,
        nonce,
        sender_npub,
        recipient_npub,
        reflexive_address,
        local_addresses,
        stun_server,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn create_traversal_answer(
    session_id: String,
    issued_at: u64,
    ttl_ms: u64,
    nonce: String,
    sender_npub: String,
    recipient_npub: String,
    in_reply_to: String,
    accepted: bool,
    reflexive_address: Option<super::TraversalAddress>,
    local_addresses: Vec<super::TraversalAddress>,
    stun_server: Option<String>,
    punch: Option<PunchHint>,
    reason: Option<String>,
) -> TraversalAnswer {
    TraversalAnswer {
        message_type: "answer".to_string(),
        session_id,
        issued_at,
        expires_at: issued_at + ttl_ms,
        nonce,
        sender_npub,
        recipient_npub,
        in_reply_to,
        accepted,
        reflexive_address,
        local_addresses,
        stun_server,
        punch,
        reason,
    }
}

pub(super) fn validate_traversal_answer_for_offer(
    offer: &TraversalOffer,
    answer: &TraversalAnswer,
    now: u64,
    signal_ttl_ms: u64,
    actual_sender_npub: &str,
    local_npub: &str,
) -> Result<(), BootstrapError> {
    if answer.message_type != "answer" {
        return Err(BootstrapError::Protocol("invalid-answer".to_string()));
    }
    if offer.expires_at <= now
        || answer.expires_at <= now
        || now.saturating_sub(answer.issued_at) > signal_ttl_ms
    {
        return Err(BootstrapError::Protocol("expired-answer".to_string()));
    }
    if offer.session_id != answer.session_id || answer.in_reply_to != offer.nonce {
        return Err(BootstrapError::Protocol("session-mismatch".to_string()));
    }
    if offer.sender_npub != local_npub
        || offer.recipient_npub != actual_sender_npub
        || answer.sender_npub != actual_sender_npub
        || answer.recipient_npub != local_npub
    {
        return Err(BootstrapError::Protocol("identity-mismatch".to_string()));
    }
    if answer.accepted && answer.reflexive_address.is_none() && answer.local_addresses.is_empty() {
        return Err(BootstrapError::Protocol("missing-addresses".to_string()));
    }
    if !answer.accepted && answer.reason.as_deref().unwrap_or_default().is_empty() {
        return Err(BootstrapError::Protocol(
            "missing-rejection-reason".to_string(),
        ));
    }
    Ok(())
}
