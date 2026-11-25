//! NIP-42: a relay's authentication challenge, answered by the machine.

use nostr::event::Kind;
use nostr::types::RelayUrl;

use super::*;

#[test]
fn an_auth_challenge_is_answered_with_a_kind_22242_event_at_the_steps_time() {
    let mut h = Harness::new(params(10));
    h.advance(1_500);
    let relay = RelayUrl::parse("wss://relay.example").unwrap();
    let reply = h.reply();
    let actions = h.input(Input::AuthChallenge {
        relay: relay.clone(),
        challenge: "challenge-123".to_string(),
        reply,
    });
    let Some((_, Reply::Auth(Ok(event)))) = reply_to(actions, reply) else {
        panic!("no authentication event");
    };
    assert_eq!(event.kind, Kind::Authentication);
    assert_eq!(event.pubkey, pubkey(NODE_A_SECRET));
    assert_eq!(event.created_at.as_secs(), (T0_MS + 1_500) / 1000);
    let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
    assert_eq!(
        tags,
        vec![
            vec!["challenge".to_string(), "challenge-123".to_string()],
            vec!["relay".to_string(), relay.to_string()],
        ]
    );
    assert!(event.verify_signature(), "signed by the node key");
}
