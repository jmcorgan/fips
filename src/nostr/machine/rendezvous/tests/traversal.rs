//! The traversal half: the responder's checks on an offer and their order,
//! the admission slot an offer gives back however its session ends, the
//! socket a failed session closes, the one
//! re-send of our offer a dual initiation allows, the initiator's offer,
//! the node's capacity, the signal gate's view of the sessions in hand, and
//! whole traversals between two machines over a fake relay and a fake
//! network with cone and symmetric NATs.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use fips_core::utils::onlink::OnLinkPrefixes;

use super::super::super::event::signal::{open_signal, rumor, seal_and_wrap};
use super::super::super::signal::{create_traversal_answer, create_traversal_offer};
use super::super::super::traversal::rules::short_npub;
use super::super::super::types::{
    OverlayTransportKind, SIGNAL_KIND, TraversalAddress, TraversalOffer,
};
use super::*;

/// A fourth key, for a sender no other offer in a test came from.
const NODE_D_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000007";

/// A traversal signal carrying `body` from the node whose secret key is
/// `from` to `to`, sealed now.
fn sealed<T: serde::Serialize>(h: &Harness, from: &str, to: &str, body: &T) -> Event {
    let now = h.now().unix_ms;
    let receiver = pubkey(to);
    let rumor = rumor(
        pubkey(from),
        receiver,
        serde_json::to_string(body).unwrap(),
        now,
    );
    seal_and_wrap::<SeededEntropy>(
        &signer(from),
        receiver,
        rumor,
        now,
        nostr::types::Timestamp::from(now / 1000 + 120),
    )
    .expect("a sealed signal")
}

/// An offer from the node whose secret key is `from` to node A, issued now,
/// under `session`.
fn offer_from(h: &Harness, from: &str, session: &str) -> TraversalOffer {
    create_traversal_offer(
        session.to_string(),
        h.now().unix_ms,
        120_000,
        session.to_string(),
        npub(from),
        npub(NODE_A_SECRET),
        None,
        Vec::new(),
        None,
    )
}

/// Deliver `offer` from `from` to node A, and return the actions.
fn deliver(h: &mut Harness, from: &str, offer: &TraversalOffer) -> Vec<Action> {
    let event = sealed(h, from, NODE_A_SECRET, offer);
    h.input(delivered(event))
}

/// What the responder did with an offer: refused it with this text, or
/// went on to look the sender's inbox relays up, which it does only once
/// the replay check has passed.
#[derive(Debug, PartialEq, Eq)]
enum Handled {
    Refused(String),
    PastTheReplayCheck,
    Nothing,
}

fn handled(actions: &[Action]) -> Handled {
    for action in actions {
        match action {
            Action::Log(Log::OfferFailed { error, .. }) => return Handled::Refused(error.clone()),
            Action::Fetch { filter, .. }
                if filter
                    .kinds
                    .as_ref()
                    .is_some_and(|kinds| kinds.contains(&Kind::InboxRelays)) =>
            {
                return Handled::PastTheReplayCheck;
            }
            _ => {}
        }
    }
    Handled::Nothing
}

/// The signals among `actions`, opened as `reader`, with the request ids.
fn signals_to(actions: &[Action], reader: &str) -> Vec<(ReqId, String)> {
    publishes(actions)
        .into_iter()
        .filter(|(_, _, event, _)| event.kind == Kind::Custom(SIGNAL_KIND))
        .map(|(req, _, event, _)| {
            let opened = open_signal(&signer(reader), &event).expect("opens");
            (req, opened.rumor.content)
        })
        .collect()
}

/// The peer whose secret key is `hex`, ordered against node A's node
/// address: `after` when its address sorts after A's.
fn ordered_peer(after: bool) -> &'static str {
    let addr = |hex: &str| {
        *fips_core::identity::PeerIdentity::from_npub(&npub(hex))
            .unwrap()
            .node_addr()
    };
    let a = addr(NODE_A_SECRET);
    // B's address sorts before A's (FRC-1601 C.5); C's is checked here.
    let b_before = addr(NODE_B_SECRET) < a;
    let c_after = addr(NODE_C_SECRET) > a;
    assert!(b_before && c_after, "the test keys' ordering changed");
    if after { NODE_C_SECRET } else { NODE_B_SECRET }
}

/// An advert for `hex`'s node naming a NAT endpoint, the harness's DM
/// relays for signals and its STUN server, cached in `h`.
fn cache_nat_advert(h: &mut Harness, hex: &str) {
    let p = params(10);
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: super::super::super::types::ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "nat".to_string(),
        }],
        signal_relays: Some(p.dm_relays.clone()),
        stun_servers: Some(p.stun_servers.clone()),
    };
    let reply = h.reply();
    h.input(Input::InsertAdvert {
        npub: npub(hex),
        advert: CachedOverlayAdvert {
            author_npub: npub(hex),
            advert,
            created_at: h.unix_secs(),
            valid_until_ms: h.now().unix_ms + 3_600_000,
        },
        reply,
    });
}

/// Run node A's connect to `hex`'s node (cached with a NAT advert) up to
/// its offer publish, and return the publish's request and the offer.
fn initiate(h: &mut Harness, hex: &str, spelling: &str, connect: u64) -> (ReqId, TraversalOffer) {
    let (req, offer, _) = initiate_on(h, hex, spelling, connect);
    (req, offer)
}

/// As [`initiate`], and the socket the traversal bound.
fn initiate_on(
    h: &mut Harness,
    hex: &str,
    spelling: &str,
    connect: u64,
) -> (ReqId, TraversalOffer, SocketId) {
    cache_nat_advert(h, hex);
    let actions = h.input(Input::Connect {
        npub: spelling.to_string(),
        connect: ConnectId(connect),
    });
    let inbox = fetches(&actions);
    assert_eq!(inbox.len(), 1, "the inbox lookup: {actions:?}");
    let actions = h.input(Input::FetchDone {
        req: inbox[0].0,
        outcome: Ok(Vec::new()),
    });
    let socket = binds(&actions)[0];
    let actions = complete(h, socket, Some("198.51.100.20".parse().unwrap()));
    let sent = signals_to(&actions, hex);
    assert_eq!(sent.len(), 1, "the offer: {actions:?}");
    let offer: TraversalOffer = serde_json::from_str(&sent[0].1).unwrap();
    (sent[0].0, offer, socket)
}

// --- the responder's checks --------------------------------------------

#[test]
fn an_offer_with_an_oversized_session_id_is_refused_before_it_is_remembered() {
    let mut h = Harness::new(params(10));
    let huge = "s".repeat(40_000);
    let mut offer = offer_from(&h, NODE_B_SECRET, "placeholder");
    offer.session_id = huge.clone();
    let oversized = Handled::Refused("protocol error: oversized-offer".to_string());
    assert_eq!(handled(&deliver(&mut h, NODE_B_SECRET, &offer)), oversized);
    // A second delivery is refused the same way, not as a replay: the id
    // was never remembered.
    offer.nonce = "n2".to_string();
    assert_eq!(handled(&deliver(&mut h, NODE_B_SECRET, &offer)), oversized);
}

#[test]
fn an_offer_with_an_oversized_nonce_is_refused_on_its_first_delivery() {
    let mut h = Harness::new(params(10));
    let mut offer = offer_from(&h, NODE_B_SECRET, "session");
    offer.nonce = "n".repeat(40_000);
    assert_eq!(
        handled(&deliver(&mut h, NODE_B_SECRET, &offer)),
        Handled::Refused("protocol error: oversized-offer".to_string())
    );
}

#[test]
fn offer_fields_are_accepted_up_to_the_bound_and_refused_one_byte_past_it() {
    let mut h = Harness::new(params(10));
    for (session, nonce, accepted) in [
        ("s".repeat(128), "n1".to_string(), true),
        ("t".repeat(129), "n2".to_string(), false),
        ("u".to_string(), "n".repeat(128), true),
        ("v".to_string(), "n".repeat(129), false),
    ] {
        let mut offer = offer_from(&h, NODE_B_SECRET, &session);
        offer.nonce = nonce;
        let outcome = handled(&deliver(&mut h, NODE_B_SECRET, &offer));
        if accepted {
            assert_eq!(
                outcome,
                Handled::PastTheReplayCheck,
                "{} bytes",
                session.len()
            );
        } else {
            assert_eq!(
                outcome,
                Handled::Refused("protocol error: oversized-offer".to_string())
            );
        }
    }
}

#[test]
fn a_new_offer_is_refused_as_seen_sessions_full_by_the_handler_when_the_memory_is_full() {
    let mut p = params(10);
    p.seen_sessions_max_entries = 2;
    let mut h = Harness::new(p);
    for i in 0..2 {
        let offer = offer_from(&h, NODE_B_SECRET, &format!("filler-{i}"));
        assert_eq!(
            handled(&deliver(&mut h, NODE_B_SECRET, &offer)),
            Handled::PastTheReplayCheck,
            "precondition: offer {i} passes the replay check"
        );
    }
    let offer = offer_from(&h, NODE_C_SECRET, "past-the-cap");
    assert_eq!(
        handled(&deliver(&mut h, NODE_C_SECRET, &offer)),
        Handled::Refused("protocol error: seen-sessions-full".to_string())
    );
}

#[test]
fn a_captured_offer_is_still_refused_as_a_replay_after_the_seen_session_cap_fills() {
    const CAP: usize = 64;
    let mut p = params(10);
    p.seen_sessions_max_entries = CAP;
    p.max_concurrent_offers_per_npub = CAP + 2;
    p.max_concurrent_incoming_offers = CAP + 2;
    let mut h = Harness::new(p);
    let captured = offer_from(&h, NODE_B_SECRET, "captured");
    assert_eq!(
        handled(&deliver(&mut h, NODE_B_SECRET, &captured)),
        Handled::PastTheReplayCheck
    );
    let replay = Handled::Refused("replayed or duplicate session id: captured".to_string());
    assert_eq!(handled(&deliver(&mut h, NODE_B_SECRET, &captured)), replay);
    // Spaced so the signal gate, ahead of every check here, sheds none.
    for i in 0..CAP {
        h.advance(200);
        let offer = offer_from(&h, NODE_B_SECRET, &format!("filler-{i}"));
        let outcome = handled(&deliver(&mut h, NODE_B_SECRET, &offer));
        assert_ne!(
            outcome, replay,
            "precondition: a new session is not taken for a replay"
        );
        assert_ne!(
            outcome,
            Handled::Nothing,
            "precondition: the gate shed none"
        );
    }
    h.advance(200);
    assert_eq!(
        handled(&deliver(&mut h, NODE_B_SECRET, &captured)),
        replay,
        "the captured offer, still fresh, passed the replay check"
    );
}

#[test]
fn capacity_off_drops_the_next_offer_and_capacity_on_admits_it() {
    let mut h = Harness::new(params(10));
    h.input(Input::Capacity(false));
    let offer = offer_from(&h, NODE_B_SECRET, "at-capacity");
    let actions = deliver(&mut h, NODE_B_SECRET, &offer);
    assert_eq!(handled(&actions), Handled::Nothing);
    assert!(logs(&actions).contains(&Log::OfferDroppedAtCapacity {
        peer: short_npub(&npub(NODE_B_SECRET)),
        session: "at-capac".to_string(),
    }));
    h.input(Input::Capacity(true));
    let offer = offer_from(&h, NODE_B_SECRET, "with-room");
    assert_eq!(
        handled(&deliver(&mut h, NODE_B_SECRET, &offer)),
        Handled::PastTheReplayCheck
    );
}

/// Run node A's responder session to its end, from `actions`, what the
/// offer from `from` led to: the sender's inbox list is empty, so the
/// answer goes to the DM relays, and the socket's observation fails, so
/// the answer refuses and the session ends once it is sent.
fn end_with_a_refused_answer(h: &mut Harness, from: &str, actions: &[Action]) {
    let inbox = fetches(actions);
    assert_eq!(inbox.len(), 1, "the inbox lookup: {actions:?}");
    let actions = h.input(Input::FetchDone {
        req: inbox[0].0,
        outcome: Ok(Vec::new()),
    });
    let socket = binds(&actions)[0];
    let actions = complete(h, socket, None);
    let sent = signals_to(&actions, from);
    assert_eq!(sent.len(), 1, "the answer: {actions:?}");
    let answer: serde_json::Value = serde_json::from_str(&sent[0].1).unwrap();
    assert_eq!(answer["accepted"], false, "the answer refuses: {answer}");
    let actions = h.input(Input::PublishDone {
        req: sent[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::Close { socket: s } if *s == socket)),
        "the session ends once its answer is sent: {actions:?}"
    );
}

#[test]
fn a_responder_session_that_ends_gives_its_admission_slot_back() {
    const BOUND: usize = 2;
    let mut p = params(10);
    p.max_concurrent_incoming_offers = BOUND;
    p.max_concurrent_offers_per_npub = BOUND;
    let mut h = Harness::new(p);
    // More offers than either bound, from two senders, each session ended
    // before the next offer arrives: every one is admitted only if the
    // sessions before it gave their slots back. Spaced so the signal gate
    // sheds none.
    for i in 0..2 * BOUND + 1 {
        h.advance(200);
        let from = if i % 2 == 0 {
            NODE_B_SECRET
        } else {
            NODE_C_SECRET
        };
        let offer = offer_from(&h, from, &format!("session-{i}"));
        let actions = deliver(&mut h, from, &offer);
        assert_eq!(
            handled(&actions),
            Handled::PastTheReplayCheck,
            "offer {i} was not admitted after {i} sessions ended: {:?}",
            logs(&actions)
        );
        end_with_a_refused_answer(&mut h, from, &actions);
    }
}

#[test]
fn an_offer_dropped_at_capacity_gives_its_admission_slot_back() {
    const BOUND: usize = 2;
    let mut p = params(10);
    p.max_concurrent_incoming_offers = BOUND;
    p.max_concurrent_offers_per_npub = BOUND;
    let mut h = Harness::new(p);
    h.input(Input::Capacity(false));
    // More offers than either bound, from two senders, each dropped: every
    // one reaches the capacity check only if the drops before it gave
    // their slots back. Spaced so the signal gate sheds none.
    for i in 0..2 * BOUND + 1 {
        h.advance(200);
        let from = if i % 2 == 0 {
            NODE_B_SECRET
        } else {
            NODE_C_SECRET
        };
        let offer = offer_from(&h, from, &format!("session-{i}"));
        let log = logs(&deliver(&mut h, from, &offer));
        assert!(
            log.iter()
                .any(|l| matches!(l, Log::OfferDroppedAtCapacity { .. })),
            "offer {i} was not dropped at capacity after {i} drops: {log:?}"
        );
    }
    h.input(Input::Capacity(true));
    h.advance(200);
    let offer = offer_from(&h, NODE_D_SECRET, "with-room");
    let actions = deliver(&mut h, NODE_D_SECRET, &offer);
    assert_eq!(
        handled(&actions),
        Handled::PastTheReplayCheck,
        "an offer from a new sender was not admitted after the drops: {:?}",
        logs(&actions)
    );
}

/// The step that asks to read the on-link prefixes, among `actions`.
fn on_link_read(actions: &[Action]) -> Option<ReqId> {
    actions.iter().find_map(|action| match action {
        Action::ReadInterfaces {
            req,
            read: Read::OnLink,
        } => Some(*req),
        _ => None,
    })
}

#[test]
fn a_responder_whose_punch_fails_closes_its_socket() {
    let mut h = Harness::new(params(10));
    let mut offer = offer_from(&h, NODE_B_SECRET, "punch-fails");
    // One target, which never answers.
    offer.reflexive_address = Some(TraversalAddress {
        protocol: "udp".to_string(),
        ip: "9.9.9.9".to_string(),
        port: 50_001,
    });
    let actions = deliver(&mut h, NODE_B_SECRET, &offer);
    assert_eq!(handled(&actions), Handled::PastTheReplayCheck);
    let inbox = fetches(&actions);
    let actions = h.input(Input::FetchDone {
        req: inbox[0].0,
        outcome: Ok(Vec::new()),
    });
    let socket = binds(&actions)[0];
    let actions = complete(&mut h, socket, Some("198.51.100.20".parse().unwrap()));
    let sent = signals_to(&actions, NODE_B_SECRET);
    assert_eq!(sent.len(), 1, "the answer: {actions:?}");
    let answer: serde_json::Value = serde_json::from_str(&sent[0].1).unwrap();
    assert_eq!(
        answer["accepted"], true,
        "setup: the answer accepts: {answer}"
    );
    let actions = h.input(Input::PublishDone {
        req: sent[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });
    let req = on_link_read(&actions).expect("setup: the on-link prefixes are read");
    let mut actions = h.input(Input::Interfaces {
        req,
        read: Interfaces::OnLink(OnLinkPrefixes::default()),
    });
    // No probe arrives: the punch runs past its duration and its timeout.
    actions.extend(h.advance(30_000));
    let target: SocketAddr = "9.9.9.9:50001".parse().unwrap();
    assert!(
        actions.iter().any(
            |a| matches!(a, Action::Send { socket: s, dst, .. } if *s == socket && *dst == target)
        ),
        "setup: the punch probed its target: {actions:?}"
    );
    assert!(
        logs(&actions)
            .iter()
            .any(|l| matches!(l, Log::ResponderPunchFailed { .. })),
        "setup: the punch failed: {:?}",
        logs(&actions)
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::Close { socket: s } if *s == socket)),
        "the responder's socket was not closed when its punch failed: {actions:?}"
    );
}

#[test]
fn the_gate_reads_awaiting_answers_from_the_session_table() {
    // A tiny shared allowance: past it, only a node awaiting an answer of
    // its own still opens signals, from its reserve.
    let mut h = Harness::new(params(10));
    let flood = |h: &mut Harness| {
        let mut shed = 0;
        for i in 0..60 {
            let offer = offer_from(h, NODE_C_SECRET, &format!("flood-{i}"));
            let actions = deliver(h, NODE_C_SECRET, &offer);
            shed += logs(&actions)
                .iter()
                .filter(|l| {
                    matches!(l, Log::SignalShed { reason, .. }
                    if *reason == super::super::super::traversal::gate::SignalShed::Shared)
                })
                .count();
        }
        shed
    };
    let before = flood(&mut h);
    assert!(before > 0, "the flood is shed by the shared allowance");

    // With an offer of our own out, the shared allowance's sheds are
    // answered from the reserve.
    let mut h = Harness::new(params(10));
    let (req, _) = initiate(&mut h, NODE_B_SECRET, &npub(NODE_B_SECRET), 1);
    h.input(Input::PublishDone {
        req,
        outcome: Outcome::Ok { reached: 1 },
    });
    let during = flood(&mut h);
    assert!(
        during < before,
        "the gate did not see the traversal awaiting its answer ({during} shed, {before} without)"
    );
}

// --- the one re-send ------------------------------------------------------

/// Node A with an offer out to `peer`, waiting on the answer, and the
/// offer.
fn awaiting(peer: &str) -> (Harness, TraversalOffer) {
    awaiting_with(params(10), peer)
}

/// As [`awaiting`], on `params`.
fn awaiting_with(params: Params, peer: &str) -> (Harness, TraversalOffer) {
    let mut h = Harness::new(params);
    let (req, offer) = initiate(&mut h, peer, &npub(peer), 1);
    h.input(Input::PublishDone {
        req,
        outcome: Outcome::Ok { reached: 1 },
    });
    (h, offer)
}

#[test]
fn suppressing_a_peers_offer_resends_ours_once() {
    let peer = ordered_peer(true);
    let (mut h, ours) = awaiting(peer);
    let mut sent = Vec::new();
    for session in ["their-session-1", "their-session-2"] {
        let actions = {
            let offer = offer_from(&h, peer, session);
            deliver(&mut h, peer, &offer)
        };
        for (req, body) in signals_to(&actions, peer) {
            sent.push(serde_json::from_str::<TraversalOffer>(&body).unwrap());
            h.input(Input::PublishDone {
                req,
                outcome: Outcome::Ok { reached: 1 },
            });
        }
        assert_eq!(
            sent,
            vec![ours.clone()],
            "our offer, with its session id, should be re-sent exactly once ({session})"
        );
    }
}

#[test]
fn a_failed_resend_is_tried_again_on_the_next_suppression() {
    let peer = ordered_peer(true);
    let (mut h, ours) = awaiting(peer);
    let actions = {
        let offer = offer_from(&h, peer, "their-session-1");
        deliver(&mut h, peer, &offer)
    };
    let first = signals_to(&actions, peer);
    assert_eq!(first.len(), 1);
    let log = logs(&h.input(Input::PublishDone {
        req: first[0].0,
        outcome: Outcome::Err("relay not found".to_string()),
    }));
    assert!(
        log.iter()
            .any(|l| matches!(l, Log::OfferResendFailed { error, .. }
                if error == "nostr error: relay not found")),
        "{log:?}"
    );

    let mut sent = Vec::new();
    for session in ["their-session-2", "their-session-3"] {
        let actions = {
            let offer = offer_from(&h, peer, session);
            deliver(&mut h, peer, &offer)
        };
        for (req, body) in signals_to(&actions, peer) {
            sent.push(serde_json::from_str::<TraversalOffer>(&body).unwrap());
            h.input(Input::PublishDone {
                req,
                outcome: Outcome::Ok { reached: 1 },
            });
        }
        assert_eq!(
            sent,
            vec![ours.clone()],
            "the retried re-send should publish our offer exactly once ({session})"
        );
    }
}

#[test]
fn a_suppressed_offer_gives_its_admission_slot_back() {
    const BOUND: usize = 2;
    let mut p = params(10);
    p.max_concurrent_incoming_offers = BOUND;
    p.max_concurrent_offers_per_npub = BOUND;
    // Our node address is the smaller, so our traversal is kept and every
    // offer the peer sends meanwhile is suppressed.
    let peer = ordered_peer(true);
    let (mut h, _) = awaiting_with(p, peer);
    for i in 0..2 * BOUND + 1 {
        h.advance(200);
        let offer = offer_from(&h, peer, &format!("their-session-{i}"));
        let log = logs(&deliver(&mut h, peer, &offer));
        assert!(
            log.iter()
                .any(|l| matches!(l, Log::ResponderSuppressed { .. })),
            "offer {i} was not suppressed after {i} suppressions: {log:?}"
        );
    }
    h.advance(200);
    let other = ordered_peer(false);
    let offer = offer_from(&h, other, "another-sender");
    let actions = deliver(&mut h, other, &offer);
    assert_eq!(
        handled(&actions),
        Handled::PastTheReplayCheck,
        "an offer from another sender was not admitted after the suppressions: {:?}",
        logs(&actions)
    );
}

#[test]
fn answering_a_peers_offer_does_not_resend_ours() {
    let peer = ordered_peer(false);
    let (mut h, _) = awaiting(peer);
    let actions = {
        let offer = offer_from(&h, peer, "their-session");
        deliver(&mut h, peer, &offer)
    };
    assert_eq!(
        handled(&actions),
        Handled::PastTheReplayCheck,
        "the peer's offer is answered"
    );
    assert!(
        signals_to(&actions, peer).is_empty(),
        "an offer we answer must not trigger a re-send"
    );
}

// --- the initiator -------------------------------------------------------

#[test]
fn a_peer_configured_in_any_case_is_sent_an_offer_addressed_to_its_canonical_npub() {
    let canonical = npub(NODE_B_SECRET);
    for spelling in [canonical.clone(), canonical.to_ascii_uppercase()] {
        let mut h = Harness::new(params(10));
        let (_, offer) = initiate(&mut h, NODE_B_SECRET, &spelling, 1);
        assert_eq!(
            offer.recipient_npub, canonical,
            "the offer to a peer configured as {spelling} is addressed to another text"
        );
        // The initiator is registered under the key: a connect by the other
        // spelling is the same traversal, and ends at once.
        let other = if spelling == canonical {
            canonical.to_ascii_uppercase()
        } else {
            canonical.clone()
        };
        let actions = h.input(Input::Connect {
            npub: other,
            connect: ConnectId(2),
        });
        assert!(
            matches!(
                actions[..],
                [Action::Release {
                    connect: ConnectId(2)
                }]
            ),
            "the initiator for a peer configured as {spelling} is not registered under its key: \
             {actions:?}"
        );
    }
}

#[test]
fn a_forged_newer_inbox_list_does_not_redirect_an_offer() {
    use super::super::super::event::inbox::inbox_list;
    let mut h = Harness::new(params(10));
    // Two relays in the pool, named by neither our DM relays nor the
    // peer's advert, so only the inbox list can put either in the offer's
    // relays.
    let p = params(10);
    let (named, redirected) = (&p.advert_relays[0], &p.advert_relays[1]);
    let now_ms = h.now().unix_ms;
    let b = signer(NODE_B_SECRET);
    let genuine = inbox_list(&b, &[named], now_ms - 20_000, [0u8; 32]).unwrap();
    let mut forged = inbox_list(&b, &[named], now_ms - 10_000, [0u8; 32]).unwrap();
    forged.tags = inbox_list(&b, &[redirected], now_ms - 10_000, [0u8; 32])
        .unwrap()
        .tags;

    cache_nat_advert(&mut h, NODE_B_SECRET);
    let actions = h.input(Input::Connect {
        npub: npub(NODE_B_SECRET),
        connect: ConnectId(1),
    });
    let inbox = fetches(&actions);
    assert_eq!(inbox.len(), 1, "the inbox lookup: {actions:?}");
    let actions = h.input(Input::FetchDone {
        req: inbox[0].0,
        outcome: Ok(vec![genuine, forged.clone()]),
    });
    let forged_lines: Vec<Log> = logs(&actions)
        .into_iter()
        .filter(|line| matches!(line, Log::EventForged { .. }))
        .collect();
    let socket = binds(&actions)[0];
    let actions = complete(&mut h, socket, Some("198.51.100.20".parse().unwrap()));
    let offers: Vec<Vec<String>> = publishes(&actions)
        .into_iter()
        .filter(|(_, _, event, _)| event.kind == nostr::event::Kind::Custom(SIGNAL_KIND))
        .map(|(_, relays, _, _)| relays)
        .collect();
    assert_eq!(offers.len(), 1, "the offer: {actions:?}");
    assert!(offers[0].contains(named), "{:?}", offers[0]);
    assert!(!offers[0].contains(redirected), "{:?}", offers[0]);
    assert_eq!(
        forged_lines,
        vec![Log::EventForged {
            kind: 10050,
            author: npub(NODE_B_SECRET),
            event: forged.id,
            total: 1,
        }]
    );
}

#[test]
fn a_failed_initiator_closes_its_socket() {
    let mut h = Harness::new(params(10));
    let (req, _, socket) = initiate_on(&mut h, NODE_B_SECRET, &npub(NODE_B_SECRET), 1);
    let actions = h.input(Input::PublishDone {
        req,
        outcome: Outcome::Err("relay not found".to_string()),
    });
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Failed {
                connect: ConnectId(1),
                ..
            }
        )),
        "setup: the connect failed: {actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::Close { socket: s } if *s == socket)),
        "the failed initiator's socket was not closed: {actions:?}"
    );
}

#[test]
fn a_peer_configured_in_upper_case_still_wins_the_dual_init_election() {
    let peer = ordered_peer(true);
    let mut h = Harness::new(params(10));
    let (req, _) = initiate(&mut h, peer, &npub(peer).to_ascii_uppercase(), 1);
    h.input(Input::PublishDone {
        req,
        outcome: Outcome::Ok { reached: 1 },
    });
    let actions = {
        let offer = offer_from(&h, peer, "their-session");
        deliver(&mut h, peer, &offer)
    };
    assert!(
        logs(&actions)
            .iter()
            .any(|l| matches!(l, Log::ResponderSuppressed { .. })),
        "the peer's offer was answered instead of suppressed in favour of ours: {actions:?}"
    );
}

// --- two machines over a fake relay and network ------------------------

/// The STUN server both nodes use, and its address.
const STUN: &str = "stun:7.7.7.7:3478";
const STUN_ADDR: &str = "7.7.7.7:3478";

/// How a node's NAT maps and filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nat {
    /// One external port per socket, open to any source.
    Cone,
    /// One external port per socket and destination, open only to that
    /// destination.
    Symmetric,
}

/// One node of the pair: its machine, its public IP and NAT, and the
/// external ports its sockets are mapped to.
struct Node {
    h: Harness,
    hex: &'static str,
    ip: [u8; 4],
    nat: Nat,
    /// (socket, destination or none for a cone) to external port.
    mappings: BTreeMap<(u64, Option<SocketAddr>), u16>,
    next_port: u16,
    adopted: Vec<(String, SocketAddr)>,
    failed: Vec<String>,
    offers_sent: usize,
}

impl Node {
    fn new(hex: &'static str, ip: [u8; 4], nat: Nat) -> Self {
        let mut p = params(10);
        p.stun_servers = vec![STUN.to_string()];
        Self {
            h: Harness::with_key(p, hex),
            hex,
            ip,
            nat,
            mappings: BTreeMap::new(),
            next_port: 50_000,
            adopted: Vec::new(),
            failed: Vec::new(),
            offers_sent: 0,
        }
    }

    /// The external address `socket`'s datagrams to `dst` leave from.
    fn map(&mut self, socket: SocketId, dst: SocketAddr) -> SocketAddr {
        let key = match self.nat {
            Nat::Cone => (socket.0, None),
            Nat::Symmetric => (socket.0, Some(dst)),
        };
        let next = &mut self.next_port;
        let port = *self.mappings.entry(key).or_insert_with(|| {
            *next += 1;
            *next
        });
        SocketAddr::from((self.ip, port))
    }

    /// The socket a datagram from `src` to external port `port` reaches.
    fn admit(&self, port: u16, src: SocketAddr) -> Option<SocketId> {
        self.mappings
            .iter()
            .find(|((_, dst), p)| **p == port && dst.is_none_or(|d| d == src))
            .map(|((socket, _), _)| SocketId(*socket))
    }
}

/// What a step of one node asks of the world.
enum Effect {
    /// Deliver a signal to the other node.
    Relay(Event),
    /// Deliver a datagram to the other node's external `dst` from `src`.
    Datagram {
        dst: SocketAddr,
        src: SocketAddr,
        bytes: Vec<u8>,
    },
}

/// Carry out `node`'s actions; the inputs they produce for `node` itself
/// are fed back at once, and what reaches the other node is returned.
fn run(node: &mut Node, mut actions: Vec<Action>) -> Vec<Effect> {
    let mut effects = Vec::new();
    while !actions.is_empty() {
        let mut next = Vec::new();
        for action in actions {
            match action {
                Action::Publish { req, event, .. } => {
                    if event.kind == Kind::Custom(SIGNAL_KIND) {
                        let opened = open_signal(&signer(peer_of(node.hex)), &event);
                        if opened.is_ok_and(|o| {
                            serde_json::from_str::<TraversalOffer>(&o.rumor.content)
                                .is_ok_and(|b| b.message_type == "offer")
                        }) {
                            node.offers_sent += 1;
                        }
                        next.extend(node.h.input(Input::PublishDone {
                            req,
                            outcome: Outcome::Ok { reached: 1 },
                        }));
                        effects.push(Effect::Relay(event));
                    } else {
                        next.extend(node.h.input(Input::PublishDone {
                            req,
                            outcome: Outcome::Ok { reached: 1 },
                        }));
                    }
                }
                Action::Fetch { req, .. } => next.extend(node.h.input(Input::FetchDone {
                    req,
                    outcome: Ok(Vec::new()),
                })),
                Action::Bind { socket } => next.extend(node.h.input(Input::SocketBound {
                    socket,
                    local: SocketAddr::from(([0, 0, 0, 0], 40_000 + socket.0 as u16)),
                })),
                Action::Send { socket, dst, bytes } => {
                    let src = node.map(socket, dst);
                    if dst == STUN_ADDR.parse().unwrap() {
                        let std::net::SocketAddr::V4(mapped) = src else {
                            unreachable!()
                        };
                        next.extend(node.h.input(Input::Datagram {
                            socket,
                            src: dst,
                            bytes: binding_success(&bytes[8..20], mapped),
                        }));
                    } else {
                        effects.push(Effect::Datagram { dst, src, bytes });
                    }
                }
                Action::ReadInterfaces { req, .. } => {
                    next.extend(node.h.input(Input::Interfaces {
                        req,
                        read: Interfaces::OnLink(OnLinkPrefixes::default()),
                    }))
                }
                Action::Adopt {
                    remote, session, ..
                } => node.adopted.push((session, remote)),
                Action::Failed { reason, .. } => node.failed.push(reason),
                _ => {}
            }
        }
        actions = next;
    }
    effects
}

/// The other node of the pair.
fn peer_of(hex: &str) -> &'static str {
    if hex == NODE_A_SECRET {
        NODE_B_SECRET
    } else {
        NODE_A_SECRET
    }
}

/// Deliver `effects` from one node to `to`, and return what `to` did.
fn deliver_effects(to: &mut Node, effects: Vec<Effect>) -> Vec<Action> {
    let mut actions = Vec::new();
    for effect in effects {
        match effect {
            Effect::Relay(event) => actions.extend(to.h.input(delivered(event))),
            Effect::Datagram { dst, src, bytes } => {
                if dst.ip() != std::net::IpAddr::from(to.ip) {
                    continue;
                }
                if let Some(socket) = to.admit(dst.port(), src) {
                    actions.extend(to.h.input(Input::Datagram { socket, src, bytes }));
                }
            }
        }
    }
    actions
}

/// Run both nodes until neither has anything to do and no deadline falls
/// before `until_ms`, moving both clocks together.
fn settle(a: &mut Node, b: &mut Node, a_first: Vec<Action>, b_first: Vec<Action>, until_ms: u64) {
    settle_with(a, b, a_first, b_first, until_ms, None);
}

/// As [`settle`], and once `a` has published its first offer, hand `a`
/// `stale` as a relay would, while `a` waits on its answer.
fn settle_with(
    a: &mut Node,
    b: &mut Node,
    a_first: Vec<Action>,
    b_first: Vec<Action>,
    until_ms: u64,
    mut stale: Option<Event>,
) {
    let (mut a_actions, mut b_actions) = (a_first, b_first);
    loop {
        while !a_actions.is_empty() || !b_actions.is_empty() {
            let to_b = run(a, std::mem::take(&mut a_actions));
            let to_a = run(b, std::mem::take(&mut b_actions));
            b_actions = deliver_effects(b, to_b);
            a_actions = deliver_effects(a, to_a);
            if a.offers_sent > 0
                && let Some(stale) = stale.take()
            {
                a_actions.extend(a.h.input(delivered(stale)));
            }
        }
        let next = [a.h.m.poll_timeout(), b.h.m.poll_timeout()]
            .into_iter()
            .flatten()
            .map(|at| at.0)
            .min();
        let Some(at) = next.filter(|at| *at <= until_ms) else {
            return;
        };
        for node in [&mut *a, &mut *b] {
            node.h.ms = node.h.ms.max(at);
        }
        a_actions = a.h.advance(0);
        b_actions = b.h.advance(0);
    }
}

/// Node A traverses to node B behind `b_nat`; A is behind a cone NAT.
fn traverse(b_nat: Nat, stale: bool) -> (Node, Node) {
    let mut a = Node::new(NODE_A_SECRET, [9, 9, 9, 9], Nat::Cone);
    let mut b = Node::new(NODE_B_SECRET, [8, 8, 4, 4], b_nat);
    cache_nat_advert(&mut a.h, NODE_B_SECRET);
    let first = a.h.input(Input::Connect {
        npub: npub(NODE_B_SECRET),
        connect: ConnectId(1),
    });
    // An answer by B to an offer A never sent, which the relay hands A
    // while A waits on its answer: it must not be taken for the answer,
    // which is routed by the offer's nonce.
    let stale = stale.then(|| {
        let answer = create_traversal_answer(
            "old-session".to_string(),
            a.h.now().unix_ms,
            120_000,
            "old-nonce".to_string(),
            npub(NODE_B_SECRET),
            npub(NODE_A_SECRET),
            "old-session".to_string(),
            false,
            None,
            Vec::new(),
            None,
            None,
            Some("busy".to_string()),
            None,
        );
        sealed(&b.h, NODE_B_SECRET, NODE_A_SECRET, &answer)
    });
    settle_with(&mut a, &mut b, first, Vec::new(), 30_000, stale);
    (a, b)
}

#[test]
fn a_whole_traversal_runs_through_a_cone_nat() {
    let (a, b) = traverse(Nat::Cone, true);
    assert!(a.failed.is_empty(), "A's connect failed: {:?}", a.failed);
    assert_eq!(a.adopted.len(), 1, "A adopts once");
    assert_eq!(b.adopted.len(), 1, "B adopts once");
    assert_eq!(a.adopted[0].0, b.adopted[0].0, "one session on both sides");
    assert_eq!(a.adopted[0].1, SocketAddr::from(([8, 8, 4, 4], 50_001)));
    assert_eq!(b.adopted[0].1, SocketAddr::from(([9, 9, 9, 9], 50_001)));
}

#[test]
fn a_whole_traversal_runs_through_a_symmetric_nat() {
    let (a, b) = traverse(Nat::Symmetric, false);
    assert!(a.failed.is_empty(), "A's connect failed: {:?}", a.failed);
    assert_eq!(a.adopted.len(), 1);
    assert_eq!(b.adopted.len(), 1);
    // B's NAT maps its probes toward A to a fresh port, which A adopts as a
    // remapped port of the target B's STUN observation named.
    assert_eq!(a.adopted[0].1.ip(), std::net::IpAddr::from([8, 8, 4, 4]));
    assert_ne!(a.adopted[0].1.port(), 50_001);
    assert_eq!(b.adopted[0].1, SocketAddr::from(([9, 9, 9, 9], 50_001)));
}

#[test]
fn dual_initiation_ends_in_one_session_with_one_resend() {
    let mut a = Node::new(NODE_A_SECRET, [9, 9, 9, 9], Nat::Cone);
    let mut b = Node::new(NODE_B_SECRET, [8, 8, 4, 4], Nat::Cone);
    cache_nat_advert(&mut a.h, NODE_B_SECRET);
    cache_nat_advert(&mut b.h, NODE_A_SECRET);
    let a_first = a.h.input(Input::Connect {
        npub: npub(NODE_B_SECRET),
        connect: ConnectId(1),
    });
    let b_first = b.h.input(Input::Connect {
        npub: npub(NODE_A_SECRET),
        connect: ConnectId(1),
    });
    settle(&mut a, &mut b, a_first, b_first, 200_000);
    // B's address is the smaller, so B's traversal survives: B adopts as
    // initiator and A as responder, in B's session.
    assert_eq!(a.adopted.len(), 1, "A adopts once: {:?}", a.adopted);
    assert_eq!(b.adopted.len(), 1, "B adopts once: {:?}", b.adopted);
    assert_eq!(a.adopted[0].0, b.adopted[0].0);
    assert!(b.failed.is_empty(), "B's connect failed: {:?}", b.failed);
    // B sent its offer once more when it suppressed A's, and no more.
    assert_eq!(b.offers_sent, 2, "B's offer and its one re-send");
    assert_eq!(a.offers_sent, 1);
    // A's own traversal is never answered, and times out.
    assert_eq!(
        a.failed,
        vec![format!(
            "signal timeout waiting for answer from {}",
            npub(NODE_B_SECRET)
        )]
    );
}
