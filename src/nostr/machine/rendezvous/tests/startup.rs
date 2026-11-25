//! Start-up: the subscribe, the inbox relay list, the first advert publish,
//! the subscribe's retry, and the inbox relay list's daily republish.

use nostr::event::Kind;
use nostr::filter::Filter;
use nostr::types::RelayUrl;

use super::super::super::event::inbox::inbox_relays;
use super::super::super::types::{ADVERT_KIND, SIGNAL_KIND};
use super::*;

/// The advertised transports of a node behind NAT.
fn nat_transports() -> Input {
    Input::Transports {
        snapshot: vec![AdvertTransportSnapshot::Udp {
            advertise: true,
            is_public: false,
            external_addr: None,
            local_addr: Some("0.0.0.0:2121".parse().unwrap()),
            transport_key: 1,
        }],
        reply: None,
    }
}

use super::super::super::adverts::assemble::AdvertTransportSnapshot;

/// Start, and answer the subscribe with `outcome`; the actions that follow.
fn started(h: &mut Harness, outcome: Outcome) -> Vec<Action> {
    let actions = h.input(Input::Start);
    let (req, _) = subscribe_of(&actions[0]).expect("a subscribe");
    h.input(Input::SubscribeDone { req, outcome })
}

#[test]
fn start_subscribes_to_signals_and_adverts_then_publishes_the_inbox_list_then_the_advert() {
    let mut h = Harness::new(params(10));
    let first = publishes(&h.input(nat_transports()));
    assert_eq!(first.len(), 1, "the assembled advert is published");
    h.input(Input::PublishDone {
        req: first[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });

    let actions = h.input(Input::Start);
    assert_eq!(actions.len(), 1, "start only subscribes: {actions:?}");
    let Action::Subscribe { req, subs, timeout } = &actions[0] else {
        panic!("not a subscribe: {actions:?}");
    };
    assert_eq!(*timeout, Duration::from_secs(5));
    assert_eq!(subs.len(), 2);
    let p = params(10);
    assert_eq!(subs[0].1, p.dm_relays);
    assert_eq!(
        subs[0].2,
        Filter::new()
            .kind(Kind::Custom(SIGNAL_KIND))
            .pubkey(pubkey(NODE_A_SECRET))
            .limit(0)
    );
    assert_eq!(subs[1].1, p.advert_relays);
    assert_eq!(
        subs[1].2,
        Filter::new()
            .kind(Kind::Custom(ADVERT_KIND))
            .identifier(ADVERT_IDENTIFIER)
    );
    assert_ne!(subs[0].0, subs[1].0, "two subscriptions");

    let inbox = publishes(&h.input(Input::SubscribeDone {
        req: *req,
        outcome: Outcome::Ok { reached: 1 },
    }));
    assert_eq!(inbox.len(), 1, "the inbox relay list follows the subscribe");
    assert_eq!(inbox[0].2.kind, Kind::InboxRelays);
    assert_eq!(inbox[0].1, p.dm_relays);
    assert_eq!(inbox[0].3, Some(Duration::from_secs(5)));

    let advert = publishes(&h.input(Input::PublishDone {
        req: inbox[0].0,
        outcome: Outcome::Ok { reached: 1 },
    }));
    assert_eq!(advert.len(), 1, "the advert follows the inbox relay list");
    assert_eq!(advert[0].2.kind, Kind::Custom(ADVERT_KIND));
    assert_eq!(advert[0].1, p.advert_relays);
    assert_eq!(advert[0].3, Some(Duration::from_secs(10)));
    assert_eq!(
        h.m.poll_timeout(),
        Some(TestInstant(100_000)),
        "the advert republish"
    );
}

#[test]
fn a_failed_subscribe_is_retried_after_two_seconds_doubling_to_sixty() {
    let mut h = Harness::new(params(10));
    let actions = h.input(Input::Start);
    let (mut req, subs) = subscribe_of(&actions[0]).unwrap();
    let mut retries = Vec::new();
    for _ in 0..7 {
        let inbox = publishes(&h.input(Input::SubscribeDone {
            req,
            outcome: Outcome::Err("relay not found".to_string()),
        }));
        assert_eq!(
            inbox.len(),
            1,
            "each attempt publishes the inbox relay list"
        );
        let failed_at = h.ms;
        h.input(Input::PublishDone {
            req: inbox[0].0,
            outcome: Outcome::Ok { reached: 1 },
        });
        let retry = loop {
            let actions = h.advance(1_000);
            if let Some(found) = actions.iter().find_map(subscribe_of) {
                break found;
            }
            assert!(h.ms - failed_at <= 60_000, "no retry within 60 s");
        };
        retries.push((h.ms - failed_at) / 1000);
        assert_eq!(retry.1, subs, "a retry names the same subscriptions");
        req = retry.0;
    }
    assert_eq!(retries, vec![2, 4, 8, 16, 32, 60, 60]);
    let log = logs(&h.input(Input::SubscribeDone {
        req,
        outcome: Outcome::TimedOut,
    }));
    assert_eq!(log, vec![Log::SubscribeTimedOut { timeout_ms: 5_000 }]);
}

#[test]
fn the_inbox_relay_list_is_republished_before_it_ages_out_of_the_lookup_window() {
    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    let lookback_ms = super::super::super::traversal::rules::INBOX_LOOKBACK.as_millis() as u64;
    let mut h = Harness::new(params(10));
    let inbox = publishes(&started(&mut h, Outcome::Ok { reached: 1 }));
    let mut sent = vec![h.ms];
    h.input(Input::PublishDone {
        req: inbox[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });
    while h.ms < 31 * DAY_MS {
        for (req, _, event, _) in publishes(&h.advance(60_000)) {
            if event.kind == Kind::InboxRelays {
                sent.push(h.ms);
                h.input(Input::PublishDone {
                    req,
                    outcome: Outcome::Ok { reached: 1 },
                });
            } else {
                h.input(Input::PublishDone {
                    req,
                    outcome: Outcome::Ok { reached: 1 },
                });
            }
        }
    }
    assert!(sent.len() >= 2, "the list should have been published again");
    let mut last = 0;
    for at in &sent {
        assert!(
            at - last < lookback_ms,
            "a gap between publishes reached the lookup window"
        );
        last = *at;
    }
    assert!(
        h.ms - last < lookback_ms,
        "the last publish aged out of the lookup window"
    );
}

#[test]
fn the_inbox_relay_list_this_node_publishes_is_read_back_as_its_dm_relays() {
    let mut h = Harness::new(params(10));
    let inbox = publishes(&started(&mut h, Outcome::Ok { reached: 1 }));
    let event = &inbox[0].2;
    assert_eq!(event.kind, Kind::InboxRelays);
    assert_eq!(event.tags.len(), 2, "the list should name both DM relays");
    let expected: Vec<String> = params(10)
        .dm_relays
        .iter()
        .map(|r| RelayUrl::parse(r).unwrap().to_string())
        .collect();
    assert_eq!(inbox_relays(event), expected);
}
