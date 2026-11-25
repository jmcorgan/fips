//! The node's queries: a peer's endpoints from the cache or a fetch, the
//! stale-advert refetch and its streak reset, open discovery, and results
//! the machine no longer expects.

use nostr::event::Kind;
use nostr::filter::Filter;

use super::super::super::types::ADVERT_KIND;
use super::super::log::{IngestPath, Source};
use super::*;

/// Ask for `hex`'s endpoints; the actions that follow and the reply id.
fn endpoints(h: &mut Harness, hex: &str) -> (Vec<Action>, ReplyId) {
    let reply = h.reply();
    let actions = h.input(Input::Endpoints {
        key: key(hex),
        reply,
    });
    (actions, reply)
}

/// Ask for a refetch of `hex`'s advert; its fetch and the reply id.
fn refetch(h: &mut Harness, hex: &str) -> (ReqId, ReplyId) {
    let reply = h.reply();
    let fetch = fetches(&h.input(Input::Refetch {
        key: key(hex),
        reply,
    }));
    assert_eq!(fetch.len(), 1, "a refetch asks the relays");
    (fetch[0].0, reply)
}

/// The outcome of a refetch answered with `events`, and the actions.
fn refetched(h: &mut Harness, hex: &str, events: Vec<Event>) -> (Vec<Action>, ReplyId) {
    let (req, reply) = refetch(h, hex);
    (
        h.input(Input::FetchDone {
            req,
            outcome: Ok(events),
        }),
        reply,
    )
}

fn refetch_outcome(actions: Vec<Action>, reply: ReplyId) -> (usize, NostrRefetchOutcome) {
    match reply_to(actions, reply) {
        Some((at, Reply::Refetch(outcome))) => (at, outcome),
        other => panic!("no refetch reply: {other:?}"),
    }
}

/// The refetch of `hex`'s advert answered with `events`, after two
/// recorded failures for the peer, and the peers whose failure streak the
/// refetch's step reset. The reset and the reply are made in one step, so
/// the reply's reader sees the reset streak.
fn refetched_after_failures(
    h: &mut Harness,
    hex: &str,
    events: Vec<Event>,
) -> (Vec<Action>, ReplyId, Vec<String>) {
    for _ in 0..2 {
        let reply = h.reply();
        h.input(Input::RecordFailure {
            npub: npub(hex),
            reply,
        });
    }
    assert!(h.m.take_status().is_some(), "the failures are recorded");
    let (actions, reply) = refetched(h, hex, events);
    let reset =
        h.m.take_status()
            .map(|status| {
                status
                    .failures
                    .into_iter()
                    .filter(|(_, record)| record.consecutive_failures == 0)
                    .map(|(npub, _)| npub)
                    .collect()
            })
            .unwrap_or_default();
    (actions, reply, reset)
}

#[test]
fn endpoints_come_from_the_cache_without_a_fetch_when_current() {
    let mut h = Harness::new(params(10));
    let event = advert_by(NODE_B_SECRET, h.unix_secs(), &body("8.8.8.8:443"));
    insert(&mut h, &event);
    let (actions, reply) = endpoints(&mut h, NODE_B_SECRET);
    assert!(
        fetches(&actions).is_empty(),
        "a current cached advert needs no fetch"
    );
    assert_eq!(
        logs(&actions),
        vec![Log::Resolved {
            peer: npub(NODE_B_SECRET),
            source: Source::Cache,
            endpoints: body("8.8.8.8:443").endpoints,
        }]
    );
    assert!(matches!(
        reply_to(actions, reply),
        Some((_, Reply::Endpoints(Ok(e)))) if e == body("8.8.8.8:443").endpoints
    ));
}

#[test]
fn endpoints_on_a_cache_miss_come_from_the_newest_fetched_advert_by_the_peer() {
    let mut h = Harness::new(params(10));
    let (actions, reply) = endpoints(&mut h, NODE_B_SECRET);
    let fetch = fetches(&actions);
    assert_eq!(fetch.len(), 1);
    assert_eq!(fetch[0].1, params(10).advert_relays);
    assert_eq!(
        fetch[0].2,
        Filter::new()
            .author(pubkey(NODE_B_SECRET))
            .kind(Kind::Custom(ADVERT_KIND))
            .identifier(ADVERT_IDENTIFIER)
    );
    let now = h.unix_secs();
    let events = vec![
        advert_by(NODE_B_SECRET, now - 20, &body("8.8.8.1:443")),
        advert_by(NODE_B_SECRET, now - 10, &body("8.8.8.2:443")),
        advert_by(NODE_C_SECRET, now, &body("8.8.8.3:443")),
    ];
    let actions = h.input(Input::FetchDone {
        req: fetch[0].0,
        outcome: Ok(events),
    });
    assert_eq!(
        logs(&actions),
        vec![Log::Resolved {
            peer: npub(NODE_B_SECRET),
            source: Source::RelayFetch,
            endpoints: body("8.8.8.2:443").endpoints,
        }]
    );
    assert!(matches!(
        reply_to(actions, reply),
        Some((_, Reply::Endpoints(Ok(e)))) if e == body("8.8.8.2:443").endpoints
    ));
    assert_eq!(
        inspect(&mut h, &npub(NODE_B_SECRET)).created_at,
        Some(now - 10),
        "the fetched advert is cached"
    );
}

#[test]
fn a_fetch_that_finds_no_advert_by_the_peer_answers_missing_advert() {
    let mut h = Harness::new(params(10));
    let (actions, reply) = endpoints(&mut h, NODE_B_SECRET);
    let req = fetches(&actions)[0].0;
    let foreign = advert_by(NODE_C_SECRET, h.unix_secs(), &body("8.8.8.3:443"));
    let actions = h.input(Input::FetchDone {
        req,
        outcome: Ok(vec![foreign]),
    });
    assert!(matches!(
        reply_to(actions, reply),
        Some((_, Reply::Endpoints(Err(Error::MissingAdvert(n))))) if n == npub(NODE_B_SECRET)
    ));

    let (actions, reply) = endpoints(&mut h, NODE_B_SECRET);
    let req = fetches(&actions)[0].0;
    let actions = h.input(Input::FetchDone {
        req,
        outcome: Err("relay not found".to_string()),
    });
    assert!(matches!(
        reply_to(actions, reply),
        Some((_, Reply::Endpoints(Err(Error::Nostr(text))))) if text == "relay not found"
    ));
}

#[test]
fn a_refetch_that_finds_nothing_evicts_and_resets_the_streak_before_replying() {
    let mut h = Harness::new(params(10));
    let event = advert_by(NODE_B_SECRET, h.unix_secs(), &body("8.8.8.8:443"));
    insert(&mut h, &event);
    let (actions, reply, reset) = refetched_after_failures(&mut h, NODE_B_SECRET, Vec::new());
    let (_, outcome) = refetch_outcome(actions, reply);
    assert_eq!(outcome, NostrRefetchOutcome::Evicted);
    assert_eq!(reset, vec![npub(NODE_B_SECRET)], "the streak is reset");
    assert_eq!(inspect(&mut h, &npub(NODE_B_SECRET)).created_at, None);
}

#[test]
fn a_forged_newer_advert_does_not_displace_the_genuine_one_in_a_fetch() {
    let mut h = Harness::new(params(10));
    let (actions, reply) = endpoints(&mut h, NODE_B_SECRET);
    let req = fetches(&actions)[0].0;
    let now = h.unix_secs();
    let genuine = advert_by(NODE_B_SECRET, now - 20, &body("8.8.8.1:443"));
    let forged = forged_by(
        NODE_B_SECRET,
        now - 10,
        &body("8.8.8.1:443"),
        &body("8.8.4.4:443"),
    );
    let actions = h.input(Input::FetchDone {
        req,
        outcome: Ok(vec![genuine, forged]),
    });
    let lines = logs(&actions);
    assert!(matches!(
        reply_to(actions, reply),
        Some((_, Reply::Endpoints(Ok(e)))) if e == body("8.8.8.1:443").endpoints
    ));
    assert_eq!(
        inspect(&mut h, &npub(NODE_B_SECRET)).created_at,
        Some(now - 20),
        "the genuine advert is cached"
    );
    assert_eq!(forged_totals(&lines).0, vec![1], "one forged event");
}

#[test]
fn a_forged_newer_advert_does_not_hold_back_a_refetch_refresh() {
    let mut h = Harness::new(params(10));
    let now = h.unix_secs();
    insert(
        &mut h,
        &advert_by(NODE_B_SECRET, now - 30, &body("8.8.8.8:443")),
    );
    let genuine = advert_by(NODE_B_SECRET, now - 25, &body("8.8.8.1:443"));
    let forged = forged_by(
        NODE_B_SECRET,
        now - 20,
        &body("8.8.8.1:443"),
        &body("8.8.4.4:443"),
    );
    let (actions, reply, reset) =
        refetched_after_failures(&mut h, NODE_B_SECRET, vec![genuine, forged]);
    let lines = logs(&actions);
    assert_eq!(
        refetch_outcome(actions, reply).1,
        NostrRefetchOutcome::Refreshed
    );
    assert_eq!(reset, vec![npub(NODE_B_SECRET)], "the streak is reset");
    assert_eq!(
        inspect(&mut h, &npub(NODE_B_SECRET)).created_at,
        Some(now - 25),
        "the genuine advert is cached"
    );
    let (actions, reply) = endpoints(&mut h, NODE_B_SECRET);
    assert!(matches!(
        reply_to(actions, reply),
        Some((_, Reply::Endpoints(Ok(e)))) if e == body("8.8.8.1:443").endpoints
    ));
    assert_eq!(forged_totals(&lines).0, vec![1], "one forged event");
}

#[test]
fn a_refetch_answered_only_by_a_forged_advert_evicts_as_if_nothing_came_back() {
    let mut h = Harness::new(params(10));
    let now = h.unix_secs();
    insert(
        &mut h,
        &advert_by(NODE_B_SECRET, now - 30, &body("8.8.8.8:443")),
    );
    let forged = forged_by(
        NODE_B_SECRET,
        now - 20,
        &body("8.8.8.8:443"),
        &body("8.8.4.4:443"),
    );
    let (actions, reply, reset) = refetched_after_failures(&mut h, NODE_B_SECRET, vec![forged]);
    let lines = logs(&actions);
    assert_eq!(
        refetch_outcome(actions, reply).1,
        NostrRefetchOutcome::Evicted
    );
    assert_eq!(reset, vec![npub(NODE_B_SECRET)], "the streak is reset");
    assert_eq!(inspect(&mut h, &npub(NODE_B_SECRET)).created_at, None);
    assert_eq!(forged_totals(&lines).0, vec![1], "one forged event");
}

#[test]
fn a_refetch_with_only_foreign_answers_is_skipped() {
    let mut h = Harness::new(params(10));
    let event = advert_by(NODE_B_SECRET, h.unix_secs(), &body("8.8.8.8:443"));
    insert(&mut h, &event);
    let foreign = advert_by(NODE_C_SECRET, h.unix_secs() + 10, &body("8.8.8.3:443"));
    let (actions, reply, reset) = refetched_after_failures(&mut h, NODE_B_SECRET, vec![foreign]);
    assert!(reset.is_empty());
    assert_eq!(
        refetch_outcome(actions, reply).1,
        NostrRefetchOutcome::Skipped
    );
    assert!(inspect(&mut h, &npub(NODE_B_SECRET)).created_at.is_some());
}

#[test]
fn a_refetch_with_an_older_or_equal_advert_is_the_same_advert() {
    let mut h = Harness::new(params(10));
    let cached = h.unix_secs() - 30;
    insert(
        &mut h,
        &advert_by(NODE_B_SECRET, cached, &body("8.8.8.8:443")),
    );
    for created in [cached, cached - 1] {
        let event = advert_by(NODE_B_SECRET, created, &body("8.8.8.9:443"));
        let (actions, reply, reset) = refetched_after_failures(&mut h, NODE_B_SECRET, vec![event]);
        assert!(reset.is_empty());
        assert_eq!(
            refetch_outcome(actions, reply).1,
            NostrRefetchOutcome::SameAdvert
        );
    }
    assert_eq!(
        inspect(&mut h, &npub(NODE_B_SECRET)).created_at,
        Some(cached)
    );
}

#[test]
fn a_refreshed_advert_that_the_full_cache_refuses_is_skipped_without_a_reset() {
    let mut h = Harness::new(params(1));
    let event = advert_by(NODE_C_SECRET, h.unix_secs(), &body("8.8.8.3:443"));
    insert(&mut h, &event);
    let newer = advert_by(NODE_B_SECRET, h.unix_secs(), &body("8.8.8.8:443"));
    let (actions, reply, reset) = refetched_after_failures(&mut h, NODE_B_SECRET, vec![newer]);
    assert!(reset.is_empty(), "the streak is not reset");
    assert_eq!(
        logs(&actions),
        vec![
            Log::CacheFull { bound: 1 },
            Log::NotCached {
                peer: npub(NODE_B_SECRET),
                path: IngestPath::Refetch,
            },
        ]
    );
    assert_eq!(
        refetch_outcome(actions, reply).1,
        NostrRefetchOutcome::Skipped
    );
}

#[test]
fn open_discovery_candidates_are_drawn_after_a_prune() {
    let mut h = Harness::new(params(10));
    // An advert whose horizon and lapse grace pass while time runs on.
    let old = advert_by(NODE_C_SECRET, h.unix_secs(), &body("8.8.8.3:443"));
    insert(&mut h, &old);
    h.advance(7_200_000 + 100_000);
    let current = advert_by(NODE_B_SECRET, h.unix_secs(), &body("8.8.8.8:443"));
    insert(&mut h, &current);
    let reply = h.reply();
    let actions = h.input(Input::OpenDiscovery {
        max: 10,
        skip: BTreeSet::new(),
        reply,
    });
    let Some((_, Reply::OpenDiscovery(candidates))) = reply_to(actions, reply) else {
        panic!("no candidates");
    };
    let authors: Vec<String> = candidates.into_iter().map(|c| c.0).collect();
    assert_eq!(authors, vec![npub(NODE_B_SECRET)]);
    assert_eq!(
        inspect(&mut h, &npub(NODE_C_SECRET)).created_at,
        None,
        "the expired entry was pruned"
    );

    let reply = h.reply();
    let actions = h.input(Input::OpenDiscovery {
        max: 10,
        skip: [npub(NODE_B_SECRET)].into_iter().collect(),
        reply,
    });
    assert!(matches!(
        reply_to(actions, reply),
        Some((_, Reply::OpenDiscovery(c))) if c.is_empty()
    ));
}

#[test]
fn a_result_for_an_operation_the_machine_no_longer_expects_is_ignored() {
    let mut h = Harness::new(params(10));
    h.input(Input::Start);
    let stray = ReqId(9_999);
    for input in [
        Input::SubscribeDone {
            req: stray,
            outcome: Outcome::Ok { reached: 1 },
        },
        Input::PublishDone {
            req: stray,
            outcome: Outcome::Ok { reached: 1 },
        },
        Input::FetchDone {
            req: stray,
            outcome: Ok(Vec::new()),
        },
        Input::SocketBound {
            socket: SocketId(9_999),
            local: "0.0.0.0:40000".parse().unwrap(),
        },
        Input::Resolved {
            req: stray,
            addrs: vec![STUN_SERVER_ADDR.parse().unwrap()],
        },
        Input::Datagram {
            socket: SocketId(9_999),
            src: STUN_SERVER_ADDR.parse().unwrap(),
            bytes: vec![0; 20],
        },
    ] {
        let actions = h.input(input);
        assert!(actions.is_empty(), "a stray result caused {actions:?}");
    }
}

#[test]
fn a_refetch_with_a_newer_valid_advert_refreshes_and_resets_the_streak_before_replying() {
    let mut h = Harness::new(params(10));
    let cached = h.unix_secs() - 30;
    insert(
        &mut h,
        &advert_by(NODE_B_SECRET, cached, &body("8.8.8.8:443")),
    );
    let newer = advert_by(NODE_B_SECRET, cached + 10, &body("8.8.8.9:443"));
    let (actions, reply, reset) = refetched_after_failures(&mut h, NODE_B_SECRET, vec![newer]);
    let (_, outcome) = refetch_outcome(actions, reply);
    assert_eq!(outcome, NostrRefetchOutcome::Refreshed);
    assert_eq!(reset, vec![npub(NODE_B_SECRET)], "the streak is reset");
    assert_eq!(
        inspect(&mut h, &npub(NODE_B_SECRET)).created_at,
        Some(cached + 10)
    );
}
