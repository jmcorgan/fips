//! Adverts: a peer's advert cached from the stream, this node's advert
//! assembled from its transports, published one at a time and republished
//! on schedule, the public address it waits for, and the cache's cap.

use std::net::SocketAddr;

use nostr::event::Kind;

use super::super::super::adverts::assemble::AdvertTransportSnapshot;
use super::super::super::types::ADVERT_KIND;
use super::super::log::IngestPath;
use super::*;

/// A wildcard public UDP transport under `key` on `port`.
fn wildcard(key: u32, port: u16) -> AdvertTransportSnapshot {
    AdvertTransportSnapshot::Udp {
        advertise: true,
        is_public: true,
        external_addr: None,
        local_addr: Some(SocketAddr::from(([0, 0, 0, 0], port))),
        transport_key: key,
    }
}

/// A public UDP transport bound to `addr`.
fn bound(addr: &str) -> AdvertTransportSnapshot {
    AdvertTransportSnapshot::Udp {
        advertise: true,
        is_public: true,
        external_addr: None,
        local_addr: Some(addr.parse().unwrap()),
        transport_key: 1,
    }
}

fn transports(snapshot: Vec<AdvertTransportSnapshot>) -> Input {
    Input::Transports {
        snapshot,
        reply: None,
    }
}

/// Whether `actions` answer `reply`.
fn replied(actions: &[Action], reply: ReplyId) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, Action::Reply { reply: r, .. } if *r == reply))
}

/// The advert body `event` carries.
fn advert_in(event: &Event) -> OverlayAdvert {
    serde_json::from_str(&event.content).unwrap()
}

/// The UDP endpoints of the advert `event` carries.
fn udp_endpoints(event: &Event) -> Vec<String> {
    advert_in(event)
        .endpoints
        .into_iter()
        .map(|e| e.addr)
        .collect()
}

#[test]
fn a_forged_advert_on_the_stream_is_not_cached_and_is_counted() {
    let mut h = Harness::new(params(10));
    let now = h.unix_secs();
    let mut totals = Vec::new();
    let mut warned = Vec::new();
    for i in 0..5 {
        let forged = forged_by(
            NODE_B_SECRET,
            now - 10 + i,
            &body("8.8.8.8:443"),
            &body("8.8.4.4:443"),
        );
        let lines = logs(&h.input(delivered(forged.clone())));
        assert!(
            lines.contains(&Log::EventForged {
                kind: ADVERT_KIND,
                author: npub(NODE_B_SECRET),
                event: forged.id,
                total: i + 1,
            }),
            "{lines:?}"
        );
        let (each, warnings) = forged_totals(&lines);
        totals.extend(each);
        warned.extend(warnings);
    }
    assert_eq!(totals, vec![1, 2, 3, 4, 5]);
    assert_eq!(warned, vec![1, 2, 4], "a warning at each power of two");
    assert_eq!(
        inspect(&mut h, &npub(NODE_B_SECRET)).created_at,
        None,
        "nothing forged is cached"
    );

    // Control: a genuine advert delivered afterwards is cached.
    let genuine = advert_by(NODE_B_SECRET, now, &body("8.8.8.8:443"));
    let lines = logs(&h.input(delivered(genuine)));
    assert_eq!(forged_totals(&lines), (Vec::new(), Vec::new()));
    assert_eq!(inspect(&mut h, &npub(NODE_B_SECRET)).created_at, Some(now));
}

#[test]
fn a_relay_delivered_advert_is_cached_and_logged_unless_it_is_our_own() {
    let mut h = Harness::new(params(10));
    let theirs = advert_by(NODE_B_SECRET, h.unix_secs(), &body("8.8.8.8:443"));
    let log = logs(&h.input(delivered(theirs.clone())));
    assert_eq!(
        log,
        vec![Log::PeerCached {
            peer: npub(NODE_B_SECRET),
            endpoints: body("8.8.8.8:443").endpoints,
            event: theirs.id,
        }]
    );
    assert_eq!(
        inspect(&mut h, &npub(NODE_B_SECRET)).created_at,
        Some(h.unix_secs())
    );

    let ours = advert_by(NODE_A_SECRET, h.unix_secs(), &body("8.8.4.4:443"));
    assert_eq!(
        logs(&h.input(delivered(ours))),
        vec![],
        "our own advert is not logged"
    );
    assert_eq!(
        inspect(&mut h, &npub(NODE_A_SECRET)).created_at,
        Some(h.unix_secs()),
        "but it is cached like any other"
    );

    let invalid = advert_by(NODE_C_SECRET, h.unix_secs(), &body("10.0.0.1:443"));
    assert_eq!(logs(&h.input(delivered(invalid))), vec![]);
    assert_eq!(inspect(&mut h, &npub(NODE_C_SECRET)).created_at, None);
}

#[test]
fn an_advert_publish_requested_while_one_is_in_flight_runs_once_after_it() {
    let mut h = Harness::new(params(10));
    let first = publishes(&h.input(transports(vec![bound("9.9.9.9:2121")])));
    assert_eq!(first.len(), 1);
    // Two more requests while it is in flight: a changed advert, and the
    // republish deadline.
    assert!(publishes(&h.input(transports(vec![bound("9.9.9.10:2121")]))).is_empty());
    h.input(Input::Start);
    assert!(publishes(&h.advance(100_000)).is_empty());
    let second = publishes(&h.input(Input::PublishDone {
        req: first[0].0,
        outcome: Outcome::Ok { reached: 1 },
    }));
    assert_eq!(second.len(), 1, "one publish after the one in flight");
    assert_eq!(udp_endpoints(&second[0].2), vec!["9.9.9.10:2121"]);
    let third = h.input(Input::PublishDone {
        req: second[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });
    assert!(publishes(&third).is_empty(), "and no more");
}

#[test]
fn the_advert_is_republished_every_refresh_interval_after_start_and_not_at_start() {
    let mut h = Harness::new(params(10));
    let first = publishes(&h.input(transports(vec![bound("9.9.9.9:2121")])));
    h.input(Input::PublishDone {
        req: first[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });
    h.advance(5_000);
    let start = h.input(Input::Start);
    assert!(publishes(&start).is_empty(), "no publish at start itself");
    let (req, _) = subscribe_of(&start[0]).unwrap();
    let inbox = publishes(&h.input(Input::SubscribeDone {
        req,
        outcome: Outcome::Ok { reached: 1 },
    }));
    let after_inbox = publishes(&h.input(Input::PublishDone {
        req: inbox[0].0,
        outcome: Outcome::Ok { reached: 1 },
    }));
    h.input(Input::PublishDone {
        req: after_inbox[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });
    for due in [105_000, 205_000] {
        assert!(publishes(&h.advance(due - 1 - h.ms)).is_empty());
        let published = publishes(&h.advance(1));
        assert_eq!(published.len(), 1, "a republish at {due} ms");
        assert_eq!(published[0].2.kind, Kind::Custom(ADVERT_KIND));
        h.input(Input::PublishDone {
            req: published[0].0,
            outcome: Outcome::Ok { reached: 1 },
        });
    }
}

#[test]
fn a_failed_or_timed_out_advert_publish_is_logged_and_changes_nothing() {
    let mut h = Harness::new(params(10));
    let first = publishes(&h.input(transports(vec![bound("9.9.9.9:2121")])));
    let log = logs(&h.input(Input::PublishDone {
        req: first[0].0,
        outcome: Outcome::Err("boom".to_string()),
    }));
    assert_eq!(
        log,
        vec![Log::AdvertFailed {
            error: "nostr error: boom".to_string()
        }]
    );
    let second = publishes(&h.input(transports(vec![bound("9.9.9.10:2121")])));
    assert_eq!(second.len(), 1, "the next request publishes");
    let log = logs(&h.input(Input::PublishDone {
        req: second[0].0,
        outcome: Outcome::TimedOut,
    }));
    assert_eq!(log, vec![Log::AdvertTimedOut { timeout_ms: 10_000 }]);
    let third = publishes(&h.input(transports(vec![bound("9.9.9.9:2121")])));
    assert_eq!(third.len(), 1);
}

#[test]
fn a_wildcard_public_udp_transport_holds_the_publish_until_its_address_is_learned() {
    let mut h = Harness::new(params(10));
    let actions = h.input(transports(vec![wildcard(7, 2121)]));
    assert!(publishes(&actions).is_empty(), "the publish waits");
    let observed = binds(&actions);
    assert_eq!(observed.len(), 1);
    let actions = complete(&mut h, observed[0], Some([8, 8, 4, 4].into()));
    let published = publishes(&actions);
    assert_eq!(published.len(), 1);
    assert_eq!(udp_endpoints(&published[0].2), vec!["8.8.4.4:2121"]);
}

#[test]
fn a_learned_address_is_reused_until_its_ttl_and_a_failure_for_a_minute() {
    // Success: kept for max(advert_refresh_secs, 60) = 100 s.
    let mut h = Harness::new(params(10));
    let observed = binds(&h.input(transports(vec![wildcard(7, 2121)])));
    complete(&mut h, observed[0], Some([8, 8, 4, 4].into()));
    h.advance(99_999);
    assert!(binds(&h.input(transports(vec![wildcard(7, 2121)]))).is_empty());
    let mut aged = h.advance(1);
    aged.extend(h.input(transports(vec![wildcard(7, 2121)])));
    assert_eq!(
        binds(&aged).len(),
        1,
        "observed again once the success has aged out"
    );

    // Failure: kept for 60 s.
    let mut h = Harness::new(params(10));
    let observed = binds(&h.input(transports(vec![wildcard(7, 2121)])));
    let log = logs(&complete(&mut h, observed[0], None));
    assert!(
        log.contains(&Log::UdpUnlearned {
            transport_id: 7,
            bind_addr: "0.0.0.0:2121".parse().unwrap(),
        }),
        "{log:?}"
    );
    h.advance(59_999);
    assert!(binds(&h.input(transports(vec![wildcard(7, 2121)]))).is_empty());
    let mut aged = h.advance(1);
    aged.extend(h.input(transports(vec![wildcard(7, 2121)])));
    assert_eq!(binds(&aged).len(), 1);
}

#[test]
fn the_cache_full_warning_is_released_a_minute_after_the_cache_drops_below_its_cap() {
    let mut h = Harness::new(params(2));
    h.input(delivered(advert_by(
        NODE_B_SECRET,
        h.unix_secs(),
        &body("8.8.8.8:443"),
    )));
    h.input(delivered(advert_by(
        NODE_A_SECRET,
        h.unix_secs(),
        &body("8.8.8.9:443"),
    )));
    let refused = logs(&h.input(delivered(advert_by(
        NODE_C_SECRET,
        h.unix_secs(),
        &body("8.8.8.10:443"),
    ))));
    assert_eq!(
        refused,
        vec![
            Log::CacheFull { bound: 2 },
            Log::NotCached {
                peer: npub(NODE_C_SECRET),
                path: IngestPath::Stream,
            },
        ]
    );

    // An eviction brings the cache below its cap.
    let reply = h.reply();
    let fetch = fetches(&h.input(Input::Refetch {
        key: key(NODE_B_SECRET),
        reply,
    }));
    h.input(Input::FetchDone {
        req: fetch[0].0,
        outcome: Ok(Vec::new()),
    });
    let below_at = h.ms;
    assert_eq!(h.m.poll_timeout(), Some(TestInstant(below_at + 60_000)));
    assert!(logs(&h.advance(59_999)).is_empty());
    assert_eq!(logs(&h.advance(1)), vec![Log::CacheBelowCap { refused: 1 }]);
}

/// Fill a cache of two with B's and A's adverts, created now, and have it
/// refuse C's: the cache-full warning is latched.
fn fill_and_refuse(h: &mut Harness) -> Vec<Log> {
    for (secret, addr) in [
        (NODE_B_SECRET, "8.8.8.8:443"),
        (NODE_A_SECRET, "8.8.8.9:443"),
    ] {
        let event = advert_by(secret, h.unix_secs(), &body(addr));
        h.input(delivered(event));
    }
    let event = advert_by(NODE_C_SECRET, h.unix_secs(), &body("8.8.8.10:443"));
    logs(&h.input(delivered(event)))
}

#[test]
fn the_cache_full_warning_is_released_a_minute_after_its_entries_expire_with_no_input() {
    let mut h = Harness::new(params(2));
    assert!(fill_and_refuse(&mut h).contains(&Log::CacheFull { bound: 2 }));

    // Both entries go at their horizon (3600 s) plus one refresh interval
    // of grace (100 s). No input arrives; the release still comes a minute
    // after that.
    assert!(logs(&h.advance(3_700_000 + 59_999)).is_empty());
    assert_eq!(logs(&h.advance(1)), vec![Log::CacheBelowCap { refused: 1 }]);
}

#[test]
fn a_second_flood_after_the_entries_expire_with_no_input_is_warned_again() {
    let mut h = Harness::new(params(2));
    assert!(fill_and_refuse(&mut h).contains(&Log::CacheFull { bound: 2 }));
    h.advance(3_700_000 + 62_000);
    assert!(fill_and_refuse(&mut h).contains(&Log::CacheFull { bound: 2 }));
}

#[test]
fn a_start_up_assembly_request_is_answered_only_once_its_address_is_learned() {
    let mut h = Harness::new(params(10));
    let waiting = h.reply();
    let actions = h.input(Input::Transports {
        snapshot: vec![wildcard(7, 2121)],
        reply: Some(waiting),
    });
    assert!(!replied(&actions, waiting));
    let observed = binds(&actions);
    // A newer snapshot before the assembly takes the request over.
    assert!(!replied(
        &h.input(transports(vec![wildcard(7, 2121)])),
        waiting
    ));
    let actions = complete(&mut h, observed[0], Some([8, 8, 4, 4].into()));
    let published = publishes(&actions);
    assert_eq!(published.len(), 1);
    let (at, reply) = reply_to(actions, waiting).expect("answered after the assembly");
    assert!(matches!(reply, Reply::Assembled));
    assert!(at > 0, "after the publish request");

    // A snapshot that needs no observation is answered in the same step.
    let at_once = h.reply();
    let actions = h.input(Input::Transports {
        snapshot: vec![bound("9.9.9.9:2121")],
        reply: Some(at_once),
    });
    assert!(matches!(
        reply_to(actions, at_once),
        Some((_, Reply::Assembled))
    ));
}

#[test]
fn a_shrunk_protected_set_trims_the_cache_to_its_cap_at_once() {
    let mut h = Harness::new(params(1));
    h.input(protect(&[npub(NODE_B_SECRET), npub(NODE_C_SECRET)]));
    h.input(delivered(advert_by(
        NODE_B_SECRET,
        h.unix_secs(),
        &body("8.8.8.8:443"),
    )));
    h.input(delivered(advert_by(
        NODE_C_SECRET,
        h.unix_secs(),
        &body("8.8.8.9:443"),
    )));
    assert!(inspect(&mut h, &npub(NODE_B_SECRET)).created_at.is_some());
    assert!(inspect(&mut h, &npub(NODE_C_SECRET)).created_at.is_some());

    let log = logs(&h.input(protect(&[npub(NODE_B_SECRET)])));
    assert_eq!(
        log,
        vec![Log::CacheEvicted {
            evicted: 1,
            retained: 1,
            cap: 1,
        }]
    );
    assert!(inspect(&mut h, &npub(NODE_B_SECRET)).created_at.is_some());
    assert!(inspect(&mut h, &npub(NODE_C_SECRET)).created_at.is_none());
}

#[test]
fn the_wildcard_public_udp_transports_are_observed_one_after_another_in_snapshot_order() {
    let mut h = Harness::new(params(10));
    let snapshot = vec![wildcard(9, 3000), bound("9.9.9.9:2121"), wildcard(7, 2121)];
    let first = binds(&h.input(transports(snapshot)));
    assert_eq!(first.len(), 1, "one observation at a time");
    // The first observation learns 8.8.4.4, the second 8.8.8.4; the advert
    // pairs each with its transport's port, so it shows which went first.
    let actions = complete(&mut h, first[0], Some([8, 8, 4, 4].into()));
    assert!(publishes(&actions).is_empty());
    let second = binds(&actions);
    assert_eq!(second.len(), 1, "the next once the first has ended");
    let actions = complete(&mut h, second[0], Some([8, 8, 8, 4].into()));
    let published = publishes(&actions);
    assert_eq!(published.len(), 1);
    assert_eq!(
        udp_endpoints(&published[0].2),
        vec!["8.8.4.4:3000", "9.9.9.9:2121", "8.8.8.4:2121"]
    );
}

#[test]
fn the_public_address_is_learned_through_the_stun_client_on_an_ephemeral_socket() {
    let mut h = Harness::new(params(10));
    let socket = binds(&h.input(transports(vec![wildcard(7, 2121)])))[0];
    let actions = h.input(Input::SocketBound {
        socket,
        local: "0.0.0.0:40000".parse().unwrap(),
    });
    let Some(Action::Resolve { req, host, port }) = actions.first() else {
        panic!("the server is looked up: {actions:?}");
    };
    assert_eq!((host.as_str(), *port), ("stun.example", 3478));
    let actions = h.input(Input::Resolved {
        req: *req,
        addrs: vec![STUN_SERVER_ADDR.parse().unwrap()],
    });
    let Some(Action::Send {
        socket: on,
        dst,
        bytes,
    }) = actions.first()
    else {
        panic!("a binding request: {actions:?}");
    };
    assert_eq!((*on, *dst), (socket, STUN_SERVER_ADDR.parse().unwrap()));
    let mapped = std::net::SocketAddrV4::new([8, 8, 4, 4].into(), 50_000);
    let actions = h.input(Input::Datagram {
        socket,
        src: *dst,
        bytes: binding_success(&bytes[8..20], mapped),
    });
    assert_eq!(
        logs(&actions),
        vec![
            Log::StunSucceeded {
                server: "stun:stun.example:3478".to_string(),
                mapped: mapped.into(),
            },
            Log::PublicAddrObserved {
                stun: Some("stun:stun.example:3478".to_string()),
                reflexive: Some(mapped.into()),
            },
        ]
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::Close { socket: s } if *s == socket)),
        "the socket is closed"
    );
    let published = publishes(&actions);
    assert_eq!(udp_endpoints(&published[0].2), vec!["8.8.4.4:2121"]);
}

#[test]
fn a_failed_bind_leaves_the_address_unknown_and_logs_it() {
    let mut h = Harness::new(params(10));
    let socket = binds(&h.input(transports(vec![wildcard(7, 2121)])))[0];
    let actions = h.input(Input::BindFailed {
        socket,
        stage: BindStage::Bind,
        error: "Address in use".to_string(),
    });
    assert_eq!(
        logs(&actions),
        vec![
            Log::PublicAddrBindFailed {
                error: "Address in use".to_string(),
            },
            Log::UdpUnlearned {
                transport_id: 7,
                bind_addr: "0.0.0.0:2121".parse().unwrap(),
            },
        ]
    );
    assert!(
        !actions.iter().any(|a| matches!(a, Action::Close { .. })),
        "nothing was bound, so nothing is closed"
    );
    assert!(
        binds(&h.input(transports(vec![wildcard(7, 2121)]))).is_empty(),
        "the failure is kept, as any failure is"
    );
}

#[test]
fn with_no_stun_servers_the_address_is_unknown_without_binding_a_socket() {
    let mut h = Harness::new(Params {
        stun_servers: Vec::new(),
        ..params(10)
    });
    let actions = h.input(transports(vec![wildcard(7, 2121), wildcard(9, 3000)]));
    assert!(binds(&actions).is_empty(), "no socket is bound");
    assert_eq!(
        logs(&actions),
        vec![
            Log::UdpUnlearned {
                transport_id: 7,
                bind_addr: "0.0.0.0:2121".parse().unwrap(),
            },
            Log::UdpUnlearned {
                transport_id: 9,
                bind_addr: "0.0.0.0:3000".parse().unwrap(),
            },
        ]
    );
    h.advance(60_000);
    assert!(binds(&h.input(transports(vec![wildcard(7, 2121)]))).is_empty());
}

#[test]
fn a_publish_that_reached_no_relay_is_logged_and_otherwise_treated_as_sent() {
    let mut h = Harness::new(params(10));
    let advert = publishes(&h.input(transports(vec![bound("9.9.9.9:2121")])));
    let log = logs(&h.input(Input::PublishDone {
        req: advert[0].0,
        outcome: Outcome::Ok { reached: 0 },
    }));
    assert_eq!(
        log[0],
        Log::PublishReachedNone {
            kind: 37195,
            event: advert[0].2.id,
            relays: 2,
        }
    );
    assert!(
        matches!(log[1], Log::AdvertPublished { .. }),
        "otherwise logged as published: {log:?}"
    );

    // The inbox relay list too, and start-up goes on as after a send.
    let start = h.input(Input::Start);
    let (req, _) = subscribe_of(&start[0]).unwrap();
    let inbox = publishes(&h.input(Input::SubscribeDone {
        req,
        outcome: Outcome::Ok { reached: 2 },
    }));
    let actions = h.input(Input::PublishDone {
        req: inbox[0].0,
        outcome: Outcome::Ok { reached: 0 },
    });
    assert_eq!(
        logs(&actions),
        vec![Log::PublishReachedNone {
            kind: 10050,
            event: inbox[0].2.id,
            relays: 2,
        }]
    );
    assert_eq!(publishes(&actions).len(), 1, "the advert publish follows");
    assert_eq!(h.m.poll_timeout(), Some(TestInstant(100_000)), "subscribed");
}

#[test]
fn a_learned_address_is_observed_again_when_its_ttl_ends_without_a_new_snapshot() {
    let mut h = Harness::new(params(10));
    let socket = binds(&h.input(transports(vec![wildcard(7, 2121)])))[0];
    let first = publishes(&complete(&mut h, socket, Some([8, 8, 4, 4].into())));
    h.input(Input::PublishDone {
        req: first[0].0,
        outcome: Outcome::Ok { reached: 1 },
    });
    assert!(binds(&h.advance(99_999)).is_empty());
    let again = h.advance(1);
    assert_eq!(
        binds(&again).len(),
        1,
        "observed again at the end of its 100 s, with no new snapshot"
    );
    let actions = complete(&mut h, binds(&again)[0], Some([8, 8, 8, 4].into()));
    assert_eq!(
        udp_endpoints(&publishes(&actions)[0].2),
        vec!["8.8.8.4:2121"],
        "and the advert assembled again"
    );
}

#[test]
fn the_wildcard_notes_are_logged_once_per_assembly() {
    let mut h = Harness::new(params(10));
    let tcp = AdvertTransportSnapshot::Tcp {
        advertise: true,
        external_addr: None,
        local_addr: Some("0.0.0.0:443".parse().unwrap()),
    };
    let note = Log::TcpWildcard {
        bind_addr: "0.0.0.0:443".parse().unwrap(),
    };
    assert_eq!(
        logs(&h.input(transports(vec![tcp.clone()]))),
        vec![note.clone()]
    );
    assert!(
        logs(&h.advance(600_000)).is_empty(),
        "not again while the snapshot stands"
    );
    assert_eq!(logs(&h.input(transports(vec![tcp]))), vec![note]);
}
