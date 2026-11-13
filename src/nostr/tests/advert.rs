use super::*;
use crate::nostr::types::OverlayTransportKind;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn ep(addr: &str) -> OverlayEndpointAdvert {
    OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: addr.to_string(),
    }
}

fn advert(endpoints: Vec<OverlayEndpointAdvert>) -> OverlayAdvert {
    OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints,
        signal_relays: None,
        stun_servers: None,
    }
}

fn cached(author: &str, created_at: u64, valid_until_ms: u64) -> CachedOverlayAdvert {
    CachedOverlayAdvert {
        author_npub: author.to_string(),
        advert: advert(vec![ep("1.2.3.4:9000")]),
        created_at,
        valid_until_ms,
    }
}

fn machine() -> AdvertMachine {
    // npub=self, advertise=true, max-age huge, cap=3
    AdvertMachine::new("npub1self".to_string(), true, 10_000_000, 3)
}

#[test]
fn observe_advert_replaces_only_when_not_older() {
    let m = machine();
    let first = m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9000")]), 100, 5000, 0);
    assert_eq!(first, AdvertAdmission::Admitted);
    // Older created_at -> not replaced.
    let older = m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9001")]), 50, 5000, 0);
    assert_eq!(older, AdvertAdmission::Stale);
    assert_eq!(m.cached_created_at("npub1peer"), Some(100));
    // Newer created_at -> replaced.
    let newer = m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9002")]), 200, 5000, 0);
    assert_eq!(newer, AdvertAdmission::Updated);
    assert_eq!(m.cached_created_at("npub1peer"), Some(200));
}

#[test]
fn observe_advert_caches_our_own_advert_like_any_other() {
    let m = machine();
    // Our own advert is cached like any other; whether to log it as a peer
    // is the caller's decision.
    let own = m.observe_advert("npub1self", advert(vec![ep("1.2.3.4:9000")]), 100, 5000, 0);
    assert_eq!(own, AdvertAdmission::Admitted);
    assert_eq!(m.cached_created_at("npub1self"), Some(100));
}

#[test]
fn prune_drops_expired_and_reports_no_eviction_under_cap() {
    let m = machine();
    m.insert_fetched("npub1a", cached("npub1a", 1, 1000), 0);
    m.insert_fetched("npub1b", cached("npub1b", 1, 3000), 0);
    // now=2000 -> npub1a expired, npub1b retained, under cap.
    assert_eq!(
        m.prune(2000),
        PruneReport {
            expired: 1,
            evicted: 0,
            retained: 1
        }
    );
    assert_eq!(m.cached_created_at("npub1a"), None);
    assert!(m.cached_created_at("npub1b").is_some());
}

#[test]
fn prune_size_cap_evicts_the_most_recently_admitted_unprotected_entry() {
    let m = machine(); // cap = 3
    // The cache can only go above its cap through protection, so four
    // entries are admitted as protected and then lose it.
    m.set_protected(set(&["npub1a", "npub1b", "npub1c", "npub1d"]));
    m.insert_fetched("npub1a", cached("npub1a", 1, 1000), 0);
    m.insert_fetched("npub1b", cached("npub1b", 1, 2000), 0);
    m.insert_fetched("npub1c", cached("npub1c", 1, 3000), 0);
    m.insert_fetched("npub1d", cached("npub1d", 1, 4000), 0);
    m.set_protected(HashSet::new());
    let report = m.prune(500);
    assert_eq!(report.evicted, 1);
    assert_eq!(report.retained, 3);
    // The entry admitted last goes, whatever its horizon.
    assert_eq!(m.cached_created_at("npub1d"), None);
    assert!(m.cached_created_at("npub1a").is_some());
}

#[test]
fn open_discovery_candidates_filters_self_and_expired() {
    let m = machine();
    m.insert_fetched("npub1self", cached("npub1self", 1, 9000), 0);
    m.insert_fetched("npub1peer", cached("npub1peer", 1, 9000), 0);
    m.insert_fetched("npub1stale", cached("npub1stale", 1, 1000), 0);
    let out = m.open_discovery_candidates(10, 2000, &HashSet::new(), &mut StdRng::seed_from_u64(1));
    assert_eq!(out.len(), 1, "only the valid non-self peer survives");
    assert_eq!(out[0].0, "npub1peer");
}

#[test]
fn open_discovery_candidates_respects_max() {
    let m = machine();
    for i in 0..5 {
        let npub = format!("npub1p{i}");
        m.insert_fetched(&npub, cached(&npub, 1, 9000), 0);
    }
    assert_eq!(
        m.open_discovery_candidates(2, 1000, &HashSet::new(), &mut StdRng::seed_from_u64(1))
            .len(),
        2
    );
}

#[test]
fn set_local_advert_detects_change() {
    let m = machine();
    let a = advert(vec![ep("1.2.3.4:9000")]);
    assert!(m.set_local_advert(Some(a.clone())), "first set is a change");
    assert!(
        !m.set_local_advert(Some(a.clone())),
        "identical set is no change"
    );
    assert!(m.set_local_advert(None), "clearing is a change");
}

#[test]
fn plan_publish_strips_relays_for_non_nat_advert() {
    let m = machine();
    let mut a = advert(vec![ep("1.2.3.4:9000")]);
    a.signal_relays = Some(vec!["wss://relay".to_string()]);
    a.stun_servers = Some(vec!["stun:host:3478".to_string()]);
    m.set_local_advert(Some(a));
    match m.plan_publish().expect("plan ok") {
        PublishPlan::Publish(out) => {
            assert!(
                out.signal_relays.is_none(),
                "non-nat advert strips signalRelays"
            );
            assert!(
                out.stun_servers.is_none(),
                "non-nat advert strips stunServers"
            );
            assert_eq!(out.identifier, ADVERT_IDENTIFIER);
            assert_eq!(out.version, ADVERT_VERSION);
        }
        other => panic!("expected Publish, got {other:?}"),
    }
}

#[test]
fn plan_publish_keeps_relays_for_nat_advert() {
    let m = machine();
    let mut a = advert(vec![ep("nat")]);
    a.signal_relays = Some(vec!["wss://relay".to_string()]);
    a.stun_servers = Some(vec!["stun:host:3478".to_string()]);
    m.set_local_advert(Some(a));
    match m.plan_publish().expect("plan ok") {
        PublishPlan::Publish(out) => {
            assert!(out.has_udp_nat_endpoint());
            assert_eq!(out.signal_relays.as_deref().map(<[_]>::len), Some(1));
            assert_eq!(out.stun_servers.as_deref().map(<[_]>::len), Some(1));
        }
        other => panic!("expected Publish, got {other:?}"),
    }
}

#[test]
fn plan_publish_nat_without_relays_errors() {
    let m = machine();
    m.set_local_advert(Some(advert(vec![ep("nat")])));
    assert!(matches!(
        m.plan_publish(),
        Err(BootstrapError::InvalidAdvert(_))
    ));
}

#[test]
fn plan_publish_nothing_when_no_local_advert() {
    let m = machine();
    assert!(matches!(m.plan_publish(), Ok(PublishPlan::Nothing)));
}

#[test]
fn plan_publish_nothing_when_advertising_disabled_even_with_a_local_advert() {
    let m = AdvertMachine::new("npub1self".to_string(), false, 10_000_000, 3);
    m.set_local_advert(Some(advert(vec![ep("1.2.3.4:9000")])));
    assert!(matches!(m.plan_publish(), Ok(PublishPlan::Nothing)));
}

// --- admission under a full cache ------------------------------------

const T0: u64 = 1_000_000;

fn capped(cap: usize) -> AdvertMachine {
    AdvertMachine::new("npub1self".to_string(), true, 10_000_000, cap)
}

fn observe(m: &AdvertMachine, npub: &str, valid_until_ms: u64, now_ms: u64) {
    let _ = m.observe_advert(
        npub,
        advert(vec![ep("1.2.3.4:9000")]),
        1,
        valid_until_ms,
        now_ms,
    );
}

fn fetched(m: &AdvertMachine, npub: &str, valid_until_ms: u64, now_ms: u64) {
    let _ = m.insert_fetched(npub, cached(npub, 1, valid_until_ms), now_ms);
}

fn held(m: &AdvertMachine, npubs: &[&str]) -> usize {
    npubs
        .iter()
        .filter(|npub| m.cached_created_at(npub).is_some())
        .count()
}

fn set(npubs: &[&str]) -> HashSet<String> {
    npubs.iter().map(|npub| npub.to_string()).collect()
}

#[test]
fn an_advert_flood_under_new_keys_cannot_evict_an_honest_cached_advert() {
    let m = capped(4);
    observe(&m, "npub1honest", T0 + 3_600_000, T0);
    let flood = ["npub1x1", "npub1x2", "npub1x3", "npub1x4"];
    for npub in flood {
        observe(&m, npub, T0 + 7_200_000, T0);
    }
    let _ = m.prune(T0 + 1);

    assert!(m.cached_created_at("npub1honest").is_some());
    let mut all = flood.to_vec();
    all.push("npub1honest");
    assert_eq!(held(&m, &all), 4);
}

#[test]
fn a_fetched_advert_from_a_new_author_is_refused_when_the_cache_is_full() {
    let m = capped(4);
    let honest = ["npub1h0", "npub1h1", "npub1h2", "npub1h3"];
    for (i, npub) in honest.iter().enumerate() {
        observe(&m, npub, T0 + 3_600_000 + i as u64, T0);
    }
    fetched(&m, "npub1attacker", T0 + 7_200_000, T0);
    let _ = m.prune(T0 + 1);

    assert_eq!(held(&m, &honest), 4, "every honest entry stays cached");
    assert!(m.cached_created_at("npub1attacker").is_none());

    // Control: with room, the same author is cached, so the refusal above
    // is the full cache and not the npub.
    let roomy = capped(4);
    fetched(&roomy, "npub1attacker", T0 + 7_200_000, T0);
    assert!(roomy.cached_created_at("npub1attacker").is_some());
}

#[test]
fn a_configured_author_arriving_at_a_cache_full_of_strangers_is_admitted() {
    let m = capped(4);
    let strangers = ["npub1u1", "npub1u2", "npub1u3", "npub1u4"];
    for (i, npub) in strangers.iter().enumerate() {
        observe(&m, npub, T0 + 7_200_000 + i as u64, T0);
    }
    m.set_protected(set(&["npub1configured"]));
    observe(&m, "npub1configured", T0 + 3_600_000, T0);
    let _ = m.prune(T0 + 1);

    assert!(m.cached_created_at("npub1configured").is_some());
    let mut all = strangers.to_vec();
    all.push("npub1configured");
    assert_eq!(held(&m, &all), 4);
    assert!(
        m.cached_created_at("npub1u4").is_none(),
        "the most recently admitted stranger makes room"
    );
    assert!(m.cached_created_at("npub1u1").is_some());
}

#[test]
fn an_over_cap_prune_keeps_a_protected_entry_with_the_soonest_horizon() {
    let m = capped(3);
    m.set_protected(set(&["npub1p", "npub1a", "npub1b", "npub1c"]));
    fetched(&m, "npub1a", 2000, 0);
    fetched(&m, "npub1b", 3000, 0);
    fetched(&m, "npub1c", 4000, 0);
    fetched(&m, "npub1p", 1000, 0);
    m.set_protected(set(&["npub1p"]));
    let _ = m.prune(500);

    assert!(m.cached_created_at("npub1p").is_some());
    assert!(m.cached_created_at("npub1c").is_none());
    assert!(m.cached_created_at("npub1a").is_some());
    assert!(m.cached_created_at("npub1b").is_some());
    assert_eq!(held(&m, &["npub1p", "npub1a", "npub1b", "npub1c"]), 3);
}

#[test]
fn a_key_cycled_through_a_link_cannot_evict_honest_cached_adverts() {
    let m = capped(4);
    observe(&m, "npub1h1", T0 + 3_600_000, T0);
    observe(&m, "npub1h2", T0 + 3_600_001, T0);
    observe(&m, "npub1a1", T0 + 7_200_000, T0);
    observe(&m, "npub1a2", T0 + 7_200_001, T0);
    let mut all: Vec<String> = ["npub1h1", "npub1h2", "npub1a1", "npub1a2"]
        .iter()
        .map(|npub| npub.to_string())
        .collect();
    for i in 1..=10u64 {
        let key = format!("npub1k{i}");
        m.set_protected(set(&[key.as_str()]));
        observe(&m, &key, T0 + 7_200_100 + i, T0);
        m.set_protected(HashSet::new());
        let _ = m.prune(T0 + 1);
        all.push(key);
    }

    assert!(m.cached_created_at("npub1h1").is_some());
    assert!(m.cached_created_at("npub1h2").is_some());
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    assert_eq!(held(&m, &all), 4);
}

/// Keys linked at the same time against a cache of honest entries only
/// each displace the newest honest entry, and those slots stay with the
/// keys after the links drop; later cycling displaces only those keys.
/// So an attacker's lasting reach is the number of links it holds at
/// once, which `max_peers` bounds.
#[test]
fn concurrently_linked_keys_displace_one_honest_advert_each_and_no_more() {
    let m = capped(4);
    for (i, npub) in ["npub1h1", "npub1h2", "npub1h3", "npub1h4"]
        .iter()
        .enumerate()
    {
        observe(&m, npub, T0 + 3_600_000 + i as u64, T0);
    }
    m.set_protected(set(&["npub1k1", "npub1k2"]));
    observe(&m, "npub1k1", T0 + 7_200_000, T0);
    observe(&m, "npub1k2", T0 + 7_200_001, T0);
    m.set_protected(HashSet::new());
    let _ = m.prune(T0 + 1);
    assert!(m.cached_created_at("npub1h3").is_none());
    assert!(m.cached_created_at("npub1h4").is_none());

    for i in 3..=12u64 {
        let key = format!("npub1k{i}");
        m.set_protected(set(&[key.as_str()]));
        observe(&m, &key, T0 + 7_200_100 + i, T0);
        m.set_protected(HashSet::new());
        let _ = m.prune(T0 + 1);
    }
    assert!(m.cached_created_at("npub1h1").is_some());
    assert!(m.cached_created_at("npub1h2").is_some());
    assert_eq!(held(&m, &["npub1h1", "npub1h2"]), 2);
}

#[test]
fn linked_authors_take_no_open_discovery_slot_and_configured_ones_are_listed_beyond_it() {
    let m = capped(256);
    let linked: Vec<String> = (0..70).map(|i| format!("npub1linked{i}")).collect();
    let configured: Vec<String> = (0..10).map(|i| format!("npub1configured{i}")).collect();
    let open: Vec<String> = (0..20).map(|i| format!("npub1open{i}")).collect();
    m.set_protected(linked.iter().chain(configured.iter()).cloned().collect());
    for npub in linked.iter().chain(configured.iter()).chain(open.iter()) {
        observe(&m, npub, T0 + 3_600_000, T0);
    }
    let skip: HashSet<String> = linked.iter().cloned().collect();

    let out = m.open_discovery_candidates(64, T0, &skip, &mut StdRng::seed_from_u64(1));
    let got: HashSet<String> = out.into_iter().map(|(npub, _, _)| npub).collect();
    let want: HashSet<String> = configured.iter().chain(open.iter()).cloned().collect();
    assert_eq!(got, want);
}

#[test]
fn every_honest_advert_cached_before_a_flood_reaches_the_open_discovery_window() {
    let m = capped(256);
    let honest: Vec<String> = (0..8).map(|i| format!("npub1honest{i}")).collect();
    let flood: Vec<String> = (0..248).map(|i| format!("npub1flood{i}")).collect();
    for npub in honest.iter().chain(flood.iter()) {
        observe(&m, npub, T0 + 3_600_000, T0);
    }
    for npub in &flood {
        observe(&m, npub, T0 + 3_600_000, T0);
    }

    let mut rng = StdRng::seed_from_u64(7);
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..200 {
        for (npub, _, _) in m.open_discovery_candidates(64, T0, &HashSet::new(), &mut rng) {
            seen.insert(npub);
        }
        for npub in &flood {
            observe(&m, npub, T0 + 3_600_000, T0);
        }
    }
    let missed: Vec<&String> = honest.iter().filter(|npub| !seen.contains(*npub)).collect();
    assert!(
        missed.is_empty(),
        "never offered to open discovery: {missed:?}"
    );
}

#[test]
fn a_new_author_is_admitted_while_the_cache_has_room_and_its_republish_replaces_it() {
    let m = capped(4);
    let first = m.observe_advert(
        "npub1new",
        advert(vec![ep("1.2.3.4:9000")]),
        10,
        T0 + 3_600_000,
        T0,
    );
    assert_eq!(first, AdvertAdmission::Admitted);
    let again = m.observe_advert(
        "npub1new",
        advert(vec![ep("1.2.3.4:9001")]),
        20,
        T0 + 3_600_000,
        T0,
    );
    assert_eq!(again, AdvertAdmission::Updated);
    assert_eq!(m.cached_created_at("npub1new"), Some(20));
}

#[test]
fn a_linked_author_keeps_its_slot_through_a_flood_and_loses_protection_when_unlinked() {
    let m = capped(3);
    observe(&m, "npub1s1", 2000, 0);
    observe(&m, "npub1s2", 3000, 0);
    m.set_protected(set(&["npub1linked"]));
    observe(&m, "npub1linked", 1000, 0);
    for npub in ["npub1s3", "npub1s4"] {
        let refused = m.observe_advert(npub, advert(vec![ep("1.2.3.4:9000")]), 1, 9000, 0);
        assert!(matches!(refused, AdvertAdmission::Refused { .. }));
    }
    let _ = m.prune(500);
    assert!(m.cached_created_at("npub1linked").is_some());

    // The link drops and a configured peer appears in the same push.
    m.set_protected(set(&["npub1configured"]));
    observe(&m, "npub1configured", 5000, 0);
    assert!(
        m.cached_created_at("npub1linked").is_none(),
        "the formerly linked author is now the newest unprotected entry"
    );
    assert!(m.cached_created_at("npub1configured").is_some());
    assert!(m.cached_created_at("npub1s1").is_some());
    assert!(m.cached_created_at("npub1s2").is_some());
}

#[test]
fn a_cache_full_of_expired_adverts_admits_a_new_unconfigured_author() {
    let m = capped(4);
    for (i, npub) in ["npub1e1", "npub1e2", "npub1e3", "npub1e4"]
        .iter()
        .enumerate()
    {
        observe(&m, npub, 1000 + i as u64, 0);
    }
    let now = 10_000;
    let admitted = m.observe_advert(
        "npub1new",
        advert(vec![ep("1.2.3.4:9000")]),
        1,
        now + 3_600_000,
        now,
    );
    assert_eq!(admitted, AdvertAdmission::Admitted);
    assert!(m.cached_created_at("npub1new").is_some());
}

#[test]
fn the_cache_full_warning_fires_once_and_releases_after_a_minute_below_the_cap() {
    let m = capped(2);
    observe(&m, "npub1a", T0 + 3_600_000, T0);
    observe(&m, "npub1b", T0 + 3_600_000, T0);
    let offer = |npub: &str| {
        m.observe_advert(
            npub,
            advert(vec![ep("1.2.3.4:9000")]),
            1,
            T0 + 3_600_000,
            T0,
        )
    };
    assert_eq!(
        offer("npub1x"),
        AdvertAdmission::Refused {
            first_at_bound: true
        }
    );
    assert_eq!(
        offer("npub1y"),
        AdvertAdmission::Refused {
            first_at_bound: false
        }
    );

    let t = Instant::now();
    assert_eq!(m.bound_tick(t), None, "still at the cap");
    m.remove("npub1a");
    assert_eq!(m.bound_tick(t), None);
    assert_eq!(m.bound_tick(t + Duration::from_millis(59_999)), None);
    assert_eq!(m.bound_tick(t + Duration::from_millis(60_000)), Some(2));
    assert_eq!(
        m.bound_tick(t + Duration::from_millis(120_000)),
        None,
        "released once"
    );
}
