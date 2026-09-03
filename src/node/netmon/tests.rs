//! Poller tests.
//!
//! The debounce, coalescing and no-net-difference paths are driven through a
//! scripted sampler on tokio's paused clock, so none of them needs a real
//! interface to flap. The two live-sampling tests assert only what is true of
//! any host, including a CI container with a single interface.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Virtual-time budget for the "nothing should arrive" assertions. On the
/// paused clock the runtime auto-advances whenever every task is idle, so this
/// covers several poll intervals without costing real wall time.
const QUIET_WINDOW: Duration = Duration::from_secs(30);

/// Await one change, failing rather than hanging if the poller never sends.
async fn expect_change(rx: &mut NetChangeRx) -> NetChange {
    tokio::time::timeout(QUIET_WINDOW, rx.recv())
        .await
        .expect("the poller must report within the quiet window")
        .expect("the channel must stay open")
}

/// Assert nothing arrives for a generous stretch of virtual time.
async fn expect_quiet(rx: &mut NetChangeRx, why: &str) {
    assert!(
        tokio::time::timeout(QUIET_WINDOW, rx.recv()).await.is_err(),
        "{}",
        why
    );
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// A timer-only wake source at the config's poll period — the portable
/// backend's behaviour, and the baseline the netlink tests compare against.
fn timer_wake(poll_secs: u64) -> WakeSource {
    WakeSource::timer_only(Duration::from_secs(poll_secs))
}

fn cfg(poll_secs: u64, debounce_ms: u64) -> NetmonConfig {
    NetmonConfig {
        enabled: true,
        poll_interval_secs: poll_secs,
        debounce_ms,
    }
}

/// A sampler that walks a script, holding on the last entry forever.
fn scripted(samples: Vec<NetFingerprint>) -> (impl Fn() -> NetFingerprint, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let sampler = move || {
        let i = counter.fetch_add(1, Ordering::SeqCst);
        samples[i.min(samples.len() - 1)].clone()
    };
    (sampler, calls)
}

#[tokio::test(start_paused = true)]
async fn steady_attachment_reports_nothing() {
    let steady = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let (sampler, _) = scripted(vec![steady]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    expect_quiet(&mut rx, "an unchanging fingerprint must produce no events").await;
}

#[tokio::test(start_paused = true)]
async fn a_default_route_move_is_reported() {
    // The WLAN → 5G shape: the interface set changes and the preferred source
    // address moves with it.
    let wlan = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let cell = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(change.generation, 1);
    assert!(change.summary.v4_source_moved);
    assert_eq!(change.summary.v4_source, Some(v4(10, 40, 0, 7)));
    assert_eq!(change.summary.added, vec![v4(10, 40, 0, 7)]);
    assert_eq!(change.summary.removed, vec![v4(192, 168, 1, 10)]);
}

#[tokio::test(start_paused = true)]
async fn a_handover_burst_coalesces_into_one_event() {
    // A handover is not atomic: the old address goes, then briefly nothing has
    // a route, then the new address arrives. Reporting each step would have the
    // handler probing every peer three times against a picture still in
    // motion. The debounce must ride the burst out and report once, against the
    // settled state.
    let wlan = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let gone = NetFingerprint::for_test(None, &[]);
    let cell = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    let (sampler, _) = scripted(vec![wlan, gone, cell]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 250), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.generation, 1,
        "the burst must report once, not per step"
    );
    assert_eq!(
        change.summary.v4_source,
        Some(v4(10, 40, 0, 7)),
        "the reported state must be the settled one, not the mid-handover one"
    );
    expect_quiet(&mut rx, "no second event for the same handover").await;
}

#[tokio::test(start_paused = true)]
async fn a_flap_that_settles_back_reports_nothing() {
    // An address that leaves and returns within the debounce window is not a
    // medium change. Reporting it would have every peer probed for nothing,
    // which on a host with churning routes is exactly the reconnect storm this
    // is meant to avoid.
    let steady = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let gone = NetFingerprint::for_test(None, &[]);
    let (sampler, _) = scripted(vec![steady.clone(), gone, steady]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 250), sampler, timer_wake(1)));

    expect_quiet(
        &mut rx,
        "a fingerprint that settles back where it started is not a change",
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn an_unread_change_coalesces_rather_than_queues() {
    // The handler's reaction is "re-evaluate every peer and every backoff",
    // which subsumes any number of changes. A second change arriving before the
    // first is drained must therefore drop, not queue: the node must never work
    // through a backlog of stale network states.
    let a = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let b = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    let c = NetFingerprint::for_test(Some(v4(172, 16, 3, 2)), &[v4(172, 16, 3, 2)]);
    let (sampler, _) = scripted(vec![a, b, c]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    // Stay idle long enough for the poller to see both changes while nothing
    // is draining, so the second meets a full channel.
    tokio::time::sleep(Duration::from_secs(10)).await;

    assert!(rx.try_recv().is_ok(), "the first change is delivered");
    assert!(
        rx.try_recv().is_err(),
        "the second must have coalesced into the undrained first, not queued behind it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_closed_receiver_ends_the_poller() {
    let a = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[]);
    let b = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[]);
    let (sampler, _) = scripted(vec![a, b]);
    let (tx, rx) = mpsc::channel(1);
    drop(rx);

    let handle = tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    tokio::time::timeout(QUIET_WINDOW, handle)
        .await
        .expect("the poller must exit once nothing is listening")
        .expect("and exit cleanly, not by panic");
}

#[test]
fn sampling_the_live_host_is_self_consistent() {
    // Two samples taken back to back on an idle host describe the same
    // attachment. This is the property the whole detector rests on: if plain
    // sampling were noisy, every poll would look like a medium change.
    let first = NetFingerprint::sample();
    let second = NetFingerprint::sample();
    assert_eq!(
        first, second,
        "consecutive samples of an unchanged host must agree"
    );
}

#[test]
fn live_interface_addresses_exclude_loopback() {
    // Loopback is present on every host and never changes, so including it
    // would only add noise. Unix enumerates; elsewhere the set is empty by
    // design and the assertion holds vacuously.
    let sample = NetFingerprint::sample();
    assert!(
        !sample.local_addrs.iter().any(|ip| ip.is_loopback()),
        "loopback must not contribute to the fingerprint: {:?}",
        sample.local_addrs
    );
}

#[test]
fn summary_of_an_empty_diff_is_legible() {
    let same = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    assert_eq!(same.diff(&same).to_string(), "no visible difference");
}

#[test]
fn summary_names_the_new_source_address() {
    let wlan = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let cell = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    let rendered = wlan.diff(&cell).to_string();
    assert!(rendered.contains("v4 source -> 10.40.0.7"), "{}", rendered);
    assert!(rendered.contains("+1 addr"), "{}", rendered);
    assert!(rendered.contains("-1 addr"), "{}", rendered);
}

// === Wake source ===

/// The point of an event-driven backend: a change is acted on when the kernel
/// says so, not when the next poll happens to come round. The poll period here
/// is an hour, so only the ping can be what woke the detector.
#[tokio::test(start_paused = true)]
async fn an_event_ping_wakes_the_detector_before_the_timer_would() {
    let wlan = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let cell = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);
    let (pings, ping_rx) = mpsc::channel(1);

    let wake = WakeSource::events(ping_rx, Duration::from_secs(3600));
    tokio::spawn(run_detector(tx, cfg(3600, 0), sampler, wake));

    pings.send(()).await.expect("the backend can ping");

    let change = expect_change(&mut rx).await;
    assert_eq!(change.summary.v4_source, Some(v4(10, 40, 0, 7)));
}

/// A netlink socket drops messages under memory pressure, and a backend can go
/// quiet without going away. The backstop timer must still get the node there,
/// so an event-driven backend is never worse than the poller it replaced.
#[tokio::test(start_paused = true)]
async fn the_backstop_still_fires_when_the_backend_says_nothing() {
    let wlan = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let cell = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);
    // Held, never sent on: the backend is alive but has missed the event.
    let (_pings, ping_rx) = mpsc::channel(1);

    let wake = WakeSource::events(ping_rx, Duration::from_secs(1));
    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, wake));

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.summary.v4_source,
        Some(v4(10, 40, 0, 7)),
        "the backstop must reach the change the backend missed"
    );
}

/// A backend that dies — socket error, sandbox revocation — must degrade the
/// node to polling, not stop detection. Spinning on the closed channel would be
/// worse still.
#[tokio::test(start_paused = true)]
async fn a_dead_backend_falls_back_to_the_timer() {
    let wlan = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let cell = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);
    let (pings, ping_rx) = mpsc::channel(1);

    let wake = WakeSource::events(ping_rx, Duration::from_secs(1));
    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, wake));

    // The backend gives up before the medium moves.
    drop(pings);

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.summary.v4_source,
        Some(v4(10, 40, 0, 7)),
        "detection must survive the backend it was using"
    );
}

/// A wake source with no backend waits out its period rather than taking the
/// free first tick a fresh `Interval` hands out — otherwise the opening sample
/// is a duplicate of the one taken microseconds earlier.
#[tokio::test(start_paused = true)]
async fn the_first_wait_is_a_real_wait() {
    let mut wake = WakeSource::timer_only(Duration::from_secs(60));
    let start = tokio::time::Instant::now();

    wake.wait().await;

    assert!(
        start.elapsed() >= Duration::from_secs(60),
        "the first tick must not come free"
    );
}

// === Kernel event source ===

/// The watcher this detector builds opens on a normal Linux host.
///
/// Distinct from the equivalent check in `transport::watcher`: that one pins
/// the *link* mask, this one pins the wider mask netmon actually asks for. A
/// group constant that was wrong only in the added bits would pass there and
/// fail here. A sandbox that refuses the subscription is a legitimate outcome
/// — it is why the fallback exists — so that case reports rather than fails.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_egress_path_watcher_starts_or_cleanly_declines() {
    use crate::transport::watcher::{LinkWatcher, groups};

    let watcher = LinkWatcher::with_groups(groups::EGRESS_PATH);
    if !watcher.is_event_driven() {
        eprintln!("kernel events unavailable in this environment; fallback path applies");
    }
}

/// A route change — with no link change alongside it — reaches the watcher.
///
/// This is the test that justifies the wider group mask, and the only one
/// that can fail if the mask is narrowed back. `RTMGRP_LINK` alone sees
/// nothing here: the interface does not appear, disappear or change state,
/// and yet the host's egress path has moved, which is exactly the event this
/// detector exists to catch. Every other test in this file drives the shared
/// decision logic through an injected channel and would pass against a
/// subscription that never fired for a route at all.
///
/// Ignored because it needs `CAP_NET_ADMIN` in a private network namespace —
/// it edits a routing table, which must not touch the developer's real
/// network. Run it with:
///
/// ```text
/// unshare -rn cargo test --lib netmon -- --ignored --nocapture
/// ```
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a private netns; run under `unshare -rn`"]
async fn a_route_change_alone_reaches_the_watcher() {
    use crate::transport::watcher::{LinkWatcher, groups};
    use futures::TryStreamExt;
    use std::net::Ipv4Addr;

    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);

    // `lo` is down in a fresh namespace and a route needs a live interface,
    // so bring it up first — before the watcher exists, so that this link
    // change cannot be the thing the assertion below observes.
    let index = handle
        .link()
        .get()
        .match_name("lo".to_string())
        .execute()
        .try_next()
        .await
        .expect("link query")
        .expect("lo exists")
        .header
        .index;
    handle
        .link()
        .change(rtnetlink::LinkUnspec::new_with_index(index).up().build())
        .execute()
        .await
        .expect("bringing lo up needs CAP_NET_ADMIN in this namespace");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let watcher = LinkWatcher::with_groups(groups::EGRESS_PATH);
    assert!(
        watcher.is_event_driven(),
        "this test cannot say anything without a live subscription"
    );

    // A route to TEST-NET-1 out of `lo`: no interface changes state, so the
    // link group stays silent and only the route group can carry this.
    handle
        .route()
        .add(
            rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::new(192, 0, 2, 0), 24)
                .output_interface(index)
                .build(),
        )
        .execute()
        .await
        .expect("adding a route needs CAP_NET_ADMIN in this namespace");

    tokio::time::timeout(Duration::from_secs(5), watcher.changed())
        .await
        .expect("a route change must reach the watcher well inside 5s");
}

/// Reactions are paced. Dropping every peer's connected socket and heartbeating
/// each of them is not free, so an interface that flaps cleanly — settling
/// between transitions, which defeats the debounce — must not drive that
/// several times a second across the whole peer set.
#[tokio::test(start_paused = true)]
async fn reports_are_spaced_out_under_clean_flapping() {
    let a = NetFingerprint::for_test(Some(v4(192, 168, 1, 10)), &[v4(192, 168, 1, 10)]);
    let b = NetFingerprint::for_test(Some(v4(10, 40, 0, 7)), &[v4(10, 40, 0, 7)]);
    // Alternates every sample: each poll sees a settled but different picture.
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let sampler = move || {
        let i = counter.fetch_add(1, Ordering::SeqCst);
        if i.is_multiple_of(2) {
            a.clone()
        } else {
            b.clone()
        }
    };
    let (tx, mut rx) = mpsc::channel(1);

    // Poll far faster than the pacing floor, so only the floor can space these.
    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    let first = expect_change(&mut rx).await;
    let started = tokio::time::Instant::now();
    let second = expect_change(&mut rx).await;

    assert_eq!(first.generation, 1);
    assert_eq!(second.generation, 2);
    assert!(
        started.elapsed() >= MIN_CHANGE_INTERVAL,
        "consecutive reports must be at least {:?} apart, got {:?}",
        MIN_CHANGE_INTERVAL,
        started.elapsed()
    );
}
