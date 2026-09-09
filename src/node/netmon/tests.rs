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

/// A distinct peer address. Only identity matters here, so the byte pattern is
/// arbitrary as long as two peers differ.
fn peer(n: u8) -> NodeAddr {
    NodeAddr::from_bytes([n; 16])
}

/// A fingerprint in which `peers` are all reached from `source`. The common
/// shape: every peering rides one medium, so they move together.
fn all_from(peers: &[NodeAddr], source: Option<IpAddr>) -> NetFingerprint {
    let sources: Vec<_> = peers.iter().map(|p| (*p, source)).collect();
    NetFingerprint::for_test(&sources)
}

/// The peers a change names, in the order its summary carries them.
fn moved_peers(change: &NetChange) -> Vec<NodeAddr> {
    change.summary.moved.iter().map(|m| m.peer).collect()
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
    let steady = all_from(&[peer(1), peer(2)], Some(v4(192, 168, 1, 10)));
    let (sampler, _) = scripted(vec![steady]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    expect_quiet(&mut rx, "an unchanging fingerprint must produce no events").await;
}

#[tokio::test(start_paused = true)]
async fn a_medium_change_under_a_peer_is_reported() {
    // The WLAN → 5G shape: the local address the kernel would reach the peer
    // from moves, which is the whole signal.
    let wlan = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let cell = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(change.generation, 1);
    assert_eq!(change.summary.probed, 1);
    assert_eq!(
        change.summary.moved,
        vec![PeerSourceMove {
            peer: peer(1),
            before: Some(v4(192, 168, 1, 10)),
            after: Some(v4(10, 40, 0, 7)),
        }]
    );
}

#[tokio::test(start_paused = true)]
async fn a_peer_losing_its_route_is_reported() {
    // The route to this peer is gone, so it is stranded on whatever socket it
    // holds — the single most important case to report, and the one a
    // "compare the addresses we can see" fingerprint would miss because the
    // absence of a route is not an address.
    let up = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let down = all_from(&[peer(1)], None);
    let (sampler, _) = scripted(vec![up, down]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(change.summary.moved.len(), 1);
    assert_eq!(change.summary.moved[0].after, None);
}

#[tokio::test(start_paused = true)]
async fn a_peer_joining_is_absorbed_rather_than_reported() {
    // Peer churn is ordinary node behaviour and says nothing about the medium.
    // The reaction drops the named peers' connected sockets and heartbeats
    // them, so firing it every time a peer authenticates would make a busy node
    // continuously tear down a send fast path that was never stale.
    let one = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let two = all_from(&[peer(1), peer(2)], Some(v4(192, 168, 1, 10)));
    let (sampler, _) = scripted(vec![one, two]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    expect_quiet(&mut rx, "a peer appearing is not a medium change").await;
}

#[tokio::test(start_paused = true)]
async fn a_peer_leaving_is_absorbed_rather_than_reported() {
    let two = all_from(&[peer(1), peer(2)], Some(v4(192, 168, 1, 10)));
    let one = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let (sampler, _) = scripted(vec![two, one]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    expect_quiet(&mut rx, "a peer being reaped is not a medium change").await;
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_joins_is_compared_on_the_sample_after() {
    // The other half of absorbing churn: `last` has to take the new peer on
    // board, or a peer authenticated after startup would sit outside every
    // future comparison and its medium changes would never be seen.
    let source = Some(v4(192, 168, 1, 10));
    let one = all_from(&[peer(1)], source);
    let two = all_from(&[peer(1), peer(2)], source);
    let moved = NetFingerprint::for_test(&[(peer(1), source), (peer(2), Some(v4(10, 40, 0, 7)))]);
    let (sampler, _) = scripted(vec![one, two, moved]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.summary.moved,
        vec![PeerSourceMove {
            peer: peer(2),
            before: source,
            after: Some(v4(10, 40, 0, 7)),
        }],
        "the peer that joined one sample ago must be under comparison now"
    );
}

#[tokio::test(start_paused = true)]
async fn a_move_in_the_window_after_a_peer_joins_is_still_reported() {
    // The hole the intersection rule opens on its own, and the reason a peer
    // seen for the first time is judged against its socket rather than skipped.
    //
    // `last` gains a peer only at the first wake after it appears, so a medium
    // change inside that window is the detector's *first* sight of that peer:
    // there is no earlier probe answer to compare against, the intersection is
    // empty, and adopting the sample silently swallows the very event being
    // adopted. Meanwhile the peer's connected socket is still pinned to the
    // path the host has just left, and nothing else will repair it — the
    // outage runs to `link_dead_timeout_secs`.
    //
    // The window is up to one poll interval after every peer that
    // authenticates, and a medium change is itself what wakes the detector, so
    // the two coincide readily. Its socket is bound on the old path while the
    // probe already answers with the new one, and that disagreement is the
    // report.
    let empty = NetFingerprint::for_test(&[]);
    let joined_after_the_move = NetFingerprint::for_test_bound(&[(
        peer(1),
        Some(v4(10, 40, 0, 7)),
        Some(v4(192, 168, 1, 10)),
    )]);
    let (sampler, _) = scripted(vec![empty, joined_after_the_move]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.summary.moved,
        vec![PeerSourceMove {
            peer: peer(1),
            before: Some(v4(192, 168, 1, 10)),
            after: Some(v4(10, 40, 0, 7)),
        }],
        "a peer whose socket is bound off the current path must be reported on \
         first sight, not adopted"
    );
}

#[tokio::test(start_paused = true)]
async fn a_peer_joining_onto_a_settled_path_is_still_not_a_change() {
    // The other side of that rule: judging a first-seen peer against its socket
    // must not turn ordinary peer churn into a medium change. A peer that
    // authenticates while nothing is moving has its socket bound exactly where
    // the probe says its traffic goes, so there is nothing to report.
    let empty = NetFingerprint::for_test(&[]);
    let joined = NetFingerprint::for_test_bound(&[(
        peer(1),
        Some(v4(192, 168, 1, 10)),
        Some(v4(192, 168, 1, 10)),
    )]);
    let (sampler, _) = scripted(vec![empty, joined]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    expect_quiet(
        &mut rx,
        "a peer joining onto a path that has not moved is not a medium change",
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn churn_during_a_handover_does_not_mask_the_handover() {
    // Both at once: a peer leaves while the medium moves under the peer that
    // stays. The intersection rule must ignore the departure and still report
    // the move.
    let before = all_from(&[peer(1), peer(2)], Some(v4(192, 168, 1, 10)));
    let after = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
    let (sampler, _) = scripted(vec![before, after]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(change.summary.moved.len(), 1);
    assert_eq!(change.summary.moved[0].peer, peer(1));
}

#[tokio::test(start_paused = true)]
async fn a_handover_burst_coalesces_into_one_event() {
    // A handover is not atomic: the route goes, then briefly there is none, then
    // the new one arrives. Reporting each step would have the handler probing
    // every peer three times against a picture still in motion. The debounce
    // must ride the burst out and report once, against the settled state.
    let wlan = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let gone = all_from(&[peer(1)], None);
    let cell = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
    let (sampler, _) = scripted(vec![wlan, gone, cell]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 250), sampler, timer_wake(1)));

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.generation, 1,
        "the burst must report once, not per step"
    );
    assert_eq!(
        change.summary.moved[0].after,
        Some(v4(10, 40, 0, 7)),
        "the reported state must be the settled one, not the mid-handover one"
    );
    expect_quiet(&mut rx, "no second event for the same handover").await;
}

#[tokio::test(start_paused = true)]
async fn a_flap_that_settles_back_reports_nothing() {
    // A route that leaves and returns within the debounce window is not a
    // medium change. Reporting it would have every peer probed for nothing,
    // which on a host with churning routes is exactly the reconnect storm this
    // is meant to avoid.
    let steady = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let gone = all_from(&[peer(1)], None);
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
    // Two changes over disjoint peer sets: the first moves peer(1) alone, the
    // second moves peer(2) alone. A second change arriving before the first is
    // drained must not queue — the node must never work through a backlog of
    // stale network states — and it must not be silently lost either, because
    // the reaction is scoped to the peers a change names and nothing else
    // would ever repair peer(2).
    let start = NetFingerprint::for_test(&[
        (peer(1), Some(v4(192, 168, 1, 10))),
        (peer(2), Some(v4(192, 168, 1, 11))),
    ]);
    let first = NetFingerprint::for_test(&[
        (peer(1), Some(v4(10, 40, 0, 7))),
        (peer(2), Some(v4(192, 168, 1, 11))),
    ]);
    let second = NetFingerprint::for_test(&[
        (peer(1), Some(v4(10, 40, 0, 7))),
        (peer(2), Some(v4(10, 40, 0, 8))),
    ]);
    let (sampler, _) = scripted(vec![start, first, second]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    // Stay idle long enough for the poller to see both changes while nothing
    // is draining, so the second meets a full channel.
    tokio::time::sleep(Duration::from_secs(10)).await;

    let queued = rx.try_recv().expect("the first change is delivered");
    assert_eq!(
        moved_peers(&queued),
        vec![peer(1)],
        "the queued change is the first one, which named only peer(1)"
    );
    assert!(
        rx.try_recv().is_err(),
        "the second must have coalesced into the undrained first, not queued behind it"
    );

    // Draining frees the slot. The dropped change named peer(2) and nobody
    // acted on it, so the detector's baseline must not have advanced past it:
    // the next sample has to re-derive that move and deliver it.
    let recovered = tokio::time::timeout(QUIET_WINDOW, rx.recv())
        .await
        .expect("a dropped change must be re-derived once the slot frees, not lost with its peers")
        .expect("the channel must stay open");
    assert!(
        moved_peers(&recovered).contains(&peer(2)),
        "a dropped change must not lose the peers it named; got {:?}",
        recovered.summary.moved
    );
}

#[tokio::test(start_paused = true)]
async fn a_closed_receiver_ends_the_poller() {
    let a = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let b = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
    let (sampler, _) = scripted(vec![a, b]);
    let (tx, rx) = mpsc::channel(1);
    drop(rx);

    let handle = tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    tokio::time::timeout(QUIET_WINDOW, handle)
        .await
        .expect("the poller must exit once nothing is listening")
        .expect("and exit cleanly, not by panic");
}

#[tokio::test(start_paused = true)]
async fn a_node_with_no_peers_reports_nothing() {
    // Nothing is bound to the old path, so there is nothing to repair. The
    // fingerprint is empty and stays empty however the host's interfaces move,
    // which is the deliberate consequence of probing peers rather than the
    // host.
    let (sampler, _) = scripted(vec![NetFingerprint::for_test(&[])]);
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, timer_wake(1)));

    expect_quiet(&mut rx, "a node holding no peers has nothing to report").await;
}

// === Live sampling ===

/// An off-link destination standing in for a peer. RFC 5737 TEST-NET-1, so the
/// route lookup is a route lookup and nothing is reachable there even by
/// accident. Nothing is ever sent to it.
const OFF_LINK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);

/// A probe target for `peer`, with no connected socket behind it.
fn target(p: NodeAddr, dest: SocketAddr) -> ProbeTarget {
    ProbeTarget {
        peer: p,
        dest,
        bound: None,
        bind: None,
    }
}

#[test]
fn sampling_the_live_host_is_self_consistent() {
    // Two samples taken back to back on an idle host describe the same
    // attachment. This is the property the whole detector rests on: if plain
    // sampling were noisy, every poll would look like a medium change.
    let targets = [target(peer(1), OFF_LINK)];
    let first = NetFingerprint::sample(&targets);
    let second = NetFingerprint::sample(&targets);
    assert_eq!(
        first, second,
        "consecutive samples of an unchanged host must agree"
    );
    assert!(
        first.moved(&second).is_empty(),
        "and must show no peer as having moved"
    );
}

/// The live-probe tests above are all satisfied by a `preferred_source` that
/// returns `None` for everything: two all-`None` samples are self-consistent,
/// the recorded-keys test never inspects a value, and the loopback assertion
/// skips through its `if let`. This one pins that the probe actually answers.
///
/// Loopback is the destination because it is routable on any host that can run
/// this suite, including a container started with `--network none`, and the
/// source for it is loopback itself.
#[test]
fn a_probe_to_loopback_answers_with_loopback() {
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let sample = NetFingerprint::sample(&[target(peer(1), dest)]);
    assert_eq!(
        sample.sources.get(&peer(1)).map(|p| p.current),
        Some(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))),
        "the probe must return the kernel's source address, not None"
    );
}

#[test]
fn every_target_is_recorded_whether_or_not_it_has_a_route() {
    // A peer with no route must stay in the map as `None` rather than dropping
    // out of it. Dropping it would make "the route to this peer just vanished"
    // indistinguishable from "this peer was reaped", and the intersection rule
    // would then discard exactly the event the detector exists to catch. The
    // assertion holds on a CI container with no route at all.
    let targets = [target(peer(1), OFF_LINK), target(peer(2), OFF_LINK)];
    let sample = NetFingerprint::sample(&targets);
    assert_eq!(sample.sources.len(), 2);
    assert!(sample.sources.contains_key(&peer(1)));
    assert!(sample.sources.contains_key(&peer(2)));
}

#[test]
fn a_probe_never_yields_a_loopback_or_unspecified_source() {
    // Either of those would be the kernel declining to choose, not an answer,
    // and treating one as an address would make the fingerprint move whenever
    // the route lookup failed differently.
    let sample = NetFingerprint::sample(&[target(peer(1), OFF_LINK)]);
    if let Some(Some(ip)) = sample.sources.get(&peer(1)).map(|p| p.current) {
        assert!(!ip.is_loopback(), "loopback source for an off-link probe");
        assert!(
            !ip.is_unspecified(),
            "unspecified source reported as an answer"
        );
    }
}

// === Summary rendering ===

#[test]
fn summary_of_nothing_moving_is_legible() {
    let summary = NetChangeSummary {
        moved: Vec::new(),
        probed: 4,
    };
    assert_eq!(summary.to_string(), "no visible difference");
}

#[test]
fn summary_names_the_peer_and_its_new_source() {
    let wlan = all_from(&[peer(0xab)], Some(v4(192, 168, 1, 10)));
    let cell = all_from(&[peer(0xab)], Some(v4(10, 40, 0, 7)));
    let summary = NetChangeSummary {
        moved: wlan.moved(&cell),
        probed: 1,
    };
    let rendered = summary.to_string();
    assert!(rendered.contains("1/1 peers"), "{}", rendered);
    // Both ends, and the peer id in the same shape every other operator
    // surface prints, so a line found in `show_peers` matches here.
    assert!(
        rendered.contains("abababab... 192.168.1.10 -> 10.40.0.7"),
        "{}",
        rendered
    );
}

#[test]
fn summary_says_when_a_peer_lost_its_route() {
    let up = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let down = all_from(&[peer(1)], None);
    let summary = NetChangeSummary {
        moved: up.moved(&down),
        probed: 1,
    };
    assert!(summary.to_string().contains("no route"), "{}", summary);
}

#[test]
fn summary_truncates_a_whole_table_moving_at_once() {
    // The common case is every peer moving together, and a log line naming a
    // hundred of them is not a log line.
    let peers: Vec<NodeAddr> = (1..=10).map(peer).collect();
    let before = all_from(&peers, Some(v4(192, 168, 1, 10)));
    let after = all_from(&peers, Some(v4(10, 40, 0, 7)));
    let summary = NetChangeSummary {
        moved: before.moved(&after),
        probed: peers.len(),
    };
    let rendered = summary.to_string();
    assert!(rendered.contains("10/10 peers"), "{}", rendered);
    assert!(rendered.contains("+7 more"), "{}", rendered);
}

// === Wake source ===

/// The point of an event-driven backend: a change is acted on when the kernel
/// says so, not when the next poll happens to come round. The poll period here
/// is an hour, so only the ping can be what woke the detector.
#[tokio::test(start_paused = true)]
async fn an_event_ping_wakes_the_detector_before_the_timer_would() {
    let wlan = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let cell = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);
    let (pings, ping_rx) = mpsc::channel(1);

    let wake = WakeSource::events(ping_rx, Duration::from_secs(3600));
    tokio::spawn(run_detector(tx, cfg(3600, 0), sampler, wake));

    pings.send(()).await.expect("the backend can ping");

    let change = expect_change(&mut rx).await;
    assert_eq!(change.summary.moved[0].after, Some(v4(10, 40, 0, 7)));
}

/// A netlink socket drops messages under memory pressure, and a backend can go
/// quiet without going away. The backstop timer must still get the node there,
/// so an event-driven backend is never worse than the poller it replaced.
#[tokio::test(start_paused = true)]
async fn the_backstop_still_fires_when_the_backend_says_nothing() {
    let wlan = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let cell = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);
    // Held, never sent on: the backend is alive but has missed the event.
    let (_pings, ping_rx) = mpsc::channel(1);

    let wake = WakeSource::events(ping_rx, Duration::from_secs(1));
    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, wake));

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.summary.moved[0].after,
        Some(v4(10, 40, 0, 7)),
        "the backstop must reach the change the backend missed"
    );
}

/// A backend that dies — socket error, sandbox revocation — must degrade the
/// node to polling, not stop detection. Spinning on the closed channel would be
/// worse still.
#[tokio::test(start_paused = true)]
async fn a_dead_backend_falls_back_to_the_timer() {
    let wlan = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let cell = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
    let (sampler, _) = scripted(vec![wlan, cell]);
    let (tx, mut rx) = mpsc::channel(1);
    let (pings, ping_rx) = mpsc::channel(1);

    let wake = WakeSource::events(ping_rx, Duration::from_secs(1));
    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, wake));

    // The backend gives up before the medium moves.
    drop(pings);

    let change = expect_change(&mut rx).await;
    assert_eq!(
        change.summary.moved[0].after,
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

/// Reactions are paced. Dropping a moved peer's connected socket and
/// heartbeating it is not free, and an interface flapping cleanly is the worst
/// case for that, because a medium change moves the whole table at once. So an
/// interface settling between transitions, which defeats the debounce, must not
/// drive that several times a second across the whole peer set.
#[tokio::test(start_paused = true)]
async fn reports_are_spaced_out_under_clean_flapping() {
    let a = all_from(&[peer(1)], Some(v4(192, 168, 1, 10)));
    let b = all_from(&[peer(1)], Some(v4(10, 40, 0, 7)));
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
    // Not `timer_wake(1)`: a one-second poll against a one-second floor makes
    // the two indistinguishable, and deleting the pacing block would still
    // produce one-second spacing and still pass.
    let wake = WakeSource::timer_only(Duration::from_millis(100));
    tokio::spawn(run_detector(tx, cfg(1, 0), sampler, wake));

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

/// The claim this whole shape exists to make: an interface appearing that is
/// not the route to any peer does not move the fingerprint.
///
/// This is the case that made the host-wide address set unusable — a container
/// bridge, a VPN, a `veth` pair or a tunnel coming up moved it, and the node
/// answered by dropping every connected socket and heartbeating every peer, for
/// a `docker compose up`. Here a second interface arrives with an address and a
/// subnet of its own, carrying no route to the peer, and nothing is reported.
///
/// Structurally this cannot fail while the fingerprint holds only per-peer
/// probe results — there is no host-wide enumeration left in the module to go
/// wrong. The test is here so that a future signal added back into
/// `NetFingerprint::sample` has to answer to it.
///
/// Like the watcher test above, this needs `CAP_NET_ADMIN` in a namespace it
/// may reconfigure:
///
/// ```text
/// unshare -rn cargo test --lib netmon -- --ignored --nocapture
/// ```
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a private netns; run under `unshare -rn`"]
async fn an_interface_no_peer_is_reached_through_does_not_move_the_fingerprint() {
    use futures::TryStreamExt;
    use std::net::Ipv4Addr;

    // Its own destination, in RFC 5737 TEST-NET-2 rather than the TEST-NET-1
    // that [`OFF_LINK`] uses: `unshare -rn` gives the whole test binary one
    // namespace, so the routes the netlink test above installs are still there
    // and a shared prefix collides with EEXIST depending on the order they run.
    const NET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
    const CARRIER: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
    const BRIDGE: Ipv4Addr = Ipv4Addr::new(172, 30, 0, 1);
    const DEST: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 9);

    /// Bring up a dummy interface carrying `addr/24`, returning its index.
    async fn dummy_up(handle: &rtnetlink::Handle, name: &str, addr: Ipv4Addr) -> u32 {
        handle
            .link()
            .add(rtnetlink::LinkDummy::new(name).build())
            .execute()
            .await
            .expect("creating a dummy link needs CAP_NET_ADMIN in this namespace");
        let index = handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await
            .expect("link query")
            .expect("the link just created exists")
            .header
            .index;
        handle
            .address()
            .add(index, std::net::IpAddr::V4(addr), 24)
            .execute()
            .await
            .expect("adding an address");
        handle
            .link()
            .set(rtnetlink::LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .expect("bringing the link up");
        index
    }

    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);

    // The medium the peer is actually reached over: an interface plus the
    // default route out of it.
    let carrier = dummy_up(&handle, "mc-carrier", CARRIER).await;
    handle
        .route()
        .add(
            rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                .output_interface(carrier)
                .build(),
        )
        .execute()
        .await
        .expect("adding a default route");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let targets = [target(peer(1), DEST)];
    let before = NetFingerprint::sample(&targets);
    assert_eq!(
        before.sources.get(&peer(1)).map(|p| p.current),
        Some(Some(IpAddr::V4(CARRIER))),
        "the peer must be reached over the carrier before anything else appears, \
         or this test proves nothing about what happens next"
    );

    // The interloper: a bridge-shaped interface with its own subnet, exactly
    // what `docker compose up` leaves behind. It is up, it is not loopback, and
    // it carries an address — every property the old host-wide set keyed on —
    // but no peer is reached through it.
    dummy_up(&handle, "mc-bridge", BRIDGE).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let after = NetFingerprint::sample(&targets);
    assert_eq!(
        before.moved(&after),
        Vec::new(),
        "an interface carrying no route to any peer must not be a medium change"
    );

    // While two addresses exist here, measure the reason the probe carries a
    // bind constraint at all.
    //
    // `open_connected_fd` binds the transport's configured address verbatim
    // and only then connects, so under a non-wildcard `transports.udp.bind_addr`
    // the socket's source is that address whatever the routing table says. An
    // unconstrained probe answers with the kernel's choice instead. Where the
    // two differ, the first-sight rule would compare them and report a move on
    // every peer, permanently, with nothing having moved.
    //
    // The interloper's address is reachable-from but is not what the route to
    // DEST would pick, so it is exactly that disagreement, made concrete: the
    // unconstrained probe answers with the carrier, the constrained one with
    // what it was told to bind.
    let unconstrained = preferred_source(DEST, None);
    let constrained = preferred_source(DEST, Some(IpAddr::V4(BRIDGE)));
    assert_eq!(
        unconstrained,
        Some(IpAddr::V4(CARRIER)),
        "an unconstrained probe follows the route"
    );
    assert_eq!(
        constrained,
        Some(IpAddr::V4(BRIDGE)),
        "a constrained probe answers from the address it was told to bind, which \
         is what a non-wildcard bind_addr makes the send path do"
    );
    assert_ne!(
        unconstrained, constrained,
        "if these agreed the constraint would be untested, and the phantom-move \
         case it exists for could not arise"
    );

    // The other half, in the same namespace and against the same live sampler:
    // put a more specific route to the peer out of the interloper, and the
    // fingerprint must move with it. Two things ride on this. It stops the
    // assertion above passing because sampling had quietly stopped working,
    // which is the failure mode a negative assertion is worst at catching. And
    // it is the per-peer route case in its own right — the default route never
    // moves here, nothing about the host's attachment changes, and no
    // host-wide sample could represent this at all.
    let bridge = handle
        .link()
        .get()
        .match_name("mc-bridge".to_string())
        .execute()
        .try_next()
        .await
        .expect("link query")
        .expect("mc-bridge exists")
        .header
        .index;
    handle
        .route()
        .add(
            rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(NET, 24)
                .output_interface(bridge)
                .build(),
        )
        .execute()
        .await
        .expect("adding a more specific route to the peer");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let moved = after.moved(&NetFingerprint::sample(&targets));
    assert_eq!(
        moved,
        vec![PeerSourceMove {
            peer: peer(1),
            before: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1))),
            after: Some(IpAddr::V4(Ipv4Addr::new(172, 30, 0, 1))),
        }],
        "the route to the peer moving is exactly what must be reported"
    );
}

/// An interface going down and coming back up, which the docker suite does not
/// cover: it moves the default route with both interfaces held up throughout,
/// deliberately, so that it tests a medium change rather than a link failure.
/// This is the other shape — the interface carrying a peer is taken away and
/// given back.
///
/// Three transitions, and the third is the one worth having. Downing the
/// interface a peer is reached over must report; bringing it back must report;
/// downing an interface no peer is reached over must not. That last case is the
/// down-direction counterpart of the container test above, and it is the one a
/// link-state watcher gets wrong — the kernel emits exactly the same link event
/// for all three.
///
/// Routes here are specific to this test's own prefix rather than defaults, so
/// it shares the `unshare -rn` namespace with the tests above without fighting
/// them over the default route.
///
/// ```text
/// unshare -rn cargo test --lib netmon -- --ignored --nocapture
/// ```
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a private netns; run under `unshare -rn`"]
async fn an_interface_going_down_is_reported_only_when_a_peer_was_reached_over_it() {
    use futures::TryStreamExt;
    use std::net::Ipv4Addr;

    // RFC 5737 TEST-NET-3, so this test's routes cannot collide with either of
    // the two above in the shared namespace.
    const NET: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);
    const DEST: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 9);
    const PRIMARY: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
    const BACKUP: Ipv4Addr = Ipv4Addr::new(10, 78, 0, 1);
    const IDLE: Ipv4Addr = Ipv4Addr::new(10, 79, 0, 1);

    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);

    async fn index_of(handle: &rtnetlink::Handle, name: &str) -> u32 {
        handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await
            .expect("link query")
            .expect("the link exists")
            .header
            .index
    }

    async fn dummy_up(handle: &rtnetlink::Handle, name: &str, addr: Ipv4Addr) -> u32 {
        handle
            .link()
            .add(rtnetlink::LinkDummy::new(name).build())
            .execute()
            .await
            .expect("creating a dummy link needs CAP_NET_ADMIN in this namespace");
        let index = index_of(handle, name).await;
        handle
            .address()
            .add(index, std::net::IpAddr::V4(addr), 24)
            .execute()
            .await
            .expect("adding an address");
        handle
            .link()
            .set(rtnetlink::LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .expect("bringing the link up");
        index
    }

    async fn set_link(handle: &rtnetlink::Handle, index: u32, up: bool) {
        let msg = if up {
            rtnetlink::LinkUnspec::new_with_index(index).up().build()
        } else {
            rtnetlink::LinkUnspec::new_with_index(index).down().build()
        };
        handle
            .link()
            .set(msg)
            .execute()
            .await
            .expect("changing link state");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    async fn route_to_peer(handle: &rtnetlink::Handle, index: u32, metric: u32) {
        handle
            .route()
            .add(
                rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(NET, 24)
                    .output_interface(index)
                    .priority(metric)
                    .build(),
            )
            .execute()
            .await
            .expect("adding a route to the peer");
    }

    // Two paths to the peer, primary preferred, plus an interface carrying no
    // route to it at all.
    let primary = dummy_up(&handle, "mc-updn-a", PRIMARY).await;
    let backup = dummy_up(&handle, "mc-updn-b", BACKUP).await;
    let idle = dummy_up(&handle, "mc-updn-c", IDLE).await;
    route_to_peer(&handle, primary, 100).await;
    route_to_peer(&handle, backup, 200).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let targets = [target(peer(1), DEST)];
    let on_primary = NetFingerprint::sample(&targets);
    assert_eq!(
        on_primary.sources.get(&peer(1)).map(|p| p.current),
        Some(Some(IpAddr::V4(PRIMARY))),
        "the peer must start out on the primary, or nothing below means anything"
    );

    // 1. The interface the peer is reached over goes down. The route with it,
    //    so the kernel falls back to the higher-metric path.
    set_link(&handle, primary, false).await;
    let on_backup = NetFingerprint::sample(&targets);
    assert_eq!(
        on_primary.moved(&on_backup),
        vec![PeerSourceMove {
            peer: peer(1),
            before: Some(IpAddr::V4(PRIMARY)),
            after: Some(IpAddr::V4(BACKUP)),
        }],
        "losing the interface a peer was reached over is a medium change"
    );

    // 2. And back. Not symmetric with the above: this direction returns to an
    //    interface that has been holding a stale address throughout.
    //
    //    The route has to be re-added by hand, because the kernel deleted it
    //    when the link went down and does not restore it when the link returns
    //    — verified in a namespace, not assumed. On a real host that re-add is
    //    what the DHCP client or the network manager does on carrier-up, so
    //    re-adding it here is modelling the real sequence rather than working
    //    around it. The address, by contrast, does survive, which is exactly
    //    the trap the detector exists for: the interface is up and addressed
    //    again the instant the link returns, and only the route says whether
    //    anything is reached over it.
    set_link(&handle, primary, true).await;
    route_to_peer(&handle, primary, 100).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let back_on_primary = NetFingerprint::sample(&targets);
    assert_eq!(
        on_backup.moved(&back_on_primary),
        vec![PeerSourceMove {
            peer: peer(1),
            before: Some(IpAddr::V4(BACKUP)),
            after: Some(IpAddr::V4(PRIMARY)),
        }],
        "the interface returning and reclaiming the route is a medium change too"
    );

    // 3. An interface no peer is reached over goes down. Same kernel link
    //    event as case 1, and it must report nothing.
    set_link(&handle, idle, false).await;
    assert_eq!(
        back_on_primary.moved(&NetFingerprint::sample(&targets)),
        Vec::new(),
        "an interface no peer was reached over going down is not a medium change"
    );

    // 4. Every path this test installed goes away at once. Where the peer
    //    lands afterwards is deliberately not asserted: it depends on what
    //    else the host offers, and in this shared namespace it falls back to
    //    the default route another `--ignored` test installed. What must hold
    //    either way is that the peer moved off the primary and that the move
    //    is reported — a peer resolving to nothing at all is pinned by
    //    `every_target_is_recorded_whether_or_not_it_has_a_route`, which runs
    //    on a CI container with no route to fall back to.
    set_link(&handle, primary, false).await;
    set_link(&handle, backup, false).await;
    let stranded = NetFingerprint::sample(&targets);
    assert_ne!(
        stranded.sources.get(&peer(1)).map(|p| p.current),
        Some(Some(IpAddr::V4(PRIMARY))),
        "the peer cannot still be reached over an interface that is down"
    );
    assert_eq!(
        back_on_primary.moved(&stranded).len(),
        1,
        "losing every path this test installed is a medium change"
    );
}

/// The group mask the detector actually ends up subscribed to, read back from
/// the kernel.
///
/// This is the one property of the netlink backend that CI could not check.
/// `a_route_change_alone_reaches_the_watcher` discriminates a wrong mask by
/// provoking a real route change, but it needs `CAP_NET_ADMIN` and is skipped
/// everywhere CI runs — so a regression to link-events-only would have passed
/// every gate while the detector silently stopped seeing the default route
/// move, which is the change it exists to catch.
///
/// A wrong mask cannot be caught by watching the bind: subscribing to the
/// wrong groups succeeds exactly like subscribing to the right ones, and only
/// differs in what never arrives afterwards. So this asks the kernel what the
/// socket is subscribed to instead, which needs no privileges at all.
///
/// It goes through `build_wake_source` rather than constructing a watcher
/// directly, so it is the production path being asserted on and not a second
/// copy of the same constant.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn the_detector_subscribes_to_the_route_groups_not_just_link() {
    use crate::transport::watcher::groups;

    let wake = build_wake_source(&cfg(5, 250));
    // Asserted, not skipped. An early return here would make this test green in
    // exactly the environment that differs from a real check — a sandbox where
    // the bind is refused — so a mask regression would pass everywhere the
    // subscription could not be inspected. `the_egress_path_mask_opens_a_source`
    // already holds the same line: the bind is expected to work on Linux.
    let subscribed = wake.subscribed_groups().expect(
        "the detector must have a live netlink subscription to inspect; without one \
         this test cannot say anything about the group mask",
    );

    assert_eq!(
        subscribed,
        groups::EGRESS_PATH,
        "the detector must be subscribed to the egress-path groups it asked for"
    );
    for (name, group) in [
        ("IPV4_ROUTE", groups::IPV4_ROUTE),
        ("IPV6_ROUTE", groups::IPV6_ROUTE),
        ("IPV4_IFADDR", groups::IPV4_IFADDR),
        ("IPV6_IFADDR", groups::IPV6_IFADDR),
    ] {
        assert_ne!(
            subscribed & group,
            0,
            "{name} is missing: a default route moving between two interfaces that both \
             stay up emits nothing in the link group, so without this the detector would \
             never fire for the change it exists to catch"
        );
    }
}
