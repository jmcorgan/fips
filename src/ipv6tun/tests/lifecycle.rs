//! Tests of the adapter's start and stop: how its children's exits are
//! reported to the node, and on which channel, what the adapter takes back
//! when the node hands it an exit, and the address its TUN device takes; and
//! how the handles answer the host on the app-owned path and for a refusal.

use super::{Exit, Handles, report_exit, report_thread};
use crate::ipv6tun::config::{DnsConfig, Settings};
use crate::ipv6tun::icmp_rate_limit::IcmpRateLimiter;
use crate::ipv6tun::link::{
    DatagramRx, Feeds, FromMesh, HostLink, LearnedRx, PeerKey, any_key, pair,
};
use std::time::Duration;

/// The panic line both reporters log.
const PANICKED: &str = "Supervised child panicked; reporting its exit";

/// A supervised task that panics is still reported to the supervisor.
///
/// Without the report the panic ends the task silently: the `JoinError` sits
/// on a handle nobody reads until `stop()`, and the node stays `Running` with
/// the child gone.
#[tokio::test]
async fn report_exit_reports_a_body_that_panics() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let handle = tokio::spawn(report_exit(
        Exit::Dns,
        async { panic!("the supervised body died") },
        Some(tx),
    ));
    let joined = handle.await;

    assert_eq!(
        rx.recv().await,
        Some(Exit::Dns),
        "a panicking child must still report its exit",
    );
    assert!(
        joined.is_ok(),
        "the panic must be contained by the reporter"
    );
}

/// A supervised task whose body returns is reported, so a future ordinary
/// exit from the DNS responder needs no further wiring.
#[tokio::test]
async fn report_exit_reports_a_body_that_returns() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(report_exit(Exit::Dns, async {}, Some(tx)))
        .await
        .unwrap();

    assert_eq!(rx.recv().await, Some(Exit::Dns));
}

/// A deliberate teardown aborts a running child, and that must not read as a
/// death: the abort drops the whole reporting future before any send.
#[tokio::test]
async fn report_exit_stays_silent_when_the_task_is_aborted() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(report_exit(
        Exit::Dns,
        async move {
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        },
        Some(tx),
    ));
    // The body is running, as a live responder is when `stop()` aborts it.
    started_rx.await.unwrap();
    handle.abort();

    assert!(handle.await.unwrap_err().is_cancelled());
    assert_eq!(rx.recv().await, None, "an aborted child must not report");
}

/// A supervised thread that panics is still reported to the supervisor.
#[test]
fn report_thread_reports_a_body_that_panics() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let joined = std::thread::spawn(move || {
        report_thread(
            Exit::Tun,
            || panic!("the supervised thread died"),
            Some(&tx),
        )
    })
    .join();

    assert_eq!(
        rx.try_recv(),
        Ok(Exit::Tun),
        "a panicking thread must still report its exit",
    );
    assert!(
        joined.is_ok(),
        "the panic must be contained by the reporter"
    );
}

/// A supervised thread whose body returns is reported.
#[test]
fn report_thread_reports_a_body_that_returns() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || report_thread(Exit::Tun, || {}, Some(&tx)))
        .join()
        .unwrap();

    assert_eq!(rx.try_recv(), Ok(Exit::Tun));
}

/// A TUN thread's panic is logged under the adapter's target, beside its
/// other start and stop logging, with the `child` field it had in the node.
///
/// The thread body runs on the calling thread, since a scoped capture does
/// not see a spawned one.
#[test]
fn a_panicking_thread_is_logged_under_the_adapter_target() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    report_thread(Exit::Tun, || panic!("the supervised thread died"), None);

    assert_eq!(logs.targets(PANICKED), vec!["fips::ipv6tun::lifecycle"]);
    let line = logs.line(PANICKED).expect("the panic is logged");
    assert!(line.contains(" child=Tun"), "{line}");
}

/// The DNS responder's panic is logged under the adapter's target too, with
/// the `child` field it had in the node.
///
/// The reporting future is awaited in place rather than spawned, so the
/// scoped capture on this thread sees its line.
#[tokio::test]
async fn a_panicking_task_is_logged_under_the_adapter_target() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    report_exit(
        Exit::Dns,
        async { panic!("the supervised body died") },
        None,
    )
    .await;

    assert_eq!(logs.targets(PANICKED), vec!["fips::ipv6tun::lifecycle"]);
    let line = logs.line(PANICKED).expect("the panic is logged");
    assert!(line.contains(" child=Dns"), "{line}");
}

/// Handles with the TUN enabled, a DNS responder on the IPv6 loopback and a
/// seed address that is not this node's, attached over a fresh link by a
/// node whose key is `node`, with the node's ends of the link. The node's
/// `Attached` and `Synced` are queued before the attach, as the node's
/// attach step replays them.
fn attached_by(node: PeerKey) -> (Handles, HostLink, DatagramRx, LearnedRx) {
    let mut handles = Handles::new("fd00::1".parse().unwrap(), dns_settings());
    let (mesh, host, datagrams, learned) = pair(8, 8);
    host.send(FromMesh::Attached {
        node,
        payload_limit: 1200,
    });
    host.send(FromMesh::Synced);
    let feeds = Feeds {
        path_mtu: true,
        identity: true,
    };
    handles.attached(mesh, feeds);
    (handles, host, datagrams, learned)
}

/// Settings with the TUN enabled and a DNS responder on the IPv6 loopback
/// at a port the kernel picks.
fn dns_settings() -> Settings {
    Settings {
        dns: DnsConfig {
            bind_addr: Some("::1".to_string()),
            port: Some(0),
            ..Default::default()
        },
        ..Settings::with_tun(true)
    }
}

/// The TUN device takes the address the node's attach gave the adapter, the
/// one the node's key names, not the seed the handles were built with.
#[test]
fn the_tun_device_takes_the_address_the_attach_gave_not_the_seed() {
    let node = any_key();
    let (handles, _host, _datagrams, _learned) = attached_by(node);
    assert_eq!(handles.tun_address().unwrap(), node.address());
}

/// The DNS responder's task holds a sender on the exit channel the start
/// opened, the one [`Handles::exits`] returned, so its exit reaches whoever
/// holds that receiver rather than a channel nobody reads. That the node opens
/// the channel before its children start, on each start, so that this is the
/// channel its receive loop reads, is pinned by the node's own tests.
#[tokio::test]
async fn the_dns_task_reports_on_the_exit_channel_this_start_opened() {
    let (mut handles, _host, _datagrams, _learned) = attached_by(any_key());
    let _exits = handles.exits();
    let sender = handles.exit_sender().expect("the start opened a channel");
    let before = sender.strong_count();

    assert!(handles.start_dns(), "the responder came up");
    assert_eq!(
        sender.strong_count(),
        before + 1,
        "the responder's task must hold a sender on this start's channel",
    );
    handles.stop_dns();
}

/// The node hands the adapter each exit before its supervisor hears of it. A
/// TUN thread's exit takes nothing back, since the teardown finds the TUN by
/// its device name; a DNS exit takes back the responder's address, from the
/// handles and from the published status, and leaves its task for the
/// teardown to find.
#[tokio::test]
async fn a_tun_exit_takes_nothing_back_and_a_dns_exit_takes_back_the_dns_address() {
    let (mut handles, _host, _datagrams, _learned) = attached_by(any_key());
    assert!(handles.start_dns(), "the responder came up");
    let bound = handles.dns_local_addr;
    assert!(bound.is_some());

    handles.exited(Exit::Tun);
    assert_eq!(handles.dns_local_addr, bound, "a TUN exit keeps it");
    assert_eq!(handles.status().read().dns_local_addr, bound);

    handles.exited(Exit::Dns);
    assert_eq!(handles.dns_local_addr, None, "a DNS exit takes it");
    assert_eq!(handles.status().read().dns_local_addr, None);
    assert!(handles.dns_up(), "the task stays for the teardown to find");
    handles.stop_dns();
}

/// A packet of `len` bytes from `src` to `dst` that carries nothing.
fn bare(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr, len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    packet[6] = 59;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet
}

/// The Packet Too Big limiter counts a refusal's source even while no TUN
/// queue is up to take the answer, so a second refusal from the same source
/// once a queue is up, inside the interval, is not answered; handles that
/// answered none before do answer it.
#[test]
fn packet_too_big_with_no_tun_queue_up_still_counts_against_its_source() {
    let us: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let peer = any_key();
    let sent = bare(us, peer.address().to_ipv6(), 1300);
    let refusal = || crate::ipv6tun::link::Refusal::TooBig {
        peer,
        payload_limit: 1000,
        payload: crate::ipv6tun::ipv6_shim::compress_ipv6(&sent).unwrap(),
    };

    // An hour's interval, so a runner stalled between the two refusals
    // cannot let the second one through.
    let mut counted = Handles::new(us, Settings::with_tun(true));
    *counted.icmp_limiter.lock().unwrap() =
        IcmpRateLimiter::with_interval(Duration::from_secs(3600));
    counted.answer(refusal());
    let (tun_tx, rx) = crate::ipv6tun::tun::TunTx::bounded(8);
    counted.install_sender(tun_tx);
    counted.answer(refusal());
    assert!(rx.try_recv().is_err(), "held back by the first refusal");

    let mut fresh = Handles::new(us, Settings::with_tun(true));
    let (tun_tx, rx) = crate::ipv6tun::tun::TunTx::bounded(8);
    fresh.install_sender(tun_tx);
    fresh.answer(refusal());
    assert_eq!(rx.try_iter().count(), 1, "answered with nothing before it");
}

/// A packet an embedder that owns the TUN sends over the node-wide MTU, to a
/// destination no key names, is answered with Packet Too Big once; a second
/// from the same source straight after is held back.
#[test]
fn repeated_packet_too_big_on_the_app_owned_path_is_answered_once() {
    let us: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let mut handles = Handles::new(us, Settings::with_tun(true));
    // An hour's interval, so a runner stalled between the two packets cannot
    // let the second one through.
    *handles.icmp_limiter.lock().unwrap() =
        IcmpRateLimiter::with_interval(Duration::from_secs(3600));
    let (tun_tx, rx) = crate::ipv6tun::tun::TunTx::bounded(8);
    handles.install_sender(tun_tx);
    let over = bare(us, any_key().address().to_ipv6(), 1400);
    assert!(handles.outbound(&over).is_none());
    assert!(handles.outbound(&over).is_none());
    let answers: Vec<Vec<u8>> = rx.try_iter().collect();
    assert_eq!(answers.len(), 1, "one Packet Too Big");
    assert_eq!(answers[0][40], 2, "ICMPv6 type 2");
}

/// The most Destination Unreachable the bucket can let through within
/// `elapsed` of being filled: its burst, and what it refills in that time
/// rounded up.
fn unreachable_ceiling(elapsed: Duration) -> usize {
    use crate::ipv6tun::icmp::{UNREACHABLE_BURST, UNREACHABLE_RATE};
    UNREACHABLE_BURST as usize + (elapsed.as_secs_f64() * UNREACHABLE_RATE).ceil() as usize
}

/// Handles with a TUN queue up that holds everything they send, the host's
/// end of it, and when they were made (their bucket is full from then).
fn queued(
    us: std::net::Ipv6Addr,
) -> (
    Handles,
    std::sync::mpsc::Receiver<Vec<u8>>,
    std::time::Instant,
) {
    let made = std::time::Instant::now();
    let mut handles = Handles::new(us, Settings::with_tun(true));
    let (tun_tx, rx) = crate::ipv6tun::tun::TunTx::bounded(256);
    handles.install_sender(tun_tx);
    (handles, rx, made)
}

/// Destination Unreachable to the host is rate limited, as RFC 4443 Section
/// 2.4 (f) requires of the ICMPv6 errors a node originates, by a token
/// bucket that lets a burst through: a hundred undeliverable packets in a
/// row on the app-owned path draw the whole burst and no more than the
/// bucket refills while they are sent.
#[test]
fn a_flood_of_undeliverable_packets_on_the_app_owned_path_draws_the_burst_and_at_most_the_refill() {
    let us: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let (mut handles, rx, made) = queued(us);
    let sent = bare(us, any_key().address().to_ipv6(), 80);
    for _ in 0..100 {
        assert!(handles.outbound(&sent).is_none());
    }
    let ceiling = unreachable_ceiling(made.elapsed());
    let answers: Vec<Vec<u8>> = rx.try_iter().collect();
    assert!(answers.iter().all(|a| a[40] == 1), "ICMPv6 type 1");
    assert!(
        (crate::ipv6tun::icmp::UNREACHABLE_BURST as usize..=ceiling).contains(&answers.len()),
        "a hundred undeliverable packets drew {} Destination Unreachable, outside the burst \
         and the bucket's ceiling of {ceiling}",
        answers.len()
    );
}

/// The same bucket covers the answers to a refusal of the packets the node
/// held for a destination it found no route to (the lookup timeout): a
/// hundred held packets draw the burst and no more than the refill.
#[test]
fn a_refusal_of_a_hundred_held_packets_draws_the_burst_and_no_more_than_the_refill() {
    let us: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let (handles, rx, made) = queued(us);
    let peer = any_key();
    let payload =
        crate::ipv6tun::ipv6_shim::compress_ipv6(&bare(us, peer.address().to_ipv6(), 80)).unwrap();
    handles.answer(crate::ipv6tun::link::Refusal::NoRoute {
        peer,
        payloads: vec![payload; 100],
    });
    let ceiling = unreachable_ceiling(made.elapsed());
    let answers = rx.try_iter().count();
    assert!(
        (crate::ipv6tun::icmp::UNREACHABLE_BURST as usize..=ceiling).contains(&answers),
        "a refusal of a hundred held packets drew {answers} Destination Unreachable, outside \
         the burst and the bucket's ceiling of {ceiling}"
    );
}

/// The TUN reader and the handles draw on one Destination Unreachable
/// bucket, so the adapter's total is one burst and one rate, as RFC 4443
/// Section 2.4 (f) limits the node: tokens the reader's host path spends are
/// gone for the handles' answers on the app-owned path.
#[test]
fn the_tun_reader_and_the_handles_draw_on_one_destination_unreachable_bucket() {
    use fips_core::time::Clock;
    let us: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let (mut handles, rx, _) = queued(us);
    handles.budget_unreachable(3, 0.0);
    let (datagrams, _node) = tokio::sync::mpsc::channel(1);
    let host = handles.reader_host(datagrams);
    {
        let mut bucket = host.unreachable.lock().unwrap();
        let now = crate::time::HostClock.now();
        for spent in 0..3 {
            assert!(bucket.try_acquire(now), "the reader's token {spent}");
        }
    }
    let sent = bare(us, any_key().address().to_ipv6(), 80);
    assert!(handles.outbound(&sent).is_none());
    assert_eq!(
        rx.try_iter().count(),
        0,
        "the handles answered from a bucket the reader had emptied"
    );
}

/// Code 5 answers to packets from a source other than ours draw on the same
/// Destination Unreachable bucket: a hundred in a row on the app-owned path
/// draw the burst and no more than the refill.
#[test]
fn a_flood_from_a_foreign_source_on_the_app_owned_path_draws_the_burst_and_no_more_than_the_refill()
{
    let us: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let (mut handles, rx, made) = queued(us);
    let sent = bare(
        "2001:db8::5".parse().unwrap(),
        any_key().address().to_ipv6(),
        80,
    );
    for _ in 0..100 {
        assert!(handles.outbound(&sent).is_none(), "not forwarded");
    }
    let ceiling = unreachable_ceiling(made.elapsed());
    let answers: Vec<Vec<u8>> = rx.try_iter().collect();
    assert!(
        answers.iter().all(|a| a[40] == 1 && a[41] == 5),
        "ICMPv6 type 1, code 5"
    );
    assert!(
        (crate::ipv6tun::icmp::UNREACHABLE_BURST as usize..=ceiling).contains(&answers.len()),
        "a hundred packets from a foreign source drew {} answers, outside the burst and the \
         bucket's ceiling of {ceiling}",
        answers.len()
    );
}
