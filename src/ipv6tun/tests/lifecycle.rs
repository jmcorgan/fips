//! Tests of the adapter's start and stop: how its children's exits are
//! reported to the node, and on which channel, what the adapter takes back
//! when the node hands it an exit, and the address its TUN device takes.

use super::{Exit, Handles, report_exit, report_thread};
use crate::ipv6tun::config::{DnsConfig, Settings};
use crate::ipv6tun::link::{
    DatagramRx, Feeds, FromMesh, HostLink, LearnedRx, PeerKey, any_key, pair,
};

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
