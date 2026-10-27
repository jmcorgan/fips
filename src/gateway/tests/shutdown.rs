//! Tests that stopping the gateway's tasks returns, so the route, proxy NDP
//! and NAT cleanup after it is reached.
//!
//! The resolver and the tick both await `send` on the bounded pool-event
//! channel inside a `select!` arm, where their shutdown arm is not polled. A
//! sender parked on a full channel therefore never sees the shutdown signal;
//! only closing the channel releases it. These tests park a sender on a full
//! channel of the gateway's real capacity and then stop.
//!
//! Two more tests check the bound on the wait: a task that does not end on
//! the signal is abandoned at [`STOP_TIMEOUT`] rather than holding the stop.
//!
//! They run on `#[tokio::test]`'s default current-thread runtime, as the
//! gateway does. That is what makes the readiness checks exact: a task runs
//! until it awaits something that is not ready, so once the test sees the
//! resolver's mapping allocated, the resolver has already reached the send
//! that follows the allocation with no await between them.

use super::*;
use crate::dnsmsg;
use crate::gateway::dns;
use crate::gateway::dns::tests::{
    TEST_TTL, assert_pool_answer, build_answer, build_query, test_pool,
};
use simple_dns::Packet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// How long the stop is given before the test counts it as hung.
const STOP_HANG: Duration = Duration::from_secs(10);

/// The wait bound the full-channel tests pass: long enough that a sender
/// released by the closed channel always ends inside it, and short enough
/// that a regression shows as an abandoned task before [`STOP_HANG`].
const FULL_CHANNEL_BOUND: Duration = Duration::from_secs(5);

/// The OpenWrt init script kills the gateway this long after SIGTERM, so a
/// stop must return well inside it.
const OPENWRT_KILL: Duration = Duration::from_secs(3);

/// How long a test waits for a task to reach the state it sets up.
const READY_WAIT: Duration = Duration::from_secs(5);

/// The value the stand-in tick returns when it ends on its own.
const TICK_ENDED: u32 = 0x71c4;

/// A pool event distinct for each `n`, for filling the channel.
fn backlog_event(n: usize) -> PoolEvent {
    let ip = Ipv6Addr::from((0xfd01_u128 << 112) | n as u128);
    PoolEvent::MappingRemoved {
        virtual_ip: ip,
        mesh_addr: ip,
    }
}

/// Fill `tx` to capacity without blocking.
fn fill(tx: &mpsc::Sender<PoolEvent>) {
    for n in 0..EVENT_CAPACITY {
        tx.try_send(backlog_event(n))
            .expect("the channel has room until it is full");
    }
    assert_eq!(tx.capacity(), 0, "the channel is full");
}

/// A fake daemon resolver that answers every AAAA query with a mesh address.
async fn answering_upstream(socket: UdpSocket) {
    let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
    loop {
        let Ok((len, src)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Ok(query) = Packet::parse(&buf[..len]) else {
            continue;
        };
        let name = query.questions[0].qname.to_string();
        let answer = build_answer(query.id(), &name, "fd00::1");
        let _ = socket.send_to(&answer, src).await;
    }
}

/// A task that idles until shutdown is signalled, then returns
/// [`TICK_ENDED`], like a tick between rounds.
fn idle_tick(mut shutdown: watch::Receiver<bool>) -> JoinHandle<u32> {
    tokio::spawn(async move {
        let _ = shutdown.changed().await;
        TICK_ENDED
    })
}

/// A fake daemon resolver that takes every query and never answers it,
/// counting the queries in `seen`.
async fn silent_upstream(socket: UdpSocket, seen: Arc<AtomicUsize>) {
    let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
    while socket.recv_from(&mut buf).await.is_ok() {
        seen.fetch_add(1, Ordering::SeqCst);
    }
}

/// Assert the stand-in tick ended on its own.
fn assert_finished(tick: TaskEnd<u32>) {
    match tick {
        TaskEnd::Finished(TICK_ENDED) => {}
        other => panic!("the tick did not end on its own: {other:?}"),
    }
}

/// Wait, polling, until `ready` holds; panic naming `what` after
/// [`READY_WAIT`].
async fn poll_until<F, Fut>(what: &str, mut ready: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let give_up = Instant::now() + READY_WAIT;
    while !ready().await {
        assert!(Instant::now() < give_up, "timed out waiting until {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The real resolver, parked in `send` on a full event channel after
/// allocating a mapping, ends on its own when stopped, and still answers the
/// client.
#[tokio::test]
async fn stopping_with_the_resolver_blocked_on_a_full_event_channel_returns_and_the_resolver_ends_on_its_own()
 {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let upstream_task = tokio::spawn(answering_upstream(upstream_socket));

    // An IPv4 listener: no arrival interface is needed, so no query on it is
    // dropped as coming from the mesh.
    let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to = listener.local_addr().unwrap();
    let pool = test_pool();
    let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
    fill(&event_tx);
    let (signal, shutdown) = watch::channel(false);
    let resolver = tokio::spawn(dns::serve(
        listener,
        upstream,
        TEST_TTL,
        Arc::clone(&pool),
        event_tx.clone(),
        shutdown.clone(),
        "fips0".to_string(),
    ));
    let tick = idle_tick(shutdown);

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&build_query(0x5150, "test.fips"), to)
        .await
        .unwrap();
    poll_until("the resolver allocates the query's mapping", || async {
        pool.lock().await.status().allocated == 1
    })
    .await;
    assert_eq!(event_tx.capacity(), 0, "the channel is still full");
    let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
    assert!(
        client.try_recv_from(&mut buf).is_err(),
        "the client was answered, so the resolver is not parked in send"
    );

    let stopped = tokio::time::timeout(
        STOP_HANG,
        stop_tasks(
            event_rx,
            &signal,
            None,
            Some(resolver),
            tick,
            FULL_CHANNEL_BOUND,
        ),
    )
    .await
    .expect("stopping hung with the resolver blocked on a full event channel");
    upstream_task.abort();

    match stopped.resolver {
        Some(TaskEnd::Finished(Ok(()))) => {}
        other => panic!("the resolver did not end on its own: {other:?}"),
    }
    assert_finished(stopped.tick);
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("the client is answered once the send fails")
        .unwrap();
    assert_pool_answer(&buf[..len]);
}

/// A task with the tick's shape, parked in `send` partway through a backlog
/// larger than the channel, ends on its own when stopped. The real tick body
/// is in the gateway binary; this stand-in has its `select!` and its loop of
/// sends.
#[tokio::test]
async fn stopping_with_the_tick_blocked_sending_a_backlog_returns_and_the_tick_ends_on_its_own() {
    const BACKLOG: usize = EVENT_CAPACITY + 36;
    let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
    let (signal, mut shutdown) = watch::channel(false);
    let attempted = Arc::new(AtomicUsize::new(0));
    let tick = {
        let attempted = Arc::clone(&attempted);
        let event_tx = event_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        for n in 0..BACKLOG {
                            let _ = event_tx.send(backlog_event(n)).await;
                            attempted.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    _ = shutdown.changed() => break,
                }
            }
            TICK_ENDED
        })
    };
    // A control task that never ends by itself, as the accept loop does not.
    let control = tokio::spawn(std::future::pending::<()>());

    poll_until("the tick parks on the full channel", || async {
        attempted.load(Ordering::SeqCst) == EVENT_CAPACITY
    })
    .await;
    assert_eq!(event_tx.capacity(), 0, "the channel is full");
    tokio::task::yield_now().await;
    assert_eq!(
        attempted.load(Ordering::SeqCst),
        EVENT_CAPACITY,
        "the tick is still parked in send"
    );

    let stopped = tokio::time::timeout(
        STOP_HANG,
        stop_tasks::<(), u32>(
            event_rx,
            &signal,
            Some(control),
            None,
            tick,
            FULL_CHANNEL_BOUND,
        ),
    )
    .await
    .expect("stopping hung with the tick blocked on a full event channel");

    assert!(stopped.resolver.is_none());
    assert_finished(stopped.tick);
    assert_eq!(
        attempted.load(Ordering::SeqCst),
        BACKLOG,
        "every remaining send failed at once"
    );
}

/// The real resolver, waiting on an upstream that never answers, holds the
/// stop only until the bound, inside the OpenWrt kill window, and is then
/// abandoned. Without the bound it holds the stop for the whole upstream
/// timeout.
#[tokio::test]
async fn stopping_with_the_resolver_waiting_on_a_silent_upstream_abandons_it_at_the_bound() {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let upstream_task = tokio::spawn(silent_upstream(upstream_socket, Arc::clone(&seen)));

    let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to = listener.local_addr().unwrap();
    let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
    let (signal, shutdown) = watch::channel(false);
    let resolver = tokio::spawn(dns::serve(
        listener,
        upstream,
        TEST_TTL,
        test_pool(),
        event_tx,
        shutdown.clone(),
        "fips0".to_string(),
    ));
    let tick = idle_tick(shutdown);

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&build_query(0x5151, "test.fips"), to)
        .await
        .unwrap();
    poll_until("the upstream has the forwarded query", || async {
        seen.load(Ordering::SeqCst) == 1
    })
    .await;

    let started = Instant::now();
    let stopped = tokio::time::timeout(
        STOP_HANG,
        stop_tasks(event_rx, &signal, None, Some(resolver), tick, STOP_TIMEOUT),
    )
    .await
    .expect("stopping hung with the resolver waiting on a silent upstream");
    let took = started.elapsed();
    upstream_task.abort();

    match stopped.resolver {
        Some(TaskEnd::Abandoned) => {}
        other => panic!("the resolver was not abandoned at the bound, after {took:?}: {other:?}"),
    }
    assert!(
        took >= STOP_TIMEOUT && took < OPENWRT_KILL,
        "the stop took {took:?}, not the {STOP_TIMEOUT:?} bound"
    );
    assert_finished(stopped.tick);
}

/// A tick that never ends, here waiting on a lock the test holds, is
/// abandoned at the bound instead of holding the stop.
#[tokio::test]
async fn stopping_with_a_tick_that_never_ends_abandons_it_at_the_bound() {
    let (_event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
    let (signal, _shutdown) = watch::channel(false);
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let held = gate.lock().await;
    let tick = {
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let _guard = gate.lock().await;
            TICK_ENDED
        })
    };
    tokio::task::yield_now().await;

    let started = Instant::now();
    let stopped = tokio::time::timeout(
        STOP_HANG,
        stop_tasks::<(), u32>(event_rx, &signal, None, None, tick, STOP_TIMEOUT),
    )
    .await
    .expect("stopping hung with a tick that never ends");
    let took = started.elapsed();
    drop(held);

    match stopped.tick {
        TaskEnd::Abandoned => {}
        other => panic!("the tick was not abandoned at the bound: {other:?}"),
    }
    assert!(
        took < OPENWRT_KILL,
        "the stop took {took:?}, not the {STOP_TIMEOUT:?} bound"
    );
}
