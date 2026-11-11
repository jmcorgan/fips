//! Closing BLE connections: what a connection's writer may do to the pool
//! once its entry has gone.
//!
//! A child of the `ble` module, so it builds pool entries with the real
//! writer task (`send_loop`) behind them, over `MockBleStream` pairs whose
//! far end the test holds.

use super::*;
use crate::testutil::wait_until;
use crate::transport::framing::build_established_frame;
use io::{MockBleIo, MockBleStream};
use std::time::Duration;

/// The pool key every connection here is at.
fn at() -> TransportAddr {
    TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:02")
}

/// A BLE transport over a mock radio, not started.
fn transport() -> BleTransport<MockBleIo> {
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let io = MockBleIo::new("hci0", BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap());
    BleTransport::new(TransportId::new(1), None, BleConfig::default(), io, tx)
}

/// A connection to `at()` with the real writer task behind it, its own id,
/// and the far end of its stream.
fn connection(t: &BleTransport<MockBleIo>) -> (BleConnection<Arc<MockBleStream>>, MockBleStream) {
    let near_addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap();
    let far_addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:02").unwrap();
    let (near, far) = MockBleStream::pair(near_addr, far_addr.clone(), 2048);
    let stream = Arc::new(near);
    let id = next_conn_id();
    let (send_tx, send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
    let (path_tx, path_rx) = tokio::sync::mpsc::channel(pool::PATH_QUEUE_DEPTH);
    let send_task = tokio::spawn(send_loop(
        Arc::clone(&stream),
        path_rx,
        send_rx,
        at(),
        id,
        Arc::clone(&t.pool),
        Arc::clone(&t.stats),
    ));
    let now = tokio::time::Instant::now();
    let conn = BleConnection {
        stream,
        send_tx,
        path_tx,
        send_task: Some(send_task),
        recv_task: None,
        send_mtu: 2048,
        recv_mtu: 2048,
        established_at: now,
        verified: true,
        grace_from: now,
        outbound: true,
        addr: far_addr,
        node_addr: None,
        id,
        proven: false,
        held_from: now,
    };
    (conn, far)
}

/// Pool `conn` at `at()`.
async fn pool(t: &BleTransport<MockBleIo>, conn: BleConnection<Arc<MockBleStream>>) {
    let outcome = t
        .pool
        .lock()
        .await
        .insert(at(), conn, tokio::time::Instant::now());
    assert!(
        matches!(outcome, Insert::Admitted { .. }),
        "precondition: the connection is pooled"
    );
}

/// Whether the transport has counted `n` failed writes within two seconds.
async fn send_errors_reach(t: &BleTransport<MockBleIo>, n: u64) -> bool {
    let stats = Arc::clone(&t.stats);
    wait_until(|| stats.snapshot().send_errors == n, Duration::from_secs(2)).await
}

/// A connection's writer whose write fails removes the pool entry only if it
/// is still its own: a newer connection at the same address stays pooled.
///
/// Connection A is taken out of the pool with its writer left running, and
/// B is pooled at the same address. A's far end is dropped, so the frame
/// then queued on A fails to write.
#[tokio::test]
async fn a_writer_whose_write_fails_leaves_a_newer_connection_at_its_address_pooled() {
    let t = transport();
    let (a, a_far) = connection(&t);
    pool(&t, a).await;
    let mut a = t
        .pool
        .lock()
        .await
        .remove(&at())
        .expect("precondition: A is pooled");
    let a_queue = a.send_tx.clone();
    let a_writer = a.send_task.take();
    drop(a);

    let (b, _b_far) = connection(&t);
    pool(&t, b).await;

    drop(a_far);
    a_queue
        .send(build_established_frame(64))
        .await
        .expect("precondition: A's writer is still running");
    assert!(
        send_errors_reach(&t, 1).await,
        "precondition: A's write failed"
    );
    assert!(
        t.has_connection(&at()).await,
        "defect: A's failed write removed the newer connection at its address"
    );
    drop(a_writer);
}

/// Queue frames on the pooled connection at `at()` until its writer is
/// blocked: the far end, which never reads, has its 64 slots filled, and the
/// writer holds one more frame it cannot write.
async fn block_writer(t: &BleTransport<MockBleIo>) {
    let frame = build_established_frame(64);
    let stats = Arc::clone(&t.stats);
    let mut queued = 0u64;
    while queued < 64 {
        // A batch no deeper than the queue, then wait for it to be written,
        // so no send finds the queue full.
        for _ in 0..pool::SEND_QUEUE_DEPTH {
            t.send_async(&at(), &frame)
                .await
                .expect("precondition: the frame is queued");
            queued += 1;
        }
        assert!(
            wait_until(
                || stats.snapshot().packets_sent == queued,
                Duration::from_secs(2)
            )
            .await,
            "precondition: the writer wrote the batch"
        );
    }
    t.send_async(&at(), &frame)
        .await
        .expect("precondition: one more frame is queued");
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        stats.snapshot().packets_sent,
        64,
        "precondition: the writer is blocked on the full far end"
    );
}

/// A deliberate close returns at once although the writer cannot finish:
/// the drain runs after the close returns, never inside it.
#[tokio::test]
async fn a_close_does_not_wait_for_the_writer() {
    let t = transport();
    let (a, _a_far) = connection(&t);
    pool(&t, a).await;
    block_writer(&t).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(200), t.close_connection_async(&at()))
            .await
            .is_ok(),
        "defect: the close waited on a writer that cannot finish"
    );
    assert!(
        !t.has_connection(&at()).await,
        "precondition: the connection is closed"
    );
}

/// A closed connection's writer, still draining, whose write then fails
/// leaves alone the newer connection that took its address in between.
///
/// Connection A's writer is blocked on a far end that does not read, A is
/// closed, and B is pooled at the same address. A's far end is then dropped,
/// so A's pending write fails.
#[tokio::test]
async fn a_closed_connections_failed_write_leaves_the_newer_connection_at_its_address_pooled() {
    let t = transport();
    let (a, a_far) = connection(&t);
    pool(&t, a).await;
    block_writer(&t).await;
    t.close_connection_async(&at()).await;
    assert!(!t.has_connection(&at()).await, "precondition: A is closed");

    let (b, _b_far) = connection(&t);
    pool(&t, b).await;
    let errors = t.stats.snapshot().send_errors;
    drop(a_far);
    assert!(
        send_errors_reach(&t, errors + 1).await,
        "precondition: A's pending write failed"
    );
    assert!(
        t.has_connection(&at()).await,
        "defect: the closed connection's failed write removed the newer connection at its address"
    );
}
