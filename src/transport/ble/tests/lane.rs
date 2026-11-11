//! The path-message lane: a BLE connection keeps path messages in a queue
//! apart from its data, which the writer drains first.
//!
//! A child of the `ble` module, so it pools a connection with the real
//! writer task (`send_loop`) behind it, over a `MockBleStream` pair whose
//! far end the test holds. Each direction of the pair holds one frame, so
//! a far end the test does not read is a link that has stopped draining:
//! the writer's write waits, and the queues behind it fill.

use super::*;
use io::MockBleStream;

/// The pool key the connection is at.
fn at() -> TransportAddr {
    TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:02")
}

/// A BLE transport over a mock radio, not started.
fn transport() -> BleTransport<io::MockBleIo> {
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let io = io::MockBleIo::new("hci0", BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap());
    BleTransport::new(TransportId::new(1), None, BleConfig::default(), io, tx)
}

/// Pool a connection at `at()` with the real writer behind it, and return
/// the far end of its stream, which holds one frame until it is read.
async fn connect(t: &BleTransport<io::MockBleIo>) -> MockBleStream {
    let near_addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap();
    let far_addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:02").unwrap();
    let (near, far) = MockBleStream::pair_with_depths(near_addr, far_addr.clone(), 2048, 1, 1);
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
    let outcome = t.pool.lock().await.insert(at(), conn, now);
    assert!(
        matches!(outcome, Insert::Admitted { .. }),
        "precondition: the connection is pooled"
    );
    far
}

/// Let the writer task run until it is waiting on the stream again.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// A frame of `len` bytes, every byte `tag`, so the far end can tell frames
/// apart.
fn frame(tag: u8, len: usize) -> Vec<u8> {
    vec![tag; len]
}

/// Send frames tagged `tag` on `lane` until one is refused, at most
/// `limit`, and return how many were accepted.
async fn fill(t: &BleTransport<io::MockBleIo>, lane: Lane, tag: u8, limit: usize) -> usize {
    for sent in 0..limit {
        let result = t.send_lane(lane, &at(), &frame(tag, 64)).await;
        settle().await;
        if result.is_err() {
            return sent;
        }
    }
    limit
}

/// A connection whose data queue is full still takes a path message: the
/// two are queued apart, so data the node itself sent cannot crowd out the
/// probes and acks that keep the path's verdict.
#[tokio::test]
async fn a_path_message_is_queued_while_the_connections_data_queue_is_full() {
    let t = transport();
    let _far = connect(&t).await;
    let accepted = fill(&t, Lane::Data, 1, 64).await;
    assert!(
        accepted < 64,
        "precondition: the data queue fills and refuses ({accepted} frames accepted)"
    );

    let path = t.send_lane(Lane::Path, &at(), &frame(2, 64)).await;
    assert!(
        path.is_ok(),
        "defect: a path message was refused behind a full data queue: {path:?}"
    );
}

/// The writer sends a waiting path message before the data queued ahead of
/// it: once the far end reads again, the path message comes out after only
/// the frames already on the stream, the one in the far end's slot and the
/// one the writer was writing.
#[tokio::test]
async fn the_writer_sends_a_waiting_path_message_before_the_data_queued_ahead_of_it() {
    let t = transport();
    let far = connect(&t).await;
    let accepted = fill(&t, Lane::Data, 1, pool::SEND_QUEUE_DEPTH).await;
    assert_eq!(
        accepted,
        pool::SEND_QUEUE_DEPTH,
        "precondition: the data is queued"
    );
    t.send_lane(Lane::Path, &at(), &frame(2, 64))
        .await
        .expect("precondition: the path message is queued");

    let mut ahead = 0;
    let mut buf = vec![0u8; 2048];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), far.recv(&mut buf))
            .await
            .expect("the writer drains")
            .expect("the stream is open");
        assert!(n > 0, "the stream closed before the path message came out");
        if buf[0] == 2 {
            break;
        }
        ahead += 1;
    }
    assert!(
        ahead <= 2,
        "defect: the path message waited behind {ahead} frames of data"
    );
}

/// A connection that has stopped draining refuses path messages once their
/// own queue is full, as it refuses data. Their queue is bounded, so a
/// probe on such a connection is refused, goes unanswered, and the path
/// still fails over.
#[tokio::test]
async fn a_connection_that_stops_draining_refuses_path_messages_once_their_queue_is_full() {
    let t = transport();
    let _far = connect(&t).await;
    let errors = t.stats.snapshot().send_errors;
    let accepted = fill(&t, Lane::Path, 2, 256).await;
    assert!(
        accepted < 256,
        "defect: a connection that stopped draining took every path message offered"
    );
    assert_eq!(
        t.stats.snapshot().send_errors,
        errors + 1,
        "the refusal is counted as a send error"
    );
}
