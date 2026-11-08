//! A BLE channel's writer against the pool when its write fails.
//!
//! A child of the `ble` module, so it builds pool entries with the real
//! writer task (`send_loop`) behind them, over `MockBleStream` pairs whose
//! far end the test holds.

use super::*;
use crate::testutil::wait_until;
use crate::transport::framing::build_established_frame;
use io::{MockBleIo, MockBleStream};
use std::time::Duration;

/// The pool key every channel here is at.
fn at() -> TransportAddr {
    TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:02")
}

/// A BLE transport over a mock radio, not started.
fn transport() -> BleTransport<MockBleIo> {
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let io = MockBleIo::new("hci0", BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap());
    BleTransport::new(TransportId::new(1), None, BleConfig::default(), io, tx)
}

/// Pool a channel at `at()`, with the real writer task behind it, and return
/// its queue and the far end of its stream.
async fn channel(
    t: &BleTransport<MockBleIo>,
    id: u64,
    outbound: bool,
) -> (tokio::sync::mpsc::Sender<Vec<u8>>, MockBleStream) {
    let near_addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap();
    let far_addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:02").unwrap();
    let (near, far) = MockBleStream::pair(near_addr, far_addr.clone(), 2048);
    let stream = Arc::new(near);
    let (send_tx, send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
    let send_task = tokio::spawn(send_loop(
        Arc::clone(&stream),
        send_rx,
        at(),
        id,
        Arc::clone(&t.pool),
        Arc::clone(&t.stats),
    ));
    let now = tokio::time::Instant::now();
    let conn = BleConnection {
        stream,
        send_tx: send_tx.clone(),
        send_task: Some(send_task),
        recv_task: None,
        send_mtu: 2048,
        recv_mtu: 2048,
        established_at: now,
        addr: far_addr,
        outbound,
        id,
    };
    t.pool
        .lock()
        .await
        .insert(at(), conn, now)
        .expect("precondition: the channel is pooled");
    (send_tx, far)
}

/// A writer whose write fails removes its own channel and leaves the other
/// channel at the address pooled.
#[tokio::test]
async fn a_writer_whose_write_fails_leaves_the_other_channel_at_its_address_pooled() {
    let t = transport();
    let (failing, failing_far) = channel(&t, 1, false).await;
    let (_kept, _kept_far) = channel(&t, 2, true).await;
    assert_eq!(
        t.pool.lock().await.held(&at()).len(),
        2,
        "precondition: both channels are held at the address"
    );

    drop(failing_far);
    failing
        .send(build_established_frame(64))
        .await
        .expect("precondition: the writer is still running");
    assert!(
        wait_until(|| failing.is_closed(), Duration::from_secs(2)).await,
        "precondition: the writer ended on its failed write"
    );

    let held = t.pool.lock().await.held(&at());
    assert_eq!(
        held,
        vec![(2, true)],
        "defect: a failed write should have removed its own channel and left the other pooled"
    );
}
