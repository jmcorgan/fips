//! Admitting a BLE link to the pool: a link the pool refuses must not start
//! its receive loop.
//!
//! The receive loop delivers packets under the link's address and removes
//! that address from the pool when its stream ends. A refused link shares its
//! address with the link the pool already holds there, so a loop started for
//! it would deliver the refused link's frames as that link's, and take that
//! link out of the pool when it closed.

use super::*;
use crate::transport::framing::build_established_frame;
use crate::transport::{PacketRx, packet_channel};
use io::{MockBleIo, MockBleStream};
use std::time::Duration;

/// This end's link address.
fn near() -> BleAddr {
    BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap()
}

/// The far end's link address, where the pool holds the incumbent.
fn far() -> BleAddr {
    BleAddr::parse("hci0/AA:BB:CC:DD:EE:02").unwrap()
}

/// A BLE transport over a mock radio, not started and with no local key, so
/// a dialled link is offered to the pool without arbitration, and the
/// receiver of the packets it delivers.
fn transport() -> (BleTransport<MockBleIo>, PacketRx) {
    let (tx, rx) = packet_channel(64);
    let io = MockBleIo::new("hci0", near());
    (
        BleTransport::new(TransportId::new(1), None, BleConfig::default(), io, tx),
        rx,
    )
}

/// The incumbent link at `far()`, with its real writer task, pooled. Its far
/// end is returned and must be kept, or the link closes.
async fn pool_incumbent(t: &BleTransport<MockBleIo>) -> (ConnId, MockBleStream) {
    let (near_end, far_end) = MockBleStream::pair(near(), far(), 2048);
    let stream = Arc::new(near_end);
    let ta = far().to_transport_addr();
    let id = next_conn_id();
    let (send_tx, send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
    let (path_tx, path_rx) = tokio::sync::mpsc::channel(pool::PATH_QUEUE_DEPTH);
    let send_task = tokio::spawn(send_loop(
        Arc::clone(&stream),
        path_rx,
        send_rx,
        ta.clone(),
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
        addr: far(),
        node_addr: None,
        id,
        proven: false,
        held_from: now,
    };
    let outcome = t.pool.lock().await.insert(ta, conn, now);
    assert!(
        matches!(outcome, Insert::Admitted { .. }),
        "precondition: the incumbent is pooled"
    );
    (id, far_end)
}

/// A second link dialled to an address the pool already holds is refused,
/// and nothing it carries reaches the node: its frame is not delivered, and
/// its stream ending does not take the incumbent out of the pool.
#[tokio::test(start_paused = true)]
async fn a_link_refused_at_an_occupied_address_delivers_nothing_and_leaves_the_incumbent() {
    let (t, mut rx) = transport();
    let (incumbent, _incumbent_far) = pool_incumbent(&t).await;

    let (near_end, far_end) = MockBleStream::pair(near(), far(), 2048);
    let stream = Arc::new(near_end);
    let reader = BleStreamRead::new(Arc::clone(&stream), 2048);
    far_end.send(&build_established_frame(32)).await.unwrap();
    drop(far_end);

    let ta = far().to_transport_addr();
    t.promote_connection(&ta, &far(), stream, reader, None)
        .await
        .expect("a link refused at an occupied address is not an error");

    // The clock is paused, so the wait ends only once every task is idle: a
    // receive loop, had one started, has read the frame and the stream's end.
    let delivered = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
    assert!(
        !matches!(delivered, Ok(Some(_))),
        "defect: the refused link's frame was delivered as the incumbent's"
    );
    let kept = t.pool.lock().await.get(&ta).map(|c| c.id);
    assert_eq!(
        kept,
        Some(incumbent),
        "defect: the refused link's stream ending took the incumbent out of the pool"
    );
}
