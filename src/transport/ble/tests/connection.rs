//! `has_connection`, the test hook that reports whether the pool holds a
//! channel at an address without starting a connect.
//!
//! The conformance rules and the settlement audit read the pool through it,
//! so a hook that dialed, or missed a pooled channel, would let those tests
//! judge the wrong state.

use super::tests::{make_transport, test_addr};
use super::*;
use io::{MockBleIo, MockBleStream};

/// `has_connection` reports whether the pool holds a channel at the address,
/// the lookup `send_async` makes first, and unlike a send to an unpooled
/// address it starts no connect.
#[tokio::test]
async fn has_connection_reports_the_pool_and_starts_no_connect() {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (transport, _rx) = make_transport(io);
    let ta = test_addr(2).to_transport_addr();

    assert!(
        !transport.has_connection(&ta).await,
        "no connection before one is pooled"
    );
    assert!(
        transport.connecting.lock().await.is_empty(),
        "the query started a connect"
    );

    let (near, _far) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
    let (send_tx, _send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
    let (path_tx, _path_rx) = tokio::sync::mpsc::channel(pool::PATH_QUEUE_DEPTH);
    transport
        .pool
        .lock()
        .await
        .insert(
            ta.clone(),
            BleConnection {
                stream: Arc::new(near),
                send_tx,
                path_tx,
                send_task: None,
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: tokio::time::Instant::now(),
                addr: test_addr(2),
                outbound: false,
                id: 0,
            },
            tokio::time::Instant::now(),
        )
        .expect("an empty pool admits the channel");
    assert!(
        transport.has_connection(&ta).await,
        "the pooled channel is reported"
    );
}
