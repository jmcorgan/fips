//! `has_connection`, the test hook that reports whether the pool holds a
//! connection to an address without promoting or dialing anything.
//!
//! The conformance rules and the settlement audit read the pool through it,
//! so a hook that reported a finished connect, or promoted one as a side
//! effect, would let those tests judge the wrong state. The Nym transport
//! dials a TCP destination through a mock SOCKS5 proxy.

use super::tests::{build_msg1_frame, nym_via_mock_proxy};
use super::*;

/// `has_connection` reports only what the pool holds. A finished background
/// connect is not a pooled connection and is left where it is; once
/// `send_existing` has promoted it, the connection is reported.
#[tokio::test]
async fn has_connection_reports_the_pool_and_never_promotes_a_finished_connect() {
    let (mut dest, mut dest_rx, mut t, target) = nym_via_mock_proxy().await;

    assert!(
        !t.has_connection(&target).await,
        "no connection before any connect"
    );
    t.connect_async(&target).await.unwrap();
    let mut waited = 0;
    while !t
        .connecting
        .try_lock()
        .is_ok_and(|c| c.get(&target).is_some_and(|e| e.task.is_finished()))
    {
        assert!(waited < 150, "background connect never finished");
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += 1;
    }
    assert!(
        !t.has_connection(&target).await,
        "a finished connect that is not pooled is not a connection"
    );
    assert!(
        t.connecting.lock().await.contains_key(&target),
        "the query moved the finished connect out of the connecting map"
    );
    assert!(
        t.pool.lock().await.is_empty(),
        "the query put a connection in the pool"
    );
    assert_eq!(
        t.stats().snapshot().connections_established,
        0,
        "the query promoted the finished connect"
    );

    let frame = build_msg1_frame();
    t.send_existing(&target, &frame).await.unwrap();
    assert!(
        t.has_connection(&target).await,
        "the promoted connection is pooled"
    );
    tokio::time::timeout(Duration::from_secs(5), dest_rx.recv())
        .await
        .expect("timeout waiting for packet")
        .expect("channel closed");

    t.stop_async().await.unwrap();
    dest.stop_async().await.unwrap();
}
