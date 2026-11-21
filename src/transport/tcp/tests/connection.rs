//! `has_connection`, the test hook that reports whether the pool holds a
//! connection to an address without promoting or dialing anything.
//!
//! The conformance rules and the settlement audit read the pool through it,
//! so a hook that reported a finished connect, promoted one as a side
//! effect, or missed a pooled connection that cannot take a frame would let
//! those tests judge the wrong state.

use super::tests::{make_config, make_outbound_config, wait_connect_finished};
use super::*;
use crate::transport::framing::build_msg1_frame;
use crate::transport::packet_channel;
use tokio::time::timeout;

/// `has_connection` reports only what the pool holds. A finished background
/// connect is not a pooled connection and is left where it is; once
/// `send_existing` has promoted it, the connection is reported, and the
/// accepting side reports the connection by its remote address.
#[tokio::test]
async fn has_connection_reports_the_pool_and_never_promotes_a_finished_connect() {
    let (tx1, _rx1) = packet_channel(100);
    let (tx2, mut rx2) = packet_channel(100);
    let mut t1 = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx1);
    let mut t2 = TcpTransport::new(TransportId::new(2), None, make_config(), tx2);
    t1.start_async().await.unwrap();
    t2.start_async().await.unwrap();
    let remote = TransportAddr::from_string(&t2.local_addr().unwrap().to_string());

    assert!(
        !t1.has_connection(&remote).await,
        "no connection before any connect"
    );

    t1.connect_async(&remote).await.unwrap();
    wait_connect_finished(&t1, &remote).await;
    assert!(
        !t1.has_connection(&remote).await,
        "a finished connect that is not pooled is not a connection"
    );
    assert!(
        t1.connecting.lock().await.contains_key(&remote),
        "the query moved the finished connect out of the connecting map"
    );
    assert!(
        t1.pool.lock().await.is_empty(),
        "the query put a connection in the pool"
    );
    assert_eq!(
        t1.stats().snapshot().connections_established,
        0,
        "the query promoted the finished connect"
    );

    t1.send_existing(&remote, &build_msg1_frame())
        .await
        .unwrap();
    assert!(
        t1.has_connection(&remote).await,
        "the promoted connection is pooled"
    );

    let packet = timeout(Duration::from_secs(2), rx2.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert!(
        t2.has_connection(&packet.remote_addr).await,
        "the accepting side holds the inbound connection by its remote address"
    );

    t1.stop_async().await.unwrap();
    t2.stop_async().await.unwrap();
}

/// A pooled connection that cannot take a frame is still reported, as
/// `send_existing` finds it and fails on the enqueue rather than with
/// `NotConnected`. Holds for a full queue and for a writer that has gone but
/// not yet removed its entry.
#[tokio::test]
async fn has_connection_reports_a_pooled_connection_whose_queue_is_full_or_closed() {
    let (tx, _rx) = packet_channel(100);
    let mut t = TcpTransport::new(TransportId::new(1), None, make_outbound_config(), tx);
    t.start_async().await.unwrap();
    let remote = TransportAddr::from_string("127.0.0.1:9");

    let (send_tx, send_rx) = mpsc::channel(1);
    send_tx.try_send(vec![0]).unwrap();
    t.pool.lock().await.insert(
        PoolKey::outbound(remote.clone()),
        TcpConnection {
            send_tx,
            path_tx: mpsc::channel(1).0,
            send_task: tokio::spawn(async {}),
            recv_task: tokio::spawn(async {}),
            mtu: 1234,
            established_at: Instant::now(),
            direction: Direction::Outbound,
            id: next_conn_id(),
        },
    );

    assert!(
        matches!(
            t.send_existing(&remote, &build_msg1_frame()).await,
            Err(TransportError::SendFailed(_))
        ),
        "a full queue fails the enqueue, not the lookup"
    );
    assert!(
        t.has_connection(&remote).await,
        "a pooled connection with a full queue is reported"
    );

    drop(send_rx);
    assert!(
        matches!(
            t.send_existing(&remote, &build_msg1_frame()).await,
            Err(TransportError::SendFailed(_))
        ),
        "a gone writer fails the enqueue, not the lookup"
    );
    assert!(
        t.has_connection(&remote).await,
        "a pooled connection whose writer has gone is reported"
    );

    t.stop_async().await.unwrap();
}
