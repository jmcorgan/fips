//! The receive bound on a TCP connection whose kernel MSS is below the
//! configured MTU.
//!
//! A TCP stream does not tie a frame to a segment, so a frame the peer's
//! sender admits (up to the configured MTU) must be delivered whatever the
//! connection's `TCP_MAXSEG`. Each test clamps the MSS with `TCP_MAXSEG` on a
//! raw socket on the far side, then checks that a frame above the clamp but
//! within the configured MTU is delivered without a receive error, on each of
//! the three ways a connection is set up: accepted, dialled by
//! connect-on-send, and dialled in the background.
//!
//! Linux only: elsewhere the transport never reads the MSS.

use super::*;
use crate::testutil::wait_until;
use crate::transport::framing::build_established_frame;
use crate::transport::packet_channel;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

/// The MTU every transport under test is configured with.
const CONFIGURED_MTU: u16 = 1400;

/// The `TCP_MAXSEG` the far side clamps its socket to, below the MTU.
const CLAMPED_MSS: u32 = 1300;

/// A frame below the clamp, delivered whether or not the bound is the MSS.
const SMALL_FRAME: u16 = 1280;

fn listener_config() -> TcpConfig {
    TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(CONFIGURED_MTU),
        ..Default::default()
    }
}

fn outbound_config() -> TcpConfig {
    TcpConfig {
        bind_addr: None,
        mtu: Some(CONFIGURED_MTU),
        ..Default::default()
    }
}

/// An established frame of exactly `len` bytes.
fn frame(len: u16) -> Vec<u8> {
    let frame = build_established_frame(len - 32);
    assert_eq!(frame.len(), len as usize);
    frame
}

/// A raw client connected to `addr`, with its MSS clamped when asked.
fn raw_client(addr: SocketAddr, mss: Option<u32>) -> tokio::net::TcpStream {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    if let Some(mss) = mss {
        sock.set_tcp_mss(mss).unwrap();
    }
    sock.connect(&addr.into()).unwrap();
    sock.set_nonblocking(true).unwrap();
    tokio::net::TcpStream::from_std(sock.into()).unwrap()
}

/// A raw listener whose MSS is clamped before `listen`, so the SYN-ACK
/// advertises the clamp and every accepted socket inherits it.
fn clamped_listener(mss: u32) -> (tokio::net::TcpListener, SocketAddr) {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    sock.set_tcp_mss(mss).unwrap();
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    sock.bind(&bind.into()).unwrap();
    sock.listen(8).unwrap();
    sock.set_nonblocking(true).unwrap();
    let std_listener: std::net::TcpListener = sock.into();
    let addr = std_listener.local_addr().unwrap();
    (
        tokio::net::TcpListener::from_std(std_listener).unwrap(),
        addr,
    )
}

/// Write a frame of `len` bytes from the far side and report whether the
/// transport delivered it, and how many receive errors it recorded meanwhile.
/// The count is a difference because the counter is per transport and a
/// connection closed earlier in the test counts its EOF there.
async fn deliver(
    t: &TcpTransport,
    rx: &mut crate::transport::PacketRx,
    far: &mut tokio::net::TcpStream,
    len: u16,
) -> (bool, u64) {
    let errors_before = t.stats().snapshot().recv_errors;
    far.write_all(&frame(len)).await.unwrap();
    let delivered = timeout(Duration::from_millis(500), rx.recv())
        .await
        .ok()
        .flatten()
        .is_some_and(|p| p.data.len() == len as usize);
    tokio::time::sleep(Duration::from_millis(50)).await;
    (delivered, t.stats().snapshot().recv_errors - errors_before)
}

/// The per-connection value read from `TCP_MAXSEG` at setup, for the only
/// pooled connection. Asserting it is below the frame under test shows the
/// clamp took effect, so the test is not passing on an unclamped link.
async fn pooled_mss(t: &TcpTransport) -> u16 {
    let pool = t.pool.lock().await;
    assert_eq!(pool.len(), 1, "expected exactly one pooled connection");
    pool.values().next().unwrap().mtu
}

/// Send a small frame, then a frame above the clamped MSS but within the
/// configured MTU, and assert both are delivered without a receive error.
async fn assert_delivers(
    t: &TcpTransport,
    rx: &mut crate::transport::PacketRx,
    far: &mut tokio::net::TcpStream,
) {
    assert_eq!(
        deliver(t, rx, far, SMALL_FRAME).await,
        (true, 0),
        "control: a frame below the clamp is delivered"
    );
    let mss_mtu = pooled_mss(t).await;
    assert!(
        mss_mtu < CONFIGURED_MTU,
        "precondition: the clamp must hold the connection's MSS below the MTU, read {mss_mtu}"
    );
    assert_eq!(
        deliver(t, rx, far, CONFIGURED_MTU).await,
        (true, 0),
        "a {CONFIGURED_MTU}-byte frame above the {mss_mtu}-byte MSS must be delivered"
    );
}

#[tokio::test]
async fn test_tcp_frame_larger_than_the_local_mss_but_within_the_configured_mtu_is_delivered() {
    // Accepted connections: the client's clamp sets the MSS the listener's
    // socket reads.
    let (tx, mut rx) = packet_channel(10);
    let mut t = TcpTransport::new(TransportId::new(1), None, listener_config(), tx);
    t.start_async().await.unwrap();
    let addr = t.local_addr().unwrap();

    // Control: an unclamped client's full-size frame is delivered.
    let mut unclamped = raw_client(addr, None);
    assert_eq!(
        deliver(&t, &mut rx, &mut unclamped, CONFIGURED_MTU).await,
        (true, 0),
        "control: an unclamped connection delivers a full-size frame"
    );
    drop(unclamped);
    assert!(
        wait_until(
            || t.pool.try_lock().is_ok_and(|p| p.is_empty()),
            Duration::from_secs(2)
        )
        .await,
        "the unclamped connection must leave the pool"
    );

    let mut clamped = raw_client(addr, Some(CLAMPED_MSS));
    assert_delivers(&t, &mut rx, &mut clamped).await;

    t.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_tcp_frame_larger_than_the_local_mss_is_delivered_on_a_connect_on_send_connection() {
    let (tx, mut rx) = packet_channel(10);
    let mut t = TcpTransport::new(TransportId::new(1), None, outbound_config(), tx);
    t.start_async().await.unwrap();
    let (listener, addr) = clamped_listener(CLAMPED_MSS);
    let remote = TransportAddr::from_string(&addr.to_string());

    // No connection exists, so this send dials.
    t.send_async(&remote, &frame(64)).await.unwrap();
    let (mut far, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("the transport dials the listener")
        .unwrap();
    assert_delivers(&t, &mut rx, &mut far).await;

    t.stop_async().await.unwrap();
}

#[tokio::test]
async fn test_tcp_frame_larger_than_the_local_mss_is_delivered_on_a_background_connection() {
    let (tx, mut rx) = packet_channel(10);
    let mut t = TcpTransport::new(TransportId::new(1), None, outbound_config(), tx);
    t.start_async().await.unwrap();
    let (listener, addr) = clamped_listener(CLAMPED_MSS);
    let remote = TransportAddr::from_string(&addr.to_string());

    t.connect_async(&remote).await.unwrap();
    let (mut far, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("the transport dials the listener")
        .unwrap();
    assert!(
        wait_until(
            || t.connection_state_sync(&remote) == ConnectionState::Connected,
            Duration::from_secs(2)
        )
        .await,
        "the background connect must be promoted"
    );
    assert_delivers(&t, &mut rx, &mut far).await;

    t.stop_async().await.unwrap();
}
