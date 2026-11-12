//! The receive bound on a Nym connection whose peer is configured with a
//! larger `mtu`.
//!
//! Nym binds no listener, so the only mixed-`mtu` case is a Nym end that
//! dials a FIPS TCP listener through its SOCKS5 proxy. The TCP sender's
//! `check_mtu` admits every frame up to its own `mtu`, and the Nym end reads
//! the connection through the shared `proxied_receive_loop`, bounded by its
//! own `mtu`. The test checks that a frame between the two values reaches
//! the Nym end without a receive error and without closing the connection.

use super::*;
use crate::config::TcpConfig;
use crate::transport::framing::build_established_frame;
use crate::transport::socks5::mock::MockSocks5Server;
use crate::transport::tcp::TcpTransport;
use crate::transport::{PacketRx, ReceivedPacket, packet_channel};
use tokio::time::{Duration, timeout};

/// The `mtu` of the receiving Nym end.
const SMALL_MTU: u16 = 1400;

/// The `mtu` of the sending TCP listener, above the receiver's.
const LARGE_MTU: u16 = 1500;

/// An established frame of exactly `len` bytes.
fn frame(len: u16) -> Vec<u8> {
    let frame = build_established_frame(len - 32);
    assert_eq!(frame.len(), len as usize);
    frame
}

/// The next packet `rx` delivers within five seconds, if any.
async fn next(rx: &mut PacketRx) -> Option<ReceivedPacket> {
    timeout(Duration::from_secs(5), rx.recv())
        .await
        .ok()
        .flatten()
}

/// Whether `rx` delivers a packet of `len` bytes within five seconds.
async fn received(rx: &mut PacketRx, len: u16) -> bool {
    next(rx).await.is_some_and(|p| p.data.len() == len as usize)
}

/// A 1400-`mtu` Nym end dials a 1500-`mtu` FIPS TCP listener through SOCKS5,
/// and the listener answers: a 1500-byte answer must reach the Nym end with
/// no receive error and the connection kept.
#[tokio::test]
async fn nym_frame_above_its_mtu_from_a_tcp_listener_configured_higher_is_delivered() {
    let (tcp_tx, mut tcp_rx) = packet_channel(32);
    let mut sender = TcpTransport::new(
        TransportId::new(1),
        None,
        TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(LARGE_MTU),
            ..Default::default()
        },
        tcp_tx,
    );
    sender.start_async().await.unwrap();
    let listen = sender.local_addr().unwrap();

    let mock = MockSocks5Server::new(listen).await.unwrap();
    let proxy = mock.addr();
    let _proxy = mock.spawn();
    let (tx, mut rx) = packet_channel(32);
    let mut receiver = NymTransport::new(
        TransportId::new(2),
        None,
        NymConfig {
            socks5_addr: Some(proxy.to_string()),
            startup_timeout_secs: Some(5),
            connect_timeout_ms: Some(5000),
            mtu: Some(SMALL_MTU),
        },
        tx,
    );
    receiver.start_async().await.unwrap();

    receiver
        .send_async(
            &TransportAddr::from_string(&listen.to_string()),
            &frame(SMALL_MTU),
        )
        .await
        .unwrap();
    let reply_to = next(&mut tcp_rx)
        .await
        .expect("the TCP listener receives the Nym end's first frame")
        .remote_addr;

    sender
        .send_async(&reply_to, &frame(SMALL_MTU))
        .await
        .unwrap();
    assert!(
        received(&mut rx, SMALL_MTU).await,
        "precondition: a {SMALL_MTU}-byte frame within both mtu values is delivered"
    );

    let before = receiver.stats().snapshot().recv_errors;
    sender
        .send_async(&reply_to, &frame(LARGE_MTU))
        .await
        .expect("the TCP sender admits a frame within its own mtu");
    let delivered = received(&mut rx, LARGE_MTU).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        (
            delivered,
            receiver.stats().snapshot().recv_errors - before,
            receiver.pool.lock().await.len(),
        ),
        (true, 0, 1),
        "defect: (delivered, receive errors, pooled connections): a {LARGE_MTU}-byte frame the \
         {LARGE_MTU}-mtu TCP listener admits must reach the {SMALL_MTU}-mtu Nym end \
         without a receive error, on a connection it keeps"
    );
}
