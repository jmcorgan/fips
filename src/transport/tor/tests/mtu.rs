//! The receive bound on a Tor connection whose peer is configured with a
//! larger `mtu`.
//!
//! A Tor sender's `check_mtu` admits every frame up to its own `mtu`, and
//! nothing tells it the peer's. The receiving end reads every Tor
//! connection through the shared `proxied_receive_loop`, which is bounded
//! by the receiver's own `mtu`. Each test sets two ends up with different
//! `mtu` values and checks that a frame between the two, sent by the end
//! with the larger value, reaches the other end without a receive error and
//! without closing the connection. Two Tor ends are checked both ways round
//! (the frame arriving on the onion listener, and on the dialling end), and
//! a Tor end that dials a FIPS TCP listener configured higher. The last test
//! is the control for the other half of that mixed link, which the TCP
//! module's fixed receive ceiling already covers.

use super::*;
use crate::config::{DirectoryServiceConfig, TcpConfig};
use crate::transport::framing::build_established_frame;
use crate::transport::socks5::mock::MockSocks5Server;
use crate::transport::tcp::TcpTransport;
use crate::transport::{PacketRx, ReceivedPacket, packet_channel};
use tempfile::TempDir;
use tokio::time::timeout;

/// The `mtu` of the receiving end.
const SMALL_MTU: u16 = 1400;

/// The `mtu` of the sending end, above the receiver's.
const LARGE_MTU: u16 = 1500;

/// The onion address the listening end reads from its hostname file.
const ONION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.onion";

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

/// A loopback port free at the time of the call.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A started Tor transport in directory mode with the given `mtu`: its
/// onion-service listener is bound on loopback, standing in for the local
/// port Tor forwards the onion service to. Returns the transport, its
/// packet channel and the listener's address.
async fn onion_listener(
    id: u32,
    mtu: u16,
    dir: &TempDir,
) -> (TorTransport, PacketRx, std::net::SocketAddr) {
    let hostname = dir.path().join("hostname");
    std::fs::write(&hostname, format!("{ONION}\n")).unwrap();
    let listen: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let config = TorConfig {
        mode: Some("directory".to_string()),
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        mtu: Some(mtu),
        directory_service: Some(DirectoryServiceConfig {
            hostname_file: Some(hostname.to_str().unwrap().to_string()),
            bind_addr: Some(listen.to_string()),
        }),
        ..Default::default()
    };
    let (tx, rx) = packet_channel(32);
    let mut t = TorTransport::new(TransportId::new(id), None, config, tx);
    t.start_async().await.unwrap();
    (t, rx, listen)
}

/// A started Tor transport in socks5 mode with the given `mtu`, whose
/// SOCKS5 proxy is a mock that connects every request to `target`.
async fn dialler(id: u32, mtu: u16, target: std::net::SocketAddr) -> (TorTransport, PacketRx) {
    let mock = MockSocks5Server::new(target).await.unwrap();
    let proxy = mock.addr();
    let _proxy = mock.spawn();
    let config = TorConfig {
        socks5_addr: Some(proxy.to_string()),
        mtu: Some(mtu),
        ..Default::default()
    };
    let (tx, rx) = packet_channel(32);
    let mut t = TorTransport::new(TransportId::new(id), None, config, tx);
    t.start_async().await.unwrap();
    (t, rx)
}

/// A started TCP transport listening on loopback with the given `mtu`.
async fn tcp_listener(id: u32, mtu: u16) -> (TcpTransport, PacketRx, std::net::SocketAddr) {
    let config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(mtu),
        ..Default::default()
    };
    let (tx, rx) = packet_channel(32);
    let mut t = TcpTransport::new(TransportId::new(id), None, config, tx);
    t.start_async().await.unwrap();
    let listen = t.local_addr().unwrap();
    (t, rx, listen)
}

/// The onion address the dialling end sends to.
fn onion_target() -> TransportAddr {
    TransportAddr::from_string(&format!("{ONION}:443"))
}

/// What a Tor receiver did with a frame of `len` bytes: whether it
/// delivered it, how many receive errors it recorded since `errors_before`,
/// and how many connections it still holds.
async fn tor_outcome(
    t: &TorTransport,
    rx: &mut PacketRx,
    len: u16,
    errors_before: u64,
) -> (bool, u64, usize) {
    let delivered = received(rx, len).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    (
        delivered,
        t.stats().snapshot().recv_errors - errors_before,
        t.pool.lock().await.len(),
    )
}

/// A 1500-`mtu` Tor end dials a 1400-`mtu` Tor end's onion listener: a
/// 1500-byte frame, which the sender admits, must reach the listener on the
/// connection it accepted, with no receive error and the connection kept.
#[tokio::test]
async fn tor_frame_above_the_receivers_mtu_from_a_tor_peer_configured_higher_is_delivered_on_the_onion_listener()
 {
    let dir = TempDir::new().unwrap();
    let (receiver, mut rx, listen) = onion_listener(1, SMALL_MTU, &dir).await;
    let (sender, _sender_rx) = dialler(2, LARGE_MTU, listen).await;
    let to = onion_target();

    sender.send_async(&to, &frame(SMALL_MTU)).await.unwrap();
    assert!(
        received(&mut rx, SMALL_MTU).await,
        "precondition: a {SMALL_MTU}-byte frame within both mtu values is delivered"
    );

    let before = receiver.stats().snapshot().recv_errors;
    sender
        .send_async(&to, &frame(LARGE_MTU))
        .await
        .expect("the sender admits a frame within its own mtu");
    assert_eq!(
        tor_outcome(&receiver, &mut rx, LARGE_MTU, before).await,
        (true, 0, 1),
        "defect: (delivered, receive errors, pooled connections): a {LARGE_MTU}-byte frame the \
         {LARGE_MTU}-mtu Tor sender admits must reach the {SMALL_MTU}-mtu onion listener \
         without a receive error, on a connection it keeps"
    );
}

/// A 1400-`mtu` Tor end dials a 1500-`mtu` Tor end's onion listener, which
/// answers on the connection it accepted: a 1500-byte answer must reach the
/// dialling end with no receive error and the connection kept.
#[tokio::test]
async fn tor_frame_above_the_receivers_mtu_from_a_tor_peer_configured_higher_is_delivered_on_a_dialled_connection()
 {
    let dir = TempDir::new().unwrap();
    let (sender, mut sender_rx, listen) = onion_listener(1, LARGE_MTU, &dir).await;
    let (receiver, mut rx) = dialler(2, SMALL_MTU, listen).await;

    receiver
        .send_async(&onion_target(), &frame(SMALL_MTU))
        .await
        .unwrap();
    let reply_to = next(&mut sender_rx)
        .await
        .expect("the onion listener receives the dialler's first frame")
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
        .expect("the sender admits a frame within its own mtu");
    assert_eq!(
        tor_outcome(&receiver, &mut rx, LARGE_MTU, before).await,
        (true, 0, 1),
        "defect: (delivered, receive errors, pooled connections): a {LARGE_MTU}-byte frame the \
         {LARGE_MTU}-mtu onion listener admits must reach the {SMALL_MTU}-mtu dialler \
         without a receive error, on a connection it keeps"
    );
}

/// A 1400-`mtu` Tor end dials a 1500-`mtu` FIPS TCP listener through SOCKS5,
/// and the listener answers: a 1500-byte answer must reach the Tor end with
/// no receive error and the connection kept.
#[tokio::test]
async fn tor_frame_above_its_mtu_from_a_tcp_listener_configured_higher_is_delivered() {
    let (sender, mut sender_rx, listen) = tcp_listener(1, LARGE_MTU).await;
    let (receiver, mut rx) = dialler(2, SMALL_MTU, listen).await;

    receiver
        .send_async(
            &TransportAddr::from_string(&listen.to_string()),
            &frame(SMALL_MTU),
        )
        .await
        .unwrap();
    let reply_to = next(&mut sender_rx)
        .await
        .expect("the TCP listener receives the Tor end's first frame")
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
    assert_eq!(
        tor_outcome(&receiver, &mut rx, LARGE_MTU, before).await,
        (true, 0, 1),
        "defect: (delivered, receive errors, pooled connections): a {LARGE_MTU}-byte frame the \
         {LARGE_MTU}-mtu TCP listener admits must reach the {SMALL_MTU}-mtu Tor end \
         without a receive error, on a connection it keeps"
    );
}

/// Control for the other half of the mixed link: a 1500-`mtu` Tor end
/// dials a 1400-`mtu` FIPS TCP listener, whose receive loop accepts frames
/// up to its fixed ceiling, so the 1500-byte frame is delivered.
#[tokio::test]
async fn tcp_listener_configured_lower_delivers_a_frame_from_a_tor_dialler_configured_higher() {
    let (receiver, mut rx, listen) = tcp_listener(1, SMALL_MTU).await;
    let (sender, _sender_rx) = dialler(2, LARGE_MTU, listen).await;
    let to = TransportAddr::from_string(&listen.to_string());

    sender.send_async(&to, &frame(SMALL_MTU)).await.unwrap();
    assert!(received(&mut rx, SMALL_MTU).await);
    sender.send_async(&to, &frame(LARGE_MTU)).await.unwrap();
    assert!(
        received(&mut rx, LARGE_MTU).await,
        "the TCP listener must deliver a {LARGE_MTU}-byte frame from the Tor dialler"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(receiver.stats().snapshot().recv_errors, 0);
}
