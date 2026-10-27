//! The receive bound on a TCP connection whose peer is configured with a
//! larger `mtu`.
//!
//! Nothing tells a TCP sender its peer's configured `mtu`, so a sender
//! admits every frame up to its own. Each test sets two transports up with
//! different `mtu` values and checks that a frame between the two, sent by
//! the end with the larger value, reaches the other end without a receive
//! error and without closing the connection, on each of the three ways the
//! receiving end can hold the connection: accepted, dialled by
//! connect-on-send, and dialled in the background.

use super::*;
use crate::testutil::wait_until;
use crate::transport::framing::build_established_frame;
use crate::transport::{PacketRx, ReceivedPacket, packet_channel};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

/// The `mtu` of the receiving end.
const SMALL_MTU: u16 = 1400;

/// The `mtu` of the sending end, above the receiver's.
const LARGE_MTU: u16 = 1500;

/// An established frame of exactly `len` bytes.
fn frame(len: u16) -> Vec<u8> {
    let frame = build_established_frame(len - 32);
    assert_eq!(frame.len(), len as usize);
    frame
}

/// A started transport with the given `mtu`, listening on loopback when
/// `listen` is set and outbound only otherwise.
async fn transport(id: u32, mtu: u16, listen: bool) -> (TcpTransport, PacketRx) {
    let config = TcpConfig {
        bind_addr: listen.then(|| "127.0.0.1:0".to_string()),
        mtu: Some(mtu),
        ..Default::default()
    };
    let (tx, rx) = packet_channel(10);
    let mut t = TcpTransport::new(TransportId::new(id), None, config, tx);
    t.start_async().await.unwrap();
    (t, rx)
}

/// The next packet `rx` delivers within five seconds, if any. A delivered
/// packet returns at once, so the wait costs time only when nothing comes.
async fn next(rx: &mut PacketRx) -> Option<ReceivedPacket> {
    timeout(Duration::from_secs(5), rx.recv())
        .await
        .ok()
        .flatten()
}

/// Send a frame of `len` bytes from `sender` to `to` and report whether
/// `receiver` delivered it, and how many receive errors `receiver` recorded
/// meanwhile.
async fn deliver(
    sender: &TcpTransport,
    to: &TransportAddr,
    receiver: &TcpTransport,
    rx: &mut PacketRx,
    len: u16,
) -> (bool, u64) {
    let errors_before = receiver.stats().snapshot().recv_errors;
    sender
        .send_async(to, &frame(len))
        .await
        .expect("the sender admits a frame within its own mtu");
    let delivered = next(rx).await.is_some_and(|p| p.data.len() == len as usize);
    tokio::time::sleep(Duration::from_millis(50)).await;
    (
        delivered,
        receiver.stats().snapshot().recv_errors - errors_before,
    )
}

/// The number of connections in `t`'s pool.
async fn pooled(t: &TcpTransport) -> usize {
    t.pool.lock().await.len()
}

/// Send a frame within both values, then one above the receiver's `mtu`
/// but within the sender's, then another within both, and assert all three
/// are delivered without a receive error on the one connection the test set
/// up.
async fn assert_carries(
    sender: &TcpTransport,
    to: &TransportAddr,
    receiver: &TcpTransport,
    rx: &mut PacketRx,
) {
    assert_eq!(
        deliver(sender, to, receiver, rx, SMALL_MTU).await,
        (true, 0),
        "control: a {SMALL_MTU}-byte frame within both mtu values is delivered"
    );
    assert_eq!(
        deliver(sender, to, receiver, rx, LARGE_MTU).await,
        (true, 0),
        "a {LARGE_MTU}-byte frame the {LARGE_MTU}-mtu sender admits must reach the \
         {SMALL_MTU}-mtu receiver without a receive error"
    );
    assert_eq!(
        pooled(receiver).await,
        1,
        "the receiver must keep the connection the larger frame arrived on"
    );
    assert_eq!(
        deliver(sender, to, receiver, rx, SMALL_MTU).await,
        (true, 0),
        "the link must still carry frames after the larger one"
    );
    assert_eq!(
        sender.stats().snapshot().connections_established
            + receiver.stats().snapshot().connections_established,
        1,
        "every frame must travel on the one connection, without a redial"
    );
}

/// A 1500-`mtu` sender dials a 1400-`mtu` listener: a 1500-byte frame
/// reaches the listener on the connection it accepted, between two
/// 1400-byte frames, with no receive error and no redial.
#[tokio::test]
async fn test_tcp_frame_above_the_receivers_mtu_but_within_the_senders_is_delivered_on_an_accepted_connection()
 {
    let (receiver, mut rx) = transport(1, SMALL_MTU, true).await;
    let (sender, _sender_rx) = transport(2, LARGE_MTU, false).await;
    let to = TransportAddr::from_string(&receiver.local_addr().unwrap().to_string());

    assert_carries(&sender, &to, &receiver, &mut rx).await;
    assert_eq!(receiver.stats().snapshot().connections_accepted, 1);
}

/// The receiver dials the sender. The first frame, from the receiver,
/// opens the connection; the sender then answers on the connection it
/// accepted, addressed to the receiver's ephemeral port.
async fn reply_address(
    dialler: &TcpTransport,
    listener: &TcpTransport,
    listener_rx: &mut PacketRx,
) -> TransportAddr {
    let at = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
    dialler.send_existing(&at, &frame(64)).await.unwrap();
    next(listener_rx)
        .await
        .expect("the listener receives the dialler's first frame")
        .remote_addr
}

/// The 1400-`mtu` end dials the 1500-`mtu` listener by connect-on-send,
/// and the listener's 1500-byte frame reaches it on that outbound
/// connection with no receive error and no redial.
#[tokio::test]
async fn test_tcp_frame_above_the_receivers_mtu_but_within_the_senders_is_delivered_on_a_connect_on_send_connection()
 {
    let (receiver, mut rx) = transport(1, SMALL_MTU, false).await;
    let (sender, mut sender_rx) = transport(2, LARGE_MTU, true).await;
    let at = TransportAddr::from_string(&sender.local_addr().unwrap().to_string());

    // No connection exists, so this send dials.
    receiver.send_async(&at, &frame(64)).await.unwrap();
    let to = next(&mut sender_rx)
        .await
        .expect("the sender receives the receiver's first frame")
        .remote_addr;

    assert_carries(&sender, &to, &receiver, &mut rx).await;
}

/// As on a connect-on-send connection, with the 1400-`mtu` end dialling
/// in the background with `connect_async`.
#[tokio::test]
async fn test_tcp_frame_above_the_receivers_mtu_but_within_the_senders_is_delivered_on_a_background_connection()
 {
    let (receiver, mut rx) = transport(1, SMALL_MTU, false).await;
    let (sender, mut sender_rx) = transport(2, LARGE_MTU, true).await;
    let at = TransportAddr::from_string(&sender.local_addr().unwrap().to_string());

    receiver.connect_async(&at).await.unwrap();
    assert!(
        wait_until(
            || receiver.connection_state_sync(&at) == ConnectionState::Connected,
            Duration::from_secs(2)
        )
        .await,
        "the background connect must be promoted"
    );
    let to = reply_address(&receiver, &sender, &mut sender_rx).await;

    assert_carries(&sender, &to, &receiver, &mut rx).await;
}

/// A 65535-byte frame reaches a 1400-`mtu` receiver, and a length prefix
/// claiming one payload byte more closes the connection with one receive
/// error.
#[tokio::test]
async fn test_tcp_frame_of_the_largest_admissible_size_is_delivered_and_one_byte_more_closes_the_connection()
 {
    // The largest frame any sender can admit is u16::MAX bytes, a payload of
    // u16::MAX - 32, because `mtu` is a u16 and `check_mtu` admits no frame
    // longer than the sender's `mtu`. It is delivered to a receiver
    // configured far below it. A frame claiming one payload byte more is
    // beyond every peer's `mtu`, so the receiver refuses it before
    // allocating and closes the connection.
    let (receiver, mut rx) = transport(1, SMALL_MTU, true).await;
    let mut far = tokio::net::TcpStream::connect(receiver.local_addr().unwrap())
        .await
        .unwrap();
    far.write_all(&frame(u16::MAX)).await.unwrap();
    assert!(
        next(&mut rx)
            .await
            .is_some_and(|p| p.data.len() == u16::MAX as usize),
        "a {}-byte frame must be delivered to a {SMALL_MTU}-mtu receiver",
        u16::MAX
    );
    assert_eq!(receiver.stats().snapshot().recv_errors, 0);

    let mut prefix = frame(64)[..4].to_vec();
    prefix[2..4].copy_from_slice(&(u16::MAX - 31).to_le_bytes());
    far.write_all(&prefix).await.unwrap();
    assert!(
        wait_until(
            || receiver.pool.try_lock().is_ok_and(|p| p.is_empty()),
            Duration::from_secs(2)
        )
        .await,
        "the receiver must close a connection whose frame exceeds every sender's mtu"
    );
    assert_eq!(receiver.stats().snapshot().recv_errors, 1);
}
