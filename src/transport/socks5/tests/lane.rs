//! The path-message lane on the proxied writer: a Tor or Nym connection
//! keeps path messages in a queue apart from its data, which the writer
//! drains first.
//!
//! Each test dials, through a mock SOCKS5 proxy, a raw listener that does
//! not read, so the connection stops draining once the kernel buffers and
//! the proxy's copy between the two ends are full: the writer task waits in
//! `write_all`, and the data queue behind it fills. Frames go through the
//! transport handle's lane send, the one the node uses for every frame on
//! an existing connection. Each rule is checked once for each transport,
//! since each routes its own sends into the shared writer.

use crate::config::{NymConfig, TorConfig};
use crate::transport::nym::NymTransport;
use crate::transport::socks5::mock::MockSocks5Server;
use crate::transport::socks5::{PATH_QUEUE_DEPTH, SEND_QUEUE_DEPTH};
use crate::transport::stream::{PARK_ROUNDS, PARK_SETTLE};
use crate::transport::tor::TorTransport;
use crate::transport::{Lane, TransportAddr, TransportHandle, TransportId, packet_channel};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Bytes in every frame the tests send.
const FRAME: usize = 1400;

/// The first byte of a data frame.
const DATA: u8 = 1;

/// The first byte of a path message.
const PATH: u8 = 2;

/// The most data frames a test offers before it gives up on the writer
/// parking.
const OFFER_LIMIT: usize = 40_000;

/// Which proxied transport a test drives.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Tor,
    Nym,
}

/// A frame of `FRAME` bytes, every byte `tag`, so the far end can tell data
/// from path messages.
fn frame(tag: u8) -> Vec<u8> {
    vec![tag; FRAME]
}

/// A listener whose accepted sockets keep a small receive buffer, so the
/// kernel absorbs little before the proxy's copy waits.
fn deaf_listener() -> TcpListener {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(64 * 1024).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket.listen(8).unwrap()
}

/// A started transport of `kind` dialling through a mock SOCKS5 proxy that
/// forwards to a listener that does not read, and the address it dials.
async fn rig(kind: Kind) -> (TransportHandle, TcpListener, TransportAddr) {
    let listener = deaf_listener();
    let target = listener.local_addr().unwrap();
    let proxy = MockSocks5Server::new(target).await.unwrap();
    let proxy_addr = Some(proxy.addr().to_string());
    let _proxy = proxy.spawn();
    let (tx, _rx) = packet_channel(64);
    let id = TransportId::new(1);
    let mut handle = match kind {
        Kind::Tor => {
            let config = TorConfig {
                socks5_addr: proxy_addr,
                ..Default::default()
            };
            TransportHandle::Tor(TorTransport::new(id, None, config, tx))
        }
        Kind::Nym => {
            let config = NymConfig {
                socks5_addr: proxy_addr,
                startup_timeout_secs: Some(5),
                connect_timeout_ms: Some(5000),
                ..Default::default()
            };
            TransportHandle::Nym(NymTransport::new(id, None, config, tx))
        }
    };
    handle.start().await.unwrap();
    (
        handle,
        listener,
        TransportAddr::from_string(&target.to_string()),
    )
}

/// The send errors the transport behind `handle` has counted.
fn send_errors(handle: &TransportHandle) -> u64 {
    match handle {
        TransportHandle::Tor(t) => t.stats().snapshot().send_errors,
        TransportHandle::Nym(t) => t.stats().snapshot().send_errors,
        _ => unreachable!("the tests build only proxied handles"),
    }
}

/// Offer one data frame on `to`'s existing connection, and say whether it
/// was queued. A send that waits is a defect of its own and fails the test.
async fn offer(handle: &TransportHandle, to: &TransportAddr) -> bool {
    timeout(
        Duration::from_secs(2),
        handle.send_lane(Lane::Data, to, &frame(DATA)),
    )
    .await
    .expect("a send waited on a peer that stopped reading")
    .is_ok()
}

/// Dial `to` with one data frame, then fill the connection's data queue
/// until the writer is parked in `write_all`. Returns the far end, which the
/// test has not read, and how many data frames were queued in all, the
/// dialling one included.
///
/// The writer is parked when a data frame is still refused after a settle
/// interval with nothing sending: the writer took no frame from the full
/// queue in that time, which it can do only while its write waits. A frame
/// accepted after the interval means the writer was still moving, and the
/// fill goes on.
async fn stall(
    handle: &TransportHandle,
    listener: &TcpListener,
    to: &TransportAddr,
) -> (TcpStream, usize) {
    handle
        .send(to, &frame(DATA))
        .await
        .expect("precondition: the dial carries the first frame");
    let (far, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("precondition: the proxy reaches the listener")
        .unwrap();
    let mut queued = 1usize;
    for _ in 0..PARK_ROUNDS {
        while queued < OFFER_LIMIT && offer(handle, to).await {
            queued += 1;
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(PARK_SETTLE).await;
        if !offer(handle, to).await {
            return (far, queued);
        }
        queued += 1;
    }
    panic!("precondition: the writer did not park after {queued} data frames");
}

/// A connection whose data queue is full still takes a path message.
async fn queued_while_data_queue_is_full(kind: Kind) {
    let (mut handle, listener, to) = rig(kind).await;
    let (_far, _) = stall(&handle, &listener, &to).await;

    let path = handle.send_lane(Lane::Path, &to, &frame(PATH)).await;
    assert!(
        path.is_ok(),
        "defect: {kind:?} refused a path message behind a full data queue: {path:?}"
    );
    handle.stop().await.unwrap();
}

/// A waiting path message comes out before every frame still in the data
/// queue.
async fn sent_before_queued_data(kind: Kind) {
    let (mut handle, listener, to) = rig(kind).await;
    let (mut far, queued) = stall(&handle, &listener, &to).await;
    let path = handle.send_lane(Lane::Path, &to, &frame(PATH)).await;
    assert!(
        path.is_ok(),
        "defect: {kind:?} refused the path message, not sending it ahead of the data: {path:?}"
    );

    let mut buf = vec![0u8; FRAME];
    let mut after = None;
    for _ in 0..=queued {
        timeout(Duration::from_secs(10), far.read_exact(&mut buf))
            .await
            .expect("the writer drains once the far end reads")
            .expect("the stream is open");
        match (buf[0], after.as_mut()) {
            (PATH, None) => after = Some(0usize),
            (DATA, Some(n)) => *n += 1,
            (DATA, None) => {}
            (tag, _) => panic!("a frame came out torn or twice: first byte {tag}"),
        }
    }
    let after = after.expect("the path message came out");
    assert!(
        after + 1 >= SEND_QUEUE_DEPTH,
        "defect: on {kind:?} only {after} data frames came out after the path message, \
         though the data queue held {SEND_QUEUE_DEPTH} when it was sent"
    );
    handle.stop().await.unwrap();
}

/// A connection that has stopped draining refuses path messages once their
/// own queue is full.
async fn refused_once_their_queue_is_full(kind: Kind) {
    let (mut handle, listener, to) = rig(kind).await;
    let (_far, _) = stall(&handle, &listener, &to).await;
    let errors = send_errors(&handle);

    let mut accepted = 0;
    while accepted < 256 {
        let sent = handle.send_lane(Lane::Path, &to, &frame(PATH)).await;
        tokio::task::yield_now().await;
        if sent.is_err() {
            break;
        }
        accepted += 1;
    }
    assert_eq!(
        accepted, PATH_QUEUE_DEPTH,
        "a stalled {kind:?} connection took {accepted} path messages, not its queue's depth"
    );
    assert_eq!(
        send_errors(&handle),
        errors + 1,
        "the refusal is counted as a send error"
    );
    handle.stop().await.unwrap();
}

/// A Tor connection whose data queue is full still takes a path message:
/// the two are queued apart, so data the node itself sent cannot crowd out
/// the probes and acks that keep the path's verdict.
#[tokio::test]
async fn a_tor_path_message_is_queued_while_the_connections_data_queue_is_full() {
    queued_while_data_queue_is_full(Kind::Tor).await;
}

/// The Nym form of the Tor test above.
#[tokio::test]
async fn a_nym_path_message_is_queued_while_the_connections_data_queue_is_full() {
    queued_while_data_queue_is_full(Kind::Nym).await;
}

/// The writer sends a waiting path message before the data queued ahead of
/// it: once the far end reads again, every frame still in the data queue
/// comes out after the path message, which waited behind only what the
/// kernel buffers and the proxy already held and the frame being written.
#[tokio::test]
async fn the_tor_writer_sends_a_waiting_path_message_before_the_data_queued_ahead_of_it() {
    sent_before_queued_data(Kind::Tor).await;
}

/// The Nym form of the Tor test above.
#[tokio::test]
async fn the_nym_writer_sends_a_waiting_path_message_before_the_data_queued_ahead_of_it() {
    sent_before_queued_data(Kind::Nym).await;
}

/// A Tor connection that has stopped draining refuses path messages once
/// their own queue is full, as it refuses data. Their queue is bounded, so
/// a probe on such a connection is refused, goes unanswered, and the path
/// still fails over.
#[tokio::test]
async fn a_tor_connection_that_stops_draining_refuses_path_messages_once_their_queue_is_full() {
    refused_once_their_queue_is_full(Kind::Tor).await;
}

/// The Nym form of the Tor test above.
#[tokio::test]
async fn a_nym_connection_that_stops_draining_refuses_path_messages_once_their_queue_is_full() {
    refused_once_their_queue_is_full(Kind::Nym).await;
}
