//! The path-message lane: a TCP connection keeps path messages in a queue
//! apart from its data, which the writer drains first.
//!
//! Each test dials a raw listener that does not read, so the connection
//! stops draining once the kernel buffers between the two ends are full: the
//! writer task waits in `write_all`, and the data queue behind it fills.
//! Frames go through the transport handle's lane send, the one the node uses
//! for every frame on an existing connection.

use super::*;
use crate::transport::stream::park_writer;
use crate::transport::{Lane, TransportHandle, packet_channel};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

/// Bytes in every frame the tests send.
const FRAME: usize = 1400;

/// The first byte of a data frame.
const DATA: u8 = 1;

/// The first byte of a path message.
const PATH: u8 = 2;

/// A frame of `FRAME` bytes, every byte `tag`, so the far end can tell data
/// from path messages.
fn frame(tag: u8) -> Vec<u8> {
    vec![tag; FRAME]
}

/// A listener whose accepted sockets keep a small receive buffer, so the
/// kernel absorbs little before the writer waits.
fn deaf_listener() -> TcpListener {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(64 * 1024).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket.listen(8).unwrap()
}

/// A started TCP transport with no listener, behind its handle.
async fn transport() -> TransportHandle {
    let (tx, _rx) = packet_channel(64);
    let config = TcpConfig {
        bind_addr: None,
        mtu: Some(FRAME as u16),
        send_buf_size: Some(64 * 1024),
        ..Default::default()
    };
    let mut handle = TransportHandle::Tcp(TcpTransport::new(TransportId::new(1), None, config, tx));
    handle.start().await.unwrap();
    handle
}

/// The TCP transport behind `handle`.
fn tcp(handle: &TransportHandle) -> &TcpTransport {
    match handle {
        TransportHandle::Tcp(t) => t,
        _ => unreachable!("the tests build only TCP handles"),
    }
}

/// Dial `listener` with one data frame, then fill the connection's data
/// queue until the writer is parked in `write_all`. Returns the far end,
/// which the test has not read, and how many data frames were queued in
/// all, the dialling one included.
async fn stall(handle: &TransportHandle, listener: &TcpListener) -> (TcpStream, usize) {
    let to = addr(listener);
    handle
        .send(&to, &frame(DATA))
        .await
        .expect("precondition: the dial carries the first frame");
    let (far, _) = listener.accept().await.unwrap();
    let t = tcp(handle);
    let queued = park_writer(
        async || match timeout(
            Duration::from_secs(2),
            handle.send_lane(Lane::Data, &to, &frame(DATA)),
        )
        .await
        {
            Ok(sent) => sent.is_ok(),
            Err(_) => panic!("a send waited on a peer that stopped reading"),
        },
        async || {
            let pool = t.pool.lock().await;
            key_for_remote(&pool, &to).and_then(|key| pool.get(&key).map(|c| c.send_tx.capacity()))
        },
    )
    .await;
    (far, queued + 1)
}

/// The address `listener` is dialled at.
fn addr(listener: &TcpListener) -> TransportAddr {
    TransportAddr::from_string(&listener.local_addr().unwrap().to_string())
}

/// A connection whose data queue is full still takes a path message: the
/// two are queued apart, so data the node itself sent cannot crowd out the
/// probes and acks that keep the path's verdict.
#[tokio::test]
async fn a_path_message_is_queued_while_the_connections_data_queue_is_full() {
    let mut handle = transport().await;
    let listener = deaf_listener();
    let (_far, _) = stall(&handle, &listener).await;

    let path = handle
        .send_lane(Lane::Path, &addr(&listener), &frame(PATH))
        .await;
    assert!(
        path.is_ok(),
        "defect: a path message was refused behind a full data queue: {path:?}"
    );
    handle.stop().await.unwrap();
}

/// The writer sends a waiting path message before the data queued ahead of
/// it: once the far end reads again, every frame still in the data queue
/// comes out after the path message, which waited behind only what was
/// already in the kernel buffers and the frame being written.
#[tokio::test]
async fn the_writer_sends_a_waiting_path_message_before_the_data_queued_ahead_of_it() {
    let mut handle = transport().await;
    let listener = deaf_listener();
    let (mut far, queued) = stall(&handle, &listener).await;
    let path = handle
        .send_lane(Lane::Path, &addr(&listener), &frame(PATH))
        .await;
    assert!(
        path.is_ok(),
        "defect: the path message was refused, not sent ahead of the data: {path:?}"
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
        after + 1 >= pool::SEND_QUEUE_DEPTH,
        "defect: only {after} data frames came out after the path message, \
         though the data queue held {} when it was sent",
        pool::SEND_QUEUE_DEPTH
    );
    handle.stop().await.unwrap();
}

/// A connection that has stopped draining refuses path messages once their
/// own queue is full, as it refuses data. Their queue is bounded, so a
/// probe on such a connection is refused, goes unanswered, and the path
/// still fails over.
#[tokio::test]
async fn a_connection_that_stops_draining_refuses_path_messages_once_their_queue_is_full() {
    let mut handle = transport().await;
    let listener = deaf_listener();
    let (_far, _) = stall(&handle, &listener).await;
    let errors = tcp(&handle).stats().snapshot().send_errors;

    let mut accepted = 0;
    while accepted < 256 {
        let sent = handle
            .send_lane(Lane::Path, &addr(&listener), &frame(PATH))
            .await;
        tokio::task::yield_now().await;
        if sent.is_err() {
            break;
        }
        accepted += 1;
    }
    assert_eq!(
        accepted,
        pool::PATH_QUEUE_DEPTH,
        "a stalled connection took {accepted} path messages, not its queue's depth"
    );
    assert_eq!(
        tcp(&handle).stats().snapshot().send_errors,
        errors + 1,
        "the refusal is counted as a send error"
    );
    handle.stop().await.unwrap();
}
