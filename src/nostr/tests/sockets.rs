//! Tests of the machine's sockets on loopback: a socket's datagrams reach
//! the pump's channel, sends go out, and a send that fails is reported.

use std::time::Duration;

use super::*;
use crate::nostr::machine::rendezvous::{Input, SocketId};

const SOON: Duration = Duration::from_secs(5);

#[tokio::test]
async fn a_socket_pump_forwards_datagrams_and_sends_what_it_is_given() {
    let (datagrams, mut received) = mpsc::channel(DATAGRAM_BACKLOG);
    let (inbox, _rx) = mpsc::unbounded_channel();
    let mut sockets = Sockets::new(datagrams, inbox);
    let socket = SocketId(1);
    let Input::SocketBound {
        socket: bound,
        local,
    } = sockets.bind(socket)
    else {
        panic!("the socket did not bind");
    };
    assert_eq!(bound, socket);
    assert!(local.ip().is_unspecified(), "bound on the wildcard");

    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sockets.send(socket, peer.local_addr().unwrap(), b"out".to_vec());
    let mut buf = [0u8; 16];
    let (len, from) = tokio::time::timeout(SOON, peer.recv_from(&mut buf))
        .await
        .expect("the send arrived within the wait")
        .unwrap();
    assert_eq!(&buf[..len], b"out");
    assert_eq!(from.port(), local.port());
    peer.send_to(b"in", ("127.0.0.1", local.port()))
        .await
        .unwrap();

    let (on, src, bytes) = tokio::time::timeout(SOON, received.recv())
        .await
        .expect("a datagram within the wait")
        .expect("the channel is open");
    assert_eq!(on, socket);
    assert_eq!(src.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
    assert_eq!(bytes, b"in");
    sockets.release(socket);
}

#[tokio::test]
async fn a_send_that_fails_is_reported_with_its_error() {
    let (datagrams, _received) = mpsc::channel(DATAGRAM_BACKLOG);
    let (inbox, mut rx) = mpsc::unbounded_channel();
    let mut sockets = Sockets::new(datagrams, inbox);
    let socket = SocketId(1);
    assert!(matches!(sockets.bind(socket), Input::SocketBound { .. }));
    // A broadcast address without SO_BROADCAST: the send fails at once.
    let dst: SocketAddr = "255.255.255.255:9".parse().unwrap();
    sockets.send(socket, dst, b"x".to_vec());
    let reported = tokio::time::timeout(SOON, rx.recv())
        .await
        .expect("a report within the wait")
        .expect("the inbox is open");
    match reported {
        Msg::Input(Input::SendFailed {
            socket: on,
            dst: to,
            error,
        }) => {
            assert_eq!((on, to), (socket, dst));
            assert!(!error.is_empty());
        }
        other => panic!("not a send failure: {other:?}"),
    }
    sockets.close_all();
}
