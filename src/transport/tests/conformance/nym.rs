//! The lifecycle rules on Nym, over a mock SOCKS5 proxy. Nym binds no
//! listener, so every connection here is one it dialled.

use super::*;
use crate::config::{NymConfig, TcpConfig};
use crate::testutil::wait_until;
use crate::transport::nym::NymTransport;
use crate::transport::socks5::mock::MockSocks5Server;
use crate::transport::tcp::TcpTransport;
use crate::transport::{TransportId, packet_channel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A started Nym transport with the given `mtu`, whose SOCKS5 proxy is a
/// mock that connects every request to `target`.
async fn dialler(id: u32, mtu: u16, target: std::net::SocketAddr) -> (NymTransport, PacketRx) {
    let mock = MockSocks5Server::new(target).await.unwrap();
    let proxy = mock.addr();
    let _proxy = mock.spawn();
    let config = NymConfig {
        socks5_addr: Some(proxy.to_string()),
        startup_timeout_secs: Some(5),
        connect_timeout_ms: Some(5000),
        mtu: Some(mtu),
    };
    let (tx, rx) = packet_channel(32);
    let mut t = NymTransport::new(TransportId::new(id), None, config, tx);
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

// ============================================================================
// Rule 1
// ============================================================================

/// A Nym dialler behind a mock proxy, connected to a TCP listener that reads
/// what arrives.
struct Pair {
    near: NymTransport,
    _near_rx: PacketRx,
    far: TcpTransport,
    far_rx: PacketRx,
    remote: TransportAddr,
}

impl Closing for Pair {
    async fn send(&self, frame: &[u8]) -> Result<usize, TransportError> {
        self.near.send_async(&self.remote, frame).await
    }

    async fn close(&self) {
        self.near.close_connection_async(&self.remote).await;
    }

    async fn far_next(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(2), self.far_rx.recv())
            .await
            .ok()
            .flatten()
            .map(|p| p.data)
    }

    async fn far_ended(&mut self) -> bool {
        let far = &self.far;
        wait_until(
            || far.stats().snapshot().pool_inbound == 0,
            Duration::from_secs(5),
        )
        .await
    }

    async fn finish(mut self) {
        self.near.stop_async().await.unwrap();
        self.far.stop_async().await.unwrap();
    }
}

#[tokio::test]
pub(super) async fn a_frame_queued_just_before_a_close_reaches_the_peer() {
    let (far, far_rx, listen) = tcp_listener(100, SMALL_MTU).await;
    let (near, _near_rx) = dialler(200, SMALL_MTU, listen).await;
    super::a_frame_queued_just_before_a_close_reaches_the_peer(Pair {
        near,
        _near_rx,
        far,
        far_rx,
        remote: TransportAddr::from_string(&listen.to_string()),
    })
    .await;
}

impl Stopping for NymTransport {
    async fn stuck_writer(&self, remote: &TransportAddr) -> tokio::sync::oneshot::Receiver<()> {
        NymTransport::stuck_writer(self, remote).await
    }

    async fn close(&self, remote: &TransportAddr) {
        self.close_connection_async(remote).await;
    }

    async fn stop(&mut self) -> Result<(), TransportError> {
        self.stop_async().await
    }
}

#[tokio::test]
pub(super) async fn stopping_the_transport_ends_a_writer_still_draining_after_a_close() {
    // No proxy runs: the startup probe is off and nothing is dialled.
    let (tx, _rx) = packet_channel(32);
    let config = NymConfig {
        socks5_addr: Some("127.0.0.1:1080".to_string()),
        startup_timeout_secs: Some(0),
        connect_timeout_ms: Some(2000),
        ..Default::default()
    };
    let mut t = NymTransport::new(TransportId::new(1), None, config, tx);
    t.start_async().await.unwrap();
    super::stopping_the_transport_ends_a_writer_still_draining_after_a_close(
        t,
        TransportAddr::from_string("192.0.2.1:2121"),
    )
    .await;
}

// ============================================================================
// Rule 3
// ============================================================================

/// A connection from a 1500-`mtu` TCP listener to the 1400-`mtu` Nym end that
/// dialled it.
struct Link {
    sender: TcpTransport,
    _sender_rx: PacketRx,
    receiver: NymTransport,
    rx: PacketRx,
    /// Where the sender sends: the Nym end's address at the listener.
    to: TransportAddr,
    /// The address the Nym end dialled, which keys its connection.
    dialled: TransportAddr,
}

impl Carrying for Link {
    async fn send(&mut self, len: u16) {
        self.sender
            .send_async(&self.to, &frame(len))
            .await
            .expect("precondition: the sender admits a frame within its own mtu");
    }

    async fn next(&mut self) -> Option<ReceivedPacket> {
        super::next(&mut self.rx).await
    }

    fn recv_errors(&self) -> u64 {
        self.receiver.stats().snapshot().recv_errors
    }

    async fn kept(&self) -> bool {
        self.receiver.has_connection(&self.dialled).await
    }

    fn connections(&self) -> u64 {
        self.sender.stats().snapshot().connections_established
            + self.receiver.stats().snapshot().connections_established
    }
}

/// A 1400-`mtu` Nym end dials a 1500-`mtu` FIPS TCP listener through SOCKS5,
/// and the listener answers.
#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_from_a_tcp_listener()
 {
    let (sender, mut sender_rx, listen) = tcp_listener(1, LARGE_MTU).await;
    let (receiver, rx) = dialler(2, SMALL_MTU, listen).await;
    let dialled = TransportAddr::from_string(&listen.to_string());
    receiver.send_async(&dialled, &frame(64)).await.unwrap();
    let to = next(&mut sender_rx)
        .await
        .expect("precondition: the TCP listener receives the Nym end's first frame")
        .remote_addr;
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(
        &mut Link {
            sender,
            _sender_rx: sender_rx,
            receiver,
            rx,
            to,
            dialled,
        },
    )
    .await;
}

/// A 1400-`mtu` Nym end connected through the mock proxy to a raw socket.
struct RawFar {
    receiver: NymTransport,
    rx: PacketRx,
    far: TcpStream,
    dialled: TransportAddr,
}

impl Raw for RawFar {
    async fn write(&mut self, bytes: &[u8]) {
        self.far.write_all(bytes).await.unwrap();
    }

    async fn next(&mut self) -> Option<ReceivedPacket> {
        super::next(&mut self.rx).await
    }

    fn recv_errors(&self) -> u64 {
        self.receiver.stats().snapshot().recv_errors
    }

    async fn kept(&self) -> bool {
        self.receiver.has_connection(&self.dialled).await
    }
}

#[tokio::test]
pub(super) async fn a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let (receiver, rx) = dialler(1, SMALL_MTU, listen).await;
    let dialled = TransportAddr::from_string(&listen.to_string());
    let opening = frame(64);
    receiver.send_async(&dialled, &opening).await.unwrap();
    let (mut far, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("precondition: the Nym end connects through the proxy")
        .unwrap();
    let mut first = vec![0u8; opening.len()];
    far.read_exact(&mut first).await.unwrap();
    assert_eq!(
        first, opening,
        "precondition: the raw far end reads the Nym end's first frame"
    );
    super::a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes(RawFar {
        receiver,
        rx,
        far,
        dialled,
    })
    .await;
}
