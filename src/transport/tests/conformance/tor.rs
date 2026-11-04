//! The lifecycle rules on Tor, over a mock SOCKS5 proxy and a directory-mode
//! onion listener bound on loopback.

use super::*;
use crate::config::{DirectoryServiceConfig, TcpConfig, TorConfig};
use crate::testutil::wait_until;
use crate::transport::socks5::mock::MockSocks5Server;
use crate::transport::tcp::TcpTransport;
use crate::transport::tor::TorTransport;
use crate::transport::{TransportId, packet_channel};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// The onion address a listening end reads from its hostname file.
const ONION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.onion";

/// The onion address a dialling end sends to.
fn onion_target() -> TransportAddr {
    TransportAddr::from_string(&format!("{ONION}:443"))
}

/// A started Tor transport in directory mode with the given `mtu`, and
/// first-frame deadline when one is given: its onion-service listener is
/// bound on loopback, standing in for the local port Tor forwards the onion
/// service to. Returns the transport, its packet channel and the listener's
/// address.
///
/// The port is picked free and then bound by the transport, so another
/// process can take it in between; a failed start is retried on a new port.
async fn onion_listener(
    id: u32,
    mtu: u16,
    dir: &TempDir,
    first_frame: Option<Duration>,
) -> (TorTransport, PacketRx, std::net::SocketAddr) {
    let hostname = dir.path().join("hostname");
    std::fs::write(&hostname, format!("{ONION}\n")).unwrap();
    for _ in 0..5 {
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
        if let Some(d) = first_frame {
            t.set_first_frame_timeout(d);
            t.set_inbound_idle_timeout(Duration::from_secs(10));
        }
        if t.start_async().await.is_ok() {
            return (t, rx, listen);
        }
    }
    panic!("precondition: an onion listener could be bound on loopback");
}

/// A started Tor transport in socks5 mode with the given `mtu`, whose SOCKS5
/// proxy is a mock that connects every request to `target`.
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

// ============================================================================
// Rule 1
// ============================================================================

/// A Tor dialler behind a mock proxy, connected to a TCP listener that reads
/// what arrives.
struct Pair {
    near: TorTransport,
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

impl Stopping for TorTransport {
    async fn stuck_writer(&self, remote: &TransportAddr) -> tokio::sync::oneshot::Receiver<()> {
        TorTransport::stuck_writer(self, remote).await
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
    let (tx, _rx) = packet_channel(32);
    let config = TorConfig {
        socks5_addr: Some("127.0.0.1:19050".to_string()),
        ..Default::default()
    };
    let mut t = TorTransport::new(TransportId::new(1), None, config, tx);
    t.start_async().await.unwrap();
    super::stopping_the_transport_ends_a_writer_still_draining_after_a_close(
        t,
        TransportAddr::from_string("abcdef1234567890.onion:2121"),
    )
    .await;
}

// ============================================================================
// Rule 2
// ============================================================================

/// The first-frame deadline the onion listener is given: short enough for a
/// unit test to wait for, and long enough that the look for an early close
/// can sit past half of it with room for a loaded host.
const DEADLINE: Duration = Duration::from_secs(1);

/// An onion listener with a short first-frame deadline.
struct Listener {
    t: TorTransport,
    rx: PacketRx,
    listen: std::net::SocketAddr,
    _dir: TempDir,
}

impl Listener {
    async fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (t, rx, listen) = onion_listener(1, SMALL_MTU, &dir, Some(DEADLINE)).await;
        Self {
            t,
            rx,
            listen,
            _dir: dir,
        }
    }
}

impl Accepting for Listener {
    type Far = TcpStream;

    fn deadline(&self) -> Duration {
        DEADLINE
    }

    fn slack(&self) -> Duration {
        Duration::from_secs(2)
    }

    /// 600 ms, past half the deadline, which leaves 400 ms for a loaded
    /// host to reach the look.
    fn early(&self) -> Duration {
        DEADLINE * 3 / 5
    }

    async fn open(&mut self) -> TcpStream {
        // Held open by the caller for the whole test, so any release is the
        // deadline's doing and not a client disconnect.
        let far = TcpStream::connect(self.listen).await.unwrap();
        let t = &self.t;
        wait_until(
            || t.stats().pool_inbound_count() == 1,
            Duration::from_secs(2),
        )
        .await;
        far
    }

    async fn first_frame(&mut self, far: &mut TcpStream) {
        far.write_all(&build_msg1_frame()).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(2), self.rx.recv())
            .await
            .ok()
            .flatten();
        assert_eq!(
            packet.map(|p| p.data),
            Some(build_msg1_frame()),
            "precondition: the first frame is delivered"
        );
    }

    async fn held(&self, far: &TcpStream) -> bool {
        let at = TransportAddr::from_string(&far.local_addr().unwrap().to_string());
        self.t.stats().pool_inbound_count() > 0 || self.t.has_connection(&at).await
    }

    async fn age(&mut self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

#[tokio::test]
pub(super) async fn an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline() {
    super::an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline(
        Listener::new().await,
    )
    .await;
}

#[tokio::test]
pub(super) async fn an_accepted_connection_that_sent_a_frame_is_kept_past_the_deadline() {
    super::an_accepted_connection_that_sent_a_frame_is_kept_past_the_deadline(
        Listener::new().await,
    )
    .await;
}

// ============================================================================
// Rule 3
// ============================================================================

/// The sending end of a receive-bound case: Tor or TCP.
enum Sender {
    Tor(TorTransport),
    Tcp(TcpTransport),
}

impl Sender {
    async fn send(&self, to: &TransportAddr, data: &[u8]) -> Result<usize, TransportError> {
        match self {
            Sender::Tor(t) => t.send_async(to, data).await,
            Sender::Tcp(t) => t.send_async(to, data).await,
        }
    }

    fn connections(&self) -> u64 {
        match self {
            Sender::Tor(t) => t.stats().snapshot().connections_established,
            Sender::Tcp(t) => t.stats().snapshot().connections_established,
        }
    }
}

/// A connection from a 1500-`mtu` sender to a 1400-`mtu` Tor receiver.
struct Link {
    sender: Sender,
    _sender_rx: PacketRx,
    receiver: TorTransport,
    rx: PacketRx,
    /// Where the sender sends.
    to: TransportAddr,
    /// The sender's address at the receiver, from the frames it delivered.
    from: Option<TransportAddr>,
    _dir: Option<TempDir>,
}

impl Carrying for Link {
    async fn send(&mut self, len: u16) {
        self.sender
            .send(&self.to, &frame(len))
            .await
            .expect("precondition: the sender admits a frame within its own mtu");
    }

    async fn next(&mut self) -> Option<ReceivedPacket> {
        let packet = super::next(&mut self.rx).await;
        if let Some(p) = &packet {
            self.from = Some(p.remote_addr.clone());
        }
        packet
    }

    fn recv_errors(&self) -> u64 {
        self.receiver.stats().snapshot().recv_errors
    }

    async fn kept(&self) -> bool {
        match &self.from {
            Some(from) => self.receiver.has_connection(from).await,
            None => false,
        }
    }

    fn connections(&self) -> u64 {
        self.sender.connections() + self.receiver.stats().snapshot().connections_established
    }
}

/// A 1500-`mtu` Tor end dials a 1400-`mtu` Tor end's onion listener, which
/// receives on the connection it accepted.
#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_the_onion_listener()
 {
    let dir = TempDir::new().unwrap();
    let (receiver, rx, listen) = onion_listener(1, SMALL_MTU, &dir, None).await;
    let (sender, sender_rx) = dialler(2, LARGE_MTU, listen).await;
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(
        &mut Link {
            sender: Sender::Tor(sender),
            _sender_rx: sender_rx,
            receiver,
            rx,
            to: onion_target(),
            from: None,
            _dir: Some(dir),
        },
    )
    .await;
}

/// A 1400-`mtu` Tor end dials a 1500-`mtu` Tor end's onion listener, which
/// answers on the connection it accepted.
#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_a_dialled_connection()
 {
    let dir = TempDir::new().unwrap();
    let (sender, mut sender_rx, listen) = onion_listener(1, LARGE_MTU, &dir, None).await;
    let (receiver, rx) = dialler(2, SMALL_MTU, listen).await;
    receiver
        .send_async(&onion_target(), &frame(64))
        .await
        .unwrap();
    let to = next(&mut sender_rx)
        .await
        .expect("precondition: the onion listener receives the dialler's first frame")
        .remote_addr;
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(
        &mut Link {
            sender: Sender::Tor(sender),
            _sender_rx: sender_rx,
            receiver,
            rx,
            to,
            from: None,
            _dir: Some(dir),
        },
    )
    .await;
}

/// A 1400-`mtu` Tor end dials a 1500-`mtu` FIPS TCP listener through SOCKS5,
/// and the listener answers.
#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_from_a_tcp_listener()
 {
    let (sender, mut sender_rx, listen) = tcp_listener(1, LARGE_MTU).await;
    let (receiver, rx) = dialler(2, SMALL_MTU, listen).await;
    receiver
        .send_async(&TransportAddr::from_string(&listen.to_string()), &frame(64))
        .await
        .unwrap();
    let to = next(&mut sender_rx)
        .await
        .expect("precondition: the TCP listener receives the Tor end's first frame")
        .remote_addr;
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(
        &mut Link {
            sender: Sender::Tcp(sender),
            _sender_rx: sender_rx,
            receiver,
            rx,
            to,
            from: None,
            _dir: None,
        },
    )
    .await;
}

/// A 1400-`mtu` onion listener and a raw socket connected to it.
struct RawFar {
    receiver: TorTransport,
    rx: PacketRx,
    far: TcpStream,
    _dir: TempDir,
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
        let at = TransportAddr::from_string(&self.far.local_addr().unwrap().to_string());
        self.receiver.has_connection(&at).await
    }
}

#[tokio::test]
pub(super) async fn a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes() {
    let dir = TempDir::new().unwrap();
    let (receiver, rx, listen) = onion_listener(1, SMALL_MTU, &dir, None).await;
    let far = TcpStream::connect(listen).await.unwrap();
    super::a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes(RawFar {
        receiver,
        rx,
        far,
        _dir: dir,
    })
    .await;
}
