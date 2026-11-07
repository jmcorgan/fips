//! The lifecycle rules on TCP, the transport they were first fixed on.

use super::*;
use crate::config::TcpConfig;
use crate::testutil::wait_until;
use crate::transport::tcp::TcpTransport;
use crate::transport::{ConnectionState, TransportId, packet_channel};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// A started TCP transport with the given `mtu`, listening on loopback when
/// `listen` is set and outbound only otherwise.
async fn transport(id: u32, mtu: u16, listen: bool) -> (TcpTransport, PacketRx) {
    let config = TcpConfig {
        bind_addr: listen.then(|| "127.0.0.1:0".to_string()),
        mtu: Some(mtu),
        ..Default::default()
    };
    let (tx, rx) = packet_channel(100);
    let mut t = TcpTransport::new(TransportId::new(id), None, config, tx);
    t.start_async().await.unwrap();
    (t, rx)
}

/// The address a transport listens on.
fn listen_addr(t: &TcpTransport) -> TransportAddr {
    TransportAddr::from_string(&t.local_addr().unwrap().to_string())
}

// ============================================================================
// Rule 1
// ============================================================================

/// A connection from an outbound transport to a listening one, which reads
/// what arrives.
struct Pair {
    near: TcpTransport,
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
    let (near, _near_rx) = transport(1, SMALL_MTU, false).await;
    let (far, far_rx) = transport(2, SMALL_MTU, true).await;
    let remote = listen_addr(&far);
    super::a_frame_queued_just_before_a_close_reaches_the_peer(Pair {
        near,
        _near_rx,
        far,
        far_rx,
        remote,
    })
    .await;
}

impl Stopping for TcpTransport {
    async fn stuck_writer(&self, remote: &TransportAddr) -> tokio::sync::oneshot::Receiver<()> {
        TcpTransport::stuck_writer(self, remote).await
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
    let (t, _rx) = transport(1, SMALL_MTU, false).await;
    super::stopping_the_transport_ends_a_writer_still_draining_after_a_close(
        t,
        TransportAddr::from_string("127.0.0.1:9"),
    )
    .await;
}

// ============================================================================
// Rule 2
// ============================================================================

/// The first-frame deadline the listener is given: short enough for a
/// unit test to wait for, and long enough that the look for an early close
/// can sit past half of it with room for a loaded host.
const DEADLINE: Duration = Duration::from_secs(1);

/// A listening transport with a short first-frame deadline.
struct Listener {
    t: TcpTransport,
    rx: PacketRx,
}

impl Listener {
    async fn new() -> Self {
        let (tx, rx) = packet_channel(100);
        let config = TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(SMALL_MTU),
            ..Default::default()
        };
        let mut t = TcpTransport::new(TransportId::new(1), None, config, tx);
        t.set_first_frame_timeout(DEADLINE);
        t.set_inbound_idle_timeout(Duration::from_secs(10));
        t.start_async().await.unwrap();
        Self { t, rx }
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
        let far = TcpStream::connect(self.t.local_addr().unwrap())
            .await
            .unwrap();
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

/// A connection between a 1500-`mtu` sender and a 1400-`mtu` receiver.
struct Link {
    sender: TcpTransport,
    _sender_rx: PacketRx,
    receiver: TcpTransport,
    rx: PacketRx,
    /// Where the sender sends.
    to: TransportAddr,
    /// The sender's address at the receiver, from the frames it delivered.
    from: Option<TransportAddr>,
}

impl Carrying for Link {
    async fn send(&mut self, len: u16) {
        self.sender
            .send_async(&self.to, &frame(len))
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
        self.sender.stats().snapshot().connections_established
            + self.receiver.stats().snapshot().connections_established
    }
}

/// The receiver dials the sender, which then answers on the connection it
/// accepted, addressed to the receiver's ephemeral port.
async fn dialled_by_the_receiver(background: bool) -> Link {
    let (receiver, rx) = transport(1, SMALL_MTU, false).await;
    let (sender, mut sender_rx) = transport(2, LARGE_MTU, true).await;
    let at = listen_addr(&sender);
    if background {
        receiver.connect_async(&at).await.unwrap();
        assert!(
            wait_until(
                || receiver.connection_state_sync(&at) == ConnectionState::Connected,
                Duration::from_secs(2)
            )
            .await,
            "precondition: the background connect is promoted"
        );
        receiver.send_existing(&at, &frame(64)).await.unwrap();
    } else {
        // No connection exists, so this send dials.
        receiver.send_async(&at, &frame(64)).await.unwrap();
    }
    let to = next(&mut sender_rx)
        .await
        .expect("precondition: the sender receives the receiver's first frame")
        .remote_addr;
    Link {
        sender,
        _sender_rx: sender_rx,
        receiver,
        rx,
        to,
        from: None,
    }
}

/// A 1500-`mtu` sender dials a 1400-`mtu` listener: the receiver holds the
/// connection it accepted.
#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_an_accepted_connection()
 {
    let (receiver, rx) = transport(1, SMALL_MTU, true).await;
    let (sender, _sender_rx) = transport(2, LARGE_MTU, false).await;
    let to = listen_addr(&receiver);
    let mut link = Link {
        sender,
        _sender_rx,
        receiver,
        rx,
        to,
        from: None,
    };
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(&mut link)
        .await;
    assert_eq!(
        link.receiver.stats().snapshot().connections_accepted,
        1,
        "defect: the receiver must have accepted exactly the one connection"
    );
}

/// The 1400-`mtu` end dials the 1500-`mtu` listener by connect-on-send.
#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_a_connect_on_send_connection()
 {
    let mut link = dialled_by_the_receiver(false).await;
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(&mut link)
        .await;
}

/// The 1400-`mtu` end dials the 1500-`mtu` listener in the background with
/// `connect_async`.
#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_a_background_connection()
 {
    let mut link = dialled_by_the_receiver(true).await;
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(&mut link)
        .await;
}

/// A 1400-`mtu` listener and a raw socket connected to it.
struct RawFar {
    receiver: TcpTransport,
    rx: PacketRx,
    far: TcpStream,
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
    let (receiver, rx) = transport(1, SMALL_MTU, true).await;
    let far = TcpStream::connect(receiver.local_addr().unwrap())
        .await
        .unwrap();
    super::a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes(RawFar {
        receiver,
        rx,
        far,
    })
    .await;
}
