//! The lifecycle rules on BLE, over the in-memory radio.
//!
//! Each connection is a `MockBleStream` pair: one end is handed to the
//! transport's accept loop, as a remote device connecting, and the test
//! holds the other. The transport runs no key exchange (no local key is
//! set), so the channel is pooled as soon as it is accepted.

use super::*;
use crate::config::BleConfig;
use crate::identity::NodeAddr;
use crate::testutil::wait_until;
use crate::transport::ble::BleTransport;
use crate::transport::ble::addr::BleAddr;
use crate::transport::ble::io::{BleStream, MockBleIo, MockBleStream};
use crate::transport::{TransportId, packet_channel};

/// The link MTU both ends of a mock channel use.
const MOCK_MTU: u16 = 2048;

/// The address of the local adapter.
fn near_addr() -> BleAddr {
    BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap()
}

/// The address of the remote device.
fn far_addr() -> BleAddr {
    BleAddr::parse("hci0/AA:BB:CC:DD:EE:02").unwrap()
}

/// A started BLE transport over a mock radio that accepts inbound channels
/// and neither scans nor advertises.
async fn transport() -> (BleTransport<MockBleIo>, PacketRx) {
    let config = BleConfig {
        adapter: Some("hci0".to_string()),
        mtu: Some(MOCK_MTU),
        accept_connections: Some(true),
        scan: Some(false),
        advertise: Some(false),
        auto_connect: Some(false),
        ..Default::default()
    };
    let (tx, rx) = packet_channel(64);
    let io = MockBleIo::new("hci0", near_addr());
    let mut t = BleTransport::new(TransportId::new(1), None, config, io, tx);
    t.start_async().await.unwrap();
    (t, rx)
}

/// Connect a remote device to `t` and return the far end of its channel,
/// with the channel's address, once the transport has pooled it.
async fn accept(t: &BleTransport<MockBleIo>) -> (MockBleStream, TransportAddr) {
    let (near, far) = MockBleStream::pair(near_addr(), far_addr(), MOCK_MTU);
    let at = far_addr().to_transport_addr();
    t.io().inject_inbound(near).await;
    let mut pooled = false;
    for _ in 0..200 {
        if t.has_connection(&at).await {
            pooled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(pooled, "precondition: the inbound channel is pooled");
    (far, at)
}

/// What the far end reads within two seconds: a frame, or `None` for a
/// closed channel or nothing at all.
async fn far_reads(far: &MockBleStream) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(2), far.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
        _ => None,
    }
}

// ============================================================================
// Rule 1
// ============================================================================

/// One pooled channel, and the far end the test reads.
struct Channel {
    t: BleTransport<MockBleIo>,
    _rx: PacketRx,
    far: MockBleStream,
    at: TransportAddr,
}

impl Channel {
    async fn new() -> Self {
        let (t, _rx) = transport().await;
        let (far, at) = accept(&t).await;
        Self { t, _rx, far, at }
    }
}

impl Closing for Channel {
    async fn send(&self, frame: &[u8]) -> Result<usize, TransportError> {
        self.t.send_async(&self.at, frame).await
    }

    async fn close(&self) {
        self.t.close_connection_async(&self.at).await;
    }

    async fn far_next(&mut self) -> Option<Vec<u8>> {
        far_reads(&self.far).await
    }

    async fn far_ended(&mut self) -> bool {
        let mut buf = vec![0u8; 4096];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.far.recv(&mut buf)).await,
            Ok(Ok(0))
        )
    }

    async fn finish(mut self) {
        self.t.stop_async().await.unwrap();
    }
}

#[tokio::test]
pub(super) async fn a_frame_queued_just_before_a_close_reaches_the_peer() {
    super::a_frame_queued_just_before_a_close_reaches_the_peer(Channel::new().await).await;
}

/// Control for the close rule: with the writer given a chance to run before
/// the close, the frame reaches the far end. The far end does receive what
/// the writer writes, so only the close can keep a frame from it.
#[tokio::test]
pub(super) async fn a_frame_written_before_a_close_reaches_the_peer() {
    let c = Channel::new().await;
    let frame = build_msg1_frame();
    assert_eq!(
        c.t.send_async(&c.at, &frame).await.ok(),
        Some(frame.len()),
        "precondition: the frame is queued"
    );
    let stats = c.t.stats();
    assert!(
        wait_until(
            || stats.snapshot().packets_sent == 1,
            Duration::from_secs(2)
        )
        .await,
        "precondition: the writer has written the frame"
    );
    c.t.close_connection_async(&c.at).await;
    assert!(
        !c.t.has_connection(&c.at).await,
        "precondition: the connection is closed"
    );
    assert_eq!(
        far_reads(&c.far).await,
        Some(frame),
        "defect: a frame the writer wrote before the close never reached the peer"
    );
    c.finish().await;
}

impl Stopping for BleTransport<MockBleIo> {
    async fn stuck_writer(&self, remote: &TransportAddr) -> tokio::sync::oneshot::Receiver<()> {
        BleTransport::stuck_writer(self, remote).await
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
    let (t, _rx) = transport().await;
    super::stopping_the_transport_ends_a_writer_still_draining_after_a_close(
        t,
        TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:09"),
    )
    .await;
}

// ============================================================================
// Rule 2
// ============================================================================

/// The handshake timeout the sweep is given.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A BLE transport swept once a second, as the node's timeout tick sweeps
/// it, with the node's hold on the channel under test set by the test.
struct Swept {
    t: BleTransport<MockBleIo>,
    _rx: PacketRx,
    /// Whether the node holds a handshake or link on the channel.
    holding: std::cell::Cell<bool>,
}

impl Swept {
    async fn new() -> Self {
        let (t, _rx) = transport().await;
        Self {
            t,
            _rx,
            holding: std::cell::Cell::new(false),
        }
    }
}

impl Accepting for Swept {
    type Far = (MockBleStream, TransportAddr);

    fn deadline(&self) -> Duration {
        TIMEOUT
    }

    fn slack(&self) -> Duration {
        Duration::ZERO
    }

    /// One sweep step, a second, before the timeout.
    fn early(&self) -> Duration {
        TIMEOUT - Duration::from_secs(1)
    }

    async fn open(&mut self) -> Self::Far {
        accept(&self.t).await
    }

    /// The node holds the channel once a msg1 has crossed it.
    async fn first_frame(&mut self, _far: &mut Self::Far) {
        self.holding.set(true);
    }

    async fn held(&self, far: &Self::Far) -> bool {
        self.t.has_connection(&far.1).await
    }

    /// Advance tokio's paused clock, which the pool's stamps read, by `d`,
    /// sweeping after each second.
    async fn age(&mut self, d: Duration) {
        let mut left = d;
        while left > Duration::ZERO {
            let step = left.min(Duration::from_secs(1));
            tokio::time::advance(step).await;
            left -= step;
            let holding = self.holding.get();
            self.t.close_unproven(TIMEOUT, |_| holding).await;
        }
    }
}

#[tokio::test(start_paused = true)]
pub(super) async fn an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline() {
    super::an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline(
        Swept::new().await,
    )
    .await;
}

/// A channel on which a handshake completed, and that its peer has since
/// left unverified, is not a channel that never carried a handshake: it is
/// kept, however long it stays unverified.
#[tokio::test(start_paused = true)]
pub(super) async fn a_channel_that_completed_a_handshake_and_was_left_unverified_is_kept() {
    let mut s = Swept::new().await;
    let far = s.open().await;
    let node = NodeAddr::from_bytes([7; 16]);
    s.t.mark_verified(&far.1, &node).await;
    assert_eq!(
        s.t.is_verified(&far.1).await,
        Some(true),
        "precondition: a handshake completed on the channel"
    );
    s.t.clear_verified(&far.1, &node, false).await;
    assert_eq!(
        s.t.is_verified(&far.1).await,
        Some(false),
        "precondition: the peer moved to another link"
    );

    s.age(TIMEOUT * 4).await;
    assert!(
        s.held(&far).await,
        "defect: a channel that completed a handshake was closed once left unverified"
    );
}

/// A channel the node holds a handshake or link on is kept, and is closed
/// only a full timeout after the node last held it.
#[tokio::test(start_paused = true)]
pub(super) async fn a_channel_the_node_holds_is_kept_a_full_timeout_after_it_lets_go() {
    let mut s = Swept::new().await;
    let far = s.open().await;
    s.holding.set(true);
    s.age(Duration::from_secs(25)).await;
    s.holding.set(false);

    s.age(TIMEOUT - Duration::from_secs(1)).await;
    assert!(
        s.held(&far).await,
        "defect: a channel was closed less than a timeout after the node last held it"
    );
    s.age(Duration::from_secs(1)).await;
    assert!(
        !s.held(&far).await,
        "defect: a channel was still pooled a full timeout after the node last held it"
    );
}
