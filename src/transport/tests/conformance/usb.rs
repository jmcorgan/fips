//! The lifecycle rules on USB, over in-memory links.
//!
//! Each link is a `UsbLink::pair`: one end is pushed to the transport's link
//! queue, as an attached cable, and the far end is either another transport
//! (rule 3's carrying instance) or held by the test, which plays the far
//! node's hello by hand and then reads or writes raw transfers.

use super::*;
use crate::config::UsbConfig;
use crate::transport::usb::{USB_TRANSFER_MAX, UsbLink, UsbLinkQueue, UsbTransport, hello_for};
use crate::transport::{TransportId, packet_channel};
use secp256k1::{Secp256k1, SecretKey};
use std::sync::Arc;

/// The x-only public key of the secret key `[seed; 32]`.
fn pubkey(seed: u8) -> [u8; 32] {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    sk.public_key(&secp).x_only_public_key().0.serialize()
}

/// A started USB transport with the key of `seed` and the link `mtu`, with
/// its link queue.
async fn transport(seed: u8, mtu: u16) -> (UsbTransport, Arc<UsbLinkQueue>, PacketRx) {
    let (tx, rx) = packet_channel(64);
    let links = Arc::new(UsbLinkQueue::new());
    let config = UsbConfig {
        mtu: Some(mtu),
        ..Default::default()
    };
    let mut t = UsbTransport::new(
        TransportId::new(seed as u32),
        None,
        config,
        Arc::clone(&links),
        tx,
    );
    t.set_local_pubkey(pubkey(seed));
    t.start_async().await.unwrap();
    (t, links, rx)
}

/// Wait up to two seconds for `t` to pool the link at `at`.
async fn pooled(t: &UsbTransport, at: &TransportAddr) -> bool {
    for _ in 0..200 {
        if t.has_connection(at).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Attach a link to `t` whose far end the test holds, play the far node's
/// hello on it, and return the far end once `t` has pooled the link, with
/// the link's address.
async fn attach(t: &UsbTransport, links: &UsbLinkQueue) -> (UsbLink, TransportAddr) {
    let (near, mut far) = UsbLink::pair("acc0", "far");
    let at = TransportAddr::from_string("acc0");
    links.push(near);
    let theirs = tokio::time::timeout(Duration::from_secs(2), far.rx.recv())
        .await
        .ok()
        .flatten();
    assert_eq!(
        theirs.map(|h| h.len()),
        Some(hello_for(&[0; 32]).len()),
        "precondition: the transport sends its hello"
    );
    far.tx.send(hello_for(&pubkey(9))).await.unwrap();
    assert!(pooled(t, &at).await, "precondition: the link is pooled");
    (far, at)
}

// ============================================================================
// Rule 1
// ============================================================================

/// One pooled link, and the far end the test reads.
struct Cable {
    t: UsbTransport,
    _links: Arc<UsbLinkQueue>,
    _rx: PacketRx,
    far: UsbLink,
    at: TransportAddr,
}

impl Cable {
    async fn new() -> Self {
        let (t, links, _rx) = transport(1, 2048).await;
        let (far, at) = attach(&t, &links).await;
        Self {
            t,
            _links: links,
            _rx,
            far,
            at,
        }
    }
}

impl Closing for Cable {
    async fn send(&self, frame: &[u8]) -> Result<usize, TransportError> {
        self.t.send_async(&self.at, frame).await
    }

    async fn close(&self) {
        self.t.close_connection_async(&self.at).await;
    }

    /// One transfer: the writer puts a lone queued frame in a transfer of
    /// its own.
    async fn far_next(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(2), self.far.rx.recv())
            .await
            .ok()
            .flatten()
    }

    async fn far_ended(&mut self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.far.rx.recv()).await,
            Ok(None)
        )
    }

    async fn finish(mut self) {
        self.t.stop_async().await.unwrap();
    }
}

#[tokio::test]
pub(super) async fn a_frame_queued_just_before_a_close_reaches_the_peer() {
    super::a_frame_queued_just_before_a_close_reaches_the_peer(Cable::new().await).await;
}

impl Stopping for UsbTransport {
    async fn stuck_writer(&self, remote: &TransportAddr) -> tokio::sync::oneshot::Receiver<()> {
        UsbTransport::stuck_writer(self, remote).await
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
    let (t, _links, _rx) = transport(1, 2048).await;
    super::stopping_the_transport_ends_a_writer_still_draining_after_a_close(
        t,
        TransportAddr::from_string("stuck0"),
    )
    .await;
}

// ============================================================================
// Rule 3
// ============================================================================

/// Two transports joined by one cable: a sender configured with `LARGE_MTU`
/// and a receiver configured with `SMALL_MTU`.
struct Pair {
    sender: UsbTransport,
    receiver: UsbTransport,
    _links: (Arc<UsbLinkQueue>, Arc<UsbLinkQueue>),
    _sender_rx: PacketRx,
    receiver_rx: PacketRx,
    /// The link's address at the sender.
    to: TransportAddr,
    /// The link's address at the receiver.
    from: TransportAddr,
}

impl Pair {
    async fn new() -> Self {
        let (sender, s_links, _sender_rx) = transport(1, LARGE_MTU).await;
        let (receiver, r_links, receiver_rx) = transport(2, SMALL_MTU).await;
        let (a, b) = UsbLink::pair("send0", "recv0");
        s_links.push(a);
        r_links.push(b);
        let to = TransportAddr::from_string("send0");
        let from = TransportAddr::from_string("recv0");
        assert!(
            pooled(&sender, &to).await && pooled(&receiver, &from).await,
            "precondition: both ends pool the link"
        );
        Self {
            sender,
            receiver,
            _links: (s_links, r_links),
            _sender_rx,
            receiver_rx,
            to,
            from,
        }
    }
}

impl Carrying for Pair {
    async fn send(&mut self, len: u16) {
        self.sender
            .send_async(&self.to, &frame(len))
            .await
            .expect("precondition: the sender admits the frame");
    }

    async fn next(&mut self) -> Option<ReceivedPacket> {
        super::next(&mut self.receiver_rx).await
    }

    fn recv_errors(&self) -> u64 {
        self.receiver.stats().snapshot().recv_errors
    }

    async fn kept(&self) -> bool {
        self.receiver.has_connection(&self.from).await
    }

    /// A cable is one link, established at each end: two for the one link.
    fn connections(&self) -> u64 {
        let total = self.sender.stats().snapshot().links_established
            + self.receiver.stats().snapshot().links_established;
        total / 2
    }
}

#[tokio::test]
pub(super) async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered() {
    super::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(
        &mut Pair::new().await,
    )
    .await;
}

/// A receiver with a far end the test writes raw transfers into.
struct Tap {
    t: UsbTransport,
    _links: Arc<UsbLinkQueue>,
    rx: PacketRx,
    far: UsbLink,
    at: TransportAddr,
}

impl Raw for Tap {
    /// Written in transfers of at most `USB_TRANSFER_MAX`, as a real link
    /// carries them.
    async fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(USB_TRANSFER_MAX) {
            if self.far.tx.send(chunk.to_vec()).await.is_err() {
                return;
            }
        }
    }

    async fn next(&mut self) -> Option<ReceivedPacket> {
        super::next(&mut self.rx).await
    }

    fn recv_errors(&self) -> u64 {
        self.t.stats().snapshot().recv_errors
    }

    async fn kept(&self) -> bool {
        self.t.has_connection(&self.at).await
    }
}

#[tokio::test]
pub(super) async fn a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes() {
    let (t, links, rx) = transport(1, SMALL_MTU).await;
    let (far, at) = attach(&t, &links).await;
    super::a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes(Tap {
        t,
        _links: links,
        rx,
        far,
        at,
    })
    .await;
}
