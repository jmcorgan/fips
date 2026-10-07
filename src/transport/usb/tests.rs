use super::*;
use crate::transport::packet_channel;
use secp256k1::{Secp256k1, SecretKey};

fn test_pubkey(seed: u8) -> [u8; 32] {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    sk.public_key(&secp).x_only_public_key().0.serialize()
}

/// An FMP established frame with `payload_len` bytes of payload, each byte
/// set to `fill`: the smallest thing the receive loop accepts as a packet.
fn fmp_frame(payload_len: u16, fill: u8) -> Vec<u8> {
    let mut frame = vec![fill; 16 + payload_len as usize + 16];
    frame[0] = 0x00; // version 0, phase established
    frame[1] = 0x00;
    frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
    frame
}

struct Side {
    transport: UsbTransport,
    links: Arc<UsbLinkQueue>,
    packets: crate::transport::PacketRx,
    pubkey: [u8; 32],
}

async fn side(seed: u8) -> Side {
    let (packet_tx, packets) = packet_channel(64);
    let links = Arc::new(UsbLinkQueue::new());
    let mut transport = UsbTransport::new(
        TransportId::new(seed as u32),
        None,
        UsbConfig::default(),
        Arc::clone(&links),
        packet_tx,
    );
    let pubkey = test_pubkey(seed);
    transport.set_local_pubkey(pubkey);
    transport.start_async().await.unwrap();
    Side {
        transport,
        links,
        packets,
        pubkey,
    }
}

/// Wait until `cond` holds, failing the test after a second.
async fn wait_for(what: &str, mut cond: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !cond().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Two started transports joined by one cable.
async fn cabled() -> (Side, Side, TransportAddr, TransportAddr) {
    let a = side(1).await;
    let b = side(2).await;
    let (link_a, link_b) = UsbLink::pair("acc0", "host/1-1");
    a.links.push(link_a);
    b.links.push(link_b);
    let (ta_a, ta_b) = (
        TransportAddr::from_string("acc0"),
        TransportAddr::from_string("host/1-1"),
    );
    wait_for("both links pooled", async || {
        a.transport.has_connection(&ta_a).await && b.transport.has_connection(&ta_b).await
    })
    .await;
    (a, b, ta_a, ta_b)
}

#[tokio::test]
async fn a_cable_publishes_each_peer_with_its_key() {
    let (a, b, ta_a, ta_b) = cabled().await;

    let seen_by_a = a.transport.discover().unwrap();
    assert_eq!(seen_by_a.len(), 1);
    assert_eq!(seen_by_a[0].addr, ta_a);
    assert_eq!(seen_by_a[0].pubkey_hint.unwrap().serialize(), b.pubkey);

    let seen_by_b = b.transport.discover().unwrap();
    assert_eq!(seen_by_b[0].addr, ta_b);
    assert_eq!(seen_by_b[0].pubkey_hint.unwrap().serialize(), a.pubkey);

    // Drained: a second poll finds nothing new.
    assert!(a.transport.discover().unwrap().is_empty());
    assert_eq!(
        a.transport.connection_state_sync(&ta_a),
        ConnectionState::Connected
    );
    a.transport.connect_async(&ta_a).await.unwrap();
}

#[tokio::test]
async fn a_packet_crosses_the_link_whole() {
    let (a, mut b, ta_a, ta_b) = cabled().await;
    let frame = fmp_frame(100, 7);
    a.transport.send_async(&ta_a, &frame).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(1), b.packets.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.data, frame);
    assert_eq!(got.remote_addr, ta_b);
}

#[tokio::test]
async fn queued_packets_share_transfers_and_arrive_in_order() {
    let (a, mut b, ta_a, _) = cabled().await;
    // Queue a burst faster than the writer drains it.
    let frames: Vec<Vec<u8>> = (0..40).map(|i| fmp_frame(900, i as u8)).collect();
    for frame in &frames {
        a.transport.send_async(&ta_a, frame).await.unwrap();
    }
    for frame in &frames {
        let got = tokio::time::timeout(Duration::from_secs(1), b.packets.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got.data, frame);
    }
    let stats = a.transport.stats().snapshot();
    assert_eq!(stats.packets_sent, 40);
    assert!(
        stats.transfers_sent < stats.packets_sent,
        "expected coalescing, got {} transfers for {} packets",
        stats.transfers_sent,
        stats.packets_sent
    );
}

#[tokio::test]
async fn no_transfer_exceeds_the_usb_limit() {
    let a = side(1).await;
    let (link_a, mut far) = UsbLink::pair("acc0", "far");
    a.links.push(link_a);

    // Play the far end by hand: answer the hello, then watch the transfers.
    let mut theirs = HELLO_MAGIC.to_vec();
    theirs.push(HELLO_VERSION);
    theirs.extend_from_slice(&test_pubkey(2));
    far.tx.send(theirs).await.unwrap();
    let hello = far.rx.recv().await.unwrap();
    assert_eq!(&hello[..4], &HELLO_MAGIC);

    let ta = TransportAddr::from_string("acc0");
    wait_for("link pooled", async || {
        a.transport.has_connection(&ta).await
    })
    .await;
    for i in 0..30 {
        a.transport
            .send_async(&ta, &fmp_frame(2000, i))
            .await
            .unwrap();
    }
    let mut total = 0;
    while total < 30 * (2000 + 32) {
        let transfer = far.rx.recv().await.unwrap();
        assert!(
            transfer.len() <= USB_TRANSFER_MAX,
            "transfer of {}",
            transfer.len()
        );
        total += transfer.len();
    }
}

#[tokio::test]
async fn a_link_that_is_not_fips_is_dropped() {
    let a = side(1).await;
    let (link_a, far) = UsbLink::pair("acc0", "far");
    a.links.push(link_a);
    far.tx.send(vec![0u8; HELLO_SIZE]).await.unwrap();

    let ta = TransportAddr::from_string("acc0");
    wait_for("hello failure", async || {
        a.transport.stats().snapshot().hello_failures == 1
    })
    .await;
    assert!(!a.transport.has_connection(&ta).await);
    assert!(a.transport.discover().unwrap().is_empty());
}

#[tokio::test]
async fn our_own_key_echoed_back_is_refused() {
    let a = side(1).await;
    let (link_a, far) = UsbLink::pair("acc0", "far");
    a.links.push(link_a);
    let mut echo = HELLO_MAGIC.to_vec();
    echo.push(HELLO_VERSION);
    echo.extend_from_slice(&a.pubkey);
    far.tx.send(echo).await.unwrap();

    wait_for("hello failure", async || {
        a.transport.stats().snapshot().hello_failures == 1
    })
    .await;
    assert!(
        !a.transport
            .has_connection(&TransportAddr::from_string("acc0"))
            .await
    );
}

#[tokio::test]
async fn a_replug_replaces_the_old_link_to_the_same_peer() {
    let (a, b, ta_a, _) = cabled().await;
    let (again_a, again_b) = UsbLink::pair("acc1", "host/1-1");
    a.links.push(again_a);
    b.links.push(again_b);

    let ta_again = TransportAddr::from_string("acc1");
    wait_for("new link pooled", async || {
        a.transport.has_connection(&ta_again).await
    })
    .await;
    assert!(!a.transport.has_connection(&ta_a).await);
    assert_eq!(a.transport.stats().snapshot().links_replaced, 1);
}

#[tokio::test]
async fn an_unplugged_link_leaves_the_pool() {
    let a = side(1).await;
    let (link_a, far) = UsbLink::pair("acc0", "far");
    a.links.push(link_a);
    let mut theirs = HELLO_MAGIC.to_vec();
    theirs.push(HELLO_VERSION);
    theirs.extend_from_slice(&test_pubkey(2));
    far.tx.send(theirs).await.unwrap();

    let ta = TransportAddr::from_string("acc0");
    wait_for("link pooled", async || {
        a.transport.has_connection(&ta).await
    })
    .await;
    drop(far);
    wait_for("link removed", async || {
        !a.transport.has_connection(&ta).await
    })
    .await;
}

#[tokio::test]
async fn a_link_attached_before_start_is_taken_on_start() {
    let (packet_tx, _packets) = packet_channel(8);
    let links = Arc::new(UsbLinkQueue::new());
    let (link_a, link_b) = UsbLink::pair("acc0", "host/1-1");
    links.push(link_a);

    let mut a = UsbTransport::new(
        TransportId::new(1),
        None,
        UsbConfig::default(),
        Arc::clone(&links),
        packet_tx,
    );
    a.set_local_pubkey(test_pubkey(1));
    let b = side(2).await;
    b.links.push(link_b);
    a.start_async().await.unwrap();

    let ta = TransportAddr::from_string("acc0");
    wait_for("link pooled", async || a.has_connection(&ta).await).await;
}

#[tokio::test]
async fn sends_to_an_unknown_link_fail_without_dialling() {
    let a = side(1).await;
    let ta = TransportAddr::from_string("nowhere");
    assert!(matches!(
        a.transport.send_async(&ta, &fmp_frame(10, 0)).await,
        Err(TransportError::NotConnected)
    ));
    assert!(matches!(
        a.transport.connect_async(&ta).await,
        Err(TransportError::NotConnected)
    ));
    assert_eq!(
        a.transport.connection_state_sync(&ta),
        ConnectionState::None
    );
}

#[tokio::test]
async fn a_transport_without_a_key_refuses_to_start() {
    let (packet_tx, _packets) = packet_channel(8);
    let mut t = UsbTransport::new(
        TransportId::new(1),
        None,
        UsbConfig::default(),
        Arc::new(UsbLinkQueue::new()),
        packet_tx,
    );
    assert!(matches!(
        t.start_async().await,
        Err(TransportError::StartFailed(_))
    ));
}
