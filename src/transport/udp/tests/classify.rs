use super::*;
use crate::transport::udp::{UdpStats, UdpTransport, udp_receive_loop};
use crate::transport::{TransportId, packet_channel};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const PROBE: [u8; 8] = [0x4E, 0x50, 0x54, 0x43, 0, 0, 0, 1];
const ACK: [u8; 8] = [0x4E, 0x50, 0x54, 0x41, 0, 0, 0, 1];
const FMP: &[u8] = b"valid-fmp-frame";
const MARKED: &[u8] = &[0xAA, 1, 2, 3];

/// A classifier that discards only datagrams starting `0xAA`, so a test can
/// tell it apart from the default filter.
fn discard_marked(data: &[u8]) -> DatagramClass {
    if data.first() == Some(&0xAA) {
        DatagramClass::Discard
    } else {
        DatagramClass::Fmp
    }
}

fn loopback() -> crate::config::UdpConfig {
    crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    }
}

/// Send each datagram from a fresh socket to `to` and return what reached the
/// packet channel, in order. It waits up to 2 s for the last datagram sent,
/// which every caller makes the one that must arrive, so a receive task that
/// starts late under load is not read as a drop; then it waits until the
/// channel stays quiet for 200 ms, to catch anything that should not arrive.
async fn deliver(
    to: std::net::SocketAddr,
    rx: &mut crate::transport::PacketRx,
    datagrams: &[&[u8]],
) -> Vec<Vec<u8>> {
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for d in datagrams {
        sender.send_to(d, to).unwrap();
    }
    let last = datagrams.last().map(|d| d.to_vec());
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while last.is_some() && got.last() != last.as_ref() {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(p)) => got.push(p.data),
            _ => break,
        }
    }
    while let Ok(Some(p)) = timeout(Duration::from_millis(200), rx.recv()).await {
        got.push(p.data);
    }
    got
}

#[test]
fn the_default_filter_discards_punch_packets_and_passes_everything_else() {
    assert_eq!(classify(None, &PROBE), DatagramClass::Discard);
    assert_eq!(classify(None, &ACK), DatagramClass::Discard);
    assert_eq!(classify(None, &PROBE[..4]), DatagramClass::Discard);
    assert_eq!(classify(None, &PROBE[..3]), DatagramClass::Fmp);
    assert_eq!(classify(None, FMP), DatagramClass::Fmp);
    assert_eq!(classify(None, &[]), DatagramClass::Fmp);
}

#[test]
fn a_registered_classifier_decides_in_place_of_the_default_filter() {
    assert_eq!(
        classify(Some(discard_marked), MARKED),
        DatagramClass::Discard
    );
    assert_eq!(classify(Some(discard_marked), &PROBE), DatagramClass::Fmp);
}

#[test]
fn the_nostr_classifier_discards_both_punch_packets() {
    let nostr: Classifier = crate::nostr::classify_datagram;
    assert_eq!(classify(Some(nostr), &PROBE), DatagramClass::Discard);
    assert_eq!(classify(Some(nostr), &ACK), DatagramClass::Discard);
    assert_eq!(classify(Some(nostr), FMP), DatagramClass::Fmp);
}

#[tokio::test]
async fn a_started_instance_applies_its_registered_classifier() {
    let (tx, mut rx) = packet_channel(16);
    let mut t = UdpTransport::new(TransportId::new(1), None, loopback(), tx);
    t.set_classifier(discard_marked);
    t.start_async().await.unwrap();
    let got = deliver(t.local_addr().unwrap(), &mut rx, &[MARKED, FMP]).await;
    assert_eq!(got, vec![FMP.to_vec()]);
    t.stop_async().await.unwrap();
}

#[tokio::test]
async fn a_started_instance_with_the_nostr_classifier_keeps_punch_packets_from_fmp() {
    let (tx, mut rx) = packet_channel(16);
    let mut t = UdpTransport::new(TransportId::new(1), None, loopback(), tx);
    t.set_classifier(crate::nostr::classify_datagram);
    t.start_async().await.unwrap();
    let got = deliver(t.local_addr().unwrap(), &mut rx, &[&PROBE, &ACK, FMP]).await;
    assert_eq!(got, vec![FMP.to_vec()]);
    t.stop_async().await.unwrap();
}

#[tokio::test]
async fn an_adopted_instance_applies_its_registered_classifier() {
    let (tx, mut rx) = packet_channel(16);
    let mut t = UdpTransport::new(TransportId::new(1), None, loopback(), tx);
    t.set_classifier(discard_marked);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    t.adopt_socket_async(socket).await.unwrap();
    let got = deliver(t.local_addr().unwrap(), &mut rx, &[MARKED, FMP]).await;
    assert_eq!(got, vec![FMP.to_vec()]);
    t.stop_async().await.unwrap();
}

#[tokio::test]
async fn an_adopted_instance_without_a_classifier_keeps_punch_packets_from_fmp() {
    let (tx, mut rx) = packet_channel(16);
    let mut t = UdpTransport::new(TransportId::new(1), None, loopback(), tx);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    t.adopt_socket_async(socket).await.unwrap();
    let got = deliver(t.local_addr().unwrap(), &mut rx, &[&PROBE, &ACK, FMP]).await;
    assert_eq!(got, vec![FMP.to_vec()]);
    t.stop_async().await.unwrap();
}

#[tokio::test]
async fn the_receive_loop_applies_the_classifier_it_was_given() {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = receiver.local_addr().unwrap();
    let socket = crate::transport::udp::io::UdpRawSocket::adopt(receiver, 65536, 65536)
        .unwrap()
        .into_async()
        .unwrap();
    let (tx, mut rx) = packet_channel(16);
    let task = tokio::spawn(udp_receive_loop(
        socket,
        TransportId::new(1),
        tx,
        1280,
        Arc::new(UdpStats::new()),
        Some(discard_marked),
    ));
    let got = deliver(to, &mut rx, &[MARKED, FMP]).await;
    assert_eq!(got, vec![FMP.to_vec()]);
    task.abort();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_connected_drain_applies_the_classifier_it_was_given() {
    use crate::transport::udp::{ConnectedPeerSocket, PeerRecvDrain, open_connected_fd};
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let owned = open_connected_fd(local, peer_addr, 1 << 20, 1 << 20, None).unwrap();
    let socket = Arc::new(ConnectedPeerSocket::from_fd(owned, peer_addr, local));
    let ours = {
        use std::os::fd::{AsRawFd, BorrowedFd};
        let fd = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
        let dup = std::net::UdpSocket::from(fd.try_clone_to_owned().unwrap());
        dup.local_addr().unwrap()
    };
    let (tx, mut rx) = packet_channel(16);
    let _drain = PeerRecvDrain::spawn(
        socket.clone(),
        TransportId::new(1),
        peer_addr,
        tx,
        Arc::new(UdpStats::new()),
        Some(discard_marked),
    )
    .unwrap();
    peer.send_to(MARKED, ours).unwrap();
    peer.send_to(FMP, ours).unwrap();
    let first = timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("a datagram reached the channel")
        .unwrap();
    assert_eq!(first.data, FMP.to_vec());
}
