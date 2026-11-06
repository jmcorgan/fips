//! What the Ethernet transport reports to the node's congestion sample.

use super::*;

/// A transport that has never bound, so it holds no socket.
fn unbound_transport() -> (EthernetTransport, super::super::PacketRx) {
    let config = EthernetConfig {
        interface: "fips-cong-x0".to_string(),
        ethertype: None,
        mtu: None,
        recv_buf_size: None,
        send_buf_size: None,
        listen: Some(true),
        announce: Some(false),
        auto_connect: None,
        accept_connections: None,
        beacon_interval_secs: None,
        optional: Some(true),
        role: crate::config::TransportRole::default(),
    };
    let (tx, rx) = super::super::packet_channel(8);
    (
        EthernetTransport::new(TransportId::new(1), None, config, tx),
        rx,
    )
}

#[cfg(target_os = "linux")]
#[test]
fn the_congestion_sample_reports_the_kernel_drop_total() {
    // Before this transport reported a count the node's sampler saw `None`
    // and could never flag the cable as dropping.
    let (eth, _rx) = unbound_transport();
    assert_eq!(eth.congestion().recv_drops, Some(0));
    eth.stats().record_kernel_drops(12);
    assert_eq!(eth.congestion().recv_drops, Some(12));
    assert_eq!(
        eth.congestion().recv_drops,
        Some(12),
        "with no socket to read, a sample must not change the total"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn the_congestion_sample_reports_nothing_where_drops_are_not_read() {
    let (eth, _rx) = unbound_transport();
    eth.stats().record_kernel_drops(12);
    assert_eq!(eth.congestion().recv_drops, None);
}
