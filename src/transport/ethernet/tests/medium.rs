//! The medium an Ethernet transport reports: unknown until a binding has
//! read it, and forgotten with the binding.

use super::*;

/// A transport on an interface no host has, so it starts absent and never
/// binds.
fn transport_on_a_missing_interface() -> (EthernetTransport, super::super::PacketRx) {
    let config = EthernetConfig {
        interface: "fips-medium-x0".to_string(),
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

#[tokio::test]
async fn a_transport_that_has_not_bound_its_interface_reports_an_unknown_medium() {
    let (mut eth, _rx) = transport_on_a_missing_interface();
    assert_eq!(eth.medium(), Medium::Unknown);
    eth.start_async().await.expect("start");
    assert_eq!(eth.medium(), Medium::Unknown, "absent, so never read");
    eth.stop_async().await.expect("stop");
}

/// A medium surviving teardown would rank the transport's paths by an
/// interface it no longer holds, and by the old device's medium once the
/// name comes back on other hardware.
#[tokio::test]
async fn teardown_forgets_the_medium_its_binding_read() {
    let (mut eth, _rx) = transport_on_a_missing_interface();
    *eth.binding.medium.write().unwrap() = Medium::Wired;
    assert_eq!(eth.medium(), Medium::Wired);
    eth.start_async().await.expect("start");
    eth.stop_async().await.expect("stop");
    assert_eq!(eth.medium(), Medium::Unknown);
}
