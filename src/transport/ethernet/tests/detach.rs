//! What the binder leaves behind when the interface it is bound to goes away.

use super::*;

/// A transport on an interface no host has, so the binder's probe finds it
/// gone the first time the transport reads as bound.
fn transport_on_a_missing_interface() -> (EthernetTransport, super::super::PacketRx) {
    let config = EthernetConfig {
        interface: "fips-detach-x0".to_string(),
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
async fn a_beacon_heard_before_the_interface_detaches_is_not_left_to_drain() {
    // A beacon heard on the binding sits in the buffer until the next
    // discovery tick drains it. If the interface goes away first, the
    // neighbour it names is reached through a binding that no longer
    // exists, and a dial to it cannot be sent.
    let (mut eth, _rx) = transport_on_a_missing_interface();
    eth.start_async()
        .await
        .expect("absence is not a start failure");
    assert_eq!(eth.presence(), Presence::Absent);

    // The receive loop's part, then the bind's: a beacon buffered on a
    // binding the transport reads as held. The binder's next probe finds
    // the interface gone and takes the detach branch.
    eth.neighbor_buffer
        .add_peer([0x16, 0x2c, 0x01, 0x84, 0x27, 0x54]);
    eth.presence.transition(Presence::Present);

    let deadline = Instant::now() + Duration::from_secs(10);
    while eth.presence() == Presence::Present {
        assert!(
            Instant::now() < deadline,
            "the binder never detached the missing interface"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(eth.presence(), Presence::Absent);

    let drained = eth.discover().expect("discover");
    assert!(
        drained.is_empty(),
        "a beacon heard before the detach was left to drain: {drained:?}"
    );

    eth.stop_async().await.expect("stop");
}
