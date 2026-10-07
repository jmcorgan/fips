//! The listing of transport kinds: for each kind, the tests that run each
//! rule against it, or the reason a rule does not apply.
//!
//! `listing` is an exhaustive `match` over [`TransportHandle`] with no
//! wildcard arm, so a new transport kind fails the build until it is listed.
//! An instance is named by its test function, so a listed instance that does
//! not exist fails the build too. The test below then checks, on one handle
//! of every kind, that the listing agrees with the type the handle itself
//! reports.

use crate::config::{NymConfig, TcpConfig, TorConfig, UdpConfig};
use crate::transport::loopback::{LoopbackTransport, new_registry};
use crate::transport::nym::NymTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::tor::TorTransport;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};

#[cfg(ble_available)]
use super::ble;
use super::{nym, tcp, tor};

/// How a transport kind meets one rule.
enum Cover {
    /// The tests that run the rule against this kind.
    Instance(&'static [fn()]),
    /// Why the rule does not apply to this kind.
    Exempt(&'static str),
}

/// A connection-oriented kind's cover for each rule.
struct Rules {
    /// Rule 1, close half: a frame queued just before a close reaches the
    /// peer.
    close: Cover,
    /// Rule 1, stop half: stopping the transport ends a writer still
    /// draining after a close.
    stop: Cover,
    /// Rule 2: an accepted connection that sends nothing is closed within
    /// its deadline.
    idle: Cover,
    /// Rule 3: the receive bound is the shared ceiling.
    bound: Cover,
}

/// What the rules make of a transport kind.
enum Kind {
    /// No connections, so no connection lifecycle.
    Connectionless,
    /// A connection-oriented kind, with its cover for each rule.
    Oriented(Rules),
    /// A test double, not a transport the rules govern, with the reason.
    TestDouble(&'static str),
}

/// The listing.
fn listing(handle: &TransportHandle) -> Kind {
    match handle {
        TransportHandle::Udp(_) => Kind::Connectionless,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        TransportHandle::Ethernet(_) => Kind::Connectionless,
        TransportHandle::Tcp(_) => Kind::Oriented(Rules {
            close: Cover::Instance(&[tcp::a_frame_queued_just_before_a_close_reaches_the_peer]),
            stop: Cover::Instance(&[
                tcp::stopping_the_transport_ends_a_writer_still_draining_after_a_close,
            ]),
            idle: Cover::Instance(&[
                tcp::an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline,
                tcp::an_accepted_connection_that_sent_a_frame_is_kept_past_the_deadline,
            ]),
            bound: Cover::Instance(&[
                tcp::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_an_accepted_connection,
                tcp::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_a_connect_on_send_connection,
                tcp::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_a_background_connection,
                tcp::a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes,
            ]),
        }),
        TransportHandle::Tor(_) => Kind::Oriented(Rules {
            close: Cover::Instance(&[tor::a_frame_queued_just_before_a_close_reaches_the_peer]),
            stop: Cover::Instance(&[
                tor::stopping_the_transport_ends_a_writer_still_draining_after_a_close,
            ]),
            idle: Cover::Instance(&[
                tor::an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline,
                tor::an_accepted_connection_that_sent_a_frame_is_kept_past_the_deadline,
            ]),
            bound: Cover::Instance(&[
                tor::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_the_onion_listener,
                tor::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_on_a_dialled_connection,
                tor::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_from_a_tcp_listener,
                tor::a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes,
            ]),
        }),
        TransportHandle::Nym(_) => Kind::Oriented(Rules {
            close: Cover::Instance(&[nym::a_frame_queued_just_before_a_close_reaches_the_peer]),
            stop: Cover::Instance(&[
                nym::stopping_the_transport_ends_a_writer_still_draining_after_a_close,
            ]),
            idle: Cover::Exempt(
                "Nym binds no listener and accepts no connection: every connection is one it \
                 dialled",
            ),
            bound: Cover::Instance(&[
                nym::a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered_from_a_tcp_listener,
                nym::a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes,
            ]),
        }),
        #[cfg(ble_available)]
        TransportHandle::Ble(_) => Kind::Oriented(Rules {
            close: Cover::Instance(&[ble::a_frame_queued_just_before_a_close_reaches_the_peer]),
            stop: Cover::Instance(&[
                ble::stopping_the_transport_ends_a_writer_still_draining_after_a_close,
            ]),
            idle: Cover::Instance(&[
                ble::an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline,
                ble::a_channel_that_completed_a_handshake_and_was_left_unverified_is_kept,
                ble::a_channel_the_node_holds_is_kept_a_full_timeout_after_it_lets_go,
            ]),
            bound: Cover::Exempt(
                "the receive bound is the L2CAP MTU both ends negotiate, and send_async refuses \
                 a frame above it, so a frame the sender admits is within the receiver's bound",
            ),
        }),
        // TODO(usb): no conformance instance yet; these are placeholders,
        // not checked exemptions.
        TransportHandle::Usb(_) => Kind::Oriented(Rules {
            close: Cover::Exempt("not yet covered: no USB instance of the close rule"),
            stop: Cover::Exempt("not yet covered: no USB instance of the stop rule"),
            idle: Cover::Exempt("not yet covered: no USB instance of the idle rule"),
            bound: Cover::Exempt("not yet covered: no USB instance of the receive-bound rule"),
        }),
        #[cfg(test)]
        TransportHandle::Loopback(_) => Kind::TestDouble(
            "an in-process test double, not a transport the rules govern, whatever type a test \
             gives it",
        ),
    }
}

/// One handle of every transport kind, each built with its inert
/// constructor: none binds a socket or starts a task.
fn every_kind() -> Vec<TransportHandle> {
    let (tx, _rx) = packet_channel(1);
    let id = TransportId::new(1);
    let mut handles = vec![
        TransportHandle::Udp(UdpTransport::new(
            id,
            None,
            UdpConfig::default(),
            tx.clone(),
        )),
        TransportHandle::Tcp(TcpTransport::new(
            id,
            None,
            TcpConfig::default(),
            tx.clone(),
        )),
        TransportHandle::Tor(TorTransport::new(
            id,
            None,
            TorConfig::default(),
            tx.clone(),
        )),
        TransportHandle::Nym(NymTransport::new(
            id,
            None,
            NymConfig::default(),
            tx.clone(),
        )),
        TransportHandle::Loopback(LoopbackTransport::new(
            id,
            TransportAddr::from_string("loopback-1"),
            new_registry(),
        )),
    ];
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    handles.push(TransportHandle::Ethernet(
        crate::transport::ethernet::EthernetTransport::new(
            id,
            None,
            crate::config::EthernetConfig {
                interface: "eth0".to_string(),
                ..Default::default()
            },
            tx.clone(),
        ),
    ));
    #[cfg(ble_available)]
    {
        use crate::transport::ble::BleTransport;
        use crate::transport::ble::addr::BleAddr;
        use crate::transport::ble::io::MockBleIo;
        let io = MockBleIo::new("hci0", BleAddr::parse("hci0/AA:BB:CC:DD:EE:01").unwrap());
        handles.push(TransportHandle::Ble(BleTransport::new(
            id,
            None,
            crate::config::BleConfig::default(),
            io,
            tx,
        )));
    }
    handles
}

/// The problems with one cover entry, if any.
fn cover_problem(kind: &str, rule: &str, cover: &Cover) -> Option<String> {
    match cover {
        Cover::Instance([]) => Some(format!("{kind}: {rule} lists an instance with no test")),
        Cover::Exempt(reason) if reason.trim().is_empty() => {
            Some(format!("{kind}: {rule} is exempt with no reason"))
        }
        _ => None,
    }
}

#[tokio::test]
async fn every_connection_oriented_kind_has_an_instance_or_a_stated_exemption() {
    let handles = every_kind();
    let mut problems = Vec::new();
    for handle in &handles {
        let ty = handle.transport_type();
        match listing(handle) {
            Kind::Connectionless if ty.connection_oriented => problems.push(format!(
                "{}: listed as connectionless, but the handle reports a connection-oriented type",
                ty.name
            )),
            Kind::Connectionless => {}
            Kind::Oriented(_) if !ty.connection_oriented => problems.push(format!(
                "{}: listed as connection-oriented, but the handle reports a connectionless type",
                ty.name
            )),
            Kind::Oriented(rules) => {
                for (rule, cover) in [
                    ("the close rule", &rules.close),
                    ("the stop rule", &rules.stop),
                    ("the idle rule", &rules.idle),
                    ("the receive-bound rule", &rules.bound),
                ] {
                    problems.extend(cover_problem(ty.name, rule, cover));
                }
            }
            Kind::TestDouble(reason) if reason.trim().is_empty() => {
                problems.push(format!("{}: a test double with no reason", ty.name))
            }
            Kind::TestDouble(_) => {}
        }
    }
    assert!(
        problems.is_empty(),
        "defect: the listing disagrees with the transport kinds: {problems:#?}"
    );
}
