//! The encrypt workers' reports of sends to unreachable addresses
//! (`encrypt_worker.rs`) and the node's handling of them
//! (`handlers/path.rs`): which failures a worker reports, and that a report
//! reaches the path it names. Loopback nodes only.

use super::paths::{
    active_of, exchange, prepared_pair, second_transport, state_at, t2, transport_at,
};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::peer::PathState;
use std::net::SocketAddr;

/// Only unix starts encrypt workers, so only unix builds their reporter.
#[cfg(unix)]
#[test]
fn a_worker_reports_only_an_unreachable_destination() {
    use crate::node::encrypt_worker::report_failure;
    use crate::node::handlers::path::SendReport;
    use std::io::{Error, ErrorKind};
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    let transport = TransportId::new(3);
    let dest: SocketAddr = "198.51.100.9:2121".parse().unwrap();
    for kind in [ErrorKind::NetworkUnreachable, ErrorKind::NetworkDown] {
        report_failure(Some(&tx), transport, dest, &Error::from(kind));
        assert_eq!(
            rx.try_recv(),
            Ok(SendReport { transport, dest }),
            "{kind:?}"
        );
    }
    report_failure(
        Some(&tx),
        transport,
        dest,
        &Error::from(ErrorKind::PermissionDenied),
    );
    assert!(rx.try_recv().is_err(), "a send refused for another reason");
    // A full channel drops the report and does not block.
    let unreachable = Error::from(ErrorKind::HostUnreachable);
    for _ in 0..3 {
        report_failure(Some(&tx), transport, dest, &unreachable);
    }
    assert!(rx.try_recv().is_ok() && rx.try_recv().is_ok());
    assert!(rx.try_recv().is_err(), "the third report was dropped");
    report_failure(None, transport, dest, &unreachable);
}

/// Two linked nodes with multipath enabled, A (0) dialling B (1) at B's
/// address `B1`, which has the form of a socket address, and each with a
/// second loopback transport `t2()`. A holds p, (t1, B1), and q (`t2()`,
/// B2), both Live, p active. Returns the nodes, B's address, `B1` and B2.
async fn socket_pair() -> (Vec<TestNode>, NodeAddr, SocketAddr, TransportAddr) {
    let b1: SocketAddr = "198.51.100.2:2121".parse().unwrap();
    let mut nodes = prepared_pair(|nodes| {
        let t1 = nodes[1].transport_id;
        nodes[1].addr = transport_at(&mut nodes[1], t1, &b1.to_string());
    })
    .await;
    second_transport(&mut nodes[0], t2(), 1280);
    let b2 = second_transport(&mut nodes[1], t2(), 1280);
    let b = *nodes[1].node.node_addr();
    nodes[0].node.offer_path(&b, t2(), b2.clone()).await;
    exchange(&mut nodes).await;
    assert_eq!(state_at(&nodes[0], &b, t2(), &b2), Some(PathState::Live));
    let t1 = nodes[0].transport_id;
    assert_eq!(active_of(&nodes[0], &b), (t1, nodes[1].addr.clone()));
    (nodes, b, b1, b2)
}

/// An encrypt worker's report of an unreachable address steps the path at that
/// pair, and one naming a pair no link holds moves nothing.
#[tokio::test]
async fn a_worker_report_steps_the_path_it_names() {
    let (mut nodes, b, b1, b2) = socket_pair().await;
    let t1 = nodes[0].transport_id;
    // A report naming a pair no link holds, on the same transport.
    let elsewhere: SocketAddr = "198.51.100.3:2121".parse().unwrap();
    nodes[0].node.path_unreachable(t1, elsewhere).await;
    assert_eq!(active_of(&nodes[0], &b).0, t1, "nothing moves");
    let p = TransportAddr::from_string(&b1.to_string());
    assert_eq!(state_at(&nodes[0], &b, t1, &p), Some(PathState::Live));
    nodes[0].node.path_unreachable(t1, b1).await;
    assert_eq!(active_of(&nodes[0], &b), (t2(), b2), "the link moved to q");
    cleanup_nodes(&mut nodes).await;
}
