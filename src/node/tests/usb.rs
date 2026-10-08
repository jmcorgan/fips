//! USB transport integration tests.
//!
//! Two nodes joined by an in-memory [`UsbLink`] pair, driven the way a cable
//! drives them: the link is attached, each side's hello publishes the other,
//! and the node's ordinary discovery path takes it from there — no address is
//! ever dialled.

use super::*;
use crate::config::UsbConfig;
use crate::transport::usb::{UsbLink, UsbLinkQueue, UsbTransport};
use crate::transport::{TransportHandle, TransportId, packet_channel};
use spanning_tree::{TestNode, cleanup_nodes, process_available_packets};
use std::sync::Arc;

/// A node with a started USB transport, and the queue its links arrive on.
async fn make_test_node_usb() -> (TestNode, Arc<UsbLinkQueue>) {
    let mut node = make_node();
    // Discovery only dials from a running node.
    node.supervisor.state = NodeState::Running;
    let transport_id = TransportId::new(1);
    let links = Arc::new(UsbLinkQueue::new());

    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = UsbTransport::new(
        transport_id,
        None,
        UsbConfig::default(),
        Arc::clone(&links),
        packet_tx,
    );
    transport.set_local_pubkey(node.identity().pubkey().serialize());
    transport.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Usb(transport));

    let test_node = TestNode {
        node,
        transport_id,
        packet_rx: spanning_tree::bridge_to_unbounded(packet_rx),
        // A USB node has no address of its own; only links do.
        addr: TransportAddr::from_string("usb"),
    };
    (test_node, links)
}

/// Wait until `node`'s USB transport has pooled the link labelled `label`,
/// that is, until its hello has completed.
async fn wait_for_link(node: &TestNode, label: &str) {
    let addr = TransportAddr::from_string(label);
    let Some(handle) = node.node.transports.get(&node.transport_id) else {
        panic!("no USB transport");
    };
    for _ in 0..200 {
        if handle.has_connection(&addr).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("USB link {label} never completed its hello");
}

/// Run the node loops the rx loop would — discovery, pending connects,
/// inbound packets — until nothing more happens.
async fn settle(nodes: &mut [TestNode]) {
    let mut quiet = 0;
    for _ in 0..300 {
        for n in nodes.iter_mut() {
            n.node.poll_transport_discovery().await;
            n.node.poll_pending_connects().await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        if process_available_packets(nodes).await == 0 {
            quiet += 1;
            if quiet >= 10 {
                return;
            }
        } else {
            quiet = 0;
        }
    }
}

/// Plugging a cable between two nodes makes them peers, with both ends
/// publishing the other and dialling at once.
#[tokio::test]
async fn a_cable_makes_two_nodes_peers() {
    let (n0, links0) = make_test_node_usb().await;
    let (n1, links1) = make_test_node_usb().await;
    let mut nodes = vec![n0, n1];

    let (a, b) = UsbLink::pair("acc0", "host/1-1");
    links0.push(a);
    links1.push(b);
    wait_for_link(&nodes[0], "acc0").await;
    wait_for_link(&nodes[1], "host/1-1").await;
    settle(&mut nodes).await;

    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 should have node 1 as peer"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 should have node 0 as peer"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Two links joined through relay tasks the test can kill, so the cable can
/// be pulled: aborting the relays closes both ends, as an unplug does.
fn cable(a_label: &str, b_label: &str) -> (UsbLink, UsbLink, Vec<tokio::task::JoinHandle<()>>) {
    use tokio::sync::mpsc;
    fn relay(
        mut from: mpsc::Receiver<Vec<u8>>,
        to: mpsc::Sender<Vec<u8>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(chunk) = from.recv().await {
                if to.send(chunk).await.is_err() {
                    break;
                }
            }
        })
    }
    let (a_tx, a_out) = mpsc::channel(8);
    let (b_in_tx, b_rx) = mpsc::channel(8);
    let (b_tx, b_out) = mpsc::channel(8);
    let (a_in_tx, a_rx) = mpsc::channel(8);
    let relays = vec![relay(a_out, b_in_tx), relay(b_out, a_in_tx)];
    (
        UsbLink {
            label: a_label.into(),
            rx: a_rx,
            tx: a_tx,
        },
        UsbLink {
            label: b_label.into(),
            rx: b_rx,
            tx: b_tx,
        },
        relays,
    )
}

/// Pulling the cable removes the peer on both ends within a fast path tick
/// or two, not after the link-dead timeout: the transport reports the link
/// closed and the node acts on it.
#[tokio::test]
async fn pulling_the_cable_removes_the_peer_at_once() {
    let (n0, links0) = make_test_node_usb().await;
    let (n1, links1) = make_test_node_usb().await;
    let mut nodes = vec![n0, n1];

    let (a, b, relays) = cable("acc0", "host/1-1");
    links0.push(a);
    links1.push(b);
    wait_for_link(&nodes[0], "acc0").await;
    wait_for_link(&nodes[1], "host/1-1").await;
    settle(&mut nodes).await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "peered before the pull"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "peered before the pull"
    );

    for relay in relays {
        relay.abort();
    }
    let pulled = std::time::Instant::now();
    loop {
        for n in nodes.iter_mut() {
            n.node.run_path_heartbeats().await;
        }
        if nodes[0].node.get_peer(&addr_1).is_none() && nodes[1].node.get_peer(&addr_0).is_none() {
            break;
        }
        assert!(
            pulled.elapsed() < Duration::from_secs(1),
            "peers still present a second after the cable was pulled"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    cleanup_nodes(&mut nodes).await;
}
