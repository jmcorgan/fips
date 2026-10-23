//! Tests that an Ethernet transport whose interface is deleted and recreated
//! (as an OpenWrt network or wifi reload rebuilds `br-lan` or a mesh vif)
//! goes on sending and receiving on the new interface without a restart.
//!
//! The tests build a network namespace holding a bridge with two veth pairs,
//! one for the node's transport and one for a peer transport, and recreate
//! the node's veth under the same name, which gives it a new index, or move
//! it to another namespace and back, which keeps its index. They need
//! root, so no CI job runs them: they are run by hand under `sudo` with
//! `--ignored`, and that run is the only coverage of the rebind. macOS (BPF)
//! is compiled by the cross-check and not run; there the same check would be
//! a transport on `bridge9`, `ifconfig bridge9 destroy; ifconfig bridge9
//! create`, and a frame from a peer. The module is Linux only.

use super::*;
use crate::transport::{PacketRx, TransportId, packet_channel};
use std::time::Duration;

/// The node transport's interface, recreated by the tests.
const NODE_IF: &str = "fn0";
/// The peer transport's interface, left alone.
const PEER_IF: &str = "fp0";

/// A root network namespace of its own, deleted on drop: bridge `br0` with
/// the veth pairs `fn0`/`fn0b` and `fp0`/`fp0b`, the `b` ends enslaved to the
/// bridge. Needs root.
struct BridgeNetns(String);

impl BridgeNetns {
    fn new() -> Self {
        let ns = Self::bare();
        ns.ip(&["link", "set", "lo", "up"]);
        ns.ip(&["link", "add", "br0", "type", "bridge"]);
        ns.ip(&["link", "set", "br0", "up"]);
        ns.veth(NODE_IF);
        ns.veth(PEER_IF);
        ns
    }

    /// An empty namespace, with no bridge or interfaces of its own.
    fn bare() -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("fipseth-{}-{seq}", std::process::id());
        crate::testutil::run_ok("ip", &["netns", "add", &name]);
        Self(name)
    }

    /// Run `ip -n <ns> <args>`, failing the test when it fails.
    fn ip(&self, args: &[&str]) {
        let mut full = vec!["-n", self.0.as_str()];
        full.extend_from_slice(args);
        crate::testutil::run_ok("ip", &full);
    }

    /// Add the veth pair `<name>`/`<name>b`, enslave the `b` end to `br0`,
    /// and bring both up.
    fn veth(&self, name: &str) {
        let bridged = format!("{name}b");
        self.ip(&[
            "link", "add", name, "type", "veth", "peer", "name", &bridged,
        ]);
        self.ip(&["link", "set", &bridged, "master", "br0"]);
        self.ip(&["link", "set", &bridged, "up"]);
        self.ip(&["link", "set", name, "up"]);
    }

    /// Delete and recreate the node's veth pair under the same names, as a
    /// network reload does: `fn0` gets a new index, the peer side is untouched.
    fn recreate(&self) {
        let before = self.index(NODE_IF);
        self.ip(&["link", "del", NODE_IF]);
        self.veth(NODE_IF);
        assert_ne!(
            self.index(NODE_IF),
            before,
            "precondition: the recreated interface has a new index"
        );
    }

    /// Move the node's interface into the namespace `away` and back, then
    /// bring it up. The kernel unregisters it from this namespace and
    /// registers it again, but it keeps its index, so a check that compares
    /// indices sees nothing change.
    fn round_trip(&self, away: &str) {
        let before = self.index(NODE_IF);
        self.ip(&["link", "set", NODE_IF, "netns", away]);
        crate::testutil::run_ok(
            "ip",
            &["-n", away, "link", "set", NODE_IF, "netns", self.0.as_str()],
        );
        self.ip(&["link", "set", NODE_IF, "up"]);
        assert_eq!(
            self.index(NODE_IF),
            before,
            "precondition: the returned interface keeps its index"
        );
    }

    fn link(&self, name: &str) -> serde_json::Value {
        let out = std::process::Command::new("ip")
            .args(["-n", &self.0, "-j", "link", "show", name])
            .output()
            .unwrap();
        assert!(out.status.success(), "ip link show {name} failed");
        let links: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        links[0].clone()
    }

    fn index(&self, name: &str) -> u64 {
        self.link(name)["ifindex"].as_u64().unwrap()
    }

    /// The MAC address of `name`.
    fn mac(&self, name: &str) -> [u8; 6] {
        parse_mac_string(self.link(name)["address"].as_str().unwrap()).unwrap()
    }

    /// Run the async test body inside the namespace, on a current-thread
    /// runtime built there: the transports' sockets, and any socket a
    /// transport opens later, are made in the calling thread's namespace.
    fn run<F, Fut>(self, body: F)
    where
        F: FnOnce(BridgeNetns) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()>,
    {
        let name = self.0.clone();
        crate::testutil::in_netns(&name, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("ethernet runtime");
            runtime.block_on(body(self));
        });
    }
}

impl Drop for BridgeNetns {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.0])
            .status();
    }
}

/// Start a transport on `interface`, returning it and its packet channel.
async fn start(id: u32, interface: &str, announce: bool) -> (EthernetTransport, PacketRx) {
    let (packet_tx, packet_rx) = packet_channel(1024);
    let mut transport = EthernetTransport::new(
        TransportId::new(id),
        None,
        EthernetConfig {
            interface: interface.to_string(),
            listen: Some(true),
            announce: Some(announce),
            beacon_interval_secs: Some(10),
            ..Default::default()
        },
        packet_tx,
    );
    transport
        .start_async()
        .await
        .expect("ethernet start (needs root in the netns)");
    (transport, packet_rx)
}

/// Whether `rx` holds a packet carrying `payload`, draining what it holds.
fn received(rx: &mut PacketRx, payload: &[u8]) -> bool {
    let mut found = false;
    while let Ok(packet) = rx.try_recv() {
        found |= packet.data == payload;
    }
    found
}

/// Send `payload` from `from` to `to` every 500 ms until `rx` receives it,
/// for at most `within`. Returns whether it arrived.
async fn delivered(
    from: &EthernetTransport,
    to: [u8; 6],
    rx: &mut PacketRx,
    payload: &[u8],
    within: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        let _ = from.send_async(&TransportAddr::from_mac(to), payload).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if received(rx, payload) {
            return true;
        }
    }
    false
}

/// The issue's sequence: beacons on, the interface recreated. The node's
/// beacons resume on the new interface, and data frames sent to it are
/// received.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn beacons_resume_and_frames_are_received_after_the_interface_is_recreated() {
    BridgeNetns::new().run(|ns| async move {
        let (node, mut node_rx) = start(1, NODE_IF, true).await;
        let (peer, _peer_rx) = start(2, PEER_IF, false).await;
        assert!(
            delivered(
                &peer,
                ns.mac(NODE_IF),
                &mut node_rx,
                b"before",
                Duration::from_secs(10)
            )
            .await,
            "precondition: the node receives frames before the recreate"
        );

        ns.recreate();
        let new_mac = TransportAddr::from_mac(ns.mac(NODE_IF));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut beaconed = false;
        while !beaconed && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(500)).await;
            beaconed = peer.discover().unwrap().iter().any(|d| d.addr == new_mac);
        }
        assert!(
            beaconed,
            "precondition: the node's beacons reach the peer from the new interface"
        );

        assert!(
            delivered(
                &peer,
                ns.mac(NODE_IF),
                &mut node_rx,
                b"after",
                Duration::from_secs(15)
            )
            .await,
            "the node beacons on the recreated interface but receives nothing on it"
        );
        drop(node);
    });
}

/// With beacons off nothing used to reopen at all: after the recreate the
/// node must still receive from the peer, and its own sends must succeed and
/// arrive.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn a_recreated_interface_is_rebound_for_sending_and_receiving_with_announce_off() {
    BridgeNetns::new().run(|ns| async move {
        let (node, mut node_rx) = start(1, NODE_IF, false).await;
        let (peer, mut peer_rx) = start(2, PEER_IF, false).await;
        let peer_mac = ns.mac(PEER_IF);
        assert!(
            delivered(
                &peer,
                ns.mac(NODE_IF),
                &mut node_rx,
                b"before",
                Duration::from_secs(10)
            )
            .await,
            "precondition: the node receives frames before the recreate"
        );

        ns.recreate();
        let node_mac = ns.mac(NODE_IF);

        assert!(
            delivered(
                &peer,
                node_mac,
                &mut node_rx,
                b"to node",
                Duration::from_secs(20)
            )
            .await,
            "the node receives nothing on the recreated interface"
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut last = None;
        let mut arrived = false;
        while !arrived && tokio::time::Instant::now() < deadline {
            last = Some(
                node.send_async(&TransportAddr::from_mac(peer_mac), b"to peer")
                    .await,
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            arrived = received(&mut peer_rx, b"to peer");
        }
        assert!(
            matches!(last, Some(Ok(_))),
            "the node's send on the recreated interface fails: {last:?}"
        );
        assert!(arrived, "the node's frames do not reach the peer");
    });
}

/// An interface that leaves the namespace and comes back keeps its index,
/// but the kernel still unhooked the transport's socket when it left. The
/// node must rebind and go on receiving and sending.
#[test]
#[ignore = "needs root: creates network namespaces; fails today: the binder does not rebind an interface that returns with its old index"]
fn an_interface_that_returns_with_the_same_index_is_rebound() {
    let away = BridgeNetns::bare();
    let away_name = away.0.clone();
    BridgeNetns::new().run(move |ns| async move {
        let (node, mut node_rx) = start(1, NODE_IF, false).await;
        let (peer, mut peer_rx) = start(2, PEER_IF, false).await;
        let node_mac = ns.mac(NODE_IF);
        let peer_mac = ns.mac(PEER_IF);
        assert!(
            delivered(
                &peer,
                node_mac,
                &mut node_rx,
                b"before",
                Duration::from_secs(10)
            )
            .await,
            "precondition: the node receives frames before the round trip"
        );

        ns.round_trip(&away_name);

        assert!(
            delivered(
                &peer,
                node_mac,
                &mut node_rx,
                b"to node",
                Duration::from_secs(20)
            )
            .await,
            "the node receives nothing after its interface returned with the same index"
        );
        assert!(
            delivered(
                &node,
                peer_mac,
                &mut peer_rx,
                b"to peer",
                Duration::from_secs(20)
            )
            .await,
            "the node's frames do not reach the peer after the round trip"
        );
        drop(away);
    });
}
