//! Tests of where the DNS responder sends a reply to a mesh source address
//! when no strict pin to the arrival interface is known to hold, and of the
//! order in which its receive loop reports an identity, sends the reply and
//! refreshes the host map, and of the two synchronous steps that loop takes
//! for each datagram.

#[cfg(target_os = "linux")]
use super::tests::{ForgedSourceNetns, bind_pktinfo, expect_answer, send_unanswered};
use super::*;
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address")
}

/// Where no strict pin holds (every target but Linux), a reply to a mesh
/// source with a known arrival interface is sent only if the route returns
/// it by that interface, on either bind and whether or not the mesh index is
/// known; one with an unknown arrival interface is withheld on a specific
/// bind with a known mesh index and routed otherwise. Non-mesh sources are
/// routed, as with a strict pin.
#[test]
fn reply_path_without_a_strict_pin_sends_mesh_source_replies_only_where_they_return() {
    use ReplyPath::{Returning, Routed, Withheld};
    let at = |ip: &str| std::net::SocketAddr::new(ip.parse().unwrap(), 4444);
    const WILD: bool = true;
    const SPECIFIC: bool = false;
    let cases = [
        // Wildcard bind, mesh interface 3.
        ("fd11:2233::7", Some(2), Some(3), WILD, Returning(2)),
        ("fd11:2233::7", None, Some(3), WILD, Routed),
        ("fdab::2", Some(5), Some(3), WILD, Returning(5)),
        ("2001:db8::2", Some(2), Some(3), WILD, Routed),
        ("fe80::1", Some(2), Some(3), WILD, Routed),
        ("::1", Some(1), Some(3), WILD, Routed),
        ("::ffff:192.0.2.2", Some(2), Some(3), WILD, Routed),
        ("192.0.2.2", Some(2), Some(3), WILD, Routed),
        // Wildcard bind, no known mesh interface.
        ("fd11:2233::7", Some(2), None, WILD, Returning(2)),
        ("fd11:2233::7", None, None, WILD, Routed),
        // Specific bind, mesh interface 3.
        ("fd11:2233::7", Some(2), Some(3), SPECIFIC, Returning(2)),
        ("fdab::2", Some(5), Some(3), SPECIFIC, Returning(5)),
        ("fd11:2233::7", None, Some(3), SPECIFIC, Withheld),
        ("fd11:2233::7", Some(3), Some(3), SPECIFIC, Returning(3)),
        ("2001:db8::2", Some(2), Some(3), SPECIFIC, Routed),
        ("::ffff:192.0.2.2", Some(2), Some(3), SPECIFIC, Routed),
        ("192.0.2.2", Some(2), Some(3), SPECIFIC, Routed),
        // Specific bind, no known mesh interface.
        ("fd11:2233::7", Some(2), None, SPECIFIC, Returning(2)),
        ("fd11:2233::7", None, None, SPECIFIC, Routed),
    ];
    for (ip, arrival, mesh, wildcard, want) in cases {
        assert_eq!(
            reply_path(at(ip), arrival, mesh, wildcard, false),
            want,
            "source {ip}, arrival {arrival:?}, mesh {mesh:?}, wildcard {wildcard}"
        );
    }
}

/// Where the mesh interface's index is unknown and a TUN is up, a mesh query
/// is recognised by address: addressed to the node's mesh address from any
/// other source, or, where the destination is not reported (Windows), from a
/// remote non-v4-mapped `fd00::/8` source. A known index keeps the interface
/// rule alone, and with no TUN nothing is dropped. Runs on every target; it
/// is the Windows coverage.
#[test]
fn a_mesh_query_is_recognised_by_destination_or_mesh_source_when_the_mesh_index_is_unknown() {
    let own: Ipv6Addr = "fd99::1".parse().unwrap();
    let at = |ip: &str| std::net::SocketAddr::new(ip.parse().unwrap(), 4444);
    let arrived = |ifindex: Option<u32>, dst: Option<&str>| Arrival {
        ifindex,
        dst: dst.map(|d| d.parse().unwrap()),
    };
    let known = MeshSide {
        ifindex: Some(3),
        addr: Some(own),
    };
    let unknown = MeshSide {
        ifindex: None,
        addr: Some(own),
    };
    let no_tun = MeshSide::default();
    let cases = [
        // Index known: the interface rule alone, no address fallback.
        (arrived(Some(3), Some("fd99::1")), "fd11::7", known, true),
        (arrived(Some(2), Some("fd99::1")), "fd11::7", known, false),
        (arrived(None, None), "fd11::7", known, false),
        // No TUN: never drops.
        (arrived(Some(2), Some("fd99::1")), "fd11::7", no_tun, false),
        (arrived(None, None), "fd11::7", no_tun, false),
        // Destination known.
        (arrived(Some(2), Some("fd99::1")), "fd11::7", unknown, true),
        (
            arrived(Some(2), Some("fd99::1")),
            "2001:db8::2",
            unknown,
            true,
        ),
        (arrived(Some(1), Some("fd99::1")), "fd99::1", unknown, false),
        (
            arrived(Some(2), Some("2001:db8:1::1")),
            "fd11::7",
            unknown,
            false,
        ),
        (arrived(Some(2), Some("fdab::1")), "fdab::2", unknown, false),
        (
            arrived(Some(2), Some("::ffff:192.0.2.1")),
            "192.0.2.2",
            unknown,
            false,
        ),
        // Destination unknown (Windows).
        (arrived(None, None), "fd11::7", unknown, true),
        (arrived(None, None), "fdab::2", unknown, true),
        (arrived(None, None), "2001:db8::2", unknown, false),
        (arrived(None, None), "::ffff:192.0.2.2", unknown, false),
        (arrived(None, None), "192.0.2.2", unknown, false),
        (arrived(None, None), "fd99::1", unknown, false),
    ];
    for (arrival, src, mesh, dropped) in cases {
        assert_eq!(
            mesh_query(arrival, at(src), mesh),
            dropped,
            "arrival {arrival:?}, source {src}, mesh {mesh:?}"
        );
    }
}

/// The receive path reports a datagram's destination address with its
/// arrival interface. Runs without root.
#[cfg(unix)]
#[tokio::test]
async fn recv_with_pktinfo_reports_the_destination_address() {
    let server =
        tokio::net::UdpSocket::from_std(super::tests::bind_pktinfo("[::1]:0".parse().unwrap()))
            .unwrap();
    let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    client
        .send_to(b"hello", server.local_addr().unwrap())
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let (len, _, arrival) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        recv_with_pktinfo(&server, &mut buf),
    )
    .await
    .expect("the datagram arrives")
    .unwrap();
    assert_eq!(&buf[..len], b"hello");
    assert_eq!(arrival.dst, Some(Ipv6Addr::LOCALHOST));
    assert!(arrival.ifindex.is_some());
}

/// A returning reply to a local destination is delivered: the probe picks
/// the destination itself as the source. Runs without root on any target.
#[tokio::test]
async fn a_returning_reply_to_a_local_address_is_delivered() {
    let sender = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let dst = receiver.local_addr().unwrap();
    send_reply(
        &sender,
        b"returning",
        dst,
        ReplyPath::Returning(0x7fff_fff0),
        None,
    )
    .await
    .unwrap();
    let mut buf = [0u8; 16];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        receiver.recv_from(&mut buf),
    )
    .await
    .expect("the returning reply to a local address was not delivered")
    .unwrap();
    assert_eq!(&buf[..len], b"returning");
}

/// A withheld reply is not sent on any target.
#[tokio::test]
async fn a_withheld_reply_is_not_sent_on_any_target() {
    let sender = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let dst = receiver.local_addr().unwrap();
    let sent = send_reply(&sender, b"withheld", dst, ReplyPath::Withheld, None)
        .await
        .unwrap();
    assert_eq!(sent, 0);
    let mut buf = [0u8; 16];
    let got = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        receiver.recv_from(&mut buf),
    )
    .await;
    assert!(got.is_err(), "the withheld reply was delivered: {got:?}");
}

/// A probe source on one of the arrival interface's prefixes returns the
/// reply by that interface; one on another interface's prefix does not.
#[test]
fn returns_by_is_true_only_for_a_source_on_the_arrival_interface() {
    let prefixes = OnLinkPrefixes::from_indexed([
        (ip("2001:db8:1::1"), 64, Some(2)),
        (ip("fdab::1"), 64, Some(2)),
        (ip("fd99::1"), 128, Some(3)),
    ]);
    assert!(returns_by(ip("fdab::1"), ip("fdab::2"), 2, &prefixes, None));
    assert!(returns_by(
        ip("2001:db8:1::1"),
        ip("fdab::2"),
        2,
        &prefixes,
        None
    ));
    assert!(!returns_by(
        ip("fd99::1"),
        ip("fd11:2233::7"),
        2,
        &prefixes,
        None
    ));
    assert!(returns_by(
        ip("fd99::1"),
        ip("fd11:2233::7"),
        3,
        &prefixes,
        None
    ));
    assert!(!returns_by(
        ip("fdab::1"),
        ip("fdab::2"),
        7,
        &prefixes,
        None
    ));
}

/// A reply whose probe source is its own destination is delivered locally,
/// whatever interface the query was reported on.
#[test]
fn returns_by_is_true_when_the_reply_is_delivered_locally() {
    let prefixes = OnLinkPrefixes::from_indexed([(ip("fd99::1"), 128, Some(3))]);
    assert!(returns_by(ip("fd99::1"), ip("fd99::1"), 2, &prefixes, None));
    assert!(returns_by(
        ip("fd99::1"),
        ip("fd99::1"),
        2,
        &OnLinkPrefixes::default(),
        None
    ));
}

/// An empty or failed interface read holds no prefix, so a reply that is not
/// delivered locally is not judged to return.
#[test]
fn returns_by_is_false_for_an_empty_or_failed_prefix_set() {
    for prefixes in [OnLinkPrefixes::default(), OnLinkPrefixes::failed()] {
        assert!(!returns_by(
            ip("fdab::1"),
            ip("fdab::2"),
            2,
            &prefixes,
            None
        ));
    }
}

/// When no interface holds the node's mesh address, the picked source says
/// nothing about egress, so a reply returns only to a destination on one of
/// the arrival interface's own prefixes, or one delivered locally. With the
/// mesh address held, or no mesh address, the source rule is unchanged. Runs
/// on every target; it is the FreeBSD, macOS and Android coverage.
#[test]
fn returns_by_with_an_addressless_mesh_interface_returns_only_to_an_on_link_destination() {
    let mesh = Some("fd99::1".parse().unwrap());
    let held = OnLinkPrefixes::from_indexed([
        (ip("2001:db8:1::1"), 64, Some(2)),
        (ip("fdab::1"), 64, Some(2)),
        (ip("fd99::1"), 128, Some(3)),
    ]);
    let bare = OnLinkPrefixes::from_indexed([
        (ip("2001:db8:1::1"), 64, Some(2)),
        (ip("fdab::1"), 64, Some(2)),
    ]);
    // Mesh address held by an interface: the source rule, unchanged.
    assert!(!returns_by(
        ip("fd99::1"),
        ip("fd11:2233::7"),
        2,
        &held,
        mesh
    ));
    assert!(returns_by(ip("fdab::1"), ip("fdab::2"), 2, &held, mesh));
    // Mesh address on no interface, destination on the arrival interface.
    assert!(returns_by(ip("fdab::1"), ip("fdab::2"), 2, &bare, mesh));
    assert!(returns_by(
        ip("2001:db8:1::1"),
        ip("2001:db8:1::2"),
        2,
        &bare,
        mesh
    ));
    // The same with an off-link destination whose picked source is on the
    // arrival interface: the reply may leave by the bare mesh interface.
    assert!(!returns_by(
        ip("fdab::1"),
        ip("fd11:2233::7"),
        2,
        &bare,
        mesh
    ));
    assert!(!returns_by(ip("fdab::1"), ip("fdab:1::9"), 2, &bare, mesh));
    // An on-link destination on another interface than the arrival one.
    assert!(!returns_by(ip("fdab::1"), ip("fdab::2"), 7, &bare, mesh));
    // Delivered locally.
    assert!(returns_by(ip("fdab::1"), ip("fdab::1"), 2, &bare, mesh));
    // No mesh address: the source rule, unchanged.
    assert!(returns_by(
        ip("fdab::1"),
        ip("fd11:2233::7"),
        2,
        &bare,
        None
    ));
}

/// A responder running on its own thread inside a node namespace, stopped
/// and joined on drop.
#[cfg(target_os = "linux")]
struct NetnsResponder {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    identities: DnsIdentityRx,
}

#[cfg(target_os = "linux")]
impl Drop for NetnsResponder {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "linux")]
impl ForgedSourceNetns {
    /// Run the responder bound to `bind` on a thread that has entered the
    /// node namespace, with its own current-thread runtime, so everything it
    /// does at reply time (sockets, interface reads) sees that namespace's
    /// routes and interfaces rather than the host's.
    fn spawn_responder(&self, bind: std::net::SocketAddr, mesh: MeshSide) -> NetnsResponder {
        use std::os::fd::AsRawFd;
        let path = format!("/run/netns/{}", self.node);
        let (identity_tx, identities) = tokio::sync::mpsc::channel(16);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let file = std::fs::File::open(&path).expect("open netns");
            let ret = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
            assert_eq!(ret, 0, "setns: {}", std::io::Error::last_os_error());
            let server = bind_pktinfo(bind);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("responder runtime");
            runtime.block_on(async move {
                let server = tokio::net::UdpSocket::from_std(server).unwrap();
                let reloader = HostMapReloader::new(
                    HostMap::new(),
                    std::path::PathBuf::from("/nonexistent/hosts"),
                );
                ready_tx.send(()).unwrap();
                tokio::select! {
                    _ = run_responder(server, identity_tx, 300, reloader, None, mesh) => {}
                    _ = stopped => {}
                }
            });
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the responder starts in the node namespace");
        NetnsResponder {
            stop: Some(stop),
            thread: Some(thread),
            identities,
        }
    }
}

/// A UDP socket bound to `addr` inside namespace `ns`, for the test runtime.
#[cfg(target_os = "linux")]
fn client_in(ns: &str, addr: &'static str) -> tokio::net::UdpSocket {
    let socket = ForgedSourceNetns::enter(ns, move || {
        let s = std::net::UdpSocket::bind(addr).unwrap();
        s.set_nonblocking(true).unwrap();
        s
    });
    tokio::net::UdpSocket::from_std(socket).unwrap()
}

/// Check, inside the node namespace, that the route probe sees that
/// namespace's table: the forged destination routes by `fips0` (source
/// `fd99::1`) and the on-link ULA client by the LAN veth (source `fdab::1`).
#[cfg(target_os = "linux")]
fn assert_probe_sees_the_node_namespace(ns: &ForgedSourceNetns) {
    let (forged, ula) = ForgedSourceNetns::enter(&ns.node, || {
        (
            probe_source("[fd11:2233::7]:4444".parse().unwrap()).unwrap(),
            probe_source("[fdab::2]:4445".parse().unwrap()).unwrap(),
        )
    });
    assert_eq!(forged, ip("fd99::1"), "probe source for the forged address");
    assert_eq!(ula, ip("fdab::1"), "probe source for the ULA client");
}

/// The specific LAN address the responder binds in the namespace tests.
#[cfg(target_os = "linux")]
const LAN_BIND: &str = "[2001:db8:1::1]:5354";

/// With the responder bound to one specific LAN address and no known mesh
/// interface index (an application-supplied TUN, or an index that did not
/// resolve), a LAN host that forges a mesh source address must not draw the
/// reply into the mesh by the `fd00::/8` route.
///
/// Needs root (network namespaces, nft): build with
/// `cargo test --lib --no-run` and run the test binary under `sudo` with
/// `--ignored`.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_forged_mesh_source_on_a_specific_bind_with_no_mesh_index_is_not_answered_into_the_mesh()
{
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, MeshSide::default());
    let forged = client_in(&ns.lan, "[fd11:2233::7]:4444");

    send_unanswered(&forged, target, &mut responder.identities).await;
    let into_mesh = ns.mesh_replies();
    drop(responder);
    assert_eq!(
        into_mesh, 0,
        "with the responder bound to 2001:db8:1::1 and no mesh index, a LAN query from \
         forged source fd11:2233::7 was answered into the mesh: {into_mesh} UDP packet(s) \
         from port 5354 left by fips0"
    );
}

/// On the same setup a LAN client with a global source address is answered.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_global_lan_client_on_a_specific_bind_with_no_mesh_index_is_answered() {
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, MeshSide::default());
    let client = client_in(&ns.lan, "[2001:db8:1::2]:4443");
    expect_answer(
        &client,
        target,
        &mut responder.identities,
        "the global LAN client is answered",
    )
    .await;
    assert_eq!(ns.mesh_replies(), 0);
}

/// On the same setup an on-link ULA client, whose source lies in `fd00::/8`
/// but on the LAN's own `fdab::/64`, is answered: the table sends its reply
/// back out of the LAN interface it arrived on.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn an_on_link_ula_client_on_a_specific_bind_with_no_mesh_index_is_answered() {
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, MeshSide::default());
    let client = client_in(&ns.lan, "[fdab::2]:4445");
    expect_answer(
        &client,
        target,
        &mut responder.identities,
        "the on-link ULA client is answered",
    )
    .await;
    assert_eq!(ns.mesh_replies(), 0);
}

/// On the same setup a local process sending from the node's own mesh
/// address to the LAN bind is answered: its reply is delivered locally and
/// never leaves the node.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_local_client_sending_from_the_mesh_address_on_a_specific_bind_is_answered() {
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, MeshSide::default());
    let client = client_in(&ns.node, "[fd99::1]:4446");
    expect_answer(
        &client,
        target,
        &mut responder.identities,
        "the local client sending from fd99::1 is answered",
    )
    .await;
    assert_eq!(ns.mesh_replies(), 0);
}

/// The node namespace's mesh address, on its `fips0`.
#[cfg(target_os = "linux")]
const MESH_ADDR: &str = "fd99::1";

/// Run the responder in the node namespace as the daemon starts it with an
/// application-supplied TUN up: the mesh interface's index is unknown, and
/// the node's mesh address is known.
#[cfg(target_os = "linux")]
fn spawn_with_app_owned_tun(ns: &ForgedSourceNetns, bind: &str) -> NetnsResponder {
    let mesh = MeshSide {
        ifindex: None,
        addr: Some(MESH_ADDR.parse().unwrap()),
    };
    ns.spawn_responder(bind.parse().unwrap(), mesh)
}

/// Send an AAAA query for a fresh npub from `client` to `to`, and report
/// whether any reply came back within 500 ms.
#[cfg(target_os = "linux")]
async fn answered(client: &tokio::net::UdpSocket, to: &str) -> bool {
    let to: std::net::SocketAddr = to.parse().unwrap();
    let query = super::tests::build_test_query(
        &format!("{}.fips", crate::Identity::generate().npub()),
        simple_dns::TYPE::AAAA,
    );
    client.send_to(&query, to).await.unwrap();
    let mut buf = [0u8; 512];
    tokio::time::timeout(
        std::time::Duration::from_millis(500),
        client.recv_from(&mut buf),
    )
    .await
    .is_ok()
}

/// A query addressed to the node's own mesh address from a remote mesh
/// source is how a mesh peer's query arrives through the node's TUN. With
/// the mesh interface's index unknown (an application-supplied TUN) the
/// arrival filter cannot see it, so the responder must recognise it by its
/// destination. Here it arrives on the LAN veth by a route the LAN namespace
/// holds for the mesh address, standing in for a TUN the node cannot index;
/// the node namespace holds a route back to the peer by the same veth, as a
/// TUN's `fd00::/8` route takes a reply back out of the TUN. Without it the
/// reply, pinned to the arrival interface, has no route and is never sent.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_query_to_the_node_mesh_address_from_a_mesh_source_is_not_answered_when_the_mesh_index_is_unknown()
 {
    let ns = ForgedSourceNetns::new();
    crate::testutil::run_ok(
        "ip",
        &[
            "-n",
            &ns.lan,
            "route",
            "add",
            "fd99::1/128",
            "via",
            "fdab::1",
        ],
    );
    crate::testutil::run_ok(
        "ip",
        &[
            "-n",
            &ns.node,
            "route",
            "add",
            "fd11:2233::7/128",
            "via",
            "fdab::2",
            "dev",
            "a0",
        ],
    );
    let _responder = spawn_with_app_owned_tun(&ns, "[::]:5354");
    let peer = client_in(&ns.lan, "[fd11:2233::7]:4444");
    assert!(
        !answered(&peer, "[fd99::1]:5354").await,
        "a query to the node's mesh address from mesh source fd11:2233::7 was answered \
         with the mesh index unknown"
    );
}

/// A local process sending from the node's own mesh address to that address
/// is not a mesh peer, and is still answered with the mesh index unknown.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_local_process_querying_its_own_mesh_address_is_still_answered_when_the_mesh_index_is_unknown()
 {
    let ns = ForgedSourceNetns::new();
    let _responder = spawn_with_app_owned_tun(&ns, "[::]:5354");
    let local = client_in(&ns.node, "[fd99::1]:4446");
    assert!(
        answered(&local, "[fd99::1]:5354").await,
        "a local process querying its own mesh address was not answered"
    );
}

/// A LAN client querying the node's LAN address on a wildcard bind is still
/// answered with the mesh index unknown.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_lan_client_on_a_wildcard_bind_is_still_answered_when_the_mesh_index_is_unknown() {
    let ns = ForgedSourceNetns::new();
    let _responder = spawn_with_app_owned_tun(&ns, "[::]:5354");
    let client = client_in(&ns.lan, "[2001:db8:1::2]:4443");
    assert!(
        answered(&client, "[2001:db8:1::1]:5354").await,
        "a LAN client on a wildcard bind was not answered"
    );
}

/// With an application-supplied TUN that carries no IPv6 address, the
/// kernel picks a reply's source from another interface, so the source no
/// longer says which interface the reply leaves by. A LAN host that forges a
/// mesh source address on a specific bind must still not draw the reply into
/// the mesh by the TUN's `fd00::/8` route.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_forged_mesh_source_on_a_specific_bind_is_not_answered_into_an_addressless_mesh_interface()
 {
    let ns = ForgedSourceNetns::with_addressless_mesh();
    let source = ForgedSourceNetns::enter(&ns.node, || {
        probe_source("[fd11:2233::7]:4444".parse().unwrap()).unwrap()
    });
    assert_eq!(
        source,
        ip("fdab::1"),
        "with fips0 bare, the probe picks the arrival interface's address for the forged source"
    );
    let mut responder = spawn_with_app_owned_tun(&ns, LAN_BIND);
    let forged = client_in(&ns.lan, "[fd11:2233::7]:4444");
    send_unanswered(
        &forged,
        LAN_BIND.parse().unwrap(),
        &mut responder.identities,
    )
    .await;
    let into_mesh = ns.mesh_replies();
    drop(responder);
    assert_eq!(
        into_mesh, 0,
        "with fips0 carrying no address, a LAN query from forged source fd11:2233::7 \
         was answered into the mesh: {into_mesh} UDP packet(s) from port 5354 left by fips0"
    );
}

/// On the same setup an on-link ULA client is answered, and nothing leaves
/// by the mesh interface.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn an_on_link_ula_client_on_a_specific_bind_is_answered_with_an_addressless_mesh_interface() {
    let ns = ForgedSourceNetns::with_addressless_mesh();
    let mut responder = spawn_with_app_owned_tun(&ns, LAN_BIND);
    let client = client_in(&ns.lan, "[fdab::2]:4445");
    expect_answer(
        &client,
        LAN_BIND.parse().unwrap(),
        &mut responder.identities,
        "the on-link ULA client is answered",
    )
    .await;
    assert_eq!(ns.mesh_replies(), 0);
}

/// A known residual, pinned so a change to it is noticed: when the node's
/// mesh address sits on some other non-loopback interface while the
/// application-supplied TUN carries no address, the rule takes the mesh
/// interface to be addressed and judges by the picked source, which comes
/// from the arrival interface; so a forged mesh source's reply is still
/// routed into the bare TUN. If this starts failing, update the doc comments
/// of `is_mesh_interface_query` and `returns_by`, which name this case.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_forged_mesh_source_still_reaches_a_bare_mesh_interface_when_the_mesh_address_is_on_another_interface()
 {
    let ns = ForgedSourceNetns::with_addressless_mesh();
    for args in [
        vec!["-n", &ns.node, "link", "add", "other0", "type", "dummy"],
        vec!["-n", &ns.node, "link", "set", "other0", "up"],
        vec![
            "-n",
            &ns.node,
            "addr",
            "add",
            "fd99::1/128",
            "dev",
            "other0",
            "nodad",
        ],
    ] {
        crate::testutil::run_ok("ip", &args);
    }
    let mut responder = spawn_with_app_owned_tun(&ns, LAN_BIND);
    let forged = client_in(&ns.lan, "[fd11:2233::7]:4444");
    send_unanswered(
        &forged,
        LAN_BIND.parse().unwrap(),
        &mut responder.identities,
    )
    .await;
    let into_mesh = ns.mesh_replies();
    drop(responder);
    assert_eq!(
        into_mesh, 1,
        "the residual case changed: with fd99::1 on other0 and fips0 bare, {into_mesh} \
         replies left by fips0"
    );
}

/// An identity sink that counts each identity and then holds the responder
/// until the test releases it.
struct Held {
    /// How many identities the responder has handed over.
    seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Released by the test to let the responder go on.
    release: std::sync::Arc<tokio::sync::Notify>,
}

impl IdentitySink for Held {
    async fn resolved(&self, _identity: DnsResolvedIdentity) {
        self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.release.notified().await;
    }
}

/// A responder on the IPv6 loopback with no mesh side, its address, and a
/// client socket beside it.
async fn loopback_responder(
    identity: impl IdentitySink + Send + 'static,
    reloader: HostMapReloader,
) -> (std::net::SocketAddr, tokio::net::UdpSocket) {
    let socket = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let to = socket.local_addr().unwrap();
    tokio::spawn(run_responder(
        socket,
        identity,
        300,
        reloader,
        None,
        MeshSide::default(),
    ));
    (to, tokio::net::UdpSocket::bind("[::1]:0").await.unwrap())
}

/// The responder hands a resolved identity over before it sends the reply:
/// while the identity sink holds it, no reply reaches the client, and once
/// the sink lets go the reply does.
#[tokio::test]
async fn the_identity_is_handed_over_before_the_reply_is_sent() {
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let held = Held {
        seen: seen.clone(),
        release: release.clone(),
    };
    let dir = tempfile::tempdir().unwrap();
    let reloader = HostMapReloader::new(HostMap::new(), dir.path().join("hosts"));
    let (to, client) = loopback_responder(held, reloader).await;
    let name = format!("{}.fips", crate::Identity::generate().npub());
    let query = super::tests::build_test_query(&name, simple_dns::TYPE::AAAA);
    client.send_to(&query, to).await.unwrap();

    let handed = || seen.load(std::sync::atomic::Ordering::SeqCst) == 1;
    assert!(
        crate::testutil::wait_until(handed, std::time::Duration::from_secs(5)).await,
        "the identity reached the sink"
    );
    let mut buf = [0u8; 512];
    let early = std::time::Duration::from_millis(300);
    assert!(
        tokio::time::timeout(early, client.recv_from(&mut buf))
            .await
            .is_err(),
        "no reply while the identity is held"
    );
    release.notify_one();
    let late = std::time::Duration::from_secs(5);
    let (len, _) = tokio::time::timeout(late, client.recv_from(&mut buf))
        .await
        .expect("the reply once the identity is taken")
        .unwrap();
    assert_eq!(
        &buf[..2],
        &query[..2],
        "the reply to the query, {len} bytes"
    );
}

/// A datagram the screen drops, and a query it refuses, cost no host-map
/// refresh: a hosts file that appears before them is read only for the
/// query that passes the screen after them.
#[tokio::test]
async fn only_a_query_that_passes_the_screen_refreshes_the_host_map() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let reloader = HostMapReloader::new(HostMap::new(), path.clone());
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let (to, client) = loopback_responder(tx, reloader).await;
    let name = format!("{}.fips", crate::Identity::generate().npub());
    std::fs::write(
        &path,
        format!("gw {}\n", crate::Identity::generate().npub()),
    )
    .unwrap();

    let mut response = super::tests::build_test_query(&name, simple_dns::TYPE::AAAA);
    response[2] |= 0x80;
    client.send_to(&response, to).await.unwrap();
    let mut update = super::tests::build_test_query(&name, simple_dns::TYPE::AAAA);
    update[2] |= 5 << 3;
    client.send_to(&update, to).await.unwrap();
    let mut buf = [0u8; 512];
    let wait = std::time::Duration::from_secs(5);
    tokio::time::timeout(wait, client.recv_from(&mut buf))
        .await
        .expect("the refused query is answered")
        .unwrap();
    assert_eq!(
        buf[3] & 0x0f,
        4,
        "NOTIMP, so the dropped datagram came first"
    );
    assert!(
        logs.lines_with("Reloaded hosts file").is_empty(),
        "refreshed for a datagram the screen did not pass"
    );

    let query = super::tests::build_test_query(&name, simple_dns::TYPE::AAAA);
    client.send_to(&query, to).await.unwrap();
    tokio::time::timeout(wait, client.recv_from(&mut buf))
        .await
        .expect("the query is answered")
        .unwrap();
    assert_eq!(logs.lines_with("Reloaded hosts file").len(), 1);
}

/// The first step on one datagram each: a query from the mesh is dropped
/// before the screen reads it, and what the screen drops or refuses is not
/// passed to be answered; a query it passes is, with the path its reply
/// takes, and the second step answers it with the identity it resolved.
#[test]
fn only_a_query_off_the_mesh_and_past_the_screen_is_passed_to_be_answered() {
    let answering = Answering {
        mesh: MeshSide {
            ifindex: Some(3),
            addr: None,
        },
        wildcard: true,
        strict_pin: true,
    };
    let from = std::net::SocketAddr::new(ip("fd11:2233::7"), 4444);
    let on = |ifindex| Arrival {
        ifindex: Some(ifindex),
        dst: None,
    };
    let name = format!("{}.fips", crate::Identity::generate().npub());
    let query = super::tests::build_test_query(&name, simple_dns::TYPE::AAAA);

    assert!(matches!(
        answering.receive(&query, from, on(3)),
        Received::Mesh
    ));
    let mut response = query.clone();
    response[2] |= 0x80;
    assert!(matches!(
        answering.receive(&response, from, on(2)),
        Received::Screened(Outcome::Drop(_), _)
    ));
    let mut update = query.clone();
    update[2] |= 5 << 3;
    assert!(matches!(
        answering.receive(&update, from, on(2)),
        Received::Screened(Outcome::Refuse(..), ReplyPath::Pinned(2))
    ));

    let Received::Screened(Outcome::Answer(passed), ReplyPath::Pinned(2)) =
        answering.receive(&query, from, on(2))
    else {
        panic!("a query off the mesh is passed, its reply pinned");
    };
    let (bytes, identity) = answer(&passed, 300, &HostMap::new());
    assert!(identity.is_some(), "an AAAA for an npub resolves it");
    assert_eq!(&bytes[..2], &query[..2]);
}

/// A raw query of `qtype` whose question name is the given wire labels, each
/// written with its own length byte, so a label may hold a dot.
fn wire_query(labels: &[&[u8]], qtype: u16) -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in labels {
        query.push(label.len() as u8);
        query.extend_from_slice(label);
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

/// The response code and answer count of a reply.
fn rcode_answers(reply: &[u8]) -> (u8, u16) {
    (reply[3] & 0x0f, u16::from_be_bytes([reply[6], reply[7]]))
}

/// A host map that maps `gateway` to `npub`.
fn gateway_map(npub: &str) -> HostMap {
    let mut hosts = HostMap::new();
    hosts.insert("gateway", npub).unwrap();
    hosts
}

/// A name is under `fips` only when its last wire label is `fips`: a single
/// label holding a dot (`gateway\.fips.`), or a last label `fips.`, gets
/// NXDOMAIN for AAAA and for another type and resolves no identity, as does
/// a name with `fips` as a label short of the last, while
/// the two labels `gateway` and `fips`, in any case, still resolve, for a
/// host-map name and for an npub (RFC 1034 Section 3.1: a name is its
/// labels, and a dot inside a label is part of that label).
#[test]
fn only_a_name_whose_last_label_is_fips_resolves_and_a_dot_inside_a_label_does_not_split_it() {
    let npub = crate::Identity::generate().npub();
    let hosts = gateway_map(&npub);
    for labels in [
        &[&b"gateway"[..], b"fips"][..],
        &[&b"GateWay"[..], b"FiPs"][..],
        &[npub.as_bytes(), b"fips"][..],
    ] {
        let (reply, identity) =
            handle_dns_packet(&wire_query(labels, 28), 4444, 300, &hosts).unwrap();
        assert_eq!(rcode_answers(&reply), (0, 1), "{labels:?} resolves");
        assert!(identity.is_some(), "{labels:?} resolves an identity");
    }
    // The one label `<npub>.fips` is 68 bytes, past the 63 a label may
    // hold, so the screen refuses it with FORMERR before it is answered.
    for labels in [
        &[&b"gateway.fips"[..]][..],
        &[&b"gateway"[..], b"fips."][..],
        &[npub.as_bytes(), b"fips."][..],
        &[&b"gateway"[..], b"fips", b"example"][..],
    ] {
        for qtype in [28, 16] {
            let (reply, identity) =
                handle_dns_packet(&wire_query(labels, qtype), 4444, 300, &hosts).unwrap();
            assert_eq!(
                rcode_answers(&reply),
                (3, 0),
                "type {qtype} for {labels:?}: want NXDOMAIN and no answer"
            );
            assert!(identity.is_none(), "{labels:?} resolved an identity");
        }
    }
}

/// Every AAAA answer's owner is the question name itself, a pointer to
/// offset 12: the answer never names labels other than the question's.
#[test]
fn an_aaaa_answer_owner_is_a_pointer_to_the_question_name() {
    let npub = crate::Identity::generate().npub();
    let hosts = gateway_map(&npub);
    for labels in [
        &[&b"gateway"[..], b"fips"][..],
        &[&b"GATEWAY"[..], b"Fips"][..],
    ] {
        let query = wire_query(labels, 28);
        let (reply, _) = handle_dns_packet(&query, 4444, 300, &hosts).unwrap();
        assert_eq!(rcode_answers(&reply).1, 1, "{labels:?} is answered");
        assert_eq!(
            &reply[query.len()..query.len() + 2],
            &[0xc0, 0x0c],
            "owner of the answer to {labels:?}"
        );
    }
}

/// Set a file's modification time.
fn set_mtime(path: &std::path::Path, at: std::time::SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(at)
        .unwrap();
}

/// Whether the responder, with its host map as `refresh_hosts` leaves it,
/// resolves `<name>.fips` for AAAA.
fn resolves(reloader: &mut HostMapReloader, name: &str) -> bool {
    refresh_hosts(reloader, None);
    let query = wire_query(&[name.as_bytes(), b"fips"], 28);
    let (_, identity) = handle_dns_packet(&query, 4444, 300, reloader.hosts()).unwrap();
    identity.is_some()
}

/// A hosts file whose good load is followed by `gateway` mapped and a
/// modification time a minute ago, and the reloader that read it.
fn loaded_hosts(
    dir: &tempfile::TempDir,
) -> (std::path::PathBuf, std::time::SystemTime, HostMapReloader) {
    let path = dir.path().join("hosts");
    let npub = crate::Identity::generate().npub();
    std::fs::write(&path, format!("gateway {npub}\n")).unwrap();
    let at = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    set_mtime(&path, at);
    let reloader = HostMapReloader::new(HostMap::new(), path.clone());
    (path, at, reloader)
}

/// A hosts file that stops reading (here, non-UTF-8 bytes) after a good load
/// leaves the names it held resolving: the responder keeps its last good map
/// rather than dropping every hosts-file name.
#[test]
fn a_hosts_file_that_becomes_unreadable_keeps_its_last_names_resolving() {
    let dir = tempfile::tempdir().unwrap();
    let (path, at, mut reloader) = loaded_hosts(&dir);
    assert!(resolves(&mut reloader, "gateway"), "the good load");

    std::fs::write(&path, b"# caf\xe9\ngateway npub1notread\n").unwrap();
    set_mtime(&path, at + std::time::Duration::from_secs(10));
    assert!(
        resolves(&mut reloader, "gateway"),
        "gateway stopped resolving once the hosts file could not be read"
    );
}

/// A hosts file that overrides a peer alias and then stops reading keeps its
/// override: the alias the file replaced does not come back, since the
/// responder keeps the map last read rather than rebuilding it from the
/// peer aliases alone.
#[test]
fn a_hosts_file_that_becomes_unreadable_keeps_its_override_of_a_peer_alias() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let alias = crate::Identity::generate().npub();
    let file = crate::Identity::generate().npub();
    std::fs::write(&path, format!("gateway {file}\n")).unwrap();
    let at = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    set_mtime(&path, at);
    let mut reloader = HostMapReloader::new(gateway_map(&alias), path.clone());
    assert!(resolves(&mut reloader, "gateway"), "the good load");
    assert_eq!(reloader.hosts().lookup_npub("gateway"), Some(file.as_str()));

    std::fs::write(&path, b"# caf\xe9\ngateway npub1notread\n").unwrap();
    set_mtime(&path, at + std::time::Duration::from_secs(10));
    assert!(
        resolves(&mut reloader, "gateway"),
        "gateway stopped resolving"
    );
    assert_eq!(
        reloader.hosts().lookup_npub("gateway"),
        Some(file.as_str()),
        "the peer alias the hosts file overrode came back once the file could not be read"
    );
}

/// A failed hosts-file read is tried again on the next query even when the
/// file then reads without its modification time changing, as after a
/// `chmod` fix: the names it then holds resolve.
#[test]
fn a_failed_hosts_file_read_is_retried_though_the_mtime_did_not_change() {
    let dir = tempfile::tempdir().unwrap();
    let (path, at, mut reloader) = loaded_hosts(&dir);
    assert!(resolves(&mut reloader, "gateway"), "the good load");

    let failed = at + std::time::Duration::from_secs(10);
    std::fs::write(&path, b"\xff\xfe not text\n").unwrap();
    set_mtime(&path, failed);
    refresh_hosts(&mut reloader, None);

    let later = crate::Identity::generate().npub();
    std::fs::write(&path, format!("later {later}\n")).unwrap();
    set_mtime(&path, failed);
    assert!(
        resolves(&mut reloader, "later"),
        "a name added while the file was unreadable never resolved, because the failed \
         read was not retried"
    );
    assert!(
        !resolves(&mut reloader, "gateway"),
        "the name the readable file dropped still resolves"
    );
}

/// A hosts file removed after a good load is not a failed read: its names
/// stop resolving, as before.
#[test]
fn a_hosts_file_removed_after_a_good_load_drops_its_names() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _, mut reloader) = loaded_hosts(&dir);
    assert!(resolves(&mut reloader, "gateway"), "the good load");
    std::fs::remove_file(&path).unwrap();
    assert!(
        !resolves(&mut reloader, "gateway"),
        "gateway still resolves with the hosts file removed"
    );
}

/// A run of failed reads warns once, however many queries retry it, and the
/// read that ends the run is logged once at info.
#[test]
fn a_run_of_failed_hosts_file_reads_warns_once_and_its_end_is_logged() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    let dir = tempfile::tempdir().unwrap();
    let (path, at, mut reloader) = loaded_hosts(&dir);
    let failed = at + std::time::Duration::from_secs(10);
    std::fs::write(&path, b"\xff\xfe not text\n").unwrap();
    set_mtime(&path, failed);
    for _ in 0..3 {
        refresh_hosts(&mut reloader, None);
    }
    let warned = logs.lines_with("Failed to read hosts file; keeping the names last read");
    assert_eq!(
        warned.len(),
        1,
        "warnings for three failed reads: {warned:?}"
    );
    assert!(warned[0].starts_with("WARN"), "{}", warned[0]);
    assert!(
        logs.lines_with("Hosts file read again after a failed read")
            .is_empty()
    );

    std::fs::write(&path, "# readable\n").unwrap();
    set_mtime(&path, failed);
    refresh_hosts(&mut reloader, None);
    refresh_hosts(&mut reloader, None);
    let again = logs.lines_with("Hosts file read again after a failed read");
    assert_eq!(again.len(), 1, "{again:?}");
    assert!(again[0].starts_with("INFO"), "{}", again[0]);
}

/// A run of failed reads is ended only by a read: when the modification time
/// returns to that of the last good read while the file is still unreadable,
/// no read happens, so no "read again" line is logged and the run goes on.
#[test]
fn a_failed_read_run_is_not_ended_by_the_mtime_returning_to_the_last_good_read() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    let dir = tempfile::tempdir().unwrap();
    let (path, at, mut reloader) = loaded_hosts(&dir);
    std::fs::write(&path, b"\xff\xfe not text\n").unwrap();
    set_mtime(&path, at + std::time::Duration::from_secs(10));
    assert!(!reloader.check_reload());
    set_mtime(&path, at);
    assert!(!reloader.check_reload());
    assert!(
        logs.lines_with("Hosts file read again after a failed read")
            .is_empty(),
        "a read that did not happen was logged"
    );

    set_mtime(&path, at + std::time::Duration::from_secs(20));
    assert!(!reloader.check_reload());
    let warned = logs.lines_with("Failed to read hosts file; keeping the names last read");
    assert_eq!(warned.len(), 1, "the run warned again: {warned:?}");
}
