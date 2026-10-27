//! Tests that the gateway DNS listener does not answer queries arriving on
//! the mesh interface, that it does not send a reply to a LAN query with a
//! forged mesh source into the mesh, and that the gateway's startup probe of
//! the daemon's resolver passes only on the daemon's answer to its own
//! question.
//!
//! A listener on the wildcard address (`listen: "[::]:53"`) is reachable from
//! the mesh through `fips0`, so without a filter any mesh node with a session
//! to the gateway could fill the virtual-IP pool and probe host-map aliases.
//! A reply sent by the routing table to an `fd00::/8` address follows the
//! TUN's mesh route, so a LAN host that forges a mesh source would have the
//! reply sent into the mesh.
//! The root tests build a gateway namespace whose `fips0` is a veth to a mesh
//! namespace, beside a LAN veth to a LAN namespace, and run the real listener
//! and `serve` inside it.

use super::tests::{TEST_TTL, assert_pool_answer, build_answer, build_query, test_pool};
use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How long a query is given to draw a reply before it counts as unanswered.
const UNANSWERED: std::time::Duration = std::time::Duration::from_millis(500);

/// A gateway listener bound to `[::1]:0` reports each datagram's arrival
/// interface, which the mesh filter needs. Runs without root on Linux.
#[tokio::test]
async fn binding_the_gateway_listener_on_ipv6_turns_on_arrival_interface_reporting() {
    let lo = {
        let name = std::ffi::CString::new("lo").unwrap();
        unsafe { libc::if_nametoindex(name.as_ptr()) }
    };
    assert_ne!(lo, 0, "loopback has an index");
    let server = bind_listener("[::1]:0").await.unwrap();
    let client = UdpSocket::bind("[::1]:0").await.unwrap();
    client
        .send_to(b"hello", server.local_addr().unwrap())
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let (len, _, arrival) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        crate::upper::dns::recv_with_pktinfo(&server, &mut buf),
    )
    .await
    .expect("the datagram arrives")
    .unwrap();
    assert_eq!(&buf[..len], b"hello");
    assert_eq!(
        arrival.ifindex,
        Some(lo),
        "the gateway listener does not report the arrival interface"
    );
}

/// A query arriving on the interface `serve` is told is the mesh gets no
/// reply and is never forwarded to the daemon. Loopback stands in for the
/// mesh, so this runs without root.
#[tokio::test]
async fn serve_drops_a_query_arriving_on_the_named_mesh_interface_and_never_forwards_it() {
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let forwarded = Arc::new(AtomicUsize::new(0));
    let upstream_task = tokio::spawn(answer_every_query(upstream_socket, forwarded.clone()));

    let server = bind_listener("[::1]:0").await.unwrap();
    let to = server.local_addr().unwrap();
    let (event_tx, mut events) = tokio::sync::mpsc::channel(16);
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(serve_excluding(
        server,
        upstream,
        TEST_TTL,
        test_pool(),
        event_tx,
        shutdown,
        "lo",
    ));

    let client = UdpSocket::bind("[::1]:0").await.unwrap();
    let reply = query(&client, to).await;
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    upstream_task.abort();

    assert!(
        reply.is_none(),
        "a query arriving on the mesh interface was answered"
    );
    assert_eq!(
        forwarded.load(Ordering::SeqCst),
        0,
        "a query arriving on the mesh interface was forwarded to the daemon"
    );
    assert!(events.try_recv().is_err(), "a pool event was sent");
}

/// The drop rule: a query is refused when it arrived on the mesh interface,
/// or when an IPv6 socket was not told where it arrived. An IPv4 socket is
/// never told, and is not refused for it.
#[test]
fn an_ipv6_arrival_with_no_interface_index_is_dropped_and_an_ipv4_one_is_not() {
    const IPV6: bool = true;
    const IPV4: bool = false;
    let cases = [
        (Some(3), Some(3), IPV6, true),
        (Some(2), Some(3), IPV6, false),
        (Some(2), None, IPV6, false),
        (None, Some(3), IPV6, true),
        (None, None, IPV6, true),
        (None, Some(3), IPV4, false),
        (None, None, IPV4, false),
        (Some(3), Some(3), IPV4, true),
    ];
    for (arrival, mesh, ipv6, dropped) in cases {
        assert_eq!(
            mesh_arrival(arrival, mesh, ipv6),
            dropped,
            "arrival {arrival:?}, mesh {mesh:?}, IPv6 socket {ipv6}"
        );
    }
}

/// The port the gateway listens on in the namespace tests.
const PORT: u16 = 5365;

/// Three root network namespaces, deleted on drop: a gateway with a veth
/// named `fips0` to a mesh namespace and a LAN veth to a LAN namespace.
///
/// The gateway's `fips0` carries `fd99::1/64` and the `fd00::/8` route, as
/// the daemon's TUN gives it; its peer in the mesh namespace is `fd99::2`.
/// The LAN veth carries `2001:db8:1::1/64`, its peer `2001:db8:1::2`.
struct GatewayNetns {
    gw: String,
    mesh: String,
    lan: String,
}

impl GatewayNetns {
    /// Create and configure the three namespaces. Needs root.
    fn new() -> Self {
        // Tests run in parallel in one process, so each set gets its own
        // sequence number.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        let id = std::process::id();
        let ns = Self {
            gw: format!("fipsgw-gw-{id}-{seq}"),
            mesh: format!("fipsgw-mesh-{id}-{seq}"),
            lan: format!("fipsgw-lan-{id}-{seq}"),
        };
        let (gw, lan) = (ns.gw.as_str(), ns.lan.as_str());
        for args in [
            vec!["netns", "add", gw],
            vec!["netns", "add", ns.mesh.as_str()],
            vec!["netns", "add", lan],
            vec!["-n", gw, "link", "set", "lo", "up"],
            vec!["-n", ns.mesh.as_str(), "link", "set", "lo", "up"],
            vec!["-n", lan, "link", "set", "lo", "up"],
            vec![
                "link", "add", "l0", "netns", gw, "type", "veth", "peer", "name", "c0", "netns",
                lan,
            ],
            vec!["-n", gw, "link", "set", "l0", "up"],
            vec!["-n", lan, "link", "set", "c0", "up"],
            vec![
                "-n",
                gw,
                "addr",
                "add",
                "2001:db8:1::1/64",
                "dev",
                "l0",
                "nodad",
            ],
            vec![
                "-n",
                lan,
                "addr",
                "add",
                "2001:db8:1::2/64",
                "dev",
                "c0",
                "nodad",
            ],
        ] {
            crate::testutil::run_ok("ip", &args);
        }
        ns.add_mesh_link();
        ns
    }

    /// Create the `fips0` veth pair and its addresses and route.
    fn add_mesh_link(&self) {
        let (gw, mesh) = (self.gw.as_str(), self.mesh.as_str());
        for args in [
            vec![
                "link", "add", "fips0", "netns", gw, "type", "veth", "peer", "name", "m0", "netns",
                mesh,
            ],
            vec!["-n", gw, "link", "set", "fips0", "up"],
            vec!["-n", mesh, "link", "set", "m0", "up"],
            vec![
                "-n",
                gw,
                "addr",
                "add",
                "fd99::1/64",
                "dev",
                "fips0",
                "nodad",
            ],
            vec![
                "-n",
                mesh,
                "addr",
                "add",
                "fd99::2/64",
                "dev",
                "m0",
                "nodad",
            ],
            vec!["-n", gw, "route", "add", "fd00::/8", "dev", "fips0"],
        ] {
            crate::testutil::run_ok("ip", &args);
        }
    }

    /// Delete the `fips0` veth pair, as a daemon restart does to its TUN.
    fn del_mesh_link(&self) {
        crate::testutil::run_ok("ip", &["-n", &self.gw, "link", "del", "fips0"]);
    }

    /// The gateway namespace's index for `fips0`.
    fn mesh_ifindex(&self) -> u32 {
        crate::testutil::in_netns(&self.gw, || {
            let name = std::ffi::CString::new("fips0").unwrap();
            unsafe { libc::if_nametoindex(name.as_ptr()) }
        })
    }

    /// A UDP socket bound to `addr` inside namespace `ns`, for the test
    /// runtime.
    fn client(ns: &str, addr: &'static str) -> UdpSocket {
        let socket = crate::testutil::in_netns(ns, move || {
            let s = std::net::UdpSocket::bind(addr).unwrap();
            s.set_nonblocking(true).unwrap();
            s
        });
        UdpSocket::from_std(socket).unwrap()
    }
}

impl Drop for GatewayNetns {
    fn drop(&mut self) {
        for ns in [&self.gw, &self.mesh, &self.lan] {
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", ns])
                .status();
        }
    }
}

/// The gateway listener and `serve` running on a thread inside the gateway
/// namespace, with a fake upstream daemon on `[::1]` there, stopped and
/// joined on drop.
struct NetnsGateway {
    stop: Option<watch::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
    events: tokio::sync::mpsc::Receiver<PoolEvent>,
    upstream_queries: Arc<AtomicUsize>,
}

impl NetnsGateway {
    /// Bind `[::]:PORT` in namespace `ns` and serve on it. Everything the
    /// listener does per datagram runs in that namespace.
    fn spawn(ns: &str) -> Self {
        Self::spawn_on(ns, format!("[::]:{PORT}"))
    }

    /// Bind `listen` in namespace `ns` and serve on it, as [`Self::spawn`].
    fn spawn_on(ns: &str, listen: String) -> Self {
        let (event_tx, events) = tokio::sync::mpsc::channel(16);
        let (stop, shutdown) = watch::channel(false);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let upstream_queries = Arc::new(AtomicUsize::new(0));
        let counted = upstream_queries.clone();
        let ns = ns.to_string();
        let thread = std::thread::spawn(move || {
            crate::testutil::in_netns(&ns, move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("gateway runtime");
                runtime.block_on(async move {
                    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
                    let upstream = upstream_socket.local_addr().unwrap();
                    let upstream_task = tokio::spawn(answer_every_query(upstream_socket, counted));
                    let socket = bind_listener(&listen).await.unwrap();
                    ready_tx.send(()).unwrap();
                    let _ = serve(
                        socket,
                        upstream,
                        TEST_TTL,
                        test_pool(),
                        event_tx,
                        shutdown,
                        "fips0".to_string(),
                    )
                    .await;
                    upstream_task.abort();
                });
            })
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the gateway starts in its namespace");
        Self {
            stop: Some(stop),
            thread: Some(thread),
            events,
            upstream_queries,
        }
    }

    /// How many queries the fake upstream daemon has received.
    fn upstream_queries(&self) -> usize {
        self.upstream_queries.load(Ordering::SeqCst)
    }
}

impl Drop for NetnsGateway {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A fake daemon resolver: counts every query and answers it with a mesh
/// address.
async fn answer_every_query(socket: UdpSocket, count: Arc<AtomicUsize>) {
    let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
    loop {
        let Ok((len, src)) = socket.recv_from(&mut buf).await else {
            return;
        };
        count.fetch_add(1, Ordering::SeqCst);
        let Ok(query) = Packet::parse(&buf[..len]) else {
            continue;
        };
        let name = query.questions[0].qname.to_string();
        let answer = build_answer(query.id(), &name, "fd12:3456::1");
        let _ = socket.send_to(&answer, src).await;
    }
}

/// Send an AAAA query for a fresh npub name from `client` to `to`, and
/// return the reply, or `None` when none arrives in [`UNANSWERED`].
async fn query(client: &UdpSocket, to: SocketAddr) -> Option<Vec<u8>> {
    let name = format!("{}.fips", crate::Identity::generate().npub());
    client
        .send_to(&build_query(0x4242, &name), to)
        .await
        .unwrap();
    let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
    match tokio::time::timeout(UNANSWERED, client.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
        Ok(Err(e)) => panic!("client receive failed: {e}"),
        Err(_) => None,
    }
}

/// Assert that a mesh query drew no reply, reached no upstream and minted no
/// mapping.
fn assert_unanswered(
    reply: Option<Vec<u8>>,
    gateway: &mut NetnsGateway,
    upstream_before: usize,
    what: &str,
) {
    assert!(
        reply.is_none(),
        "{what}: a query arriving on fips0 was answered"
    );
    assert_eq!(
        gateway.upstream_queries(),
        upstream_before,
        "{what}: a query arriving on fips0 was forwarded to the daemon"
    );
    let event = gateway.events.try_recv();
    assert!(
        event.is_err(),
        "{what}: a query arriving on fips0 minted a pool mapping: {event:?}"
    );
}

/// A mesh node that reaches a wildcard gateway listener through `fips0` gets
/// no answer, and its query neither reaches the daemon nor mints a mapping.
///
/// Needs root (network namespaces): build with `cargo test --lib --no-run`
/// and run the test binary under `sudo` with `--ignored`.
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_dns_query_arriving_on_fips0_is_not_answered_and_mints_no_mapping() {
    let ns = GatewayNetns::new();
    let mut gateway = NetnsGateway::spawn(&ns.gw);
    let peer = GatewayNetns::client(&ns.mesh, "[fd99::2]:0");
    let to = SocketAddr::from(("fd99::1".parse::<Ipv6Addr>().unwrap(), PORT));
    let reply = query(&peer, to).await;
    assert_unanswered(reply, &mut gateway, 0, "mesh query");
}

/// On the same gateway a LAN client is still answered with a pool address.
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_lan_query_on_a_wildcard_listener_is_still_answered_with_a_pool_address() {
    let ns = GatewayNetns::new();
    let mut gateway = NetnsGateway::spawn(&ns.gw);
    let client = GatewayNetns::client(&ns.lan, "[2001:db8:1::2]:0");
    let to = SocketAddr::from(("2001:db8:1::1".parse::<Ipv6Addr>().unwrap(), PORT));
    let reply = query(&client, to)
        .await
        .expect("the LAN client is answered");
    assert_pool_answer(&reply);
    assert_eq!(gateway.upstream_queries(), 1);
    assert!(
        matches!(
            gateway.events.try_recv(),
            Ok(PoolEvent::MappingCreated { .. })
        ),
        "the LAN query mints a mapping"
    );
}

/// A `fips0` deleted and created again under a running gateway, as when the
/// daemon restarts, has a new index; a mesh query arriving on the new one is
/// still not answered.
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_query_arriving_on_a_recreated_fips0_is_still_not_answered() {
    let ns = GatewayNetns::new();
    let mut gateway = NetnsGateway::spawn(&ns.gw);
    let to = SocketAddr::from(("fd99::1".parse::<Ipv6Addr>().unwrap(), PORT));

    let peer = GatewayNetns::client(&ns.mesh, "[fd99::2]:0");
    let reply = query(&peer, to).await;
    assert_unanswered(reply, &mut gateway, 0, "before the restart");

    let before = ns.mesh_ifindex();
    ns.del_mesh_link();
    ns.add_mesh_link();
    assert_ne!(
        ns.mesh_ifindex(),
        before,
        "the recreated fips0 has a new index"
    );

    let peer = GatewayNetns::client(&ns.mesh, "[fd99::2]:0");
    let reply = query(&peer, to).await;
    assert_unanswered(reply, &mut gateway, 0, "after the restart");
}

/// The startup probe against an upstream socket that `answer` drives: it
/// receives the probe's query, and `answer` gets the socket, the query and its
/// source. Returns the probe's result and how long it took.
async fn probe_with<F, Fut>(
    wait: std::time::Duration,
    answer: F,
) -> (Result<(), String>, std::time::Duration)
where
    F: FnOnce(UdpSocket, Vec<u8>, SocketAddr) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
        let (len, src) = upstream_socket.recv_from(&mut buf).await.unwrap();
        answer(upstream_socket, buf[..len].to_vec(), src).await;
    });
    let probe = UdpSocket::bind("[::]:0").await.unwrap();
    let started = std::time::Instant::now();
    let result = probe_upstream(&probe, upstream, wait).await;
    let took = started.elapsed();
    upstream_task.abort();
    (result, took)
}

/// The daemon's answer to the probe, `test.fips` AAAA: an NXDOMAIN that
/// carries the question.
fn daemon_answer(query: &[u8]) -> Vec<u8> {
    let hosts = crate::upper::hosts::HostMap::new();
    let (answer, _) = crate::upper::dns::handle_dns_packet(query, 40000, TEST_TTL, &hosts)
        .expect("the daemon answers the probe's query");
    answer
}

/// The probe passes on the answer the daemon's own resolver gives it.
#[tokio::test]
async fn the_startup_probe_accepts_the_daemons_answer_to_its_question() {
    let (result, _) = probe_with(
        std::time::Duration::from_secs(2),
        |socket, query, src| async move {
            socket.send_to(&daemon_answer(&query), src).await.unwrap();
        },
    )
    .await;
    assert_eq!(
        result,
        Ok(()),
        "the daemon's answer to the probe was not accepted"
    );
}

/// A datagram from any address but the upstream's does not pass the probe,
/// even one that looks exactly like the daemon's answer. The upstream itself
/// stays silent, as a resolver that is not yet up does.
#[tokio::test]
async fn the_startup_probe_ignores_a_datagram_from_another_source() {
    let (result, _) = probe_with(
        std::time::Duration::from_secs(1),
        |_silent, query, src| async move {
            let stray = UdpSocket::bind("[::1]:0").await.unwrap();
            stray.send_to(&daemon_answer(&query), src).await.unwrap();
            std::future::pending::<()>().await;
        },
    )
    .await;
    assert!(
        result.is_err(),
        "the probe passed on a datagram from a source other than the upstream"
    );
}

/// A datagram from the upstream that does not answer the probe's question
/// does not pass it.
#[tokio::test]
async fn the_startup_probe_ignores_an_upstream_datagram_that_does_not_answer_its_question() {
    let (result, _) = probe_with(
        std::time::Duration::from_secs(1),
        |socket, query, src| async move {
            let mut wrong_id = daemon_answer(&query);
            wrong_id[0] ^= 0xff;
            socket.send_to(&wrong_id, src).await.unwrap();
            socket.send_to(b"not dns", src).await.unwrap();
            std::future::pending::<()>().await;
        },
    )
    .await;
    assert!(
        result.is_err(),
        "the probe passed on an upstream datagram that does not answer it"
    );
}

/// With nothing listening on the upstream port, an attempt fails, but only
/// after waiting out its time, as it did before the socket was connected: at
/// start-up a refused port is the daemon's responder still binding, and the
/// gateway's retries are sized for that.
#[tokio::test]
async fn the_startup_probe_waits_out_its_time_when_the_upstream_port_is_closed() {
    let closed = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = closed.local_addr().unwrap();
    drop(closed);
    let probe = UdpSocket::bind("[::]:0").await.unwrap();
    let wait = std::time::Duration::from_millis(1500);
    let started = std::time::Instant::now();
    let result = probe_upstream(&probe, upstream, wait).await;
    let took = started.elapsed();
    assert!(result.is_err(), "the probe passed with nothing listening");
    assert!(
        took >= std::time::Duration::from_millis(1400),
        "the probe gave up after {took:?} on a closed port instead of waiting out {wait:?}, \
         which shortens the time the daemon has to bind its responder"
    );
}

impl GatewayNetns {
    /// The forged mesh source the LAN host puts on its own link.
    const FORGED: &'static str = "fd11:2233::7";

    /// Give the LAN an on-link ULA prefix (`fdab::1/64` on the gateway,
    /// `fdab::2/64` on the LAN host), as OpenWrt LANs commonly have, put the
    /// forged mesh source on the LAN host's link, and count, in the gateway
    /// namespace, the UDP packets from the listener's port that leave by
    /// `fips0`.
    fn forge_source(&self) {
        let forged = format!("{}/128", Self::FORGED);
        let (gw, lan) = (self.gw.as_str(), self.lan.as_str());
        for args in [
            vec!["-n", gw, "addr", "add", "fdab::1/64", "dev", "l0", "nodad"],
            vec!["-n", lan, "addr", "add", "fdab::2/64", "dev", "c0", "nodad"],
            vec![
                "-n",
                lan,
                "addr",
                "add",
                forged.as_str(),
                "dev",
                "c0",
                "nodad",
            ],
        ] {
            crate::testutil::run_ok("ip", &args);
        }
        let rule = format!("oifname fips0 udp sport {PORT} counter name refl");
        for cmd in [
            "add table inet gwtest".to_string(),
            "add counter inet gwtest refl".to_string(),
            "add chain inet gwtest out { type filter hook output priority 0 ; }".to_string(),
            format!("add rule inet gwtest out {rule}"),
        ] {
            let mut args = vec!["netns", "exec", gw, "nft"];
            args.extend(cmd.split(' '));
            crate::testutil::run_ok("ip", &args);
        }
    }

    /// UDP packets from the listener's port that have left by `fips0`.
    fn mesh_replies(&self) -> u64 {
        let out = std::process::Command::new("ip")
            .args([
                "netns", "exec", &self.gw, "nft", "list", "counter", "inet", "gwtest", "refl",
            ])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace()
            .skip_while(|w| *w != "packets")
            .nth(1)
            .unwrap_or_else(|| panic!("no packet count in nft output: {text}"))
            .parse()
            .unwrap()
    }
}

/// Send a query from `forged` (a LAN host's socket on the forged mesh source)
/// to `to`, and assert that no reply leaves the gateway by `fips0`, and that
/// a query from each of `healthy` is still answered.
async fn assert_offmesh(
    ns: &GatewayNetns,
    forged: &UdpSocket,
    healthy: &[(&UdpSocket, SocketAddr, &str)],
    to: SocketAddr,
    what: &str,
) {
    for (client, to, who) in healthy {
        assert!(
            query(client, *to).await.is_some(),
            "{what}: {who} is not answered"
        );
    }
    let _ = query(forged, to).await;
    let into_mesh = ns.mesh_replies();
    assert_eq!(
        into_mesh,
        0,
        "{what}: a LAN query from forged mesh source {} was answered into the mesh: \
         {into_mesh} UDP packet(s) from port {PORT} left by fips0",
        GatewayNetns::FORGED
    );
}

/// A LAN host that forges a mesh source address must not make a wildcard
/// gateway listener answer into the mesh, while LAN clients with a global and
/// an on-link ULA address are still answered.
///
/// Needs root (network namespaces, nft): build with
/// `cargo test --lib --no-run` and run the test binary under `sudo` with
/// `--ignored`.
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_lan_query_from_a_forged_mesh_source_is_not_answered_into_the_mesh() {
    let ns = GatewayNetns::new();
    ns.forge_source();
    let _gateway = NetnsGateway::spawn(&ns.gw);
    let to = SocketAddr::from(("2001:db8:1::1".parse::<Ipv6Addr>().unwrap(), PORT));
    let ula_to = SocketAddr::from(("fdab::1".parse::<Ipv6Addr>().unwrap(), PORT));
    let genuine = GatewayNetns::client(&ns.lan, "[2001:db8:1::2]:0");
    let ula = GatewayNetns::client(&ns.lan, "[fdab::2]:0");
    let forged = GatewayNetns::client(&ns.lan, "[fd11:2233::7]:4444");
    assert_offmesh(
        &ns,
        &forged,
        &[
            (&genuine, to, "the LAN client"),
            (&ula, ula_to, "the on-link ULA client"),
        ],
        to,
        "wildcard listener",
    )
    .await;
}

/// The same on a gateway listener bound to one LAN address, which always
/// sends from that address, so the kernel does not hold a reply to the
/// arrival interface. An on-link ULA client is still answered.
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_lan_query_from_a_forged_mesh_source_is_not_answered_into_the_mesh_on_a_specific_bind() {
    let ns = GatewayNetns::new();
    ns.forge_source();
    let _gateway = NetnsGateway::spawn_on(&ns.gw, format!("[fdab::1]:{PORT}"));
    let to = SocketAddr::from(("fdab::1".parse::<Ipv6Addr>().unwrap(), PORT));
    let ula = GatewayNetns::client(&ns.lan, "[fdab::2]:0");
    let forged = GatewayNetns::client(&ns.lan, "[fd11:2233::7]:4444");
    assert_offmesh(
        &ns,
        &forged,
        &[(&ula, to, "the on-link ULA client")],
        to,
        "listener bound to fdab::1",
    )
    .await;
}
