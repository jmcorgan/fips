//! FIPS DNS Responder
//!
//! Resolves `.fips` queries to FipsAddress IPv6 addresses. Two resolution
//! paths are supported:
//!
//! 1. **Hostname**: `<hostname>.fips` — looked up in the [`HostMap`] to get
//!    an npub, then resolved to IPv6.
//! 2. **Direct npub**: `<npub>.fips` — pure computation from public key.
//!
//! As a side effect, resolved identities are sent to the Node for identity
//! cache population, enabling subsequent TUN packet routing.

use crate::dnsmsg::{self, AA, Outcome, Query, Rcode, Screen, TYPE_AAAA};
use crate::identity::FIPS_ADDRESS_PREFIX;
use crate::upper::hosts::{HostMap, HostMapReloader};
use crate::utils::onlink::OnLinkPrefixes;
use crate::{NodeAddr, PeerIdentity};
use std::net::Ipv6Addr;
use tracing::{debug, trace};

/// Identity resolved by the DNS responder, sent to Node for cache population.
pub struct DnsResolvedIdentity {
    pub node_addr: NodeAddr,
    pub pubkey: secp256k1::PublicKey,
}

/// Channel sender for DNS → Node identity registration.
pub type DnsIdentityTx = tokio::sync::mpsc::Sender<DnsResolvedIdentity>;

/// Channel receiver consumed by the Node RX event loop.
pub type DnsIdentityRx = tokio::sync::mpsc::Receiver<DnsResolvedIdentity>;

/// Extract the label before `.fips` from a DNS query name.
///
/// Handles trailing dots and case-insensitive `.fips` suffix matching.
fn extract_fips_label(name: &str) -> Option<&str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    name.strip_suffix(".fips")
        .or_else(|| name.strip_suffix(".FIPS"))
        .or_else(|| {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".fips") {
                Some(&name[..name.len() - 5])
            } else {
                None
            }
        })
}

/// Resolve a `.fips` domain name to an IPv6 address and identity.
///
/// The name should be `<npub>.fips` (with optional trailing dot).
/// Returns the FipsAddress IPv6, NodeAddr, and full PublicKey on success.
pub fn resolve_fips_query(name: &str) -> Option<(Ipv6Addr, NodeAddr, secp256k1::PublicKey)> {
    let npub = extract_fips_label(name)?;
    let peer = PeerIdentity::from_npub(npub).ok()?;
    let ipv6 = peer.address().to_ipv6();
    let node_addr = *peer.node_addr();
    let pubkey = peer.pubkey_full();

    Some((ipv6, node_addr, pubkey))
}

/// Resolve a `.fips` domain name with host map lookup.
///
/// Resolution order:
/// 1. Extract the label before `.fips`
/// 2. If the label matches a hostname in the host map, use the mapped npub
/// 3. Otherwise, treat the label as a direct npub
/// 4. Resolve the npub to IPv6 via `PeerIdentity`
pub fn resolve_fips_query_with_hosts(
    name: &str,
    hosts: &HostMap,
) -> Option<(Ipv6Addr, NodeAddr, secp256k1::PublicKey)> {
    let label = extract_fips_label(name)?;

    // Try host map first, then direct npub
    let npub_owned;
    let npub = if let Some(mapped) = hosts.lookup_npub(label) {
        npub_owned = mapped.to_string();
        &npub_owned
    } else {
        label
    };

    let peer = PeerIdentity::from_npub(npub).ok()?;
    let ipv6 = peer.address().to_ipv6();
    let node_addr = *peer.node_addr();
    let pubkey = peer.pubkey_full();

    Some((ipv6, node_addr, pubkey))
}

/// Handle a raw DNS datagram and produce a response.
///
/// `src_port` is the UDP source port the datagram came from. The datagram is
/// screened first (see `dnsmsg::screen`): `None` means it gets no reply at
/// all. Otherwise returns the response bytes and an optional resolved
/// identity (for AAAA queries that successfully resolved a `.fips` name). The
/// host map is consulted first for hostname resolution before falling back to
/// direct npub resolution.
pub fn handle_dns_packet(
    query_bytes: &[u8],
    src_port: u16,
    ttl: u32,
    hosts: &HostMap,
) -> Option<(Vec<u8>, Option<DnsResolvedIdentity>)> {
    match respond(query_bytes, src_port, ttl, || hosts) {
        Outcome::Drop(_) => None,
        Outcome::Refuse(_, bytes) => Some((bytes, None)),
        Outcome::Answer(answer) => Some(answer),
    }
}

/// Screen a datagram and, if it is a query, answer it.
///
/// The one dispatch both the receive loop and [`handle_dns_packet`] run.
/// `hosts` is called only for a datagram the screen passes as a query, so a
/// dropped or refused datagram costs no host-map refresh.
fn respond<'h>(
    datagram: &[u8],
    src_port: u16,
    ttl: u32,
    hosts: impl FnOnce() -> &'h HostMap,
) -> Outcome<(Vec<u8>, Option<DnsResolvedIdentity>)> {
    match dnsmsg::screen(datagram, src_port) {
        Screen::Drop(reason) => Outcome::Drop(reason),
        Screen::Reply(rcode, bytes) => Outcome::Refuse(rcode, bytes),
        Screen::Query(query) => Outcome::Answer(answer(&query, ttl, hosts())),
    }
}

/// Answer a screened query, authoritatively.
///
/// A resolvable name gets its address for AAAA and an empty NOERROR (NODATA)
/// for any other type, known or not: NXDOMAIN would tell the client the name
/// does not exist, causing resolvers like nslookup to give up without trying
/// AAAA. An unresolvable name gets NXDOMAIN.
fn answer(query: &Query<'_>, ttl: u32, hosts: &HostMap) -> (Vec<u8>, Option<DnsResolvedIdentity>) {
    match resolve_fips_query_with_hosts(&query.name, hosts) {
        Some((ipv6, node_addr, pubkey)) if query.qtype == TYPE_AAAA => {
            let records = [dnsmsg::aaaa(ipv6, ttl)];
            let bytes = dnsmsg::reply(query, Rcode::NOERROR, AA, &records, &[]);
            (bytes, Some(DnsResolvedIdentity { node_addr, pubkey }))
        }
        Some(_) => (dnsmsg::reply(query, Rcode::NOERROR, AA, &[], &[]), None),
        None => (dnsmsg::reply(query, Rcode::NXDOMAIN, AA, &[], &[]), None),
    }
}

/// Whether a received DNS query arrived on the mesh interface.
///
/// True iff the mesh interface's index (`mesh_ifindex`) is known and the
/// packet arrived on that interface (`arrival_ifindex`). Queries arriving on
/// any other interface (loopback, LAN, or unknown, with no PKTINFO cmsg) are
/// not matched. Where the mesh index is unknown, [`mesh_query`] recognises
/// mesh queries by address instead.
///
/// The arrival-interface check is robust regardless of source address. LAN
/// segments using RFC 4193 ULA prefixes (`fd00::/8`, common with OpenWrt
/// `odhcpd` and NetworkManager ULA auto-generation) would collide with the
/// FIPS mesh prefix under a source-prefix filter; this filter is immune.
///
/// The filter does not cover the reply's path; [`reply_path`] does. On Linux
/// with the socket bound to the wildcard address, a reply to a mesh source
/// address (`fd00::/8`) leaves only by the interface the query arrived on;
/// with the socket bound to a specific address, a query from a mesh source
/// address that arrived on any interface but the mesh interface gets no
/// reply when the mesh interface's index is known, and when it is not, the
/// reply is sent only if the routing table takes it back out of the arrival
/// interface or delivers it locally. On other platforms no interface pin is
/// relied on (FreeBSD was measured not to hold one): a reply to a mesh
/// source is sent only under that same routing-table check, on either bind.
/// So a query arriving on another interface with a forged mesh source
/// address is not answered into the mesh by this socket. The check reads
/// the egress interface from the source address the kernel picks, which
/// relies on the mesh interface carrying an address of the reply's family.
/// When no interface holds the node's mesh address (an
/// application-supplied TUN with no IPv6 address), the check instead sends
/// the reply only to a destination on one of the arrival interface's own
/// prefixes, or delivered locally (see [`returns_by`]). That stands in for
/// "the mesh interface has no address": an embedder that puts the mesh
/// address on some other interface while leaving its TUN bare is judged by
/// the picked source, which then says nothing about the TUN, and is not
/// covered. Source-based policy routing on Linux can also route the bound
/// socket differently from the check. A node that forwards IPv6
/// from that interface into the mesh can still have the reply routed back
/// to it and forward it into the mesh, as it would any packet from that
/// network to a mesh address. On Windows the arrival interface is not read,
/// so the reply is routed; there, while a TUN is up, [`mesh_query`] refuses
/// every query from a remote mesh source address, so a forged one gets no
/// reply either. Measured on Linux and FreeBSD; macOS and Android follow the
/// same code path but were not run.
pub(crate) fn is_mesh_interface_query(
    arrival_ifindex: Option<u32>,
    mesh_ifindex: Option<u32>,
) -> bool {
    match (arrival_ifindex, mesh_ifindex) {
        (Some(arrival), Some(mesh)) => arrival == mesh,
        _ => false,
    }
}

/// What the responder knows of this node's mesh side: the mesh interface's
/// index, when it resolved, and the node's own mesh address, when a TUN is
/// up (the daemon's own or an application-supplied one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct MeshSide {
    /// Index of the mesh interface; `None` with an application-supplied TUN,
    /// on Windows, or when the device name did not resolve.
    pub(crate) ifindex: Option<u32>,
    /// The node's own mesh address (`fd00::/8`); `None` when no TUN is up.
    pub(crate) addr: Option<Ipv6Addr>,
}

/// Whether a query from `src` that arrived as `arrival` came from the mesh
/// and must be dropped unanswered.
///
/// Where the mesh interface's index is known, this is exactly
/// [`is_mesh_interface_query`]. Where it is not (an application-supplied
/// TUN, an unresolved device name, or Windows) but a TUN is up, the query is
/// recognised by address. Every packet the node delivers from the mesh into
/// its TUN carries the remote node's `fd00::/8` address as source and this
/// node's own mesh address as destination. So a query whose destination is
/// the node's mesh address and whose source is not is dropped; where the
/// destination is not reported (Windows), a query from any remote
/// non-v4-mapped `fd00::/8` source is dropped. A local process sending from
/// the node's own mesh address is always answered. With no TUN up there is
/// no mesh to filter, and nothing is dropped.
///
/// The cost of the address rule: with the mesh index unknown, a LAN client
/// that queries the node's mesh address directly is dropped, and on Windows a
/// LAN client with a ULA (`fd00::/8`) source gets no answer while a TUN is
/// up.
pub(crate) fn mesh_query(arrival: Arrival, src: std::net::SocketAddr, mesh: MeshSide) -> bool {
    if is_mesh_interface_query(arrival.ifindex, mesh.ifindex) {
        return true;
    }
    if mesh.ifindex.is_some() {
        return false;
    }
    let Some(own) = mesh.addr else {
        return false;
    };
    let src = match src.ip() {
        std::net::IpAddr::V6(ip) => Some(ip),
        std::net::IpAddr::V4(_) => None,
    };
    if src == Some(own) {
        return false;
    }
    match arrival.dst {
        Some(dst) => dst == own,
        None => src.is_some_and(|ip| {
            ip.octets()[0] == FIPS_ADDRESS_PREFIX && ip.to_ipv4_mapped().is_none()
        }),
    }
}

/// How a reply to a DNS query is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyPath {
    /// To the query's source by the routing table.
    Routed,
    /// To the query's source, only out of the interface with this index.
    Pinned(u32),
    /// Not sent: no path is known to keep the reply out of the mesh.
    Withheld,
    /// To the query's source by the routing table, but only when the table
    /// sends it back out of the interface with this index (the one the query
    /// arrived on) or delivers it locally; otherwise not sent. Used where no
    /// strict pin to the arrival interface is known to hold (see
    /// [`returns_by`]).
    Returning(u32),
}

/// Choose how to send the reply to a query from `src` that arrived on
/// `arrival_ifindex`, given the mesh interface's index and whether the
/// socket is bound to the wildcard address (`::` or `0.0.0.0`).
///
/// A reply to a mesh source address (`fd00::/8`, first byte
/// [`FIPS_ADDRESS_PREFIX`]) is pinned to the arrival interface, so a query
/// that arrived on a LAN with a forged mesh source is not answered into the
/// mesh by the TUN's `fd00::/8` route. Everything else is routed. Four kernel
/// facts set the rule, measured on Linux:
///
/// - the mesh route is `fd00::/8`, so only those destinations can be drawn
///   into the mesh;
/// - Linux holds a reply strictly to a requested outgoing interface only when
///   the source address is left unspecified, so the pin names the interface
///   alone (a pinned source address still leaves by the mesh);
/// - a socket bound to a specific address always sends from that address,
///   so on such a socket the pin is not strict and the reply can still leave
///   by the mesh;
/// - a send to a v4-mapped address with an unspecified IPv6 source fails with
///   `EINVAL`, so IPv4 clients on a dual-stack socket are never pinned.
///
/// With `strict_pin` (Linux): on a wildcard socket, a mesh source with a
/// known arrival interface is pinned and one with an unknown arrival
/// interface is routed. On a socket bound to a specific address, a mesh
/// source is answered (pinned) only when it arrived on the mesh interface;
/// when it arrived on any other interface, or its arrival interface is
/// unknown, the reply is withheld. With no known mesh interface (no TUN, an
/// application-supplied TUN, or an unresolved index) a specific socket
/// cannot tell the mesh interface apart and cannot hold a pin, so a mesh
/// source with a known arrival interface gets a [`ReplyPath::Returning`]
/// reply: sent only if the routing table takes it back out of the arrival
/// interface.
///
/// Without `strict_pin` (every other target), no pin is relied on: a mesh
/// source with a known arrival interface always gets a
/// [`ReplyPath::Returning`] reply, whatever the bind, and one with an unknown
/// arrival interface is withheld on a specific bind with a known mesh
/// interface and routed otherwise. Measured on FreeBSD, an `IPV6_PKTINFO`
/// interface does not hold a reply to that interface: the kernel uses it
/// only to pick the source and still routes by the table.
///
/// The decision is one pure function for every target, so its table is
/// tested on any host; `strict_pin` says whether the target holds a pin.
pub(crate) fn reply_path(
    src: std::net::SocketAddr,
    arrival_ifindex: Option<u32>,
    mesh_ifindex: Option<u32>,
    wildcard: bool,
    strict_pin: bool,
) -> ReplyPath {
    let std::net::SocketAddr::V6(v6) = src else {
        return ReplyPath::Routed;
    };
    if v6.ip().octets()[0] != FIPS_ADDRESS_PREFIX || v6.ip().to_ipv4_mapped().is_some() {
        return ReplyPath::Routed;
    }
    match (arrival_ifindex, mesh_ifindex) {
        (None, Some(_)) if !wildcard => ReplyPath::Withheld,
        (None, _) => ReplyPath::Routed,
        (Some(arrival), _) if !strict_pin => ReplyPath::Returning(arrival),
        (Some(arrival), Some(mesh)) if !wildcard && arrival != mesh => ReplyPath::Withheld,
        (Some(arrival), None) if !wildcard => ReplyPath::Returning(arrival),
        (Some(arrival), _) => ReplyPath::Pinned(arrival),
    }
}

/// Whether a reply whose route the kernel gives source address `source`
/// stays out of the mesh: true when the reply goes back out of interface
/// `arrival`, or is delivered locally. `mesh_addr` is the node's own mesh
/// address while a TUN is up.
///
/// `source` is what [`probe_source`] reports for the reply's `destination`,
/// and `prefixes` holds this node's interface prefixes. The egress interface
/// is inferred from the source the kernel picks: one of the arrival
/// interface's own prefixes holds it only when the route leaves by that
/// interface. When `source == destination`, the destination is one of this
/// node's own addresses (the kernel picks the destination itself as the
/// source, RFC 6724 rule 1), so the reply never leaves the node. An empty or
/// failed prefix set holds nothing and so answers false.
///
/// The inference needs the egress interface to carry an address of the
/// destination's family. The daemon's TUN does (its mesh address); an
/// application-supplied TUN with no IPv6 address does not, and a reply
/// routed into it would be judged by the LAN source the kernel then picks.
/// So when the node's mesh address is known and no interface prefix holds
/// it, the picked source says nothing about egress, and the reply is judged
/// by its destination instead: it returns only when the destination lies in
/// one of the arrival interface's own prefixes, whose connected route is
/// more specific than the mesh's `fd00::/8`. A ULA client reached through a
/// LAN router then gets no reply. A TUN carrying some other address than the
/// node's mesh address is treated as bare, which errs toward withholding.
/// The mesh address on another non-loopback interface while the TUN is bare
/// is not caught: the mesh interface is then taken to be addressed.
fn returns_by(
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    arrival: u32,
    prefixes: &OnLinkPrefixes,
    mesh_addr: Option<Ipv6Addr>,
) -> bool {
    if source == destination {
        return true;
    }
    match mesh_addr {
        Some(mesh) if !prefixes.contains(std::net::IpAddr::V6(mesh)) => {
            prefixes.contains_on(destination, &[arrival])
        }
        _ => prefixes.contains_on(source, &[arrival]),
    }
}

/// The source address the kernel picks for a datagram to `destination` by
/// the routing table.
///
/// An unbound UDP socket of the destination's family is connected to it;
/// connecting a UDP socket sends nothing, and `local_addr` then reports the
/// source of the chosen route. With source-based policy routing a socket
/// bound to a specific address can take a different route than this
/// unbound probe.
fn probe_source(destination: std::net::SocketAddr) -> std::io::Result<std::net::IpAddr> {
    let any: std::net::SocketAddr = match destination {
        std::net::SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        std::net::SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let probe = std::net::UdpSocket::bind(any)?;
    probe.connect(destination)?;
    Ok(probe.local_addr()?.ip())
}

/// Whether a [`ReplyPath::Returning`] reply to `dst`, whose query arrived on
/// interface `arrival`, may be sent: `Ok(())` when the routing table takes
/// it back out of `arrival` or delivers it locally, otherwise the reason it
/// is withheld. A failed probe or interface read withholds. `mesh_addr` is
/// the node's own mesh address while a TUN is up.
fn check_returning(
    dst: std::net::SocketAddr,
    arrival: u32,
    mesh_addr: Option<Ipv6Addr>,
) -> Result<(), &'static str> {
    let source = probe_source(dst).map_err(|_| "reply-route-probe-failed")?;
    let prefixes = OnLinkPrefixes::read_system();
    if prefixes.read_failed() {
        return Err("interface-read-failed");
    }
    if returns_by(source, dst.ip(), arrival, &prefixes, mesh_addr) {
        Ok(())
    } else {
        Err("reply-route-leaves-by-another-interface")
    }
}

/// Whether a socket with local address `local` is bound to the wildcard
/// address (`::` or `0.0.0.0`). An unreadable address counts as specific,
/// the form for which [`reply_path`] withholds more.
pub(crate) fn wildcard_bind(local: std::io::Result<std::net::SocketAddr>) -> bool {
    local.is_ok_and(|addr| addr.ip().is_unspecified())
}

/// Run the DNS responder UDP server loop.
///
/// Listens for DNS queries, resolves `.fips` names, and sends resolved
/// identities to the Node via the identity channel. The host map reloader
/// checks the hosts file modification time on each query that passes the
/// screen and reloads automatically when changes are detected.
///
/// When `mesh_ifindex` is `Some`, queries arriving on that interface are
/// dropped silently. This closes the fips0-exposure side-channel created
/// by the `::` bind: mesh peers can reach the listener over fips0 and
/// probe `/etc/fips/hosts` aliases via dictionary attack. The check
/// requires `IPV6_RECVPKTINFO` to be enabled on the socket (done in
/// `Node::bind_dns_socket`); if it is not, arrival ifindex is unknown
/// and no filter is applied. This entry point does not know the node's mesh
/// address, so with `mesh_ifindex` `None` nothing is filtered; the daemon
/// starts the responder with its mesh address as well (see [`mesh_query`]).
pub async fn run_dns_responder(
    socket: tokio::net::UdpSocket,
    identity_tx: DnsIdentityTx,
    ttl: u32,
    reloader: HostMapReloader,
    mesh_ifindex: Option<u32>,
) {
    let mesh = MeshSide {
        ifindex: mesh_ifindex,
        addr: None,
    };
    run_responder(socket, identity_tx, ttl, reloader, None, mesh).await
}

/// Run the DNS responder UDP server loop, taking peer-alias base updates.
///
/// Behaves as [`run_dns_responder`], and in addition, when `aliases` is
/// `Some`, applies the newest peer-alias base sent on it before answering
/// each query, so aliases follow the node's peer list when it is replaced
/// at runtime. The hosts file stays merged over the new base and still wins.
/// Queries from the mesh, as [`mesh_query`] judges them against `mesh`, are
/// dropped unanswered.
pub(crate) async fn run_responder(
    socket: tokio::net::UdpSocket,
    identity_tx: DnsIdentityTx,
    ttl: u32,
    mut reloader: HostMapReloader,
    mut aliases: Option<tokio::sync::watch::Receiver<HostMap>>,
    mesh: MeshSide,
) {
    let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
    let wildcard = wildcard_bind(socket.local_addr());

    loop {
        let (len, src, arrival) = match recv_with_pktinfo(&socket, &mut buf).await {
            Ok(result) => result,
            Err(e) => {
                debug!(error = %e, "DNS socket recv error");
                continue;
            }
        };
        let arrival_ifindex = arrival.ifindex;

        if mesh_query(arrival, src, mesh) {
            trace!(
                src = %src,
                ifindex = ?arrival_ifindex,
                dst = ?arrival.dst,
                "DNS query from the mesh, dropping"
            );
            continue;
        }

        let query_bytes = &buf[..len];

        // For a query, apply any new peer-alias base, then check for hosts
        // file changes (cheap stat call).
        let outcome = respond(query_bytes, src.port(), ttl, || {
            refresh_hosts(&mut reloader, aliases.as_mut());
            reloader.hosts()
        });
        let (response_bytes, identity) = match outcome {
            Outcome::Drop(reason) => {
                debug!(src = %src, len, reason = reason.as_str(), "DNS datagram dropped");
                continue;
            }
            Outcome::Refuse(rcode, bytes) => {
                debug!(src = %src, len, rcode = %rcode, "DNS query refused");
                (bytes, None)
            }
            Outcome::Answer(answer) => answer,
        };

        if let Some(id) = identity {
            debug!(
                node_addr = %id.node_addr,
                "DNS resolved .fips name, registering identity"
            );
            let _ = identity_tx.send(id).await;
        }

        let strict_pin = cfg!(target_os = "linux");
        let path = reply_path(src, arrival_ifindex, mesh.ifindex, wildcard, strict_pin);
        if let Err(e) = send_reply(&socket, &response_bytes, src, path, mesh.addr).await {
            debug!(error = %e, "DNS send error");
        }
    }
}

/// Send `buf` to `dst` by `path`: routed, pinned to the arrival interface
/// (Linux), or dropped when withheld. A `Returning` reply is routed when the
/// table takes it back out of its arrival interface or delivers it locally,
/// and dropped otherwise. [`reply_path`] gives `Pinned` only on Linux; on any
/// other target a `Pinned` path is treated as `Returning`. `mesh_addr` is the
/// node's own mesh address while a TUN is up, which a `Returning` check
/// uses.
pub(crate) async fn send_reply(
    socket: &tokio::net::UdpSocket,
    buf: &[u8],
    dst: std::net::SocketAddr,
    path: ReplyPath,
    mesh_addr: Option<Ipv6Addr>,
) -> std::io::Result<usize> {
    match path {
        ReplyPath::Routed => socket.send_to(buf, dst).await,
        ReplyPath::Returning(arrival) => send_returning(socket, buf, dst, arrival, mesh_addr).await,
        #[cfg(target_os = "linux")]
        ReplyPath::Pinned(ifindex) => send_pinned(socket, buf, dst, ifindex).await,
        #[cfg(not(target_os = "linux"))]
        ReplyPath::Pinned(arrival) => send_returning(socket, buf, dst, arrival, mesh_addr).await,
        ReplyPath::Withheld => {
            debug!(
                src = %dst,
                reason = "mesh-source-off-mesh-interface",
                "DNS reply withheld on a specific bind"
            );
            Ok(0)
        }
    }
}

/// Send `buf` to `dst` by the routing table if the table takes it back out
/// of interface `arrival` or delivers it locally; otherwise drop it.
async fn send_returning(
    socket: &tokio::net::UdpSocket,
    buf: &[u8],
    dst: std::net::SocketAddr,
    arrival: u32,
    mesh_addr: Option<Ipv6Addr>,
) -> std::io::Result<usize> {
    match check_returning(dst, arrival, mesh_addr) {
        Ok(()) => socket.send_to(buf, dst).await,
        Err(reason) => {
            debug!(
                src = %dst,
                ifindex = arrival,
                reason,
                "DNS reply to a mesh source withheld"
            );
            Ok(0)
        }
    }
}

/// Send `buf` to the IPv6 address `dst` only out of interface `ifindex`.
///
/// One `sendmsg` carrying an `IPV6_PKTINFO` control message with the
/// interface index and an unspecified source address, so the kernel picks
/// the source and fails the send (`ENETUNREACH`) rather than route it by
/// another interface when `dst` is not reachable through `ifindex`.
#[cfg(target_os = "linux")]
async fn send_pinned(
    socket: &tokio::net::UdpSocket,
    buf: &[u8],
    dst: std::net::SocketAddr,
    ifindex: u32,
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;
    let std::net::SocketAddr::V6(dst) = dst else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pinned DNS reply to a non-IPv6 address",
        ));
    };
    loop {
        socket.writable().await?;
        let fd = socket.as_raw_fd();
        match socket.try_io(tokio::io::Interest::WRITABLE, || {
            sendmsg_pinned(fd, buf, &dst, ifindex)
        }) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            other => return other,
        }
    }
}

/// Non-blocking `sendmsg` of `buf` to `dst` with one `IPV6_PKTINFO` control
/// message naming `ifindex` and an unspecified source address.
///
/// Returns `Err(WouldBlock)` when the socket buffer is full (caller should
/// await writability again).
#[cfg(target_os = "linux")]
fn sendmsg_pinned(
    fd: std::os::fd::RawFd,
    buf: &[u8],
    dst: &std::net::SocketAddrV6,
    ifindex: u32,
) -> std::io::Result<usize> {
    // SAFETY: an all-zero sockaddr_in6 is a valid value; the fields set
    // below are the ones sendmsg reads.
    let mut name: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    name.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    name.sin6_port = dst.port().to_be();
    name.sin6_flowinfo = dst.flowinfo();
    name.sin6_addr.s6_addr = dst.ip().octets();
    name.sin6_scope_id = dst.scope_id();

    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut _,
        iov_len: buf.len(),
    };

    let info_len = std::mem::size_of::<libc::in6_pktinfo>() as u32;
    // u64 elements keep the buffer aligned for cmsghdr; 64 bytes is ample
    // for one IPV6_PKTINFO message.
    let mut cmsg_buf = [0u64; 8];

    // SAFETY: an all-zero msghdr is valid; every pointer stored in it below
    // refers to a local that outlives the sendmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut _;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    // SAFETY: CMSG_SPACE is a pure size computation.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(info_len) } as _;

    // SAFETY: msg_control points at a buffer of at least msg_controllen
    // bytes, so CMSG_FIRSTHDR is non-null and its data fits one in6_pktinfo.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(info_len) as _;
        let info = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
            ipi6_ifindex: ifindex,
        };
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo, info);
    }

    // SAFETY: msg is fully initialised above and its buffers are live.
    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Bring the responder's host map up to date before answering a query.
///
/// Applies the newest peer-alias base from `aliases` if it has not been seen
/// yet, then re-reads the hosts file if its mtime changed. The change test is
/// made on the borrowed value rather than the receiver, so a value sent just
/// before the sender closed is still applied.
fn refresh_hosts(
    reloader: &mut HostMapReloader,
    aliases: Option<&mut tokio::sync::watch::Receiver<HostMap>>,
) {
    if let Some(rx) = aliases {
        // Take the value out so the watch lock is released before the merge.
        let next = {
            let seen = rx.borrow_and_update();
            seen.has_changed().then(|| seen.clone())
        };
        if let Some(base) = next {
            reloader.set_base(base);
        }
    }
    reloader.check_reload();
}

/// Where a received datagram arrived, as far as the socket reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Arrival {
    /// The index of the interface the datagram arrived on, from
    /// `IPV6_PKTINFO`; `None` when the kernel gave no such message.
    pub(crate) ifindex: Option<u32>,
    /// The datagram's destination address, from the same message (v4-mapped
    /// for an IPv4 arrival on a dual-stack socket); `None` when the kernel
    /// gave no such message, and always on Windows.
    pub(crate) dst: Option<Ipv6Addr>,
}

/// Enable `IPV6_RECVPKTINFO` on an IPv6 UDP socket.
///
/// After this setsockopt, each `recvmsg()` call on the socket receives
/// an `IPV6_PKTINFO` control message containing the arrival interface
/// index, which the DNS responder uses for its mesh-interface filter.
#[cfg(unix)]
pub(crate) fn set_recv_pktinfo_v6(sock: &socket2::Socket) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;
    let enable: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a UDP datagram with arrival-interface info via `IPV6_PKTINFO`.
///
/// Returns `(len, src, arrival)`. The arrival ifindex and destination are
/// `Some` when the kernel delivered an `IPV6_PKTINFO` control message, which
/// Linux does for IPv4 arrivals on a dual-stack socket too; `None` otherwise
/// (for example `IPV6_RECVPKTINFO` not enabled, or on Windows, which reads
/// neither). A `None` ifindex disables the interface filter for that packet
/// (fail-open on unknown arrival; [`mesh_query`] then judges by address when
/// the node's mesh address is known) and leaves its reply routed, except a
/// reply to a mesh source on a socket bound to a specific address with a
/// known mesh interface, which [`reply_path`] withholds.
#[cfg(unix)]
pub(crate) async fn recv_with_pktinfo(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Arrival)> {
    use std::os::fd::AsRawFd;
    loop {
        socket.readable().await?;
        let fd = socket.as_raw_fd();
        match socket.try_io(tokio::io::Interest::READABLE, || {
            recvmsg_with_pktinfo(fd, buf)
        }) {
            Ok(result) => return Ok(result),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(not(unix))]
pub(crate) async fn recv_with_pktinfo(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Arrival)> {
    let (len, src) = socket.recv_from(buf).await?;
    Ok((len, src, Arrival::default()))
}

/// Blocking `recvmsg` wrapper that extracts `IPV6_PKTINFO` ifindex.
///
/// Returns `Err(WouldBlock)` when the socket has no data (caller should
/// await readability again).
#[cfg(unix)]
fn recvmsg_with_pktinfo(
    fd: std::os::fd::RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Arrival)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };

    let mut src_store: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    // 128 bytes is ample: IPV6_PKTINFO cmsg is ~36 bytes aligned.
    let mut cmsg_buf = [0u8; 128];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_store as *mut _ as *mut _;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let n = n as usize;

    let src = sockaddr_storage_to_socket_addr(&src_store, msg.msg_namelen)?;

    Ok((n, src, extract_pktinfo(&msg)))
}

/// Walk the cmsg chain and return the `IPV6_PKTINFO` ifindex and destination
/// address, if present.
#[cfg(unix)]
fn extract_pktinfo(msg: &libc::msghdr) -> Arrival {
    let mut cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg_ptr.is_null() {
        let cmsg = unsafe { &*cmsg_ptr };
        if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_PKTINFO {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg_ptr) } as *const libc::in6_pktinfo;
            let pktinfo: libc::in6_pktinfo = unsafe { std::ptr::read_unaligned(data_ptr) };
            return Arrival {
                ifindex: Some(pktinfo.ipi6_ifindex as u32),
                dst: Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)),
            };
        }
        cmsg_ptr = unsafe { libc::CMSG_NXTHDR(msg, cmsg_ptr) };
    }
    Arrival::default()
}

/// Convert a populated `sockaddr_storage` to `SocketAddr`.
#[cfg(unix)]
fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> std::io::Result<std::net::SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "sockaddr_in too small",
                ));
            }
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                ip, port,
            )))
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "sockaddr_in6 too small",
                ));
            }
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        af => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected address family: {}", af),
        )),
    }
}

#[cfg(test)]
#[path = "tests/dns.rs"]
mod reply_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use simple_dns::rdata::RData;
    use simple_dns::{CLASS, Name, Packet, QTYPE, RCODE, TYPE};

    #[test]
    fn test_resolve_valid_npub() {
        let identity = Identity::generate();
        let npub = identity.npub();
        let expected_ipv6 = identity.address().to_ipv6();

        let query = format!("{}.fips", npub);
        let result = resolve_fips_query(&query);

        assert!(result.is_some(), "should resolve valid npub.fips");
        let (ipv6, node_addr, _pubkey) = result.unwrap();
        assert_eq!(ipv6, expected_ipv6);
        assert_eq!(node_addr, *identity.node_addr());
    }

    #[test]
    fn test_resolve_trailing_dot() {
        let identity = Identity::generate();
        let npub = identity.npub();
        let expected_ipv6 = identity.address().to_ipv6();

        let query = format!("{}.fips.", npub);
        let result = resolve_fips_query(&query);

        assert!(result.is_some(), "should handle trailing dot");
        let (ipv6, _, _) = result.unwrap();
        assert_eq!(ipv6, expected_ipv6);
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let identity = Identity::generate();
        let npub = identity.npub();

        // .FIPS
        let result = resolve_fips_query(&format!("{}.FIPS", npub));
        assert!(result.is_some(), "should handle .FIPS");

        // .Fips
        let result = resolve_fips_query(&format!("{}.Fips", npub));
        assert!(result.is_some(), "should handle .Fips");
    }

    #[test]
    fn test_resolve_invalid_npub() {
        let result = resolve_fips_query("not-a-valid-npub.fips");
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_wrong_suffix() {
        let identity = Identity::generate();
        let npub = identity.npub();

        let result = resolve_fips_query(&format!("{}.com", npub));
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_empty_name() {
        assert!(resolve_fips_query("").is_none());
        assert!(resolve_fips_query(".fips").is_none());
        assert!(resolve_fips_query("fips").is_none());
    }

    // --- resolve_fips_query_with_hosts tests ---

    #[test]
    fn test_resolve_hostname_via_hosts() {
        let identity = Identity::generate();
        let expected_ipv6 = identity.address().to_ipv6();

        let mut hosts = HostMap::new();
        hosts.insert("gateway", &identity.npub()).unwrap();

        let result = resolve_fips_query_with_hosts("gateway.fips", &hosts);
        assert!(result.is_some(), "should resolve hostname via host map");
        let (ipv6, node_addr, _) = result.unwrap();
        assert_eq!(ipv6, expected_ipv6);
        assert_eq!(node_addr, *identity.node_addr());
    }

    #[test]
    fn test_resolve_hostname_case_insensitive() {
        let identity = Identity::generate();

        let mut hosts = HostMap::new();
        hosts.insert("gateway", &identity.npub()).unwrap();

        assert!(resolve_fips_query_with_hosts("Gateway.FIPS", &hosts).is_some());
        assert!(resolve_fips_query_with_hosts("GATEWAY.fips", &hosts).is_some());
    }

    #[test]
    fn test_resolve_hostname_trailing_dot() {
        let identity = Identity::generate();

        let mut hosts = HostMap::new();
        hosts.insert("gateway", &identity.npub()).unwrap();

        assert!(resolve_fips_query_with_hosts("gateway.fips.", &hosts).is_some());
    }

    #[test]
    fn test_resolve_npub_with_empty_hosts() {
        let identity = Identity::generate();
        let expected_ipv6 = identity.address().to_ipv6();
        let hosts = HostMap::new();

        let query = format!("{}.fips", identity.npub());
        let result = resolve_fips_query_with_hosts(&query, &hosts);
        assert!(result.is_some(), "should fall through to npub resolution");
        let (ipv6, _, _) = result.unwrap();
        assert_eq!(ipv6, expected_ipv6);
    }

    #[test]
    fn test_resolve_unknown_hostname_returns_none() {
        let hosts = HostMap::new();
        assert!(resolve_fips_query_with_hosts("unknown.fips", &hosts).is_none());
    }

    // --- handle_dns_packet tests ---

    #[test]
    fn test_handle_aaaa_query() {
        let identity = Identity::generate();
        let npub = identity.npub();
        let expected_ipv6 = identity.address().to_ipv6();
        let hosts = HostMap::new();

        let query_name = format!("{}.fips", npub);
        let query_packet = build_test_query(&query_name, TYPE::AAAA);

        let result = handle_dns_packet(&query_packet, 53000, 300, &hosts);
        assert!(result.is_some(), "should handle AAAA query");

        let (response_bytes, identity_opt) = result.unwrap();
        assert!(identity_opt.is_some(), "should produce identity");

        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.answers.len(), 1);

        if let RData::AAAA(aaaa) = &response.answers[0].rdata {
            let addr = Ipv6Addr::from(aaaa.address);
            assert_eq!(addr, expected_ipv6);
        } else {
            panic!("expected AAAA record");
        }
    }

    #[test]
    fn test_handle_aaaa_query_hostname() {
        let identity = Identity::generate();
        let expected_ipv6 = identity.address().to_ipv6();

        let mut hosts = HostMap::new();
        hosts.insert("gateway", &identity.npub()).unwrap();

        let query_packet = build_test_query("gateway.fips", TYPE::AAAA);

        let result = handle_dns_packet(&query_packet, 53000, 300, &hosts);
        assert!(result.is_some(), "should handle hostname AAAA query");

        let (response_bytes, identity_opt) = result.unwrap();
        assert!(
            identity_opt.is_some(),
            "should produce identity for hostname"
        );

        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.answers.len(), 1);

        if let RData::AAAA(aaaa) = &response.answers[0].rdata {
            assert_eq!(Ipv6Addr::from(aaaa.address), expected_ipv6);
        } else {
            panic!("expected AAAA record");
        }
    }

    #[test]
    fn test_handle_nxdomain_for_unknown() {
        let hosts = HostMap::new();
        let query_packet = build_test_query("unknown.fips", TYPE::AAAA);

        let result = handle_dns_packet(&query_packet, 53000, 300, &hosts);
        assert!(result.is_some());

        let (response_bytes, identity_opt) = result.unwrap();
        assert!(
            identity_opt.is_none(),
            "should not produce identity for unknown"
        );

        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.rcode(), RCODE::NameError);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn test_handle_non_aaaa_query() {
        let identity = Identity::generate();
        let hosts = HostMap::new();
        let query_name = format!("{}.fips", identity.npub());
        let query_packet = build_test_query(&query_name, TYPE::A);

        let result = handle_dns_packet(&query_packet, 53000, 300, &hosts);
        assert!(result.is_some());

        let (response_bytes, identity_opt) = result.unwrap();
        assert!(identity_opt.is_none(), "A query should not resolve .fips");

        // Valid .fips name but unsupported record type: NOERROR with empty
        // answers (not NXDOMAIN, which would stop resolvers from trying AAAA)
        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.rcode(), RCODE::NoError);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn test_dns_responder_udp() {
        let identity = Identity::generate();
        let npub = identity.npub();
        let expected_ipv6 = identity.address().to_ipv6();

        // Use a nonexistent path — reloader handles missing file gracefully
        let reloader = HostMapReloader::new(
            HostMap::new(),
            std::path::PathBuf::from("/nonexistent/hosts"),
        );

        // Bind responder on ephemeral port
        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let (identity_tx, mut identity_rx) = tokio::sync::mpsc::channel(16);

        // Spawn the responder
        let responder_handle = tokio::spawn(run_dns_responder(
            server_socket,
            identity_tx,
            300,
            reloader,
            None,
        ));

        // Send a query
        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_test_query(&format!("{}.fips", npub), TYPE::AAAA);
        client_socket.send_to(&query, server_addr).await.unwrap();

        // Receive response
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        let response = Packet::parse(&buf[..len]).unwrap();
        assert_eq!(response.answers.len(), 1);
        if let RData::AAAA(aaaa) = &response.answers[0].rdata {
            assert_eq!(Ipv6Addr::from(aaaa.address), expected_ipv6);
        } else {
            panic!("expected AAAA record");
        }

        // Verify identity was sent through channel
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), identity_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.node_addr, *identity.node_addr());

        responder_handle.abort();
    }

    #[tokio::test]
    async fn test_dns_responder_with_hosts() {
        let identity = Identity::generate();
        let expected_ipv6 = identity.address().to_ipv6();

        // Write a hosts file with our test entry
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        std::fs::write(&hosts_path, format!("gateway   {}\n", identity.npub())).unwrap();

        let reloader = HostMapReloader::new(HostMap::new(), hosts_path);

        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let (identity_tx, mut identity_rx) = tokio::sync::mpsc::channel(16);

        let responder_handle = tokio::spawn(run_dns_responder(
            server_socket,
            identity_tx,
            300,
            reloader,
            None,
        ));

        // Query by hostname instead of npub
        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_test_query("gateway.fips", TYPE::AAAA);
        client_socket.send_to(&query, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        let response = Packet::parse(&buf[..len]).unwrap();
        assert_eq!(response.answers.len(), 1);
        if let RData::AAAA(aaaa) = &response.answers[0].rdata {
            assert_eq!(Ipv6Addr::from(aaaa.address), expected_ipv6);
        } else {
            panic!("expected AAAA record");
        }

        // Verify identity registration
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(1), identity_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.node_addr, *identity.node_addr());

        responder_handle.abort();
    }

    #[tokio::test]
    async fn test_dns_responder_auto_reload() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let expected_ipv6_2 = id2.address().to_ipv6();

        // Start with hosts file containing only id1
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        std::fs::write(&hosts_path, format!("gateway   {}\n", id1.npub())).unwrap();

        let reloader = HostMapReloader::new(HostMap::new(), hosts_path.clone());

        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (identity_tx, _identity_rx) = tokio::sync::mpsc::channel(16);

        let responder_handle = tokio::spawn(run_dns_responder(
            server_socket,
            identity_tx,
            300,
            reloader,
            None,
        ));

        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // "server2" should not resolve yet
        let query = build_test_query("server2.fips", TYPE::AAAA);
        client_socket.send_to(&query, server_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = Packet::parse(&buf[..len]).unwrap();
        assert!(
            response.answers.is_empty(),
            "server2 should not resolve before reload"
        );

        // Update the hosts file to add server2
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(
            &hosts_path,
            format!("gateway   {}\nserver2   {}\n", id1.npub(), id2.npub()),
        )
        .unwrap();

        // Next query should trigger reload — query server2 again
        let query = build_test_query("server2.fips", TYPE::AAAA);
        client_socket.send_to(&query, server_addr).await.unwrap();
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = Packet::parse(&buf[..len]).unwrap();
        assert_eq!(
            response.answers.len(),
            1,
            "server2 should resolve after reload"
        );
        if let RData::AAAA(aaaa) = &response.answers[0].rdata {
            assert_eq!(Ipv6Addr::from(aaaa.address), expected_ipv6_2);
        } else {
            panic!("expected AAAA record");
        }

        responder_handle.abort();
    }

    // --- mesh-interface filter tests ---

    #[test]
    fn test_is_mesh_interface_query_matching() {
        assert!(
            is_mesh_interface_query(Some(7), Some(7)),
            "arrival == mesh ifindex should drop"
        );
    }

    #[test]
    fn test_is_mesh_interface_query_non_matching() {
        assert!(
            !is_mesh_interface_query(Some(1), Some(7)),
            "lo arrival should pass when mesh is fips0"
        );
    }

    #[test]
    fn test_is_mesh_interface_query_no_arrival() {
        assert!(
            !is_mesh_interface_query(None, Some(7)),
            "unknown arrival (no PKTINFO cmsg) should fail-open"
        );
    }

    #[test]
    fn test_is_mesh_interface_query_no_filter() {
        assert!(
            !is_mesh_interface_query(Some(7), None),
            "unconfigured mesh ifindex disables the filter"
        );
    }

    /// Look up loopback ifindex for tests. Returns 0 if lookup fails,
    /// which causes the calling test to skip.
    #[cfg(unix)]
    fn loopback_ifindex_for_test() -> u32 {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let c = std::ffi::CString::new(name).unwrap();
        unsafe { libc::if_nametoindex(c.as_ptr()) }
    }

    /// Build a socket bound to `[::1]:0` with `IPV6_RECVPKTINFO` enabled,
    /// mirroring the setup done in `Node::bind_dns_socket`.
    #[cfg(unix)]
    fn bind_loopback_v6_with_pktinfo() -> tokio::net::UdpSocket {
        tokio::net::UdpSocket::from_std(bind_pktinfo("[::1]:0".parse().unwrap())).unwrap()
    }

    /// Build a dual-stack socket bound to `addr` with `IPV6_RECVPKTINFO`
    /// enabled, mirroring the setup done in `Node::bind_dns_socket`.
    #[cfg(unix)]
    pub(super) fn bind_pktinfo(addr: std::net::SocketAddr) -> std::net::UdpSocket {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::os::fd::AsRawFd;
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        sock.set_only_v6(false).unwrap();
        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0, "setsockopt IPV6_RECVPKTINFO failed");
        sock.set_nonblocking(true).unwrap();
        sock.bind(&addr.into()).unwrap();
        sock.into()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_recv_with_pktinfo_returns_loopback_ifindex() {
        let lo = loopback_ifindex_for_test();
        if lo == 0 {
            // Lookup failed — skip rather than misreport a problem with the
            // filter for an environment issue.
            return;
        }

        let server = bind_loopback_v6_with_pktinfo();
        let server_addr = server.local_addr().unwrap();

        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        client.send_to(b"hello", server_addr).await.unwrap();

        let mut buf = [0u8; 32];
        let (len, src, arrival) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            recv_with_pktinfo(&server, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(&buf[..len], b"hello");
        assert!(src.ip().is_loopback(), "source should be loopback");
        assert_eq!(
            arrival.ifindex,
            Some(lo),
            "IPV6_PKTINFO should report loopback ifindex"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_dns_responder_drops_mesh_interface_query() {
        let lo = loopback_ifindex_for_test();
        if lo == 0 {
            return;
        }

        let server_socket = bind_loopback_v6_with_pktinfo();
        let server_addr = server_socket.local_addr().unwrap();

        let reloader = HostMapReloader::new(
            HostMap::new(),
            std::path::PathBuf::from("/nonexistent/hosts"),
        );
        let (identity_tx, _identity_rx) = tokio::sync::mpsc::channel(16);

        // Treat loopback as the "mesh" interface so queries from ::1 are
        // dropped. This exercises the real filter path end-to-end without
        // needing a TUN.
        let responder_handle = tokio::spawn(run_dns_responder(
            server_socket,
            identity_tx,
            300,
            reloader,
            Some(lo),
        ));

        let identity = Identity::generate();
        let query = build_test_query(&format!("{}.fips", identity.npub()), TYPE::AAAA);
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        client.send_to(&query, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client.recv_from(&mut buf),
        )
        .await;

        assert!(
            result.is_err(),
            "response arrived from server ({:?}) — filter did not drop mesh-interface query",
            result
        );

        responder_handle.abort();
    }

    /// On a wildcard bind, only a reply to a non-v4-mapped mesh source
    /// (`fd00::/8`) with a known arrival interface is pinned; everything else
    /// is routed. On a specific bind, a reply to a mesh source is withheld
    /// unless it arrived on the known mesh interface; with no known mesh
    /// interface it is sent only if the route returns it by its arrival
    /// interface. Non-mesh sources are routed on either bind. This is the
    /// table for a target that holds a strict pin (Linux); the other one is
    /// in `tests/dns.rs`.
    #[test]
    fn reply_path_pins_mesh_sources_and_withholds_them_off_the_mesh_on_a_specific_bind() {
        use ReplyPath::{Pinned, Returning, Routed, Withheld};
        let at = |ip: &str| std::net::SocketAddr::new(ip.parse().unwrap(), 4444);
        const WILD: bool = true;
        const SPECIFIC: bool = false;
        let cases = [
            // Wildcard bind, mesh interface 3.
            ("fd11:2233::7", Some(2), Some(3), WILD, Pinned(2)),
            ("fd11:2233::7", None, Some(3), WILD, Routed),
            ("fdab::2", Some(5), Some(3), WILD, Pinned(5)),
            ("2001:db8::2", Some(2), Some(3), WILD, Routed),
            ("fe80::1", Some(2), Some(3), WILD, Routed),
            ("::1", Some(1), Some(3), WILD, Routed),
            ("::ffff:192.0.2.2", Some(2), Some(3), WILD, Routed),
            ("::ffff:127.0.0.1", Some(1), Some(3), WILD, Routed),
            ("192.0.2.2", Some(2), Some(3), WILD, Routed),
            // Wildcard bind, no known mesh interface.
            ("fd11:2233::7", Some(2), None, WILD, Pinned(2)),
            ("fd11:2233::7", None, None, WILD, Routed),
            // Specific bind, mesh interface 3: a mesh source is answered only
            // when it arrived on the mesh interface.
            ("fd11:2233::7", Some(2), Some(3), SPECIFIC, Withheld),
            ("fdab::2", Some(5), Some(3), SPECIFIC, Withheld),
            ("fd11:2233::7", Some(1), Some(3), SPECIFIC, Withheld),
            ("fd11:2233::7", None, Some(3), SPECIFIC, Withheld),
            ("fd11:2233::7", Some(3), Some(3), SPECIFIC, Pinned(3)),
            ("2001:db8::2", Some(2), Some(3), SPECIFIC, Routed),
            ("fe80::1", Some(2), Some(3), SPECIFIC, Routed),
            ("::1", Some(1), Some(3), SPECIFIC, Routed),
            ("::ffff:192.0.2.2", Some(2), Some(3), SPECIFIC, Routed),
            ("192.0.2.2", Some(2), Some(3), SPECIFIC, Routed),
            // Specific bind, no known mesh interface.
            ("fd11:2233::7", Some(2), None, SPECIFIC, Returning(2)),
            ("fd11:2233::7", None, None, SPECIFIC, Routed),
        ];
        for (ip, arrival, mesh, wildcard, want) in cases {
            assert_eq!(
                reply_path(at(ip), arrival, mesh, wildcard, true),
                want,
                "source {ip}, arrival {arrival:?}, mesh {mesh:?}, wildcard {wildcard}"
            );
        }
    }

    /// Only a socket bound to `::` or `0.0.0.0` counts as a wildcard bind; a
    /// specific address, and an address that cannot be read, do not.
    #[test]
    fn wildcard_bind_is_true_only_for_the_unspecified_addresses() {
        let at = |addr: &str| Ok(addr.parse::<std::net::SocketAddr>().unwrap());
        assert!(wildcard_bind(at("[::]:5354")));
        assert!(wildcard_bind(at("0.0.0.0:5354")));
        assert!(!wildcard_bind(at("[::1]:5354")));
        assert!(!wildcard_bind(at("127.0.0.1:5354")));
        assert!(!wildcard_bind(at("[2001:db8:1::1]:5354")));
        assert!(!wildcard_bind(at("192.0.2.1:5354")));
        assert!(!wildcard_bind(Err(std::io::Error::other("no address"))));
    }

    /// A withheld reply is not sent at all.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_withheld_reply_is_not_delivered() {
        let sender = bind_loopback_v6_with_pktinfo();
        let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let dst = receiver.local_addr().unwrap();
        send_reply(&sender, b"withheld", dst, ReplyPath::Withheld, None)
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receiver.recv_from(&mut buf),
        )
        .await;
        assert!(got.is_err(), "the withheld reply was delivered: {got:?}");
    }

    /// The same send as a routed reply is delivered, so the receiver above
    /// would see a reply that was sent.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_routed_reply_to_the_same_receiver_is_delivered() {
        let sender = bind_loopback_v6_with_pktinfo();
        let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let dst = receiver.local_addr().unwrap();
        send_reply(&sender, b"routed", dst, ReplyPath::Routed, None)
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_millis(2000),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("the routed reply was not delivered")
        .unwrap();
        assert_eq!(&buf[..len], b"routed");
    }

    /// A responder on a dual-stack `IPV6_RECVPKTINFO` socket still answers
    /// IPv6 and IPv4 loopback clients, whose replies are routed.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_responder_still_answers_ipv6_and_ipv4_loopback_clients() {
        let server =
            tokio::net::UdpSocket::from_std(bind_pktinfo("[::]:0".parse().unwrap())).unwrap();
        let port = server.local_addr().unwrap().port();
        let reloader = HostMapReloader::new(
            HostMap::new(),
            std::path::PathBuf::from("/nonexistent/hosts"),
        );
        let (identity_tx, _identity_rx) = tokio::sync::mpsc::channel(16);
        let responder = tokio::spawn(run_responder(
            server,
            identity_tx,
            300,
            reloader,
            None,
            MeshSide::default(),
        ));

        for (client, server) in [("[::1]:0", "[::1]"), ("127.0.0.1:0", "127.0.0.1")] {
            let socket = tokio::net::UdpSocket::bind(client).await.unwrap();
            let target: std::net::SocketAddr = format!("{server}:{port}").parse().unwrap();
            let query =
                build_test_query(&format!("{}.fips", Identity::generate().npub()), TYPE::AAAA);
            socket.send_to(&query, target).await.unwrap();
            let mut buf = [0u8; 512];
            let (len, _) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.recv_from(&mut buf),
            )
            .await
            .unwrap_or_else(|_| panic!("the {server} client is answered"))
            .unwrap();
            assert_eq!(Packet::parse(&buf[..len]).unwrap().answers.len(), 1);
        }
        responder.abort();
    }

    /// A pinned send to `[::1]` out of the loopback interface is delivered.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_reply_pinned_to_loopback_reaches_a_loopback_client() {
        let lo = loopback_ifindex_for_test();
        assert_ne!(lo, 0, "loopback has an index");
        let sender = bind_loopback_v6_with_pktinfo();
        let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let dst = receiver.local_addr().unwrap();

        let sent = send_pinned(&sender, b"pinned", dst, lo).await.unwrap();
        assert_eq!(sent, 6);
        let mut buf = [0u8; 16];
        let (len, src) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("the pinned send is delivered")
        .unwrap();
        assert_eq!(&buf[..len], b"pinned");
        assert_eq!(src, sender.local_addr().unwrap());
    }

    /// A pinned send naming an interface that does not exist fails and
    /// delivers nothing, so the send carries the pin. Whether the kernel
    /// holds the reply strictly to the pinned interface is checked only by
    /// the root-namespace test below.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_reply_pinned_to_a_missing_interface_fails_and_is_not_delivered() {
        let sender = bind_loopback_v6_with_pktinfo();
        let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let dst = receiver.local_addr().unwrap();

        let sent = send_pinned(&sender, b"pinned", dst, 0x7fff_fff0).await;
        assert!(
            sent.is_err(),
            "a send pinned to a missing interface went out: {sent:?}"
        );
        let mut buf = [0u8; 16];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receiver.recv_from(&mut buf),
        )
        .await;
        assert!(got.is_err(), "the pinned datagram was delivered: {got:?}");
    }

    /// Two root network namespaces joined by a veth, deleted on drop.
    ///
    /// The responder side carries a dummy `fips0` with a mesh address and
    /// the `fd00::/8` route, as the daemon's TUN gives it, and an nft counter
    /// of UDP leaving `fips0` from the responder's port. Needs root.
    #[cfg(target_os = "linux")]
    pub(super) struct ForgedSourceNetns {
        pub(super) node: String,
        pub(super) lan: String,
    }

    #[cfg(target_os = "linux")]
    impl ForgedSourceNetns {
        pub(super) const PORT: u16 = 5354;

        /// Create and configure both namespaces.
        pub(super) fn new() -> Self {
            Self::build(true)
        }

        /// As [`Self::new`], but `fips0` carries no address, only the
        /// `fd00::/8` route, as an application-supplied TUN may.
        pub(super) fn with_addressless_mesh() -> Self {
            Self::build(false)
        }

        /// Create and configure both namespaces, with `fd99::1` on `fips0`
        /// when `mesh_addr` is set.
        fn build(mesh_addr: bool) -> Self {
            // Tests run in parallel in one process, so each pair gets its own
            // sequence number.
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let id = std::process::id();
            let ns = Self {
                node: format!("fipsdns-node-{id}-{seq}"),
                lan: format!("fipsdns-lan-{id}-{seq}"),
            };
            let (a, b) = (ns.node.as_str(), ns.lan.as_str());
            for args in [
                vec!["netns", "add", a],
                vec!["netns", "add", b],
                vec![
                    "link", "add", "a0", "netns", a, "type", "veth", "peer", "name", "b0", "netns",
                    b,
                ],
                vec!["-n", a, "link", "set", "lo", "up"],
                vec!["-n", b, "link", "set", "lo", "up"],
                vec!["-n", a, "link", "set", "a0", "up"],
                vec!["-n", b, "link", "set", "b0", "up"],
                vec![
                    "-n",
                    a,
                    "addr",
                    "add",
                    "2001:db8:1::1/64",
                    "dev",
                    "a0",
                    "nodad",
                ],
                vec![
                    "-n",
                    b,
                    "addr",
                    "add",
                    "2001:db8:1::2/64",
                    "dev",
                    "b0",
                    "nodad",
                ],
                vec!["-n", a, "addr", "add", "fdab::1/64", "dev", "a0", "nodad"],
                vec!["-n", b, "addr", "add", "fdab::2/64", "dev", "b0", "nodad"],
                vec![
                    "-n",
                    b,
                    "addr",
                    "add",
                    "fd11:2233::7/128",
                    "dev",
                    "b0",
                    "nodad",
                ],
                vec!["-n", a, "link", "add", "fips0", "type", "dummy"],
                vec!["-n", a, "link", "set", "fips0", "up"],
                vec![
                    "-n",
                    a,
                    "addr",
                    "add",
                    "fd99::1/128",
                    "dev",
                    "fips0",
                    "nodad",
                ],
                vec!["-n", a, "route", "add", "fd00::/8", "dev", "fips0"],
            ] {
                if !mesh_addr && args.contains(&"fd99::1/128") {
                    continue;
                }
                crate::testutil::run_ok("ip", &args);
            }
            let rule = format!(
                "oifname \"fips0\" udp sport {} counter name refl",
                Self::PORT
            );
            for cmd in [
                "add table inet dnstest".to_string(),
                "add counter inet dnstest refl".to_string(),
                "add chain inet dnstest out { type filter hook output priority 0 ; }".to_string(),
                format!("add rule inet dnstest out {rule}"),
            ] {
                let mut args = vec!["netns", "exec", a, "nft"];
                args.extend(cmd.split(' '));
                crate::testutil::run_ok("ip", &args);
            }
            ns
        }

        /// Run `f` on a thread that has entered namespace `name`, so any
        /// socket it creates belongs to that namespace.
        pub(super) fn enter<T: Send + 'static>(
            name: &str,
            f: impl FnOnce() -> T + Send + 'static,
        ) -> T {
            crate::testutil::in_netns(name, f)
        }

        /// Index of the responder side's `fips0`.
        pub(super) fn mesh_ifindex(&self) -> u32 {
            Self::enter(&self.node, || {
                let c = std::ffi::CString::new("fips0").unwrap();
                unsafe { libc::if_nametoindex(c.as_ptr()) }
            })
        }

        /// UDP packets from the responder's port that have left by `fips0`.
        pub(super) fn mesh_replies(&self) -> u64 {
            let out = std::process::Command::new("ip")
                .args([
                    "netns", "exec", &self.node, "nft", "list", "counter", "inet", "dnstest",
                    "refl",
                ])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            let n = text
                .split_whitespace()
                .skip_while(|w| *w != "packets")
                .nth(1)
                .unwrap_or_else(|| panic!("no packet count in nft output: {text}"));
            n.parse().unwrap()
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ForgedSourceNetns {
        fn drop(&mut self) {
            for ns in [&self.node, &self.lan] {
                let _ = std::process::Command::new("ip")
                    .args(["netns", "del", ns])
                    .status();
            }
        }
    }

    /// A LAN host that forges a mesh source address must not make this node
    /// send the reply into the mesh. The responder is bound to `[::]` as with
    /// a non-loopback `dns.bind_addr`, and the query arrives on the LAN veth,
    /// so the mesh-interface filter does not apply to it.
    ///
    /// Needs root (network namespaces, nft): build with
    /// `cargo test --lib --no-run` and run the test binary under `sudo` with
    /// `--ignored`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs root: creates network namespaces"]
    async fn a_lan_query_with_a_forged_mesh_source_is_not_answered_into_the_mesh() {
        let ns = ForgedSourceNetns::new();
        let mesh_ifindex = ns.mesh_ifindex();
        assert_ne!(mesh_ifindex, 0, "fips0 has an index");

        let server = ForgedSourceNetns::enter(&ns.node, || {
            let addr = std::net::SocketAddr::from((Ipv6Addr::UNSPECIFIED, ForgedSourceNetns::PORT));
            bind_pktinfo(addr)
        });
        let server = tokio::net::UdpSocket::from_std(server).unwrap();
        let (genuine, ula, forged) = ForgedSourceNetns::enter(&ns.lan, || {
            let bind = |a: &str| {
                let s = std::net::UdpSocket::bind(a).unwrap();
                s.set_nonblocking(true).unwrap();
                s
            };
            (
                bind("[2001:db8:1::2]:4443"),
                bind("[fdab::2]:4445"),
                bind("[fd11:2233::7]:4444"),
            )
        });
        let genuine = tokio::net::UdpSocket::from_std(genuine).unwrap();
        let ula = tokio::net::UdpSocket::from_std(ula).unwrap();
        let forged = tokio::net::UdpSocket::from_std(forged).unwrap();

        let reloader = HostMapReloader::new(
            HostMap::new(),
            std::path::PathBuf::from("/nonexistent/hosts"),
        );
        let (identity_tx, mut identity_rx) = tokio::sync::mpsc::channel(16);
        let responder = tokio::spawn(run_responder(
            server,
            identity_tx,
            300,
            reloader,
            None,
            MeshSide {
                ifindex: Some(mesh_ifindex),
                addr: None,
            },
        ));

        let target: std::net::SocketAddr = "[2001:db8:1::1]:5354".parse().unwrap();
        let ula_target: std::net::SocketAddr = "[fdab::1]:5354".parse().unwrap();

        // Healthy path: a LAN client's query is answered on the LAN, and so
        // is an on-link ULA client's, whose source is in fd00::/8 too.
        for (client, to, what) in [
            (&genuine, target, "the LAN client is answered"),
            (&ula, ula_target, "the on-link ULA client is answered"),
        ] {
            expect_answer(client, to, &mut identity_rx, what).await;
        }

        // The forged query reaches the responder and is resolved, but its
        // reply must not leave by the mesh interface.
        send_unanswered(&forged, target, &mut identity_rx).await;
        let into_mesh = ns.mesh_replies();
        responder.abort();
        assert_eq!(
            into_mesh, 0,
            "a LAN query from forged source fd11:2233::7 was answered into the mesh: \
             {into_mesh} UDP packet(s) from port 5354 left by fips0"
        );
    }

    /// A LAN host that forges a mesh source address must not make this node
    /// send the reply into the mesh when the responder is bound to one
    /// specific LAN address. Such a socket sends from that address, so the
    /// kernel does not hold a pinned reply to the arrival interface; the
    /// reply must be withheld instead. A LAN client with a global source is
    /// still answered.
    ///
    /// Needs root (network namespaces, nft): build with
    /// `cargo test --lib --no-run` and run the test binary under `sudo` with
    /// `--ignored`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs root: creates network namespaces"]
    async fn a_lan_query_with_a_forged_mesh_source_is_not_answered_into_the_mesh_on_a_specific_bind()
     {
        let ns = ForgedSourceNetns::new();
        let mesh_ifindex = ns.mesh_ifindex();
        assert_ne!(mesh_ifindex, 0, "fips0 has an index");

        let target: std::net::SocketAddr = "[2001:db8:1::1]:5354".parse().unwrap();
        let server = ForgedSourceNetns::enter(&ns.node, move || bind_pktinfo(target));
        let server = tokio::net::UdpSocket::from_std(server).unwrap();
        let (genuine, forged) = ForgedSourceNetns::enter(&ns.lan, || {
            let bind = |a: &str| {
                let s = std::net::UdpSocket::bind(a).unwrap();
                s.set_nonblocking(true).unwrap();
                s
            };
            (bind("[2001:db8:1::2]:4443"), bind("[fd11:2233::7]:4444"))
        });
        let genuine = tokio::net::UdpSocket::from_std(genuine).unwrap();
        let forged = tokio::net::UdpSocket::from_std(forged).unwrap();

        let reloader = HostMapReloader::new(
            HostMap::new(),
            std::path::PathBuf::from("/nonexistent/hosts"),
        );
        let (identity_tx, mut identity_rx) = tokio::sync::mpsc::channel(16);
        let responder = tokio::spawn(run_responder(
            server,
            identity_tx,
            300,
            reloader,
            None,
            MeshSide {
                ifindex: Some(mesh_ifindex),
                addr: None,
            },
        ));

        expect_answer(
            &genuine,
            target,
            &mut identity_rx,
            "the LAN client is answered",
        )
        .await;
        send_unanswered(&forged, target, &mut identity_rx).await;
        let into_mesh = ns.mesh_replies();
        responder.abort();
        assert_eq!(
            into_mesh, 0,
            "with the responder bound to 2001:db8:1::1, a LAN query from forged source \
             fd11:2233::7 was answered into the mesh: {into_mesh} UDP packet(s) from port 5354 \
             left by fips0"
        );
    }

    /// Send an AAAA query for a fresh npub from `client` to `to` and expect
    /// an answer with one record, and the resolved identity on `identity_rx`.
    #[cfg(target_os = "linux")]
    pub(super) async fn expect_answer(
        client: &tokio::net::UdpSocket,
        to: std::net::SocketAddr,
        identity_rx: &mut DnsIdentityRx,
        what: &str,
    ) {
        let wait = std::time::Duration::from_secs(2);
        let query = build_test_query(&format!("{}.fips", Identity::generate().npub()), TYPE::AAAA);
        client.send_to(&query, to).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(wait, client.recv_from(&mut buf))
            .await
            .expect(what)
            .unwrap();
        assert_eq!(Packet::parse(&buf[..len]).unwrap().answers.len(), 1);
        tokio::time::timeout(wait, identity_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }

    /// Send an AAAA query for a fresh npub from `client` to `to`, wait until
    /// the responder has resolved it, then long enough for its reply to
    /// leave.
    #[cfg(target_os = "linux")]
    pub(super) async fn send_unanswered(
        client: &tokio::net::UdpSocket,
        to: std::net::SocketAddr,
        identity_rx: &mut DnsIdentityRx,
    ) {
        let query = build_test_query(&format!("{}.fips", Identity::generate().npub()), TYPE::AAAA);
        client.send_to(&query, to).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), identity_rx.recv())
            .await
            .expect("the forged query reaches the responder")
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    /// Build a test DNS query packet for a given name and record type.
    pub(super) fn build_test_query(name: &str, rtype: TYPE) -> Vec<u8> {
        use simple_dns::Question;

        let mut packet = Packet::new_query(0x1234);
        let question = Question::new(
            Name::new_unchecked(name).into_owned(),
            QTYPE::TYPE(rtype),
            simple_dns::QCLASS::CLASS(CLASS::IN),
            false,
        );
        packet.questions.push(question);
        packet.build_bytes_vec().unwrap()
    }

    /// Build a one-entry host map.
    fn one_entry(name: &str, id: &Identity) -> HostMap {
        let mut map = HostMap::new();
        map.insert(name, &id.npub()).unwrap();
        map
    }

    /// A base sent on the alias channel is applied before the next answer,
    /// and is kept once the sender is gone.
    #[test]
    fn refresh_hosts_applies_the_latest_base_before_answering() {
        let (x, y) = (Identity::generate(), Identity::generate());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent-hosts");
        let npub = |r: &HostMapReloader| r.hosts().lookup_npub("a").map(String::from);

        let mut reloader = HostMapReloader::new(one_entry("a", &x), path.clone());
        let (tx, mut rx) = tokio::sync::watch::channel(one_entry("a", &x));
        tx.send_replace(one_entry("a", &y));
        refresh_hosts(&mut reloader, Some(&mut rx));
        assert_eq!(npub(&reloader), Some(y.npub()), "new base applied");
        drop(tx);
        refresh_hosts(&mut reloader, Some(&mut rx));
        assert_eq!(npub(&reloader), Some(y.npub()), "base kept after close");

        // A value sent just before the sender closed is still applied.
        let mut reloader = HostMapReloader::new(one_entry("a", &x), path);
        let (tx, mut rx) = tokio::sync::watch::channel(one_entry("a", &x));
        tx.send_replace(one_entry("a", &y));
        drop(tx);
        refresh_hosts(&mut reloader, Some(&mut rx));
        assert_eq!(
            npub(&reloader),
            Some(y.npub()),
            "pending base applied although the sender is closed"
        );
    }
}

/// Screening of untrusted datagrams by the `.fips` responder.
///
/// These tests use only `handle_dns_packet`, `run_dns_responder`, the host
/// map types and byte builders of their own, so they run unchanged against
/// the responder before and after its datagrams were screened.
#[cfg(test)]
mod screening_tests {
    use super::*;
    use crate::Identity;
    use simple_dns::Packet;
    use simple_dns::rdata::RData;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// The daemon's configured record TTL, in seconds.
    const TTL: u32 = 300;
    /// An ordinary client source port, as a resolver would send from.
    const CLIENT_PORT: u16 = 53000;
    /// Record type A.
    const TYPE_A: u16 = 1;
    /// Record type AAAA.
    const TYPE_AAAA: u16 = 28;
    /// Record type SSHFP, one `simple-dns` cannot parse in a question.
    const TYPE_SSHFP: u16 = 44;
    /// Record type HTTPS.
    const TYPE_HTTPS: u16 = 65;
    /// Class IN.
    const CLASS_IN: u16 = 1;
    /// Class CH (Chaos).
    const CLASS_CH: u16 = 3;
    /// Rcode NOERROR.
    const NOERROR: u16 = 0;
    /// Rcode FORMERR.
    const FORMERR: u16 = 1;
    /// Rcode NXDOMAIN.
    const NXDOMAIN: u16 = 3;
    /// Rcode NOTIMP.
    const NOTIMP: u16 = 4;
    /// Rcode REFUSED.
    const REFUSED: u16 = 5;
    /// A daytime service's reply, as it would arrive from port 13.
    const DAYTIME: &[u8] = b"Thu Oct  9 12:00:00 2026\r\n";

    /// A dotted name in wire form, ending in the root label.
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A 255-byte wire name: three 63-byte labels and a 61-byte label, every
    /// label byte `fill`.
    fn longest_name(fill: u8) -> Vec<u8> {
        let mut out = Vec::new();
        for len in [63usize, 63, 63, 61] {
            out.push(len as u8);
            out.extend(std::iter::repeat_n(fill, len));
        }
        out.push(0);
        assert_eq!(out.len(), 255);
        out
    }

    /// A message: header with `id`, `flags` and the four counts, then `body`.
    fn message(id: u16, flags: u16, counts: [u16; 4], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        for count in counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    /// A question: a wire name, then type and class.
    fn question(name: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&qclass.to_be_bytes());
        out
    }

    /// A one-question query with no records.
    fn query(id: u16, flags: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let body = question(&wire_name(name), qtype, qclass);
        message(id, flags, [1, 0, 0, 0], &body)
    }

    /// An AAAA IN query for `name`, no flags.
    fn aaaa_query(id: u16, name: &str) -> Vec<u8> {
        query(id, 0, name, TYPE_AAAA, CLASS_IN)
    }

    /// An AAAA IN query for `name` carrying one EDNS OPT record whose
    /// padding option makes the datagram exactly `total` bytes long.
    fn padded_query(id: u16, name: &str, total: usize) -> Vec<u8> {
        let mut body = question(&wire_name(name), TYPE_AAAA, CLASS_IN);
        let fixed = 12 + body.len() + 11 + 4;
        let pad = total
            .checked_sub(fixed)
            .expect("total too small for the OPT");
        body.push(0); // root owner
        body.extend_from_slice(&41u16.to_be_bytes()); // OPT
        body.extend_from_slice(&1232u16.to_be_bytes()); // UDP payload size
        body.extend_from_slice(&0u32.to_be_bytes()); // extended rcode and flags
        body.extend_from_slice(&((4 + pad) as u16).to_be_bytes());
        body.extend_from_slice(&12u16.to_be_bytes()); // padding option
        body.extend_from_slice(&(pad as u16).to_be_bytes());
        body.extend(std::iter::repeat_n(0u8, pad));
        let out = message(id, 0, [1, 0, 0, 1], &body);
        assert_eq!(out.len(), total);
        out
    }

    /// The big-endian `u16` at `offset`.
    fn word(bytes: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
    }

    /// The rcode in a reply's header.
    fn rcode(reply: &[u8]) -> u16 {
        word(reply, 2) & 0x000F
    }

    /// A fresh identity and its `<npub>.fips` name.
    fn npub_name() -> (Identity, String) {
        let identity = Identity::generate();
        let name = format!("{}.fips", identity.npub());
        (identity, name)
    }

    /// The daemon's reply bytes for `datagram` from source port `port`.
    fn answer(datagram: &[u8], port: u16, hosts: &HostMap) -> Option<Vec<u8>> {
        handle_dns_packet(datagram, port, TTL, hosts).map(|(bytes, _)| bytes)
    }

    /// The reflection bound: either no reply, or a reply at most one AAAA
    /// record longer than the query, with at most one question, at most one
    /// answer, every answer an AAAA, and no authority or additional record.
    fn assert_bounded(query: &[u8], reply: Option<&[u8]>) {
        let Some(reply) = reply else { return };
        assert!(
            reply.len() <= query.len() + 28,
            "a {}-byte query drew a {}-byte reply, more than one AAAA record larger",
            query.len(),
            reply.len()
        );
        assert!(
            word(reply, 4) <= 1,
            "reply carries {} questions",
            word(reply, 4)
        );
        assert!(
            word(reply, 6) <= 1,
            "reply carries {} answers",
            word(reply, 6)
        );
        assert_eq!(word(reply, 8), 0, "reply carries authority records");
        assert_eq!(word(reply, 10), 0, "reply carries additional records");
        let packet = Packet::parse(reply).expect("the reply parses");
        for record in &packet.answers {
            assert!(
                matches!(record.rdata, RData::AAAA(_)),
                "reply carries a non-AAAA answer: {record:?}"
            );
        }
    }

    // --- reflection ---

    #[test]
    fn a_query_carrying_an_answer_record_draws_no_reply_that_echoes_it() {
        let hosts = HostMap::new();
        let clean = aaaa_query(0x1111, "example.com");
        assert!(
            answer(&clean, CLIENT_PORT, &hosts).is_some(),
            "control: the clean query is answered"
        );

        let mut forged = wire_name("evil.fips");
        forged.extend_from_slice(&TYPE_A.to_be_bytes());
        forged.extend_from_slice(&CLASS_IN.to_be_bytes());
        forged.extend_from_slice(&99_999u32.to_be_bytes());
        forged.extend_from_slice(&4u16.to_be_bytes());
        forged.extend_from_slice(&[1, 2, 3, 4]);
        let mut body = question(&wire_name("example.com"), TYPE_AAAA, CLASS_IN);
        body.extend_from_slice(&forged);
        let datagram = message(0x1112, 0, [1, 1, 0, 0], &body);

        let reply = answer(&datagram, CLIENT_PORT, &hosts);
        if let Some(reply) = &reply {
            assert!(
                !reply.windows(forged.len()).any(|w| w == forged.as_slice()),
                "the reply echoes the query's answer record"
            );
        }
        assert_bounded(&datagram, reply.as_deref());
    }

    #[test]
    fn a_511_byte_query_with_twelve_pointer_srv_records_draws_no_reply_over_the_query_plus_28() {
        let hosts = HostMap::new();
        let name = longest_name(b'a');
        let mut body = question(&name, TYPE_AAAA, CLASS_IN);
        for _ in 0..12 {
            body.extend_from_slice(&[0xC0, 0x0C]); // owner: the question name
            body.extend_from_slice(&33u16.to_be_bytes()); // SRV
            body.extend_from_slice(&CLASS_IN.to_be_bytes());
            body.extend_from_slice(&TTL.to_be_bytes());
            body.extend_from_slice(&8u16.to_be_bytes());
            body.extend_from_slice(&[0, 0, 0, 0, 0, 53]); // priority, weight, port
            body.extend_from_slice(&[0xC0, 0x0C]); // target: the question name
        }
        let datagram = message(0x2222, 0, [1, 12, 0, 0], &body);
        assert_eq!(datagram.len(), 511);

        let control = message(
            0x2223,
            0,
            [1, 0, 0, 0],
            &question(&name, TYPE_AAAA, CLASS_IN),
        );
        assert!(
            answer(&control, CLIENT_PORT, &hosts).is_some(),
            "control: the same name without records is answered"
        );
        assert_bounded(&datagram, answer(&datagram, CLIENT_PORT, &hosts).as_deref());
    }

    #[test]
    fn a_277_byte_two_question_query_draws_no_reply_over_the_query_plus_28() {
        let hosts = HostMap::new();
        let name = longest_name(0x01);
        let mut body = question(&name, TYPE_AAAA, CLASS_IN);
        // A second question whose name points at offset 13, inside the first
        // label's bytes, which decodes as a run of one-byte labels.
        body.extend_from_slice(&[0xC0, 0x0D, 0x00, 0x1C, 0x00, 0x01]);
        let datagram = message(0x3333, 0, [2, 0, 0, 0], &body);
        assert_eq!(datagram.len(), 277);

        let control = message(
            0x3334,
            0,
            [1, 0, 0, 0],
            &question(&name, TYPE_AAAA, CLASS_IN),
        );
        assert!(
            answer(&control, CLIENT_PORT, &hosts).is_some(),
            "control: the first question alone is answered"
        );
        assert_bounded(&datagram, answer(&datagram, CLIENT_PORT, &hosts).as_deref());
    }

    // --- loops ---

    #[test]
    fn a_reply_fed_back_in_gets_no_reply() {
        let hosts = HostMap::new();
        let reply = answer(&aaaa_query(0x4444, "unknown.fips"), CLIENT_PORT, &hosts)
            .expect("control: the query is answered");
        let echoed = answer(&reply, CLIENT_PORT, &hosts);
        assert!(
            echoed.is_none(),
            "the responder answered its own {}-byte reply with {:?} bytes",
            reply.len(),
            echoed.map(|r| r.len())
        );
    }

    #[test]
    fn a_well_formed_query_from_the_chargen_port_gets_no_reply() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        let datagram = aaaa_query(0x5555, &name);
        assert!(
            answer(&datagram, CLIENT_PORT, &hosts).is_some(),
            "control: the query from port {CLIENT_PORT} is answered"
        );
        assert!(
            answer(&datagram, 19, &hosts).is_none(),
            "the query from port 19 (chargen) was answered"
        );
    }

    #[test]
    fn a_daytime_text_datagram_gets_no_reply_from_port_13_or_an_ordinary_port() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        assert!(
            answer(&aaaa_query(0x5556, &name), CLIENT_PORT, &hosts).is_some(),
            "control: a query from port {CLIENT_PORT} is answered"
        );
        assert!(
            answer(DAYTIME, CLIENT_PORT, &hosts).is_none(),
            "daytime text from port {CLIENT_PORT} was answered"
        );
        assert!(
            answer(DAYTIME, 13, &hosts).is_none(),
            "daytime text from port 13 was answered"
        );
    }

    // --- header handling ---

    #[test]
    fn an_update_opcode_query_gets_a_header_only_notimp() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        let datagram = query(0x6666, 5 << 11, &name, TYPE_AAAA, CLASS_IN);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("an UPDATE gets a reply");
        assert_eq!(rcode(&reply), NOTIMP, "rcode");
        assert_eq!(word(&reply, 4), 0, "QDCOUNT of a header-only reply");
        assert_eq!(reply.len(), 12, "a header-only reply");
        assert_eq!((word(&reply, 2) >> 11) & 0x0F, 5, "opcode copied");
        assert_eq!(word(&reply, 0), 0x6666, "ID copied");
    }

    #[test]
    fn an_sshfp_query_for_an_npub_name_gets_nodata() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        let datagram = query(0x7777, 0, &name, TYPE_SSHFP, CLASS_IN);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("an SSHFP query gets a reply");
        assert_eq!(rcode(&reply), NOERROR, "rcode");
        assert_eq!(word(&reply, 6), 0, "no answers");
        assert_ne!(word(&reply, 2) & 0x0400, 0, "AA set");
        assert_eq!(
            &reply[12..],
            &datagram[12..],
            "the question, and nothing else"
        );
    }

    #[test]
    fn an_sshfp_query_for_an_unknown_name_gets_nxdomain() {
        let hosts = HostMap::new();
        let datagram = query(0x7778, 0, "unknown.fips", TYPE_SSHFP, CLASS_IN);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("an SSHFP query gets a reply");
        assert_eq!(rcode(&reply), NXDOMAIN, "rcode");
        assert_eq!(word(&reply, 6), 0, "no answers");
    }

    #[test]
    fn a_ch_class_aaaa_query_for_an_npub_gets_refused() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        let datagram = query(0x8888, 0, &name, TYPE_AAAA, CLASS_CH);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("a CH query gets a reply");
        assert_eq!(rcode(&reply), REFUSED, "rcode");
        assert_eq!(word(&reply, 4), 1, "the question is carried");
        assert_eq!(word(&reply, 6), 0, "no answers");
        assert_eq!(
            &reply[12..],
            &datagram[12..],
            "the question, and nothing else"
        );
    }

    #[test]
    fn an_rd_and_cd_query_gets_rd_and_cd_back() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        let datagram = query(0x9999, 0x0110, &name, TYPE_AAAA, CLASS_IN);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("the query is answered");
        assert_eq!(
            word(&reply, 2) & 0x0110,
            0x0110,
            "flags {:#06x}: RD and CD not both copied",
            word(&reply, 2)
        );
    }

    #[test]
    fn a_z_bit_query_is_answered_and_z_is_not_echoed() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        let datagram = query(0xAAAA, 0x0040, &name, TYPE_AAAA, CLASS_IN);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("a Z-bit query is answered");
        assert_eq!(word(&reply, 2) & 0x0040, 0, "Z echoed");
        assert_eq!(word(&reply, 6), 1, "one answer");
    }

    #[test]
    fn a_query_with_no_question_gets_a_header_only_formerr() {
        let hosts = HostMap::new();
        let datagram = message(0xBBBB, 0, [0, 0, 0, 0], &[]);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("a QDCOUNT 0 query gets a reply");
        assert_eq!(rcode(&reply), FORMERR, "rcode");
        assert_eq!(reply.len(), 12, "a header-only reply");
        assert_eq!(word(&reply, 0), 0xBBBB, "ID copied");
    }

    // --- healthy path ---

    #[test]
    fn an_aaaa_query_for_an_npub_gets_its_address_with_aa_in_a_reply_exactly_28_bytes_longer() {
        let hosts = HostMap::new();
        let (identity, name) = npub_name();
        let datagram = aaaa_query(0xCCCC, &name);
        let (reply, resolved) =
            handle_dns_packet(&datagram, CLIENT_PORT, TTL, &hosts).expect("the query is answered");
        assert_eq!(reply.len(), datagram.len() + 28, "reply length");
        assert_eq!(word(&reply, 0), 0xCCCC, "ID");
        assert_ne!(word(&reply, 2) & 0x0400, 0, "AA set");
        let packet = Packet::parse(&reply).expect("the reply parses");
        assert_eq!(packet.answers.len(), 1);
        match &packet.answers[0].rdata {
            RData::AAAA(aaaa) => {
                assert_eq!(Ipv6Addr::from(aaaa.address), identity.address().to_ipv6())
            }
            other => panic!("expected an AAAA answer, got {other:?}"),
        }
        assert_eq!(
            resolved.map(|r| r.node_addr),
            Some(*identity.node_addr()),
            "the identity is registered"
        );
    }

    #[test]
    fn an_aaaa_query_carrying_an_opt_record_is_answered_without_an_opt() {
        let hosts = HostMap::new();
        let (_, name) = npub_name();
        let datagram = padded_query(0xCCCD, &name, 439);
        let reply = answer(&datagram, CLIENT_PORT, &hosts).expect("the query is answered");
        assert_eq!(word(&reply, 6), 1, "one answer");
        assert_eq!(word(&reply, 10), 0, "ARCOUNT");
        assert_bounded(&datagram, Some(&reply));
    }

    #[test]
    fn a_and_https_queries_for_an_npub_and_a_hosts_alias_still_get_nodata() {
        let (identity, name) = npub_name();
        let mut hosts = HostMap::new();
        hosts.insert("gateway", &identity.npub()).unwrap();
        for qname in [name.as_str(), "gateway.fips"] {
            for qtype in [TYPE_A, TYPE_HTTPS] {
                let datagram = query(0xCCCE, 0, qname, qtype, CLASS_IN);
                let reply = answer(&datagram, CLIENT_PORT, &hosts)
                    .unwrap_or_else(|| panic!("type {qtype} for {qname} is answered"));
                assert_eq!(rcode(&reply), NOERROR, "type {qtype} for {qname}: rcode");
                assert_eq!(word(&reply, 6), 0, "type {qtype} for {qname}: no answers");
            }
        }
    }

    // --- through the receive loop ---

    /// A responder on `127.0.0.1:0` with an empty host map, and a client.
    async fn spawn_responder() -> (std::net::SocketAddr, UdpSocket, tokio::task::JoinHandle<()>) {
        let reloader = HostMapReloader::new(
            HostMap::new(),
            std::path::PathBuf::from("/nonexistent/hosts"),
        );
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let (identity_tx, identity_rx) = tokio::sync::mpsc::channel(16);
        let handle = tokio::spawn(async move {
            let _keep = identity_rx;
            run_dns_responder(server, identity_tx, TTL, reloader, None).await
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (addr, client, handle)
    }

    /// The next datagram the client receives, failing the test with `what`
    /// if none arrives within two seconds.
    async fn next_reply(client: &UdpSocket, what: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 65_536];
        let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("no reply within 2 s: expected {what}"))
            .expect("client receive");
        buf.truncate(len);
        buf
    }

    #[tokio::test]
    async fn a_600_byte_edns_padded_query_is_answered_over_udp() {
        let (server, client, handle) = spawn_responder().await;
        let (_, name) = npub_name();
        let padded = padded_query(0x6001, &name, 600);
        let control = aaaa_query(0x6002, &name);
        client.send_to(&padded, server).await.unwrap();
        client.send_to(&control, server).await.unwrap();

        let first = next_reply(&client, "the padded query's reply").await;
        assert_eq!(
            word(&first, 0),
            0x6001,
            "the first reply has ID {:#06x}; the padded query (0x6001) was not answered \
             before the control (0x6002)",
            word(&first, 0)
        );
        assert_eq!(word(&first, 6), 1, "the padded query gets its address");
        let second = next_reply(&client, "the control's reply").await;
        assert_eq!(word(&second, 0), 0x6002, "the control's reply follows");
        handle.abort();
    }

    #[tokio::test]
    async fn a_datagram_larger_than_the_receive_buffer_gets_no_reply() {
        let (server, client, handle) = spawn_responder().await;
        let (_, name) = npub_name();
        client
            .send_to(&aaaa_query(0x4201, &name), server)
            .await
            .unwrap();
        let first = next_reply(&client, "the first control's reply").await;
        assert_eq!(word(&first, 0), 0x4201, "control answered");

        client
            .send_to(&padded_query(0x4202, &name, 4200), server)
            .await
            .unwrap();
        client
            .send_to(&aaaa_query(0x4203, &name), server)
            .await
            .unwrap();
        let next = next_reply(&client, "the second control's reply").await;
        assert_eq!(
            word(&next, 0),
            0x4203,
            "the 4,200-byte datagram (0x4202) drew a reply before the second control (0x4203)"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn run_dns_responder_drops_a_response_and_answers_the_next_query() {
        let (server, client, handle) = spawn_responder().await;
        client
            .send_to(&aaaa_query(0x5001, "unknown.fips"), server)
            .await
            .unwrap();
        let mut reply = next_reply(&client, "the first control's reply").await;
        assert_eq!(word(&reply, 0), 0x5001, "control answered");

        reply[0..2].copy_from_slice(&0x5002u16.to_be_bytes());
        client.send_to(&reply, server).await.unwrap();
        client
            .send_to(&aaaa_query(0x5003, "unknown.fips"), server)
            .await
            .unwrap();
        let next = next_reply(&client, "the second control's reply").await;
        assert_eq!(
            word(&next, 0),
            0x5003,
            "the response (0x5002) drew a reply before the second control (0x5003)"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn run_dns_responder_answers_a_query_with_no_question_with_a_header_only_formerr() {
        let (server, client, handle) = spawn_responder().await;
        client
            .send_to(&aaaa_query(0x7001, "unknown.fips"), server)
            .await
            .unwrap();
        let first = next_reply(&client, "the first control's reply").await;
        assert_eq!(word(&first, 0), 0x7001, "control answered");

        client
            .send_to(&message(0x7002, 0, [0, 0, 0, 0], &[]), server)
            .await
            .unwrap();
        client
            .send_to(&aaaa_query(0x7003, "unknown.fips"), server)
            .await
            .unwrap();
        let formerr = next_reply(&client, "the FORMERR").await;
        assert_eq!(
            word(&formerr, 0),
            0x7002,
            "the next reply has ID {:#06x}, not the QDCOUNT 0 query's (0x7002)",
            word(&formerr, 0)
        );
        assert_eq!(rcode(&formerr), FORMERR, "rcode");
        assert_eq!(word(&formerr, 4), 0, "QDCOUNT");
        let last = next_reply(&client, "the second control's reply").await;
        assert_eq!(word(&last, 0), 0x7003, "the second control follows");
        handle.abort();
    }
}

/// The gateway's forwarder relaying through this responder, end to end over
/// loopback. Linux-only, like the gateway.
#[cfg(all(test, target_os = "linux"))]
mod interop_tests {
    use super::*;
    use crate::Identity;
    use crate::gateway::dns::handle_query;
    use crate::gateway::pool::{PoolEvent, VirtualIpPool};
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    /// The gateway's configured record TTL, in seconds.
    const TTL: u32 = 60;

    /// The big-endian `u16` at `offset`.
    fn word(bytes: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
    }

    /// An AAAA IN query for `name` with RD set.
    fn rd_query(id: u16, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.extend_from_slice(&[0, 0, 28, 0, 1]);
        out
    }

    /// The daemon's responder on `127.0.0.1:0`, with a hosts file mapping
    /// `gateway` to a fresh identity.
    async fn spawn_daemon() -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let identity = Identity::generate();
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        std::fs::write(&hosts_path, format!("gateway   {}\n", identity.npub())).unwrap();
        let reloader = HostMapReloader::new(HostMap::new(), hosts_path);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (identity_tx, identity_rx) = tokio::sync::mpsc::channel(16);
        let handle = tokio::spawn(async move {
            let _keep = identity_rx;
            run_dns_responder(socket, identity_tx, 300, reloader, None).await
        });
        (addr, handle, dir)
    }

    /// A fresh gateway address pool on `fd01::/112`.
    fn pool() -> Arc<tokio::sync::Mutex<VirtualIpPool>> {
        Arc::new(tokio::sync::Mutex::new(
            VirtualIpPool::new("fd01::/112", TTL as u64, 30).unwrap(),
        ))
    }

    #[tokio::test]
    async fn the_gateway_relays_a_mixed_case_query_through_the_real_daemon_and_maps_it() {
        let (daemon, handle, _dir) = spawn_daemon().await;
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let query = rd_query(0x5151, "GateWay.FIPS");
        let reply = handle_query(&query, 53000, daemon, TTL, &pool(), &event_tx)
            .await
            .expect("the gateway answers");
        assert_eq!(word(&reply, 2) & 0x000F, 0, "rcode");
        assert_eq!(word(&reply, 6), 1, "one answer");
        assert_eq!(
            &reply[12..query.len()],
            &query[12..],
            "the client's question, case and all"
        );
        let answer = &reply[reply.len() - 16..];
        assert_eq!(&answer[..2], &[0xfd, 0x01], "a pool address");
        assert!(
            matches!(event_rx.try_recv(), Ok(PoolEvent::MappingCreated { .. })),
            "one MappingCreated"
        );
        assert!(event_rx.try_recv().is_err(), "only one MappingCreated");
        handle.abort();
    }

    #[tokio::test]
    async fn the_gateway_copies_rd_and_adds_an_soa_to_a_relayed_nxdomain_through_the_real_daemon() {
        let (daemon, handle, _dir) = spawn_daemon().await;
        let (event_tx, _event_rx) = mpsc::channel(16);
        let pool = pool();

        let query = rd_query(0x5252, "GateWay.FIPS");
        let reply = handle_query(&query, 53000, daemon, TTL, &pool, &event_tx)
            .await
            .expect("the gateway answers");
        assert_eq!(
            word(&reply, 2) & 0x0180,
            0x0180,
            "flags {:#06x}: RD and RA not both set",
            word(&reply, 2)
        );

        let query = rd_query(0x5253, "nosuchname.fips");
        let reply = handle_query(&query, 53000, daemon, TTL, &pool, &event_tx)
            .await
            .expect("the gateway answers");
        assert_eq!(word(&reply, 2) & 0x000F, 3, "rcode NXDOMAIN");
        assert_eq!(word(&reply, 8), 1, "one authority record");
        let record = &reply[query.len()..];
        assert_eq!(word(record, 2), 6, "the authority record is an SOA");
        // "nosuchname.fips": the fips label starts 11 bytes into the name.
        assert_eq!(
            word(record, 0),
            0xC000 | (12 + 11),
            "owned by the fips label"
        );
        assert_eq!(reply.len(), query.len() + 51, "reply length");
        handle.abort();
    }
}
