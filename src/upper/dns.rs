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

use crate::upper::hosts::{HostMap, HostMapReloader};
use crate::{NodeAddr, PeerIdentity};
use simple_dns::rdata::{AAAA, RData};
use simple_dns::{CLASS, Name, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, TYPE};
use std::net::Ipv6Addr;
use tracing::{debug, trace, warn};

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

/// Handle a raw DNS query packet and produce a response.
///
/// Returns the response bytes and an optional resolved identity (for AAAA queries
/// that successfully resolved a `.fips` name). The host map is consulted first
/// for hostname resolution before falling back to direct npub resolution.
pub fn handle_dns_packet(
    query_bytes: &[u8],
    ttl: u32,
    hosts: &HostMap,
) -> Option<(Vec<u8>, Option<DnsResolvedIdentity>)> {
    let query = Packet::parse(query_bytes).ok()?;
    let question = query.questions.first()?;

    let qname = question.qname.to_string();
    let is_aaaa = matches!(question.qtype, QTYPE::TYPE(TYPE::AAAA));

    let mut response = query.into_reply();
    response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

    if is_aaaa && let Some((ipv6, node_addr, pubkey)) = resolve_fips_query_with_hosts(&qname, hosts)
    {
        let name = Name::new_unchecked(&qname).into_owned();
        let record = ResourceRecord::new(name, CLASS::IN, ttl, RData::AAAA(AAAA::from(ipv6)));
        response.answers.push(record);

        let identity = DnsResolvedIdentity { node_addr, pubkey };
        let bytes = response.build_bytes_vec_compressed().ok()?;
        return Some((bytes, Some(identity)));
    }

    // Non-AAAA query (e.g. A) for a resolvable .fips name: return NOERROR
    // with empty answers.  NXDOMAIN would tell the client the name doesn't
    // exist, causing resolvers like nslookup to give up without trying AAAA.
    if !is_aaaa && resolve_fips_query_with_hosts(&qname, hosts).is_some() {
        let bytes = response.build_bytes_vec_compressed().ok()?;
        return Some((bytes, None));
    }

    // Unresolvable name: NXDOMAIN
    *response.rcode_mut() = RCODE::NameError;
    let bytes = response.build_bytes_vec_compressed().ok()?;
    Some((bytes, None))
}

/// Decide whether a received DNS query should be dropped as mesh-originated.
///
/// A query is dropped iff we have a configured mesh interface index
/// (`mesh_ifindex`) and the packet arrived on that interface
/// (`arrival_ifindex`). Queries arriving on any other interface — loopback,
/// LAN, or unknown (no PKTINFO cmsg) — are not dropped.
///
/// The arrival-interface check is robust regardless of source address. LAN
/// segments using RFC 4193 ULA prefixes (`fd00::/8`, common with OpenWrt
/// `odhcpd` and NetworkManager ULA auto-generation) would collide with the
/// FIPS mesh prefix under a source-prefix filter; this filter is immune.
fn is_mesh_interface_query(arrival_ifindex: Option<u32>, mesh_ifindex: Option<u32>) -> bool {
    match (arrival_ifindex, mesh_ifindex) {
        (Some(arrival), Some(mesh)) => arrival == mesh,
        _ => false,
    }
}

/// Run the DNS responder UDP server loop.
///
/// Listens for DNS queries, resolves `.fips` names, and sends resolved
/// identities to the Node via the identity channel. The host map reloader
/// checks the hosts file modification time on each request and reloads
/// automatically when changes are detected.
///
/// When `mesh_ifindex` is `Some`, queries arriving on that interface are
/// dropped silently. This closes the fips0-exposure side-channel created
/// by the `::` bind: mesh peers can reach the listener over fips0 and
/// probe `/etc/fips/hosts` aliases via dictionary attack. The check
/// requires `IPV6_RECVPKTINFO` to be enabled on the socket (done in
/// `Node::bind_dns_socket`); if it is not, arrival ifindex is unknown
/// and no filter is applied.
pub async fn run_dns_responder(
    socket: tokio::net::UdpSocket,
    identity_tx: DnsIdentityTx,
    ttl: u32,
    mut reloader: HostMapReloader,
    mesh_ifindex: Option<u32>,
) {
    let mut buf = [0u8; 512]; // Standard DNS UDP max

    loop {
        let (len, src, arrival_ifindex) = match recv_with_pktinfo(&socket, &mut buf).await {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "DNS socket recv error");
                continue;
            }
        };

        if is_mesh_interface_query(arrival_ifindex, mesh_ifindex) {
            trace!(
                src = %src,
                ifindex = ?arrival_ifindex,
                "DNS query arrived on mesh interface, dropping"
            );
            continue;
        }

        let query_bytes = &buf[..len];

        // Check for hosts file changes on each request (cheap stat call)
        reloader.check_reload();

        match handle_dns_packet(query_bytes, ttl, reloader.hosts()) {
            Some((response_bytes, identity)) => {
                if let Some(id) = identity {
                    debug!(
                        node_addr = %id.node_addr,
                        "DNS resolved .fips name, registering identity"
                    );
                    let _ = identity_tx.send(id).await;
                }

                if let Err(e) = socket.send_to(&response_bytes, src).await {
                    debug!(error = %e, "DNS send error");
                }
            }
            None => {
                debug!(len, "Failed to parse DNS query, dropping");
            }
        }
    }
}

/// Receive a UDP datagram with arrival-interface info via `IPV6_PKTINFO`.
///
/// Returns `(len, src, arrival_ifindex)`. The ifindex is `Some` when the
/// kernel delivered an `IPV6_PKTINFO` control message; `None` otherwise
/// (IPv4 arrival on a dual-stack socket without `IP_PKTINFO` set, or
/// `IPV6_RECVPKTINFO` not enabled). A `None` ifindex disables filtering
/// for that packet — fail-open on unknown arrival.
#[cfg(unix)]
async fn recv_with_pktinfo(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Option<u32>)> {
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
async fn recv_with_pktinfo(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Option<u32>)> {
    let (len, src) = socket.recv_from(buf).await?;
    Ok((len, src, None))
}

/// Blocking `recvmsg` wrapper that extracts `IPV6_PKTINFO` ifindex.
///
/// Returns `Err(WouldBlock)` when the socket has no data (caller should
/// await readability again).
#[cfg(unix)]
fn recvmsg_with_pktinfo(
    fd: std::os::fd::RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Option<u32>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };

    let mut src_store: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    // 128 bytes is ample: IPV6_PKTINFO cmsg is ~36 bytes aligned.
    let mut cmsg_buf = [0u8; 128];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_store as *mut _ as *mut _;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
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
    let ifindex = extract_pktinfo_ifindex(&msg);

    Ok((n, src, ifindex))
}

/// Walk the cmsg chain and return the `IPV6_PKTINFO` ifindex, if present.
#[cfg(unix)]
fn extract_pktinfo_ifindex(msg: &libc::msghdr) -> Option<u32> {
    let mut cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg_ptr.is_null() {
        let cmsg = unsafe { &*cmsg_ptr };
        if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_PKTINFO {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg_ptr) } as *const libc::in6_pktinfo;
            let pktinfo: libc::in6_pktinfo = unsafe { std::ptr::read_unaligned(data_ptr) };
            return Some(pktinfo.ipi6_ifindex);
        }
        cmsg_ptr = unsafe { libc::CMSG_NXTHDR(msg, cmsg_ptr) };
    }
    None
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
mod tests {
    use super::*;
    use crate::Identity;

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

        let result = handle_dns_packet(&query_packet, 300, &hosts);
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

        let result = handle_dns_packet(&query_packet, 300, &hosts);
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

        let result = handle_dns_packet(&query_packet, 300, &hosts);
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

        let result = handle_dns_packet(&query_packet, 300, &hosts);
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
        let addr: std::net::SocketAddr = "[::1]:0".parse().unwrap();
        sock.bind(&addr.into()).unwrap();
        tokio::net::UdpSocket::from_std(sock.into()).unwrap()
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
        let (len, src, ifindex) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            recv_with_pktinfo(&server, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(&buf[..len], b"hello");
        assert!(src.ip().is_loopback(), "source should be loopback");
        assert_eq!(
            ifindex,
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

    /// Build a test DNS query packet for a given name and record type.
    fn build_test_query(name: &str, rtype: TYPE) -> Vec<u8> {
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
}
