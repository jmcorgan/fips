use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::{UdpSocket, lookup_host};
use tracing::debug;

use super::machine::stun::candidates::{self, InterfaceAddr};
use super::machine::stun::create_stun_binding_request;
pub(super) use super::machine::stun::{parse_stun_binding_success, parse_stun_url};
use super::types::{BootstrapError, TraversalAddress};

// Current STUN parsing is intentionally minimal and only supports
// MAPPED-ADDRESS / XOR-MAPPED-ADDRESS for IPv4 and IPv6.
// Local interface discovery remains best-effort and may still be incomplete
// on dual-stack, NAT64, or heavily firewalled hosts.

/// Default per-server STUN response wait used by the per-traversal flow.
/// Latency-sensitive: keep tight so a misbehaving STUN server doesn't
/// stretch every traversal attempt.
pub(super) const TRAVERSAL_STUN_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-server STUN response wait used by the advert-publish path's
/// public-IP discovery. Longer than `TRAVERSAL_STUN_TIMEOUT` because
/// it's a one-shot at startup (cached afterward) and we'd rather block
/// the first advert build by a few seconds than skip UDP advertising
/// over a slow first response. Returns immediately on success.
pub(super) const ADVERT_STUN_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn observe_traversal_addresses(
    socket: &std::net::UdpSocket,
    stun_servers: &[String],
    share_local_candidates: bool,
    per_server_timeout: Duration,
) -> Result<
    (
        Option<TraversalAddress>,
        Vec<TraversalAddress>,
        Option<String>,
    ),
    BootstrapError,
> {
    let local_port = socket.local_addr()?.port();
    let local_addresses = if share_local_candidates {
        local_addresses_from_port(local_port)
            .into_iter()
            .map(|ip| TraversalAddress {
                protocol: "udp".to_string(),
                ip,
                port: local_port,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut last_error = None;
    for stun_server in stun_servers {
        match perform_stun(socket, stun_server, per_server_timeout).await {
            Ok(mapped) => {
                debug!(
                    stun_server = %stun_server,
                    reflexive = ?mapped,
                    "STUN observation succeeded"
                );
                return Ok((
                    mapped.map(|addr| TraversalAddress {
                        protocol: "udp".to_string(),
                        ip: addr.ip().to_string(),
                        port: addr.port(),
                    }),
                    local_addresses.clone(),
                    Some(stun_server.clone()),
                ));
            }
            Err(err) => last_error = Some(err),
        }
    }

    if let Some(err) = last_error {
        debug!(error = %err, "stun observation failed, falling back to LAN-only addresses");
    }

    Ok((None, local_addresses, None))
}

/// Send a STUN binding request on `socket` and return the reflexive address
/// the server reports.
///
/// Only a datagram whose source is exactly the resolved server address is
/// parsed; anything else is consumed and discarded, so an on-path attacker
/// who has seen the transaction id cannot substitute a mapped address by
/// injecting a reply. The comparison is exact because every socket handed to
/// this function is bound to the IPv4 wildcard, so a source can never arrive
/// in v4-mapped IPv6 form. A dual-stack bind would require normalising both
/// sides with `IpAddr::to_canonical()` before comparing.
///
/// Caller requirement: this drains and discards every datagram arriving on
/// `socket` until the deadline, so it must not be entered on a socket that
/// may concurrently carry other traffic the caller cares about.
async fn perform_stun(
    socket: &std::net::UdpSocket,
    stun_server: &str,
    response_timeout: Duration,
) -> Result<Option<SocketAddr>, BootstrapError> {
    let endpoint = parse_stun_url(stun_server)?;
    let txn_id = random_txn_id();
    let request = create_stun_binding_request(txn_id);
    let addr = resolve_udp_target(&endpoint.host, endpoint.port)
        .await?
        .ok_or_else(|| BootstrapError::Stun(format!("no address for {}", stun_server)))?;
    let udp = UdpSocket::from_std(socket.try_clone()?)?;
    udp.send_to(&request, addr).await?;
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + response_timeout;
    let mut rejected = 0u64;
    let mut last_unexpected = None;
    loop {
        let result = tokio::time::timeout_at(deadline, udp.recv_from(&mut buf)).await;
        let Ok(Ok((len, remote))) = result else {
            break;
        };
        if remote != addr {
            rejected += 1;
            last_unexpected = Some(remote);
            continue;
        }
        if let Some(mapped) = parse_stun_binding_success(&buf[..len], &txn_id) {
            return Ok(Some(mapped));
        }
    }
    // One line per call rather than per datagram: a flooder controls the rate.
    if rejected > 0 {
        debug!(
            stun_server = %stun_server,
            expected = %addr,
            rejected,
            last_unexpected = ?last_unexpected,
            "discarded STUN datagrams from unexpected sources"
        );
    }
    Err(BootstrapError::Stun(format!(
        "timed out waiting for {}",
        stun_server
    )))
}

async fn resolve_udp_target(host: &str, port: u16) -> Result<Option<SocketAddr>, BootstrapError> {
    let normalized_host = host
        .strip_prefix('[')
        .and_then(|trimmed| trimmed.strip_suffix(']'))
        .unwrap_or(host);

    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        return Ok(Some(SocketAddr::new(ip, port)));
    }
    let mut results = lookup_host((normalized_host, port)).await?;
    Ok(results.next())
}

fn local_addresses_from_port(port: u16) -> Vec<String> {
    let mut observed = Vec::new();
    for (bind_addr, connect_addr) in candidates::PROBES {
        observed.push(local_probe(bind_addr, connect_addr));
    }
    for host in candidates::WILDCARDS {
        observed.push(bound_addr((host, port)));
    }
    candidates::local_candidates(&interface_addrs(), &observed)
}

/// Every IPv4 and IPv6 address in the host's interface list, in listing
/// order, with its interface's up and loopback flags.
#[cfg(unix)]
fn interface_addrs() -> Vec<InterfaceAddr> {
    let mut output = Vec::new();
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: `getifaddrs` initializes `ifaddrs` on success, and the linked
    // list is valid until `freeifaddrs` is called.
    let rc = unsafe { libc::getifaddrs(&mut ifaddrs) };
    if rc != 0 || ifaddrs.is_null() {
        return output;
    }

    let mut cursor = ifaddrs;
    while !cursor.is_null() {
        // SAFETY: `cursor` points at a valid node from the `getifaddrs` list.
        let entry = unsafe { &*cursor };
        let flags = entry.ifa_flags as i32;

        if !entry.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is non-null and its concrete type matches
            // `sa_family` for this entry.
            let maybe_ip = unsafe {
                match (*entry.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sockaddr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        Some(IpAddr::V4(std::net::Ipv4Addr::from(
                            sockaddr.sin_addr.s_addr.to_ne_bytes(),
                        )))
                    }
                    libc::AF_INET6 => {
                        let sockaddr = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        Some(IpAddr::V6(std::net::Ipv6Addr::from(
                            sockaddr.sin6_addr.s6_addr,
                        )))
                    }
                    _ => None,
                }
            };

            if let Some(ip) = maybe_ip {
                output.push(InterfaceAddr {
                    ip,
                    up: (flags & libc::IFF_UP) != 0,
                    loopback: (flags & libc::IFF_LOOPBACK) != 0,
                });
            }
        }

        cursor = entry.ifa_next;
    }

    // SAFETY: `ifaddrs` came from `getifaddrs` and has not yet been freed.
    unsafe { libc::freeifaddrs(ifaddrs) };
    output
}

#[cfg(not(unix))]
fn interface_addrs() -> Vec<InterfaceAddr> {
    Vec::new()
}

/// The local address the host picks for a UDP socket bound to `bind_addr`
/// and connected to `connect_addr`, if both steps succeed.
fn local_probe(bind_addr: &str, connect_addr: &str) -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind(bind_addr).ok()?;
    socket.connect(connect_addr).ok()?;
    socket.local_addr().ok().map(|local_addr| local_addr.ip())
}

/// The local address of a UDP socket bound to `bind_addr`, if the bind
/// succeeds.
fn bound_addr<A: std::net::ToSocketAddrs>(bind_addr: A) -> Option<IpAddr> {
    std::net::UdpSocket::bind(bind_addr)
        .and_then(|socket| socket.local_addr())
        .ok()
        .map(|local_addr| local_addr.ip())
}

fn random_txn_id() -> [u8; 12] {
    let mut txn_id = [0u8; 12];
    for byte in &mut txn_id {
        *byte = rand::random::<u8>();
    }
    txn_id
}

#[cfg(test)]
#[path = "tests/stun.rs"]
mod tests;
