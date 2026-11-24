use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::{UdpSocket, lookup_host};
use tracing::debug;

use super::machine::stun::candidates::{self, InterfaceAddr};
#[cfg(test)]
use super::machine::stun::client::pick_family;
use super::machine::stun::client::{Observation, Out};
#[cfg(test)]
pub(super) use super::machine::stun::parse_stun_binding_success;
pub(super) use super::machine::stun::parse_stun_url;
use super::types::{BootstrapError, TraversalAddress};
use crate::identity::OsEntropy;
use crate::time::HostInstant;

// Current STUN parsing is intentionally minimal and only supports
// MAPPED-ADDRESS / XOR-MAPPED-ADDRESS for IPv4 and IPv6.
// Local interface discovery remains best-effort and may still be incomplete
// on dual-stack, NAT64, or heavily firewalled hosts.

/// Default per-server STUN response wait used by the per-traversal flow.
/// Latency-sensitive: keep tight so a misbehaving STUN server doesn't
/// stretch every traversal attempt.
pub(super) const TRAVERSAL_STUN_TIMEOUT: Duration = Duration::from_secs(2);

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
    let local_addr = socket.local_addr()?;
    let local_port = local_addr.port();
    let local_addresses = if share_local_candidates {
        offerable(local_addresses_from_port(local_port), local_addr.is_ipv4())
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
/// The exchange is the machine's STUN client (`machine/stun/client.rs`) for
/// this one server; this drives it on `socket` and the host's clocks. Only a
/// datagram whose source is exactly the resolved server address is parsed;
/// anything else is consumed and discarded, so an on-path attacker who has
/// seen the transaction id cannot substitute a mapped address by injecting a
/// reply. The comparison is exact because every socket handed to this
/// function is bound to the IPv4 wildcard, so a source can never arrive in
/// v4-mapped IPv6 form.
///
/// The request is retransmitted, with the same transaction id, from 500 ms
/// and doubling until the deadline, so one lost datagram does not lose the
/// server (RFC 8489 Section 6.2.1). It goes to the first resolved address of
/// the socket's family; a server with none is skipped. A first send that
/// fails fails the server at once; a failed retransmission leaves the
/// earlier sends in flight.
///
/// Caller requirement: this drains and discards every datagram arriving on
/// `socket` until the deadline, so it must not be entered on a socket that
/// may concurrently carry other traffic the caller cares about.
async fn perform_stun(
    socket: &std::net::UdpSocket,
    stun_server: &str,
    response_timeout: Duration,
) -> Result<Option<SocketAddr>, BootstrapError> {
    // The URL's own error, as the client would give it for this server.
    parse_stun_url(stun_server)?;
    let want_v4 = socket.local_addr()?.is_ipv4();
    let udp = UdpSocket::from_std(socket.try_clone()?)?;
    let mut client: Observation<HostInstant, OsEntropy> =
        Observation::new(vec![stun_server.to_string()], response_timeout, want_v4);
    // What a failure the client reports means: before the request is out,
    // no address of the socket's family; after, no answer in time.
    let mut sent = false;
    let failure = |sent: bool| {
        BootstrapError::Stun(if sent {
            format!("timed out waiting for {stun_server}")
        } else {
            format!("no address for {stun_server}")
        })
    };
    let mut pending: VecDeque<Out> = client.begin(mono()).into();
    let mut buf = [0u8; 2048];
    loop {
        while let Some(out) = pending.pop_front() {
            match out {
                Out::Resolve { host, port } => {
                    let addrs: Vec<SocketAddr> =
                        lookup_host((host.as_str(), port)).await?.collect();
                    pending.extend(client.resolved(addrs, mono()));
                }
                Out::Send { dst, bytes } => {
                    sent = true;
                    if let Err(e) = udp.send_to(&bytes, dst).await {
                        let out = client.send_failed(dst, e.to_string(), mono());
                        if out.iter().any(|o| matches!(o, Out::Failed { .. })) {
                            return Err(e.into());
                        }
                        pending.extend(out);
                    }
                }
                Out::Succeeded { mapped, .. } => return Ok(Some(mapped)),
                Out::Discarded {
                    server,
                    expected,
                    rejected,
                    last_unexpected,
                } => {
                    // One line per call rather than per datagram: a flooder
                    // controls the rate.
                    debug!(
                        stun_server = %server,
                        expected = %expected,
                        rejected,
                        last_unexpected = ?last_unexpected,
                        "discarded STUN datagrams from unexpected sources"
                    );
                }
                Out::Failed { .. } => return Err(failure(sent)),
            }
        }
        let Some(wake) = client.deadline() else {
            return Err(failure(sent));
        };
        let wake = tokio::time::Instant::from_std(wake.into());
        match tokio::time::timeout_at(wake, udp.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => pending.extend(client.datagram(src, &buf[..len], mono())),
            Ok(Err(_)) => pending.extend(client.recv_error(mono())),
            Err(_) => pending.extend(client.timeout(mono())),
        }
    }
}

/// The monotonic reading the STUN client's deadlines are on: tokio's clock,
/// as the pump reads it.
fn mono() -> HostInstant {
    HostInstant::from(tokio::time::Instant::now().into_std())
}

/// The local candidate addresses to offer for a socket: those of its family.
/// The socket's port is offered on each, and no peer can reach an address of
/// the other family on it.
fn offerable(addresses: Vec<String>, socket_v4: bool) -> Vec<String> {
    addresses
        .into_iter()
        .filter(|ip| {
            ip.parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_ipv4() == socket_v4)
        })
        .collect()
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

#[cfg(test)]
#[path = "tests/stun.rs"]
mod tests;
