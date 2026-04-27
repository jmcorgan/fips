use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{UdpSocket, lookup_host};
use tracing::debug;

use super::types::{BootstrapError, TraversalAddress};

// Current STUN parsing is intentionally minimal and only supports
// MAPPED-ADDRESS / XOR-MAPPED-ADDRESS for IPv4 and IPv6.
// Local interface discovery remains best-effort and may still be incomplete
// on dual-stack, NAT64, or heavily firewalled hosts.

pub(super) async fn observe_traversal_addresses(
    socket: &std::net::UdpSocket,
    stun_servers: &[String],
    share_local_candidates: bool,
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
        match perform_stun(socket, stun_server).await {
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

async fn perform_stun(
    socket: &std::net::UdpSocket,
    stun_server: &str,
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let result = tokio::time::timeout_at(deadline, udp.recv_from(&mut buf)).await;
        let Ok(Ok((len, _remote))) = result else {
            break;
        };
        if let Some(mapped) = parse_stun_binding_success(&buf[..len], &txn_id) {
            return Ok(Some(mapped));
        }
    }
    Err(BootstrapError::Stun(format!(
        "timed out waiting for {}",
        stun_server
    )))
}

pub(super) fn parse_stun_url(input: &str) -> Result<StunEndpoint, BootstrapError> {
    let raw = input.strip_prefix("stun:").unwrap_or(input);
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(BootstrapError::Stun(format!("invalid STUN URL: {}", input)));
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| BootstrapError::Stun(format!("invalid STUN URL: {}", input)))?;
    if host.is_empty() {
        return Err(BootstrapError::Stun(format!("invalid STUN URL: {}", input)));
    }
    Ok(StunEndpoint {
        host: host.to_string(),
        port,
    })
}

pub(super) struct StunEndpoint {
    pub(super) host: String,
    pub(super) port: u16,
}

fn create_stun_binding_request(txn_id: [u8; 12]) -> [u8; 20] {
    const STUN_BINDING_REQUEST: u16 = 0x0001;
    const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
    let mut packet = [0u8; 20];
    packet[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    packet[2..4].copy_from_slice(&0u16.to_be_bytes());
    packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    packet[8..20].copy_from_slice(&txn_id);
    packet
}

pub(super) fn parse_stun_binding_success(packet: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    const STUN_BINDING_SUCCESS: u16 = 0x0101;
    const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
    const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
    const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

    if packet.len() < 20 {
        return None;
    }
    if u16::from_be_bytes(packet[..2].try_into().ok()?) != STUN_BINDING_SUCCESS {
        return None;
    }
    if u32::from_be_bytes(packet[4..8].try_into().ok()?) != STUN_MAGIC_COOKIE {
        return None;
    }
    if &packet[8..20] != txn_id {
        return None;
    }

    let message_length = u16::from_be_bytes(packet[2..4].try_into().ok()?) as usize;
    let mut offset = 20usize;
    let max_offset = packet.len().min(20 + message_length);
    while offset + 4 <= max_offset {
        let attr_type = u16::from_be_bytes(packet[offset..offset + 2].try_into().ok()?);
        let attr_len = u16::from_be_bytes(packet[offset + 2..offset + 4].try_into().ok()?) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > packet.len() {
            break;
        }
        let value = &packet[value_start..value_end];
        let parsed = match attr_type {
            STUN_ATTR_XOR_MAPPED_ADDRESS => parse_xor_mapped_address(value, txn_id),
            STUN_ATTR_MAPPED_ADDRESS => parse_mapped_address(value),
            _ => None,
        };
        if parsed.is_some() {
            return parsed;
        }
        offset = value_end + ((4 - (attr_len % 4)) % 4);
    }
    None
}

fn parse_mapped_address(value: &[u8]) -> Option<SocketAddr> {
    match value.get(1).copied()? {
        0x01 if value.len() >= 8 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7])),
            u16::from_be_bytes([value[2], value[3]]),
        )),
        0x02 if value.len() >= 20 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&value[4..20]).ok()?);
            Some(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be_bytes([value[2], value[3]]),
            ))
        }
        _ => None,
    }
}

fn parse_xor_mapped_address(value: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
    let xored_port = u16::from_be_bytes([value.get(2).copied()?, value.get(3).copied()?])
        ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();

    match value.get(1).copied()? {
        0x01 if value.len() >= 8 => {
            let ip = Ipv4Addr::new(
                value[4] ^ cookie[0],
                value[5] ^ cookie[1],
                value[6] ^ cookie[2],
                value[7] ^ cookie[3],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), xored_port))
        }
        0x02 if value.len() >= 20 => {
            let mut ip = [0u8; 16];
            for (index, byte) in ip.iter_mut().enumerate() {
                let mask = if index < 4 {
                    cookie[index]
                } else {
                    txn_id[index - 4]
                };
                *byte = value[4 + index] ^ mask;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), xored_port))
        }
        _ => None,
    }
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
    let mut addresses = Vec::new();
    push_private_interface_ips(&mut addresses);
    push_local_probe(&mut addresses, "0.0.0.0:0", "8.8.8.8:80");
    push_local_probe(&mut addresses, "[::]:0", "[2001:4860:4860::8888]:80");
    push_bound_addr(&mut addresses, ("0.0.0.0", port));
    push_bound_addr(&mut addresses, ("::", port));
    addresses
}

fn push_private_interface_ips(addresses: &mut Vec<String>) {
    for ip in private_interface_ips() {
        push_ip(addresses, ip);
    }
}

#[cfg(unix)]
fn private_interface_ips() -> Vec<IpAddr> {
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
        let is_up = (flags & libc::IFF_UP) != 0;
        let is_loopback = (flags & libc::IFF_LOOPBACK) != 0;

        if is_up && !is_loopback && !entry.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is non-null and its concrete type matches
            // `sa_family` for this entry.
            let maybe_ip = unsafe {
                match (*entry.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sockaddr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        Some(IpAddr::V4(Ipv4Addr::from(
                            sockaddr.sin_addr.s_addr.to_ne_bytes(),
                        )))
                    }
                    libc::AF_INET6 => {
                        let sockaddr = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        Some(IpAddr::V6(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr)))
                    }
                    _ => None,
                }
            };

            if let Some(ip) = maybe_ip
                && is_private_overlay_candidate_ip(ip)
            {
                output.push(ip);
            }
        }

        cursor = entry.ifa_next;
    }

    // SAFETY: `ifaddrs` came from `getifaddrs` and has not yet been freed.
    unsafe { libc::freeifaddrs(ifaddrs) };
    output
}

#[cfg(not(unix))]
fn private_interface_ips() -> Vec<IpAddr> {
    Vec::new()
}

fn is_private_overlay_candidate_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

fn push_local_probe(addresses: &mut Vec<String>, bind_addr: &str, connect_addr: &str) {
    if let Ok(socket) = std::net::UdpSocket::bind(bind_addr)
        && socket.connect(connect_addr).is_ok()
        && let Ok(local_addr) = socket.local_addr()
    {
        push_ip(addresses, local_addr.ip());
    }
}

fn push_bound_addr<A: std::net::ToSocketAddrs>(addresses: &mut Vec<String>, bind_addr: A) {
    if let Ok(local_addr) =
        std::net::UdpSocket::bind(bind_addr).and_then(|socket| socket.local_addr())
    {
        push_ip(addresses, local_addr.ip());
    }
}

fn push_ip(addresses: &mut Vec<String>, ip: IpAddr) {
    if ip.is_unspecified() {
        return;
    }
    let ip = ip.to_string();
    if !addresses.contains(&ip) {
        addresses.push(ip);
    }
}

fn random_txn_id() -> [u8; 12] {
    let mut txn_id = [0u8; 12];
    for byte in &mut txn_id {
        *byte = rand::random::<u8>();
    }
    txn_id
}

#[cfg(test)]
mod tests {
    use super::is_private_overlay_candidate_ip;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn private_overlay_candidate_filter_includes_rfc1918_and_ula() {
        assert!(is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 10
        ))));
        assert!(is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 4
        ))));
        assert!(is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
            172, 16, 5, 20
        ))));
        assert!(is_private_overlay_candidate_ip(IpAddr::V6(
            "fd00::1234".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[test]
    fn private_overlay_candidate_filter_excludes_public_and_link_local() {
        assert!(!is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 10
        ))));
        assert!(!is_private_overlay_candidate_ip(IpAddr::V6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_private_overlay_candidate_ip(IpAddr::V6(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        )));
    }
}
