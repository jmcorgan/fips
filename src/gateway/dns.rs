//! Gateway DNS resolver.
//!
//! Forwarding proxy that handles `.fips` queries from LAN hosts,
//! forwards them to the FIPS daemon resolver (localhost:5354),
//! and returns virtual IP addresses from the pool.
//!
//! The daemon resolver populates its identity cache as a side effect
//! of resolution, which is required for fips0 routing to work.

use simple_dns::{CLASS, Packet, PacketFlag, RCODE, ResourceRecord, rdata};

use simple_dns::{QTYPE, TYPE};
use std::net::{Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};

use super::pool::{PoolEvent, VirtualIpPool};
use crate::NodeAddr;

/// Timeout for upstream DNS queries.
const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum DNS packet size.
const MAX_DNS_SIZE: usize = 4096;

/// Events emitted by the DNS resolver.
#[derive(Debug)]
pub struct DnsAllocation {
    pub node_addr: NodeAddr,
    pub virtual_ip: Ipv6Addr,
    pub mesh_addr: Ipv6Addr,
    pub is_new: bool,
}

/// Extract the `.fips` query name from a DNS packet.
/// Returns Some(name) if the query is for a `.fips` domain, None otherwise.
fn extract_fips_name(packet: &Packet) -> Option<String> {
    let question = packet.questions.first()?;
    let name = question.qname.to_string();
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".fips") || lower.ends_with(".fips.") {
        Some(lower.trim_end_matches('.').to_string())
    } else {
        None
    }
}

/// Extract the AAAA (IPv6) address from a DNS response.
fn extract_aaaa(packet: &Packet) -> Option<Ipv6Addr> {
    for answer in &packet.answers {
        if let rdata::RData::AAAA(aaaa) = &answer.rdata {
            return Some(aaaa.address.into());
        }
    }
    None
}

/// Derive NodeAddr from a FIPS mesh address (fd00::/8).
/// The NodeAddr is bytes 1-15 of the IPv6 address prepended with the first byte.
fn node_addr_from_mesh(mesh_addr: Ipv6Addr) -> NodeAddr {
    let bytes = mesh_addr.octets();
    // NodeAddr = first 16 bytes of SHA-256(pubkey), which maps to
    // FipsAddress = fd + NodeAddr[1..16]. So NodeAddr[0] = bytes[1].
    // Actually, FipsAddress = [0xfd, nodeaddr[0..15]]
    // So nodeaddr[0..15] = bytes[1..16]
    let mut node_bytes = [0u8; 16];
    node_bytes[..15].copy_from_slice(&bytes[1..16]);
    NodeAddr::from_bytes(node_bytes)
}

/// Build a REFUSED DNS response.
fn build_refused(query: &Packet) -> Option<Vec<u8>> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);
    *response.rcode_mut() = RCODE::Refused;
    response.questions.clone_from(&query.questions);
    response.build_bytes_vec_compressed().ok()
}

/// Build a SERVFAIL DNS response.
fn build_servfail(query: &Packet) -> Option<Vec<u8>> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);
    *response.rcode_mut() = RCODE::ServerFailure;
    response.questions.clone_from(&query.questions);
    response.build_bytes_vec_compressed().ok()
}

/// Build a NODATA response (NOERROR with no answer records).
/// Signals "this name exists but has no records of the requested type".
fn build_nodata(query: &Packet, ttl: u32) -> Option<Vec<u8>> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);
    response.questions.clone_from(&query.questions);

    // Add a minimal SOA in the authority section (RFC 2308 §2.2).
    // This tells the client how long to cache the negative answer.
    let question = query.questions.first()?;
    let soa = rdata::RData::SOA(rdata::SOA {
        mname: simple_dns::Name::new_unchecked("gateway.fips"),
        rname: simple_dns::Name::new_unchecked("nobody.fips"),
        serial: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1),
        refresh: ttl as i32,
        retry: ttl as i32,
        expire: ttl as i32,
        minimum: ttl,
    });
    let soa_record = ResourceRecord::new(question.qname.clone(), CLASS::IN, ttl, soa);
    response.name_servers.push(soa_record);

    response.build_bytes_vec_compressed().ok()
}

/// Build an AAAA response with the given virtual IP.
fn build_aaaa_response(query: &Packet, virtual_ip: Ipv6Addr, ttl: u32) -> Option<Vec<u8>> {
    let question = query.questions.first()?;
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);

    // Echo the question section (required by RFC 1035 §4.1.1)
    response.questions.push(question.clone());

    let aaaa = rdata::RData::AAAA(rdata::AAAA {
        address: virtual_ip.into(),
    });
    let record = ResourceRecord::new(question.qname.clone(), CLASS::IN, ttl, aaaa);
    response.answers.push(record);

    response.build_bytes_vec_compressed().ok()
}

/// Run the gateway DNS resolver.
///
/// Listens for DNS queries, forwards `.fips` queries to the upstream
/// daemon resolver, allocates virtual IPs, and returns them to clients.
pub async fn run_dns_resolver(
    listen_addr: &str,
    upstream_addr: &str,
    ttl: u32,
    pool: std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
    event_tx: tokio::sync::mpsc::Sender<PoolEvent>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind(listen_addr).await?;
    info!(addr = %listen_addr, "Gateway DNS resolver listening");

    let upstream: SocketAddr = upstream_addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let mut buf = vec![0u8; MAX_DNS_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                let (len, client_addr) = result?;
                let query_bytes = &buf[..len];

                let response = match handle_query(
                    query_bytes,
                    upstream,
                    ttl,
                    &pool,
                    &event_tx,
                ).await {
                    Some(resp) => resp,
                    None => continue,
                };

                if let Err(e) = socket.send_to(&response, client_addr).await {
                    debug!(error = %e, "Failed to send DNS response");
                }
            }
            _ = shutdown.changed() => {
                info!("DNS resolver shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single DNS query. Returns the response bytes to send back.
async fn handle_query(
    query_bytes: &[u8],
    upstream: SocketAddr,
    ttl: u32,
    pool: &std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
    event_tx: &tokio::sync::mpsc::Sender<PoolEvent>,
) -> Option<Vec<u8>> {
    let query = Packet::parse(query_bytes).ok()?;

    // Check if this is a .fips query
    let fips_name = match extract_fips_name(&query) {
        Some(name) => name,
        None => {
            trace!(id = query.id(), "Non-.fips query, returning REFUSED");
            return build_refused(&query);
        }
    };

    debug!(name = %fips_name, id = query.id(), "Forwarding .fips query to daemon");

    // Build an AAAA query for the daemon regardless of what the client asked
    // (A, AAAA, ANY, etc.).  Mesh addresses are always IPv6, so the daemon
    // only returns useful answers for AAAA queries.
    let upstream_query_bytes = {
        let question = query.questions.first()?;
        let mut aaaa_query = Packet::new_query(query.id());
        let aaaa_question = simple_dns::Question::new(
            question.qname.clone(),
            QTYPE::TYPE(TYPE::AAAA),
            question.qclass,
            question.unicast_response,
        );
        aaaa_query.questions.push(aaaa_question);
        match aaaa_query.build_bytes_vec_compressed() {
            Ok(bytes) => bytes,
            Err(_) => return build_servfail(&query),
        }
    };

    // Forward to upstream daemon resolver.
    // Bind to the same address family as the upstream to avoid dual-stack issues
    // (OpenWrt often has net.ipv6.bindv6only=1).
    let bind_addr = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let upstream_socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "Failed to bind upstream socket");
            return build_servfail(&query);
        }
    };

    if let Err(e) = upstream_socket
        .send_to(&upstream_query_bytes, upstream)
        .await
    {
        warn!(error = %e, "Failed to forward query to daemon");
        return build_servfail(&query);
    }

    let mut resp_buf = vec![0u8; MAX_DNS_SIZE];
    let resp_len =
        match tokio::time::timeout(UPSTREAM_TIMEOUT, upstream_socket.recv(&mut resp_buf)).await {
            Ok(Ok(len)) => len,
            Ok(Err(e)) => {
                warn!(error = %e, "Upstream recv error");
                return build_servfail(&query);
            }
            Err(_) => {
                warn!("Upstream DNS timeout");
                return build_servfail(&query);
            }
        };

    let upstream_response = match Packet::parse(&resp_buf[..resp_len]) {
        Ok(p) => p,
        Err(_) => return build_servfail(&query),
    };

    // If upstream returned NXDOMAIN or error, rebuild the response with the
    // client's original question section (not the AAAA question we sent upstream).
    if upstream_response.rcode() != RCODE::NoError {
        debug!(
            name = %fips_name,
            rcode = ?upstream_response.rcode(),
            "Upstream returned non-success"
        );
        let mut err_resp = Packet::new_reply(query.id());
        err_resp.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);
        *err_resp.rcode_mut() = upstream_response.rcode();
        err_resp.questions.clone_from(&query.questions);
        return err_resp.build_bytes_vec_compressed().ok();
    }

    // Extract the fd00:: mesh address from the AAAA response
    let mesh_addr = match extract_aaaa(&upstream_response) {
        Some(addr) => addr,
        None => {
            debug!(name = %fips_name, "No AAAA record in upstream response");
            return build_servfail(&query);
        }
    };

    // Derive NodeAddr from mesh address
    let node_addr = node_addr_from_mesh(mesh_addr);

    // Allocate virtual IP from pool
    let mut pool_guard = pool.lock().await;
    let (virtual_ip, is_new) = match pool_guard.allocate(node_addr, mesh_addr, &fips_name) {
        Ok(result) => result,
        Err(e) => {
            warn!(error = %e, "Pool allocation failed");
            return build_servfail(&query);
        }
    };
    drop(pool_guard);

    // Notify NAT module of new mapping
    if is_new {
        let event = PoolEvent::MappingCreated {
            virtual_ip,
            mesh_addr,
        };
        if let Err(e) = event_tx.send(event).await {
            warn!(error = %e, "Failed to send pool event");
        }
    }

    debug!(
        name = %fips_name,
        virtual_ip = %virtual_ip,
        mesh_addr = %mesh_addr,
        is_new,
        "Resolved .fips query"
    );

    // Check what the client originally asked for.
    // Only return an AAAA record if the client asked for AAAA (or ANY).
    // For A queries, return an empty NOERROR — the client's resolver will
    // use the AAAA answer from its parallel AAAA query instead.
    let client_qtype = query
        .questions
        .first()
        .map(|q| q.qtype)
        .unwrap_or(QTYPE::TYPE(TYPE::AAAA));

    match client_qtype {
        QTYPE::TYPE(TYPE::AAAA) | QTYPE::ANY => build_aaaa_response(&query, virtual_ip, ttl),
        // All other types (A, HTTPS, etc.): return NODATA — the name exists
        // but has no records of the requested type.
        _ => build_nodata(&query, ttl),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_addr_from_mesh() {
        // fd00::1 → node_addr bytes should be [0, 0, ..., 0, 1] in positions 0..15
        let mesh: Ipv6Addr = "fd00::1".parse().unwrap();
        let node = node_addr_from_mesh(mesh);
        let bytes = node.as_bytes();
        // mesh = [0xfd, 0, 0, ..., 0, 1]
        // node = bytes[1..16] of mesh = [0, 0, ..., 0, 1] in first 15 bytes
        assert_eq!(bytes[14], 1);
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn test_extract_fips_name() {
        // Build a simple AAAA query for test.fips
        let mut packet = Packet::new_query(1);
        use simple_dns::{Name, Question};
        let name = Name::new_unchecked("test.fips");
        let question = Question::new(name, QTYPE::TYPE(TYPE::AAAA), CLASS::IN.into(), false);
        packet.questions.push(question);

        let result = extract_fips_name(&packet);
        assert_eq!(result, Some("test.fips".to_string()));
    }

    #[test]
    fn test_extract_non_fips_name() {
        let mut packet = Packet::new_query(1);
        use simple_dns::{Name, Question};
        let name = Name::new_unchecked("example.com");
        let question = Question::new(name, QTYPE::TYPE(TYPE::AAAA), CLASS::IN.into(), false);
        packet.questions.push(question);

        assert!(extract_fips_name(&packet).is_none());
    }

    #[test]
    fn test_build_aaaa_response() {
        let mut query = Packet::new_query(42);
        use simple_dns::{Name, Question};
        let name = Name::new_unchecked("test.fips");
        let question = Question::new(name, QTYPE::TYPE(TYPE::AAAA), CLASS::IN.into(), false);
        query.questions.push(question);

        let vip: Ipv6Addr = "fd01::1".parse().unwrap();
        let response_bytes = build_aaaa_response(&query, vip, 60).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.id(), 42);
        assert_eq!(response.answers.len(), 1);
        if let rdata::RData::AAAA(aaaa) = &response.answers[0].rdata {
            assert_eq!(Ipv6Addr::from(aaaa.address), vip);
        } else {
            panic!("Expected AAAA record");
        }
    }
}
