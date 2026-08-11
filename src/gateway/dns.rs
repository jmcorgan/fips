//! Gateway DNS resolver.
//!
//! Forwarding proxy that handles `.fips` queries from LAN hosts,
//! forwards them to the FIPS daemon resolver (localhost:5354),
//! and returns virtual IP addresses from the pool.
//!
//! The daemon resolver populates its identity cache as a side effect
//! of resolution, which is required for fips0 routing to work.

use simple_dns::{CLASS, Packet, PacketFlag, RCODE, ResourceRecord, rdata};

use simple_dns::{QCLASS, QTYPE, TYPE};
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
/// Returns None unless the address carries the FIPS prefix.
fn node_addr_from_mesh(mesh_addr: Ipv6Addr) -> Option<NodeAddr> {
    // FipsAddress = [0xfd, node_addr[0..15]], so node_addr[0..15] = bytes[1..16].
    let bytes = *crate::identity::FipsAddress::from_bytes(mesh_addr.octets())
        .ok()?
        .as_bytes();
    let mut node_bytes = [0u8; 16];
    node_bytes[..15].copy_from_slice(&bytes[1..16]);
    Some(NodeAddr::from_bytes(node_bytes))
}

/// Check that an upstream datagram answers the query we actually sent.
///
/// Guards against off-path forgery: the transaction ID and question must
/// match, and the packet must be a response. Names are compared
/// case-insensitively because DNS names are case-insensitive on the wire
/// while `simple_dns` compares label bytes exactly.
fn upstream_response_matches(
    response: &Packet,
    upstream_id: u16,
    upstream_qname: &str,
    upstream_qclass: QCLASS,
) -> bool {
    if !response.has_flags(PacketFlag::RESPONSE) || response.id() != upstream_id {
        return false;
    }
    if response.questions.len() != 1 {
        return false;
    }
    let question = &response.questions[0];
    question.qtype == QTYPE::TYPE(TYPE::AAAA)
        && question.qclass == upstream_qclass
        && question.qname.to_string().to_ascii_lowercase() == upstream_qname
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
    // The upstream transaction ID is drawn fresh so that an off-path forger
    // cannot guess it from the client's query. Client-facing responses keep
    // the client's own ID.
    let upstream_id: u16 = rand::random();
    let question = query.questions.first()?;
    let upstream_qname = question.qname.to_string().to_ascii_lowercase();
    let upstream_qclass = question.qclass;

    let upstream_query_bytes = {
        let mut aaaa_query = Packet::new_query(upstream_id);
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

    // Connect the socket so the kernel drops datagrams from any source other
    // than the configured upstream.
    if let Err(e) = upstream_socket.connect(upstream).await {
        warn!(error = %e, upstream = %upstream, "Failed to connect upstream socket");
        return build_servfail(&query);
    }

    if let Err(e) = upstream_socket.send(&upstream_query_bytes).await {
        warn!(error = %e, "Failed to forward query to daemon");
        return build_servfail(&query);
    }

    // Keep reading until a datagram matches the query we sent, or the deadline
    // passes. Datagrams that do not match are discarded rather than accepted.
    let deadline = tokio::time::Instant::now() + UPSTREAM_TIMEOUT;
    let mut resp_buf = vec![0u8; MAX_DNS_SIZE];
    let upstream_response_bytes = loop {
        let resp_len =
            match tokio::time::timeout_at(deadline, upstream_socket.recv(&mut resp_buf)).await {
                Ok(Ok(len)) => len,
                Ok(Err(e)) => {
                    warn!(error = %e, upstream = %upstream, "Upstream recv error");
                    return build_servfail(&query);
                }
                Err(_) => {
                    warn!(upstream = %upstream, "Upstream DNS timeout");
                    return build_servfail(&query);
                }
            };

        match Packet::parse(&resp_buf[..resp_len]) {
            Ok(p) => {
                if upstream_response_matches(&p, upstream_id, &upstream_qname, upstream_qclass) {
                    break resp_buf[..resp_len].to_vec();
                }
                debug!(name = %fips_name, "Discarding unsolicited upstream datagram");
            }
            Err(_) => {
                debug!(name = %fips_name, "Discarding unparseable upstream datagram");
            }
        }
    };

    let upstream_response = match Packet::parse(&upstream_response_bytes) {
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

    // Derive NodeAddr from mesh address. An answer outside fd00::/8 is not a
    // mesh address and must never reach the NAT mapping path.
    let node_addr = match node_addr_from_mesh(mesh_addr) {
        Some(addr) => addr,
        None => {
            warn!(
                name = %fips_name,
                mesh_addr = %mesh_addr,
                "Upstream AAAA is not a FIPS mesh address, rejecting"
            );
            return build_servfail(&query);
        }
    };

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

    use simple_dns::{Name, Question};
    use tokio::sync::mpsc;

    const TEST_TTL: u32 = 60;

    /// Build a client-facing AAAA query.
    fn build_query(id: u16, qname: &str) -> Vec<u8> {
        let mut packet = Packet::new_query(id);
        let question = Question::new(
            Name::new_unchecked(qname),
            QTYPE::TYPE(TYPE::AAAA),
            CLASS::IN.into(),
            false,
        );
        packet.questions.push(question);
        packet.build_bytes_vec_compressed().unwrap()
    }

    /// Build an upstream NOERROR AAAA answer.
    fn build_answer(id: u16, qname: &str, addr: &str) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);
        let name = Name::new_unchecked(qname);
        packet.questions.push(Question::new(
            name.clone(),
            QTYPE::TYPE(TYPE::AAAA),
            CLASS::IN.into(),
            false,
        ));
        let address: Ipv6Addr = addr.parse().unwrap();
        packet.answers.push(ResourceRecord::new(
            name,
            CLASS::IN,
            TEST_TTL,
            rdata::RData::AAAA(rdata::AAAA {
                address: address.into(),
            }),
        ));
        packet.build_bytes_vec_compressed().unwrap()
    }

    /// A fake upstream that answers one query with a scripted list of
    /// datagrams, in order, from its own socket.
    fn spawn_upstream<F>(socket: UdpSocket, replies: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(u16) -> Vec<Vec<u8>> + Send + 'static,
    {
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_SIZE];
            let (len, src) = socket.recv_from(&mut buf).await.unwrap();
            let observed_id = Packet::parse(&buf[..len]).unwrap().id();
            for reply in replies(observed_id) {
                socket.send_to(&reply, src).await.unwrap();
            }
        })
    }

    fn test_pool() -> std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>> {
        std::sync::Arc::new(tokio::sync::Mutex::new(
            VirtualIpPool::new("fd01::/112", TEST_TTL as u64, 30).unwrap(),
        ))
    }

    /// Assert the response is an AAAA answer whose address came from the pool.
    fn assert_pool_answer(response: &[u8]) -> Ipv6Addr {
        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.rcode(), RCODE::NoError);
        let addr = extract_aaaa(&packet).expect("expected an AAAA answer");
        assert!(
            addr.octets()[0] == 0xfd && addr.octets()[1] == 0x01,
            "expected a pool virtual IP, got {addr}"
        );
        addr
    }

    #[test]
    fn test_node_addr_from_mesh() {
        // fd00::1 → node_addr bytes should be [0, 0, ..., 0, 1] in positions 0..15
        let mesh: Ipv6Addr = "fd00::1".parse().unwrap();
        let node = node_addr_from_mesh(mesh).unwrap();
        let bytes = node.as_bytes();
        // mesh = [0xfd, 0, 0, ..., 0, 1]
        // node = bytes[1..16] of mesh = [0, 0, ..., 0, 1] in first 15 bytes
        assert_eq!(bytes[14], 1);
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn test_node_addr_from_mesh_rejects_non_mesh() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(node_addr_from_mesh(addr).is_none());
    }

    #[tokio::test]
    async fn test_foreign_source_answer_not_accepted() {
        let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let foreign = UdpSocket::bind("[::1]:0").await.unwrap();

        // The fake upstream learns the gateway's ephemeral port from the query
        // it receives, has a third socket forge an answer to that port, then
        // sends the genuine answer itself.
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_SIZE];
            let (len, src) = upstream_socket.recv_from(&mut buf).await.unwrap();
            let observed_id = Packet::parse(&buf[..len]).unwrap().id();
            let forged = build_answer(observed_id, "test.fips", "2001:db8::1");
            foreign.send_to(&forged, src).await.unwrap();
            let genuine = build_answer(observed_id, "test.fips", "fd00::1");
            upstream_socket.send_to(&genuine, src).await.unwrap();
        });

        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let response = handle_query(
            &build_query(0x1234, "test.fips"),
            upstream,
            TEST_TTL,
            &pool,
            &event_tx,
        )
        .await
        .unwrap();
        handle.await.unwrap();

        assert_pool_answer(&response);
        match event_rx.try_recv().unwrap() {
            PoolEvent::MappingCreated { mesh_addr, .. } => {
                assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
            }
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn test_upstream_id_mismatch_discarded() {
        let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let handle = spawn_upstream(upstream_socket, |id| {
            vec![
                build_answer(id.wrapping_add(1), "test.fips", "2001:db8::1"),
                build_answer(id, "test.fips", "fd00::1"),
            ]
        });

        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let response = handle_query(
            &build_query(0x1234, "test.fips"),
            upstream,
            TEST_TTL,
            &pool,
            &event_tx,
        )
        .await
        .unwrap();
        handle.await.unwrap();

        assert_pool_answer(&response);
        match event_rx.try_recv().unwrap() {
            PoolEvent::MappingCreated { mesh_addr, .. } => {
                assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_upstream_question_mismatch_discarded() {
        let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let handle = spawn_upstream(upstream_socket, |id| {
            vec![
                build_answer(id, "other.fips", "2001:db8::1"),
                build_answer(id, "test.fips", "fd00::1"),
            ]
        });

        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let response = handle_query(
            &build_query(0x1234, "test.fips"),
            upstream,
            TEST_TTL,
            &pool,
            &event_tx,
        )
        .await
        .unwrap();
        handle.await.unwrap();

        assert_pool_answer(&response);
        match event_rx.try_recv().unwrap() {
            PoolEvent::MappingCreated { mesh_addr, .. } => {
                assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_non_mesh_aaaa_rejected() {
        let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let handle = spawn_upstream(upstream_socket, |id| {
            vec![build_answer(id, "test.fips", "2001:db8::1")]
        });

        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let response = handle_query(
            &build_query(0x1234, "test.fips"),
            upstream,
            TEST_TTL,
            &pool,
            &event_tx,
        )
        .await
        .unwrap();
        handle.await.unwrap();

        let packet = Packet::parse(&response).unwrap();
        assert_eq!(packet.rcode(), RCODE::ServerFailure);
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn test_healthy_path_resolves() {
        let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let handle = spawn_upstream(upstream_socket, |id| {
            vec![build_answer(id, "test.fips", "fd00::1")]
        });

        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let response = handle_query(
            &build_query(0x1234, "test.fips"),
            upstream,
            TEST_TTL,
            &pool,
            &event_tx,
        )
        .await
        .unwrap();
        handle.await.unwrap();

        assert_pool_answer(&response);
        match event_rx.try_recv().unwrap() {
            PoolEvent::MappingCreated { mesh_addr, .. } => {
                assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
            }
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
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
