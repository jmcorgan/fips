//! Gateway DNS resolver.
//!
//! Forwarding proxy that handles `.fips` queries from LAN hosts,
//! forwards them to the FIPS daemon resolver (localhost:5354),
//! and returns virtual IP addresses from the pool.
//!
//! The daemon resolver populates its identity cache as a side effect
//! of resolution, which is required for fips0 routing to work.

use simple_dns::{CLASS, Packet, PacketFlag, rdata};

use simple_dns::{QCLASS, QTYPE, TYPE};
use std::net::{Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};

use super::pool::{PoolEvent, VirtualIpPool};
use crate::NodeAddr;
use crate::config::GatewayDnsConfig;
use crate::dnsmsg::{
    self, CLASS_IN, Outcome, Query, RA, Rcode, Record, Screen, TYPE_AAAA, TYPE_ANY,
};

/// Timeout for upstream DNS queries.
const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Events emitted by the DNS resolver.
#[derive(Debug)]
pub struct DnsAllocation {
    pub node_addr: NodeAddr,
    pub virtual_ip: Ipv6Addr,
    pub mesh_addr: Ipv6Addr,
    pub is_new: bool,
}

/// Extract the `.fips` query name from a question name in text form.
/// Returns Some(name) if the query is for a `.fips` domain, None otherwise.
fn extract_fips_name(name: &str) -> Option<String> {
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
fn build_refused(query: &Query<'_>) -> Vec<u8> {
    dnsmsg::reply(query, Rcode::REFUSED, RA, &[], &[])
}

/// Build a SERVFAIL DNS response.
fn build_servfail(query: &Query<'_>) -> Vec<u8> {
    dnsmsg::reply(query, Rcode::SERVFAIL, RA, &[], &[])
}

/// Build a NODATA response (NOERROR with no answer records).
/// Signals "this name exists but has no records of the requested type".
fn build_nodata(query: &Query<'_>, ttl: u32) -> Vec<u8> {
    dnsmsg::reply(query, Rcode::NOERROR, RA, &[], &[negative_soa(query, ttl)])
}

/// Relay an upstream error. An NXDOMAIN carries the same SOA as NODATA, so
/// the client can cache it (RFC 2308 Section 5); any other error carries the
/// question only, since caching a failure would outlast it.
fn build_relayed(query: &Query<'_>, rcode: Rcode, ttl: u32) -> Vec<u8> {
    if rcode == Rcode::NXDOMAIN {
        dnsmsg::reply(query, rcode, RA, &[], &[negative_soa(query, ttl)])
    } else {
        dnsmsg::reply(query, rcode, RA, &[], &[])
    }
}

/// The SOA for a negative answer (RFC 2308 Section 2.2), which tells the
/// client how long to cache it.
fn negative_soa(query: &Query<'_>, ttl: u32) -> Record {
    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1);
    dnsmsg::soa(query, "fips", "gateway.fips", "nobody.fips", serial, ttl)
}

/// Build an AAAA response with the given virtual IP.
fn build_aaaa_response(query: &Query<'_>, virtual_ip: Ipv6Addr, ttl: u32) -> Vec<u8> {
    let records = [dnsmsg::aaaa(virtual_ip, ttl)];
    dnsmsg::reply(query, Rcode::NOERROR, RA, &records, &[])
}

/// The gateway DNS listener could not be bound.
///
/// The message names the listen address and, when the port is already in
/// use, the service most likely to hold it and how to find the holder.
#[derive(Debug, thiserror::Error)]
#[error("cannot bind the gateway DNS listener on {listen}: {source}{}", in_use_hint(.listen, .source))]
pub struct ListenError {
    listen: String,
    source: std::io::Error,
}

impl ListenError {
    /// The kind of the underlying bind error.
    pub fn kind(&self) -> std::io::ErrorKind {
        self.source.kind()
    }
}

/// The suffix `ListenError`'s message carries for an address-in-use error:
/// the likely holder of the port, and how to find the actual one.
fn in_use_hint(listen: &str, source: &std::io::Error) -> String {
    if source.kind() != std::io::ErrorKind::AddrInUse {
        return String::new();
    }
    let (holder, port) = match GatewayDnsConfig::port_of(listen) {
        Some(port) => (holder_hint(port), port.to_string()),
        None => (holder_hint(0), "<port>".to_string()),
    };
    format!(
        "; {holder}; find the holder with `ss -ulpn 'sport = :{port}'` or `netstat -ulnp`, \
         or set gateway.dns.listen to a free port and point the resolver that forwards .fips at it"
    )
}

/// The service most likely to hold a DNS listen port that is already in use.
pub(crate) fn holder_hint(port: u16) -> &'static str {
    match port {
        53 => {
            "another DNS server holds port 53: dnsmasq, systemd-resolved's stub listener, unbound or BIND"
        }
        5353 => {
            "port 5353 is mDNS: the fips daemon's LAN rendezvous (node.rendezvous.lan), \
             avahi-daemon or systemd-resolved's MulticastDNS may hold it"
        }
        5354 => {
            "the fips daemon's own DNS responder listens on 5354 by default; \
             gateway.dns.listen must not be the daemon's DNS port"
        }
        5355 => "port 5355 is LLMNR, held by systemd-resolved unless LLMNR=no",
        5365 => "another fips-gateway may already be running",
        _ => "another process holds it",
    }
}

/// Bind the gateway DNS listener.
///
/// Called before the gateway creates anything it would have to tear down, so
/// a port that is already taken stops the gateway before it starts.
pub async fn bind_listener(listen: &str) -> Result<UdpSocket, ListenError> {
    UdpSocket::bind(listen).await.map_err(|source| ListenError {
        listen: listen.to_string(),
        source,
    })
}

/// Run the gateway DNS resolver.
///
/// Binds `listen_addr`, then serves as [`serve`] does. The gateway binary
/// binds and serves separately so that a bind failure stops it at startup.
pub async fn run_dns_resolver(
    listen_addr: &str,
    upstream_addr: &str,
    ttl: u32,
    pool: std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
    event_tx: tokio::sync::mpsc::Sender<PoolEvent>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let socket = bind_listener(listen_addr)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), e))?;
    info!(addr = %listen_addr, "Gateway DNS resolver listening");

    let upstream: SocketAddr = upstream_addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    serve(socket, upstream, ttl, pool, event_tx, shutdown).await
}

/// Serve DNS queries on a bound listener until shutdown.
///
/// Forwards `.fips` queries to the upstream daemon resolver, allocates
/// virtual IPs, and returns them to clients. Returns `Ok` on shutdown and
/// `Err` when receiving from the listener fails.
pub async fn serve(
    socket: UdpSocket,
    upstream: SocketAddr,
    ttl: u32,
    pool: std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
    event_tx: tokio::sync::mpsc::Sender<PoolEvent>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                let (len, client_addr) = result?;
                let query_bytes = &buf[..len];

                let outcome = respond(
                    query_bytes,
                    client_addr.port(),
                    upstream,
                    ttl,
                    &pool,
                    &event_tx,
                ).await;
                let response = match outcome {
                    Outcome::Drop(reason) => {
                        debug!(src = %client_addr, len, reason = reason.as_str(), "DNS datagram dropped");
                        continue;
                    }
                    Outcome::Refuse(rcode, bytes) => {
                        debug!(src = %client_addr, len, rcode = %rcode, "DNS query refused");
                        bytes
                    }
                    Outcome::Answer(bytes) => bytes,
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

/// Handle a single DNS datagram from `src_port`. Returns the response bytes
/// to send back, or `None` when the datagram gets no reply.
#[cfg(test)]
pub(crate) async fn handle_query(
    query_bytes: &[u8],
    src_port: u16,
    upstream: SocketAddr,
    ttl: u32,
    pool: &std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
    event_tx: &tokio::sync::mpsc::Sender<PoolEvent>,
) -> Option<Vec<u8>> {
    match respond(query_bytes, src_port, upstream, ttl, pool, event_tx).await {
        Outcome::Drop(_) => None,
        Outcome::Refuse(_, bytes) | Outcome::Answer(bytes) => Some(bytes),
    }
}

/// Screen a datagram and, if it is a query, resolve it.
///
/// The one dispatch both [`serve`] and the tests run.
async fn respond(
    datagram: &[u8],
    src_port: u16,
    upstream: SocketAddr,
    ttl: u32,
    pool: &std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
    event_tx: &tokio::sync::mpsc::Sender<PoolEvent>,
) -> Outcome<Vec<u8>> {
    match dnsmsg::screen(datagram, src_port) {
        Screen::Drop(reason) => Outcome::Drop(reason),
        Screen::Reply(rcode, bytes) => Outcome::Refuse(rcode, bytes),
        Screen::Query(query) => {
            Outcome::Answer(resolve_query(query, upstream, ttl, pool, event_tx).await)
        }
    }
}

/// Resolve a screened query. Returns the response bytes to send back.
async fn resolve_query(
    query: Query<'_>,
    upstream: SocketAddr,
    ttl: u32,
    pool: &std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
    event_tx: &tokio::sync::mpsc::Sender<PoolEvent>,
) -> Vec<u8> {
    // Check if this is a .fips query
    let fips_name = match extract_fips_name(&query.name) {
        Some(name) => name,
        None => {
            trace!(id = query.id, "Non-.fips query, returning REFUSED");
            return build_refused(&query);
        }
    };

    debug!(name = %fips_name, id = query.id, "Forwarding .fips query to daemon");

    // Build an AAAA query for the daemon regardless of what the client asked
    // (A, AAAA, ANY, etc.).  Mesh addresses are always IPv6, so the daemon
    // only returns useful answers for AAAA queries.
    // The upstream transaction ID is drawn fresh so that an off-path forger
    // cannot guess it from the client's query. Client-facing responses keep
    // the client's own ID.
    let upstream_id: u16 = rand::random();
    let upstream_qname = query.name.to_ascii_lowercase();
    let upstream_qclass = QCLASS::CLASS(CLASS::IN);
    let upstream_query_bytes =
        dnsmsg::encode_query(upstream_id, query.qname_wire(), TYPE_AAAA, CLASS_IN);

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
            debug!(error = %e, "Failed to bind upstream socket");
            return build_servfail(&query);
        }
    };

    // Connect the socket so the kernel drops datagrams from any source other
    // than the configured upstream.
    if let Err(e) = upstream_socket.connect(upstream).await {
        debug!(error = %e, upstream = %upstream, "Failed to connect upstream socket");
        return build_servfail(&query);
    }

    if let Err(e) = upstream_socket.send(&upstream_query_bytes).await {
        debug!(error = %e, "Failed to forward query to daemon");
        return build_servfail(&query);
    }

    // Keep reading until a datagram matches the query we sent, or the deadline
    // passes. Datagrams that do not match are discarded rather than accepted.
    let deadline = tokio::time::Instant::now() + UPSTREAM_TIMEOUT;
    let mut resp_buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
    let upstream_response_bytes = loop {
        let resp_len =
            match tokio::time::timeout_at(deadline, upstream_socket.recv(&mut resp_buf)).await {
                Ok(Ok(len)) => len,
                Ok(Err(e)) => {
                    debug!(error = %e, upstream = %upstream, "Upstream recv error");
                    return build_servfail(&query);
                }
                Err(_) => {
                    debug!(upstream = %upstream, "Upstream DNS timeout");
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

    // If upstream returned NXDOMAIN or error, relay it with the client's
    // original question (not the AAAA question we sent upstream). The rcode
    // is read from the raw header: simple-dns maps header codes 11 to 15 to
    // values whose low bits read as other codes.
    let rcode = Rcode::from_header(upstream_response_bytes[3]);
    if rcode != Rcode::NOERROR {
        debug!(name = %fips_name, rcode = %rcode, "Upstream returned non-success");
        return build_relayed(&query, rcode, ttl);
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
            debug!(
                name = %fips_name,
                mesh_addr = %mesh_addr,
                "Upstream AAAA is not a FIPS mesh address, rejecting"
            );
            return build_servfail(&query);
        }
    };

    // What the client actually asked for. Only AAAA and ANY are answered with
    // an address, and only those may mint a mapping: allocating for a query
    // type the gateway answers with NODATA let any LAN host take a pool
    // address per name without ever being given one.
    let client_qtype = query.qtype;

    if client_qtype != TYPE_AAAA && client_qtype != TYPE_ANY {
        // The client is still using the name, so an existing mapping's TTL
        // clock is refreshed if the mapping has carried traffic: a client
        // that re-queries a mapped name with both A and AAAA should not lose
        // half of its refresh. A name nobody has used expires TTL plus grace
        // after it was created however often it is queried. Nothing is
        // created.
        let refreshed = pool.lock().await.refresh_if_present(node_addr);
        debug!(
            name = %fips_name,
            mesh_addr = %mesh_addr,
            refreshed,
            "Non-AAAA .fips query, returning NODATA"
        );
        return build_nodata(&query, ttl);
    }

    // Allocate virtual IP from pool
    let mut pool_guard = pool.lock().await;
    let allocation = match pool_guard.allocate(node_addr, mesh_addr, &fips_name) {
        Ok(allocation) => allocation,
        Err(e) => {
            // Per query and driven by LAN hosts, so not a warning: the pool
            // warns once when it starts refusing at a bound.
            debug!(reason = e.reason(), error = %e, name = %fips_name, "Pool allocation failed");
            return build_servfail(&query);
        }
    };
    drop(pool_guard);
    let virtual_ip = allocation.virtual_ip;
    let is_new = allocation.is_new;

    // A mapping replaced at the ceiling loses its rules before the new one
    // gains its own.
    if let Some(evicted) = allocation.evicted {
        let event = PoolEvent::MappingRemoved {
            virtual_ip: evicted.virtual_ip,
            mesh_addr: evicted.mesh_addr,
        };
        if let Err(e) = event_tx.send(event).await {
            warn!(error = %e, "Failed to send pool event");
        }
    }

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
        ttl = allocation.ttl,
        "Resolved .fips query"
    );

    build_aaaa_response(&query, virtual_ip, allocation.ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::gateway::pool::ConntrackSnapshot;
    use simple_dns::{Name, Question, RCODE, ResourceRecord};
    use tokio::sync::mpsc;

    const TEST_TTL: u32 = 60;

    /// Build a client-facing AAAA query.
    fn build_query(id: u16, qname: &str) -> Vec<u8> {
        build_query_of_type(id, qname, QTYPE::TYPE(TYPE::AAAA))
    }

    /// Build a client-facing query of any type.
    fn build_query_of_type(id: u16, qname: &str, qtype: QTYPE) -> Vec<u8> {
        let mut packet = Packet::new_query(id);
        let question = Question::new(Name::new_unchecked(qname), qtype, CLASS::IN.into(), false);
        packet.questions.push(question);
        packet.build_bytes_vec_compressed().unwrap()
    }

    /// Assert the response is NODATA: NOERROR with no answer records.
    fn assert_nodata(response: &[u8]) {
        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.rcode(), RCODE::NoError);
        assert!(
            packet.answers.is_empty(),
            "expected NODATA, got {} answer(s)",
            packet.answers.len()
        );
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
            let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
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
            let mut buf = vec![0u8; dnsmsg::MAX_DATAGRAM];
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
            53000,
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
            53000,
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
            53000,
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
            53000,
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
    async fn an_a_query_returns_nodata_and_mints_no_mapping() {
        let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let handle = spawn_upstream(upstream_socket, |id| {
            vec![build_answer(id, "test.fips", "fd00::1")]
        });

        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let response = handle_query(
            &build_query_of_type(0x1234, "test.fips", QTYPE::TYPE(TYPE::A)),
            53000,
            upstream,
            TEST_TTL,
            &pool,
            &event_tx,
        )
        .await
        .unwrap();
        handle.await.unwrap();

        assert_nodata(&response);
        assert!(
            matches!(event_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "an A query minted a mapping, so any LAN host can take a pool \
             address per name with a query type it is never given one for"
        );
        assert!(
            pool.lock()
                .await
                .mapping_info(std::time::Instant::now())
                .is_empty(),
            "an A query left a mapping in the pool"
        );
    }

    /// Ask `pool` through the gateway resolver for `qname` with `qtype`,
    /// the daemon answering `mesh`.
    async fn ask(
        pool: &std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>>,
        event_tx: &mpsc::Sender<PoolEvent>,
        id: u16,
        qname: &str,
        mesh: &'static str,
        qtype: QTYPE,
    ) -> Vec<u8> {
        let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        let name = qname.to_string();
        let handle = spawn_upstream(upstream_socket, move |id| {
            vec![build_answer(id, &name, mesh)]
        });
        let response = handle_query(
            &build_query_of_type(id, qname, qtype),
            53000,
            upstream,
            TEST_TTL,
            pool,
            event_tx,
        )
        .await
        .unwrap();
        handle.await.unwrap();
        response
    }

    #[tokio::test]
    async fn an_a_query_does_not_refresh_a_never_used_mapping() {
        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let aaaa = QTYPE::TYPE(TYPE::AAAA);
        let response = ask(&pool, &event_tx, 0x1234, "test.fips", "fd00::1", aaaa).await;
        let virtual_ip = assert_pool_answer(&response);
        assert!(matches!(
            event_rx.try_recv().unwrap(),
            PoolEvent::MappingCreated { .. }
        ));
        let before = pool
            .lock()
            .await
            .lookup_virtual_ip(&virtual_ip)
            .unwrap()
            .last_referenced;

        let a = QTYPE::TYPE(TYPE::A);
        assert_nodata(&ask(&pool, &event_tx, 0x1235, "test.fips", "fd00::1", a).await);

        let guard = pool.lock().await;
        let mapping = guard
            .lookup_virtual_ip(&virtual_ip)
            .expect("the A query removed or replaced the mapping");
        assert_eq!(
            mapping.last_referenced, before,
            "an A query extended a mapping that has never carried traffic"
        );
        drop(guard);
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn an_a_query_refreshes_a_mapping_that_has_carried_traffic() {
        let pool = test_pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let aaaa = QTYPE::TYPE(TYPE::AAAA);
        let response = ask(&pool, &event_tx, 0x1234, "test.fips", "fd00::1", aaaa).await;
        let virtual_ip = assert_pool_answer(&response);
        let _ = event_rx.try_recv();

        // A reply from the node, read on a tick, marks the mapping used.
        let mut replies = ConntrackSnapshot::empty_read();
        replies.record_binding(virtual_ip, "fd00::1".parse().unwrap(), true);
        let before = {
            let mut guard = pool.lock().await;
            guard.tick(std::time::Instant::now(), &replies);
            let mapping = guard.lookup_virtual_ip(&virtual_ip).unwrap();
            assert!(mapping.used, "control: the mapping carried traffic");
            mapping.last_referenced
        };

        let a = QTYPE::TYPE(TYPE::A);
        assert_nodata(&ask(&pool, &event_tx, 0x1235, "test.fips", "fd00::1", a).await);

        let guard = pool.lock().await;
        let mapping = guard
            .lookup_virtual_ip(&virtual_ip)
            .expect("the A query removed or replaced the mapping");
        assert!(
            mapping.last_referenced > before,
            "the A query did not refresh a mapping that carries traffic"
        );
        drop(guard);
        assert!(
            matches!(event_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the A query sent a second MappingCreated"
        );
    }

    #[tokio::test]
    async fn an_eviction_sends_the_removal_before_the_creation() {
        let pool = std::sync::Arc::new(tokio::sync::Mutex::new(
            VirtualIpPool::with_limits("fd01::/112", TEST_TTL as u64, 30, 1, 10, 10).unwrap(),
        ));
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let aaaa = QTYPE::TYPE(TYPE::AAAA);
        let first =
            assert_pool_answer(&ask(&pool, &event_tx, 0x1234, "one.fips", "fd00::1", aaaa).await);
        let _ = event_rx.try_recv();

        let second =
            assert_pool_answer(&ask(&pool, &event_tx, 0x1235, "two.fips", "fd00::2", aaaa).await);
        match event_rx.try_recv().unwrap() {
            PoolEvent::MappingRemoved {
                virtual_ip,
                mesh_addr,
            } => {
                assert_eq!(virtual_ip, first);
                assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
            }
            other => panic!("expected the evicted mapping's removal first, got {other:?}"),
        }
        match event_rx.try_recv().unwrap() {
            PoolEvent::MappingCreated { virtual_ip, .. } => assert_eq!(virtual_ip, second),
            other => panic!("expected the new mapping's creation, got {other:?}"),
        }
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
            53000,
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
    fn an_in_use_hint_names_the_mdns_responders_for_5353() {
        let hint = holder_hint(5353);
        assert!(hint.contains("mDNS"), "{hint}");
        assert!(hint.contains("node.rendezvous.lan"), "{hint}");
        assert!(hint.contains("avahi-daemon"), "{hint}");
    }

    #[test]
    fn an_in_use_hint_names_llmnr_for_5355() {
        let hint = holder_hint(5355);
        assert!(hint.contains("LLMNR"), "{hint}");
        assert!(!hint.contains("mDNS"), "{hint}");
    }

    #[test]
    fn an_in_use_hint_names_the_daemon_for_5354() {
        let hint = holder_hint(5354);
        assert!(hint.contains("fips daemon's own DNS responder"), "{hint}");
    }

    #[test]
    fn an_in_use_hint_names_a_dns_server_for_53() {
        let hint = holder_hint(53);
        assert!(hint.contains("another DNS server"), "{hint}");
        assert!(hint.contains("dnsmasq"), "{hint}");
    }

    #[test]
    fn an_in_use_hint_names_another_gateway_for_the_default_port() {
        let hint = holder_hint(5365);
        assert!(hint.contains("another fips-gateway"), "{hint}");
    }

    #[test]
    fn an_in_use_hint_names_another_process_for_an_unknown_port() {
        assert_eq!(holder_hint(40000), "another process holds it");
    }

    #[tokio::test]
    async fn binding_a_held_port_fails_with_addr_in_use_and_names_the_port_ss_and_netstat() {
        let holder = UdpSocket::bind("[::1]:0").await.unwrap();
        let port = holder.local_addr().unwrap().port();
        let listen = format!("[::1]:{port}");

        let err = bind_listener(&listen)
            .await
            .expect_err("binding a held port must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        let message = err.to_string();
        assert!(message.contains(&listen), "{message}");
        assert!(message.contains(&format!("sport = :{port}")), "{message}");
        assert!(message.contains("ss -ulpn"), "{message}");
        assert!(message.contains("netstat -ulnp"), "{message}");
        assert!(message.contains(holder_hint(port)), "{message}");
    }

    #[tokio::test]
    async fn binding_a_free_port_returns_a_bound_socket() {
        let socket = bind_listener("[::1]:0").await.expect("bind a free port");
        assert_ne!(socket.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn test_extract_fips_name() {
        let bytes = build_query(1, "test.fips");
        let Screen::Query(query) = dnsmsg::screen(&bytes, 53000) else {
            panic!("a clean AAAA query passes the screen");
        };
        assert_eq!(
            extract_fips_name(&query.name),
            Some("test.fips".to_string())
        );
    }

    #[test]
    fn test_extract_non_fips_name() {
        let bytes = build_query(1, "example.com");
        let Screen::Query(query) = dnsmsg::screen(&bytes, 53000) else {
            panic!("a clean AAAA query passes the screen");
        };
        assert!(extract_fips_name(&query.name).is_none());
    }

    #[test]
    fn test_build_aaaa_response() {
        let bytes = build_query(42, "test.fips");
        let Screen::Query(query) = dnsmsg::screen(&bytes, 53000) else {
            panic!("a clean AAAA query passes the screen");
        };

        let vip: Ipv6Addr = "fd01::1".parse().unwrap();
        let response_bytes = build_aaaa_response(&query, vip, 60);
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

/// Screening of untrusted datagrams by the gateway's forwarder.
///
/// These tests use only `handle_query`, `serve`, `VirtualIpPool::new`, a fake
/// upstream of their own and byte builders of their own, so they run
/// unchanged against the forwarder before and after its datagrams were
/// screened.
#[cfg(test)]
mod screening_tests {
    use super::*;
    use simple_dns::Packet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// The gateway's configured record TTL, in seconds.
    const TTL: u32 = 60;
    /// An ordinary client source port, as a resolver would send from.
    const CLIENT_PORT: u16 = 53000;
    /// Record type A.
    const TYPE_A: u16 = 1;
    /// Record type AAAA.
    const TYPE_AAAA: u16 = 28;
    /// Record type SSHFP, one `simple-dns` cannot parse in a question.
    const TYPE_SSHFP: u16 = 44;
    /// Class IN.
    const CLASS_IN: u16 = 1;
    /// Rcode NOERROR.
    const NOERROR: u16 = 0;
    /// Rcode FORMERR.
    const FORMERR: u16 = 1;
    /// Rcode SERVFAIL.
    const SERVFAIL: u16 = 2;
    /// Rcode NXDOMAIN.
    const NXDOMAIN: u16 = 3;
    /// Rcode NOTIMP.
    const NOTIMP: u16 = 4;
    /// Rcode REFUSED.
    const REFUSED: u16 = 5;
    /// A daytime service's reply, as it would arrive from port 13.
    const DAYTIME: &[u8] = b"Thu Oct  9 12:00:00 2026\r\n";

    /// `name` in wire form, with a label per dot-separated part.
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A message with this header and `body` after it.
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

    /// A question section entry for the wire name `name`.
    fn question(name: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&qclass.to_be_bytes());
        out
    }

    /// A one-question message asking for `name`.
    fn query(id: u16, flags: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        message(
            id,
            flags,
            [1, 0, 0, 0],
            &question(&wire_name(name), qtype, qclass),
        )
    }

    /// A plain AAAA query for `name`, class IN, no flags.
    fn aaaa_query(id: u16, name: &str) -> Vec<u8> {
        query(id, 0, name, TYPE_AAAA, CLASS_IN)
    }

    /// An AAAA IN query for `name` with one EDNS OPT record padded so the
    /// datagram is exactly `total` bytes long.
    fn padded_query(id: u16, name: &str, total: usize) -> Vec<u8> {
        let mut body = question(&wire_name(name), TYPE_AAAA, CLASS_IN);
        let pad = total - (12 + body.len() + 15);
        body.push(0);
        body.extend_from_slice(&41u16.to_be_bytes());
        body.extend_from_slice(&1232u16.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&((4 + pad) as u16).to_be_bytes());
        body.extend_from_slice(&12u16.to_be_bytes());
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

    /// The upstream's answer to `query`: its header and question with QR,
    /// AA and `rcode` set, plus an AAAA record for `addr` when given.
    fn upstream_answer(query: &[u8], rcode: u16, addr: Option<Ipv6Addr>) -> Vec<u8> {
        let mut out = query.to_vec();
        out[2..4].copy_from_slice(&(0x8400 | (word(query, 2) & 0x0100) | rcode).to_be_bytes());
        if let Some(addr) = addr {
            out[6..8].copy_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&[0xC0, 0x0C, 0, 28, 0, 1]);
            out.extend_from_slice(&TTL.to_be_bytes());
            out.extend_from_slice(&16u16.to_be_bytes());
            out.extend_from_slice(&addr.octets());
        }
        out
    }

    /// A fake upstream on `[::1]:0` that answers each datagram it receives
    /// with `answer`, counting what it receives. Abort the handle when done.
    async fn fake_upstream<F>(
        answer: F,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + 'static,
    {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let _ = socket.send_to(&answer(&buf[..len]), src).await;
            }
        });
        (addr, received, handle)
    }

    /// An upstream that answers every query with the mesh address `fd00::1`.
    async fn mesh_upstream() -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        fake_upstream(|q| upstream_answer(q, NOERROR, Some("fd00::1".parse().unwrap()))).await
    }

    /// An address no upstream listens on, for queries that never reach one.
    fn no_upstream() -> SocketAddr {
        "[::1]:9".parse().unwrap()
    }

    /// A fresh gateway address pool on `fd01::/112`.
    fn pool() -> Arc<tokio::sync::Mutex<VirtualIpPool>> {
        Arc::new(tokio::sync::Mutex::new(
            VirtualIpPool::new("fd01::/112", TTL as u64, 30).unwrap(),
        ))
    }

    /// Run the gateway's handler on `datagram` from source port `port`.
    async fn ask(
        datagram: &[u8],
        port: u16,
        upstream: SocketAddr,
        pool: &Arc<tokio::sync::Mutex<VirtualIpPool>>,
        event_tx: &mpsc::Sender<PoolEvent>,
    ) -> Option<Vec<u8>> {
        handle_query(datagram, port, upstream, TTL, pool, event_tx).await
    }

    /// Ask with a fresh pool and an upstream that is never contacted.
    async fn ask_alone(datagram: &[u8], port: u16) -> Option<Vec<u8>> {
        let (event_tx, _event_rx) = mpsc::channel(16);
        ask(datagram, port, no_upstream(), &pool(), &event_tx).await
    }

    /// The pool address in a reply's one AAAA answer.
    fn pool_address(reply: &[u8]) -> Ipv6Addr {
        let packet = Packet::parse(reply).expect("the reply parses");
        assert_eq!(rcode(reply), NOERROR, "rcode");
        let addr = extract_aaaa(&packet).expect("an AAAA answer");
        assert_eq!(
            &addr.octets()[..2],
            &[0xfd, 0x01],
            "a pool address, got {addr}"
        );
        addr
    }

    /// The owner name of a reply's one authority record, which must be an
    /// SOA whose owner is a pointer into the question. Read by hand, since
    /// simple-dns cannot parse a reply to a query type it does not know.
    fn soa_owner(reply: &[u8], query_len: usize) -> String {
        assert_eq!(word(reply, 6), 0, "no answers");
        assert_eq!(word(reply, 8), 1, "one authority record");
        let record = &reply[query_len..];
        assert_eq!(record[0] & 0xC0, 0xC0, "the SOA owner is a pointer");
        assert_eq!(word(record, 2), 6, "the authority record is an SOA");
        let mut pos = (word(record, 0) & 0x3FFF) as usize;
        let mut labels = Vec::new();
        while reply[pos] != 0 {
            let len = reply[pos] as usize;
            labels.push(String::from_utf8_lossy(&reply[pos + 1..pos + 1 + len]).into_owned());
            pos += 1 + len;
        }
        labels.join(".")
    }

    // --- loops and reflection ---

    #[tokio::test]
    async fn a_response_for_a_non_fips_name_gets_no_reply() {
        let control = aaaa_query(0x1001, "example.com");
        let reply = ask_alone(&control, CLIENT_PORT)
            .await
            .expect("control answered");
        assert_eq!(rcode(&reply), REFUSED, "control: REFUSED");

        let response = query(0x1002, 0x8000, "example.com", TYPE_AAAA, CLASS_IN);
        let reply = ask_alone(&response, CLIENT_PORT).await;
        assert!(
            reply.is_none(),
            "the response drew a reply with flags {:#06x}",
            reply.map(|r| word(&r, 2)).unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn a_text_datagram_gets_no_reply() {
        let control = aaaa_query(0x1101, "example.com");
        assert!(
            ask_alone(&control, CLIENT_PORT).await.is_some(),
            "control: a clean query from port {CLIENT_PORT} is answered"
        );
        assert!(
            ask_alone(DAYTIME, CLIENT_PORT).await.is_none(),
            "daytime text was answered"
        );
    }

    #[tokio::test]
    async fn a_two_question_query_for_a_non_fips_name_gets_no_reply() {
        let mut name = Vec::new();
        for len in [63usize, 63, 63, 61] {
            name.push(len as u8);
            name.extend(std::iter::repeat_n(0x01u8, len));
        }
        name.push(0);
        let one = question(&name, TYPE_AAAA, CLASS_IN);
        let control = message(0x1201, 0, [1, 0, 0, 0], &one);
        let reply = ask_alone(&control, CLIENT_PORT)
            .await
            .expect("control answered");
        assert_eq!(rcode(&reply), REFUSED, "control: REFUSED");

        let mut body = one.clone();
        body.extend_from_slice(&[0xC0, 0x0D, 0x00, 0x1C, 0x00, 0x01]);
        let datagram = message(0x1202, 0, [2, 0, 0, 0], &body);
        assert_eq!(datagram.len(), 277);
        let reply = ask_alone(&datagram, CLIENT_PORT).await;
        assert!(
            reply.is_none(),
            "the 277-byte two-question query drew a {:?}-byte reply",
            reply.map(|r| r.len())
        );
    }

    #[tokio::test]
    async fn a_response_for_a_fips_name_gets_no_reply_and_mints_no_mapping() {
        let (upstream, received, handle) = mesh_upstream().await;
        let pool = pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);

        let response = query(0x1301, 0x8000, "test.fips", TYPE_AAAA, CLASS_IN);
        let reply = ask(&response, CLIENT_PORT, upstream, &pool, &event_tx).await;
        assert!(reply.is_none(), "the response drew a reply");
        assert_eq!(
            received.load(Ordering::SeqCst),
            0,
            "the response was forwarded upstream"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "the response minted a mapping"
        );

        let control = aaaa_query(0x1302, "test.fips");
        let reply = ask(&control, CLIENT_PORT, upstream, &pool, &event_tx)
            .await
            .expect("control answered");
        pool_address(&reply);
        assert!(
            matches!(event_rx.try_recv(), Ok(PoolEvent::MappingCreated { .. })),
            "control: one MappingCreated"
        );
        handle.abort();
    }

    // --- header handling ---

    #[tokio::test]
    async fn an_sshfp_query_for_a_non_fips_name_gets_refused() {
        let datagram = query(0x2001, 0, "example.com", TYPE_SSHFP, CLASS_IN);
        let reply = ask_alone(&datagram, CLIENT_PORT)
            .await
            .expect("an SSHFP query gets a reply");
        assert_eq!(rcode(&reply), REFUSED, "rcode");
    }

    #[tokio::test]
    async fn an_rd_query_for_a_non_fips_name_gets_rd_and_ra_back() {
        let datagram = query(0x2101, 0x0100, "example.com", TYPE_AAAA, CLASS_IN);
        let reply = ask_alone(&datagram, CLIENT_PORT).await.expect("answered");
        assert_eq!(
            word(&reply, 2) & 0x0180,
            0x0180,
            "flags {:#06x}: RD and RA not both set",
            word(&reply, 2)
        );
    }

    #[tokio::test]
    async fn an_opcode_4_query_for_a_non_fips_name_gets_a_header_only_notimp() {
        let datagram = query(0x2201, 4 << 11, "example.com", TYPE_AAAA, CLASS_IN);
        let reply = ask_alone(&datagram, CLIENT_PORT)
            .await
            .expect("an opcode 4 query gets a reply");
        assert_eq!(rcode(&reply), NOTIMP, "rcode");
        assert_eq!((word(&reply, 2) >> 11) & 0x0F, 4, "opcode copied");
        assert_eq!(word(&reply, 4), 0, "QDCOUNT");
        assert_eq!(reply.len(), 12, "a header-only reply");
    }

    #[tokio::test]
    async fn a_query_with_no_question_gets_a_header_only_formerr_from_the_gateway() {
        let datagram = message(0x2301, 0, [0, 0, 0, 0], &[]);
        let reply = ask_alone(&datagram, CLIENT_PORT)
            .await
            .expect("a QDCOUNT 0 query gets a reply");
        assert_eq!(rcode(&reply), FORMERR, "rcode");
        assert_eq!(word(&reply, 4), 0, "QDCOUNT");
        assert_eq!(reply.len(), 12, "a header-only reply");
    }

    #[tokio::test]
    async fn a_class_5_query_gets_refused_from_the_gateway() {
        let datagram = query(0x2401, 0, "test.fips", TYPE_AAAA, 5);
        let reply = ask_alone(&datagram, CLIENT_PORT)
            .await
            .expect("a class 5 query gets a reply");
        assert_eq!(rcode(&reply), REFUSED, "rcode");
        assert_eq!(
            &reply[12..],
            &datagram[12..],
            "the question, and nothing else"
        );
    }

    #[tokio::test]
    async fn an_sshfp_query_for_a_fips_name_gets_nodata_with_an_soa_and_mints_no_mapping() {
        let (upstream, _, handle) = mesh_upstream().await;
        let pool = pool();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let datagram = query(0x2501, 0, "test.fips", TYPE_SSHFP, CLASS_IN);
        let reply = ask(&datagram, CLIENT_PORT, upstream, &pool, &event_tx)
            .await
            .expect("an SSHFP query for a .fips name gets a reply");
        assert_eq!(rcode(&reply), NOERROR, "rcode");
        assert_eq!(word(&reply, 6), 0, "no answers");
        assert_eq!(soa_owner(&reply, datagram.len()), "fips");
        assert_eq!(reply.len(), datagram.len() + 51, "reply length");
        assert!(
            event_rx.try_recv().is_err(),
            "an SSHFP query minted a mapping"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn an_upstream_nxdomain_for_a_fips_is_relayed_with_an_soa_in_a_75_byte_reply() {
        let (upstream, _, handle) = fake_upstream(|q| upstream_answer(q, NXDOMAIN, None)).await;
        let (event_tx, _event_rx) = mpsc::channel(16);
        let datagram = aaaa_query(0x2601, "a.fips");
        assert_eq!(datagram.len(), 24);
        let reply = ask(&datagram, CLIENT_PORT, upstream, &pool(), &event_tx)
            .await
            .expect("answered");
        assert_eq!(rcode(&reply), NXDOMAIN, "rcode");
        assert_eq!(soa_owner(&reply, datagram.len()), "fips");
        assert_eq!(reply.len(), 75, "reply length");
        handle.abort();
    }

    /// Ask for `a.fips` through an upstream that answers with `upstream_rcode`
    /// and no records, and return the 24-byte query and the reply.
    async fn relayed(upstream_rcode: u16) -> (Vec<u8>, Vec<u8>) {
        let (upstream, _, handle) =
            fake_upstream(move |q| upstream_answer(q, upstream_rcode, None)).await;
        let (event_tx, _event_rx) = mpsc::channel(16);
        let datagram = aaaa_query(0x2611, "a.fips");
        assert_eq!(datagram.len(), 24);
        let reply = ask(&datagram, CLIENT_PORT, upstream, &pool(), &event_tx)
            .await
            .expect("answered");
        handle.abort();
        (datagram, reply)
    }

    #[tokio::test]
    async fn an_upstream_servfail_is_relayed_as_servfail_with_no_authority_record_in_a_24_byte_reply()
     {
        let (datagram, reply) = relayed(SERVFAIL).await;
        assert_eq!(rcode(&reply), SERVFAIL, "rcode");
        assert_eq!(word(&reply, 6), 0, "no answers");
        assert_eq!(word(&reply, 8), 0, "no authority record");
        assert_eq!(reply.len(), datagram.len(), "reply length");
    }

    #[tokio::test]
    async fn an_upstream_rcode_of_13_is_relayed_unchanged_with_no_authority_record() {
        let (datagram, reply) = relayed(13).await;
        assert_eq!(rcode(&reply), 13, "rcode");
        assert_eq!(word(&reply, 8), 0, "no authority record");
        assert_eq!(reply.len(), datagram.len(), "reply length");
    }

    #[tokio::test]
    async fn an_upstream_nxdomain_for_the_single_label_dot_fips_is_relayed_in_an_82_byte_reply() {
        let (upstream, _, handle) = fake_upstream(|q| upstream_answer(q, NXDOMAIN, None)).await;
        let (event_tx, _event_rx) = mpsc::channel(16);
        let name = [5, b'.', b'f', b'i', b'p', b's', 0];
        let datagram = message(
            0x2701,
            0,
            [1, 0, 0, 0],
            &question(&name, TYPE_AAAA, CLASS_IN),
        );
        assert_eq!(datagram.len(), 23);
        let reply = ask(&datagram, CLIENT_PORT, upstream, &pool(), &event_tx)
            .await
            .expect("answered");
        assert_eq!(rcode(&reply), NXDOMAIN, "rcode");
        assert_eq!(soa_owner(&reply, datagram.len()), ".fips");
        assert_eq!(&reply[23..25], &[0xC0, 0x0C], "owned by the question name");
        assert_eq!(reply.len(), datagram.len() + 59, "reply length");
        handle.abort();
    }

    #[tokio::test]
    async fn an_rd_aaaa_query_for_a_fips_name_gets_rd_back_with_its_pool_address() {
        let (upstream, _, handle) = mesh_upstream().await;
        let (event_tx, _event_rx) = mpsc::channel(16);
        let datagram = query(0x2801, 0x0100, "test.fips", TYPE_AAAA, CLASS_IN);
        let reply = ask(&datagram, CLIENT_PORT, upstream, &pool(), &event_tx)
            .await
            .expect("answered");
        pool_address(&reply);
        assert_eq!(
            word(&reply, 2) & 0x0180,
            0x0180,
            "flags {:#06x}: RD and RA not both set",
            word(&reply, 2)
        );
        handle.abort();
    }

    #[tokio::test]
    async fn a_z_bit_aaaa_query_for_a_fips_name_gets_its_pool_address_with_z_clear() {
        let (upstream, _, handle) = mesh_upstream().await;
        let (event_tx, _event_rx) = mpsc::channel(16);
        let datagram = query(0x2901, 0x0040, "test.fips", TYPE_AAAA, CLASS_IN);
        let reply = ask(&datagram, CLIENT_PORT, upstream, &pool(), &event_tx)
            .await
            .expect("a Z-bit query is answered");
        pool_address(&reply);
        assert_eq!(word(&reply, 2) & 0x0040, 0, "Z echoed");
        handle.abort();
    }

    // --- healthy path ---

    #[tokio::test]
    async fn an_a_query_for_a_fips_name_gets_nodata_with_an_soa_of_the_configured_ttl() {
        let (upstream, _, handle) = mesh_upstream().await;
        let (event_tx, _event_rx) = mpsc::channel(16);
        let datagram = query(0x3001, 0x0100, "test.fips", TYPE_A, CLASS_IN);
        let reply = ask(&datagram, CLIENT_PORT, upstream, &pool(), &event_tx)
            .await
            .expect("answered");
        assert_eq!(rcode(&reply), NOERROR, "rcode");
        assert_eq!(word(&reply, 6), 0, "no answers");
        let packet = Packet::parse(&reply).expect("the reply parses");
        let record = &packet.name_servers[0];
        assert_eq!(record.ttl, TTL, "SOA record TTL");
        match &record.rdata {
            rdata::RData::SOA(soa) => assert_eq!(soa.minimum, TTL, "SOA minimum"),
            other => panic!("expected an SOA, got {other:?}"),
        }
        handle.abort();
    }

    // --- through the receive loop ---

    /// `serve` on `127.0.0.1:0` with no reachable upstream, and a client.
    async fn spawn_serve() -> (SocketAddr, UdpSocket, watch::Sender<bool>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (event_tx, event_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            let _keep = event_rx;
            serve(socket, no_upstream(), TTL, pool(), event_tx, shutdown_rx).await
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (addr, client, shutdown_tx)
    }

    /// The next datagram `client` receives, waiting at most 2 s; `what`
    /// names the expected reply in the panic.
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
    async fn serve_drops_a_datagram_that_fills_its_buffer_and_answers_the_next_query() {
        let (server, client, shutdown) = spawn_serve().await;
        client
            .send_to(&aaaa_query(0x4001, "example.com"), server)
            .await
            .unwrap();
        let first = next_reply(&client, "the first control's reply").await;
        assert_eq!(word(&first, 0), 0x4001, "control answered");

        let oversize = padded_query(0x4002, "example.com", 4200);
        client.send_to(&oversize, server).await.unwrap();
        client
            .send_to(&aaaa_query(0x4003, "example.com"), server)
            .await
            .unwrap();
        let next = next_reply(&client, "the second control's reply").await;
        assert_eq!(
            word(&next, 0),
            0x4003,
            "the 4,200-byte datagram (0x4002) drew a reply before the second control (0x4003)"
        );
        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn serve_drops_a_response_and_answers_the_next_query() {
        let (server, client, shutdown) = spawn_serve().await;
        client
            .send_to(&aaaa_query(0x4101, "example.com"), server)
            .await
            .unwrap();
        let first = next_reply(&client, "the first control's reply").await;
        assert_eq!(word(&first, 0), 0x4101, "control answered");

        let response = query(0x4102, 0x8000, "example.com", TYPE_AAAA, CLASS_IN);
        client.send_to(&response, server).await.unwrap();
        client
            .send_to(&aaaa_query(0x4103, "example.com"), server)
            .await
            .unwrap();
        let next = next_reply(&client, "the second control's reply").await;
        assert_eq!(
            word(&next, 0),
            0x4103,
            "the response (0x4102) drew a reply before the second control (0x4103)"
        );
        let _ = shutdown.send(true);
    }

    #[tokio::test]
    async fn serve_answers_an_opcode_4_query_with_a_header_only_notimp_and_then_the_next_query() {
        let (server, client, shutdown) = spawn_serve().await;
        client
            .send_to(&aaaa_query(0x4201, "example.com"), server)
            .await
            .unwrap();
        let first = next_reply(&client, "the first control's reply").await;
        assert_eq!(word(&first, 0), 0x4201, "control answered");

        let notify = query(0x4202, 4 << 11, "example.com", TYPE_AAAA, CLASS_IN);
        client.send_to(&notify, server).await.unwrap();
        client
            .send_to(&aaaa_query(0x4203, "example.com"), server)
            .await
            .unwrap();
        let notimp = next_reply(&client, "the NOTIMP").await;
        assert_eq!(
            word(&notimp, 0),
            0x4202,
            "the opcode 4 query's reply comes next"
        );
        assert_eq!(rcode(&notimp), NOTIMP, "rcode");
        assert_eq!((word(&notimp, 2) >> 11) & 0x0F, 4, "opcode copied");
        assert_eq!(word(&notimp, 4), 0, "QDCOUNT");
        let last = next_reply(&client, "the second control's reply").await;
        assert_eq!(word(&last, 0), 0x4203, "the second control follows");
        let _ = shutdown.send(true);
    }
}
