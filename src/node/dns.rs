//! FIPS DNS Responder
//!
//! Resolves `<npub>.fips` queries to FipsAddress IPv6 addresses.
//! The resolution is pure computation: npub → PublicKey → NodeAddr → FipsAddress.
//! As a side effect, resolved identities are sent to the Node for identity
//! cache population, enabling subsequent TUN packet routing.

use crate::{NodeAddr, PeerIdentity};
use simple_dns::rdata::{RData, AAAA};
use simple_dns::{Packet, Name, ResourceRecord, CLASS, RCODE, PacketFlag, QTYPE, TYPE};
use std::net::Ipv6Addr;
use tracing::{debug, warn};

/// Identity resolved by the DNS responder, sent to Node for cache population.
pub struct DnsResolvedIdentity {
    pub node_addr: NodeAddr,
    pub pubkey: secp256k1::PublicKey,
}

/// Channel sender for DNS → Node identity registration.
pub type DnsIdentityTx = tokio::sync::mpsc::Sender<DnsResolvedIdentity>;

/// Channel receiver consumed by the Node RX event loop.
pub type DnsIdentityRx = tokio::sync::mpsc::Receiver<DnsResolvedIdentity>;

/// Resolve a `.fips` domain name to an IPv6 address and identity.
///
/// The name should be `<npub>.fips` (with optional trailing dot).
/// Returns the FipsAddress IPv6, NodeAddr, and full PublicKey on success.
pub fn resolve_fips_query(name: &str) -> Option<(Ipv6Addr, NodeAddr, secp256k1::PublicKey)> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let npub = name.strip_suffix(".fips")
        .or_else(|| name.strip_suffix(".FIPS"))
        .or_else(|| {
            // Case-insensitive check for .fips suffix
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".fips") {
                Some(&name[..name.len() - 5])
            } else {
                None
            }
        })?;

    let peer = PeerIdentity::from_npub(npub).ok()?;
    let ipv6 = peer.address().to_ipv6();
    let node_addr = *peer.node_addr();
    let pubkey = peer.pubkey_full();

    Some((ipv6, node_addr, pubkey))
}

/// Handle a raw DNS query packet and produce a response.
///
/// Returns the response bytes and an optional resolved identity (for AAAA queries
/// that successfully resolved a `.fips` name).
pub fn handle_dns_packet(query_bytes: &[u8], ttl: u32) -> Option<(Vec<u8>, Option<DnsResolvedIdentity>)> {
    let query = Packet::parse(query_bytes).ok()?;
    let question = query.questions.first()?;

    let qname = question.qname.to_string();
    let is_aaaa = matches!(question.qtype, QTYPE::TYPE(TYPE::AAAA));

    let mut response = query.into_reply();
    response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

    if is_aaaa
        && let Some((ipv6, node_addr, pubkey)) = resolve_fips_query(&qname)
    {
        let name = Name::new_unchecked(&qname).into_owned();
        let record = ResourceRecord::new(
            name,
            CLASS::IN,
            ttl,
            RData::AAAA(AAAA::from(ipv6)),
        );
        response.answers.push(record);

        let identity = DnsResolvedIdentity { node_addr, pubkey };
        let bytes = response.build_bytes_vec_compressed().ok()?;
        return Some((bytes, Some(identity)));
    }

    // Query we can't answer: NXDOMAIN
    *response.rcode_mut() = RCODE::NameError;
    let bytes = response.build_bytes_vec_compressed().ok()?;
    Some((bytes, None))
}

/// Run the DNS responder UDP server loop.
///
/// Listens for DNS queries, resolves `.fips` names, and sends resolved
/// identities to the Node via the identity channel.
pub async fn run_dns_responder(
    socket: tokio::net::UdpSocket,
    identity_tx: DnsIdentityTx,
    ttl: u32,
) {
    let mut buf = [0u8; 512]; // Standard DNS UDP max

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "DNS socket recv error");
                continue;
            }
        };

        let query_bytes = &buf[..len];

        match handle_dns_packet(query_bytes, ttl) {
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

    #[test]
    fn test_handle_aaaa_query() {
        let identity = Identity::generate();
        let npub = identity.npub();
        let expected_ipv6 = identity.address().to_ipv6();

        // Build a DNS AAAA query packet
        let query_name = format!("{}.fips", npub);
        let query_packet = build_test_query(&query_name, TYPE::AAAA);

        let result = handle_dns_packet(&query_packet, 300);
        assert!(result.is_some(), "should handle AAAA query");

        let (response_bytes, identity_opt) = result.unwrap();
        assert!(identity_opt.is_some(), "should produce identity");

        // Parse the response
        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.answers.len(), 1);

        // Verify the AAAA record
        if let RData::AAAA(aaaa) = &response.answers[0].rdata {
            let addr = Ipv6Addr::from(aaaa.address);
            assert_eq!(addr, expected_ipv6);
        } else {
            panic!("expected AAAA record");
        }
    }

    #[test]
    fn test_handle_nxdomain_for_unknown() {
        let query_packet = build_test_query("unknown.fips", TYPE::AAAA);

        let result = handle_dns_packet(&query_packet, 300);
        assert!(result.is_some());

        let (response_bytes, identity_opt) = result.unwrap();
        assert!(identity_opt.is_none(), "should not produce identity for unknown");

        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.rcode(), RCODE::NameError);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn test_handle_non_aaaa_query() {
        let identity = Identity::generate();
        let query_name = format!("{}.fips", identity.npub());
        let query_packet = build_test_query(&query_name, TYPE::A);

        let result = handle_dns_packet(&query_packet, 300);
        assert!(result.is_some());

        let (response_bytes, identity_opt) = result.unwrap();
        assert!(identity_opt.is_none(), "A query should not resolve .fips");

        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.rcode(), RCODE::NameError);
    }

    #[tokio::test]
    async fn test_dns_responder_udp() {
        let identity = Identity::generate();
        let npub = identity.npub();
        let expected_ipv6 = identity.address().to_ipv6();

        // Bind responder on ephemeral port
        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let (identity_tx, mut identity_rx) = tokio::sync::mpsc::channel(16);

        // Spawn the responder
        let responder_handle = tokio::spawn(run_dns_responder(server_socket, identity_tx, 300));

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
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            identity_rx.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(resolved.node_addr, *identity.node_addr());

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
