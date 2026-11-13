//! Tests of `stun.rs`: the STUN binding-success parser, the private-address
//! filter for local candidates, and `perform_stun`'s source check against a
//! loopback server.

use super::{is_private_overlay_candidate_ip, parse_stun_binding_success};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
const TEST_TXN_ID: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

/// Build a STUN Binding Success header with the given message length and txn id.
fn build_success_header(message_length: u16, txn_id: &[u8; 12]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
    packet.extend_from_slice(&message_length.to_be_bytes());
    packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    packet.extend_from_slice(txn_id);
    packet
}

#[test]
fn parse_stun_binding_success_rejects_truncated_header() {
    // Anything shorter than the 20-byte header must be rejected.
    for len in 0..20usize {
        let packet = vec![0u8; len];
        assert!(
            parse_stun_binding_success(&packet, &TEST_TXN_ID).is_none(),
            "expected None for {}-byte packet",
            len
        );
    }
}

#[test]
fn parse_stun_binding_success_rejects_bad_magic_cookie() {
    let mut packet = build_success_header(0, &TEST_TXN_ID);
    // Corrupt the magic cookie at bytes 4..8.
    packet[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
    assert!(parse_stun_binding_success(&packet, &TEST_TXN_ID).is_none());
}

#[test]
fn parse_stun_binding_success_skips_unknown_attribute_type() {
    // Unknown attribute (type 0x00ff, 4-byte body) followed by a valid
    // XOR-MAPPED-ADDRESS. The parser should skip the unknown attr and
    // still return the mapped address from the second TLV.
    let mut packet = build_success_header(0, &TEST_TXN_ID);

    // Unknown attribute: type=0x00ff, len=4, body=4 zero bytes.
    packet.extend_from_slice(&0x00ffu16.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());
    packet.extend_from_slice(&[0u8; 4]);

    // XOR-MAPPED-ADDRESS for 192.0.2.1:1234.
    // Build the unxored body, then XOR with cookie/txn so the parser
    // recovers the original IP/port.
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let xport = 1234u16 ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let xip = [192 ^ cookie[0], cookie[1], 2 ^ cookie[2], 1 ^ cookie[3]];
    packet.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
    packet.extend_from_slice(&8u16.to_be_bytes()); // length
    packet.push(0x00); // reserved
    packet.push(0x01); // family IPv4
    packet.extend_from_slice(&xport.to_be_bytes());
    packet.extend_from_slice(&xip);

    // Patch the message length (everything after the 20-byte header).
    let body_len = (packet.len() - 20) as u16;
    packet[2..4].copy_from_slice(&body_len.to_be_bytes());

    let mapped = parse_stun_binding_success(&packet, &TEST_TXN_ID)
        .expect("parser should skip unknown attr and find XOR-MAPPED-ADDRESS");
    assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(mapped.port(), 1234);
}

#[test]
fn parse_stun_binding_success_rejects_truncated_xor_mapped_address() {
    // XOR-MAPPED-ADDRESS attribute with family=IPv4 but only 6 bytes of
    // body (need 8). Parser should silently ignore and return None.
    let mut packet = build_success_header(0, &TEST_TXN_ID);
    packet.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
    packet.extend_from_slice(&6u16.to_be_bytes()); // declared length 6 (too short)
    packet.push(0x00); // reserved
    packet.push(0x01); // family IPv4
    packet.extend_from_slice(&[0u8; 4]); // truncated: port + partial IP only

    let body_len = (packet.len() - 20) as u16;
    packet[2..4].copy_from_slice(&body_len.to_be_bytes());

    assert!(parse_stun_binding_success(&packet, &TEST_TXN_ID).is_none());
}

#[test]
fn parse_stun_binding_success_rejects_length_overflow_attribute() {
    // Attribute declares length larger than what's actually present in
    // the buffer; parser must break out of the loop and return None
    // rather than panic or read past the end.
    let mut packet = build_success_header(0, &TEST_TXN_ID);
    packet.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
    packet.extend_from_slice(&64u16.to_be_bytes()); // claims 64 bytes...
    packet.extend_from_slice(&[0u8; 4]); // ...but only 4 bytes follow

    let body_len = (packet.len() - 20) as u16;
    packet[2..4].copy_from_slice(&body_len.to_be_bytes());

    assert!(parse_stun_binding_success(&packet, &TEST_TXN_ID).is_none());
}

#[test]
fn parse_stun_binding_success_rejects_txn_id_mismatch() {
    // Valid header + valid XOR-MAPPED-ADDRESS, but txn id in the packet
    // does not match the expected one. Parser must reject.
    let other_txn: [u8; 12] = [0xff; 12];
    let mut packet = build_success_header(12, &other_txn);
    packet.extend_from_slice(&0x0020u16.to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.push(0x00);
    packet.push(0x01);
    packet.extend_from_slice(&[0u8; 6]);

    assert!(parse_stun_binding_success(&packet, &TEST_TXN_ID).is_none());
}

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

/// Build a complete Binding Success carrying one XOR-MAPPED-ADDRESS.
fn build_binding_success(mapped: std::net::SocketAddrV4, txn_id: &[u8; 12]) -> Vec<u8> {
    let mut packet = build_success_header(0, txn_id);
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let octets = mapped.ip().octets();
    let xport = mapped.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    packet.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.push(0x00); // reserved
    packet.push(0x01); // family IPv4
    packet.extend_from_slice(&xport.to_be_bytes());
    for (index, octet) in octets.iter().enumerate() {
        packet.push(octet ^ cookie[index]);
    }
    let body_len = (packet.len() - 20) as u16;
    packet[2..4].copy_from_slice(&body_len.to_be_bytes());
    packet
}

/// Bind a loopback socket suitable for handing to `perform_stun`.
///
/// `set_nonblocking` is mandatory rather than tidiness: `perform_stun`
/// passes the socket to `tokio::net::UdpSocket::from_std`, which requires
/// a non-blocking socket and does not make one. A blocking socket parks
/// the runtime thread and the deadline never fires.
fn bind_stun_caller() -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

#[tokio::test]
async fn stun_binding_response_from_an_unexpected_source_is_refused() {
    let caller = bind_stun_caller();
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let attacker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().unwrap();

    // Stands in for an on-path attacker: it learns the transaction id the
    // way a real one would, by reading the request, and answers from its
    // own address while the server stays silent.
    let forger = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (len, from) = server.recv_from(&mut buf).unwrap();
        assert!(len >= 20);
        let mut txn_id = [0u8; 12];
        txn_id.copy_from_slice(&buf[8..20]);
        let forged = build_binding_success("203.0.113.7:1".parse().unwrap(), &txn_id);
        attacker.send_to(&forged, from).unwrap();
    });

    let result = super::perform_stun(
        &caller,
        &server_addr.to_string(),
        std::time::Duration::from_millis(300),
    )
    .await;
    forger.join().unwrap();
    assert!(
        result.is_err(),
        "a binding success from a host other than the server must not be believed, got {:?}",
        result
    );
}

#[tokio::test]
async fn stun_binding_response_from_the_server_is_accepted() {
    let caller = bind_stun_caller();
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().unwrap();

    let responder = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (_len, from) = server.recv_from(&mut buf).unwrap();
        let mut txn_id = [0u8; 12];
        txn_id.copy_from_slice(&buf[8..20]);
        let reply = build_binding_success("198.51.100.9:4242".parse().unwrap(), &txn_id);
        server.send_to(&reply, from).unwrap();
    });

    let mapped = super::perform_stun(
        &caller,
        &server_addr.to_string(),
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap()
    .unwrap();
    responder.join().unwrap();
    assert_eq!(mapped.to_string(), "198.51.100.9:4242");
}

#[test]
fn only_local_candidates_of_the_sockets_family_are_offered() {
    let candidates = || {
        ["192.168.1.2", "fd00::1", "10.0.0.3", "2001:db8::1"]
            .map(String::from)
            .to_vec()
    };
    assert_eq!(
        super::offerable(candidates(), true),
        ["192.168.1.2", "10.0.0.3"],
        "IPv6 candidates offered with an IPv4 socket's port, which no peer can reach"
    );
    assert_eq!(
        super::offerable(candidates(), false),
        ["fd00::1", "2001:db8::1"]
    );
}

#[test]
fn a_stun_server_is_reached_at_a_resolved_address_of_the_sockets_family() {
    let v6: std::net::SocketAddr = "[::1]:3478".parse().unwrap();
    let v4: std::net::SocketAddr = "127.0.0.1:3478".parse().unwrap();
    assert_eq!(
        super::pick_family([v6, v4], true),
        Some(v4),
        "an IPv4 socket was sent to an IPv6 server address"
    );
    assert_eq!(super::pick_family([v4, v6], false), Some(v6));
    assert_eq!(super::pick_family([v6], true), None);
}

/// Serve STUN binding requests on loopback, answering with the requester's
/// address; when `drop_first`, the first request is ignored, as a lossy path
/// would lose it.
async fn spawn_stun_server(drop_first: bool) -> std::net::SocketAddr {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind stun");
    let local = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let mut dropped = !drop_first;
        loop {
            let Ok((len, from)) = server.recv_from(&mut buf).await else {
                return;
            };
            if len < 20 {
                continue;
            }
            if !dropped {
                dropped = true;
                continue;
            }
            let txn_id: [u8; 12] = buf[8..20].try_into().unwrap();
            let std::net::SocketAddr::V4(from_v4) = from else {
                return;
            };
            let reply = build_binding_success(from_v4, &txn_id);
            let _ = server.send_to(&reply, from).await;
        }
    });
    local
}

/// An IPv4 traversal socket like the one the runtime binds.
fn ipv4_traversal_socket() -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

#[tokio::test]
async fn stun_observation_survives_one_lost_binding_request() {
    let timeout = std::time::Duration::from_secs(2);

    let healthy = spawn_stun_server(false).await;
    let (reflexive, _, _) = super::observe_traversal_addresses(
        &ipv4_traversal_socket(),
        &[healthy.to_string()],
        false,
        timeout,
    )
    .await
    .unwrap();
    assert!(reflexive.is_some(), "control: a lossless exchange succeeds");

    let lossy = spawn_stun_server(true).await;
    let started = std::time::Instant::now();
    let (reflexive, _, _) = super::observe_traversal_addresses(
        &ipv4_traversal_socket(),
        &[lossy.to_string()],
        false,
        timeout,
    )
    .await
    .unwrap();
    assert!(
        reflexive.is_some(),
        "one lost binding request lost the server: no reflexive address after {} ms",
        started.elapsed().as_millis()
    );
}
