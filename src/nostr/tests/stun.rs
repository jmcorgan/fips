//! Tests of `stun.rs`: `perform_stun`'s source check and its retransmission
//! against a loopback server, and the address-family filters on local
//! candidates and resolved server addresses (`offerable`, `pick_family`).

const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;

/// Build a STUN Binding Success header with the given message length and txn id.
fn build_success_header(message_length: u16, txn_id: &[u8; 12]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
    packet.extend_from_slice(&message_length.to_be_bytes());
    packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    packet.extend_from_slice(txn_id);
    packet
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
