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
