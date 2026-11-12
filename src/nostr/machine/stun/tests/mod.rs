use super::parse_stun_binding_success;
use std::net::{IpAddr, Ipv4Addr};

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
