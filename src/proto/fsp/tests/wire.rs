//! Tests for the FSP session wire codec and message types.

use crate::NodeAddr;
use crate::proto::fsp::wire::*;
use crate::proto::stp::TreeCoordinate;

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

// ===== SessionMessageType Tests =====

#[test]
fn test_session_message_type_roundtrip() {
    let types = [
        SessionMessageType::DataPacket,
        SessionMessageType::SenderReport,
        SessionMessageType::ReceiverReport,
        SessionMessageType::PathMtuNotification,
        SessionMessageType::CoordsWarmup,
    ];

    for ty in types {
        let byte = ty.to_byte();
        let restored = SessionMessageType::from_byte(byte);
        assert_eq!(restored, Some(ty));
    }
}

#[test]
fn test_session_message_type_invalid() {
    assert!(SessionMessageType::from_byte(0xFF).is_none());
    assert!(SessionMessageType::from_byte(0x99).is_none());
    // The 0x20-0x2F routing-signal range is no longer part of this enum.
    assert!(SessionMessageType::from_byte(0x20).is_none());
    assert!(SessionMessageType::from_byte(0x22).is_none());
}

// ===== SessionFlags Tests =====

#[test]
fn test_session_flags() {
    let flags = SessionFlags::new().with_ack().bidirectional();

    assert!(flags.request_ack);
    assert!(flags.bidirectional);

    let byte = flags.to_byte();
    let restored = SessionFlags::from_byte(byte);

    assert_eq!(flags, restored);
}

#[test]
fn test_session_flags_default() {
    let flags = SessionFlags::new();
    assert!(!flags.request_ack);
    assert!(!flags.bidirectional);
    assert_eq!(flags.to_byte(), 0);
}

// ===== SessionSetup Tests =====

#[test]
fn test_session_setup() {
    let setup = SessionSetup::new(make_coords(&[1, 0]), make_coords(&[2, 0]))
        .with_flags(SessionFlags::new().with_ack());

    assert!(setup.flags.request_ack);
    assert!(!setup.flags.bidirectional);
}

// ===== Encode/Decode Roundtrip Tests =====

#[test]
fn test_session_setup_encode_decode() {
    let handshake = vec![0xAA; 82]; // typical Noise IK msg1
    let setup = SessionSetup::new(make_coords(&[1, 2, 0]), make_coords(&[3, 4, 0]))
        .with_flags(SessionFlags::new().with_ack().bidirectional())
        .with_handshake(handshake.clone());

    let encoded = setup.encode();

    // Verify FSP prefix: ver_phase=0x01 (version 0, phase MSG1)
    assert_eq!(encoded[0], 0x01);
    assert_eq!(encoded[1], 0x00); // flags = 0 for handshake
    let payload_len = u16::from_le_bytes([encoded[2], encoded[3]]);
    assert_eq!(payload_len as usize, encoded.len() - 4);

    // Decode (skip 4-byte FSP prefix)
    let decoded = SessionSetup::decode(&encoded[4..]).unwrap();

    assert_eq!(decoded.flags, setup.flags);
    assert_eq!(decoded.src_coords, setup.src_coords);
    assert_eq!(decoded.dest_coords, setup.dest_coords);
    assert_eq!(decoded.handshake_payload, handshake);
}

#[test]
fn test_session_setup_no_handshake() {
    let setup = SessionSetup::new(make_coords(&[5, 0]), make_coords(&[6, 0]));

    let encoded = setup.encode();
    let decoded = SessionSetup::decode(&encoded[4..]).unwrap();

    assert!(decoded.handshake_payload.is_empty());
    assert_eq!(decoded.src_coords, setup.src_coords);
    assert_eq!(decoded.dest_coords, setup.dest_coords);
}

#[test]
fn test_session_ack_encode_decode() {
    let handshake = vec![0xBB; 33]; // typical Noise IK msg2
    let ack = SessionAck::new(make_coords(&[7, 8, 0]), make_coords(&[3, 4, 0]))
        .with_handshake(handshake.clone());

    let encoded = ack.encode();
    // Verify FSP prefix: ver_phase=0x02 (version 0, phase MSG2)
    assert_eq!(encoded[0], 0x02);
    assert_eq!(encoded[1], 0x00); // flags = 0 for handshake

    let decoded = SessionAck::decode(&encoded[4..]).unwrap();
    assert_eq!(decoded.src_coords, ack.src_coords);
    assert_eq!(decoded.dest_coords, ack.dest_coords);
    assert_eq!(decoded.handshake_payload, handshake);
}

#[test]
fn test_session_setup_decode_too_short() {
    assert!(SessionSetup::decode(&[]).is_err());
}

#[test]
fn test_session_ack_decode_too_short() {
    assert!(SessionAck::decode(&[]).is_err());
}

#[test]
fn test_session_setup_deep_coords() {
    // Depth-10 coordinate (11 entries: self + 10 ancestors)
    let addrs: Vec<u8> = (0..11).collect();
    let src = make_coords(&addrs);
    let dest = make_coords(&[20, 21, 22, 23, 24]);
    let setup = SessionSetup::new(src.clone(), dest.clone()).with_handshake(vec![0x55; 82]);

    let encoded = setup.encode();
    let decoded = SessionSetup::decode(&encoded[4..]).unwrap();

    assert_eq!(decoded.src_coords, src);
    assert_eq!(decoded.dest_coords, dest);
}

// ===== FspFlags Tests =====

#[test]
fn test_fsp_flags_default() {
    let flags = FspFlags::new();
    assert!(!flags.coords_present);
    assert!(!flags.key_epoch);
    assert!(!flags.unencrypted);
    assert_eq!(flags.to_byte(), 0x00);
}

#[test]
fn test_fsp_flags_roundtrip() {
    // All combinations of 3 bits
    for byte in 0u8..=0x07 {
        let flags = FspFlags::from_byte(byte);
        assert_eq!(flags.to_byte(), byte);
    }
}

#[test]
fn test_fsp_flags_individual_bits() {
    let cp = FspFlags::from_byte(0x01);
    assert!(cp.coords_present);
    assert!(!cp.key_epoch);
    assert!(!cp.unencrypted);

    let k = FspFlags::from_byte(0x02);
    assert!(!k.coords_present);
    assert!(k.key_epoch);
    assert!(!k.unencrypted);

    let u = FspFlags::from_byte(0x04);
    assert!(!u.coords_present);
    assert!(!u.key_epoch);
    assert!(u.unencrypted);
}

#[test]
fn test_fsp_flags_ignores_reserved_bits() {
    // Reserved bits in upper 5 bits are not preserved
    let flags = FspFlags::from_byte(0xFF);
    assert!(flags.coords_present);
    assert!(flags.key_epoch);
    assert!(flags.unencrypted);
    assert_eq!(flags.to_byte(), 0x07); // only lower 3 bits
}

// ===== FspInnerFlags Tests =====

#[test]
fn test_fsp_inner_flags_default() {
    let flags = FspInnerFlags::new();
    assert!(!flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x00);
}

#[test]
fn test_fsp_inner_flags_roundtrip() {
    let flags = FspInnerFlags::from_byte(0x01);
    assert!(flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x01);

    let flags = FspInnerFlags::from_byte(0x00);
    assert!(!flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x00);
}

#[test]
fn test_fsp_inner_flags_ignores_reserved() {
    let flags = FspInnerFlags::from_byte(0xFE);
    assert!(!flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x00);

    let flags = FspInnerFlags::from_byte(0xFF);
    assert!(flags.spin_bit);
    assert_eq!(flags.to_byte(), 0x01);
}

// ===== New SessionMessageType Values =====

#[test]
fn test_session_message_type_new_values() {
    assert_eq!(SessionMessageType::SenderReport.to_byte(), 0x11);
    assert_eq!(SessionMessageType::ReceiverReport.to_byte(), 0x12);
    assert_eq!(SessionMessageType::PathMtuNotification.to_byte(), 0x13);
}

#[test]
fn test_session_message_type_display() {
    assert_eq!(
        format!("{}", SessionMessageType::SenderReport),
        "SenderReport"
    );
    assert_eq!(
        format!("{}", SessionMessageType::ReceiverReport),
        "ReceiverReport"
    );
    assert_eq!(
        format!("{}", SessionMessageType::PathMtuNotification),
        "PathMtuNotification"
    );
}

// (The 0x20-0x2F routing-signal types — CoordsRequired/PathBroken/MtuExceeded
// — moved to `RoutingSignalType`; their tests live in the routing subsystem.)

// ===== SessionMsg3 Tests =====

#[test]
fn test_session_msg3_encode_decode() {
    let handshake = vec![0xCC; 73]; // typical XK msg3
    let msg3 = SessionMsg3::new(handshake.clone());

    let encoded = msg3.encode();
    // Verify FSP prefix: ver_phase=0x03 (version 0, phase MSG3)
    assert_eq!(encoded[0], 0x03);
    assert_eq!(encoded[1], 0x00); // flags = 0 for handshake
    let payload_len = u16::from_le_bytes([encoded[2], encoded[3]]);
    assert_eq!(payload_len as usize, encoded.len() - 4);

    // Decode (skip 4-byte FSP prefix)
    let decoded = SessionMsg3::decode(&encoded[4..]).unwrap();
    assert_eq!(decoded.flags, 0);
    assert_eq!(decoded.handshake_payload, handshake);
}

#[test]
fn test_session_msg3_decode_too_short() {
    assert!(SessionMsg3::decode(&[]).is_err());
    assert!(SessionMsg3::decode(&[0x00]).is_err()); // flags only, no hs_len
}

#[test]
fn test_session_msg3_empty_handshake() {
    let msg3 = SessionMsg3::new(vec![]);
    let encoded = msg3.encode();
    let decoded = SessionMsg3::decode(&encoded[4..]).unwrap();
    assert!(decoded.handshake_payload.is_empty());
}

// ===== Size Constant Tests =====

#[test]
fn test_wire_sizes() {
    assert_eq!(FSP_COMMON_PREFIX_SIZE, 4);
    assert_eq!(FSP_HEADER_SIZE, 12);
    assert_eq!(FSP_INNER_HEADER_SIZE, 6);
    assert_eq!(FSP_ENCRYPTED_MIN_SIZE, 28); // 12 + 16
}

// ===== Common Prefix Tests =====

#[test]
fn test_common_prefix_parse_established() {
    let data = [0x00, 0x01, 0x40, 0x00]; // ver=0, phase=0, flags=CP, payload_len=64
    let prefix = FspCommonPrefix::parse(&data).unwrap();
    assert_eq!(prefix.version, 0);
    assert_eq!(prefix.phase, FSP_PHASE_ESTABLISHED);
    assert_eq!(prefix.flags, FSP_FLAG_CP);
    assert_eq!(prefix.payload_len, 64);
    assert!(prefix.has_coords());
    assert!(!prefix.is_unencrypted());
}

#[test]
fn test_common_prefix_parse_handshake() {
    let data = [0x01, 0x00, 0x50, 0x00]; // ver=0, phase=1, flags=0, payload_len=80
    let prefix = FspCommonPrefix::parse(&data).unwrap();
    assert_eq!(prefix.version, 0);
    assert_eq!(prefix.phase, FSP_PHASE_MSG1);
    assert_eq!(prefix.flags, 0);
    assert_eq!(prefix.payload_len, 80);
}

#[test]
fn test_common_prefix_parse_error_signal() {
    let data = [0x00, FSP_FLAG_U, 0x22, 0x00]; // ver=0, phase=0, U flag, payload_len=34
    let prefix = FspCommonPrefix::parse(&data).unwrap();
    assert_eq!(prefix.phase, FSP_PHASE_ESTABLISHED);
    assert!(prefix.is_unencrypted());
    assert_eq!(prefix.payload_len, 34);
}

#[test]
fn test_common_prefix_too_short() {
    assert!(FspCommonPrefix::parse(&[0, 0, 0]).is_none());
}

// ===== Encrypted Header Tests =====

#[test]
fn test_encrypted_header_parse() {
    let counter = 42u64;
    let flags = FSP_FLAG_CP;
    let payload_len = 100u16;
    let header = build_fsp_header(counter, flags, payload_len);

    // Build a minimal packet: header + 16 bytes of fake ciphertext (tag)
    let mut packet = Vec::from(header);
    packet.extend_from_slice(&[0xaa; TAG_SIZE]);

    let parsed = FspEncryptedHeader::parse(&packet).unwrap();
    assert_eq!(parsed.counter, 42);
    assert_eq!(parsed.flags, FSP_FLAG_CP);
    assert_eq!(parsed.payload_len, 100);
    assert!(parsed.has_coords());
    assert_eq!(parsed.header_bytes, header);
    assert_eq!(parsed.data_offset(), FSP_HEADER_SIZE);
}

#[test]
fn test_encrypted_header_too_short() {
    let packet = vec![0x00; FSP_ENCRYPTED_MIN_SIZE - 1];
    assert!(FspEncryptedHeader::parse(&packet).is_none());
}

#[test]
fn test_encrypted_header_wrong_phase() {
    let mut packet = vec![0x00; FSP_ENCRYPTED_MIN_SIZE];
    packet[0] = 0x01; // phase 1 (msg1), not established
    assert!(FspEncryptedHeader::parse(&packet).is_none());
}

#[test]
fn test_encrypted_header_wrong_version() {
    let mut packet = vec![0x00; FSP_ENCRYPTED_MIN_SIZE];
    packet[0] = 0x10; // version 1, phase 0
    assert!(FspEncryptedHeader::parse(&packet).is_none());
}

#[test]
fn test_encrypted_header_u_flag_rejected() {
    let mut packet = vec![0x00; FSP_ENCRYPTED_MIN_SIZE];
    packet[1] = FSP_FLAG_U; // U flag set → not encrypted
    assert!(FspEncryptedHeader::parse(&packet).is_none());
}

// ===== Build Header Tests =====

#[test]
fn test_build_fsp_header() {
    let header = build_fsp_header(1000, FSP_FLAG_CP, 200);
    assert_eq!(header[0], 0x00); // ver=0, phase=0
    assert_eq!(header[1], FSP_FLAG_CP);
    assert_eq!(u16::from_le_bytes([header[2], header[3]]), 200);
    assert_eq!(
        u64::from_le_bytes([
            header[4], header[5], header[6], header[7], header[8], header[9], header[10],
            header[11],
        ]),
        1000
    );
}

#[test]
fn test_build_fsp_encrypted() {
    let header = build_fsp_header(0, 0, 10);
    let ciphertext = vec![0xCC; 26]; // 10 payload + 16 tag
    let packet = build_fsp_encrypted(&header, &ciphertext);
    assert_eq!(packet.len(), FSP_HEADER_SIZE + 26);
    assert_eq!(&packet[..FSP_HEADER_SIZE], &header);
    assert_eq!(&packet[FSP_HEADER_SIZE..], &ciphertext[..]);
}

// ===== Handshake Prefix Tests =====

#[test]
fn test_build_fsp_handshake_prefix_msg1() {
    let prefix = build_fsp_handshake_prefix(FSP_PHASE_MSG1, 100);
    assert_eq!(prefix[0], 0x01); // ver=0, phase=1
    assert_eq!(prefix[1], 0x00); // flags zero
    assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 100);

    let parsed = FspCommonPrefix::parse(&prefix).unwrap();
    assert_eq!(parsed.phase, FSP_PHASE_MSG1);
}

#[test]
fn test_build_fsp_handshake_prefix_msg2() {
    let prefix = build_fsp_handshake_prefix(FSP_PHASE_MSG2, 50);
    assert_eq!(prefix[0], 0x02); // ver=0, phase=2
    assert_eq!(prefix[1], 0x00);
    assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 50);
}

#[test]
fn test_build_fsp_handshake_prefix_msg3() {
    let prefix = build_fsp_handshake_prefix(FSP_PHASE_MSG3, 73);
    assert_eq!(prefix[0], 0x03); // ver=0, phase=3
    assert_eq!(prefix[1], 0x00); // flags zero
    assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 73);

    let parsed = FspCommonPrefix::parse(&prefix).unwrap();
    assert_eq!(parsed.phase, FSP_PHASE_MSG3);
}

// ===== Error Prefix Tests =====

#[test]
fn test_build_fsp_error_prefix() {
    let prefix = build_fsp_error_prefix(34);
    assert_eq!(prefix[0], 0x00); // ver=0, phase=0
    assert_eq!(prefix[1], FSP_FLAG_U);
    assert_eq!(u16::from_le_bytes([prefix[2], prefix[3]]), 34);

    let parsed = FspCommonPrefix::parse(&prefix).unwrap();
    assert!(parsed.is_unencrypted());
    assert_eq!(parsed.phase, FSP_PHASE_ESTABLISHED);
}

// ===== Inner Header Tests =====

#[test]
fn test_inner_header_prepend_strip() {
    let timestamp: u32 = 12345;
    let msg_type: u8 = 0x10;
    let inner_flags: u8 = 0x01; // SP bit
    let payload = vec![0xAA, 0xBB, 0xCC];

    let with_header = fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &payload);
    assert_eq!(with_header.len(), FSP_INNER_HEADER_SIZE + 3);

    let (ts, mt, flags, rest) = fsp_strip_inner_header(&with_header).unwrap();
    assert_eq!(ts, 12345);
    assert_eq!(mt, 0x10);
    assert_eq!(flags, 0x01);
    assert_eq!(rest, &payload[..]);
}

#[test]
fn test_inner_header_empty_payload() {
    let with_header = fsp_prepend_inner_header(0, 0x13, 0, &[]);
    assert_eq!(with_header.len(), FSP_INNER_HEADER_SIZE);

    let (ts, mt, flags, rest) = fsp_strip_inner_header(&with_header).unwrap();
    assert_eq!(ts, 0);
    assert_eq!(mt, 0x13);
    assert_eq!(flags, 0);
    assert!(rest.is_empty());
}

#[test]
fn test_inner_header_too_short() {
    assert!(fsp_strip_inner_header(&[0, 0, 0, 0, 0]).is_none()); // needs 6 bytes
    assert!(fsp_strip_inner_header(&[]).is_none());
}

// ===== Flag Constants Tests =====

#[test]
fn test_flag_bits_distinct() {
    // Cleartext flags don't overlap
    assert_eq!(FSP_FLAG_CP & FSP_FLAG_K, 0);
    assert_eq!(FSP_FLAG_CP & FSP_FLAG_U, 0);
    assert_eq!(FSP_FLAG_K & FSP_FLAG_U, 0);
}

#[test]
fn test_header_roundtrip() {
    let counter = 0xDEADBEEF_12345678u64;
    let flags = FSP_FLAG_CP | FSP_FLAG_K;
    let payload_len = 1234u16;

    let header = build_fsp_header(counter, flags, payload_len);
    let ciphertext = vec![0xFF; payload_len as usize + TAG_SIZE];
    let packet = build_fsp_encrypted(&header, &ciphertext);

    let parsed = FspEncryptedHeader::parse(&packet).unwrap();
    assert_eq!(parsed.counter, counter);
    assert_eq!(parsed.flags, flags);
    assert_eq!(parsed.payload_len, payload_len);
    assert!(parsed.has_coords());
    assert_eq!(parsed.header_bytes, header);
}

#[test]
fn test_all_message_types_through_prefix() {
    // Encrypted (phase 0, no U)
    let prefix = FspCommonPrefix::parse(&[0x00, 0x00, 0x10, 0x00]).unwrap();
    assert_eq!(prefix.phase, 0);
    assert!(!prefix.is_unencrypted());

    // Error signal (phase 0, U set)
    let prefix = FspCommonPrefix::parse(&[0x00, FSP_FLAG_U, 0x22, 0x00]).unwrap();
    assert_eq!(prefix.phase, 0);
    assert!(prefix.is_unencrypted());

    // SessionSetup (phase 1)
    let prefix = FspCommonPrefix::parse(&[0x01, 0x00, 0x50, 0x00]).unwrap();
    assert_eq!(prefix.phase, 1);

    // SessionAck (phase 2)
    let prefix = FspCommonPrefix::parse(&[0x02, 0x00, 0x21, 0x00]).unwrap();
    assert_eq!(prefix.phase, 2);

    // SessionMsg3 (phase 3)
    let prefix = FspCommonPrefix::parse(&[0x03, 0x00, 0x49, 0x00]).unwrap();
    assert_eq!(prefix.phase, 3);
}
