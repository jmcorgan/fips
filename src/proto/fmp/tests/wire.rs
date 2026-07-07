//! Tests for the FMP wire codec: XX handshake framing, orderly disconnect,
//! and the negotiation payload.

use super::super::wire::NEGOTIATION_HEADER_SIZE;
use crate::proto::fmp::{
    Disconnect, DisconnectReason, HandshakeMessageType, NegotiationPayload, NodeProfile,
};

// ===== HandshakeMessageType Tests =====

#[test]
fn test_handshake_message_type_roundtrip() {
    let types = [
        HandshakeMessageType::Msg1,
        HandshakeMessageType::Msg2,
        HandshakeMessageType::Msg3,
    ];

    for ty in types {
        let byte = ty.to_byte();
        let restored = HandshakeMessageType::from_byte(byte);
        assert_eq!(restored, Some(ty));
    }
}

#[test]
fn test_handshake_message_type_invalid() {
    assert!(HandshakeMessageType::from_byte(0x00).is_none());
    assert!(HandshakeMessageType::from_byte(0x04).is_none());
    assert!(HandshakeMessageType::from_byte(0x10).is_none());
}

#[test]
fn test_handshake_message_type_is_handshake() {
    assert!(HandshakeMessageType::is_handshake(0x01));
    assert!(HandshakeMessageType::is_handshake(0x02));
    assert!(HandshakeMessageType::is_handshake(0x03));
    assert!(!HandshakeMessageType::is_handshake(0x00));
    assert!(!HandshakeMessageType::is_handshake(0x04));
    assert!(!HandshakeMessageType::is_handshake(0x10));
}

// ===== DisconnectReason Tests =====

#[test]
fn test_disconnect_reason_roundtrip() {
    let reasons = [
        DisconnectReason::Shutdown,
        DisconnectReason::Restart,
        DisconnectReason::ProtocolError,
        DisconnectReason::TransportFailure,
        DisconnectReason::ResourceExhaustion,
        DisconnectReason::SecurityViolation,
        DisconnectReason::ConfigurationChange,
        DisconnectReason::Timeout,
        DisconnectReason::Other,
    ];

    for reason in reasons {
        let byte = reason.to_byte();
        let restored = DisconnectReason::from_byte(byte);
        assert_eq!(restored, Some(reason));
    }
}

#[test]
fn test_disconnect_reason_unknown_byte() {
    assert!(DisconnectReason::from_byte(0x08).is_none());
    assert!(DisconnectReason::from_byte(0x80).is_none());
    assert!(DisconnectReason::from_byte(0xFE).is_none());
}

// ===== Disconnect Message Tests =====

#[test]
fn test_disconnect_encode_decode() {
    let msg = Disconnect::new(DisconnectReason::Shutdown);
    let encoded = msg.encode();

    assert_eq!(encoded.len(), 2);
    assert_eq!(encoded[0], 0x50); // LinkMessageType::Disconnect
    assert_eq!(encoded[1], 0x00); // DisconnectReason::Shutdown

    // Decode from payload (after msg_type byte)
    let decoded = Disconnect::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.reason, DisconnectReason::Shutdown);
}

#[test]
fn test_disconnect_all_reasons() {
    let reasons = [
        DisconnectReason::Shutdown,
        DisconnectReason::Restart,
        DisconnectReason::ProtocolError,
        DisconnectReason::Other,
    ];

    for reason in reasons {
        let msg = Disconnect::new(reason);
        let encoded = msg.encode();
        let decoded = Disconnect::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.reason, reason);
    }
}

#[test]
fn test_disconnect_decode_empty_payload() {
    let result = Disconnect::decode(&[]);
    assert!(result.is_err());
}

#[test]
fn test_disconnect_decode_unknown_reason() {
    let decoded = Disconnect::decode(&[0x80]).unwrap();
    assert_eq!(decoded.reason, DisconnectReason::Other);
}

// ===== Negotiation payload codec Tests =====

#[test]
fn test_encode_decode_roundtrip() {
    let payload = NegotiationPayload::new(1, 3, 0x00000000_0000002A);
    let encoded = payload.encode();
    assert_eq!(encoded.len(), NEGOTIATION_HEADER_SIZE);

    let decoded = NegotiationPayload::decode(&encoded).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn test_encode_decode_with_tlv() {
    let payload = NegotiationPayload::new(0, 1, 0)
        .with_tlv(1, vec![0xAA, 0xBB])
        .with_tlv(256, vec![0x01, 0x02, 0x03, 0x04]);

    let encoded = payload.encode();
    // 10 header + (2+2+2) + (2+2+4) = 10 + 6 + 8 = 24
    assert_eq!(encoded.len(), 24);

    let decoded = NegotiationPayload::decode(&encoded).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(decoded.tlv_entries.len(), 2);
    assert_eq!(decoded.tlv_entries[0].field_num, 1);
    assert_eq!(decoded.tlv_entries[0].value, vec![0xAA, 0xBB]);
    assert_eq!(decoded.tlv_entries[1].field_num, 256);
    assert_eq!(decoded.tlv_entries[1].value, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_unknown_format_rejected() {
    let mut data = NegotiationPayload::new(0, 0, 0).encode();
    data[0] = 1; // Set format to 1
    assert!(NegotiationPayload::decode(&data).is_err());
}

#[test]
fn test_invalid_version_range() {
    let mut data = NegotiationPayload::new(0, 0, 0).encode();
    // Set version_min=5, version_max=3 (invalid: min > max)
    data[1] = (5 << 4) | 3;
    assert!(NegotiationPayload::decode(&data).is_err());
}

#[test]
fn test_unknown_tlv_forward_compat() {
    // Unknown field_nums should be preserved through encode/decode
    let payload = NegotiationPayload::new(0, 1, 0).with_tlv(9999, vec![0xFF, 0xFE, 0xFD]);

    let encoded = payload.encode();
    let decoded = NegotiationPayload::decode(&encoded).unwrap();
    assert_eq!(decoded.tlv_entries.len(), 1);
    assert_eq!(decoded.tlv_entries[0].field_num, 9999);
    assert_eq!(decoded.tlv_entries[0].value, vec![0xFF, 0xFE, 0xFD]);
}

#[test]
fn test_empty_payload() {
    let payload = NegotiationPayload::new(0, 0, 0);
    let encoded = payload.encode();
    assert_eq!(encoded.len(), NEGOTIATION_HEADER_SIZE);

    let decoded = NegotiationPayload::decode(&encoded).unwrap();
    assert_eq!(decoded.version_min, 0);
    assert_eq!(decoded.version_max, 0);
    assert_eq!(decoded.features, 0);
    assert!(decoded.tlv_entries.is_empty());
}

#[test]
fn test_truncated_payload() {
    // Less than header size
    assert!(NegotiationPayload::decode(&[0u8; 5]).is_err());
    assert!(NegotiationPayload::decode(&[]).is_err());
}

#[test]
fn test_truncated_tlv() {
    let payload = NegotiationPayload::new(0, 1, 0).with_tlv(1, vec![0xAA, 0xBB, 0xCC]);
    let mut encoded = payload.encode();

    // Truncate the TLV value (remove last byte)
    encoded.pop();
    assert!(NegotiationPayload::decode(&encoded).is_err());

    // Truncate to just partial TLV header (only 2 of 4 header bytes)
    let mut partial = NegotiationPayload::new(0, 1, 0).encode();
    partial.extend_from_slice(&[0x01, 0x00]); // Only field_num, no length
    assert!(NegotiationPayload::decode(&partial).is_err());
}

#[test]
fn test_node_profile_try_from() {
    assert_eq!(NodeProfile::try_from(0).unwrap(), NodeProfile::Full);
    assert_eq!(NodeProfile::try_from(1).unwrap(), NodeProfile::NonRouting);
    assert_eq!(NodeProfile::try_from(2).unwrap(), NodeProfile::Leaf);
    assert!(NodeProfile::try_from(3).is_err());
    assert!(NodeProfile::try_from(7).is_err());
}
