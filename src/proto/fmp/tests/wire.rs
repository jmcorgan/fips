//! Tests for the FMP link-framing wire codec.

use crate::proto::fmp::{Disconnect, DisconnectReason, HandshakeMessageType};

// ===== HandshakeMessageType Tests =====

#[test]
fn test_handshake_message_type_roundtrip() {
    let types = [
        HandshakeMessageType::NoiseIKMsg1,
        HandshakeMessageType::NoiseIKMsg2,
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
    assert!(HandshakeMessageType::from_byte(0x03).is_none());
    assert!(HandshakeMessageType::from_byte(0x10).is_none());
}

#[test]
fn test_handshake_message_type_is_handshake() {
    assert!(HandshakeMessageType::is_handshake(0x01));
    assert!(HandshakeMessageType::is_handshake(0x02));
    assert!(!HandshakeMessageType::is_handshake(0x00));
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
