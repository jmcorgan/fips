//! Tests for the MMP report wire codecs (link-layer and session-layer).

use crate::proto::mmp::wire::{
    PATH_MTU_NOTIFICATION_SIZE, PathMtuNotification, RECEIVER_REPORT_PAYLOAD, RECEIVER_REPORT_SIZE,
    ReceiverReport, SENDER_REPORT_PAYLOAD, SENDER_REPORT_SIZE, SESSION_RECEIVER_REPORT_SIZE,
    SESSION_SENDER_REPORT_SIZE, SenderReport, SessionReceiverReport, SessionSenderReport,
};

// ===== Link-layer report tests (mmp/report.rs) =====

fn sample_sender_report() -> SenderReport {
    SenderReport {
        interval_packets_sent: 100,
        interval_bytes_sent: 50_000,
        cumulative_packets_sent: 10_000,
    }
}

fn sample_receiver_report() -> ReceiverReport {
    ReceiverReport {
        timestamp_echo: 5900,
        dwell_time: 5,
        highest_counter: 195,
        cumulative_packets_recv: 9_500,
        cumulative_bytes_recv: 4_750_000,
        jitter: 1200,
        ecn_ce_count: 0,
        owd_trend: -50,
        burst_loss_count: 2,
        cumulative_reorder_count: 10,
    }
}

#[test]
fn test_sender_report_encode_size() {
    let sr = sample_sender_report();
    let encoded = sr.encode();
    assert_eq!(encoded.len(), SENDER_REPORT_SIZE);
    assert_eq!(encoded[0], 0x01); // msg_type
    assert_eq!(encoded[1], 0x00); // format_version
    let total_len = u16::from_le_bytes([encoded[2], encoded[3]]);
    assert_eq!(total_len, SENDER_REPORT_PAYLOAD);
}

#[test]
fn test_sender_report_roundtrip() {
    let sr = sample_sender_report();
    let encoded = sr.encode();
    let decoded = SenderReport::decode(&encoded[1..]).unwrap();
    assert_eq!(sr, decoded);
}

#[test]
fn test_sender_report_too_short() {
    let result = SenderReport::decode(&[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn test_receiver_report_encode_size() {
    let rr = sample_receiver_report();
    let encoded = rr.encode();
    assert_eq!(encoded.len(), RECEIVER_REPORT_SIZE);
    assert_eq!(encoded[0], 0x02); // msg_type
    assert_eq!(encoded[1], 0x00); // format_version
    let total_len = u16::from_le_bytes([encoded[2], encoded[3]]);
    assert_eq!(total_len, RECEIVER_REPORT_PAYLOAD);
}

#[test]
fn test_receiver_report_roundtrip() {
    let rr = sample_receiver_report();
    let encoded = rr.encode();
    let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
    assert_eq!(rr, decoded);
}

#[test]
fn test_receiver_report_too_short() {
    let result = ReceiverReport::decode(&[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn test_sender_report_zero_values() {
    let sr = SenderReport {
        interval_packets_sent: 0,
        interval_bytes_sent: 0,
        cumulative_packets_sent: 0,
    };
    let encoded = sr.encode();
    let decoded = SenderReport::decode(&encoded[1..]).unwrap();
    assert_eq!(sr, decoded);
}

#[test]
fn test_receiver_report_max_values() {
    let rr = ReceiverReport {
        timestamp_echo: u32::MAX,
        dwell_time: u16::MAX,
        highest_counter: u64::MAX,
        cumulative_packets_recv: u64::MAX,
        cumulative_bytes_recv: u64::MAX,
        jitter: u32::MAX,
        ecn_ce_count: u32::MAX,
        owd_trend: i32::MAX,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: u32::MAX,
    };
    let encoded = rr.encode();
    let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
    assert_eq!(rr, decoded);
}

#[test]
fn test_receiver_report_negative_owd_trend() {
    let rr = ReceiverReport {
        owd_trend: -12345,
        ..sample_receiver_report()
    };
    let encoded = rr.encode();
    let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.owd_trend, -12345);
}

#[test]
fn test_sender_report_forward_compat_trailing_bytes() {
    let sr = sample_sender_report();
    let mut encoded = sr.encode();
    // Simulate a future version with extra trailing bytes:
    // bump total_length to include 4 extra bytes
    let new_total_len = SENDER_REPORT_PAYLOAD + 4;
    encoded[2..4].copy_from_slice(&new_total_len.to_le_bytes());
    encoded.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    // Decoder should skip trailing bytes and parse v0 fields
    let decoded = SenderReport::decode(&encoded[1..]).unwrap();
    assert_eq!(sr, decoded);
}

#[test]
fn test_receiver_report_forward_compat_trailing_bytes() {
    let rr = sample_receiver_report();
    let mut encoded = rr.encode();
    // Simulate a future version with extra trailing bytes
    let new_total_len = RECEIVER_REPORT_PAYLOAD + 8;
    encoded[2..4].copy_from_slice(&new_total_len.to_le_bytes());
    encoded.extend_from_slice(&[0x11; 8]);
    let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
    assert_eq!(rr, decoded);
}

#[test]
fn test_sender_report_v1_parsed_by_v0_decoder() {
    let sr = sample_sender_report();
    let mut encoded = sr.encode();
    // Set format_version = 1
    encoded[1] = 1;
    // Extend with hypothetical v1 fields (8 extra bytes)
    let new_total_len = SENDER_REPORT_PAYLOAD + 8;
    encoded[2..4].copy_from_slice(&new_total_len.to_le_bytes());
    encoded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    // v0 decoder parses known fields correctly
    let decoded = SenderReport::decode(&encoded[1..]).unwrap();
    assert_eq!(sr, decoded);
}

#[test]
fn test_receiver_report_v1_parsed_by_v0_decoder() {
    let rr = sample_receiver_report();
    let mut encoded = rr.encode();
    // Set format_version = 1
    encoded[1] = 1;
    // Extend with hypothetical v1 fields (12 extra bytes)
    let new_total_len = RECEIVER_REPORT_PAYLOAD + 12;
    encoded[2..4].copy_from_slice(&new_total_len.to_le_bytes());
    encoded.extend_from_slice(&[0xAB; 12]);
    // v0 decoder parses known fields correctly
    let decoded = ReceiverReport::decode(&encoded[1..]).unwrap();
    assert_eq!(rr, decoded);
}

#[test]
fn test_sender_report_v1_total_length_too_short() {
    let sr = sample_sender_report();
    let mut encoded = sr.encode();
    // Set format_version = 1 but total_length < v0 payload size
    encoded[1] = 1;
    let short_len: u16 = SENDER_REPORT_PAYLOAD - 2;
    encoded[2..4].copy_from_slice(&short_len.to_le_bytes());
    assert!(SenderReport::decode(&encoded[1..]).is_err());
}

#[test]
fn test_receiver_report_v1_total_length_too_short() {
    let rr = sample_receiver_report();
    let mut encoded = rr.encode();
    // Set format_version = 1 but total_length < v0 payload size
    encoded[1] = 1;
    let short_len: u16 = RECEIVER_REPORT_PAYLOAD - 4;
    encoded[2..4].copy_from_slice(&short_len.to_le_bytes());
    assert!(ReceiverReport::decode(&encoded[1..]).is_err());
}

// ===== Session-layer report tests (protocol/session.rs) =====
// ===== SessionSenderReport Tests =====

fn sample_session_sender_report() -> SessionSenderReport {
    SessionSenderReport {
        interval_packets_sent: 100,
        interval_bytes_sent: 50_000,
        cumulative_packets_sent: 10_000,
    }
}

#[test]
fn test_session_sender_report_encode_size() {
    let sr = sample_session_sender_report();
    let encoded = sr.encode();
    assert_eq!(encoded.len(), SESSION_SENDER_REPORT_SIZE);
}

#[test]
fn test_session_sender_report_roundtrip() {
    let sr = sample_session_sender_report();
    let encoded = sr.encode();
    let decoded = SessionSenderReport::decode(&encoded).unwrap();
    assert_eq!(sr, decoded);
}

#[test]
fn test_session_sender_report_too_short() {
    assert!(SessionSenderReport::decode(&[0u8; 10]).is_err());
}

// ===== SessionReceiverReport Tests =====

fn sample_session_receiver_report() -> SessionReceiverReport {
    SessionReceiverReport {
        timestamp_echo: 5900,
        dwell_time: 5,
        highest_counter: 195,
        cumulative_packets_recv: 9_500,
        cumulative_bytes_recv: 4_750_000,
        jitter: 1200,
        ecn_ce_count: 0,
        owd_trend: -50,
        burst_loss_count: 2,
        cumulative_reorder_count: 10,
    }
}

#[test]
fn test_session_receiver_report_encode_size() {
    let rr = sample_session_receiver_report();
    let encoded = rr.encode();
    assert_eq!(encoded.len(), SESSION_RECEIVER_REPORT_SIZE);
}

#[test]
fn test_session_receiver_report_roundtrip() {
    let rr = sample_session_receiver_report();
    let encoded = rr.encode();
    let decoded = SessionReceiverReport::decode(&encoded).unwrap();
    assert_eq!(rr, decoded);
}

#[test]
fn test_session_receiver_report_too_short() {
    assert!(SessionReceiverReport::decode(&[0u8; 10]).is_err());
}

#[test]
fn test_session_receiver_report_negative_owd_trend() {
    let rr = SessionReceiverReport {
        owd_trend: -12345,
        ..sample_session_receiver_report()
    };
    let encoded = rr.encode();
    let decoded = SessionReceiverReport::decode(&encoded).unwrap();
    assert_eq!(decoded.owd_trend, -12345);
}

// ===== PathMtuNotification Tests =====

#[test]
fn test_path_mtu_notification_encode_size() {
    let n = PathMtuNotification::new(1400);
    let encoded = n.encode();
    assert_eq!(encoded.len(), PATH_MTU_NOTIFICATION_SIZE);
}

#[test]
fn test_path_mtu_notification_roundtrip() {
    let n = PathMtuNotification::new(1400);
    let encoded = n.encode();
    let decoded = PathMtuNotification::decode(&encoded).unwrap();
    assert_eq!(decoded.path_mtu, 1400);
}

#[test]
fn test_path_mtu_notification_too_short() {
    assert!(PathMtuNotification::decode(&[]).is_err());
    assert!(PathMtuNotification::decode(&[0x00]).is_err());
}

#[test]
fn test_path_mtu_notification_boundary_values() {
    for mtu in [0u16, 1280, 1500, u16::MAX] {
        let n = PathMtuNotification::new(mtu);
        let encoded = n.encode();
        let decoded = PathMtuNotification::decode(&encoded).unwrap();
        assert_eq!(decoded.path_mtu, mtu);
    }
}
