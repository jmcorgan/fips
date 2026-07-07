//! Tests for the MMP report wire codecs (link-layer and session-layer).

use crate::proto::mmp::wire::{
    PATH_MTU_NOTIFICATION_SIZE, PathMtuNotification, ReceiverReport, SESSION_RECEIVER_REPORT_SIZE,
    SESSION_SENDER_REPORT_SIZE, SenderReport, SessionReceiverReport, SessionSenderReport,
};

// ===== Link-layer report tests (mmp/report.rs) =====

fn sample_sender_report() -> SenderReport {
    SenderReport {
        interval_start_counter: 100,
        interval_end_counter: 200,
        interval_start_timestamp: 5000,
        interval_end_timestamp: 6000,
        interval_bytes_sent: 50_000,
        cumulative_packets_sent: 10_000,
        cumulative_bytes_sent: 5_000_000,
    }
}

fn sample_receiver_report() -> ReceiverReport {
    ReceiverReport {
        highest_counter: 195,
        cumulative_packets_recv: 9_500,
        cumulative_bytes_recv: 4_750_000,
        timestamp_echo: 5900,
        dwell_time: 5,
        max_burst_loss: 3,
        mean_burst_loss: 384, // 1.5 in u8.8
        jitter: 1200,
        ecn_ce_count: 0,
        owd_trend: -50,
        burst_loss_count: 2,
        cumulative_reorder_count: 10,
        interval_packets_recv: 95,
        interval_bytes_recv: 47_500,
    }
}

#[test]
fn test_sender_report_encode_size() {
    let sr = sample_sender_report();
    let encoded = sr.encode();
    assert_eq!(encoded.len(), 48);
    assert_eq!(encoded[0], 0x01); // msg_type
}

#[test]
fn test_sender_report_roundtrip() {
    let sr = sample_sender_report();
    let encoded = sr.encode();
    // decode expects payload after msg_type
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
    assert_eq!(encoded.len(), 68);
    assert_eq!(encoded[0], 0x02); // msg_type
}

#[test]
fn test_receiver_report_roundtrip() {
    let rr = sample_receiver_report();
    let encoded = rr.encode();
    // decode expects payload after msg_type
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
        interval_start_counter: 0,
        interval_end_counter: 0,
        interval_start_timestamp: 0,
        interval_end_timestamp: 0,
        interval_bytes_sent: 0,
        cumulative_packets_sent: 0,
        cumulative_bytes_sent: 0,
    };
    let encoded = sr.encode();
    let decoded = SenderReport::decode(&encoded[1..]).unwrap();
    assert_eq!(sr, decoded);
}

#[test]
fn test_receiver_report_max_values() {
    let rr = ReceiverReport {
        highest_counter: u64::MAX,
        cumulative_packets_recv: u64::MAX,
        cumulative_bytes_recv: u64::MAX,
        timestamp_echo: u32::MAX,
        dwell_time: u16::MAX,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: u32::MAX,
        owd_trend: i32::MAX,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: u32::MAX,
        interval_packets_recv: u32::MAX,
        interval_bytes_recv: u32::MAX,
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

// ===== Session-layer report tests (protocol/session.rs) =====

fn sample_session_sender_report() -> SessionSenderReport {
    SessionSenderReport {
        interval_start_counter: 100,
        interval_end_counter: 200,
        interval_start_timestamp: 5000,
        interval_end_timestamp: 6000,
        interval_bytes_sent: 50_000,
        cumulative_packets_sent: 10_000,
        cumulative_bytes_sent: 5_000_000,
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

fn sample_session_receiver_report() -> SessionReceiverReport {
    SessionReceiverReport {
        highest_counter: 195,
        cumulative_packets_recv: 9_500,
        cumulative_bytes_recv: 4_750_000,
        timestamp_echo: 5900,
        dwell_time: 5,
        max_burst_loss: 3,
        mean_burst_loss: 384,
        jitter: 1200,
        ecn_ce_count: 0,
        owd_trend: -50,
        burst_loss_count: 2,
        cumulative_reorder_count: 10,
        interval_packets_recv: 95,
        interval_bytes_recv: 47_500,
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
