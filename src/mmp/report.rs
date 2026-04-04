//! MMP report wire format: SenderReport and ReceiverReport.
//!
//! Serialization and deserialization for the two report types exchanged
//! between link-layer peers. Wire format uses an extensibility header:
//! `[msg_type:1][format_version:1][total_length:2 LE]` followed by payload.
//! Format version 0 defines the slim layouts below. Decoders skip unknown
//! trailing bytes via total_length for forward compatibility.

use crate::protocol::ProtocolError;

/// Current format version for MMP reports.
const FORMAT_VERSION: u8 = 0;

// ============================================================================
// SenderReport (msg_type 0x01, 20 bytes total)
// ============================================================================

/// Link-layer sender report.
///
/// Wire layout (20 bytes total, sent as link message):
/// ```text
/// [0]     msg_type = 0x01
/// [1]     format_version = 0
/// [2-3]   total_length: u16 LE (= 16, payload bytes after this field)
/// [4-7]   interval_packets_sent: u32 LE
/// [8-11]  interval_bytes_sent: u32 LE
/// [12-19] cumulative_packets_sent: u64 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    pub interval_packets_sent: u32,
    pub interval_bytes_sent: u32,
    pub cumulative_packets_sent: u64,
}

/// Total wire size for SenderReport.
pub const SENDER_REPORT_SIZE: usize = 20;

/// Payload size after total_length field for SenderReport format v0.
const SENDER_REPORT_PAYLOAD: u16 = 16;

/// ReceiverReport (msg_type 0x02, 54 bytes total)
///
/// Wire layout (54 bytes total, sent as link message):
/// ```text
/// [0]     msg_type = 0x02
/// [1]     format_version = 0
/// [2-3]   total_length: u16 LE (= 50, payload bytes after this field)
/// [4-7]   timestamp_echo: u32 LE
/// [8-9]   dwell_time: u16 LE
/// [10-17] highest_counter: u64 LE
/// [18-25] cumulative_packets_recv: u64 LE
/// [26-33] cumulative_bytes_recv: u64 LE
/// [34-37] jitter: u32 LE (microseconds)
/// [38-41] ecn_ce_count: u32 LE
/// [42-45] owd_trend: i32 LE (µs/s)
/// [46-49] burst_loss_count: u32 LE
/// [50-53] cumulative_reorder_count: u32 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    pub timestamp_echo: u32,
    pub dwell_time: u16,
    pub highest_counter: u64,
    pub cumulative_packets_recv: u64,
    pub cumulative_bytes_recv: u64,
    pub jitter: u32,
    pub ecn_ce_count: u32,
    pub owd_trend: i32,
    pub burst_loss_count: u32,
    pub cumulative_reorder_count: u32,
}

/// Total wire size for ReceiverReport.
pub const RECEIVER_REPORT_SIZE: usize = 54;

/// Payload size after total_length field for ReceiverReport format v0.
const RECEIVER_REPORT_PAYLOAD: u16 = 50;

impl SenderReport {
    /// Encode to wire format (20 bytes: header + payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SENDER_REPORT_SIZE);
        buf.push(0x01); // msg_type
        buf.push(FORMAT_VERSION);
        buf.extend_from_slice(&SENDER_REPORT_PAYLOAD.to_le_bytes());
        buf.extend_from_slice(&self.interval_packets_sent.to_le_bytes());
        buf.extend_from_slice(&self.interval_bytes_sent.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_packets_sent.to_le_bytes());
        buf
    }

    /// Decode from payload after msg_type byte has been consumed.
    ///
    /// `payload` starts at format_version (offset 1 in the wire format).
    /// Unknown trailing bytes (from future format extensions) are skipped
    /// via total_length.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // Need at least: format_version(1) + total_length(2) + v0 payload(16) = 19
        if payload.len() < 19 {
            return Err(ProtocolError::MessageTooShort {
                expected: 19,
                got: payload.len(),
            });
        }
        let format_version = payload[0];
        let total_length = u16::from_le_bytes(payload[1..3].try_into().unwrap()) as usize;

        // Verify we have enough data for the declared length
        if payload.len() < 3 + total_length {
            return Err(ProtocolError::MessageTooShort {
                expected: 3 + total_length,
                got: payload.len(),
            });
        }

        // For version 0, parse known fields from offset 3
        if format_version > 0 {
            // Future versions: we can still parse v0 fields if total_length >= 14
            if total_length < SENDER_REPORT_PAYLOAD as usize {
                return Err(ProtocolError::MessageTooShort {
                    expected: SENDER_REPORT_PAYLOAD as usize,
                    got: total_length,
                });
            }
        }

        let p = &payload[3..];
        Ok(Self {
            interval_packets_sent: u32::from_le_bytes(p[0..4].try_into().unwrap()),
            interval_bytes_sent: u32::from_le_bytes(p[4..8].try_into().unwrap()),
            cumulative_packets_sent: u64::from_le_bytes(p[8..16].try_into().unwrap()),
        })
    }
}

impl ReceiverReport {
    /// Encode to wire format (54 bytes: header + payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RECEIVER_REPORT_SIZE);
        buf.push(0x02); // msg_type
        buf.push(FORMAT_VERSION);
        buf.extend_from_slice(&RECEIVER_REPORT_PAYLOAD.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_echo.to_le_bytes());
        buf.extend_from_slice(&self.dwell_time.to_le_bytes());
        buf.extend_from_slice(&self.highest_counter.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_packets_recv.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_bytes_recv.to_le_bytes());
        buf.extend_from_slice(&self.jitter.to_le_bytes());
        buf.extend_from_slice(&self.ecn_ce_count.to_le_bytes());
        buf.extend_from_slice(&self.owd_trend.to_le_bytes());
        buf.extend_from_slice(&self.burst_loss_count.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_reorder_count.to_le_bytes());
        buf
    }

    /// Decode from payload after msg_type byte has been consumed.
    ///
    /// `payload` starts at format_version (offset 1 in the wire format).
    /// Unknown trailing bytes (from future format extensions) are skipped
    /// via total_length.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // Need at least: format_version(1) + total_length(2) + v0 payload(50) = 53
        if payload.len() < 53 {
            return Err(ProtocolError::MessageTooShort {
                expected: 53,
                got: payload.len(),
            });
        }
        let format_version = payload[0];
        let total_length = u16::from_le_bytes(payload[1..3].try_into().unwrap()) as usize;

        if payload.len() < 3 + total_length {
            return Err(ProtocolError::MessageTooShort {
                expected: 3 + total_length,
                got: payload.len(),
            });
        }

        if format_version > 0
            && total_length < RECEIVER_REPORT_PAYLOAD as usize
        {
            return Err(ProtocolError::MessageTooShort {
                expected: RECEIVER_REPORT_PAYLOAD as usize,
                got: total_length,
            });
        }

        let p = &payload[3..];
        Ok(Self {
            timestamp_echo: u32::from_le_bytes(p[0..4].try_into().unwrap()),
            dwell_time: u16::from_le_bytes(p[4..6].try_into().unwrap()),
            highest_counter: u64::from_le_bytes(p[6..14].try_into().unwrap()),
            cumulative_packets_recv: u64::from_le_bytes(p[14..22].try_into().unwrap()),
            cumulative_bytes_recv: u64::from_le_bytes(p[22..30].try_into().unwrap()),
            jitter: u32::from_le_bytes(p[30..34].try_into().unwrap()),
            ecn_ce_count: u32::from_le_bytes(p[34..38].try_into().unwrap()),
            owd_trend: i32::from_le_bytes(p[38..42].try_into().unwrap()),
            burst_loss_count: u32::from_le_bytes(p[42..46].try_into().unwrap()),
            cumulative_reorder_count: u32::from_le_bytes(p[46..50].try_into().unwrap()),
        })
    }
}

// ============================================================================
// Conversions between link-layer and session-layer report types
// ============================================================================

use crate::protocol::{SessionReceiverReport, SessionSenderReport};

impl From<&SenderReport> for SessionSenderReport {
    fn from(r: &SenderReport) -> Self {
        Self {
            interval_packets_sent: r.interval_packets_sent,
            interval_bytes_sent: r.interval_bytes_sent,
            cumulative_packets_sent: r.cumulative_packets_sent,
        }
    }
}

impl From<&SessionSenderReport> for SenderReport {
    fn from(r: &SessionSenderReport) -> Self {
        Self {
            interval_packets_sent: r.interval_packets_sent,
            interval_bytes_sent: r.interval_bytes_sent,
            cumulative_packets_sent: r.cumulative_packets_sent,
        }
    }
}

impl From<&ReceiverReport> for SessionReceiverReport {
    fn from(r: &ReceiverReport) -> Self {
        Self {
            timestamp_echo: r.timestamp_echo,
            dwell_time: r.dwell_time,
            highest_counter: r.highest_counter,
            cumulative_packets_recv: r.cumulative_packets_recv,
            cumulative_bytes_recv: r.cumulative_bytes_recv,
            jitter: r.jitter,
            ecn_ce_count: r.ecn_ce_count,
            owd_trend: r.owd_trend,
            burst_loss_count: r.burst_loss_count,
            cumulative_reorder_count: r.cumulative_reorder_count,
        }
    }
}

impl From<&SessionReceiverReport> for ReceiverReport {
    fn from(r: &SessionReceiverReport) -> Self {
        Self {
            timestamp_echo: r.timestamp_echo,
            dwell_time: r.dwell_time,
            highest_counter: r.highest_counter,
            cumulative_packets_recv: r.cumulative_packets_recv,
            cumulative_bytes_recv: r.cumulative_bytes_recv,
            jitter: r.jitter,
            ecn_ce_count: r.ecn_ce_count,
            owd_trend: r.owd_trend,
            burst_loss_count: r.burst_loss_count,
            cumulative_reorder_count: r.cumulative_reorder_count,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
}
