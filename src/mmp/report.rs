//! MMP report wire format: SenderReport and ReceiverReport.
//!
//! Serialization and deserialization for the two report types exchanged
//! between link-layer peers. Wire format follows the MMP design doc.

use crate::protocol::ProtocolError;

// ============================================================================
// SenderReport (msg_type 0x01, 48-byte body including type byte)
// ============================================================================

/// Link-layer sender report.
///
/// Wire layout (48 bytes total, sent as link message):
/// ```text
/// [0]    msg_type = 0x01
/// [1-3]  reserved (zero)
/// [4-11] interval_start_counter: u64 LE
/// [12-19] interval_end_counter: u64 LE
/// [20-23] interval_start_timestamp: u32 LE
/// [24-27] interval_end_timestamp: u32 LE
/// [28-31] interval_bytes_sent: u32 LE
/// [32-39] cumulative_packets_sent: u64 LE
/// [40-47] cumulative_bytes_sent: u64 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    pub interval_start_counter: u64,
    pub interval_end_counter: u64,
    pub interval_start_timestamp: u32,
    pub interval_end_timestamp: u32,
    pub interval_bytes_sent: u32,
    pub cumulative_packets_sent: u64,
    pub cumulative_bytes_sent: u64,
}

/// ReceiverReport (msg_type 0x02, 68-byte body including type byte)
///
/// Wire layout (68 bytes total, sent as link message):
/// ```text
/// [0]    msg_type = 0x02
/// [1-3]  reserved (zero)
/// [4-11] highest_counter: u64 LE
/// [12-19] cumulative_packets_recv: u64 LE
/// [20-27] cumulative_bytes_recv: u64 LE
/// [28-31] timestamp_echo: u32 LE
/// [32-33] dwell_time: u16 LE
/// [34-35] max_burst_loss: u16 LE
/// [36-37] mean_burst_loss: u16 LE (u8.8 fixed-point)
/// [38-39] reserved: u16 LE
/// [40-43] jitter: u32 LE (microseconds)
/// [44-47] ecn_ce_count: u32 LE
/// [48-51] owd_trend: i32 LE (µs/s)
/// [52-55] burst_loss_count: u32 LE
/// [56-59] cumulative_reorder_count: u32 LE
/// [60-63] interval_packets_recv: u32 LE
/// [64-67] interval_bytes_recv: u32 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    pub highest_counter: u64,
    pub cumulative_packets_recv: u64,
    pub cumulative_bytes_recv: u64,
    pub timestamp_echo: u32,
    pub dwell_time: u16,
    pub max_burst_loss: u16,
    pub mean_burst_loss: u16,
    pub jitter: u32,
    pub ecn_ce_count: u32,
    pub owd_trend: i32,
    pub burst_loss_count: u32,
    pub cumulative_reorder_count: u32,
    pub interval_packets_recv: u32,
    pub interval_bytes_recv: u32,
}

// Encode/decode will be implemented in Step 2.

impl SenderReport {
    /// Encode to wire format (48 bytes: msg_type + 3 reserved + 44 payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48);
        buf.push(0x01); // msg_type
        buf.extend_from_slice(&[0u8; 3]); // reserved
        buf.extend_from_slice(&self.interval_start_counter.to_le_bytes());
        buf.extend_from_slice(&self.interval_end_counter.to_le_bytes());
        buf.extend_from_slice(&self.interval_start_timestamp.to_le_bytes());
        buf.extend_from_slice(&self.interval_end_timestamp.to_le_bytes());
        buf.extend_from_slice(&self.interval_bytes_sent.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_packets_sent.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_bytes_sent.to_le_bytes());
        buf
    }

    /// Decode from payload after msg_type byte has been consumed.
    ///
    /// `payload` starts at the reserved bytes (offset 1 in the wire format).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 47 {
            return Err(ProtocolError::MessageTooShort {
                expected: 47,
                got: payload.len(),
            });
        }
        // Skip 3 reserved bytes
        let p = &payload[3..];
        Ok(Self {
            interval_start_counter: u64::from_le_bytes(p[0..8].try_into().unwrap()),
            interval_end_counter: u64::from_le_bytes(p[8..16].try_into().unwrap()),
            interval_start_timestamp: u32::from_le_bytes(p[16..20].try_into().unwrap()),
            interval_end_timestamp: u32::from_le_bytes(p[20..24].try_into().unwrap()),
            interval_bytes_sent: u32::from_le_bytes(p[24..28].try_into().unwrap()),
            cumulative_packets_sent: u64::from_le_bytes(p[28..36].try_into().unwrap()),
            cumulative_bytes_sent: u64::from_le_bytes(p[36..44].try_into().unwrap()),
        })
    }
}

impl ReceiverReport {
    /// Encode to wire format (68 bytes: msg_type + 3 reserved + 64 payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(68);
        buf.push(0x02); // msg_type
        buf.extend_from_slice(&[0u8; 3]); // reserved
        buf.extend_from_slice(&self.highest_counter.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_packets_recv.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_bytes_recv.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_echo.to_le_bytes());
        buf.extend_from_slice(&self.dwell_time.to_le_bytes());
        buf.extend_from_slice(&self.max_burst_loss.to_le_bytes());
        buf.extend_from_slice(&self.mean_burst_loss.to_le_bytes());
        buf.extend_from_slice(&[0u8; 2]); // reserved
        buf.extend_from_slice(&self.jitter.to_le_bytes());
        buf.extend_from_slice(&self.ecn_ce_count.to_le_bytes());
        buf.extend_from_slice(&self.owd_trend.to_le_bytes());
        buf.extend_from_slice(&self.burst_loss_count.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_reorder_count.to_le_bytes());
        buf.extend_from_slice(&self.interval_packets_recv.to_le_bytes());
        buf.extend_from_slice(&self.interval_bytes_recv.to_le_bytes());
        buf
    }

    /// Decode from payload after msg_type byte has been consumed.
    ///
    /// `payload` starts at the reserved bytes (offset 1 in the wire format).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 67 {
            return Err(ProtocolError::MessageTooShort {
                expected: 67,
                got: payload.len(),
            });
        }
        // Skip 3 reserved bytes
        let p = &payload[3..];
        Ok(Self {
            highest_counter: u64::from_le_bytes(p[0..8].try_into().unwrap()),
            cumulative_packets_recv: u64::from_le_bytes(p[8..16].try_into().unwrap()),
            cumulative_bytes_recv: u64::from_le_bytes(p[16..24].try_into().unwrap()),
            timestamp_echo: u32::from_le_bytes(p[24..28].try_into().unwrap()),
            dwell_time: u16::from_le_bytes(p[28..30].try_into().unwrap()),
            max_burst_loss: u16::from_le_bytes(p[30..32].try_into().unwrap()),
            mean_burst_loss: u16::from_le_bytes(p[32..34].try_into().unwrap()),
            // skip 2 reserved bytes at p[34..36]
            jitter: u32::from_le_bytes(p[36..40].try_into().unwrap()),
            ecn_ce_count: u32::from_le_bytes(p[40..44].try_into().unwrap()),
            owd_trend: i32::from_le_bytes(p[44..48].try_into().unwrap()),
            burst_loss_count: u32::from_le_bytes(p[48..52].try_into().unwrap()),
            cumulative_reorder_count: u32::from_le_bytes(p[52..56].try_into().unwrap()),
            interval_packets_recv: u32::from_le_bytes(p[56..60].try_into().unwrap()),
            interval_bytes_recv: u32::from_le_bytes(p[60..64].try_into().unwrap()),
        })
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
}
