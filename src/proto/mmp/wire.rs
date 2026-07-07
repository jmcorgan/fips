//! MMP report wire format: link-layer and session-layer report codecs.
//!
//! Serialization and deserialization for the report types exchanged between
//! MMP peers: the link-layer [`SenderReport`]/[`ReceiverReport`] and their
//! session-layer FSP counterparts ([`SessionSenderReport`]/
//! [`SessionReceiverReport`]/[`PathMtuNotification`]), plus the conversions
//! between the two layers. Wire format follows the MMP design doc.

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
// Session-Layer MMP Reports
// ============================================================================

/// Session-layer sender report (msg_type 0x11).
///
/// Mirrors the FMP `SenderReport` fields but carried as an FSP session
/// message inside the AEAD envelope. The msg_type is in the FSP inner
/// header, so the body starts with reserved bytes.
///
/// ## Wire Format (46 bytes body, after inner header stripped)
///
/// ```text
/// [0-1]   reserved (zero)
/// [2-9]   interval_start_counter: u64 LE
/// [10-17] interval_end_counter: u64 LE
/// [18-21] interval_start_timestamp: u32 LE
/// [22-25] interval_end_timestamp: u32 LE
/// [26-29] interval_bytes_sent: u32 LE
/// [30-37] cumulative_packets_sent: u64 LE
/// [38-45] cumulative_bytes_sent: u64 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSenderReport {
    pub interval_start_counter: u64,
    pub interval_end_counter: u64,
    pub interval_start_timestamp: u32,
    pub interval_end_timestamp: u32,
    pub interval_bytes_sent: u32,
    pub cumulative_packets_sent: u64,
    pub cumulative_bytes_sent: u64,
}

/// Body size for SessionSenderReport: 2 reserved + 44 fields.
pub const SESSION_SENDER_REPORT_SIZE: usize = 46;

impl SessionSenderReport {
    /// Encode to wire format (46 bytes body).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_SENDER_REPORT_SIZE);
        buf.extend_from_slice(&[0u8; 2]); // reserved
        buf.extend_from_slice(&self.interval_start_counter.to_le_bytes());
        buf.extend_from_slice(&self.interval_end_counter.to_le_bytes());
        buf.extend_from_slice(&self.interval_start_timestamp.to_le_bytes());
        buf.extend_from_slice(&self.interval_end_timestamp.to_le_bytes());
        buf.extend_from_slice(&self.interval_bytes_sent.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_packets_sent.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_bytes_sent.to_le_bytes());
        buf
    }

    /// Decode from body (after FSP inner header has been stripped).
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        if body.len() < SESSION_SENDER_REPORT_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: SESSION_SENDER_REPORT_SIZE,
                got: body.len(),
            });
        }
        // Skip 2 reserved bytes
        let p = &body[2..];
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

/// Session-layer receiver report (msg_type 0x12).
///
/// Mirrors the FMP `ReceiverReport` fields but carried as an FSP session
/// message inside the AEAD envelope.
///
/// ## Wire Format (66 bytes body, after inner header stripped)
///
/// ```text
/// [0-1]   reserved (zero)
/// [2-9]   highest_counter: u64 LE
/// [10-17] cumulative_packets_recv: u64 LE
/// [18-25] cumulative_bytes_recv: u64 LE
/// [26-29] timestamp_echo: u32 LE
/// [30-31] dwell_time: u16 LE
/// [32-33] max_burst_loss: u16 LE
/// [34-35] mean_burst_loss: u16 LE (u8.8 fixed-point)
/// [36-37] reserved: u16 LE
/// [38-41] jitter: u32 LE (microseconds)
/// [42-45] ecn_ce_count: u32 LE
/// [46-49] owd_trend: i32 LE (µs/s)
/// [50-53] burst_loss_count: u32 LE
/// [54-57] cumulative_reorder_count: u32 LE
/// [58-61] interval_packets_recv: u32 LE
/// [62-65] interval_bytes_recv: u32 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReceiverReport {
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

/// Body size for SessionReceiverReport: 2 reserved + 64 fields.
pub const SESSION_RECEIVER_REPORT_SIZE: usize = 66;

impl SessionReceiverReport {
    /// Encode to wire format (66 bytes body).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_RECEIVER_REPORT_SIZE);
        buf.extend_from_slice(&[0u8; 2]); // reserved
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

    /// Decode from body (after FSP inner header has been stripped).
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        if body.len() < SESSION_RECEIVER_REPORT_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: SESSION_RECEIVER_REPORT_SIZE,
                got: body.len(),
            });
        }
        // Skip 2 reserved bytes
        let p = &body[2..];
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

/// Path MTU notification (msg_type 0x13).
///
/// Sent by a node that discovers a path MTU value (from transit router
/// feedback or ICMP Packet Too Big). Allows the remote endpoint to
/// adjust its sending MTU.
///
/// ## Wire Format (2 bytes body, after inner header stripped)
///
/// ```text
/// [0-1]   path_mtu: u16 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMtuNotification {
    /// Discovered path MTU in bytes.
    pub path_mtu: u16,
}

/// Body size for PathMtuNotification.
pub const PATH_MTU_NOTIFICATION_SIZE: usize = 2;

impl PathMtuNotification {
    /// Create a new path MTU notification.
    pub fn new(path_mtu: u16) -> Self {
        Self { path_mtu }
    }

    /// Encode to wire format (2 bytes body).
    pub fn encode(&self) -> Vec<u8> {
        self.path_mtu.to_le_bytes().to_vec()
    }

    /// Decode from body (after FSP inner header has been stripped).
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        if body.len() < PATH_MTU_NOTIFICATION_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: PATH_MTU_NOTIFICATION_SIZE,
                got: body.len(),
            });
        }
        Ok(Self {
            path_mtu: u16::from_le_bytes([body[0], body[1]]),
        })
    }
}

// ============================================================================
// Conversions between link-layer and session-layer report types
// ============================================================================

impl From<&SenderReport> for SessionSenderReport {
    fn from(r: &SenderReport) -> Self {
        Self {
            interval_start_counter: r.interval_start_counter,
            interval_end_counter: r.interval_end_counter,
            interval_start_timestamp: r.interval_start_timestamp,
            interval_end_timestamp: r.interval_end_timestamp,
            interval_bytes_sent: r.interval_bytes_sent,
            cumulative_packets_sent: r.cumulative_packets_sent,
            cumulative_bytes_sent: r.cumulative_bytes_sent,
        }
    }
}

impl From<&SessionSenderReport> for SenderReport {
    fn from(r: &SessionSenderReport) -> Self {
        Self {
            interval_start_counter: r.interval_start_counter,
            interval_end_counter: r.interval_end_counter,
            interval_start_timestamp: r.interval_start_timestamp,
            interval_end_timestamp: r.interval_end_timestamp,
            interval_bytes_sent: r.interval_bytes_sent,
            cumulative_packets_sent: r.cumulative_packets_sent,
            cumulative_bytes_sent: r.cumulative_bytes_sent,
        }
    }
}

impl From<&ReceiverReport> for SessionReceiverReport {
    fn from(r: &ReceiverReport) -> Self {
        Self {
            highest_counter: r.highest_counter,
            cumulative_packets_recv: r.cumulative_packets_recv,
            cumulative_bytes_recv: r.cumulative_bytes_recv,
            timestamp_echo: r.timestamp_echo,
            dwell_time: r.dwell_time,
            max_burst_loss: r.max_burst_loss,
            mean_burst_loss: r.mean_burst_loss,
            jitter: r.jitter,
            ecn_ce_count: r.ecn_ce_count,
            owd_trend: r.owd_trend,
            burst_loss_count: r.burst_loss_count,
            cumulative_reorder_count: r.cumulative_reorder_count,
            interval_packets_recv: r.interval_packets_recv,
            interval_bytes_recv: r.interval_bytes_recv,
        }
    }
}

impl From<&SessionReceiverReport> for ReceiverReport {
    fn from(r: &SessionReceiverReport) -> Self {
        Self {
            highest_counter: r.highest_counter,
            cumulative_packets_recv: r.cumulative_packets_recv,
            cumulative_bytes_recv: r.cumulative_bytes_recv,
            timestamp_echo: r.timestamp_echo,
            dwell_time: r.dwell_time,
            max_burst_loss: r.max_burst_loss,
            mean_burst_loss: r.mean_burst_loss,
            jitter: r.jitter,
            ecn_ce_count: r.ecn_ce_count,
            owd_trend: r.owd_trend,
            burst_loss_count: r.burst_loss_count,
            cumulative_reorder_count: r.cumulative_reorder_count,
            interval_packets_recv: r.interval_packets_recv,
            interval_bytes_recv: r.interval_bytes_recv,
        }
    }
}
