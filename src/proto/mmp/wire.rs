//! MMP report wire format: link-layer and session-layer report codecs.
//!
//! Serialization and deserialization for the report types exchanged between
//! MMP peers: the link-layer [`SenderReport`]/[`ReceiverReport`] and their
//! session-layer FSP counterparts ([`SessionSenderReport`]/
//! [`SessionReceiverReport`]/[`PathMtuNotification`]), plus the conversions
//! between the two layers. Wire format uses an extensibility header:
//! `[format_version:1][total_length:2 LE]` (link reports prefix this with a
//! `msg_type:1` byte). Format version 0 defines the slim layouts below;
//! decoders skip unknown trailing bytes via total_length for forward
//! compatibility.

use crate::proto::Error;

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
pub(crate) const SENDER_REPORT_PAYLOAD: u16 = 16;

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
pub(crate) const RECEIVER_REPORT_PAYLOAD: u16 = 50;

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
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        // Need at least: format_version(1) + total_length(2) + v0 payload(16) = 19
        if payload.len() < 19 {
            return Err(Error::MessageTooShort {
                expected: 19,
                got: payload.len(),
            });
        }
        let format_version = payload[0];
        let total_length = u16::from_le_bytes(payload[1..3].try_into().unwrap()) as usize;

        // Verify we have enough data for the declared length
        if payload.len() < 3 + total_length {
            return Err(Error::MessageTooShort {
                expected: 3 + total_length,
                got: payload.len(),
            });
        }

        // For version 0, parse known fields from offset 3
        if format_version > 0 {
            // Future versions: we can still parse v0 fields if total_length >= 14
            if total_length < SENDER_REPORT_PAYLOAD as usize {
                return Err(Error::MessageTooShort {
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
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        // Need at least: format_version(1) + total_length(2) + v0 payload(50) = 53
        if payload.len() < 53 {
            return Err(Error::MessageTooShort {
                expected: 53,
                got: payload.len(),
            });
        }
        let format_version = payload[0];
        let total_length = u16::from_le_bytes(payload[1..3].try_into().unwrap()) as usize;

        if payload.len() < 3 + total_length {
            return Err(Error::MessageTooShort {
                expected: 3 + total_length,
                got: payload.len(),
            });
        }

        if format_version > 0 && total_length < RECEIVER_REPORT_PAYLOAD as usize {
            return Err(Error::MessageTooShort {
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
// Session-Layer MMP Reports
// ============================================================================

/// Session-layer sender report (msg_type 0x11).
///
/// Mirrors the link-layer `SenderReport` fields but carried as an FSP session
/// message inside the AEAD envelope. The msg_type is in the FSP inner header,
/// so the body starts with the extensibility header (format_version +
/// total_length).
///
/// ## Wire Format (19 bytes body, after inner header stripped)
///
/// ```text
/// [0]     format_version = 0
/// [1-2]   total_length: u16 LE (= 16)
/// [3-6]   interval_packets_sent: u32 LE
/// [7-10]  interval_bytes_sent: u32 LE
/// [11-18] cumulative_packets_sent: u64 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSenderReport {
    pub interval_packets_sent: u32,
    pub interval_bytes_sent: u32,
    pub cumulative_packets_sent: u64,
}

/// Body size for SessionSenderReport: format_version(1) + total_length(2) + payload(16).
pub const SESSION_SENDER_REPORT_SIZE: usize = 19;

/// Payload size after total_length field for SessionSenderReport format v0.
const SESSION_SR_PAYLOAD: u16 = 16;

impl SessionSenderReport {
    /// Encode to wire format (19 bytes body).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_SENDER_REPORT_SIZE);
        buf.push(0x00); // format_version
        buf.extend_from_slice(&SESSION_SR_PAYLOAD.to_le_bytes());
        buf.extend_from_slice(&self.interval_packets_sent.to_le_bytes());
        buf.extend_from_slice(&self.interval_bytes_sent.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_packets_sent.to_le_bytes());
        buf
    }

    /// Decode from body (after FSP inner header has been stripped).
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        if body.len() < SESSION_SENDER_REPORT_SIZE {
            return Err(Error::MessageTooShort {
                expected: SESSION_SENDER_REPORT_SIZE,
                got: body.len(),
            });
        }
        let _format_version = body[0];
        let total_length = u16::from_le_bytes(body[1..3].try_into().unwrap()) as usize;
        if body.len() < 3 + total_length {
            return Err(Error::MessageTooShort {
                expected: 3 + total_length,
                got: body.len(),
            });
        }
        let p = &body[3..];
        Ok(Self {
            interval_packets_sent: u32::from_le_bytes(p[0..4].try_into().unwrap()),
            interval_bytes_sent: u32::from_le_bytes(p[4..8].try_into().unwrap()),
            cumulative_packets_sent: u64::from_le_bytes(p[8..16].try_into().unwrap()),
        })
    }
}

/// Session-layer receiver report (msg_type 0x12).
///
/// Mirrors the link-layer `ReceiverReport` fields but carried as an FSP session
/// message inside the AEAD envelope. Uses the same extensibility header as the
/// link-layer format: `[format_version:1][total_length:2 LE]`.
///
/// ## Wire Format (53 bytes body, after inner header stripped)
///
/// ```text
/// [0]     format_version = 0
/// [1-2]   total_length: u16 LE (= 50)
/// [3-6]   timestamp_echo: u32 LE
/// [7-8]   dwell_time: u16 LE
/// [9-16]  highest_counter: u64 LE
/// [17-24] cumulative_packets_recv: u64 LE
/// [25-32] cumulative_bytes_recv: u64 LE
/// [33-36] jitter: u32 LE (microseconds)
/// [37-40] ecn_ce_count: u32 LE
/// [41-44] owd_trend: i32 LE (µs/s)
/// [45-48] burst_loss_count: u32 LE
/// [49-52] cumulative_reorder_count: u32 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReceiverReport {
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

/// Body size for SessionReceiverReport: format_version(1) + total_length(2) + payload(50).
pub const SESSION_RECEIVER_REPORT_SIZE: usize = 53;

/// Payload size after total_length field for SessionReceiverReport format v0.
const SESSION_RR_PAYLOAD: u16 = 50;

impl SessionReceiverReport {
    /// Encode to wire format (53 bytes body).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_RECEIVER_REPORT_SIZE);
        buf.push(0x00); // format_version
        buf.extend_from_slice(&SESSION_RR_PAYLOAD.to_le_bytes());
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

    /// Decode from body (after FSP inner header has been stripped).
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        if body.len() < SESSION_RECEIVER_REPORT_SIZE {
            return Err(Error::MessageTooShort {
                expected: SESSION_RECEIVER_REPORT_SIZE,
                got: body.len(),
            });
        }
        let _format_version = body[0];
        let total_length = u16::from_le_bytes(body[1..3].try_into().unwrap()) as usize;
        if body.len() < 3 + total_length {
            return Err(Error::MessageTooShort {
                expected: 3 + total_length,
                got: body.len(),
            });
        }
        let p = &body[3..];
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
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        if body.len() < PATH_MTU_NOTIFICATION_SIZE {
            return Err(Error::MessageTooShort {
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
