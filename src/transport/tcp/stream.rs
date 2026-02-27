//! FMP-Aware Stream Reader
//!
//! Recovers FIPS packet boundaries from a TCP byte stream using the
//! existing 4-byte FMP common prefix `[ver+phase:1][flags:1][payload_len:2 LE]`.
//!
//! This module is deliberately separate from the TCP transport so it can
//! be reused by the future Tor transport.

use tokio::io::{AsyncRead, AsyncReadExt};

/// FMP phase values (low nibble of byte 0).
const PHASE_ESTABLISHED: u8 = 0x0;
const PHASE_MSG1: u8 = 0x1;
const PHASE_MSG2: u8 = 0x2;

/// Size of the FMP common prefix.
const PREFIX_SIZE: usize = 4;

/// Overhead for established frames: 12 bytes remaining header + 16 bytes AEAD tag.
/// The full established header is 16 bytes (PREFIX_SIZE + 12), so after reading
/// the 4-byte prefix, 12 more header bytes remain. Then payload_len bytes of
/// ciphertext, then 16 bytes of AEAD tag.
const ESTABLISHED_REMAINING_HEADER: usize = 12;
const AEAD_TAG_SIZE: usize = 16;

/// Errors from the FMP stream reader.
#[derive(Debug)]
pub enum StreamError {
    /// Unknown FMP phase byte — protocol error, close connection.
    UnknownPhase(u8),
    /// Payload length exceeds the connection's MTU — corrupted or malicious.
    PayloadTooLarge { payload_len: u16, max_payload_len: u16 },
    /// Handshake packet has unexpected payload_len for its phase.
    HandshakeSizeMismatch { phase: u8, expected: u16, got: u16 },
    /// I/O error (including EOF).
    Io(std::io::Error),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::UnknownPhase(p) => write!(f, "unknown FMP phase: 0x{:02x}", p),
            StreamError::PayloadTooLarge { payload_len, max_payload_len } => {
                write!(f, "payload_len {} exceeds max {}", payload_len, max_payload_len)
            }
            StreamError::HandshakeSizeMismatch { phase, expected, got } => {
                write!(f, "handshake phase 0x{:x}: expected payload_len {}, got {}", phase, expected, got)
            }
            StreamError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        StreamError::Io(e)
    }
}

/// Known wire sizes for handshake messages.
/// msg1: 4 (prefix) + 4 (sender_idx) + 106 (noise_msg1) = 114 bytes
/// msg2: 4 (prefix) + 4 (sender_idx) + 4 (receiver_idx) + 57 (noise_msg2) = 69 bytes
const MSG1_WIRE_SIZE: usize = 114;
const MSG2_WIRE_SIZE: usize = 69;

/// Expected payload_len for msg1: sender_idx(4) + noise_msg1(106) = 110.
const MSG1_PAYLOAD_LEN: u16 = (MSG1_WIRE_SIZE - PREFIX_SIZE) as u16;

/// Expected payload_len for msg2: sender_idx(4) + receiver_idx(4) + noise_msg2(57) = 65.
const MSG2_PAYLOAD_LEN: u16 = (MSG2_WIRE_SIZE - PREFIX_SIZE) as u16;

/// Read one complete FMP packet from an async reader.
///
/// Uses the 4-byte FMP common prefix to determine the total packet size,
/// then reads the remaining bytes. Returns the complete packet as a `Vec<u8>`.
///
/// # Arguments
///
/// * `reader` - Any async reader (typically an `OwnedReadHalf`)
/// * `mtu` - The connection's MTU for validation of established frame sizes
///
/// # Errors
///
/// * `UnknownPhase` — unrecognized phase nibble (protocol error)
/// * `PayloadTooLarge` — established frame exceeds MTU
/// * `HandshakeSizeMismatch` — handshake packet has wrong payload_len
/// * `Io` — underlying read error (including EOF)
pub async fn read_fmp_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    mtu: u16,
) -> Result<Vec<u8>, StreamError> {
    // Read the 4-byte FMP common prefix
    let mut prefix = [0u8; PREFIX_SIZE];
    reader.read_exact(&mut prefix).await?;

    let phase = prefix[0] & 0x0F;
    let payload_len = u16::from_le_bytes([prefix[2], prefix[3]]);

    // Compute remaining bytes based on phase
    let remaining = match phase {
        PHASE_ESTABLISHED => {
            // Validate payload_len against MTU:
            // total packet = 16 (header) + payload_len + 16 (tag) = payload_len + 32
            // max_payload_len = mtu - 32
            let max_payload_len = mtu.saturating_sub(
                (ESTABLISHED_REMAINING_HEADER + PREFIX_SIZE + AEAD_TAG_SIZE) as u16,
            );
            if payload_len > max_payload_len {
                return Err(StreamError::PayloadTooLarge {
                    payload_len,
                    max_payload_len,
                });
            }
            // remaining = 12 (rest of header) + payload_len + 16 (AEAD tag)
            ESTABLISHED_REMAINING_HEADER + payload_len as usize + AEAD_TAG_SIZE
        }
        PHASE_MSG1 => {
            if payload_len != MSG1_PAYLOAD_LEN {
                return Err(StreamError::HandshakeSizeMismatch {
                    phase,
                    expected: MSG1_PAYLOAD_LEN,
                    got: payload_len,
                });
            }
            payload_len as usize
        }
        PHASE_MSG2 => {
            if payload_len != MSG2_PAYLOAD_LEN {
                return Err(StreamError::HandshakeSizeMismatch {
                    phase,
                    expected: MSG2_PAYLOAD_LEN,
                    got: payload_len,
                });
            }
            payload_len as usize
        }
        _ => {
            return Err(StreamError::UnknownPhase(phase));
        }
    };

    // Allocate buffer for the complete packet (prefix + remaining)
    let total = PREFIX_SIZE + remaining;
    let mut packet = vec![0u8; total];
    packet[..PREFIX_SIZE].copy_from_slice(&prefix);
    reader.read_exact(&mut packet[PREFIX_SIZE..]).await?;

    Ok(packet)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a minimal established frame with the given payload_len.
    /// Layout: [ver+phase:1][flags:1][payload_len:2 LE][12 bytes header][payload_len bytes][16 bytes tag]
    fn build_established_frame(payload_len: u16) -> Vec<u8> {
        let total = PREFIX_SIZE + ESTABLISHED_REMAINING_HEADER + payload_len as usize + AEAD_TAG_SIZE;
        let mut frame = vec![0u8; total];
        frame[0] = 0x00; // ver=0, phase=0 (established)
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
        // Fill remaining with pattern for verification
        for i in PREFIX_SIZE..total {
            frame[i] = (i & 0xFF) as u8;
        }
        frame
    }

    /// Build a msg1 frame (114 bytes total).
    fn build_msg1_frame() -> Vec<u8> {
        let mut frame = vec![0xAA; MSG1_WIRE_SIZE];
        frame[0] = 0x01; // ver=0, phase=1
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&MSG1_PAYLOAD_LEN.to_le_bytes());
        frame
    }

    /// Build a msg2 frame (69 bytes total).
    fn build_msg2_frame() -> Vec<u8> {
        let mut frame = vec![0xBB; MSG2_WIRE_SIZE];
        frame[0] = 0x02; // ver=0, phase=2
        frame[1] = 0x00; // flags
        frame[2..4].copy_from_slice(&MSG2_PAYLOAD_LEN.to_le_bytes());
        frame
    }

    #[tokio::test]
    async fn test_read_established_frame() {
        let payload_len = 64u16;
        let frame = build_established_frame(payload_len);
        let expected = frame.clone();

        let mut cursor = Cursor::new(frame);
        let packet = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(packet, expected);
    }

    #[tokio::test]
    async fn test_read_msg1_frame() {
        let frame = build_msg1_frame();
        let expected = frame.clone();

        let mut cursor = Cursor::new(frame);
        let packet = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(packet.len(), MSG1_WIRE_SIZE);
        assert_eq!(packet, expected);
    }

    #[tokio::test]
    async fn test_read_msg2_frame() {
        let frame = build_msg2_frame();
        let expected = frame.clone();

        let mut cursor = Cursor::new(frame);
        let packet = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(packet.len(), MSG2_WIRE_SIZE);
        assert_eq!(packet, expected);
    }

    #[tokio::test]
    async fn test_read_multiple_packets() {
        let mut data = Vec::new();
        let msg1 = build_msg1_frame();
        let est = build_established_frame(32);
        let msg2 = build_msg2_frame();
        data.extend_from_slice(&msg1);
        data.extend_from_slice(&est);
        data.extend_from_slice(&msg2);

        let mut cursor = Cursor::new(data);
        let p1 = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(p1.len(), MSG1_WIRE_SIZE);

        let p2 = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(p2, est);

        let p3 = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(p3.len(), MSG2_WIRE_SIZE);
    }

    #[tokio::test]
    async fn test_unknown_phase_error() {
        let mut frame = vec![0u8; 100];
        frame[0] = 0x05; // unknown phase
        frame[2..4].copy_from_slice(&10u16.to_le_bytes());

        let mut cursor = Cursor::new(frame);
        let err = read_fmp_packet(&mut cursor, 1400).await.unwrap_err();
        assert!(matches!(err, StreamError::UnknownPhase(0x5)));
    }

    #[tokio::test]
    async fn test_payload_too_large() {
        // mtu=100, max_payload_len = 100 - 32 = 68
        let payload_len = 100u16; // exceeds max of 68
        let mut prefix = [0u8; 4];
        prefix[0] = 0x00; // established
        prefix[2..4].copy_from_slice(&payload_len.to_le_bytes());

        // Provide enough bytes for the reader to read prefix
        let mut data = prefix.to_vec();
        data.extend_from_slice(&vec![0u8; 200]); // extra bytes

        let mut cursor = Cursor::new(data);
        let err = read_fmp_packet(&mut cursor, 100).await.unwrap_err();
        assert!(matches!(err, StreamError::PayloadTooLarge { .. }));
    }

    #[tokio::test]
    async fn test_handshake_size_mismatch_msg1() {
        let mut frame = vec![0u8; 200];
        frame[0] = 0x01; // msg1
        // Wrong payload_len (should be 110)
        frame[2..4].copy_from_slice(&50u16.to_le_bytes());

        let mut cursor = Cursor::new(frame);
        let err = read_fmp_packet(&mut cursor, 1400).await.unwrap_err();
        assert!(matches!(err, StreamError::HandshakeSizeMismatch { phase: 0x1, .. }));
    }

    #[tokio::test]
    async fn test_handshake_size_mismatch_msg2() {
        let mut frame = vec![0u8; 200];
        frame[0] = 0x02; // msg2
        // Wrong payload_len (should be 65)
        frame[2..4].copy_from_slice(&50u16.to_le_bytes());

        let mut cursor = Cursor::new(frame);
        let err = read_fmp_packet(&mut cursor, 1400).await.unwrap_err();
        assert!(matches!(err, StreamError::HandshakeSizeMismatch { phase: 0x2, .. }));
    }

    #[tokio::test]
    async fn test_eof_on_prefix() {
        // Only 2 bytes available (need 4 for prefix)
        let data = vec![0u8; 2];
        let mut cursor = Cursor::new(data);
        let err = read_fmp_packet(&mut cursor, 1400).await.unwrap_err();
        assert!(matches!(err, StreamError::Io(_)));
    }

    #[tokio::test]
    async fn test_eof_on_body() {
        // Valid msg1 prefix but truncated body
        let mut data = vec![0u8; 10]; // need 114 total
        data[0] = 0x01; // msg1
        data[2..4].copy_from_slice(&MSG1_PAYLOAD_LEN.to_le_bytes());

        let mut cursor = Cursor::new(data);
        let err = read_fmp_packet(&mut cursor, 1400).await.unwrap_err();
        assert!(matches!(err, StreamError::Io(_)));
    }

    #[tokio::test]
    async fn test_zero_payload_established() {
        // payload_len = 0 is valid (header-only encrypted frame with tag)
        let frame = build_established_frame(0);
        let expected_len = PREFIX_SIZE + ESTABLISHED_REMAINING_HEADER + AEAD_TAG_SIZE;
        assert_eq!(frame.len(), expected_len);

        let mut cursor = Cursor::new(frame.clone());
        let packet = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(packet.len(), expected_len);
        assert_eq!(packet, frame);
    }

    #[tokio::test]
    async fn test_max_payload_at_mtu_boundary() {
        // mtu=1400, max_payload_len = 1400 - 32 = 1368
        let max_payload = 1400u16 - 32;
        let frame = build_established_frame(max_payload);

        let mut cursor = Cursor::new(frame.clone());
        let packet = read_fmp_packet(&mut cursor, 1400).await.unwrap();
        assert_eq!(packet, frame);
    }

    #[tokio::test]
    async fn test_payload_one_over_mtu() {
        // mtu=1400, max_payload_len = 1368, try 1369
        let over = 1400u16 - 32 + 1;
        let mut prefix = [0u8; 4];
        prefix[0] = 0x00; // established
        prefix[2..4].copy_from_slice(&over.to_le_bytes());

        let mut data = prefix.to_vec();
        data.extend_from_slice(&vec![0u8; 2000]);

        let mut cursor = Cursor::new(data);
        let err = read_fmp_packet(&mut cursor, 1400).await.unwrap_err();
        assert!(matches!(err, StreamError::PayloadTooLarge { .. }));
    }
}
