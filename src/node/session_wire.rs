//! FSP Wire Format Parsing and Serialization
//!
//! Defines the FIPS session-layer wire format (FSP) for packet dispatch.
//! All FSP messages begin with a 4-byte common prefix followed by phase-specific
//! fields. Encrypted messages use a 12-byte cleartext header as AAD for AEAD,
//! and a 6-byte encrypted inner header containing timestamps and message type.
//!
//! ## Common Prefix (4 bytes)
//!
//! ```text
//! [ver+phase:1][flags:1][payload_len:2 LE]
//! ```
//!
//! ## Message Classes
//!
//! | Phase | U Flag | Type             | Description                       |
//! |-------|--------|------------------|-----------------------------------|
//! | 0x0   | 0      | Encrypted        | Post-handshake encrypted data     |
//! | 0x0   | 1      | Plaintext error  | CoordsRequired, PathBroken        |
//! | 0x1   | -      | Handshake msg1   | SessionSetup (Noise IK msg1)      |
//! | 0x2   | -      | Handshake msg2   | SessionAck (Noise IK msg2)        |

use crate::protocol::{ProtocolError, decode_optional_coords};
use crate::tree::TreeCoordinate;

// ============================================================================
// Constants
// ============================================================================

/// FSP protocol version (4 high bits of byte 0).
pub const FSP_VERSION: u8 = 0;

/// Phase value for established (encrypted or plaintext error) messages.
pub const FSP_PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for SessionSetup (Noise IK message 1).
pub const FSP_PHASE_MSG1: u8 = 0x1;

/// Phase value for SessionAck (Noise IK message 2).
pub const FSP_PHASE_MSG2: u8 = 0x2;

/// Size of the common packet prefix (all FSP message types).
pub const FSP_COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full encrypted message header (prefix + counter).
pub const FSP_HEADER_SIZE: usize = 12;

/// Size of the encrypted inner header (timestamp + msg_type + inner_flags).
pub const FSP_INNER_HEADER_SIZE: usize = 6;

/// AEAD authentication tag size (ChaCha20-Poly1305).
const TAG_SIZE: usize = 16;

/// Minimum size for an encrypted FSP message: header + tag (no plaintext).
pub const FSP_ENCRYPTED_MIN_SIZE: usize = FSP_HEADER_SIZE + TAG_SIZE; // 28 bytes

// Cleartext flag bit constants (byte 1 of common prefix, phase 0x0 only).

/// Coords Present — source and destination coordinates follow the header.
pub const FSP_FLAG_CP: u8 = 0x01;

/// Key Epoch — selects active key during rekeying.
#[allow(dead_code)]
pub const FSP_FLAG_K: u8 = 0x02;

/// Unencrypted — payload is plaintext (error signals).
pub const FSP_FLAG_U: u8 = 0x04;

// Inner flag bit constants (byte 5 of decrypted inner header).

/// Spin bit for end-to-end RTT measurement (inside AEAD).
#[allow(dead_code)]
pub const FSP_INNER_FLAG_SP: u8 = 0x01;

// ============================================================================
// Common Prefix
// ============================================================================

/// Parsed FSP common packet prefix (first 4 bytes of every FSP message).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct FspCommonPrefix {
    /// Protocol version (high nibble of byte 0).
    #[cfg_attr(not(test), allow(dead_code))]
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-message signal flags.
    pub flags: u8,
    /// Length of payload following the phase-specific header.
    #[cfg_attr(not(test), allow(dead_code))]
    pub payload_len: u16,
}

impl FspCommonPrefix {
    /// Parse a common prefix from the first 4 bytes of FSP message data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < FSP_COMMON_PREFIX_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;
        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);

        Some(Self {
            version,
            phase,
            flags,
            payload_len,
        })
    }

    /// Check if the Unencrypted flag is set.
    pub fn is_unencrypted(&self) -> bool {
        self.flags & FSP_FLAG_U != 0
    }

    /// Check if the Coords Present flag is set.
    pub fn has_coords(&self) -> bool {
        self.flags & FSP_FLAG_CP != 0
    }

    /// Encode the ver+phase byte.
    fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

// ============================================================================
// Encrypted Message Header
// ============================================================================

/// Parsed FSP encrypted message header (phase 0x0, U flag clear).
///
/// Wire format (12 bytes):
/// ```text
/// [ver+phase:1][flags:1][payload_len:2 LE][counter:8 LE]
/// ```
///
/// The full 12-byte header is used as AAD for the AEAD construction.
/// No receiver_idx — unlike FMP, FSP is end-to-end (dispatched by src_addr
/// from the SessionDatagram envelope, not by index).
#[derive(Clone, Debug)]
pub struct FspEncryptedHeader {
    /// Per-message flags (CP, K).
    pub flags: u8,
    /// Length of encrypted payload (excluding AEAD tag).
    #[cfg_attr(not(test), allow(dead_code))]
    pub payload_len: u16,
    /// Monotonic counter used as AEAD nonce.
    pub counter: u64,
    /// Raw 12-byte header for use as AEAD AAD.
    pub header_bytes: [u8; FSP_HEADER_SIZE],
}

impl FspEncryptedHeader {
    /// Parse an encrypted message header from FSP message data.
    ///
    /// Returns None if the data is too short or has wrong version/phase,
    /// or if the U flag is set (plaintext messages use a different path).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < FSP_ENCRYPTED_MIN_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FSP_VERSION || phase != FSP_PHASE_ESTABLISHED {
            return None;
        }

        let flags = data[1];

        // U flag means plaintext — not an encrypted message
        if flags & FSP_FLAG_U != 0 {
            return None;
        }

        let payload_len = u16::from_le_bytes([data[2], data[3]]);
        let counter = u64::from_le_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]);

        let mut header_bytes = [0u8; FSP_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..FSP_HEADER_SIZE]);

        Some(Self {
            flags,
            payload_len,
            counter,
            header_bytes,
        })
    }

    /// Check if the Coords Present flag is set.
    pub fn has_coords(&self) -> bool {
        self.flags & FSP_FLAG_CP != 0
    }

    /// Offset where ciphertext (or coords if CP) begins in the original data.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn data_offset(&self) -> usize {
        FSP_HEADER_SIZE
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build the 12-byte cleartext header for an encrypted FSP message.
///
/// Returns the header bytes for use as AEAD AAD.
pub fn build_fsp_header(
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> [u8; FSP_HEADER_SIZE] {
    let mut header = [0u8; FSP_HEADER_SIZE];
    header[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, FSP_PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..12].copy_from_slice(&counter.to_le_bytes());
    header
}

/// Assemble a wire-format encrypted FSP message.
///
/// Format: `[header:12][ciphertext+tag]`
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_encrypted(header: &[u8; FSP_HEADER_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(FSP_HEADER_SIZE + ciphertext.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(ciphertext);
    packet
}

/// Build a 4-byte common prefix for a handshake message.
///
/// `phase` should be `FSP_PHASE_MSG1` or `FSP_PHASE_MSG2`.
/// Flags are zero during handshake.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_handshake_prefix(phase: u8, payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    let mut prefix = [0u8; FSP_COMMON_PREFIX_SIZE];
    prefix[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, phase);
    prefix[1] = 0x00; // flags must be zero during handshake
    prefix[2..4].copy_from_slice(&payload_len.to_le_bytes());
    prefix
}

/// Build a 4-byte common prefix for a plaintext error signal.
///
/// Sets phase 0x0 and U flag.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_fsp_error_prefix(payload_len: u16) -> [u8; FSP_COMMON_PREFIX_SIZE] {
    let mut prefix = [0u8; FSP_COMMON_PREFIX_SIZE];
    prefix[0] = FspCommonPrefix::ver_phase_byte(FSP_VERSION, FSP_PHASE_ESTABLISHED);
    prefix[1] = FSP_FLAG_U;
    prefix[2..4].copy_from_slice(&payload_len.to_le_bytes());
    prefix
}

// ============================================================================
// Inner Header Helpers
// ============================================================================

/// Prepend the 6-byte FSP inner header to a message payload.
///
/// Inner header: `[timestamp:4 LE][msg_type:1][inner_flags:1]`
///
/// The caller provides the message-type-specific payload (e.g., application
/// data for msg_type 0x10, report fields for SenderReport). This function
/// prepends the inner header.
pub fn fsp_prepend_inner_header(
    timestamp_ms: u32,
    msg_type: u8,
    inner_flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FSP_INNER_HEADER_SIZE + payload.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(msg_type);
    buf.push(inner_flags);
    buf.extend_from_slice(payload);
    buf
}

/// Strip the 6-byte FSP inner header from a decrypted payload.
///
/// Returns `(timestamp, msg_type, inner_flags, &rest)` or None if too short.
pub fn fsp_strip_inner_header(plaintext: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    if plaintext.len() < FSP_INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([
        plaintext[0], plaintext[1], plaintext[2], plaintext[3],
    ]);
    let msg_type = plaintext[4];
    let inner_flags = plaintext[5];
    Some((timestamp, msg_type, inner_flags, &plaintext[FSP_INNER_HEADER_SIZE..]))
}

// ============================================================================
// Coordinate Parsing (for transit nodes and receive path)
// ============================================================================

/// Parse source and destination coordinates from the cleartext section
/// of an encrypted FSP message when the CP flag is set.
///
/// Coordinates appear between the 12-byte header and the ciphertext:
/// `[src_coords_count:2 LE][src_coords:16×n][dest_coords_count:2 LE][dest_coords:16×m]`
///
/// Returns `(src_coords, dest_coords, bytes_consumed)`.
pub fn parse_encrypted_coords(
    data: &[u8],
) -> Result<(Option<TreeCoordinate>, Option<TreeCoordinate>, usize), ProtocolError> {
    let (src_coords, src_consumed) = decode_optional_coords(data)?;
    let (dest_coords, dest_consumed) = decode_optional_coords(&data[src_consumed..])?;
    Ok((src_coords, dest_coords, src_consumed + dest_consumed))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
                header[4], header[5], header[6], header[7],
                header[8], header[9], header[10], header[11],
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
    }
}
