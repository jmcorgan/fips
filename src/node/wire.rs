//! Wire Format Parsing and Serialization
//!
//! Defines the FIPS link-layer wire format (FLP) for packet dispatch.
//! All packets begin with a 4-byte common prefix followed by phase-specific fields.
//!
//! ## Common Prefix (4 bytes)
//!
//! ```text
//! [ver+phase:1][flags:1][payload_len:2 LE]
//! ```
//!
//! ## Packet Types
//!
//! | Phase | Type            | Size      | Description                    |
//! |-------|-----------------|-----------|--------------------------------|
//! | 0x0   | Encrypted frame | 32+ bytes | Post-handshake encrypted data  |
//! | 0x1   | Noise IK msg1   | 90 bytes  | Handshake initiation           |
//! | 0x2   | Noise IK msg2   | 45 bytes  | Handshake response             |

use crate::utils::index::SessionIndex;
use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, TAG_SIZE};

// ============================================================================
// Constants
// ============================================================================

/// FLP protocol version (4 high bits of byte 0).
pub const FLP_VERSION: u8 = 0;

/// Phase value for established (encrypted) frames.
pub const PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for Noise IK message 1 (handshake initiation).
pub const PHASE_MSG1: u8 = 0x1;

/// Phase value for Noise IK message 2 (handshake response).
pub const PHASE_MSG2: u8 = 0x2;

/// Size of the common packet prefix (all packet types).
pub const COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full established frame header (prefix + receiver_idx + counter).
pub const ESTABLISHED_HEADER_SIZE: usize = 16;

/// Size of Noise IK message 1 wire packet: prefix + sender_idx + noise_msg1.
pub const MSG1_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + HANDSHAKE_MSG1_SIZE; // 90 bytes

/// Size of Noise IK message 2 wire packet: prefix + sender_idx + receiver_idx + noise_msg2.
pub const MSG2_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + 4 + HANDSHAKE_MSG2_SIZE; // 45 bytes

/// Minimum size for encrypted frame: header + tag (no plaintext).
pub const ENCRYPTED_MIN_SIZE: usize = ESTABLISHED_HEADER_SIZE + TAG_SIZE; // 32 bytes

/// Size of the encrypted inner header (timestamp + message type).
pub const INNER_HEADER_SIZE: usize = 5;

// Flag bit constants (byte 1 of common prefix, meaningful only for phase 0x0).
// Reserved for upcoming rekeying, congestion signaling, and RTT measurement.
#[allow(dead_code)]
/// Key epoch flag — selects active key during rekeying.
pub const FLAG_KEY_EPOCH: u8 = 0x01;
#[allow(dead_code)]
/// Congestion Experienced echo flag.
pub const FLAG_CE: u8 = 0x02;
#[allow(dead_code)]
/// Spin bit for RTT measurement.
pub const FLAG_SP: u8 = 0x04;

// ============================================================================
// Common Prefix
// ============================================================================

/// Parsed common packet prefix (first 4 bytes of every FLP packet).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct CommonPrefix {
    /// Protocol version (high nibble of byte 0).
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-packet signal flags (meaningful only for phase 0x0).
    #[allow(dead_code)]
    pub flags: u8,
    /// Length of payload following the phase-specific header (excludes AEAD tag).
    #[allow(dead_code)]
    pub payload_len: u16,
}

impl CommonPrefix {
    /// Parse a common prefix from the first 4 bytes of packet data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < COMMON_PREFIX_SIZE {
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

    /// Encode the ver+phase byte.
    fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

// ============================================================================
// Encrypted Frame Header
// ============================================================================

/// Parsed established frame header (phase 0x0).
///
/// Wire format (16 bytes):
/// ```text
/// [ver+phase:1][flags:1][payload_len:2 LE][receiver_idx:4 LE][counter:8 LE]
/// ```
///
/// The full 16-byte header is used as AAD for the AEAD construction.
#[derive(Clone, Debug)]
pub struct EncryptedHeader {
    /// Per-packet flags (K, CE, SP).
    #[allow(dead_code)]
    pub flags: u8,
    /// Length of encrypted payload (excluding AEAD tag).
    #[allow(dead_code)]
    pub payload_len: u16,
    /// Session index chosen by the receiver (for O(1) lookup).
    pub receiver_idx: SessionIndex,
    /// Monotonic counter used as AEAD nonce.
    pub counter: u64,
    /// Raw 16-byte header for use as AEAD AAD.
    pub header_bytes: [u8; ESTABLISHED_HEADER_SIZE],
}

impl EncryptedHeader {
    /// Parse an established frame header from packet data.
    ///
    /// Returns None if the packet is too short or has wrong version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ENCRYPTED_MIN_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FLP_VERSION || phase != PHASE_ESTABLISHED {
            return None;
        }

        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);

        let mut header_bytes = [0u8; ESTABLISHED_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..ESTABLISHED_HEADER_SIZE]);

        Some(Self {
            flags,
            payload_len,
            receiver_idx,
            counter,
            header_bytes,
        })
    }

    /// Offset where ciphertext begins in the original packet.
    pub fn ciphertext_offset(&self) -> usize {
        ESTABLISHED_HEADER_SIZE
    }

    /// Get the ciphertext slice from the original packet.
    #[cfg(test)]
    pub fn ciphertext<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[ESTABLISHED_HEADER_SIZE..]
    }
}

// ============================================================================
// Msg1 Header
// ============================================================================

/// Parsed Noise IK message 1 header (phase 0x1).
///
/// Wire format (90 bytes):
/// ```text
/// [0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:82]
/// ```
#[derive(Clone, Debug)]
pub struct Msg1Header {
    /// Session index chosen by the sender (becomes receiver_idx for responses).
    pub sender_idx: SessionIndex,
    /// Offset where Noise msg1 payload begins.
    pub noise_msg1_offset: usize,
}

impl Msg1Header {
    /// Parse a msg1 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG1_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FLP_VERSION || phase != PHASE_MSG1 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Some(Self {
            sender_idx,
            noise_msg1_offset: COMMON_PREFIX_SIZE + 4, // 8
        })
    }

    /// Get the Noise msg1 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg1<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg1_offset..]
    }
}

// ============================================================================
// Msg2 Header
// ============================================================================

/// Parsed Noise IK message 2 header (phase 0x2).
///
/// Wire format (45 bytes):
/// ```text
/// [0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:33]
/// ```
#[derive(Clone, Debug)]
pub struct Msg2Header {
    /// Session index chosen by the responder.
    pub sender_idx: SessionIndex,
    /// Echo of the initiator's sender_idx from msg1.
    pub receiver_idx: SessionIndex,
    /// Offset where Noise msg2 payload begins.
    pub noise_msg2_offset: usize,
}

impl Msg2Header {
    /// Parse a msg2 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG2_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FLP_VERSION || phase != PHASE_MSG2 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[8], data[9], data[10], data[11]]);

        Some(Self {
            sender_idx,
            receiver_idx,
            noise_msg2_offset: COMMON_PREFIX_SIZE + 4 + 4, // 12
        })
    }

    /// Get the Noise msg2 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg2<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg2_offset..]
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build a wire-format msg1 packet.
///
/// Format: `[0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:82]`
pub fn build_msg1(sender_idx: SessionIndex, noise_msg1: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg1.len(), HANDSHAKE_MSG1_SIZE);

    let payload_len = (4 + noise_msg1.len()) as u16; // sender_idx + noise_msg1

    let mut packet = Vec::with_capacity(MSG1_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FLP_VERSION, PHASE_MSG1));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg1);
    packet
}

/// Build a wire-format msg2 packet.
///
/// Format: `[0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:33]`
pub fn build_msg2(sender_idx: SessionIndex, receiver_idx: SessionIndex, noise_msg2: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg2.len(), HANDSHAKE_MSG2_SIZE);

    let payload_len = (4 + 4 + noise_msg2.len()) as u16; // sender + receiver + noise

    let mut packet = Vec::with_capacity(MSG2_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FLP_VERSION, PHASE_MSG2));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg2);
    packet
}

/// Build the 16-byte outer header for an established frame.
///
/// Returns the header bytes (for use as AAD) separately from the construction.
pub fn build_established_header(
    receiver_idx: SessionIndex,
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> [u8; ESTABLISHED_HEADER_SIZE] {
    let mut header = [0u8; ESTABLISHED_HEADER_SIZE];
    header[0] = CommonPrefix::ver_phase_byte(FLP_VERSION, PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
    header[8..16].copy_from_slice(&counter.to_le_bytes());
    header
}

/// Build a wire-format encrypted frame.
///
/// Format: `[header:16][ciphertext+tag]`
///
/// The header is constructed from the parameters and used as AAD during
/// encryption. The caller should use `build_established_header` to construct
/// the header, encrypt with it as AAD, then call this to assemble the packet.
pub fn build_encrypted(header: &[u8; ESTABLISHED_HEADER_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + ciphertext.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(ciphertext);
    packet
}

// ============================================================================
// Inner Header Helpers
// ============================================================================

/// Prepend the 5-byte inner header (timestamp + msg_type) to a link message.
///
/// The caller provides the original plaintext starting with `[msg_type][payload...]`.
/// This prepends `[timestamp:4 LE]` before the msg_type byte.
pub fn prepend_inner_header(timestamp_ms: u32, plaintext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + plaintext.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.extend_from_slice(plaintext);
    buf
}

/// Strip the 4-byte timestamp from a decrypted inner payload.
///
/// Returns `(timestamp, &payload_starting_at_msg_type)` or None if too short.
pub fn strip_inner_header(plaintext: &[u8]) -> Option<(u32, &[u8])> {
    if plaintext.len() < INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    Some((timestamp, &plaintext[4..]))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_prefix_parse() {
        let data = [0x00, 0x04, 0x20, 0x00]; // ver=0, phase=0, flags=SP, payload_len=32
        let prefix = CommonPrefix::parse(&data).unwrap();
        assert_eq!(prefix.version, 0);
        assert_eq!(prefix.phase, 0);
        assert_eq!(prefix.flags, FLAG_SP);
        assert_eq!(prefix.payload_len, 32);
    }

    #[test]
    fn test_common_prefix_too_short() {
        assert!(CommonPrefix::parse(&[0, 0, 0]).is_none());
    }

    #[test]
    fn test_encrypted_header_parse() {
        let receiver_idx = SessionIndex::new(0x12345678);
        let counter = 42u64;
        let flags = 0u8;
        let payload_len = 32u16; // 16 plaintext + 16 tag
        let ciphertext = vec![0xaa; 48]; // payload_len + TAG_SIZE

        let header = build_established_header(receiver_idx, counter, flags, payload_len);
        let packet = build_encrypted(&header, &ciphertext);

        assert_eq!(packet.len(), ESTABLISHED_HEADER_SIZE + 48);
        assert_eq!(packet[0], 0x00); // ver=0, phase=0

        let parsed = EncryptedHeader::parse(&packet).expect("should parse");
        assert_eq!(parsed.receiver_idx, receiver_idx);
        assert_eq!(parsed.counter, 42);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.payload_len, 32);
        assert_eq!(parsed.header_bytes, header);
        assert_eq!(parsed.ciphertext(&packet), &ciphertext[..]);
    }

    #[test]
    fn test_encrypted_header_too_short() {
        let packet = vec![0x00; ENCRYPTED_MIN_SIZE - 1];
        assert!(EncryptedHeader::parse(&packet).is_none());
    }

    #[test]
    fn test_encrypted_header_wrong_phase() {
        let mut packet = vec![0x00; ENCRYPTED_MIN_SIZE];
        packet[0] = 0x01; // phase 1 (msg1), not established
        assert!(EncryptedHeader::parse(&packet).is_none());
    }

    #[test]
    fn test_encrypted_header_wrong_version() {
        let mut packet = vec![0x00; ENCRYPTED_MIN_SIZE];
        packet[0] = 0x10; // version 1, phase 0
        assert!(EncryptedHeader::parse(&packet).is_none());
    }

    #[test]
    fn test_msg1_header_parse() {
        let sender_idx = SessionIndex::new(0xABCDEF01);
        let noise_msg1 = vec![0xbb; HANDSHAKE_MSG1_SIZE];

        let packet = build_msg1(sender_idx, &noise_msg1);

        assert_eq!(packet.len(), MSG1_WIRE_SIZE);
        assert_eq!(packet[0], 0x01); // ver=0, phase=1

        let header = Msg1Header::parse(&packet).expect("should parse");
        assert_eq!(header.sender_idx, sender_idx);
        assert_eq!(header.noise_msg1_offset, 8);
        assert_eq!(header.noise_msg1(&packet), &noise_msg1[..]);
    }

    #[test]
    fn test_msg1_header_wrong_size() {
        let packet = vec![0x01; MSG1_WIRE_SIZE - 1];
        assert!(Msg1Header::parse(&packet).is_none());

        let packet = vec![0x01; MSG1_WIRE_SIZE + 1];
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg1_header_wrong_phase() {
        let mut packet = vec![0x00; MSG1_WIRE_SIZE];
        packet[0] = 0x02; // phase 2, not phase 1
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg1_header_nonzero_flags() {
        let mut packet = build_msg1(SessionIndex::new(1), &[0u8; HANDSHAKE_MSG1_SIZE]);
        packet[1] = 0x01; // flags must be zero during handshake
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg2_header_parse() {
        let sender_idx = SessionIndex::new(0x11223344);
        let receiver_idx = SessionIndex::new(0x55667788);
        let noise_msg2 = vec![0xcc; HANDSHAKE_MSG2_SIZE];

        let packet = build_msg2(sender_idx, receiver_idx, &noise_msg2);

        assert_eq!(packet.len(), MSG2_WIRE_SIZE);
        assert_eq!(packet[0], 0x02); // ver=0, phase=2

        let header = Msg2Header::parse(&packet).expect("should parse");
        assert_eq!(header.sender_idx, sender_idx);
        assert_eq!(header.receiver_idx, receiver_idx);
        assert_eq!(header.noise_msg2_offset, 12);
        assert_eq!(header.noise_msg2(&packet), &noise_msg2[..]);
    }

    #[test]
    fn test_msg2_header_wrong_size() {
        let packet = vec![0x02; MSG2_WIRE_SIZE - 1];
        assert!(Msg2Header::parse(&packet).is_none());

        let packet = vec![0x02; MSG2_WIRE_SIZE + 1];
        assert!(Msg2Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg2_header_wrong_phase() {
        let mut packet = vec![0x00; MSG2_WIRE_SIZE];
        packet[0] = 0x00; // phase 0, not phase 2
        assert!(Msg2Header::parse(&packet).is_none());
    }

    #[test]
    fn test_wire_sizes() {
        assert_eq!(MSG1_WIRE_SIZE, 90);  // 4 + 4 + 82
        assert_eq!(MSG2_WIRE_SIZE, 45);  // 4 + 4 + 4 + 33
        assert_eq!(ENCRYPTED_MIN_SIZE, 32); // 16 + 16
        assert_eq!(COMMON_PREFIX_SIZE, 4);
        assert_eq!(ESTABLISHED_HEADER_SIZE, 16);
        assert_eq!(INNER_HEADER_SIZE, 5);
    }

    #[test]
    fn test_roundtrip_indices() {
        let idx = SessionIndex::new(0xDEADBEEF);

        let msg1 = build_msg1(idx, &[0u8; HANDSHAKE_MSG1_SIZE]);
        let parsed = Msg1Header::parse(&msg1).unwrap();
        assert_eq!(parsed.sender_idx.as_u32(), 0xDEADBEEF);

        // Verify little-endian encoding (sender_idx starts at offset 4)
        assert_eq!(msg1[4], 0xEF);
        assert_eq!(msg1[5], 0xBE);
        assert_eq!(msg1[6], 0xAD);
        assert_eq!(msg1[7], 0xDE);
    }

    #[test]
    fn test_inner_header_prepend_strip() {
        let timestamp: u32 = 12345;
        let original = vec![0x10, 0xAA, 0xBB]; // msg_type + payload

        let with_header = prepend_inner_header(timestamp, &original);
        assert_eq!(with_header.len(), 4 + 3); // timestamp + original

        let (ts, rest) = strip_inner_header(&with_header).unwrap();
        assert_eq!(ts, 12345);
        assert_eq!(rest, &original[..]);
    }

    #[test]
    fn test_inner_header_too_short() {
        assert!(strip_inner_header(&[0, 0, 0, 0]).is_none()); // needs 5 bytes minimum
    }

    #[test]
    fn test_flags_byte() {
        let header = build_established_header(
            SessionIndex::new(1),
            0,
            FLAG_KEY_EPOCH | FLAG_SP,
            100,
        );
        assert_eq!(header[1], 0x05); // bits 0 and 2 set

        let parsed = EncryptedHeader::parse(&[
            header[0], header[1], header[2], header[3],
            header[4], header[5], header[6], header[7],
            header[8], header[9], header[10], header[11],
            header[12], header[13], header[14], header[15],
            // minimum: TAG_SIZE bytes of ciphertext
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]).unwrap();
        assert_eq!(parsed.flags & FLAG_KEY_EPOCH, FLAG_KEY_EPOCH);
        assert_eq!(parsed.flags & FLAG_CE, 0);
        assert_eq!(parsed.flags & FLAG_SP, FLAG_SP);
    }

    #[test]
    fn test_payload_len_in_msg1() {
        let packet = build_msg1(SessionIndex::new(1), &[0u8; HANDSHAKE_MSG1_SIZE]);
        let prefix = CommonPrefix::parse(&packet).unwrap();
        // payload_len = sender_idx(4) + noise_msg1(82) = 86
        assert_eq!(prefix.payload_len, 86);
    }

    #[test]
    fn test_payload_len_in_msg2() {
        let packet = build_msg2(
            SessionIndex::new(1),
            SessionIndex::new(2),
            &[0u8; HANDSHAKE_MSG2_SIZE],
        );
        let prefix = CommonPrefix::parse(&packet).unwrap();
        // payload_len = sender_idx(4) + receiver_idx(4) + noise_msg2(33) = 41
        assert_eq!(prefix.payload_len, 41);
    }
}
