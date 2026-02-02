//! Wire Format Parsing and Serialization
//!
//! Defines the FIPS link-layer wire format for packet dispatch.
//! All packets begin with a discriminator byte followed by type-specific payload.
//!
//! ## Packet Types
//!
//! | Byte | Type            | Size      | Description                    |
//! |------|-----------------|-----------|--------------------------------|
//! | 0x00 | Encrypted frame | 29+ bytes | Post-handshake encrypted data  |
//! | 0x01 | Noise IK msg1   | 87 bytes  | Handshake initiation           |
//! | 0x02 | Noise IK msg2   | 42 bytes  | Handshake response             |

use crate::index::SessionIndex;
use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, TAG_SIZE};

// ============================================================================
// Constants
// ============================================================================

/// Discriminator for encrypted frames (post-handshake data).
pub const DISCRIMINATOR_ENCRYPTED: u8 = 0x00;

/// Discriminator for Noise IK message 1 (handshake initiation).
pub const DISCRIMINATOR_MSG1: u8 = 0x01;

/// Discriminator for Noise IK message 2 (handshake response).
pub const DISCRIMINATOR_MSG2: u8 = 0x02;

/// Size of Noise IK message 1 wire packet: discriminator + sender_idx + noise_msg1.
pub const MSG1_WIRE_SIZE: usize = 1 + 4 + HANDSHAKE_MSG1_SIZE; // 87 bytes

/// Size of Noise IK message 2 wire packet: discriminator + sender_idx + receiver_idx + noise_msg2.
pub const MSG2_WIRE_SIZE: usize = 1 + 4 + 4 + HANDSHAKE_MSG2_SIZE; // 42 bytes

/// Minimum size for encrypted frame: discriminator + receiver_idx + counter + tag.
pub const ENCRYPTED_MIN_SIZE: usize = 1 + 4 + 8 + TAG_SIZE; // 29 bytes

/// Overhead added by encrypted frame wrapper.
pub const ENCRYPTED_OVERHEAD: usize = ENCRYPTED_MIN_SIZE;

// ============================================================================
// Encrypted Frame Header
// ============================================================================

/// Parsed encrypted frame header.
///
/// Wire format:
/// ```text
/// [0x00][receiver_idx:4 LE][counter:8 LE][ciphertext+tag]
/// ```
#[derive(Clone, Debug)]
pub struct EncryptedHeader {
    /// Session index chosen by the receiver (for O(1) lookup).
    pub receiver_idx: SessionIndex,
    /// Monotonic counter used as AEAD nonce.
    pub counter: u64,
    /// Offset where ciphertext begins in the original packet.
    pub ciphertext_offset: usize,
}

impl EncryptedHeader {
    /// Parse an encrypted frame header from packet data.
    ///
    /// Returns None if the packet is too short or has wrong discriminator.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ENCRYPTED_MIN_SIZE {
            return None;
        }

        if data[0] != DISCRIMINATOR_ENCRYPTED {
            return None;
        }

        let receiver_idx = SessionIndex::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let counter = u64::from_le_bytes([
            data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
        ]);

        Some(Self {
            receiver_idx,
            counter,
            ciphertext_offset: 13,
        })
    }

    /// Get the ciphertext slice from the original packet.
    pub fn ciphertext<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.ciphertext_offset..]
    }
}

// ============================================================================
// Msg1 Header
// ============================================================================

/// Parsed Noise IK message 1 header.
///
/// Wire format:
/// ```text
/// [0x01][sender_idx:4 LE][noise_msg1:82]
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
    /// Returns None if the packet has wrong size or discriminator.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG1_WIRE_SIZE {
            return None;
        }

        if data[0] != DISCRIMINATOR_MSG1 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[1], data[2], data[3], data[4]]);

        Some(Self {
            sender_idx,
            noise_msg1_offset: 5,
        })
    }

    /// Get the Noise msg1 payload from the original packet.
    pub fn noise_msg1<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg1_offset..]
    }
}

// ============================================================================
// Msg2 Header
// ============================================================================

/// Parsed Noise IK message 2 header.
///
/// Wire format:
/// ```text
/// [0x02][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:33]
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
    /// Returns None if the packet has wrong size or discriminator.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG2_WIRE_SIZE {
            return None;
        }

        if data[0] != DISCRIMINATOR_MSG2 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[5], data[6], data[7], data[8]]);

        Some(Self {
            sender_idx,
            receiver_idx,
            noise_msg2_offset: 9,
        })
    }

    /// Get the Noise msg2 payload from the original packet.
    pub fn noise_msg2<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg2_offset..]
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build a wire-format msg1 packet.
///
/// Format: `[0x01][sender_idx:4 LE][noise_msg1:82]`
pub fn build_msg1(sender_idx: SessionIndex, noise_msg1: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg1.len(), HANDSHAKE_MSG1_SIZE);

    let mut packet = Vec::with_capacity(MSG1_WIRE_SIZE);
    packet.push(DISCRIMINATOR_MSG1);
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg1);
    packet
}

/// Build a wire-format msg2 packet.
///
/// Format: `[0x02][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:33]`
pub fn build_msg2(sender_idx: SessionIndex, receiver_idx: SessionIndex, noise_msg2: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg2.len(), HANDSHAKE_MSG2_SIZE);

    let mut packet = Vec::with_capacity(MSG2_WIRE_SIZE);
    packet.push(DISCRIMINATOR_MSG2);
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg2);
    packet
}

/// Build a wire-format encrypted frame.
///
/// Format: `[0x00][receiver_idx:4 LE][counter:8 LE][ciphertext+tag]`
pub fn build_encrypted(receiver_idx: SessionIndex, counter: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(13 + ciphertext.len());
    packet.push(DISCRIMINATOR_ENCRYPTED);
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(&counter.to_le_bytes());
    packet.extend_from_slice(ciphertext);
    packet
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_header_parse() {
        // Build a valid encrypted frame
        let receiver_idx = SessionIndex::new(0x12345678);
        let counter = 42u64;
        let ciphertext = vec![0xaa; 32]; // 16 plaintext + 16 tag

        let packet = build_encrypted(receiver_idx, counter, &ciphertext);

        assert_eq!(packet.len(), 13 + 32);
        assert_eq!(packet[0], DISCRIMINATOR_ENCRYPTED);

        // Parse it back
        let header = EncryptedHeader::parse(&packet).expect("should parse");
        assert_eq!(header.receiver_idx, receiver_idx);
        assert_eq!(header.counter, 42);
        assert_eq!(header.ciphertext_offset, 13);
        assert_eq!(header.ciphertext(&packet), &ciphertext[..]);
    }

    #[test]
    fn test_encrypted_header_too_short() {
        let packet = vec![0x00; 28]; // One byte too short
        assert!(EncryptedHeader::parse(&packet).is_none());
    }

    #[test]
    fn test_encrypted_header_wrong_discriminator() {
        let mut packet = vec![0x00; 30];
        packet[0] = 0x01; // Wrong discriminator
        assert!(EncryptedHeader::parse(&packet).is_none());
    }

    #[test]
    fn test_msg1_header_parse() {
        let sender_idx = SessionIndex::new(0xABCDEF01);
        let noise_msg1 = vec![0xbb; HANDSHAKE_MSG1_SIZE];

        let packet = build_msg1(sender_idx, &noise_msg1);

        assert_eq!(packet.len(), MSG1_WIRE_SIZE);
        assert_eq!(packet[0], DISCRIMINATOR_MSG1);

        let header = Msg1Header::parse(&packet).expect("should parse");
        assert_eq!(header.sender_idx, sender_idx);
        assert_eq!(header.noise_msg1_offset, 5);
        assert_eq!(header.noise_msg1(&packet), &noise_msg1[..]);
    }

    #[test]
    fn test_msg1_header_wrong_size() {
        let packet = vec![0x01; 86]; // One byte too short
        assert!(Msg1Header::parse(&packet).is_none());

        let packet = vec![0x01; 88]; // One byte too long
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg1_header_wrong_discriminator() {
        let mut packet = vec![0x00; MSG1_WIRE_SIZE];
        packet[0] = 0x02; // Wrong discriminator
        assert!(Msg1Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg2_header_parse() {
        let sender_idx = SessionIndex::new(0x11223344);
        let receiver_idx = SessionIndex::new(0x55667788);
        let noise_msg2 = vec![0xcc; HANDSHAKE_MSG2_SIZE];

        let packet = build_msg2(sender_idx, receiver_idx, &noise_msg2);

        assert_eq!(packet.len(), MSG2_WIRE_SIZE);
        assert_eq!(packet[0], DISCRIMINATOR_MSG2);

        let header = Msg2Header::parse(&packet).expect("should parse");
        assert_eq!(header.sender_idx, sender_idx);
        assert_eq!(header.receiver_idx, receiver_idx);
        assert_eq!(header.noise_msg2_offset, 9);
        assert_eq!(header.noise_msg2(&packet), &noise_msg2[..]);
    }

    #[test]
    fn test_msg2_header_wrong_size() {
        let packet = vec![0x02; 41]; // One byte too short
        assert!(Msg2Header::parse(&packet).is_none());

        let packet = vec![0x02; 43]; // One byte too long
        assert!(Msg2Header::parse(&packet).is_none());
    }

    #[test]
    fn test_msg2_header_wrong_discriminator() {
        let mut packet = vec![0x00; MSG2_WIRE_SIZE];
        packet[0] = 0x00; // Wrong discriminator
        assert!(Msg2Header::parse(&packet).is_none());
    }

    #[test]
    fn test_wire_sizes() {
        // Verify constants match spec
        assert_eq!(MSG1_WIRE_SIZE, 87); // 1 + 4 + 82
        assert_eq!(MSG2_WIRE_SIZE, 42); // 1 + 4 + 4 + 33
        assert_eq!(ENCRYPTED_MIN_SIZE, 29); // 1 + 4 + 8 + 16
    }

    #[test]
    fn test_roundtrip_indices() {
        // Test that indices survive the roundtrip correctly (endianness)
        let idx = SessionIndex::new(0xDEADBEEF);

        let msg1 = build_msg1(idx, &[0u8; HANDSHAKE_MSG1_SIZE]);
        let parsed = Msg1Header::parse(&msg1).unwrap();
        assert_eq!(parsed.sender_idx.as_u32(), 0xDEADBEEF);

        // Verify little-endian encoding
        assert_eq!(msg1[1], 0xEF);
        assert_eq!(msg1[2], 0xBE);
        assert_eq!(msg1[3], 0xAD);
        assert_eq!(msg1[4], 0xDE);
    }
}
