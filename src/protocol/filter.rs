//! FilterAnnounce message: bloom filter reachability propagation.
//!
//! Supports both full sends and delta (XOR diff) updates with RLE compression.

use super::error::ProtocolError;
use super::link::LinkMessageType;
use crate::bloom::codec::{rle_decode, rle_encode, CompressionStats};
use crate::bloom::BloomFilter;

/// Flag bit: this is a delta (XOR diff) update, not a full filter.
const FLAG_DELTA: u8 = 0x01;

/// FilterAnnounce message for bloom filter reachability propagation.
///
/// ## Wire Format
///
/// ```text
/// [0x20][flags:1][sequence:8 LE][base_seq:8 LE][size_class:1][compressed_payload]
/// ```
///
/// - `flags` bit 0: is_delta (0 = full filter, 1 = XOR diff)
/// - `sequence`: current filter sequence number
/// - `base_seq`: for deltas, the sequence this diff is relative to (0 for full)
/// - `size_class`: filter size in bytes = 512 << size_class (0-6)
/// - `compressed_payload`: RLE-compressed u64 words
#[derive(Clone, Debug)]
pub struct FilterAnnounce {
    /// The bloom filter contents (full filter or XOR diff).
    pub filter: BloomFilter,
    /// Sequence number for this filter update.
    pub sequence: u64,
    /// For deltas: the sequence number this diff is relative to.
    /// For full sends: 0.
    pub base_seq: u64,
    /// Size class: filter size in bytes = 512 << size_class.
    pub size_class: u8,
    /// Whether this is a delta (XOR diff) update.
    pub is_delta: bool,
}

impl FilterAnnounce {
    /// Minimum payload size after msg_type is stripped:
    /// flags(1) + sequence(8) + base_seq(8) + size_class(1) = 18
    const MIN_PAYLOAD_SIZE: usize = 18;

    /// Create a full (non-delta) FilterAnnounce.
    pub fn full(filter: BloomFilter, sequence: u64, size_class: u8) -> Self {
        Self {
            filter,
            sequence,
            base_seq: 0,
            size_class,
            is_delta: false,
        }
    }

    /// Create a delta (XOR diff) FilterAnnounce.
    pub fn delta(
        diff: BloomFilter,
        sequence: u64,
        base_seq: u64,
        size_class: u8,
    ) -> Self {
        Self {
            filter: diff,
            sequence,
            base_seq,
            size_class,
            is_delta: true,
        }
    }

    /// Get the expected filter size in bytes for this size_class.
    pub fn filter_size_bytes(&self) -> usize {
        512usize << self.size_class
    }

    /// Validate the filter matches the declared size_class.
    pub fn is_valid(&self) -> bool {
        self.filter.num_bytes() == self.filter_size_bytes()
            && (self.size_class as usize) < crate::bloom::SIZE_CLASS_BYTES.len()
    }

    /// Encode as link-layer plaintext (includes msg_type byte).
    ///
    /// The filter words are RLE-compressed.
    pub fn encode(&self) -> Result<(Vec<u8>, CompressionStats), ProtocolError> {
        if !self.is_valid() {
            return Err(ProtocolError::Malformed(
                "filter size does not match size_class".into(),
            ));
        }

        let (compressed, stats) = rle_encode(self.filter.as_words());
        let size = 1 + Self::MIN_PAYLOAD_SIZE + compressed.len();
        let mut buf = Vec::with_capacity(size);

        // msg_type
        buf.push(LinkMessageType::FilterAnnounce.to_byte());
        // flags
        let flags = if self.is_delta { FLAG_DELTA } else { 0 };
        buf.push(flags);
        // sequence (8 LE)
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        // base_seq (8 LE)
        buf.extend_from_slice(&self.base_seq.to_le_bytes());
        // size_class
        buf.push(self.size_class);
        // compressed payload
        buf.extend_from_slice(&compressed);

        Ok((buf, stats))
    }

    /// Decode from link-layer payload (after msg_type byte stripped by dispatcher).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < Self::MIN_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::MIN_PAYLOAD_SIZE,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        // flags
        let flags = payload[pos];
        let is_delta = flags & FLAG_DELTA != 0;
        pos += 1;

        // sequence (8 LE)
        let sequence = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad sequence".into()))?,
        );
        pos += 8;

        // base_seq (8 LE)
        let base_seq = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad base_seq".into()))?,
        );
        pos += 8;

        // size_class
        let size_class = payload[pos];
        pos += 1;

        if (size_class as usize) >= crate::bloom::SIZE_CLASS_BYTES.len() {
            return Err(ProtocolError::Malformed(format!(
                "invalid size_class: {size_class} (max {})",
                crate::bloom::MAX_SIZE_CLASS
            )));
        }

        // Decompress RLE payload
        let expected_bytes = 512usize << size_class;
        let expected_words = expected_bytes / 8;
        let compressed_data = &payload[pos..];

        let words = rle_decode(compressed_data, expected_words).map_err(|e| {
            ProtocolError::Malformed(format!("RLE decode error: {e}"))
        })?;

        // Convert words to bytes for BloomFilter construction
        let mut bytes = Vec::with_capacity(expected_bytes);
        for &word in &words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }

        let filter = BloomFilter::from_bytes(bytes, crate::bloom::DEFAULT_HASH_COUNT)
            .map_err(|e| {
                ProtocolError::Malformed(format!("invalid bloom filter: {e}"))
            })?;

        Ok(Self {
            filter,
            sequence,
            base_seq,
            size_class,
            is_delta,
        })
    }
}

/// FilterNack message: request full filter retransmission.
///
/// Sent when a node receives an out-of-sequence delta update.
///
/// ## Wire Format
///
/// ```text
/// [0x21][expected_seq:8 LE]
/// ```
#[derive(Clone, Debug)]
pub struct FilterNack {
    /// The sequence number the receiver expected.
    pub expected_seq: u64,
}

impl FilterNack {
    /// Encode as link-layer plaintext (includes msg_type byte).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9);
        buf.push(LinkMessageType::FilterNack.to_byte());
        buf.extend_from_slice(&self.expected_seq.to_le_bytes());
        buf
    }

    /// Decode from link-layer payload (after msg_type byte stripped by dispatcher).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 8 {
            return Err(ProtocolError::MessageTooShort {
                expected: 8,
                got: payload.len(),
            });
        }
        let expected_seq = u64::from_le_bytes(
            payload[..8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad expected_seq".into()))?,
        );
        Ok(Self { expected_seq })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeAddr;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    #[test]
    fn test_filter_announce_full_roundtrip() {
        let mut filter = BloomFilter::new();
        filter.insert(&make_node_addr(42));
        filter.insert(&make_node_addr(99));

        let announce = FilterAnnounce::full(filter, 500, 1);
        assert!(announce.is_valid());
        assert!(!announce.is_delta);

        let (encoded, stats) = announce.encode().unwrap();
        assert!(stats.compressed_bytes > 0);
        assert_eq!(encoded[0], LinkMessageType::FilterAnnounce.to_byte());

        // Decode strips msg_type
        let decoded = FilterAnnounce::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.sequence, 500);
        assert_eq!(decoded.base_seq, 0);
        assert_eq!(decoded.size_class, 1);
        assert!(!decoded.is_delta);
        assert!(decoded.filter.contains(&make_node_addr(42)));
        assert!(decoded.filter.contains(&make_node_addr(99)));
        assert!(!decoded.filter.contains(&make_node_addr(1)));
    }

    #[test]
    fn test_filter_announce_delta_roundtrip() {
        let mut old_filter = BloomFilter::new();
        old_filter.insert(&make_node_addr(1));

        let mut new_filter = BloomFilter::new();
        new_filter.insert(&make_node_addr(1));
        new_filter.insert(&make_node_addr(2));

        let diff = old_filter.xor_diff(&new_filter).unwrap();
        let announce = FilterAnnounce::delta(diff.clone(), 5, 4, 1);
        assert!(announce.is_delta);

        let (encoded, _) = announce.encode().unwrap();
        let decoded = FilterAnnounce::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.sequence, 5);
        assert_eq!(decoded.base_seq, 4);
        assert!(decoded.is_delta);
        assert_eq!(decoded.filter, diff);
    }

    #[test]
    fn test_filter_announce_empty_filter_compresses_well() {
        let filter = BloomFilter::new(); // all zeros
        let announce = FilterAnnounce::full(filter, 1, 1);
        let (encoded, stats) = announce.encode().unwrap();

        // 1KB of zeros should compress to ~10 bytes of RLE + 19 bytes header
        assert!(encoded.len() < 50, "encoded size: {}", encoded.len());
        assert_eq!(stats.run_count, 1);
    }

    #[test]
    fn test_filter_announce_various_size_classes() {
        for size_class in 0..=6u8 {
            let num_bits = crate::bloom::size_class_to_bits(size_class);
            let filter = BloomFilter::with_params(num_bits, 5).unwrap();
            let announce = FilterAnnounce::full(filter, 1, size_class);
            assert!(announce.is_valid());

            let (encoded, _) = announce.encode().unwrap();
            let decoded = FilterAnnounce::decode(&encoded[1..]).unwrap();
            assert_eq!(decoded.size_class, size_class);
            assert_eq!(decoded.filter.num_bits(), num_bits);
        }
    }

    #[test]
    fn test_filter_announce_decode_rejects_bad_size_class() {
        let filter = BloomFilter::new();
        let announce = FilterAnnounce::full(filter, 1, 1);
        let (mut encoded, _) = announce.encode().unwrap();

        // Corrupt size_class byte (offset: 1 msg_type + 1 flags + 8 seq + 8 base_seq = 18)
        encoded[18] = 7; // invalid

        let result = FilterAnnounce::decode(&encoded[1..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_announce_decode_rejects_truncated() {
        let result = FilterAnnounce::decode(&[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_nack_roundtrip() {
        let nack = FilterNack { expected_seq: 42 };
        let encoded = nack.encode();
        assert_eq!(encoded.len(), 9);
        assert_eq!(encoded[0], LinkMessageType::FilterNack.to_byte());

        let decoded = FilterNack::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.expected_seq, 42);
    }

    #[test]
    fn test_filter_nack_decode_truncated() {
        let result = FilterNack::decode(&[0u8; 3]);
        assert!(result.is_err());
    }
}
