//! Word-level RLE compression for bloom filter data.
//!
//! Encodes a sequence of `u64` words using run-length encoding.
//! Each run is encoded as `[count:2 LE][word:8 LE]` (10 bytes per run).
//! Sparse data (XOR diffs with mostly zero words) compresses well.
//!
//! ## Delta vs Full Strategy
//!
//! The sender tracks `last_sent_filter` per peer. When a new filter is
//! ready, the sender XORs it with the last-sent filter to produce a diff.
//! The diff is mostly zero words (only changed bits set), which RLE
//! compresses efficiently. If no previous filter exists (first send,
//! size class change, or NACK recovery), a full filter is sent instead.
//!
//! The same RLE codec handles both cases — full filters at ~25% fill
//! still benefit from zero-word runs between set regions.
//!
//! ## NACK Recovery
//!
//! If the receiver detects a sequence gap (missed delta), it sends a
//! NACK. The sender responds with a full filter, resetting the delta
//! baseline for that peer.

/// Statistics from a compression operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionStats {
    /// Number of u64 words in the uncompressed input.
    pub raw_words: usize,
    /// Number of bytes in the compressed output.
    pub compressed_bytes: usize,
    /// Number of distinct runs in the encoding.
    pub run_count: usize,
}

/// RLE-encode a slice of u64 words.
///
/// Returns the compressed bytes and compression statistics.
/// Each run is encoded as `[count:2 LE][word:8 LE]`.
/// Maximum run length is `u16::MAX` (65535); longer runs are split.
pub fn rle_encode(words: &[u64]) -> (Vec<u8>, CompressionStats) {
    let mut buf = Vec::new();
    let mut run_count = 0usize;

    let mut i = 0;
    while i < words.len() {
        let value = words[i];
        let mut count = 1u16;
        while i + (count as usize) < words.len()
            && words[i + count as usize] == value
            && count < u16::MAX
        {
            count += 1;
        }

        buf.extend_from_slice(&count.to_le_bytes());
        buf.extend_from_slice(&value.to_le_bytes());
        run_count += 1;
        i += count as usize;
    }

    let stats = CompressionStats {
        raw_words: words.len(),
        compressed_bytes: buf.len(),
        run_count,
    };
    (buf, stats)
}

/// RLE-decode compressed bytes back to u64 words.
///
/// `expected_words` is the expected number of output words (for validation).
/// Returns an error if the data is truncated or the decoded length doesn't
/// match the expected count.
pub fn rle_decode(data: &[u8], expected_words: usize) -> Result<Vec<u64>, RleError> {
    let mut words = Vec::with_capacity(expected_words);
    let mut pos = 0;

    while pos + 10 <= data.len() {
        let count = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        let value = u64::from_le_bytes(data[pos + 2..pos + 10].try_into().unwrap());
        pos += 10;

        if words.len() + count > expected_words {
            return Err(RleError::DecodedTooLarge {
                expected: expected_words,
                got: words.len() + count,
            });
        }

        words.extend(std::iter::repeat_n(value, count));
    }

    if pos != data.len() {
        return Err(RleError::TruncatedInput {
            remaining: data.len() - pos,
        });
    }

    if words.len() != expected_words {
        return Err(RleError::DecodedSizeMismatch {
            expected: expected_words,
            got: words.len(),
        });
    }

    Ok(words)
}

/// Errors from RLE decoding.
#[derive(Debug, thiserror::Error)]
pub enum RleError {
    #[error("truncated RLE input: {remaining} trailing bytes")]
    TruncatedInput { remaining: usize },

    #[error("decoded size mismatch: expected {expected} words, got {got}")]
    DecodedSizeMismatch { expected: usize, got: usize },

    #[error("decoded data too large: expected {expected} words, got {got}")]
    DecodedTooLarge { expected: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rle_round_trip_all_zero() {
        let words = vec![0u64; 128]; // 1KB filter
        let (encoded, stats) = rle_encode(&words);

        // All zeros = 1 run of 128 zero words = 10 bytes
        assert_eq!(stats.run_count, 1);
        assert_eq!(stats.compressed_bytes, 10);
        assert_eq!(stats.raw_words, 128);

        let decoded = rle_decode(&encoded, 128).unwrap();
        assert_eq!(decoded, words);
    }

    #[test]
    fn test_rle_round_trip_random() {
        // Non-uniform data: each word different
        let words: Vec<u64> = (0..64).map(|i| i * 0x0123456789ABCDEF).collect();
        let (encoded, stats) = rle_encode(&words);

        assert_eq!(stats.raw_words, 64);
        assert_eq!(stats.run_count, 64); // no compression
        assert_eq!(stats.compressed_bytes, 64 * 10);

        let decoded = rle_decode(&encoded, 64).unwrap();
        assert_eq!(decoded, words);
    }

    #[test]
    fn test_rle_round_trip_sparse_diff() {
        // Simulate XOR diff: mostly zeros with a few set words
        let mut words = vec![0u64; 128];
        words[10] = 0xFF00FF00;
        words[50] = 0xDEADBEEF;
        words[127] = 0x1;

        let (encoded, stats) = rle_encode(&words);

        // Should compress well: ~7 runs
        assert!(stats.run_count < 10);
        assert!(stats.compressed_bytes < 128 * 8); // much smaller than raw

        let decoded = rle_decode(&encoded, 128).unwrap();
        assert_eq!(decoded, words);
    }

    #[test]
    fn test_rle_empty_input() {
        let (encoded, stats) = rle_encode(&[]);
        assert_eq!(stats.raw_words, 0);
        assert_eq!(stats.compressed_bytes, 0);
        assert_eq!(stats.run_count, 0);

        let decoded = rle_decode(&encoded, 0).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_rle_decode_truncated() {
        // 5 bytes is not a complete run (need 10)
        let bad_data = vec![0u8; 5];
        let result = rle_decode(&bad_data, 1);
        assert!(matches!(result, Err(RleError::TruncatedInput { .. })));
    }

    #[test]
    fn test_rle_decode_size_mismatch() {
        let words = vec![0u64; 10];
        let (encoded, _) = rle_encode(&words);

        // Expect wrong number of words
        let result = rle_decode(&encoded, 20);
        assert!(matches!(result, Err(RleError::DecodedSizeMismatch { .. })));
    }

    #[test]
    fn test_rle_decode_too_large() {
        let words = vec![0u64; 100];
        let (encoded, _) = rle_encode(&words);

        // Expect fewer words than what's encoded
        let result = rle_decode(&encoded, 50);
        assert!(matches!(result, Err(RleError::DecodedTooLarge { .. })));
    }

    #[test]
    fn test_rle_compression_stats() {
        // 3 runs: 10 zeros, 5 ones, 5 zeros
        let mut words = vec![0u64; 20];
        for w in &mut words[10..15] {
            *w = u64::MAX;
        }

        let (_, stats) = rle_encode(&words);
        assert_eq!(stats.raw_words, 20);
        assert_eq!(stats.run_count, 3);
        assert_eq!(stats.compressed_bytes, 30); // 3 * 10
    }
}
