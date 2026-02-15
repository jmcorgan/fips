use super::REPLAY_WINDOW_SIZE;
use std::fmt;

/// Sliding window for replay protection.
///
/// Tracks which packet counters have been received within a window of
/// REPLAY_WINDOW_SIZE. Packets with counters below the window or already
/// seen within the window are rejected.
///
/// Based on WireGuard's anti-replay mechanism (RFC 6479 style).
#[derive(Clone)]
pub struct ReplayWindow {
    /// Highest counter value seen.
    highest: u64,
    /// Bitmap tracking which counters in the window have been seen.
    /// Bit i corresponds to counter (highest - i).
    bitmap: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl ReplayWindow {
    /// Create a new replay window.
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    /// Check if a counter is valid (not replayed, not too old).
    ///
    /// Returns true if the counter is acceptable, false if it should be rejected.
    /// Does NOT update the window - call `accept` after successful decryption.
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.highest {
            // New highest - always acceptable
            return true;
        }

        // Counter is <= highest, check if it's within the window
        let diff = self.highest - counter;
        if diff as usize >= REPLAY_WINDOW_SIZE {
            // Too old (outside window)
            return false;
        }

        // Check bitmap - bit is set if counter was already seen
        let word_idx = (diff as usize) / 64;
        let bit_idx = (diff as usize) % 64;
        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// Accept a counter into the window.
    ///
    /// Call this only after successful decryption to prevent
    /// DoS attacks that exhaust the window.
    pub fn accept(&mut self, counter: u64) {
        if counter > self.highest {
            // Shift the window
            let shift = counter - self.highest;
            if shift as usize >= REPLAY_WINDOW_SIZE {
                // Complete reset
                self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                // Shift bitmap
                self.shift_bitmap(shift as usize);
            }
            self.highest = counter;
            // Mark counter 0 (which is now the highest) as seen
            self.bitmap[0] |= 1;
        } else {
            // Mark the counter as seen
            let diff = self.highest - counter;
            let word_idx = (diff as usize) / 64;
            let bit_idx = (diff as usize) % 64;
            self.bitmap[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// Shift the bitmap by the given number of positions.
    ///
    /// This moves old counters to higher bit positions to make room for the
    /// new highest counter at position 0.
    fn shift_bitmap(&mut self, shift: usize) {
        if shift >= REPLAY_WINDOW_SIZE {
            self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            return;
        }

        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        // Shift entire words first (from high to low to avoid overwriting)
        if word_shift > 0 {
            for i in (word_shift..self.bitmap.len()).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for i in 0..word_shift {
                self.bitmap[i] = 0;
            }
        }

        // Shift bits within words (from low to high so carry propagates correctly)
        if bit_shift > 0 {
            let mut carry = 0u64;
            for i in 0..self.bitmap.len() {
                let new_carry = self.bitmap[i] >> (64 - bit_shift);
                self.bitmap[i] = (self.bitmap[i] << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    /// Get the highest counter seen.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Reset the window (use when rekeying).
    pub fn reset(&mut self) {
        self.highest = 0;
        self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("highest", &self.highest)
            .field("window_size", &REPLAY_WINDOW_SIZE)
            .finish()
    }
}
