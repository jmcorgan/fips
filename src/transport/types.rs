//! Plain, `no_std`+`alloc`-clean transport primitives.
//!
//! The identifier/address/statistics value types shared across the transport
//! layer, defined free of any `std` dependency so the sans-IO protocol cores
//! (e.g. `proto::fmp`) can name them without pulling in `std`. The
//! `std`-requiring helpers (`TransportAddr::from_socket_addr`, socket-address
//! resolution, `local_addr`) stay in `transport`. Re-exported from `transport`
//! via `pub use types::*`, so existing `crate::transport::{LinkId, ...}`
//! imports are unaffected.

use core::fmt;
use core::time::Duration;

// ============================================================================
// Transport Identifiers
// ============================================================================

/// Unique identifier for a transport instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportId(u32);

impl TransportId {
    /// Create a new transport ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport:{}", self.0)
    }
}

/// Unique identifier for a link instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkId(u64);

impl LinkId {
    /// Create a new link ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "link:{}", self.0)
    }
}

// ============================================================================
// Link Direction
// ============================================================================

/// Direction of link establishment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDirection {
    /// We initiated the connection.
    Outbound,
    /// They initiated the connection.
    Inbound,
}

impl fmt::Display for LinkDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LinkDirection::Outbound => "outbound",
            LinkDirection::Inbound => "inbound",
        };
        write!(f, "{}", s)
    }
}

// ============================================================================
// Transport Address
// ============================================================================

/// Opaque transport-specific address.
///
/// Each transport type interprets this differently:
/// - UDP/TCP: "host:port" (IP address or DNS hostname)
/// - Ethernet: MAC address (6 bytes)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TransportAddr(Vec<u8>);

impl TransportAddr {
    /// Create a transport address from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create a transport address from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Create a transport address from a string.
    pub fn from_string(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Try to interpret as a UTF-8 string.
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// Get the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "TransportAddr(\"{}\")", s),
            None => write!(f, "TransportAddr({:?})", self.0),
        }
    }
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Best-effort display as string if valid UTF-8. Otherwise render a
        // 6-byte payload as a colon-separated MAC (standard Unix notation,
        // matching BLE addrs, `ip link`/`ip neigh`, and packet logs), and
        // any other non-UTF-8 byte string as bare hex.
        match self.as_str() {
            Some(s) => write!(f, "{}", s),
            None if self.0.len() == 6 => {
                for (i, byte) in self.0.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
            None => {
                for byte in &self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }
    }
}

impl From<&str> for TransportAddr {
    fn from(s: &str) -> Self {
        Self::from_string(s)
    }
}

impl From<String> for TransportAddr {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

// ============================================================================
// Link Statistics
// ============================================================================

/// Statistics for a link.
#[derive(Clone, Debug, Default)]
pub struct LinkStats {
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_recv: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_recv: u64,
    /// Timestamp of last received packet (Unix milliseconds).
    pub last_recv_ms: u64,
    /// Estimated round-trip time in milliseconds (0 = no estimate yet).
    rtt_estimate: u64,
    /// Observed packet loss rate (0.0-1.0).
    pub loss_rate: f32,
    /// Estimated throughput in bytes/second.
    pub throughput_estimate: u64,
}

impl LinkStats {
    /// Create new link statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sent packet.
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received packet.
    pub fn record_recv(&mut self, bytes: usize, timestamp_ms: u64) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
        self.last_recv_ms = timestamp_ms;
    }

    /// Get the RTT estimate, if available.
    pub fn rtt_estimate(&self) -> Option<Duration> {
        if self.rtt_estimate == 0 {
            None
        } else {
            Some(Duration::from_millis(self.rtt_estimate))
        }
    }

    /// Update RTT estimate from a probe response.
    ///
    /// Uses exponential moving average with alpha=0.2.
    pub fn update_rtt(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_millis() as u64;
        if self.rtt_estimate == 0 {
            self.rtt_estimate = rtt_ms;
        } else {
            let alpha = 0.2;
            self.rtt_estimate =
                (alpha * rtt_ms as f64 + (1.0 - alpha) * self.rtt_estimate as f64) as u64;
        }
    }

    /// Time since last receive (for keepalive/timeout).
    pub fn time_since_recv(&self, current_time_ms: u64) -> u64 {
        if self.last_recv_ms == 0 {
            return u64::MAX;
        }
        current_time_ms.saturating_sub(self.last_recv_ms)
    }

    /// Reset all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}
