//! Encapsulation overhead spanning the FMP and FSP layers.
//!
//! The framing cost of a session datagram is the sum of FMP link framing and
//! FSP session framing, so it belongs to neither layer's wire module alone.

use crate::proto::fsp::wire::FSP_PORT_HEADER_SIZE;

/// FIPS base encapsulation overhead for DataPacket (excluding port payload).
///
/// This is the fixed overhead for a SessionDatagram carrying an FSP DataPacket,
/// used by the send path's CP-flag guard to check whether piggybacked coords
/// fit within the transport MTU. For IPv6 effective MTU calculations, use
/// `FIPS_IPV6_OVERHEAD` which accounts for port multiplexing and header
/// compression.
///
/// Breakdown (traced through the actual send path):
///
/// ```text
/// FMP outer header (cleartext AAD)              16
///   common prefix (4) + receiver_idx (4) + counter (8)
/// FMP AEAD ciphertext:
///   timestamp (4) + msg_type (1)                 5   [FMP inner header]
///   ttl (1) + path_mtu (2) + src (16) + dst (16) 35  [SessionDatagram body]
///   FSP header (4 prefix + 8 counter)            12   [cleartext AAD]
///   FSP AEAD ciphertext:
///     timestamp (4) + msg_type (1) + flags (1)    6   [FSP inner header]
///     <application data>
///     Poly1305 tag                               16   [FSP AEAD]
/// FMP Poly1305 tag                              16   [FMP AEAD]
///                                              ────
///                                               106
/// ```
///
/// Note: the FMP inner header msg_type byte IS the SessionDatagram msg_type
/// byte (shared, not double-counted). The "35 bytes" is the SessionDatagram
/// body after msg_type is consumed by the dispatch layer.
pub const FIPS_OVERHEAD: u16 = 16 + 16 + 5 + 35 + 12 + 6 + 16; // 106 bytes

/// The largest FSP payload a path MTU of `mtu` bytes admits once FMP and FSP
/// framing and the port header are paid, saturating at zero.
#[inline]
pub fn payload_limit(mtu: u16) -> u16 {
    mtu.saturating_sub(FIPS_OVERHEAD)
        .saturating_sub(FSP_PORT_HEADER_SIZE as u16)
}

#[cfg(test)]
#[path = "tests/framing.rs"]
mod tests;
