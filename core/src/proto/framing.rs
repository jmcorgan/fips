//! Encapsulation overhead spanning the FMP and FSP layers.
//!
//! The framing cost of a session datagram is the sum of FMP link framing and
//! FSP session framing, so it belongs to neither layer's wire module alone.

use crate::noise;
use crate::proto::fsp::wire::FSP_PORT_HEADER_SIZE;
use crate::proto::{fmp, fsp, link};

/// The SessionDatagram's msg_type byte, which is also the last byte of the
/// FMP inner header, so the sum counts it once.
const SHARED_BYTE: usize = 1;

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
pub const FIPS_OVERHEAD: u16 = (fmp::wire::ESTABLISHED_HEADER_SIZE
    + fmp::wire::INNER_HEADER_SIZE
    + (link::SESSION_DATAGRAM_HEADER_SIZE - SHARED_BYTE)
    + fsp::wire::FSP_HEADER_SIZE
    + fsp::wire::FSP_INNER_HEADER_SIZE
    + fsp::wire::TAG_SIZE
    + noise::TAG_SIZE) as u16;

// Every payload limit and IPv6 MTU the node reports is derived from this
// figure; a framing change that moves it has to be made here on purpose.
const _: () = assert!(
    FIPS_OVERHEAD == 106,
    "the FIPS framing overhead is no longer 106 bytes"
);

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
