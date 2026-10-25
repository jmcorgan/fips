//! The IPv6 adapter's MTU arithmetic: how large an IPv6 packet, and how large
//! a TCP segment, a FIPS path carries.
//!
//! Two inputs, one set of constants. The transport form starts from a
//! transport MTU, which the node reports and logs; the payload-limit form
//! starts from the FSP payload limit the node publishes over the link. They
//! agree from a transport MTU of 110 up. Below it the transport form gives
//! the MTU less 77, saturating at zero, while the payload limit has already
//! saturated to zero and gives 33; neither admits a 40-byte IPv6 header.
//! The two TCP MSS forms agree at every MTU.

use super::ipv6_shim::{HEADER_SAVING, IPV6_HEADER_SIZE};
use crate::proto::framing::FIPS_OVERHEAD;
use crate::proto::fsp::wire::FSP_PORT_HEADER_SIZE;

/// The minimum TCP header, without options.
const TCP_HEADER: u16 = 20;

/// FIPS encapsulation overhead for compressed IPv6 shim traffic (port 256):
/// the session datagram framing (`FIPS_OVERHEAD`) and the port header, less
/// what the shim's header compression saves (`HEADER_SAVING`).
///
/// With port multiplexing (4 bytes) and IPv6 header compression (format byte +
/// 6 residual bytes, stripping 34 bytes of addresses/version/payload length),
/// the net overhead for IPv6 packets is 77 bytes.
///
/// ```text
/// Wire size = FIPS_OVERHEAD(106) + port_header(4) + format(1) + residual(6) + upper_payload
///           = 117 + (ipv6_len - 40)
///           = ipv6_len + 77
/// ```
pub const FIPS_IPV6_OVERHEAD: u16 = FIPS_OVERHEAD + FSP_PORT_HEADER_SIZE as u16 - HEADER_SAVING;

// Every node reports and clamps by this figure; a framing change that moves
// it is a visible change and has to be made here on purpose.
const _: () = assert!(
    FIPS_IPV6_OVERHEAD == 77,
    "the IPv6 shim overhead is no longer 77 bytes"
);

/// Calculate the effective IPv6 MTU for FIPS-encapsulated traffic.
///
/// Given a transport MTU (e.g., UDP payload size), returns the maximum
/// IPv6 packet size (including IPv6 header) that can be transmitted
/// through the FIPS mesh after IPv6 header compression.
pub fn effective_ipv6_mtu(transport_mtu: u16) -> u16 {
    transport_mtu.saturating_sub(FIPS_IPV6_OVERHEAD)
}

/// Largest TCP segment size a FIPS-encapsulated path of `transport_mtu`
/// bytes on the wire admits: the effective inner IPv6 MTU less the 40-byte
/// IPv6 header and the 20-byte TCP header.
///
/// Zero means the path has no room for even one payload byte, so no TCP
/// segment fits and no clamp derived from it carries information. That is
/// the one condition the SYN-time clamp treats as unusable regardless of
/// where the MTU came from, and it is why the seed site warns; both read it
/// from here so they cannot disagree about where the cliff is.
pub fn mss_ceiling(transport_mtu: u16) -> u16 {
    max_segment(effective_ipv6_mtu(transport_mtu))
}

/// The largest IPv6 packet a payload limit admits: the shim compresses a
/// 40-byte IPv6 header to [`HEADER_SAVING`] bytes fewer.
pub(crate) fn ipv6_mtu(payload_limit: u16) -> u16 {
    payload_limit.saturating_add(HEADER_SAVING)
}

/// The largest TCP segment a payload limit admits: its IPv6 MTU less the
/// 40-byte IPv6 and 20-byte TCP headers. Zero when not one payload byte fits.
pub(crate) fn tcp_mss(payload_limit: u16) -> u16 {
    max_segment(ipv6_mtu(payload_limit))
}

/// The largest TCP segment an IPv6 MTU of `mtu` bytes carries: less the IPv6
/// header and the minimum TCP header. Zero when not one payload byte fits.
fn max_segment(mtu: u16) -> u16 {
    mtu.saturating_sub(IPV6_HEADER_SIZE as u16)
        .saturating_sub(TCP_HEADER)
}

#[cfg(test)]
#[path = "tests/mtu.rs"]
mod tests;
