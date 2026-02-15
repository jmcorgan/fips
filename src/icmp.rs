//! ICMPv6 message handling for FIPS.
//!
//! Implements ICMPv6 error message generation per RFC 4443.
//! Currently supports Destination Unreachable (Type 1) for
//! packets that cannot be routed.

use std::net::Ipv6Addr;

/// ICMPv6 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6Type {
    /// Destination Unreachable (error).
    DestinationUnreachable = 1,
    /// Packet Too Big (error).
    PacketTooBig = 2,
    /// Time Exceeded (error).
    TimeExceeded = 3,
    /// Parameter Problem (error).
    ParameterProblem = 4,
    /// Echo Request.
    EchoRequest = 128,
    /// Echo Reply.
    EchoReply = 129,
}

/// ICMPv6 Destination Unreachable codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestUnreachableCode {
    /// No route to destination.
    NoRoute = 0,
    /// Communication administratively prohibited.
    AdminProhibited = 1,
    /// Beyond scope of source address.
    BeyondScope = 2,
    /// Address unreachable.
    AddressUnreachable = 3,
    /// Port unreachable.
    PortUnreachable = 4,
    /// Source address failed policy.
    SourcePolicy = 5,
    /// Reject route to destination.
    RejectRoute = 6,
}

/// IPv6 header next-header value for ICMPv6.
pub const IPPROTO_ICMPV6: u8 = 58;

/// Minimum IPv6 MTU - ICMPv6 responses must not exceed this.
const MIN_IPV6_MTU: usize = 1280;

/// IPv6 header length.
const IPV6_HEADER_LEN: usize = 40;

/// ICMPv6 header length (type + code + checksum + unused/data).
const ICMPV6_HEADER_LEN: usize = 8;

/// Maximum original packet bytes to include in ICMPv6 error.
const MAX_ORIGINAL_PACKET: usize = MIN_IPV6_MTU - IPV6_HEADER_LEN - ICMPV6_HEADER_LEN;

/// Check if we should send an ICMPv6 error for this packet.
///
/// Returns false if the packet is:
/// - Too short to be valid IPv6
/// - Not IPv6
/// - An ICMPv6 error message itself
/// - Has a multicast source address
/// - Has a multicast destination address
/// - Has an unspecified source address (::)
pub fn should_send_icmp_error(packet: &[u8]) -> bool {
    // Must have at least an IPv6 header
    if packet.len() < IPV6_HEADER_LEN {
        return false;
    }

    // Must be IPv6
    let version = packet[0] >> 4;
    if version != 6 {
        return false;
    }

    // Extract source address
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());

    // Don't send errors for unspecified source
    if src.is_unspecified() {
        return false;
    }

    // Don't send errors for multicast source (first byte 0xff)
    if src.octets()[0] == 0xff {
        return false;
    }

    // Extract destination address
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());

    // Don't send errors for multicast destination (first byte 0xff)
    // e.g., ff02::2 (all-routers) from Router Solicitation
    if dst.octets()[0] == 0xff {
        return false;
    }

    // Don't send errors for ICMPv6 error messages (types 0-127)
    let next_header = packet[6];
    if next_header == IPPROTO_ICMPV6 && packet.len() > IPV6_HEADER_LEN {
        let icmp_type = packet[IPV6_HEADER_LEN];
        // ICMPv6 error messages are types 0-127
        if icmp_type < 128 {
            return false;
        }
    }

    true
}

/// Build an ICMPv6 Destination Unreachable response.
///
/// Takes the original packet that couldn't be delivered and returns
/// a complete IPv6 packet containing the ICMPv6 error response.
///
/// Arguments:
/// - `original_packet`: The packet that couldn't be routed
/// - `code`: The specific unreachable reason
/// - `our_addr`: Our FIPS address (source of the error)
///
/// Returns None if the original packet is invalid.
pub fn build_dest_unreachable(
    original_packet: &[u8],
    code: DestUnreachableCode,
    our_addr: Ipv6Addr,
) -> Option<Vec<u8>> {
    // Validate original packet
    if original_packet.len() < IPV6_HEADER_LEN {
        return None;
    }

    // Extract destination from original packet (becomes our destination)
    let dest_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&original_packet[8..24]).unwrap());

    // Calculate how much of the original packet to include
    let original_len = original_packet.len().min(MAX_ORIGINAL_PACKET);
    let icmpv6_len = ICMPV6_HEADER_LEN + original_len;
    let total_len = IPV6_HEADER_LEN + icmpv6_len;

    let mut response = vec![0u8; total_len];

    // === IPv6 Header ===
    // Version (4) + Traffic Class (8) + Flow Label (20)
    response[0] = 0x60; // Version 6, TC high bits = 0
    // response[1..4] = 0 (TC low bits + flow label)

    // Payload length (ICMPv6 header + body)
    let payload_len = icmpv6_len as u16;
    response[4..6].copy_from_slice(&payload_len.to_be_bytes());

    // Next header = ICMPv6
    response[6] = IPPROTO_ICMPV6;

    // Hop limit
    response[7] = 64;

    // Source = our address
    response[8..24].copy_from_slice(&our_addr.octets());

    // Destination = original source
    response[24..40].copy_from_slice(&dest_addr.octets());

    // === ICMPv6 Header ===
    let icmp_start = IPV6_HEADER_LEN;

    // Type = Destination Unreachable
    response[icmp_start] = Icmpv6Type::DestinationUnreachable as u8;

    // Code
    response[icmp_start + 1] = code as u8;

    // Checksum placeholder (calculated below)
    // response[icmp_start + 2..icmp_start + 4] = 0

    // Unused (4 bytes of zeros for Dest Unreachable)
    // response[icmp_start + 4..icmp_start + 8] = 0

    // === ICMPv6 Body ===
    // As much of original packet as fits
    response[icmp_start + ICMPV6_HEADER_LEN..].copy_from_slice(&original_packet[..original_len]);

    // Calculate checksum
    let checksum = icmpv6_checksum(&response[icmp_start..], &our_addr, &dest_addr);
    response[icmp_start + 2..icmp_start + 4].copy_from_slice(&checksum.to_be_bytes());

    Some(response)
}

/// Calculate ICMPv6 checksum per RFC 4443.
///
/// The checksum is calculated over a pseudo-header plus the ICMPv6 message.
fn icmpv6_checksum(icmpv6_message: &[u8], src: &Ipv6Addr, dst: &Ipv6Addr) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address (16 bytes)
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Pseudo-header: destination address (16 bytes)
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Pseudo-header: upper-layer packet length (4 bytes, as u32)
    let len = icmpv6_message.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;

    // Pseudo-header: next header (padded to 4 bytes)
    sum += IPPROTO_ICMPV6 as u32;

    // ICMPv6 message (with checksum field = 0)
    let mut i = 0;
    while i + 1 < icmpv6_message.len() {
        // Skip the checksum field (bytes 2-3)
        if i == 2 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([icmpv6_message[i], icmpv6_message[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < icmpv6_message.len() {
        sum += (icmpv6_message[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // One's complement
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV6_HEADER_LEN + payload.len()];

        // Version + TC + Flow Label
        packet[0] = 0x60;

        // Payload length
        let len = payload.len() as u16;
        packet[4..6].copy_from_slice(&len.to_be_bytes());

        // Next header
        packet[6] = next_header;

        // Hop limit
        packet[7] = 64;

        // Source
        packet[8..24].copy_from_slice(&src.octets());

        // Destination
        packet[24..40].copy_from_slice(&dst.octets());

        // Payload
        packet[IPV6_HEADER_LEN..].copy_from_slice(payload);

        packet
    }

    #[test]
    fn test_should_send_error_valid_packet() {
        let src = "fd00::1".parse().unwrap();
        let dst = "fd00::2".parse().unwrap();
        let packet = make_ipv6_packet(src, dst, 17, &[0u8; 8]); // UDP

        assert!(should_send_icmp_error(&packet));
    }

    #[test]
    fn test_should_not_send_error_unspecified_source() {
        let src = Ipv6Addr::UNSPECIFIED;
        let dst = "fd00::2".parse().unwrap();
        let packet = make_ipv6_packet(src, dst, 17, &[0u8; 8]);

        assert!(!should_send_icmp_error(&packet));
    }

    #[test]
    fn test_should_not_send_error_multicast_source() {
        let src = "ff02::1".parse().unwrap();
        let dst = "fd00::2".parse().unwrap();
        let packet = make_ipv6_packet(src, dst, 17, &[0u8; 8]);

        assert!(!should_send_icmp_error(&packet));
    }

    #[test]
    fn test_should_not_send_error_multicast_destination() {
        let src = "fe80::1".parse().unwrap();
        let dst = "ff02::2".parse().unwrap(); // all-routers multicast
        let packet = make_ipv6_packet(src, dst, 17, &[0u8; 8]);

        assert!(!should_send_icmp_error(&packet));
    }

    #[test]
    fn test_should_not_send_error_for_icmp_error() {
        let src = "fd00::1".parse().unwrap();
        let dst = "fd00::2".parse().unwrap();
        // ICMPv6 Destination Unreachable (type 1)
        let icmp_payload = [1u8, 0, 0, 0, 0, 0, 0, 0];
        let packet = make_ipv6_packet(src, dst, IPPROTO_ICMPV6, &icmp_payload);

        assert!(!should_send_icmp_error(&packet));
    }

    #[test]
    fn test_should_send_error_for_icmp_echo() {
        let src = "fd00::1".parse().unwrap();
        let dst = "fd00::2".parse().unwrap();
        // ICMPv6 Echo Request (type 128) - informational, not error
        let icmp_payload = [128u8, 0, 0, 0, 0, 0, 0, 0];
        let packet = make_ipv6_packet(src, dst, IPPROTO_ICMPV6, &icmp_payload);

        assert!(should_send_icmp_error(&packet));
    }

    #[test]
    fn test_should_not_send_error_short_packet() {
        let packet = vec![0u8; 20]; // Too short for IPv6
        assert!(!should_send_icmp_error(&packet));
    }

    #[test]
    fn test_build_dest_unreachable() {
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        let original = make_ipv6_packet(src, dst, 17, &[0u8; 8]);

        let our_addr: Ipv6Addr = "fd00::ffff".parse().unwrap();
        let response = build_dest_unreachable(&original, DestUnreachableCode::NoRoute, our_addr);

        assert!(response.is_some());
        let response = response.unwrap();

        // Check IPv6 header
        assert_eq!(response[0] >> 4, 6); // Version
        assert_eq!(response[6], IPPROTO_ICMPV6); // Next header

        // Check source is our address
        let resp_src = Ipv6Addr::from(<[u8; 16]>::try_from(&response[8..24]).unwrap());
        assert_eq!(resp_src, our_addr);

        // Check destination is original source
        let resp_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&response[24..40]).unwrap());
        assert_eq!(resp_dst, src);

        // Check ICMPv6 type and code
        assert_eq!(response[IPV6_HEADER_LEN], 1); // Type = Dest Unreachable
        assert_eq!(response[IPV6_HEADER_LEN + 1], 0); // Code = No Route
    }

    #[test]
    fn test_build_dest_unreachable_invalid_input() {
        let short_packet = vec![0u8; 20];
        let our_addr: Ipv6Addr = "fd00::ffff".parse().unwrap();

        let response = build_dest_unreachable(&short_packet, DestUnreachableCode::NoRoute, our_addr);
        assert!(response.is_none());
    }

    #[test]
    fn test_build_dest_unreachable_truncates_large_packet() {
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        // Large payload
        let original = make_ipv6_packet(src, dst, 17, &[0u8; 2000]);

        let our_addr: Ipv6Addr = "fd00::ffff".parse().unwrap();
        let response = build_dest_unreachable(&original, DestUnreachableCode::NoRoute, our_addr);

        assert!(response.is_some());
        let response = response.unwrap();

        // Response must not exceed minimum MTU
        assert!(response.len() <= MIN_IPV6_MTU);
    }
}
