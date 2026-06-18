//! TCP MSS (Maximum Segment Size) clamping for MTU handling.
//!
//! Intercepts TCP SYN packets and reduces the MSS option to ensure
//! TCP segments fit within the FIPS effective MTU after encapsulation.

/// TCP header minimum length (without options).
const TCP_HEADER_MIN_LEN: usize = 20;

/// TCP option kind for MSS.
const TCP_OPT_MSS: u8 = 2;

/// TCP option length for MSS (kind + length + value).
const TCP_OPT_MSS_LEN: u8 = 4;

/// TCP flags offset in header.
const TCP_FLAGS_OFFSET: usize = 13;

/// TCP SYN flag bit.
const TCP_FLAG_SYN: u8 = 0x02;

/// Check if a TCP packet is a SYN packet (has SYN flag set).
fn is_tcp_syn(tcp_header: &[u8]) -> bool {
    if tcp_header.len() < TCP_HEADER_MIN_LEN {
        return false;
    }
    (tcp_header[TCP_FLAGS_OFFSET] & TCP_FLAG_SYN) != 0
}

/// Get the TCP data offset (header length in 32-bit words).
fn get_tcp_data_offset(tcp_header: &[u8]) -> usize {
    if tcp_header.len() < TCP_HEADER_MIN_LEN {
        return 0;
    }
    ((tcp_header[12] >> 4) as usize) * 4
}

/// Clamp TCP MSS in a SYN packet if needed.
///
/// Searches for the MSS option in TCP options and reduces it if it exceeds
/// the maximum safe MSS for the given MTU.
///
/// Returns true if the packet was modified (MSS was clamped).
pub fn clamp_tcp_mss(ipv6_packet: &mut [u8], max_mss: u16) -> bool {
    // Validate IPv6 header
    if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
        return false;
    }

    // Check if next header is TCP (6)
    let next_header = ipv6_packet[6];
    if next_header != 6 {
        return false;
    }

    // Get TCP header start
    let tcp_start = 40;
    if ipv6_packet.len() < tcp_start + TCP_HEADER_MIN_LEN {
        return false;
    }

    let tcp_header = &ipv6_packet[tcp_start..];

    // Only process SYN packets
    if !is_tcp_syn(tcp_header) {
        return false;
    }

    // Get TCP header length
    let tcp_header_len = get_tcp_data_offset(tcp_header);
    if tcp_header_len < TCP_HEADER_MIN_LEN || tcp_header_len > tcp_header.len() {
        return false;
    }

    // Parse TCP options
    let options_start = tcp_start + TCP_HEADER_MIN_LEN;
    let options_end = tcp_start + tcp_header_len;

    if options_end > ipv6_packet.len() {
        return false;
    }

    let mut modified = false;
    let mut i = options_start;

    while i < options_end {
        let kind = ipv6_packet[i];

        // End of options
        if kind == 0 {
            break;
        }

        // NOP (padding)
        if kind == 1 {
            i += 1;
            continue;
        }

        // All other options have length field
        if i + 1 >= options_end {
            break;
        }

        let length = ipv6_packet[i + 1] as usize;
        if length < 2 || i + length > options_end {
            break;
        }

        // Check for MSS option
        if kind == TCP_OPT_MSS && length == TCP_OPT_MSS_LEN as usize {
            // Read current MSS value
            let current_mss = u16::from_be_bytes([ipv6_packet[i + 2], ipv6_packet[i + 3]]);

            // Clamp if needed
            if current_mss > max_mss {
                ipv6_packet[i + 2..i + 4].copy_from_slice(&max_mss.to_be_bytes());

                // Recompute the now-stale checksum over the rewritten header.
                recalculate_l4_checksum(ipv6_packet);

                modified = true;
            }
            break; // MSS option found, no need to continue
        }

        i += length;
    }

    modified
}

/// Recalculate the TCP or UDP checksum (IPv6 pseudo-header + segment) in place.
///
/// Completes the checksum macOS leaves offloaded on hairpinned self-traffic, and
/// is reused by MSS clamping. No-op for other next-headers (e.g. ICMPv6) and for
/// malformed packets. Assumes the L4 header follows the 40-byte IPv6 header, as
/// all FIPS packets do.
pub fn recalculate_l4_checksum(ipv6_packet: &mut [u8]) {
    if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
        return;
    }
    let payload_len = u16::from_be_bytes([ipv6_packet[4], ipv6_packet[5]]) as usize;
    if payload_len == 0 || 40 + payload_len > ipv6_packet.len() {
        return;
    }

    // Transport checksum field offset within the packet: TCP at 16, UDP at 6.
    let proto = ipv6_packet[6];
    let csum = match proto {
        6 if payload_len >= TCP_HEADER_MIN_LEN => 40 + 16,
        17 if payload_len >= 8 => 40 + 6,
        _ => return,
    };
    ipv6_packet[csum] = 0;
    ipv6_packet[csum + 1] = 0;

    // Pseudo-header (src + dst are contiguous at 8..40), length, next header,
    let mut sum: u32 = 0;
    for chunk in ipv6_packet[8..40].chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += payload_len as u32 + proto as u32;
    // then the transport segment itself (with the checksum field zeroed above).
    for chunk in ipv6_packet[40..40 + payload_len].chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += value as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // IPv6 forbids an all-zero UDP checksum; send 0xffff instead (TCP keeps 0).
    let checksum = match (!sum as u16, proto) {
        (0, 17) => 0xffff,
        (c, _) => c,
    };
    ipv6_packet[csum..csum + 2].copy_from_slice(&checksum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_syn_packet(src: [u8; 16], dst: [u8; 16], mss: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + 40]; // IPv6 + TCP with options

        // IPv6 header
        packet[0] = 0x60; // Version 6
        packet[4..6].copy_from_slice(&40u16.to_be_bytes()); // Payload length
        packet[6] = 6; // Next header = TCP
        packet[7] = 64; // Hop limit
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);

        // TCP header
        let tcp_start = 40;
        packet[tcp_start..tcp_start + 2].copy_from_slice(&12345u16.to_be_bytes()); // Source port
        packet[tcp_start + 2..tcp_start + 4].copy_from_slice(&80u16.to_be_bytes()); // Dest port
        packet[tcp_start + 4..tcp_start + 8].copy_from_slice(&1000u32.to_be_bytes()); // Seq
        packet[tcp_start + 8..tcp_start + 12].copy_from_slice(&0u32.to_be_bytes()); // Ack
        packet[tcp_start + 12] = 0xa0; // Data offset = 10 (40 bytes header)
        packet[tcp_start + 13] = TCP_FLAG_SYN; // Flags = SYN
        packet[tcp_start + 14..tcp_start + 16].copy_from_slice(&8192u16.to_be_bytes()); // Window

        // TCP options: MSS
        packet[tcp_start + 20] = TCP_OPT_MSS; // Kind
        packet[tcp_start + 21] = TCP_OPT_MSS_LEN; // Length
        packet[tcp_start + 22..tcp_start + 24].copy_from_slice(&mss.to_be_bytes()); // MSS value

        // End of options
        packet[tcp_start + 24] = 0;

        // Calculate checksum
        recalculate_l4_checksum(&mut packet);

        packet
    }

    #[test]
    fn test_clamp_tcp_mss_reduces_large_mss() {
        let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut packet = make_tcp_syn_packet(src, dst, 1460);

        let modified = clamp_tcp_mss(&mut packet, 1200);

        assert!(modified);

        // Check MSS was clamped
        let tcp_start = 40;
        let mss = u16::from_be_bytes([packet[tcp_start + 22], packet[tcp_start + 23]]);
        assert_eq!(mss, 1200);
    }

    #[test]
    fn test_clamp_tcp_mss_leaves_small_mss_unchanged() {
        let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut packet = make_tcp_syn_packet(src, dst, 1000);

        let modified = clamp_tcp_mss(&mut packet, 1200);

        assert!(!modified);

        // Check MSS unchanged
        let tcp_start = 40;
        let mss = u16::from_be_bytes([packet[tcp_start + 22], packet[tcp_start + 23]]);
        assert_eq!(mss, 1000);
    }

    #[test]
    fn test_clamp_tcp_mss_ignores_non_syn() {
        let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut packet = make_tcp_syn_packet(src, dst, 1460);

        // Clear SYN flag
        packet[40 + 13] = 0x10; // ACK only

        let modified = clamp_tcp_mss(&mut packet, 1200);

        assert!(!modified);
    }

    #[test]
    fn test_clamp_tcp_mss_ignores_non_tcp() {
        let mut packet = vec![0u8; 80];
        packet[0] = 0x60; // IPv6
        packet[6] = 17; // UDP, not TCP

        let modified = clamp_tcp_mss(&mut packet, 1200);

        assert!(!modified);
    }

    // ========================================================================
    // recalculate_l4_checksum — finish macOS's offloaded self-traffic
    // checksums (the bug that left ACK/data/FIN segments undeliverable).
    // ========================================================================

    /// True if the packet's TCP/UDP checksum verifies (folded ones-complement
    /// sum over pseudo-header + segment, including the checksum field, == 0xffff).
    fn l4_checksum_valid(pkt: &[u8]) -> bool {
        let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        let mut sum: u32 = 0;
        for chunk in pkt[8..40].chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += payload_len as u32;
        sum += pkt[6] as u32; // next header
        for chunk in pkt[40..40 + payload_len].chunks(2) {
            let v = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += v as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    const SELF_ADDR: [u8; 16] = [0xfd, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x55];

    /// A self-addressed 20-byte TCP ACK (no options) carrying a deliberately
    /// wrong checksum — the shape macOS hands us for hairpinned non-SYN traffic.
    fn make_tcp_ack_packet() -> Vec<u8> {
        let mut p = vec![0u8; 40 + 20];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload length
        p[6] = 6; // TCP
        p[7] = 64;
        p[8..24].copy_from_slice(&SELF_ADDR);
        p[24..40].copy_from_slice(&SELF_ADDR);
        let t = 40;
        p[t..t + 2].copy_from_slice(&52097u16.to_be_bytes());
        p[t + 2..t + 4].copy_from_slice(&9999u16.to_be_bytes());
        p[t + 4..t + 8].copy_from_slice(&1000u32.to_be_bytes()); // seq
        p[t + 8..t + 12].copy_from_slice(&2000u32.to_be_bytes()); // ack
        p[t + 12] = 0x50; // data offset = 5 (20-byte header)
        p[t + 13] = 0x10; // ACK
        p[t + 14..t + 16].copy_from_slice(&2049u16.to_be_bytes()); // window
        p[t + 16] = 0x8e; // bogus checksum (macOS pseudo-header partial)
        p[t + 17] = 0xce;
        p
    }

    #[test]
    fn recompute_fixes_tcp_non_syn_checksum() {
        let mut pkt = make_tcp_ack_packet();
        assert!(
            !l4_checksum_valid(&pkt),
            "fixture should start with a bad checksum"
        );
        recalculate_l4_checksum(&mut pkt);
        assert!(
            l4_checksum_valid(&pkt),
            "TCP checksum must verify after recompute"
        );
    }

    #[test]
    fn recompute_fixes_udp_checksum() {
        let mut p = vec![0u8; 40 + 12]; // 8-byte UDP header + 4-byte payload
        p[0] = 0x60;
        p[4..6].copy_from_slice(&12u16.to_be_bytes());
        p[6] = 17; // UDP
        p[7] = 64;
        p[8..24].copy_from_slice(&SELF_ADDR);
        p[24..40].copy_from_slice(&SELF_ADDR);
        let u = 40;
        p[u..u + 2].copy_from_slice(&40000u16.to_be_bytes()); // src port
        p[u + 2..u + 4].copy_from_slice(&5354u16.to_be_bytes()); // dst port
        p[u + 4..u + 6].copy_from_slice(&12u16.to_be_bytes()); // UDP length
        p[u + 6] = 0x8e; // bogus checksum
        p[u + 7] = 0xce;
        p[u + 8..u + 12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload

        assert!(!l4_checksum_valid(&p), "fixture should start invalid");
        recalculate_l4_checksum(&mut p);
        assert!(
            l4_checksum_valid(&p),
            "UDP checksum must verify after recompute"
        );
        assert_ne!(
            &p[u + 6..u + 8],
            &[0, 0],
            "IPv6 UDP checksum must not be zero"
        );
    }

    #[test]
    fn recompute_is_noop_for_non_transport() {
        // Next-header 59 (No Next Header): nothing to checksum.
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
        pkt[6] = 59;
        let before = pkt.clone();
        recalculate_l4_checksum(&mut pkt);
        assert_eq!(pkt, before, "non-transport packet must be left untouched");
    }

    #[test]
    fn recompute_ignores_truncated_packet() {
        // payload_len claims 20 bytes of TCP but only 10 are present.
        let mut pkt = vec![0u8; 40 + 10];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
        pkt[6] = 6;
        let before = pkt.clone();
        recalculate_l4_checksum(&mut pkt); // must not panic
        assert_eq!(pkt, before, "truncated packet must be left untouched");
    }
}
