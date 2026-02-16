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
                
                // Recalculate TCP checksum
                recalculate_tcp_checksum(ipv6_packet, tcp_start);
                
                modified = true;
            }
            break; // MSS option found, no need to continue
        }

        i += length;
    }

    modified
}

/// Recalculate TCP checksum after modifying the packet.
fn recalculate_tcp_checksum(ipv6_packet: &mut [u8], tcp_start: usize) {
    // Zero out existing checksum
    ipv6_packet[tcp_start + 16] = 0;
    ipv6_packet[tcp_start + 17] = 0;

    // Extract addresses
    let src = &ipv6_packet[8..24];
    let dst = &ipv6_packet[24..40];

    // Get TCP segment length
    let payload_len = u16::from_be_bytes([ipv6_packet[4], ipv6_packet[5]]) as usize;
    let tcp_segment = &ipv6_packet[tcp_start..tcp_start + payload_len];

    // Calculate checksum with pseudo-header
    let mut sum: u32 = 0;

    // Pseudo-header: source address
    for chunk in src.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Pseudo-header: destination address
    for chunk in dst.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Pseudo-header: TCP length
    sum += payload_len as u32;

    // Pseudo-header: next header (TCP = 6)
    sum += 6;

    // TCP segment
    for chunk in tcp_segment.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += value as u32;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // One's complement
    let checksum = !sum as u16;
    ipv6_packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
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
        recalculate_tcp_checksum(&mut packet, tcp_start);

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
}