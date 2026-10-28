//! Unit tests for the IPv6 adapter's TCP MSS clamp.

use super::*;
use std::collections::HashMap;
use std::sync::RwLock;

/// A mesh address whose first byte after the prefix is `b`.
fn fips_addr_with_node_byte(b: u8) -> Ipv6Address {
    let mut bytes = [0u8; 16];
    bytes[0] = crate::identity::IPV6_ADDRESS_PREFIX;
    bytes[1] = b;
    Ipv6Address::from_bytes(bytes).unwrap()
}

/// A replica with no entries.
fn empty_lookup() -> PathMtuReplica {
    Arc::new(RwLock::new(HashMap::new()))
}

/// The payload limit the node reports for a stored path MTU of `mtu`.
fn held(mtu: u16) -> u16 {
    crate::node::path_mtu::payload_limit(mtu)
}

#[test]
fn per_flow_empty_lookup_returns_conservative_ceiling() {
    // Cold-flow first-SYN race-window guard: when no per-destination
    // path_mtu has been learned yet, fall back to the IPv6-minimum-
    // derived ceiling (1280 - 77 - 60 = 1143) rather than the local
    // global ceiling. This ensures the first SYN to an unknown
    // destination clamps small enough to traverse any RFC-8200-
    // compliant IPv6 path.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1143);
}

#[test]
fn per_flow_empty_lookup_returns_global_when_global_smaller() {
    // When the local global ceiling is already <= the conservative
    // 1143 ceiling (e.g. a daemon configured with UDP-1280 only),
    // the empty-lookup fallback stays at the global rather than
    // expanding upward.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1100), 1100);
}

#[test]
fn per_flow_clamps_to_path_mtu_when_smaller() {
    // Discovery learned path_mtu=1280 for this destination; global
    // ceiling is 1360. Per-flow clamp should be min(1360, 1280-77-60)
    // = min(1360, 1143) = 1143.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    lookup.write().unwrap().insert(addr, held(1280));
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1143);
}

#[test]
fn per_flow_keeps_global_when_path_mtu_larger() {
    // Discovery learned path_mtu=1452 (> global). Per-flow stays at
    // global 1143 (the smaller of the two).
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    lookup.write().unwrap().insert(addr, held(1452));
    // global=1143 (UDP-1280-derived); path_max = 1452-77-60 = 1315.
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1143), 1143);
}

#[test]
fn per_flow_learned_value_overrides_conservative_ceiling() {
    // When discovery has learned a per-destination value LARGER than
    // the conservative 1143 ceiling, the learned value (capped by
    // the global ceiling) wins. The conservative ceiling is only the
    // empty-lookup fallback; once an entry exists, the actual
    // learned value governs.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    lookup.write().unwrap().insert(addr, held(1452));
    // global=1360, path_max = 1452-77-60 = 1315; min(1360, 1315) = 1315.
    // 1315 > 1143, so the conservative ceiling did NOT clamp here.
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1315);
}

#[test]
fn per_flow_stored_mtu_admitting_no_payload_byte_falls_back_to_conservative_ceiling() {
    // A stored MTU of 137 or less leaves nothing after the 77 bytes of
    // FIPS encapsulation and the 40 + 20 bytes of IPv6 and TCP header, so
    // the MSS arithmetic saturates to zero. Returning that zero would be
    // worse than the fallback: `clamp_tcp_mss` refuses a ceiling of zero,
    // so the SYN would go out at the kernel-natural MSS, unclamped.
    for stored in [0u16, 1, 100, 137] {
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        lookup.write().unwrap().insert(addr, held(stored));
        assert_eq!(
            per_flow_max_mss(&lookup, addr.as_bytes(), 1360),
            1143,
            "stored path_mtu {stored} admits no payload byte and must be ignored"
        );
    }
}

#[test]
fn per_flow_honors_a_locally_seeded_sub_floor_mtu_instead_of_loosening_to_the_ceiling() {
    // Only `seed_path_mtu_for_link_peer` can put a sub-floor value in this
    // map: every remote-supplied path MTU is refused at ingress, at the
    // path MTU state machine, the reactive `MtuExceeded` write and the
    // discovery response. A seeded value is therefore the node's own link
    // measurement, and BLE negotiates one per connection that lands in
    // this band routinely.
    //
    // Applying the remote-value floor here discarded it and advertised
    // 1143 instead, which a link this narrow cannot carry: every full-size
    // segment is refused by the transport, a direct link has no forwarder
    // to answer with `MtuExceeded`, and the flow stalls with no feedback.
    // The tight clamp is the whole reason the seed exists.
    //
    // 138 is the first MTU admitting a payload byte; 240 is a plausible
    // negotiated BLE value; 255 is one below the remote-value floor. The
    // whole table is evaluated before asserting, so a regression names
    // every band it broke rather than only the first.
    let want = [(138u16, 1u16), (240, 103), (255, 118)];
    let got: Vec<(u16, u16)> = want
        .iter()
        .map(|&(stored, _)| {
            let lookup = empty_lookup();
            let addr = fips_addr_with_node_byte(0x42);
            lookup.write().unwrap().insert(addr, held(stored));
            (stored, per_flow_max_mss(&lookup, addr.as_bytes(), 1360))
        })
        .collect();
    assert_eq!(
        got,
        want.to_vec(),
        "each locally seeded path_mtu must clamp tight, not fall back to 1143"
    );
}

#[test]
fn per_flow_stored_mtu_at_the_actionable_floor_is_still_honored() {
    // The smallest value the node will accept from a remote party still
    // clamps to its own arithmetic and nothing coarser: 256 - 77 - 40 - 20
    // = 119. Reintroducing the remote-value floor as a clamp-time guard
    // would leave this case passing, so it is pinned separately from the
    // sub-floor table above.
    let lookup = empty_lookup();
    let addr = fips_addr_with_node_byte(0x42);
    lookup
        .write()
        .unwrap()
        .insert(addr, held(crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU));
    assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 119);
}

#[test]
fn per_flow_returns_conservative_ceiling_for_non_fips_addr() {
    // Non-fips IPv6 (e.g. fe80::/10 link-local) takes the empty-
    // lookup path. With global=1360, fall back to 1143.
    let lookup = empty_lookup();
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    assert_eq!(per_flow_max_mss(&lookup, &bytes, 1360), 1143);
}

#[test]
fn per_flow_returns_conservative_ceiling_on_short_addr_slice() {
    let lookup = empty_lookup();
    let bytes = [0u8; 8];
    assert_eq!(per_flow_max_mss(&lookup, &bytes, 1360), 1143);
}

#[test]
fn per_flow_independent_per_destination() {
    // Two different destinations with different path MTUs. Each
    // lookup honors its own value; cross-talk would be a regression.
    let lookup = empty_lookup();
    let a = fips_addr_with_node_byte(0x10);
    let b = fips_addr_with_node_byte(0x20);
    lookup.write().unwrap().insert(a, held(1280));
    lookup.write().unwrap().insert(b, held(1452));
    assert_eq!(per_flow_max_mss(&lookup, a.as_bytes(), 1360), 1143);
    assert_eq!(per_flow_max_mss(&lookup, b.as_bytes(), 1360), 1315);
}

/// A fallback the per-destination clamp takes is traced under the MSS
/// module's target, which a filter on the TUN module no longer selects.
#[test]
fn the_clamp_fallback_logs_under_the_mss_module_target() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    per_flow_max_mss(&empty_lookup(), &[0u8; 4], 1360);

    assert_eq!(
        logs.targets(
            "per_flow_max_mss: addr_bytes wrong length, fall back to conservative ceiling"
        ),
        vec!["fips::ipv6tun::mss"]
    );
}

/// A SYN from `src` to `dst`: a 40-byte IPv6 header carrying TCP and a
/// 24-byte TCP header with data offset 6, the SYN flag and one MSS option of
/// `mss`. The checksum is left zero; these tests read the MSS option, and
/// the clamp only updates the checksum for the bytes it rewrites.
fn syn_packet(src: &Ipv6Address, dst: &Ipv6Address, mss: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 64];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(src.as_bytes());
    packet[24..40].copy_from_slice(dst.as_bytes());
    packet[52] = 6 << 4;
    packet[53] = 0x02;
    packet[60] = 2;
    packet[61] = 4;
    packet[62..64].copy_from_slice(&mss.to_be_bytes());
    packet
}

/// The MSS option of a packet `syn_packet` built.
fn mss_option(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[62], packet[63]])
}

/// A SYN toward the host is clamped by the stored path to its source, the
/// far end of the flow, and not by the conservative fallback.
#[test]
fn a_syn_toward_the_host_is_clamped_by_the_path_to_its_source() {
    let paths = empty_lookup();
    let far = fips_addr_with_node_byte(0x42);
    let host = fips_addr_with_node_byte(0x55);
    paths.write().unwrap().insert(far, held(1000));
    let mut packet = syn_packet(&far, &host, 1440);

    assert_eq!(clamp(&mut packet, 1360, &paths, Remote::Source), Some(863));
    assert_eq!(mss_option(&packet), 863);
}

/// A SYN from the host is clamped by the stored path to its destination, the
/// far end of the flow, and not by the conservative fallback.
#[test]
fn a_syn_from_the_host_is_clamped_by_the_path_to_its_destination() {
    let paths = empty_lookup();
    let far = fips_addr_with_node_byte(0x42);
    let host = fips_addr_with_node_byte(0x55);
    paths.write().unwrap().insert(far, held(1000));
    let mut packet = syn_packet(&host, &far, 1440);

    assert_eq!(
        clamp(&mut packet, 1360, &paths, Remote::Destination),
        Some(863)
    );
    assert_eq!(mss_option(&packet), 863);
}

/// A packet too short to hold its source address is left alone rather than
/// read past its end.
#[test]
fn a_packet_too_short_to_name_its_source_is_left_unclamped() {
    let mut packet = [0x60; 20];

    assert_eq!(
        clamp(&mut packet, 1360, &empty_lookup(), Remote::Source),
        None
    );
    assert_eq!(packet, [0x60; 20]);
}

/// A segment without the SYN flag is not clamped, and its MSS bytes are
/// left as they were.
#[test]
fn a_segment_that_is_not_a_syn_is_not_clamped() {
    let far = fips_addr_with_node_byte(0x42);
    let host = fips_addr_with_node_byte(0x55);
    let mut packet = syn_packet(&far, &host, 1440);
    packet[53] = 0x10;

    assert_eq!(
        clamp(&mut packet, 1360, &empty_lookup(), Remote::Source),
        None
    );
    assert_eq!(mss_option(&packet), 1440);
}

/// A SYN-ACK arriving from the mesh whose TCP header follows an 8-byte
/// Hop-by-Hop Options header is clamped on its way to the host, as the TUN
/// writers clamp it, to the far end's ceiling, as a plain SYN-ACK is (RFC
/// 9293 Section 3.7.1: the MSS option counts no extension header).
#[test]
fn an_inbound_syn_ack_behind_a_hop_by_hop_header_is_clamped_to_the_ceiling_a_plain_one_gets() {
    let far = fips_addr_with_node_byte(0x42);
    let near = fips_addr_with_node_byte(0x55);
    let mut p = vec![0u8; 40 + 8 + 24];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&32u16.to_be_bytes());
    p[6] = 0; // Hop-by-Hop Options
    p[7] = 64;
    p[8..24].copy_from_slice(far.as_bytes());
    p[24..40].copy_from_slice(near.as_bytes());
    // Hop-by-Hop: next header TCP, length 0 (8 bytes), one PadN.
    p[40..48].copy_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);
    p[48 + 12] = 6 << 4;
    p[48 + 13] = 0x12; // SYN, ACK
    p[68..72].copy_from_slice(&[2, 4, 0x05, 0xa0]); // MSS 1440

    assert_eq!(
        clamp(&mut p, 1360, &empty_lookup(), Remote::Source),
        Some(1143),
        "clamped by the conservative ceiling"
    );
    assert_eq!(
        u16::from_be_bytes([p[70], p[71]]),
        1143,
        "the conservative 1143, nothing taken off for the header"
    );
}
