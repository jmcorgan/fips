use super::*;

/// An IPv6 packet of `total` bytes with next header `nh`, whose payload
/// bytes count upward. A TCP packet gets a 20-byte header (data offset 5).
fn packet(total: usize, nh: u8) -> Vec<u8> {
    let mut p = vec![0u8; total];
    p[0] = 0x60;
    p[1] = 0x12; // traffic class and flow label, to check they are copied
    p[2] = 0x34;
    p[3] = 0x56;
    p[4..6].copy_from_slice(&((total - HDR) as u16).to_be_bytes());
    p[6] = nh;
    p[7] = 64;
    for (i, b) in p[8..HDR].iter_mut().enumerate() {
        *b = 0xf0 | i as u8;
    }
    for (i, b) in p[HDR..].iter_mut().enumerate() {
        *b = i as u8;
    }
    if nh == NH_TCP {
        p[HDR + 12] = 5 << 4;
    }
    p
}

/// A host-made fragment of `total` bytes: inner next header `inner`, byte
/// offset `offset`, M flag `more`, identification `ident`.
fn host_fragment(total: usize, inner: u8, offset: u16, more: bool, ident: u32) -> Vec<u8> {
    let mut p = packet(total, NH_FRAGMENT);
    p[HDR] = inner;
    p[HDR + 1] = 0;
    p[HDR + 2..HDR + 4].copy_from_slice(&(offset | more as u16).to_be_bytes());
    p[HDR + 4..HDR + 8].copy_from_slice(&ident.to_be_bytes());
    p
}

/// A fragment's (byte offset, M flag, identification, inner next header).
fn frag_fields(f: &[u8]) -> (usize, bool, u32, u8) {
    let offset_m = u16::from_be_bytes([f[HDR + 2], f[HDR + 3]]);
    (
        (offset_m & 0xfff8) as usize,
        offset_m & 1 == 1,
        u32::from_be_bytes([f[HDR + 4], f[HDR + 5], f[HDR + 6], f[HDR + 7]]),
        f[HDR],
    )
}

fn sizes(frags: &[Vec<u8>]) -> Vec<usize> {
    frags.iter().map(Vec::len).collect()
}

/// Reassemble fragments the way a receiving host does, checking each one's
/// framing, and return the original packet.
fn reassemble(original: &[u8], frags: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    let (_, _, ident, inner) = frag_fields(&frags[0]);
    for (i, f) in frags.iter().enumerate() {
        assert_eq!(f[6], NH_FRAGMENT, "fragment {i} next header");
        assert_eq!(
            u16::from_be_bytes([f[4], f[5]]) as usize + HDR,
            f.len(),
            "fragment {i} payload length"
        );
        assert_eq!(f[..4], original[..4], "fragment {i} version, class, flow");
        assert_eq!(
            f[7..HDR],
            original[7..HDR],
            "fragment {i} hop limit, addresses"
        );
        assert_eq!(f[HDR + 1], 0, "fragment {i} reserved byte");
        let (offset, more, id, nh) = frag_fields(f);
        assert_eq!(offset % 8, 0, "fragment {i} offset alignment");
        assert_eq!(offset, data.len(), "fragment {i} offset");
        assert_eq!(more, i + 1 < frags.len(), "fragment {i} more flag");
        assert_eq!((id, nh), (ident, inner), "fragment {i} identification");
        data.extend_from_slice(&f[HDR + FRAG_HDR..]);
    }
    let mut p = frags[0][..HDR].to_vec();
    p[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
    p[6] = inner;
    p.extend_from_slice(&data);
    p
}

#[test]
fn a_1280_byte_packet_splits_into_fragments_that_fit_and_reassemble_to_the_original() {
    let p = packet(1280, NH_TCP);
    for (mtu, expected) in [(1123, vec![1120, 216]), (1203, vec![1200, 136])] {
        let frags = fragment_for_path(&p, mtu, 0x0bad_cafe).unwrap();
        assert_eq!(sizes(&frags), expected, "at {mtu}");
        assert!(frags.iter().all(|f| f.len() <= mtu), "at {mtu}");
        assert_eq!(frag_fields(&frags[0]).2, 0x0bad_cafe, "at {mtu}");
        assert_eq!(frag_fields(&frags[0]).3, NH_TCP, "at {mtu}");
        assert_eq!(reassemble(&p, &frags), p, "at {mtu}");
        assert!(can_fragment(&p, mtu));
    }
}

#[test]
fn fragmenting_is_left_to_packet_too_big_when_the_packet_fits_or_exceeds_1280_or_is_malformed() {
    let p = packet(1280, NH_TCP);
    assert_eq!(fragment_for_path(&p, 1280, 1), None, "fits at 1280");
    assert_eq!(
        fragment_for_path(&packet(1123, NH_TCP), 1123, 1),
        None,
        "exactly the MTU"
    );
    assert_eq!(
        fragment_for_path(&packet(1300, NH_TCP), 1123, 1),
        None,
        "over 1280"
    );
    assert_eq!(fragment_for_path(&p, 47, 1), None, "MTU under the headers");
    assert_eq!(fragment_for_path(&p, 0, 1), None, "MTU zero");

    let mut short = p.clone();
    short[4..6].copy_from_slice(&1000u16.to_be_bytes());
    assert_eq!(
        fragment_for_path(&short, 1123, 1),
        None,
        "payload length 1000"
    );

    let mut empty = packet(1280, NH_NONE);
    empty[4..6].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(fragment_for_path(&empty, 1123, 1), None, "payload length 0");

    let mut not_v6 = p.clone();
    not_v6[0] = 0x40;
    assert_eq!(fragment_for_path(&not_v6, 1123, 1), None, "version 4");
    assert!(!can_fragment(&packet(1300, NH_TCP), 1123));
}

#[test]
fn a_host_made_fragment_is_split_further_under_its_own_identification_offset_and_final_flag() {
    let middle = host_fragment(1280, NH_UDP, 1232, true, 0xdead_beef);
    let frags = fragment_for_path(&middle, 1123, 7).unwrap();
    assert_eq!(sizes(&frags), vec![1120, 208]);
    let fields: Vec<_> = frags.iter().map(|f| frag_fields(f)).collect();
    assert_eq!(
        fields,
        vec![
            (1232, true, 0xdead_beef, NH_UDP),
            (2304, true, 0xdead_beef, NH_UDP),
        ]
    );
    let joined: Vec<u8> = frags
        .iter()
        .flat_map(|f| f[HDR + FRAG_HDR..].to_vec())
        .collect();
    assert_eq!(joined, middle[HDR + FRAG_HDR..]);

    let last = host_fragment(1280, NH_UDP, 1232, false, 0xdead_beef);
    let frags = fragment_for_path(&last, 1123, 7).unwrap();
    let flags: Vec<bool> = frags.iter().map(|f| frag_fields(f).1).collect();
    assert_eq!(flags, vec![true, false]);

    let near_limit = host_fragment(1280, NH_UDP, 65000, true, 0xdead_beef);
    assert_eq!(fragment_for_path(&near_limit, 1123, 7), None);
}

#[test]
fn extension_headers_the_first_fragment_cannot_carry_whole_leave_the_packet_to_packet_too_big() {
    assert_eq!(
        fragment_for_path(&packet(1280, NH_HOP_BY_HOP), 1123, 1),
        None,
        "Hop-by-Hop first"
    );
    assert_eq!(
        fragment_for_path(&packet(1280, NH_ROUTING), 1123, 1),
        None,
        "Routing first"
    );
    for (second, what) in [
        (NH_ROUTING, "Destination Options then Routing"),
        (NH_FRAGMENT, "Destination Options then Fragment"),
        (132, "Destination Options then SCTP"),
    ] {
        let mut p = packet(1280, NH_DEST_OPTS);
        p[HDR] = second;
        p[HDR + 1] = 0; // 8 bytes
        assert_eq!(fragment_for_path(&p, 1123, 1), None, "{what}");
    }
    assert_eq!(
        fragment_for_path(&packet(1280, 132), 1123, 1),
        None,
        "an unrecognised upper-layer protocol"
    );

    // A 200-byte Destination Options header, then a 20-byte TCP header.
    let mut d = packet(1280, NH_DEST_OPTS);
    d[HDR] = NH_TCP;
    d[HDR + 1] = 24;
    d[HDR + 200 + 12] = 5 << 4;
    assert_eq!(
        fragment_for_path(&d, 179, 1),
        None,
        "TCP would start in the second fragment"
    );
    let frags = fragment_for_path(&d, 300, 1).unwrap();
    assert_eq!(sizes(&frags), vec![296; 5]);
    assert!(
        frags[0].len() - HDR - FRAG_HDR >= 220,
        "headers in the first"
    );
    assert_eq!(reassemble(&d, &frags), d);

    // A 60-byte TCP header with no extension header fits the smallest chunk.
    let mut t = packet(1280, NH_TCP);
    t[HDR + 12] = 15 << 4;
    let frags = fragment_for_path(&t, 179, 1).unwrap();
    assert_eq!(reassemble(&t, &frags), t);
}

#[test]
fn a_udp_icmpv6_or_esp_header_that_would_start_in_the_second_fragment_leaves_the_packet_to_packet_too_big()
 {
    for (upper, what) in [(NH_UDP, "UDP"), (NH_ICMPV6, "ICMPv6"), (NH_ESP, "ESP")] {
        // At MTU 179 each fragment carries 128 data bytes, all of them taken
        // by a 128-byte Destination Options header.
        let mut p = packet(1280, NH_DEST_OPTS);
        p[HDR] = upper;
        p[HDR + 1] = 15; // (15 + 1) * 8 = 128 bytes
        assert_eq!(fragment_for_path(&p, 179, 1), None, "{what} after 128");
        assert!(!can_fragment(&p, 179), "{what} after 128");

        // A 120-byte header leaves the 8-byte one room in the first.
        p[HDR + 1] = 14;
        let frags = fragment_for_path(&p, 179, 1).unwrap();
        assert_eq!(frags.len(), 10, "{what} after 120");
        assert_eq!(reassemble(&p, &frags), p, "{what} after 120");
    }
}

#[test]
fn a_later_host_fragment_whose_inner_header_belongs_before_a_fragment_header_is_left_to_packet_too_big()
 {
    for (inner, what) in [
        (NH_HOP_BY_HOP, "Hop-by-Hop"),
        (NH_ROUTING, "Routing"),
        (NH_FRAGMENT, "Fragment"),
    ] {
        let p = host_fragment(1280, inner, 1232, true, 9);
        assert_eq!(fragment_for_path(&p, 1123, 1), None, "{what}");
        assert!(!can_fragment(&p, 1123), "{what}");
    }
}

#[test]
fn a_1280_byte_packet_needs_two_fragments_down_to_an_ipv6_mtu_of_672_and_ten_below_192() {
    let p = packet(1280, NH_UDP);
    let at = |mtu| sizes(&fragment_for_path(&p, mtu, 1).unwrap());
    assert_eq!(at(672), vec![672, 664]);
    assert_eq!(at(671), vec![664, 664, 56]);
    assert_eq!(at(192).len(), 9);
    assert_eq!(at(191).len(), 10);
}

#[test]
fn no_packet_is_split_into_more_than_ten_fragments() {
    let p = packet(1280, NH_UDP);
    for mtu in [179, 176] {
        let frags = fragment_for_path(&p, mtu, 1).unwrap();
        let mut expected = vec![176; 9];
        expected.push(136);
        assert_eq!(sizes(&frags), expected, "at {mtu}");
        assert!(frags.iter().all(|f| f.len() <= mtu), "at {mtu}");
        assert_eq!(reassemble(&p, &frags), p, "at {mtu}");
    }
    for mtu in [175, 140, 56] {
        assert_eq!(fragment_for_path(&p, mtu, 1), None, "at {mtu}");
    }
    assert_eq!(MIN_FRAG_DATA, 128);
}

#[test]
fn a_packet_over_1280_on_a_path_under_1280_is_told_1280() {
    assert_eq!(packet_too_big_mtu(1300, 1203), 1280);
    assert_eq!(packet_too_big_mtu(1280, 1203), 1203);
    assert_eq!(packet_too_big_mtu(1500, 1400), 1400);
}
