//! Tests for the path message codec. Golden bytes are written out by hand
//! from the multipath v1 draft's layouts (Sections 7.2 to 7.5), not produced
//! by the encoder.

use super::*;
use alloc::vec;
use alloc::vec::Vec;

const PROBE_ID: u32 = 0x1122_3344;
const PROBE_PATH: u32 = 0xA1B2_C3D4;
const ACK_PATH: u32 = 0x5566_7788;

/// A minimum-size `PathProbe`: ACTIVE, AGGREGATE, 16 bytes of padding.
fn golden_probe() -> Vec<u8> {
    let mut b = vec![
        0x52, // type
        0x44, 0x33, 0x22, 0x11, // probe_id
        0x01, // flags: ACTIVE
        0xD4, 0xC3, 0xB2, 0xA1, // path_id
        0x01, // caps: AGGREGATE
    ];
    b.extend_from_slice(&[0u8; 16]);
    b
}

/// A `PathAck` answering `golden_probe`, unpadded (27 bytes).
fn golden_ack() -> Vec<u8> {
    vec![
        0x53, // type
        0x44, 0x33, 0x22, 0x11, // probe_id
        0x00, // flags
        0x88, 0x77, 0x66, 0x55, // path_id
        0xD4, 0xC3, 0xB2, 0xA1, // echo_path_id
        0x00, // caps
        0x04, 0x03, 0x02, 0x01, // rx_time_us
        0x00, 0x01, 0x00, 0x00, // rx_frames
        0xEF, 0xBE, 0xAD, 0xDE, // rx_bytes
    ]
}

fn sample_ack() -> PathAck {
    PathAck {
        probe_id: PROBE_ID,
        flags: PathFlags::default(),
        path_id: ACK_PATH,
        echo_path_id: PROBE_PATH,
        caps: PathCaps::default(),
        rx_time_us: 0x0102_0304,
        rx_frames: 0x100,
        rx_bytes: 0xDEAD_BEEF,
        len: PATH_ACK_FIXED_SIZE,
    }
}

fn sample_probe() -> PathProbe {
    PathProbe::new(
        PROBE_ID,
        PROBE_PATH,
        PathFlags::with_active(true),
        PathCaps::with_aggregate(true),
    )
}

/// A probe's fixed part with `EXT` set, followed by `tail`.
fn probe_with_ext(tail: &[u8]) -> Vec<u8> {
    let mut b = golden_probe()[..PATH_PROBE_FIXED_SIZE].to_vec();
    b[5] = PathFlags::EXT;
    b.extend_from_slice(tail);
    b
}

// ===== Catalog =====

#[test]
fn path_message_types_are_0x52_to_0x54_in_the_link_catalog() {
    assert_eq!(
        LinkMessageType::from_byte(0x52),
        Some(LinkMessageType::PathProbe)
    );
    assert_eq!(
        LinkMessageType::from_byte(0x53),
        Some(LinkMessageType::PathAck)
    );
    assert_eq!(
        LinkMessageType::from_byte(0x54),
        Some(LinkMessageType::PathClose)
    );
    assert_eq!(LinkMessageType::from_byte(0x55), None);
    assert_eq!(alloc::format!("{}", LinkMessageType::PathAck), "PathAck");
}

// ===== PathProbe =====

#[test]
fn a_minimum_probe_encodes_to_the_draft_layout_padded_to_27_bytes() {
    assert_eq!(sample_probe().encode(), golden_probe());
}

#[test]
fn a_probe_padded_below_the_minimum_is_raised_to_27_bytes() {
    let bytes = sample_probe().with_len(PATH_PROBE_FIXED_SIZE).encode();
    assert_eq!(bytes, golden_probe());
}

#[test]
fn a_probe_padded_to_a_target_length_ends_in_zeros() {
    let bytes = sample_probe().with_len(1200).encode();
    assert_eq!(bytes.len(), 1200);
    assert_eq!(&bytes[..PATH_PROBE_MIN_SIZE], &golden_probe()[..]);
    assert!(bytes[PATH_PROBE_FIXED_SIZE..].iter().all(|&b| b == 0));
}

#[test]
fn a_probe_encoder_sends_reserved_bits_as_zero_and_never_sets_ext() {
    let probe = PathProbe::new(
        PROBE_ID,
        PROBE_PATH,
        PathFlags::from_bits(0xFF),
        PathCaps::from_bits(0xFF),
    );
    let bytes = probe.encode();
    assert_eq!(bytes[5], PathFlags::ACTIVE);
    assert_eq!(bytes[10], PathCaps::AGGREGATE);
}

#[test]
fn a_golden_probe_decodes_to_its_fields_and_length() {
    let probe = PathProbe::decode(&golden_probe()[1..]).unwrap();
    assert_eq!(probe.probe_id, PROBE_ID);
    assert_eq!(probe.path_id, PROBE_PATH);
    assert!(probe.flags.active());
    assert!(!probe.flags.ext());
    assert!(probe.caps.aggregate());
    assert_eq!(probe.len, PATH_PROBE_MIN_SIZE);
    assert!(probe.answerable());
}

#[test]
fn a_padded_probe_round_trips_with_its_length() {
    let sent = sample_probe().with_len(300);
    let bytes = sent.encode();
    let got = PathProbe::decode(&bytes[1..]).unwrap();
    assert_eq!(got, sent);
}

#[test]
fn a_probe_one_byte_short_of_its_fixed_part_is_rejected() {
    let bytes = golden_probe();
    let err = PathProbe::decode(&bytes[1..PATH_PROBE_FIXED_SIZE - 1]).unwrap_err();
    assert!(matches!(err, Error::MessageTooShort { .. }), "{err}");
}

#[test]
fn a_probe_of_only_its_fixed_part_decodes_but_is_not_answerable() {
    let bytes = golden_probe();
    let probe = PathProbe::decode(&bytes[1..PATH_PROBE_FIXED_SIZE]).unwrap();
    assert_eq!(probe.len, PATH_PROBE_FIXED_SIZE);
    assert!(!probe.answerable());
    let probe = PathProbe::decode(&bytes[1..PATH_PROBE_MIN_SIZE - 1]).unwrap();
    assert!(!probe.answerable());
}

#[test]
fn a_probe_reads_only_its_named_bits_and_keeps_the_reserved_ones() {
    let mut bytes = golden_probe();
    bytes[5] = 0xFD; // every bit but EXT
    bytes[10] = 0xFE; // every bit but AGGREGATE
    let probe = PathProbe::decode(&bytes[1..]).unwrap();
    assert!(probe.flags.active());
    assert!(!probe.flags.ext());
    assert!(!probe.caps.aggregate());
    assert_eq!(probe.flags.bits(), 0xFD);
    assert_eq!(probe.caps.bits(), 0xFE);
}

#[test]
fn a_probe_ignores_the_content_of_its_padding() {
    let mut bytes = golden_probe();
    for b in &mut bytes[PATH_PROBE_FIXED_SIZE..] {
        *b = 0xAA;
    }
    let probe = PathProbe::decode(&bytes[1..]).unwrap();
    assert_eq!(probe, sample_probe());
}

#[test]
fn a_probe_with_path_id_zero_is_rejected() {
    let mut bytes = golden_probe();
    bytes[6..10].fill(0);
    assert!(matches!(
        PathProbe::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
}

// ===== PathAck =====

#[test]
fn an_ack_encodes_to_the_draft_layout() {
    assert_eq!(sample_ack().encode(), golden_ack());
}

#[test]
fn an_ack_padded_below_its_fixed_part_is_raised_to_27_bytes() {
    let ack = PathAck {
        len: 5,
        ..sample_ack()
    };
    assert_eq!(ack.encode(), golden_ack());
}

#[test]
fn an_ack_padded_to_a_target_length_ends_in_zeros() {
    let ack = PathAck {
        len: 64,
        ..sample_ack()
    };
    let bytes = ack.encode();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[..PATH_ACK_FIXED_SIZE], &golden_ack()[..]);
    assert!(bytes[PATH_ACK_FIXED_SIZE..].iter().all(|&b| b == 0));
}

#[test]
fn an_ack_encoder_sends_reserved_bits_as_zero_and_never_sets_ext() {
    let ack = PathAck {
        flags: PathFlags::from_bits(0xFE),
        caps: PathCaps::from_bits(0xFE),
        ..sample_ack()
    };
    let bytes = ack.encode();
    assert_eq!(bytes[5], 0);
    assert_eq!(bytes[14], 0);
}

#[test]
fn a_golden_ack_decodes_to_its_fields() {
    let ack = PathAck::decode(&golden_ack()[1..]).unwrap();
    assert_eq!(ack, sample_ack());
}

#[test]
fn a_padded_ack_round_trips_with_its_length() {
    let sent = PathAck {
        len: 1000,
        flags: PathFlags::with_active(true),
        caps: PathCaps::with_aggregate(true),
        ..sample_ack()
    };
    let bytes = sent.encode();
    assert_eq!(PathAck::decode(&bytes[1..]).unwrap(), sent);
}

#[test]
fn an_ack_one_byte_short_of_its_fixed_part_is_rejected() {
    let bytes = golden_ack();
    let err = PathAck::decode(&bytes[1..PATH_ACK_FIXED_SIZE - 1]).unwrap_err();
    assert!(matches!(err, Error::MessageTooShort { .. }), "{err}");
}

#[test]
fn an_ack_reads_only_its_named_bits_and_keeps_the_reserved_ones() {
    let mut bytes = golden_ack();
    bytes[5] = 0xFD;
    bytes[14] = 0xFE;
    let ack = PathAck::decode(&bytes[1..]).unwrap();
    assert!(ack.flags.active());
    assert!(!ack.caps.aggregate());
    assert_eq!(ack.flags.bits(), 0xFD);
    assert_eq!(ack.caps.bits(), 0xFE);
}

#[test]
fn an_ack_with_path_id_zero_is_rejected() {
    let mut bytes = golden_ack();
    bytes[6..10].fill(0);
    assert!(matches!(
        PathAck::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn ack_length_is_the_smaller_of_probe_length_and_the_transport_mtu_less_the_frame_overhead() {
    // A 500-byte transport MTU leaves 464 bytes for the link message.
    assert_eq!(ack_len(1200, 500), 464);
    assert_eq!(ack_len(300, 1200), 300);
    // At the boundary the frame of a 1200-byte ack is exactly 1236 bytes.
    assert_eq!(ack_len(1200, 1236), 1200);
    assert_eq!(ack_len(1300, 1236), 1200);
    assert_eq!(ack_len(PATH_PROBE_MIN_SIZE, 1200), PATH_ACK_FIXED_SIZE);
    assert_eq!(ack_len(11, 1200), PATH_ACK_FIXED_SIZE);
    // A transport MTU below the overhead saturates to the fixed part.
    assert_eq!(ack_len(1200, 20), PATH_ACK_FIXED_SIZE);
}

// ===== PathClose =====

#[test]
fn a_close_encodes_to_the_draft_layout() {
    let close = PathClose {
        path_id: PROBE_PATH,
        reason: PathCloseReason::CarrierLost,
    };
    assert_eq!(close.encode(), [0x54, 0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00]);
}

#[test]
fn a_close_decodes_every_assigned_reason() {
    for (byte, reason) in [
        (0, PathCloseReason::Unspecified),
        (1, PathCloseReason::InterfaceGone),
        (2, PathCloseReason::CarrierLost),
        (3, PathCloseReason::Operator),
    ] {
        let close = PathClose::decode(&[0xD4, 0xC3, 0xB2, 0xA1, byte, 0x00]).unwrap();
        assert_eq!(close.path_id, PROBE_PATH);
        assert_eq!(close.reason, reason);
    }
}

#[test]
fn a_close_with_an_unassigned_reason_reads_as_unspecified() {
    for byte in [4, 239, 240, 255] {
        let close = PathClose::decode(&[1, 0, 0, 0, byte, 0]).unwrap();
        assert_eq!(close.reason, PathCloseReason::Unspecified);
    }
}

#[test]
fn a_close_ignores_its_reserved_flags_and_trailing_bytes() {
    let close = PathClose::decode(&[1, 0, 0, 0, 3, 0xFF, 0xAA, 0xBB, 0xCC]).unwrap();
    assert_eq!(close.path_id, 1);
    assert_eq!(close.reason, PathCloseReason::Operator);
}

#[test]
fn a_close_one_byte_short_is_rejected() {
    let err = PathClose::decode(&[1, 0, 0, 0, 3]).unwrap_err();
    assert!(matches!(err, Error::MessageTooShort { .. }), "{err}");
}

// ===== Extension block =====

#[test]
fn a_probe_with_one_unknown_non_critical_tlv_decodes() {
    // ext_len 6: TLV type 0x0001, len 2, value AB CD; then padding.
    let mut bytes = probe_with_ext(&[0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0xAB, 0xCD]);
    bytes.resize(40, 0);
    let probe = PathProbe::decode(&bytes[1..]).unwrap();
    assert!(probe.flags.ext());
    assert_eq!(probe.path_id, PROBE_PATH);
    assert_eq!(probe.len, 40);
}

#[test]
fn an_ack_with_one_unknown_non_critical_tlv_decodes() {
    let mut bytes = golden_ack();
    bytes[5] = PathFlags::EXT;
    bytes.extend_from_slice(&[0x05, 0x00, 0xFF, 0x7F, 0x01, 0x00, 0x99]);
    let ack = PathAck::decode(&bytes[1..]).unwrap();
    assert!(ack.flags.ext());
    assert_eq!(ack.rx_bytes, 0xDEAD_BEEF);
}

#[test]
fn an_empty_extension_block_decodes() {
    let bytes = probe_with_ext(&[0x00, 0x00]);
    assert!(PathProbe::decode(&bytes[1..]).is_ok());
}

#[test]
fn an_unknown_critical_tlv_rejects_the_message() {
    // A non-critical TLV first, then type 0x8001 (critical bit set).
    let bytes = probe_with_ext(&[
        0x09, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00,
    ]);
    assert!(matches!(
        PathProbe::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
    let mut ack = golden_ack();
    ack[5] = PathFlags::EXT;
    ack.extend_from_slice(&[0x04, 0x00, 0x01, 0x80, 0x00, 0x00]);
    assert!(matches!(
        PathAck::decode(&ack[1..]),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn an_extension_length_past_the_end_of_the_message_rejects_it() {
    let bytes = probe_with_ext(&[0x07, 0x00, 0x01, 0x00, 0x02, 0x00, 0xAB, 0xCD]);
    assert!(matches!(
        PathProbe::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
    let mut ack = golden_ack();
    ack[5] = PathFlags::EXT;
    ack.extend_from_slice(&[0x01, 0x00]);
    assert!(matches!(
        PathAck::decode(&ack[1..]),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn a_tlv_length_past_the_end_of_the_block_rejects_the_message() {
    // ext_len 6, but the TLV claims 3 bytes of value where 2 remain; padding
    // follows, so the message itself is long enough.
    let mut bytes = probe_with_ext(&[0x06, 0x00, 0x01, 0x00, 0x03, 0x00, 0xAB, 0xCD]);
    bytes.resize(40, 0);
    assert!(matches!(
        PathProbe::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn a_tlv_header_cut_off_by_the_end_of_the_block_rejects_the_message() {
    let mut bytes = probe_with_ext(&[0x03, 0x00, 0x01, 0x00, 0x00]);
    bytes.resize(40, 0);
    assert!(matches!(
        PathProbe::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn ext_set_with_no_room_for_the_extension_length_rejects_the_message() {
    let bytes = probe_with_ext(&[]);
    assert!(matches!(
        PathProbe::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
    let bytes = probe_with_ext(&[0x00]);
    assert!(matches!(
        PathProbe::decode(&bytes[1..]),
        Err(Error::Malformed(_))
    ));
    let mut ack = golden_ack();
    ack[5] = PathFlags::EXT;
    assert!(matches!(
        PathAck::decode(&ack[1..]),
        Err(Error::Malformed(_))
    ));
}
