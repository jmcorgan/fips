use super::*;

const SESSION: &str = "session-classify-vectors";

#[test]
fn classify_ignores_unparseable_bytes() {
    // P1: too short to parse.
    assert_eq!(
        classify_punch_packet(&[0u8; 4], session_hash(SESSION)),
        PunchAction::Ignore
    );
}

#[test]
fn classify_ignores_mismatched_session_hash() {
    // P2: parseable, but hash is for a different session.
    let packet = build_punch_packet(PunchPacketKind::Probe, 7, SESSION);
    let other_hash = session_hash("some-other-session");
    assert_eq!(
        classify_punch_packet(&packet, other_hash),
        PunchAction::Ignore
    );
}

#[test]
fn classify_probe_matching_hash_acks_with_sequence() {
    // P3: matching probe -> Ack carrying the packet's sequence.
    let packet = build_punch_packet(PunchPacketKind::Probe, 42, SESSION);
    assert_eq!(
        classify_punch_packet(&packet, session_hash(SESSION)),
        PunchAction::Ack { sequence: 42 }
    );
}

#[test]
fn classify_ack_matching_hash_is_matched() {
    // P4: matching non-probe (ack) -> Matched.
    let packet = build_punch_packet(PunchPacketKind::Ack, 3, SESSION);
    assert_eq!(
        classify_punch_packet(&packet, session_hash(SESSION)),
        PunchAction::Matched
    );
}
