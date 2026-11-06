use super::*;
use alloc::vec;
use std::println;

// ===== LinkMessageType Tests =====

#[test]
fn test_link_message_type_roundtrip() {
    let types = [
        LinkMessageType::TreeAnnounce,
        LinkMessageType::FilterAnnounce,
        LinkMessageType::LookupRequest,
        LinkMessageType::LookupResponse,
        LinkMessageType::SessionDatagram,
        LinkMessageType::Disconnect,
        LinkMessageType::Heartbeat,
        LinkMessageType::PathProbe,
        LinkMessageType::PathAck,
        LinkMessageType::PathClose,
    ];

    for ty in types {
        let byte = ty.to_byte();
        let restored = LinkMessageType::from_byte(byte);
        assert_eq!(restored, Some(ty));
    }
}

#[test]
fn test_link_message_type_invalid() {
    assert!(LinkMessageType::from_byte(0xFF).is_none());
    assert!(LinkMessageType::from_byte(0x03).is_none());
    assert!(LinkMessageType::from_byte(0x40).is_none());
}

// ===== SessionDatagram Tests =====

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

#[test]
fn test_session_datagram_encode_decode() {
    let src = make_node_addr(0xAA);
    let dest = make_node_addr(0xBB);
    let payload = vec![0x10, 0x00, 0x05, 0x00, 1, 2, 3, 4, 5]; // session payload
    let dg = SessionDatagram::new(src, dest, payload.clone()).with_ttl(32);

    let encoded = dg.encode();
    assert_eq!(encoded[0], 0x00); // msg_type (SessionDatagram)
    assert_eq!(encoded.len(), SESSION_DATAGRAM_HEADER_SIZE + payload.len());

    // Decode (after msg_type)
    let decoded = SessionDatagram::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.src_addr, src);
    assert_eq!(decoded.dest_addr, dest);
    assert_eq!(decoded.ttl, 32);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn test_session_datagram_ref_decode_borrows_payload() {
    let src = make_node_addr(0xAA);
    let dest = make_node_addr(0xBB);
    let payload = vec![0x10, 0x00, 0x05, 0x00, 1, 2, 3, 4, 5];
    let dg = SessionDatagram::new(src, dest, payload.clone())
        .with_ttl(32)
        .with_path_mtu(1400);

    let encoded = dg.encode();
    let decoded = SessionDatagramRef::decode(&encoded[1..]).unwrap();

    assert_eq!(decoded.src_addr, src);
    assert_eq!(decoded.dest_addr, dest);
    assert_eq!(decoded.ttl, 32);
    assert_eq!(decoded.path_mtu, 1400);
    assert_eq!(decoded.payload, payload.as_slice());
    assert_eq!(
        decoded.payload.as_ptr(),
        encoded[SESSION_DATAGRAM_HEADER_SIZE..].as_ptr()
    );
}

#[test]
#[ignore = "performance benchmark; run explicitly with --ignored --nocapture"]
fn bench_session_datagram_decode_owned_vs_ref() {
    use std::hint::black_box;
    use std::time::Instant;

    const ITERS: usize = 300_000;

    let src = make_node_addr(0xAA);
    let dest = make_node_addr(0xBB);
    let payload = vec![0x5A; 1200];
    let datagram = SessionDatagram::new(src, dest, payload)
        .with_ttl(32)
        .with_path_mtu(1400);
    let encoded = datagram.encode();
    let link_payload = &encoded[1..];

    let ref_start = Instant::now();
    let mut ref_bytes = 0usize;
    for _ in 0..ITERS {
        let decoded = SessionDatagramRef::decode(black_box(link_payload)).unwrap();
        ref_bytes = ref_bytes.wrapping_add(decoded.payload.len());
        black_box(decoded);
    }
    let ref_elapsed = ref_start.elapsed();

    let owned_start = Instant::now();
    let mut owned_bytes = 0usize;
    for _ in 0..ITERS {
        let decoded = SessionDatagram::decode(black_box(link_payload)).unwrap();
        owned_bytes = owned_bytes.wrapping_add(decoded.payload.len());
        black_box(decoded);
    }
    let owned_elapsed = owned_start.elapsed();

    assert_eq!(ref_bytes, owned_bytes);
    println!(
        "SessionDatagram decode: ref={:.1} ns/op owned={:.1} ns/op speedup={:.2}x iters={} payload_bytes={}",
        ref_elapsed.as_secs_f64() * 1_000_000_000.0 / ITERS as f64,
        owned_elapsed.as_secs_f64() * 1_000_000_000.0 / ITERS as f64,
        owned_elapsed.as_secs_f64() / ref_elapsed.as_secs_f64(),
        ITERS,
        link_payload.len() - 35
    );
}

#[test]
fn test_session_datagram_empty_payload() {
    let dg = SessionDatagram::new(make_node_addr(1), make_node_addr(2), Vec::new());

    let encoded = dg.encode();
    assert_eq!(encoded.len(), SESSION_DATAGRAM_HEADER_SIZE);

    let decoded = SessionDatagram::decode(&encoded[1..]).unwrap();
    assert!(decoded.payload.is_empty());
}

#[test]
fn test_session_datagram_decode_too_short() {
    assert!(SessionDatagram::decode(&[]).is_err());
    assert!(SessionDatagram::decode(&[0x00; 20]).is_err());
}

#[test]
fn test_session_datagram_ttl_roundtrip() {
    for hop in [0u8, 1, 64, 128, 255] {
        let dg =
            SessionDatagram::new(make_node_addr(1), make_node_addr(2), vec![0x42]).with_ttl(hop);

        let encoded = dg.encode();
        let decoded = SessionDatagram::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.ttl, hop);
    }
}

#[test]
fn test_session_datagram_can_forward() {
    let dg = SessionDatagram::new(make_node_addr(1), make_node_addr(2), vec![0x42]);

    assert!(!dg.clone().with_ttl(0).can_forward());
    assert!(
        !dg.clone().with_ttl(1).can_forward(),
        "ttl=1 would leave at zero, so it is not forwardable"
    );
    assert!(
        dg.clone().with_ttl(2).can_forward(),
        "ttl=2 leaves at one, so it is forwardable"
    );
    assert!(dg.with_ttl(255).can_forward());
}

#[test]
fn ttl_after_hop_drops_only_what_would_leave_at_zero() {
    assert_eq!(
        ttl_after_hop(0),
        None,
        "an exhausted arrival leaves at zero"
    );
    assert_eq!(ttl_after_hop(1), None, "a last-hop arrival leaves at zero");
    assert_eq!(ttl_after_hop(2), Some(1));
    assert_eq!(ttl_after_hop(255), Some(254));

    let dg = SessionDatagram::new(make_node_addr(1), make_node_addr(2), vec![0x42]);
    for ttl in 0..=u8::MAX {
        assert_eq!(
            ttl_after_hop(ttl).is_some(),
            ttl > 1,
            "ttl={ttl}: only a TTL of 2 or more survives the hop"
        );
        let owned = dg.clone().with_ttl(ttl);
        let encoded = owned.encode();
        let view = SessionDatagramRef::decode(&encoded[1..]).unwrap();
        assert_eq!(
            view.can_forward(),
            owned.can_forward(),
            "ttl={ttl}: the borrowed and owned views must agree"
        );
        assert_eq!(view.can_forward(), ttl_after_hop(ttl).is_some());
    }
}

#[test]
fn test_session_datagram_decrement_ttl() {
    let base = SessionDatagram::new(make_node_addr(1), make_node_addr(2), vec![0x42]);

    let mut dg = base.clone().with_ttl(0);
    assert!(!dg.decrement_ttl(), "ttl=0 is already exhausted");
    assert_eq!(dg.ttl, 0, "decrement must saturate rather than wrap");

    let mut dg = base.clone().with_ttl(1);
    assert!(
        !dg.decrement_ttl(),
        "ttl=1 leaves at zero, so it is dropped"
    );
    assert_eq!(dg.ttl, 0);

    let mut dg = base.clone().with_ttl(2);
    assert!(dg.decrement_ttl());
    assert_eq!(dg.ttl, 1);

    let mut dg = base.with_ttl(64);
    assert!(dg.decrement_ttl());
    assert_eq!(dg.ttl, 63);
}
