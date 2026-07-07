//! Tests for the MMP algorithmic building blocks.

use crate::proto::mmp::algorithms::{
    DualEwma, JitterEstimator, OwdTrendDetector, SpinBitState, SrttEstimator, compute_etx,
};

#[test]
fn test_jitter_zero_input() {
    let mut j = JitterEstimator::new();
    j.update(0);
    assert_eq!(j.jitter_us(), 0);
}

#[test]
fn test_jitter_convergence() {
    let mut j = JitterEstimator::new();
    // Feed constant transit delta of 1000µs
    for _ in 0..200 {
        j.update(1000);
    }
    // Should converge near 1000µs
    let jitter = j.jitter_us();
    assert!(
        jitter > 900 && jitter < 1100,
        "jitter={jitter}, expected ~1000"
    );
}

#[test]
fn test_srtt_first_sample() {
    let mut s = SrttEstimator::new();
    s.update(10_000); // 10ms
    assert_eq!(s.srtt_us(), 10_000);
    assert_eq!(s.rttvar_us(), 5_000);
    assert!(s.initialized());
}

#[test]
fn test_srtt_convergence() {
    let mut s = SrttEstimator::new();
    // Feed constant 50ms RTT
    for _ in 0..100 {
        s.update(50_000);
    }
    let srtt = s.srtt_us();
    assert!((srtt - 50_000).abs() < 1000, "srtt={srtt}, expected ~50000");
}

#[test]
fn test_dual_ewma_initialization() {
    let mut e = DualEwma::new();
    assert!(!e.initialized());
    e.update(100.0);
    assert!(e.initialized());
    assert_eq!(e.short(), 100.0);
    assert_eq!(e.long(), 100.0);
}

#[test]
fn test_dual_ewma_short_tracks_faster() {
    let mut e = DualEwma::new();
    // Initialize at 0
    e.update(0.0);
    // Jump to 100
    for _ in 0..20 {
        e.update(100.0);
    }
    // Short should be closer to 100 than long
    assert!(
        e.short() > e.long(),
        "short={} long={}",
        e.short(),
        e.long()
    );
}

#[test]
fn test_owd_trend_flat() {
    let mut d = OwdTrendDetector::new(32);
    for i in 0..20 {
        d.push(i, 5000); // constant OWD
    }
    let trend = d.trend_us_per_sec();
    assert_eq!(trend, 0, "flat OWD should have zero trend");
}

#[test]
fn test_owd_trend_increasing() {
    let mut d = OwdTrendDetector::new(32);
    for i in 0..20 {
        d.push(i, 5000 + (i as i64) * 100); // increasing by 100µs per packet
    }
    let trend = d.trend_us_per_sec();
    assert!(
        trend > 0,
        "increasing OWD should have positive trend, got {trend}"
    );
}

#[test]
fn test_owd_trend_insufficient_samples() {
    let mut d = OwdTrendDetector::new(32);
    d.push(0, 5000);
    assert_eq!(d.trend_us_per_sec(), 0);
}

#[test]
fn test_etx_perfect_link() {
    assert!((compute_etx(1.0, 1.0) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_etx_lossy_link() {
    // 10% forward loss, 5% reverse loss
    let etx = compute_etx(0.9, 0.95);
    assert!(etx > 1.0 && etx < 2.0, "etx={etx}");
}

#[test]
fn test_etx_zero_delivery() {
    assert_eq!(compute_etx(0.0, 1.0), 100.0);
    assert_eq!(compute_etx(1.0, 0.0), 100.0);
}

#[test]
fn test_spin_bit_initiator_rtt() {
    let mut initiator = SpinBitState::new(true);
    let mut responder = SpinBitState::new(false);

    // Injected monotonic milliseconds: t0=0, t1=10ms, t2=20ms.
    let t0 = 0u64;
    let t1 = 10u64;
    let t2 = 20u64;

    // Initiator sends with spin=false (initial)
    let bit_to_send = initiator.tx_bit();
    assert!(!bit_to_send);

    // Responder receives, copies bit
    responder.rx_observe(bit_to_send, 1, t0);
    assert!(!responder.tx_bit());

    // Responder sends back, initiator receives
    let resp_bit = responder.tx_bit();
    let rtt1 = initiator.rx_observe(resp_bit, 2, t1);
    // First edge: no previous edge to compare
    assert!(rtt1.is_none());

    // Now initiator's spin flipped to true
    let bit2 = initiator.tx_bit();
    assert!(bit2);

    // Responder receives new bit
    responder.rx_observe(bit2, 3, t1);
    assert!(responder.tx_bit());

    // Responder sends back, initiator receives
    let resp_bit2 = responder.tx_bit();
    let rtt2 = initiator.rx_observe(resp_bit2, 4, t2);
    // Second edge: should produce an RTT sample
    assert!(rtt2.is_some());
}

#[test]
fn test_spin_bit_responder_counter_guard() {
    let mut responder = SpinBitState::new(false);

    // Receive counter=5 with spin=true
    responder.rx_observe(true, 5, 0);
    assert!(responder.tx_bit());

    // Reordered packet with counter=3 and spin=false should be ignored
    responder.rx_observe(false, 3, 0);
    assert!(responder.tx_bit()); // unchanged
}
