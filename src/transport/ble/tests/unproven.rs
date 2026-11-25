//! Tests for the pool's account of channels on which no handshake has
//! completed: [`ConnectionPool::unproven`] and [`ConnectionPool::hold`].
//! Every instant is given explicitly; no test reads a clock after setup.

use std::time::Duration;

use super::*;

/// The handshake timeout every test here runs with.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The eviction grace every test here runs with.
const GRACE: Duration = Duration::from_secs(10);

/// A distinct link address per `n`.
fn addr(n: u8) -> TransportAddr {
    TransportAddr::from_string(&format!("hci0/AA:BB:CC:DD:EE:{n:02X}"))
}

/// A distinct node identity per `n`.
fn node(n: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = n;
    NodeAddr::from_bytes(bytes)
}

/// An unverified link at `addr(n)` claiming `node(n)`, admitted at `at`.
fn conn(n: u8, at: tokio::time::Instant) -> BleConnection<()> {
    BleConnection {
        stream: (),
        recv_task: None,
        send_mtu: 2048,
        recv_mtu: 2048,
        established_at: at,
        verified: false,
        grace_from: at,
        addr: BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        },
        node_addr: Some(node(n)),
        proven: false,
        held_from: at,
    }
}

/// A pool holding the unverified link `addr(1)`, admitted at `t0`.
fn pool_with_one(t0: tokio::time::Instant) -> ConnectionPool<()> {
    let mut pool = ConnectionPool::new(7, GRACE);
    assert!(
        matches!(
            pool.insert(addr(1), conn(1, t0), t0),
            Insert::Admitted { .. }
        ),
        "precondition: the link is pooled"
    );
    pool
}

#[test]
fn a_never_verified_link_is_unproven_from_the_timeout_after_admission_and_not_before() {
    let t0 = tokio::time::Instant::now();
    let pool = pool_with_one(t0);
    let second = Duration::from_secs(1);
    assert!(pool.unproven(t0 + TIMEOUT - second, TIMEOUT).is_empty());
    assert_eq!(pool.unproven(t0 + TIMEOUT, TIMEOUT), vec![addr(1)]);
}

#[test]
fn holding_a_link_starts_its_timeout_again_from_the_hold() {
    let t0 = tokio::time::Instant::now();
    let mut pool = pool_with_one(t0);
    let second = Duration::from_secs(1);
    let held = t0 + Duration::from_secs(20);
    pool.hold(&addr(1), held);
    assert!(
        pool.unproven(t0 + TIMEOUT, TIMEOUT).is_empty(),
        "a link held 20 s after admission was named at the admission's timeout"
    );
    assert!(pool.unproven(held + TIMEOUT - second, TIMEOUT).is_empty());
    assert_eq!(pool.unproven(held + TIMEOUT, TIMEOUT), vec![addr(1)]);
}

#[test]
fn a_link_verified_once_and_then_cleared_is_never_unproven() {
    let t0 = tokio::time::Instant::now();
    let mut pool = pool_with_one(t0);
    assert!(matches!(
        pool.mark_verified(&addr(1), &node(1)),
        Verify::Marked { .. }
    ));
    assert!(
        pool.clear_verified(&addr(1), &node(1), None),
        "precondition: the link is unverified again"
    );
    assert!(pool.unproven(t0 + 4 * TIMEOUT, TIMEOUT).is_empty());
}

#[test]
fn a_verified_link_is_never_unproven() {
    let t0 = tokio::time::Instant::now();
    let mut pool = pool_with_one(t0);
    assert!(matches!(
        pool.mark_verified(&addr(1), &node(1)),
        Verify::Marked { .. }
    ));
    assert!(pool.unproven(t0 + 4 * TIMEOUT, TIMEOUT).is_empty());
}
