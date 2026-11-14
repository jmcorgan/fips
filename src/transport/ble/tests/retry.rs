//! Tests for the scan and probe loop's retry tick: on each tick it ages out
//! of the learned PSM memory every address that is not live and has gone
//! unseen for [`RECALLED_ADDR_MAX_AGE`], and keeps every address that is
//! live.
//!
//! The test reaches the memory only through `remember` and `remembered`, so
//! they are the only lines that depend on how this branch stores it.
//!
//! [`RECALLED_ADDR_MAX_AGE`]: super::recall::RECALLED_ADDR_MAX_AGE

use super::io::{MockBleIo, MockBleStream, ScanAdvert};
use super::*;

/// The retry tick's period, and so the probe cooldown, in seconds.
const COOLDOWN_SECS: u64 = 1;

/// A link address on the mock adapter.
fn test_addr(n: u8) -> BleAddr {
    BleAddr {
        adapter: "hci0".to_string(),
        device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
    }
}

/// A scanning transport that accepts no inbound links. Its dials to
/// `peer_at` hand the remote end to the returned receiver; every other dial
/// is refused.
fn probing_transport(
    peer_at: &BleAddr,
) -> (
    BleTransport<MockBleIo>,
    tokio::sync::mpsc::UnboundedReceiver<MockBleStream>,
) {
    let io = MockBleIo::new("hci0", test_addr(1));
    let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();
    let peer_at = peer_at.clone();
    io.set_connect_handler(move |addr, _psm| {
        if *addr != peer_at {
            return Err(TransportError::ConnectionRefused);
        }
        let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
        peer_tx
            .send(theirs)
            .map_err(|_| TransportError::ConnectionRefused)?;
        Ok(mine)
    });
    let config = BleConfig {
        adapter: Some("hci0".to_string()),
        scan: Some(true),
        advertise: Some(false),
        accept_connections: Some(false),
        probe_cooldown_secs: Some(COOLDOWN_SECS),
        ..Default::default()
    };
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
    (transport, peer_rx)
}

/// Note `addr` in the learned PSM memory at `now`, as advertising `psm`.
/// Every address noted here is passed as live, so noting evicts nothing.
fn remember(
    transport: &BleTransport<MockBleIo>,
    addr: &BleAddr,
    psm: u16,
    now: tokio::time::Instant,
) {
    recall(&transport.learned_psm).note(addr, psm, now, |_| true);
}

/// Whether `addr` is in the learned PSM memory.
fn remembered(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> bool {
    recall(&transport.learned_psm).get(addr).is_some()
}

/// Whether a link is pooled at `addr`, without waiting on the lock.
fn pooled(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> bool {
    transport
        .pool
        .try_lock()
        .map(|p| p.contains(&addr.to_transport_addr()))
        .unwrap_or(false)
}

/// Let the clock run in one-millisecond steps until `cond` holds or `limit`
/// has passed, and say whether it held. Each step's sleep is what lets the
/// probe loop's timers fire; the clock is paused, so the steps cost no real
/// time.
async fn holds_within(limit: std::time::Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        if cond() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
}

/// The retry tick forgets the learned PSM of an address that is neither
/// pooled nor in the retry book once it has gone unseen for the age limit,
/// and keeps a pooled one's however long ago it was noted.
#[tokio::test(start_paused = true)]
async fn the_retry_tick_ages_out_learned_psms_that_are_not_live_and_keeps_pooled_ones() {
    let pooled_at = test_addr(2);
    let stale = test_addr(3);
    let (mut transport, mut peer_rx) = probing_transport(&pooled_at);
    transport.start_async().await.unwrap();

    // Pool a peer through its advertisement, which also teaches the
    // transport its PSM.
    transport
        .io
        .inject_scan_advert(ScanAdvert::with_psm(pooled_at.clone(), 0x00C1))
        .await;
    let theirs = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
        .await
        .expect("the peer is probed")
        .unwrap();
    assert!(
        holds_within(std::time::Duration::from_secs(5), || pooled(
            &transport, &pooled_at
        ))
        .await,
        "the peer is pooled"
    );

    // Note both addresses at the same instant: the pooled one, and one that
    // is neither pooled nor in the retry book.
    let now = tokio::time::Instant::now();
    remember(&transport, &pooled_at, 0x00C1, now);
    remember(&transport, &stale, 0x00C2, now);
    assert!(
        remembered(&transport, &pooled_at),
        "the pooled address's PSM is in the memory"
    );
    assert!(
        remembered(&transport, &stale),
        "the PSM of the address that is not live is in the memory"
    );

    // Past the age limit, then long enough for at least one more tick.
    tokio::time::sleep(recall::RECALLED_ADDR_MAX_AGE).await;
    let cooldown = std::time::Duration::from_secs(COOLDOWN_SECS);
    let aged_out = holds_within(2 * cooldown, || !remembered(&transport, &stale)).await;

    assert!(
        aged_out,
        "defect: the retry tick kept the PSM of an address that is not live past the age limit"
    );
    assert!(
        pooled(&transport, &pooled_at),
        "the peer's link is still pooled"
    );
    assert!(
        remembered(&transport, &pooled_at),
        "defect: the retry tick aged out the PSM of a pooled link"
    );

    drop(theirs);
    transport.stop_async().await.unwrap();
}
