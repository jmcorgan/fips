//! Tests for the scan and probe loop's retry tick: on each tick it ages out
//! of the probe memory every address that is not live and has gone unseen for
//! [`RECALLED_ADDR_MAX_AGE`], and keeps every address that is live.
//!
//!
//! The test reaches the probe memory only through `remember` and
//! `remembered`, so they are the only lines that depend on how this branch
//! stores it.
//!
//! [`RECALLED_ADDR_MAX_AGE`]: super::recall::RECALLED_ADDR_MAX_AGE

use super::io::{MockBleIo, MockBleStream, ScanAdvert};
use super::*;
use secp256k1::{Secp256k1, SecretKey};

/// The retry tick's period, and so the probe cooldown, in seconds.
const COOLDOWN_SECS: u64 = 1;

/// A link address on the mock adapter.
fn test_addr(n: u8) -> BleAddr {
    BleAddr {
        adapter: "hci0".to_string(),
        device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
    }
}

/// `n` x-only pubkeys sorted ascending by node address, so the transport can
/// take the smaller and win the probe tie-break.
fn pubkeys_by_node_addr(n: u8) -> Vec<[u8; 32]> {
    let secp = Secp256k1::new();
    let mut keys: Vec<[u8; 32]> = (1..=n)
        .map(|seed| {
            let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
            sk.public_key(&secp).x_only_public_key().0.serialize()
        })
        .collect();
    keys.sort_by_key(|k| NodeAddr::from_pubkey(&XOnlyPublicKey::from_slice(k).unwrap()));
    keys
}

/// The node address a 32-byte x-only key derives.
fn node_of(pubkey: &[u8; 32]) -> NodeAddr {
    NodeAddr::from_pubkey(&XOnlyPublicKey::from_slice(pubkey).unwrap())
}

/// Run the peer half of the pubkey exchange over a mock stream end.
async fn peer_side_exchange(peer: &MockBleStream, peer_pubkey: &[u8; 32]) {
    let mut msg = [0u8; PUBKEY_EXCHANGE_SIZE];
    msg[0] = PUBKEY_EXCHANGE_PREFIX;
    msg[1..].copy_from_slice(peer_pubkey);
    peer.send(&msg).await.unwrap();
    let mut buf = [0u8; PUBKEY_EXCHANGE_SIZE];
    let n = peer.recv(&mut buf).await.unwrap();
    assert_eq!(n, PUBKEY_EXCHANGE_SIZE);
}

/// A scanning transport holding `ours` that accepts no inbound links. Its
/// dials to `peer_at` hand the remote end to the returned receiver; every
/// other dial is refused.
fn probing_transport(
    ours: [u8; 32],
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
    let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
    transport.set_local_pubkey(ours);
    (transport, peer_rx)
}

/// Note `addr` in both halves of the probe memory at `now`, as resolved to
/// `node` and advertising `psm`. Every address noted here is passed as live,
/// so noting evicts nothing.
fn remember(
    transport: &BleTransport<MockBleIo>,
    addr: &BleAddr,
    node: NodeAddr,
    psm: u16,
    now: tokio::time::Instant,
) {
    recall(&transport.known_node_of).note(addr, node, now, |_| true);
    recall(&transport.learned_psm).note(addr, psm, now, |_| true);
}

/// Whether `addr` is in the probe memory's two halves: the node it was
/// resolved to, and the PSM it advertised.
fn remembered(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> (bool, bool) {
    (
        recall(&transport.known_node_of).get(addr).is_some(),
        recall(&transport.learned_psm).get(addr).is_some(),
    )
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

/// The retry tick forgets an address that is neither pooled nor in the retry
/// book once it has gone unseen for the age limit, and keeps a pooled one
/// however long ago it was noted.
#[tokio::test(start_paused = true)]
async fn the_retry_tick_ages_out_addresses_that_are_not_live_and_keeps_pooled_ones() {
    let keys = pubkeys_by_node_addr(2);
    let (ours, peer) = (keys[0], keys[1]);
    let pooled_at = test_addr(2);
    let stale = test_addr(3);
    let (mut transport, mut peer_rx) = probing_transport(ours, &pooled_at);
    transport.start_async().await.unwrap();

    // Pool a peer through its advertisement and key exchange. Its PSM is
    // learned from the advertisement.
    transport
        .io
        .inject_scan_advert(ScanAdvert::with_psm(pooled_at.clone(), 0x00C1))
        .await;
    let theirs = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
        .await
        .expect("the peer is probed")
        .unwrap();
    peer_side_exchange(&theirs, &peer).await;
    assert!(
        holds_within(std::time::Duration::from_secs(5), || pooled(
            &transport, &pooled_at
        ))
        .await,
        "the peer is pooled"
    );

    // Note both addresses in both halves at the same instant: the pooled one,
    // and one that is neither pooled nor in the retry book.
    let now = tokio::time::Instant::now();
    remember(&transport, &pooled_at, node_of(&peer), 0x00C1, now);
    remember(&transport, &stale, node_of(&peer), 0x00C2, now);
    assert_eq!(
        remembered(&transport, &pooled_at),
        (true, true),
        "the pooled address is in both halves of the memory"
    );
    assert_eq!(
        remembered(&transport, &stale),
        (true, true),
        "the address that is not live is in both halves of the memory"
    );

    // Past the age limit, then long enough for at least one more tick.
    tokio::time::sleep(recall::RECALLED_ADDR_MAX_AGE).await;
    let cooldown = std::time::Duration::from_secs(COOLDOWN_SECS);
    let aged_out = holds_within(2 * cooldown, || {
        remembered(&transport, &stale) == (false, false)
    })
    .await;

    assert!(
        aged_out,
        "defect: the retry tick kept an address that is not live past the age limit: {:?}",
        remembered(&transport, &stale)
    );
    assert!(
        pooled(&transport, &pooled_at),
        "the peer's link is still pooled"
    );
    assert_eq!(
        remembered(&transport, &pooled_at),
        (true, true),
        "defect: the retry tick aged out the address of a pooled link"
    );

    drop(theirs);
    transport.stop_async().await.unwrap();
}
