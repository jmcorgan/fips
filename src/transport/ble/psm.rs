//! Per-peer PSM discovery (BLE v2).
//!
//! On the platforms that matter the L2CAP listener PSM is **OS-assigned**, not
//! chosen by the app (Android `listenUsingInsecureL2capChannel`, macOS
//! `CBPeripheralManager.publishL2CAPChannel`); only BlueZ can bind a fixed one.
//! So rather than relying on the fixed `DEFAULT_PSM` (0x0085), every node
//! **advertises its own listener PSM** as a 16-bit little-endian value in the
//! service-data field keyed on the FIPS service UUID, and every dialer **reads a
//! peer's advertised PSM before `connect()`**. The fixed-PSM assumption was a
//! BlueZ quirk; this makes discovery symmetric across all backends.
//!
//! This module holds the platform-agnostic pieces shared by every `BleIo`
//! backend (`BluerIo`, `BluestIo`, `AndroidIo`): the service-data **codec** and
//! the short-lived **`BleAddr → PSM` map**. The per-backend advertise/scan/dial
//! wiring lives in the backends. See
//! [`docs/reference/ble-wire.md`](../../../../docs/reference/ble-wire.md) and
//! [`docs/design/ble-interop.md`](../../../../docs/design/ble-interop.md).

use std::collections::HashMap;
use std::sync::Mutex;

use super::addr::BleAddr;

/// Encode a listener PSM as the 2-byte little-endian service-data payload
/// advertised under the FIPS service UUID.
///
/// The legacy advertising PDU caps at ~31 bytes, so a 128-bit UUID + this
/// 2-byte value is the tight, legacy-safe layout (see ble-wire.md).
pub fn encode_psm(psm: u16) -> [u8; 2] {
    psm.to_le_bytes()
}

/// Decode a peer's advertised PSM from its FIPS service-data payload.
///
/// Returns `None` when fewer than 2 bytes are present — e.g. a legacy,
/// UUID-only advert that carries no PSM, for which the dialer falls back to
/// [`DEFAULT_PSM`](super::DEFAULT_PSM). Any bytes beyond the first two are
/// ignored, so the encoding can grow without breaking older readers.
pub fn decode_psm(data: &[u8]) -> Option<u16> {
    match data {
        [lo, hi, ..] => Some(u16::from_le_bytes([*lo, *hi])),
        _ => None,
    }
}

/// Short-lived map of discovered peer addresses to their advertised listener
/// PSM, populated by the scan loop and consulted by `connect()`.
///
/// Keyed on [`BleAddr`], which **rotates** with MAC randomization, so entries
/// are transient: they are re-learned each scan cycle rather than cached
/// durably. A stale entry merely causes one dial failure and a re-probe on the
/// next scan tick (see "Why MAC randomization is harmless" in ble-interop.md).
#[derive(Debug, Default)]
pub struct PsmMap {
    inner: Mutex<HashMap<BleAddr, u16>>,
}

impl PsmMap {
    /// Create an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a peer's advertised PSM, learned from a scan advert. A later
    /// advert for the same address overwrites the earlier value.
    pub fn learn(&self, addr: &BleAddr, psm: u16) {
        self.lock().insert(addr.clone(), psm);
    }

    /// Look up a peer's learned PSM, if one has been seen this scan cycle.
    pub fn lookup(&self, addr: &BleAddr) -> Option<u16> {
        self.lock().get(addr).copied()
    }

    /// Resolve the PSM to dial for `addr`: the learned per-peer PSM if known,
    /// otherwise `fallback` (the configured PSM, else the legacy
    /// [`DEFAULT_PSM`](super::DEFAULT_PSM)).
    pub fn resolve(&self, addr: &BleAddr, fallback: u16) -> u16 {
        self.lookup(addr).unwrap_or(fallback)
    }

    /// Forget a single learned entry (e.g. after a dial failure).
    pub fn forget(&self, addr: &BleAddr) {
        self.lock().remove(addr);
    }

    /// Drop all learned entries. Called at the start of a scan cycle, since
    /// addresses rotate and a dropped PSM only costs a dial-retry.
    pub fn clear(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BleAddr, u16>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ble::DEFAULT_PSM;

    fn addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "ble0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    #[test]
    fn codec_roundtrips_little_endian() {
        // 0x0085 -> [0x85, 0x00]; explicit LE byte order matches the wire spec.
        assert_eq!(encode_psm(0x0085), [0x85, 0x00]);
        assert_eq!(encode_psm(0x1234), [0x34, 0x12]);
        for psm in [0u16, 1, 0x0085, 0x0080, 0x00FF, 0x1234, u16::MAX] {
            assert_eq!(decode_psm(&encode_psm(psm)), Some(psm));
        }
    }

    #[test]
    fn decode_rejects_short_payload_but_ignores_trailing() {
        assert_eq!(decode_psm(&[]), None); // legacy UUID-only advert
        assert_eq!(decode_psm(&[0x85]), None); // truncated
        // Forward-compatible: trailing bytes beyond the PSM are ignored.
        assert_eq!(decode_psm(&[0x85, 0x00, 0xFF, 0xFF]), Some(0x0085));
    }

    #[test]
    fn learn_lookup_and_overwrite() {
        let map = PsmMap::new();
        assert_eq!(map.lookup(&addr(1)), None);

        map.learn(&addr(1), 0x0091);
        assert_eq!(map.lookup(&addr(1)), Some(0x0091));

        // A later advert for the same address overwrites.
        map.learn(&addr(1), 0x00A0);
        assert_eq!(map.lookup(&addr(1)), Some(0x00A0));

        // Distinct addresses are independent.
        map.learn(&addr(2), 0x00B0);
        assert_eq!(map.lookup(&addr(1)), Some(0x00A0));
        assert_eq!(map.lookup(&addr(2)), Some(0x00B0));
    }

    #[test]
    fn resolve_prefers_learned_then_falls_back() {
        let map = PsmMap::new();
        // No learned PSM yet -> legacy default.
        assert_eq!(map.resolve(&addr(1), DEFAULT_PSM), DEFAULT_PSM);

        map.learn(&addr(1), 0x0091);
        assert_eq!(map.resolve(&addr(1), DEFAULT_PSM), 0x0091);
        // A different, unseen address still falls back.
        assert_eq!(map.resolve(&addr(9), DEFAULT_PSM), DEFAULT_PSM);
    }

    #[test]
    fn forget_and_clear_drop_entries() {
        let map = PsmMap::new();
        map.learn(&addr(1), 0x0091);
        map.learn(&addr(2), 0x0092);

        map.forget(&addr(1));
        assert_eq!(map.lookup(&addr(1)), None);
        assert_eq!(map.lookup(&addr(2)), Some(0x0092));

        map.clear();
        assert_eq!(map.lookup(&addr(2)), None);
    }
}
