//! Advertising the L2CAP listener PSM.
//!
//! A dialer has to know which PSM a peer's L2CAP listener is bound to. On
//! BlueZ an application can *choose* that number, so both ends can agree on a
//! configured constant. BlueZ is the exception: Android's
//! `listenUsingInsecureL2capChannel` and macOS's
//! `CBPeripheralManager.publishL2CAPChannel` both return an **OS-assigned**
//! PSM the application cannot request. A dialer cannot guess it, and before a
//! connection exists there is no channel to be told it on other than the
//! advertisement itself.
//!
//! This module is the wire specification for putting it there. It is
//! deliberately state-free: learning and caching belong to the scan/probe
//! loop, which already owns per-address state.
//!
//! # Wire layout
//!
//! The PSM rides a **Service Data — 16-bit UUID** AD structure (AD type
//! `0x16`) keyed on [`PSM_SERVICE_DATA_UUID16`], carrying the PSM as two
//! bytes little-endian.
//!
//! ## Why a 16-bit key, and not the FIPS service UUID
//!
//! A legacy advertising PDU carries 31 bytes of AD payload. Keying the
//! service data on the full 128-bit FIPS service UUID does not fit:
//!
//! | AD structure                                  | bytes |
//! |-----------------------------------------------|-------|
//! | Flags                                         | 3     |
//! | Complete list of 128-bit service UUIDs        | 18    |
//! | Service Data — **128-bit** UUID + 2-byte PSM  | 20    |
//! | **total**                                     | **41** — over by 10 |
//!
//! Keying it on the 16-bit UUID [`PSM_SERVICE_DATA_UUID16`] does:
//!
//! | AD structure                                  | bytes |
//! |-----------------------------------------------|-------|
//! | Flags                                         | 3     |
//! | Complete list of 128-bit service UUIDs        | 18    |
//! | Service Data — **16-bit** UUID + 2-byte PSM   | 6     |
//! | **total**                                     | **27** — fits |
//!
//! `0x9C90` is the leading 16 bits of the FIPS service UUID, expanded through
//! the Bluetooth base UUID (`00009C90-0000-1000-8000-00805F9B34FB`). The
//! budget is asserted at compile time below, so a change that reverts to a
//! 128-bit key fails the build rather than the radio. It also means an
//! advertiser using this layout has no room left for a local name.
//!
//! ## Why the primary advertisement, not the scan response
//!
//! A scan response only arrives after a successful active-scan
//! request/response round-trip, and that round-trip drops asymmetrically
//! across chipsets. Peers that never answer a scan request would become
//! undiscoverable rather than merely slower. The primary advertisement is
//! received passively on every advertising interval, so the PSM must ride it.
//!
//! ## Compatibility
//!
//! A reader ignores trailing bytes, so the value can be extended without
//! breaking older peers, and an advert with no service data at all decodes to
//! `None` — which is what every legacy UUID-only advertiser produces, and
//! what makes them keep working against the configured PSM.

/// Service-data key for the advertised L2CAP PSM.
///
/// The leading 16 bits of the FIPS service UUID, i.e. the Bluetooth
/// base-range UUID `00009C90-0000-1000-8000-00805F9B34FB`. Backends that
/// speak in whole UUIDs must expand it through the base UUID; backends that
/// speak in AD structures emit it as AD type `0x16`.
pub const PSM_SERVICE_DATA_UUID16: u16 = 0x9C90;

/// AD payload budget of a legacy advertising PDU, in bytes.
const LEGACY_ADV_PAYLOAD_BYTES: usize = 31;

/// Flags AD structure: length + type + one byte of flags.
const FLAGS_AD_BYTES: usize = 3;

/// Complete list of 128-bit service UUIDs: length + type + one UUID.
const UUID128_LIST_AD_BYTES: usize = 2 + 16;

/// Service data keyed on a 16-bit UUID: length + type + key + PSM.
const PSM_SERVICE_DATA_AD_BYTES: usize = 2 + 2 + PSM_ENCODED_LEN;

/// Encoded width of the PSM value itself.
const PSM_ENCODED_LEN: usize = 2;

/// The layout above must fit a legacy advertising PDU. If this fails, the
/// advert would be silently truncated or rejected by the controller.
const _: () = assert!(
    FLAGS_AD_BYTES + UUID128_LIST_AD_BYTES + PSM_SERVICE_DATA_AD_BYTES <= LEGACY_ADV_PAYLOAD_BYTES,
    "PSM advert layout exceeds the 31-byte legacy advertising PDU"
);

/// Encode a PSM as advertised service data: two bytes, little-endian.
pub fn encode_psm(psm: u16) -> [u8; PSM_ENCODED_LEN] {
    psm.to_le_bytes()
}

/// Decode a PSM from advertised service data.
///
/// Returns `None` for absent or truncated data — a legacy UUID-only
/// advertiser, which the caller answers by dialling the configured PSM.
/// Trailing bytes are ignored so the value can be extended later without
/// breaking readers built against this version.
pub fn decode_psm(data: &[u8]) -> Option<u16> {
    if data.len() < PSM_ENCODED_LEN {
        return None;
    }
    Some(u16::from_le_bytes([data[0], data[1]]))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_is_little_endian() {
        assert_eq!(encode_psm(0x0085), [0x85, 0x00]);
        assert_eq!(encode_psm(0x1234), [0x34, 0x12]);
    }

    #[test]
    fn test_round_trip() {
        for psm in [0u16, 1, 0x0085, 0x00FF, 0x1234, u16::MAX] {
            assert_eq!(decode_psm(&encode_psm(psm)), Some(psm), "psm {psm:#06x}");
        }
    }

    #[test]
    fn test_absent_service_data_decodes_to_none() {
        // A legacy UUID-only advertiser carries no service data at all.
        assert_eq!(decode_psm(&[]), None);
    }

    #[test]
    fn test_truncated_service_data_decodes_to_none() {
        assert_eq!(decode_psm(&[0x85]), None);
    }

    #[test]
    fn test_trailing_bytes_are_ignored() {
        // Forward compatibility: a future advertiser may append fields.
        assert_eq!(decode_psm(&[0x85, 0x00, 0xFF, 0xFF]), Some(0x0085));
    }

    /// The byte budget is a build-time assertion, not a comment. This test
    /// records the arithmetic it encodes so the numbers stay legible.
    #[test]
    fn test_advert_fits_the_legacy_pdu() {
        assert_eq!(FLAGS_AD_BYTES, 3);
        assert_eq!(UUID128_LIST_AD_BYTES, 18);
        assert_eq!(PSM_SERVICE_DATA_AD_BYTES, 6);
        assert_eq!(
            FLAGS_AD_BYTES + UUID128_LIST_AD_BYTES + PSM_SERVICE_DATA_AD_BYTES,
            27
        );
        assert_eq!(LEGACY_ADV_PAYLOAD_BYTES, 31);
        // A 128-bit service-data key would need 20 bytes, not 6 — the layout
        // this module exists to reject.
        assert_eq!(FLAGS_AD_BYTES + UUID128_LIST_AD_BYTES + 20, 41);
    }

    #[test]
    fn test_key_is_the_leading_16_bits_of_the_fips_uuid() {
        // FIPS service UUID: 9c90b790-2cc5-42c0-9f87-c9cc40648f4c
        const FIPS_SERVICE_UUID_U128: u128 = 0x9c90_b790_2cc5_42c0_9f87_c9cc_4064_8f4c;
        assert_eq!(
            PSM_SERVICE_DATA_UUID16,
            (FIPS_SERVICE_UUID_U128 >> 112) as u16
        );
    }
}
