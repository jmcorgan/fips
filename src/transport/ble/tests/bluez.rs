//! Tests for the two decisions the BlueZ backend makes without BlueZ: which
//! cached device objects scan start removes, and which LE address type a
//! dial uses.
//!
//! The D-Bus property reads and the kernel connect around these decisions
//! are not exercised here; they need a Bluetooth adapter.

use super::*;

/// A cached object with none of the four flags set.
fn bare() -> CachedDevice {
    CachedDevice {
        paired: false,
        trusted: false,
        connected: false,
        blocked: false,
    }
}

#[test]
fn a_paired_device_is_not_removed_when_scanning_starts() {
    let dev = CachedDevice {
        paired: true,
        ..bare()
    };
    assert!(
        !clear_at_scan_start(&dev),
        "defect: scan start removes a paired device, which deletes its pairing keys"
    );
}

#[test]
fn a_connected_device_is_not_removed_when_scanning_starts() {
    let dev = CachedDevice {
        connected: true,
        ..bare()
    };
    assert!(
        !clear_at_scan_start(&dev),
        "defect: scan start removes a connected device, which drops its live connection"
    );
}

#[test]
fn a_trusted_device_is_not_removed_when_scanning_starts() {
    let dev = CachedDevice {
        trusted: true,
        ..bare()
    };
    assert!(
        !clear_at_scan_start(&dev),
        "defect: scan start removes a trusted device, which discards the user's trust setting"
    );
}

#[test]
fn a_blocked_device_is_not_removed_when_scanning_starts() {
    let dev = CachedDevice {
        blocked: true,
        ..bare()
    };
    assert!(
        !clear_at_scan_start(&dev),
        "defect: scan start removes a blocked device, which lifts the user's block"
    );
}

#[test]
fn an_unpaired_untrusted_disconnected_device_is_still_cleared_so_its_next_advert_is_seen() {
    assert!(
        clear_at_scan_start(&bare()),
        "defect: scan start keeps a device object with no user state, so its next advert \
         raises no DeviceAdded and the scanner misses the peer"
    );
}

#[test]
fn a_peer_bluez_reports_as_random_is_dialled_as_random() {
    assert_eq!(
        dial_addr_type(Some(AddressType::LeRandom)),
        AddressType::LeRandom,
        "defect: a peer BlueZ knows by a random address is dialled as public"
    );
}

#[test]
fn a_peer_bluez_has_no_record_of_is_dialled_as_public() {
    assert_eq!(
        dial_addr_type(None),
        AddressType::LePublic,
        "defect: a peer with no BlueZ object is no longer dialled as public"
    );
}

#[test]
fn a_peer_bluez_reports_as_public_is_dialled_as_public() {
    assert_eq!(
        dial_addr_type(Some(AddressType::LePublic)),
        AddressType::LePublic,
        "defect: a peer BlueZ reports as public is not dialled as public"
    );
}
