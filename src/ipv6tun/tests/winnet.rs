//! Tests of the Windows IP Helper calls in `../winnet.rs`.
//!
//! The tests that need no privilege check that a call IP Helper refuses
//! comes back with its Win32 code, and that a stop finding no adapter
//! succeeds. The ones that add and remove rows need
//! Administrator; they are `#[ignore]`d and run by a step of the Windows
//! unit-test job, whose runner is elevated. Most work on the loopback
//! interface and a documentation prefix (RFC 3849), so nothing they add
//! carries real traffic. One creates the Wintun adapter itself through
//! `TunDevice::create`, and needs `wintun.dll` on the DLL search path; the
//! job downloads a hash-pinned copy for it.

use super::*;
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;

/// A documentation prefix the privileged tests route and address.
const TEST_PREFIX: (Ipv6Addr, u8) = (Ipv6Addr::new(0x2001, 0xdb8, 0xf1b5, 0, 0, 0, 0, 0), 48);

/// A LUID no interface has: interface type 6 (Ethernet) with the largest
/// net LUID index (bits 24..48).
const ABSENT_LUID: u64 = (6u64 << 48) | (0x00ff_ffffu64 << 24);

/// The LUID of the IPv6 loopback interface.
fn loopback_luid() -> u64 {
    let index = if_addrs::get_if_addrs()
        .expect("interfaces")
        .into_iter()
        .find(|i| i.is_loopback() && i.ip().is_ipv6())
        .and_then(|i| i.index)
        .expect("an IPv6 loopback interface with an index");
    let mut out = luid(0);
    // SAFETY: `out` is a valid LUID to fill.
    check(unsafe { ConvertInterfaceIndexToLuid(index, &mut out) }).expect("loopback LUID");
    // SAFETY: every bit pattern of the union is a valid u64.
    unsafe { out.Value }
}

/// No test that runs before this one leaves a `FIPS` adapter: the unit-test
/// run creates none, and in the Administrator step, which runs one test at a
/// time in name order, this one comes before the adapter test.
#[test]
fn a_stop_with_no_fips_adapter_present_is_not_an_error() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    if let Ok(luid) = alias_luid(ADAPTER) {
        panic!("an adapter named {ADAPTER} is present ({luid:#x}); the test needs none");
    }
    runtime
        .block_on(crate::ipv6tun::tun::shutdown_tun_interface("tun"))
        .unwrap();
}

#[test]
fn an_unknown_adapter_alias_has_no_luid_and_the_code_is_kept() {
    let err = alias_luid("fips-no-such-adapter").unwrap_err();
    eprintln!("unknown alias: {err}");
    assert!(err.raw_os_error().is_some(), "{err}");
}

#[test]
fn an_interface_that_does_not_exist_has_no_ipv6_row() {
    assert!(!ipv6_present(ABSENT_LUID).unwrap());
}

#[test]
fn a_route_on_an_interface_that_does_not_exist_fails_with_its_code() {
    let err = add_route(ABSENT_LUID, TEST_PREFIX.0, TEST_PREFIX.1).unwrap_err();
    eprintln!("route on absent interface: {err}");
    let code = err.raw_os_error();
    assert!(
        code.is_some() && code != Some(ERROR_OBJECT_ALREADY_EXISTS as i32),
        "{err}"
    );
    // What the TUN setup reports carries the system's message and code.
    assert!(err.to_string().contains("os error"), "{err}");
}

#[test]
fn an_address_on_an_interface_that_does_not_exist_fails_with_its_code() {
    let err = add_address(ABSENT_LUID, TEST_PREFIX.0, 128).unwrap_err();
    eprintln!("address on absent interface: {err}");
    assert!(err.raw_os_error().is_some(), "{err}");
}

#[test]
fn the_mtu_of_an_interface_that_does_not_exist_cannot_be_set() {
    let err = set_mtu(ABSENT_LUID, 1280).unwrap_err();
    eprintln!("MTU of absent interface: {err}");
    assert!(missing(&err), "{err}");
}

#[test]
#[ignore = "needs Administrator: adds and deletes a route"]
fn a_route_added_twice_on_one_interface_is_accepted() {
    let lo = loopback_luid();
    let (dst, len) = TEST_PREFIX;
    let _ = delete_route(lo, dst, len);
    assert_eq!(add_route(lo, dst, len).unwrap(), Created::Added);
    assert_eq!(add_route(lo, dst, len).unwrap(), Created::Exists);
    assert!(delete_route(lo, dst, len).unwrap());
    assert!(!delete_route(lo, dst, len).unwrap());
}

#[test]
#[ignore = "needs Administrator: adds and deletes an address"]
fn an_address_added_twice_on_one_interface_is_accepted() {
    let lo = loopback_luid();
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0xf1b5, 0, 0, 0, 0, 1);
    let _ = delete_address(lo, addr);
    assert_eq!(add_address(lo, addr, 128).unwrap(), Created::Added);
    assert_eq!(add_address(lo, addr, 128).unwrap(), Created::Exists);
    assert!(delete_address(lo, addr).unwrap());
}

/// Puts an interface's IPv6 MTU back when dropped, so a failed assertion
/// does not leave the runner's loopback changed.
struct MtuGuard {
    /// The interface.
    luid: u64,
    /// Its MTU before the test.
    mtu: u32,
}

impl Drop for MtuGuard {
    /// Restores the MTU. A refused restore cannot fail the test from here,
    /// so it is printed with its code: a runner left at the test's MTU then
    /// shows in the log.
    fn drop(&mut self) {
        if let Err(e) = set_mtu(self.luid, self.mtu) {
            eprintln!(
                "restoring loopback IPv6 MTU {} failed, code {:?}: {e}",
                self.mtu,
                e.raw_os_error()
            );
        }
    }
}

#[test]
#[ignore = "needs Administrator: writes an interface's IPv6 settings"]
fn an_interface_mtu_written_through_its_ipv6_row_reads_back_changed() {
    let lo = loopback_luid();
    assert!(ipv6_present(lo).unwrap());
    let before = mtu(lo).unwrap();
    let _guard = MtuGuard {
        luid: lo,
        mtu: before,
    };
    // A value other than the current one, so a write that changed nothing
    // cannot pass.
    let target = if before == 1400 { 1280 } else { 1400 };
    eprintln!("loopback IPv6 MTU {before}, writing {target}");
    set_mtu(lo, target).unwrap();
    assert_eq!(mtu(lo).unwrap(), target);
}

/// The name `TunDevice::create` gives the Wintun adapter.
const ADAPTER: &str = "FIPS";

#[test]
#[ignore = "needs Administrator and wintun.dll: creates the Wintun adapter"]
fn a_wintun_adapter_created_twice_in_turn_comes_up_configured_both_times() {
    use crate::ipv6tun::tun::TunDevice;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    // Not the default MTU, so the read-back shows this setup wrote it.
    let config = crate::TunConfig {
        enabled: true,
        name: None,
        mtu: Some(1400),
    };
    let mesh: Ipv6Addr = "fd00::".parse().unwrap();
    for round in 0..2 {
        let address = *crate::Identity::generate().address();
        let device = runtime
            .block_on(TunDevice::create(&config, address))
            .unwrap_or_else(|e| panic!("create, round {round}: {e}"));
        let luid = alias_luid(ADAPTER).expect("adapter LUID");
        eprintln!("round {round}: adapter LUID {luid:#x}");
        assert_eq!(mtu(luid).unwrap(), 1400, "round {round}");
        // Both are present: IP Helper answers a second add with
        // ERROR_OBJECT_ALREADY_EXISTS.
        assert_eq!(
            add_address(luid, address.to_ipv6(), 128).unwrap(),
            Created::Exists,
            "round {round}"
        );
        assert_eq!(
            add_route(luid, mesh, 8).unwrap(),
            Created::Exists,
            "round {round}"
        );
        runtime.block_on(device.shutdown()).unwrap();
        assert!(!delete_route(luid, mesh, 8).unwrap(), "round {round}");
        drop(device);
    }
}
