//! Tests of the macOS and FreeBSD host configuration calls in `../bsdnet.rs`.
//!
//! The unprivileged tests run in every test run on those platforms: the
//! routing message layout, and the kernel's own error codes surfacing for
//! calls it refuses. The tests that change the host's routes or create a
//! TUN device need root; they are `#[ignore]`d and run as root by the
//! FreeBSD package workflow and by a `sudo` step of the macOS unit-test job.

use super::*;

/// A documentation prefix (RFC 3849) the privileged tests route, so nothing
/// they add can carry real traffic.
const TEST_PREFIX: (Ipv6Addr, u8) = (Ipv6Addr::new(0x2001, 0xdb8, 0xf1b5, 0, 0, 0, 0, 0), 48);

/// An interface name no host has.
const ABSENT_IF: &str = "fipsnone0";

#[test]
fn prefix_masks_cover_the_named_number_of_leading_bits() {
    assert_eq!(prefix_mask(0), Ipv6Addr::UNSPECIFIED);
    assert_eq!(prefix_mask(8), "ff00::".parse::<Ipv6Addr>().unwrap());
    assert_eq!(
        prefix_mask(48),
        "ffff:ffff:ffff::".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(prefix_mask(128), Ipv6Addr::from(u128::MAX));
}

#[test]
fn socket_addresses_in_a_routing_message_are_padded_to_the_platform_alignment() {
    #[cfg(target_os = "macos")]
    let (in6, empty) = (28, 4);
    #[cfg(target_os = "freebsd")]
    let (in6, empty) = (32, size_of::<libc::c_long>());
    assert_eq!(sa_space(size_of::<libc::sockaddr_in6>()), in6);
    assert_eq!(sa_space(0), empty);
    assert_eq!(sa_space(1), SA_ALIGN);
}

#[test]
fn a_route_add_message_carries_destination_gateway_and_mask_in_that_order() {
    let msg = route_message(libc::RTM_ADD, 7, TEST_PREFIX.0, TEST_PREFIX.1, Some(3)).unwrap();
    let hdr: RtMsghdr = unsafe { std::ptr::read_unaligned(msg.as_ptr().cast()) };
    assert_eq!(usize::from(hdr.rtm_msglen), msg.len());
    assert_eq!(hdr.rtm_version, 5);
    assert_eq!(c_int::from(hdr.rtm_type), libc::RTM_ADD);
    assert_eq!(hdr.rtm_seq, 7);
    assert_eq!(hdr.rtm_flags, libc::RTF_UP | libc::RTF_STATIC);
    assert_eq!(
        hdr.rtm_addrs,
        libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK
    );

    let in6 = sa_space(size_of::<libc::sockaddr_in6>());
    let dl = sa_space(size_of::<libc::sockaddr_dl>());
    assert_eq!(msg.len(), size_of::<RtMsghdr>() + in6 + dl + in6);

    let mut at = size_of::<RtMsghdr>();
    let dst: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(msg[at..].as_ptr().cast()) };
    assert_eq!(c_int::from(dst.sin6_family), libc::AF_INET6);
    assert_eq!(dst.sin6_addr.s6_addr, TEST_PREFIX.0.octets());
    at += in6;
    let gw: libc::sockaddr_dl = unsafe { std::ptr::read_unaligned(msg[at..].as_ptr().cast()) };
    assert_eq!(c_int::from(gw.sdl_family), libc::AF_LINK);
    assert_eq!(gw.sdl_index, 3);
    at += dl;
    let mask: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(msg[at..].as_ptr().cast()) };
    assert_eq!(mask.sin6_addr.s6_addr, prefix_mask(TEST_PREFIX.1).octets());
}

#[test]
fn a_route_get_message_has_no_gateway() {
    let msg = route_message(libc::RTM_GET, 1, TEST_PREFIX.0, TEST_PREFIX.1, None).unwrap();
    let hdr: RtMsghdr = unsafe { std::ptr::read_unaligned(msg.as_ptr().cast()) };
    assert_eq!(hdr.rtm_addrs, libc::RTA_DST | libc::RTA_NETMASK);
    assert_eq!(
        msg.len(),
        size_of::<RtMsghdr>() + 2 * sa_space(size_of::<libc::sockaddr_in6>())
    );
}

#[test]
fn an_unknown_sysctl_name_fails_with_enoent() {
    let err = sysctl_int("fips.no.such.name").unwrap_err();
    eprintln!("unknown sysctl: {err}");
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "{err}");
}

#[test]
fn a_known_integer_sysctl_is_read() {
    assert!(sysctl_int("kern.maxproc").unwrap() > 0);
}

#[test]
fn an_unknown_interface_has_no_index_and_the_kernel_error_is_kept() {
    let err = interface_index(ABSENT_IF).unwrap_err();
    eprintln!("unknown interface index: {err}");
    assert_eq!(err.raw_os_error(), Some(libc::ENXIO), "{err}");
}

#[test]
fn bringing_up_an_unknown_interface_fails_with_the_kernel_error() {
    let err = set_up(ABSENT_IF, true).unwrap_err();
    eprintln!("unknown interface up: {err}");
    assert_eq!(err.raw_os_error(), Some(libc::ENXIO), "{err}");
}

#[test]
fn an_address_add_on_an_unknown_interface_fails_with_the_kernel_error() {
    let err = add_address(ABSENT_IF, TEST_PREFIX.0, 128).unwrap_err();
    eprintln!("address on unknown interface: {err}");
    assert!(err.raw_os_error().is_some(), "{err}");
}

#[test]
fn an_overlong_interface_name_is_refused_before_any_call() {
    let err = set_up("fips-name-longer-than-ifnamsiz", true).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

/// A route the kernel refuses for a reason other than "already present"
/// comes back as that refusal: without root the routing socket refuses the
/// add itself, and with root no interface has this index.
#[test]
fn a_route_add_the_kernel_refuses_returns_its_error_code() {
    let err = ensure_route(TEST_PREFIX.0, TEST_PREFIX.1, 65000).unwrap_err();
    eprintln!("refused route add: {err}");
    let code = err.raw_os_error();
    assert!(code.is_some() && code != Some(libc::EEXIST), "{err}");
    // What the TUN setup reports carries the platform's message and code.
    assert!(err.to_string().contains("os error"), "{err}");
}

/// The index of the loopback interface, `lo0` on both platforms.
fn loopback_index() -> u32 {
    interface_index("lo0").expect("lo0 has an index")
}

/// The name and index of an interface other than the loopback.
///
/// Chosen by interface index: `if_addrs` marks an entry loopback by its
/// address, and `lo0` also carries `fe80::1`, which is not a loopback
/// address.
fn other_interface() -> (String, u32) {
    let lo = loopback_index();
    if_addrs::get_if_addrs()
        .expect("interfaces")
        .into_iter()
        .find_map(|i| match interface_index(&i.name) {
            Ok(index) if index != lo => Some((i.name, index)),
            _ => None,
        })
        .expect("an interface other than lo0")
}

/// `SIOCGIFMTU`: read an interface's MTU.
const SIOCGIFMTU: c_ulong = ioc(IOC_INOUT, b'i', 51, size_of::<libc::ifreq>());

const _: () = assert!(SIOCGIFMTU == 0xc020_6933);

/// An `ifreq` naming interface `name`, filled by `request` on an IPv6
/// socket.
fn ifreq_get(name: &str, request: c_ulong) -> libc::ifreq {
    // SAFETY: `ifreq` is plain data; all-zero is a valid value.
    let mut req: libc::ifreq = unsafe { zeroed() };
    req.ifr_name = ifname(name).unwrap();
    let sock = inet6_socket().unwrap();
    // SAFETY: `req` is the `ifreq` the interface requests here encode.
    unsafe { ioctl(&sock, request, &mut req) }.unwrap_or_else(|e| panic!("{name}: {e}"));
    req
}

/// The flags of interface `name` as one word. FreeBSD splits them into a
/// low and a high short; both are kept, so a write that corrupted the high
/// one shows.
fn interface_flags(name: &str) -> c_int {
    flags_word(&ifreq_get(name, SIOCGIFFLAGS))
}

/// The flags SIOCGIFFLAGS put in `req`, low short and high short joined.
#[cfg(target_os = "freebsd")]
fn flags_word(req: &libc::ifreq) -> c_int {
    // SAFETY: SIOCGIFFLAGS filled the flags member of the union.
    let [low, high] = unsafe { req.ifr_ifru.ifru_flags };
    c_int::from(low as u16) | (c_int::from(high) << 16)
}

/// The flags SIOCGIFFLAGS put in `req`.
#[cfg(target_os = "macos")]
fn flags_word(req: &libc::ifreq) -> c_int {
    // SAFETY: SIOCGIFFLAGS filled the flags member of the union.
    c_int::from(unsafe { req.ifr_ifru.ifru_flags })
}

/// The MTU of interface `name`, as the kernel holds it.
fn interface_mtu(name: &str) -> c_int {
    let req = ifreq_get(name, SIOCGIFMTU);
    // SAFETY: SIOCGIFMTU filled the MTU member of the union.
    unsafe { req.ifr_ifru.ifru_mtu }
}

/// Removes the test prefix's route when dropped, so a failed assertion does
/// not leave it behind.
struct RouteGuard;

impl Drop for RouteGuard {
    fn drop(&mut self) {
        let _ = delete_route(TEST_PREFIX.0, TEST_PREFIX.1);
    }
}

#[test]
#[ignore = "needs root: adds and deletes a route"]
fn a_route_added_twice_through_the_same_interface_is_accepted() {
    let (dst, len) = TEST_PREFIX;
    let _ = delete_route(dst, len);
    let _guard = RouteGuard;
    let lo = loopback_index();

    assert_eq!(add_route(dst, len, lo).unwrap(), RouteAdd::Added);
    // The condition the old code matched in route(8)'s text: the kernel's
    // answer to the second add is EEXIST.
    assert_eq!(add_route(dst, len, lo).unwrap(), RouteAdd::Exists);
    ensure_route(dst, len, lo).unwrap();
    assert_eq!(route_interface(dst, len).unwrap(), Some(lo));

    assert!(delete_route(dst, len).unwrap());
    assert!(!delete_route(dst, len).unwrap());
    assert_eq!(route_interface(dst, len).unwrap(), None);
}

#[test]
#[ignore = "needs root: adds and deletes a route"]
fn a_route_present_through_another_interface_is_refused_and_left_in_place() {
    let (dst, len) = TEST_PREFIX;
    let _ = delete_route(dst, len);
    let _guard = RouteGuard;
    let (name, other) = other_interface();

    assert_eq!(
        add_route(dst, len, other).unwrap(),
        RouteAdd::Added,
        "via {name}"
    );
    let err = ensure_route(dst, len, loopback_index()).unwrap_err();
    eprintln!("route through another interface: {err}");
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
    // The refusal names the other interface, not only its index.
    assert!(
        err.to_string()
            .contains(&format!("interface {name} (index {other})")),
        "{err}"
    );
    assert_eq!(route_interface(dst, len).unwrap(), Some(other));
}

#[test]
#[ignore = "needs root: creates a TUN device and routes fd00::/8 through it"]
fn a_tun_device_created_twice_in_turn_comes_up_configured_both_times() {
    use crate::ipv6tun::tun::TunDevice;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let config = crate::TunConfig {
        enabled: true,
        name: None,
        mtu: None,
    };
    let mesh: Ipv6Addr = "fd00::".parse().unwrap();
    for round in 0..2 {
        // Whether a route from the previous round is still in place, so the
        // log shows which path this round's setup took.
        eprintln!(
            "round {round}: fd00::/8 before create goes through index {:?}",
            route_interface(mesh, 8).unwrap()
        );
        let address = *crate::Identity::generate().address();
        let device = runtime
            .block_on(TunDevice::create(&config, address))
            .unwrap_or_else(|e| panic!("create, round {round}: {e}"));
        let index = interface_index(device.name()).unwrap();
        eprintln!("round {round}: device {} index {index}", device.name());
        assert_eq!(
            route_interface(mesh, 8).unwrap(),
            Some(index),
            "round {round}"
        );
        let has_address = if_addrs::get_if_addrs()
            .unwrap()
            .iter()
            .any(|i| i.name == device.name() && i.ip() == std::net::IpAddr::V6(address.to_ipv6()));
        assert!(
            has_address,
            "round {round}: {} lacks {address}",
            device.name()
        );
        // The tun crate sets the MTU at create; the setup no longer does.
        // The default differs from the driver's 1500, so a create that left
        // the MTU alone fails here.
        assert_eq!(
            interface_mtu(device.name()),
            c_int::from(device.mtu()),
            "round {round}"
        );

        let up = libc::IFF_UP;
        // IFF_RUNNING belongs to the driver, which may change it when the
        // interface goes down; every other flag is the setup's to keep.
        let kept = !(up | libc::IFF_RUNNING);
        let upflags = interface_flags(device.name());
        assert_ne!(upflags & up, 0, "round {round}: not up, {upflags:#x}");
        runtime.block_on(device.shutdown()).unwrap();
        let downflags = interface_flags(device.name());
        eprintln!("round {round}: flags {upflags:#x} up, {downflags:#x} after shutdown");
        assert_eq!(downflags & up, 0, "round {round}: still up");
        assert_eq!(downflags & kept, upflags & kept, "round {round}");
        // Whatever else raised the flag at create, this is set_up alone
        // bringing the interface back up.
        set_up(device.name(), true).unwrap();
        let again = interface_flags(device.name());
        assert_ne!(again & up, 0, "round {round}: set_up did not raise IFF_UP");
        assert_eq!(again & kept, upflags & kept, "round {round}");
        runtime.block_on(device.shutdown()).unwrap();
        drop(device);
    }
    // Remove the mesh route if the closed device left it behind.
    let _ = delete_route(mesh, 8);
}

/// The production path for an address and route already present: setting
/// up a configured device a second time finds the kernel answering `EEXIST`
/// to the route add, and succeeds with the route through the device.
#[test]
#[ignore = "needs root: creates a TUN device and routes fd00::/8 through it"]
fn configuring_a_configured_tun_device_again_accepts_its_own_address_and_route() {
    use crate::ipv6tun::tun::{TunDevice, platform};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let config = crate::TunConfig {
        enabled: true,
        name: None,
        mtu: None,
    };
    let mesh: Ipv6Addr = "fd00::".parse().unwrap();
    let address = *crate::Identity::generate().address();
    let device = runtime
        .block_on(TunDevice::create(&config, address))
        .expect("create");
    let index = interface_index(device.name()).unwrap();
    // The condition the second setup meets: the kernel refuses a second add.
    assert_eq!(add_route(mesh, 8, index).unwrap(), RouteAdd::Exists);
    runtime
        .block_on(platform::configure_interface(
            device.name(),
            address.to_ipv6(),
            device.mtu(),
        ))
        .unwrap_or_else(|e| panic!("second setup of {}: {e}", device.name()));
    assert_eq!(route_interface(mesh, 8).unwrap(), Some(index));
    runtime.block_on(device.shutdown()).unwrap();
    drop(device);
    let _ = delete_route(mesh, 8);
}
