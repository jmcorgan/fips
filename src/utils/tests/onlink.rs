use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address")
}

/// The interface addresses [`read_system`] considers, with the prefix length
/// the platform reported for each, sorted: loopback and down interfaces
/// skipped, as [`read_system`] skips them.
fn listed_interfaces() -> Vec<(IpAddr, u8)> {
    let mut listed: Vec<(IpAddr, u8)> = if_addrs::get_if_addrs()
        .expect("getifaddrs failed")
        .iter()
        .filter(|iface| !iface.is_loopback())
        .filter(|iface| {
            !matches!(
                iface.oper_status,
                if_addrs::IfOperStatus::Down
                    | if_addrs::IfOperStatus::NotPresent
                    | if_addrs::IfOperStatus::LowerLayerDown
            )
        })
        .map(|iface| match &iface.addr {
            if_addrs::IfAddr::V4(v4) => (IpAddr::V4(v4.ip), v4.prefixlen),
            if_addrs::IfAddr::V6(v6) => (IpAddr::V6(v6.ip), v6.prefixlen),
        })
        .collect();
    listed.sort_unstable();
    listed
}

/// Attempts at a read the host's interfaces held still for. One interface
/// created or removed (a container network, a VPN) spoils at most the
/// attempt it lands in, and its address follows within milliseconds, so
/// ten attempts 50 ms apart ride out several such changes in half a
/// second. A host still changing on every attempt after that cannot be
/// judged, and the test fails saying so.
const SETTLE_ATTEMPTS: u32 = 10;

/// Take a read with `reader` and the interface listing it was read from.
///
/// Other processes create and remove interfaces while the test runs, so
/// the host is listed before and after the read, and the read is returned
/// only with a listing both sides agree on.
fn settled_read(mut reader: impl FnMut() -> OnLinkPrefixes) -> (Vec<(IpAddr, u8)>, OnLinkPrefixes) {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let before = listed_interfaces();
        let read = reader();
        let after = listed_interfaces();
        if before == after {
            return (before, read);
        }
        assert!(
            attempt < SETTLE_ATTEMPTS,
            "the host's interfaces changed during each of {SETTLE_ATTEMPTS} reads; \
             last before {before:?}, after {after:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Check a system read against the interface list it was read from.
///
/// Every listed prefix with a nonzero length is decodable: its address,
/// and the first and last address of its range, must be held. A listed
/// length of 0 is a netmask the platform handed back undecodable (a macOS
/// VPN `utun` interface does this); it must be dropped, and the read's
/// discard count must match the number listed. The address checks cover
/// IPv4 only.
fn check_read(listed: &[(IpAddr, u8)], read: &OnLinkPrefixes) -> Result<(), String> {
    if read.contains(ip("127.0.0.1")) {
        return Err("the read holds loopback".into());
    }
    let undecodable = listed.iter().filter(|(_, len)| *len == 0).count();
    if read.discarded() != undecodable {
        return Err(format!(
            "{} discarded, {undecodable} listed with prefix length 0: {listed:?}",
            read.discarded()
        ));
    }
    for (addr, len) in listed {
        let (IpAddr::V4(v4), 1..) = (addr, len) else {
            continue;
        };
        let mask = u32::MAX.checked_shl(32 - u32::from(*len)).unwrap_or(0);
        let first = std::net::Ipv4Addr::from(u32::from(*v4) & mask);
        let last = std::net::Ipv4Addr::from(u32::from(*v4) | !mask);
        for held in [*v4, first, last] {
            if !read.contains(IpAddr::V4(held)) {
                return Err(format!("{held} of {v4}/{len} missing from the read"));
            }
        }
    }
    Ok(())
}

#[test]
fn the_read_check_accepts_undecodable_utun_prefixes_as_counted_discards() {
    // What a Mac with two VPNs up lists: Wi-Fi reads /24, and both utun
    // interfaces read /0 from a netmask the reader could not decode.
    let listed = [
        (ip("192.168.1.10"), 24),
        (ip("10.8.0.2"), 0),
        (ip("10.9.0.2"), 0),
        (ip("fe80::1"), 64),
    ];
    let read = OnLinkPrefixes::from_pairs(listed);
    assert_eq!(read.discarded(), 2);
    assert_eq!(check_read(&listed, &read), Ok(()));
}

#[test]
fn the_read_check_fails_a_read_that_lost_a_decodable_prefix() {
    let listed = [
        (ip("192.168.1.10"), 24),
        (ip("10.8.0.2"), 0),
        (ip("172.16.4.2"), 22),
    ];
    let lost = OnLinkPrefixes::from_pairs([listed[0], listed[1]]);
    assert!(check_read(&listed, &lost).is_err());
    let zeroed = OnLinkPrefixes::from_pairs([listed[0], listed[1], (ip("172.16.4.2"), 0)]);
    assert!(check_read(&listed, &zeroed).is_err());
    let narrowed = OnLinkPrefixes::from_pairs([listed[0], listed[1], (ip("172.16.4.2"), 24)]);
    assert!(check_read(&listed, &narrowed).is_err());
    let whole = OnLinkPrefixes::from_pairs(listed);
    assert_eq!(check_read(&listed, &whole), Ok(()));
}

#[test]
fn the_system_read_holds_every_decodable_up_non_loopback_ipv4_interface_prefix() {
    let (listed, read) = settled_read(read_system);
    if let Err(problem) = check_read(&listed, &read) {
        panic!("{problem}");
    }
}
