use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address")
}

/// The host's up, non-loopback IPv4 addresses and prefix lengths, sorted,
/// filtered as [`read_system`] filters them.
fn up_v4() -> Vec<(std::net::Ipv4Addr, u8)> {
    let interfaces = if_addrs::get_if_addrs().expect("getifaddrs failed");
    let mut up_v4: Vec<(std::net::Ipv4Addr, u8)> = interfaces
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
        .filter_map(|iface| match &iface.addr {
            if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.prefixlen)),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();
    up_v4.sort_unstable();
    up_v4
}

/// Attempts at a read the host's interfaces held still for. One interface
/// created or removed (a container network, a VPN) spoils at most the
/// attempt it lands in, and its address follows within milliseconds, so
/// ten attempts 50 ms apart ride out several such changes in half a
/// second. A host still changing on every attempt after that cannot be
/// judged, and the test fails saying so.
const SETTLE_ATTEMPTS: u32 = 10;

/// Check that what `reader` returns holds every up non-loopback IPv4
/// address of the host.
///
/// Other processes create and remove interfaces while the test runs, so
/// the host is listed before and after the read, and the read is judged
/// only against a listing both sides agree on.
fn check_read(mut reader: impl FnMut() -> OnLinkPrefixes) {
    let mut attempt = 0;
    let (up_v4, read) = loop {
        attempt += 1;
        let before = up_v4();
        let read = reader();
        let after = up_v4();
        if before == after {
            break (before, read);
        }
        assert!(
            attempt < SETTLE_ATTEMPTS,
            "the host's interfaces changed during each of {SETTLE_ATTEMPTS} reads; \
             last before {before:?}, after {after:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(!read.contains(ip("127.0.0.1")));
    if up_v4.is_empty() {
        // A loopback-only host has nothing to compare.
        return;
    }
    assert!(
        up_v4.iter().all(|(_, len)| *len > 0),
        "an interface reported prefix length 0: {up_v4:?}"
    );
    assert!(!read.is_empty());
    assert_eq!(read.discarded(), 0);
    for (addr, _) in &up_v4 {
        assert!(
            read.contains(IpAddr::V4(*addr)),
            "{addr} missing from the read"
        );
    }
}

#[test]
fn the_system_read_holds_every_up_non_loopback_ipv4_interface_prefix() {
    check_read(read_system);
}
