//! The IPv6-minimum MTU warning on the path where the node opens its own TUN.
//!
//! `start()` logs "Transport MTU too small for the IPv6 minimum" when the
//! system TUN comes up over transports that cannot carry a 1280-byte IPv6
//! packet. The unit tests cover the shortfall arithmetic and the app-owned
//! TUN path; this covers the system TUN path every packaged daemon takes.
//!
//! Creating a TUN needs root, so the test runs in a network namespace of its
//! own and is ignored by default, like the namespace tests in
//! `src/upper/tests/tun.rs`. The GitHub Linux unit-test job runs it under
//! `sudo` with `--ignored`; run the lib test binary the same way by hand.
//! Linux only.

use super::*;

/// The interface name the test configures inside its namespace.
const NAME: &str = "fipsw0";

/// A root network namespace of its own, deleted on drop. Needs root.
struct Netns(String);

impl Netns {
    /// Create a uniquely named namespace with its loopback up.
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("fipswarn-{}-{seq}", std::process::id());
        crate::testutil::run_ok("ip", &["netns", "add", &name]);
        crate::testutil::run_ok("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self(name)
    }
}

impl Drop for Netns {
    /// Delete the namespace, ignoring a failure so a panicking test still unwinds.
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.0])
            .output();
    }
}

/// Start a node with a system TUN over one loopback UDP transport of `mtu`
/// inside a fresh namespace, and return how many shortfall warnings it
/// logged and whether it recorded the TUN's name.
fn shortfall_warnings(mtu: Option<u16>) -> (usize, Option<String>) {
    let netns = Netns::new();
    crate::testutil::in_netns(&netns.0, move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("node runtime");
        runtime.block_on(async move {
            let mut config = Config::new();
            config.transports.udp =
                crate::config::TransportInstances::Single(crate::config::UdpConfig {
                    bind_addr: Some("127.0.0.1:0".to_string()),
                    mtu,
                    ..Default::default()
                });
            config.dns.enabled = false;
            config.tun.enabled = true;
            config.tun.name = Some(NAME.to_string());
            let mut node = make_node_with(config);

            let (logs, guard) = crate::testutil::capture_logs_scoped();
            node.start().await.unwrap();
            let tun = node.tun_name().map(str::to_string);
            node.stop().await.unwrap();
            drop(guard);

            let hits = logs
                .warnings()
                .iter()
                .filter(|line| line.contains("too small for the IPv6 minimum"))
                .count();
            (hits, tun)
        })
    })
}

/// A node that opens its own TUN over a 1280-byte UDP transport warns once
/// that it cannot carry a 1280-byte IPv6 packet, and at the default UDP MTU
/// it does not warn.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn start_with_a_system_tun_warns_once_when_the_udp_mtu_is_too_small_for_a_1280_byte_ipv6_packet_and_not_at_the_default()
 {
    for (mtu, expected) in [(Some(1280), 1), (None, 0)] {
        let (hits, tun) = shortfall_warnings(mtu);
        assert_eq!(
            tun.as_deref(),
            Some(NAME),
            "udp mtu {mtu:?}: no TUN name recorded, so the system TUN path was not taken"
        );
        assert_eq!(hits, expected, "udp mtu {mtu:?}: shortfall warnings logged");
    }
}
