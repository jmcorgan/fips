//! Tests that TUN startup never deletes, downs or takes over an interface
//! that already has the configured `tun.name`, other than reopening an
//! unheld persistent TUN of that name; and that the `fd00::/8` policy rule
//! startup adds is removed at stop, replaces an older rule rather than
//! sitting beside it, and is harmless when an exit without stop leaves it.
//!
//! The namespace tests need root, so no CI job runs them: they are run by
//! hand under `sudo` with `--ignored`, and that run is the only coverage of
//! the Linux outcomes. macOS and FreeBSD are not run at all; there the
//! kernel names the device, and after the fix no code touches an interface
//! by `tun.name` before create. The module is Linux only.
//!
//! One test of the reader's TCP MSS clamp also lives here, because only
//! `tun.rs`'s child modules reach the reader's packet handler. It needs no
//! root, so the Linux lib suite runs it.

use super::*;

/// The interface name the namespace tests configure.
const NAME: &str = "fipst0";

/// The priority of the `fd00::/8` policy rule startup adds.
const RULE_PRIORITY: &str = "5265";

/// A root network namespace of its own, deleted on drop. Needs root.
struct TunNetns(String);

impl TunNetns {
    fn new() -> Self {
        // Tests run in parallel in one process, so each gets its own name.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("fipstun-{}-{seq}", std::process::id());
        crate::testutil::run_ok("ip", &["netns", "add", &name]);
        crate::testutil::run_ok("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self(name)
    }

    /// Run `TunDevice::create` for `tun.name: fipst0` with a fresh identity.
    fn create(&self) -> Result<TunDevice, TunError> {
        self.create_as(*crate::Identity::generate().address())
    }

    /// Run `TunDevice::create` for `tun.name: fipst0` and `address` inside
    /// the namespace, on a current-thread runtime of its own: create spawns
    /// its netlink connection, and the device is made in the calling
    /// thread's namespace.
    fn create_as(&self, address: crate::Ipv6Address) -> Result<TunDevice, TunError> {
        crate::testutil::in_netns(&self.0, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tun runtime");
            let config = TunConfig {
                enabled: true,
                name: Some(NAME.to_string()),
                mtu: None,
            };
            runtime.block_on(TunDevice::create(&config, address))
        })
    }

    /// The index and link kind of `fipst0`, or `None` when it does not exist.
    fn link(&self) -> Option<(u64, String)> {
        let out = std::process::Command::new("ip")
            .args(["-n", &self.0, "-j", "-d", "link", "show", NAME])
            .output()
            .unwrap();
        if !out.status.success() {
            return None;
        }
        let links: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let link = &links[0];
        let kind = link["linkinfo"]["info_kind"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Some((link["ifindex"].as_u64().unwrap(), kind))
    }

    /// The `fd00::/8` addresses on `fipst0`, as `addr/prefixlen`, sorted.
    fn mesh_addresses(&self) -> Vec<String> {
        let out = std::process::Command::new("ip")
            .args(["-n", &self.0, "-j", "-6", "addr", "show", "dev", NAME])
            .output()
            .unwrap();
        assert!(out.status.success(), "ip addr show {NAME} failed");
        let links: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let mut found: Vec<String> = links[0]["addr_info"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| {
                let local = a["local"].as_str()?;
                local
                    .starts_with("fd")
                    .then(|| format!("{local}/{}", a["prefixlen"]))
            })
            .collect();
        found.sort();
        found
    }

    /// The `fd00::/8` routes through `fipst0`, as `ip -6 route` prints them.
    fn mesh_routes(&self) -> Vec<String> {
        let out = std::process::Command::new("ip")
            .args([
                "-n", &self.0, "-6", "route", "show", "fd00::/8", "dev", NAME,
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "ip -6 route show failed");
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Run `ip -n <ns> <args>`, failing the test when it fails.
    fn ip(&self, args: &[&str]) {
        let mut full = vec!["-n", self.0.as_str()];
        full.extend_from_slice(args);
        crate::testutil::run_ok("ip", &full);
    }

    /// Stop the TUN as the daemon's stop does, through
    /// `shutdown_tun_interface`, inside the namespace.
    fn stop(&self) -> Result<(), TunError> {
        crate::testutil::in_netns(&self.0, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tun runtime");
            runtime.block_on(shutdown_tun_interface(NAME))
        })
    }

    /// Shut `device` down through `TunDevice::shutdown` inside the
    /// namespace, then drop it.
    fn shutdown(&self, device: TunDevice) -> Result<(), TunError> {
        crate::testutil::in_netns(&self.0, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tun runtime");
            let result = runtime.block_on(device.shutdown());
            drop(device);
            result
        })
    }

    /// The IPv6 policy rules at the mesh rule's priority, as `ip -6 rule`
    /// prints them.
    fn mesh_rules(&self) -> Vec<String> {
        let out = std::process::Command::new("ip")
            .args(["-n", &self.0, "-6", "rule", "show", "pref", RULE_PRIORITY])
            .output()
            .unwrap();
        assert!(out.status.success(), "ip -6 rule show failed");
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The device `ip -6 route get <dst>` sends `dst` out of.
    fn route_dev(&self, dst: &str) -> String {
        let out = std::process::Command::new("ip")
            .args(["-n", &self.0, "-j", "-6", "route", "get", dst])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ip -6 route get {dst} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let routes: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        routes[0]["dev"].as_str().unwrap_or("").to_string()
    }

    /// A persistent `fipst0` that a node configured as `old` and then left
    /// without stopping, as a crash or `kill -9` leaves it: the TUN stays,
    /// and so do the node's address and its `fd00::/8` route.
    fn leftover_persistent_tun(&self, old: crate::Ipv6Address) -> (u64, String) {
        crate::testutil::run_ok("ip", &["-n", &self.0, "tuntap", "add", NAME, "mode", "tun"]);
        let before = self.link().expect("the persistent TUN exists");
        drop(
            self.create_as(old)
                .expect("the first node configures the TUN"),
        );
        assert_eq!(
            self.mesh_addresses(),
            vec![format!("{}/128", old.to_ipv6())],
            "the unclean exit leaves the old address on the TUN"
        );
        assert_eq!(
            self.mesh_routes().len(),
            1,
            "the unclean exit leaves the fd00::/8 route on the TUN"
        );
        before
    }

    /// Restart on a TUN `leftover_persistent_tun` left, as `new`: the TUN is
    /// reopened with the same index and carries exactly `new`'s address and
    /// one `fd00::/8` route.
    fn assert_restart_reconfigures(&self, before: (u64, String), new: crate::Ipv6Address) {
        let device = match self.create_as(new) {
            Ok(device) => device,
            Err(e) => panic!("restart after an unclean exit left no TUN: {e}"),
        };
        assert_eq!(device.name(), NAME);
        assert_eq!(self.link(), Some(before), "the TUN was replaced");
        assert_eq!(
            self.mesh_addresses(),
            vec![format!("{}/128", new.to_ipv6())],
            "the TUN carries exactly the new node's mesh address"
        );
        assert_eq!(
            self.mesh_routes().len(),
            1,
            "the TUN carries one fd00::/8 route: {:?}",
            self.mesh_routes()
        );
    }
}

impl Drop for TunNetns {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.0])
            .status();
    }
}

/// A dummy link that has the configured TUN name is refused, and is left as
/// it was: same index, still a dummy.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn startup_refuses_and_keeps_a_dummy_link_that_has_the_configured_tun_name() {
    let ns = TunNetns::new();
    crate::testutil::run_ok("ip", &["-n", &ns.0, "link", "add", NAME, "type", "dummy"]);
    let before = ns.link().expect("the dummy exists");
    assert_eq!(before.1, "dummy");

    let created = ns.create();
    let after = ns.link();
    let Err(err) = created else {
        panic!("create took over an existing dummy link");
    };
    assert!(
        err.to_string().contains(NAME),
        "the error names the interface: {err}"
    );
    assert_eq!(after, Some(before), "the dummy link was changed or deleted");
}

/// A second create on a TUN name another device holds fails, and leaves the
/// first device in place.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn a_second_create_on_a_held_tun_name_fails_and_leaves_the_first_device_in_place() {
    let ns = TunNetns::new();
    let first = ns.create().expect("the first create succeeds");
    let before = ns.link().expect("the first device exists");
    assert_eq!(before.1, "tun");

    let second = ns.create();
    let after = ns.link();
    drop(first);
    let Err(err) = second else {
        panic!("a second create on a held TUN name succeeded");
    };
    assert!(
        err.to_string().contains("held by another process"),
        "the error says the TUN is held: {err}"
    );
    assert_eq!(
        after,
        Some(before),
        "the first device was deleted or replaced"
    );
}

/// A persistent TUN of the configured name that no process holds is
/// reopened, keeping its index, rather than deleted and recreated.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn startup_reopens_an_unheld_persistent_tun_with_the_configured_name() {
    let ns = TunNetns::new();
    crate::testutil::run_ok("ip", &["-n", &ns.0, "tuntap", "add", NAME, "mode", "tun"]);
    let before = ns.link().expect("the persistent TUN exists");
    assert_eq!(before.1, "tun");

    let device = ns.create().expect("an unheld persistent TUN is reopened");
    assert_eq!(device.name(), NAME);
    assert_eq!(
        ns.link(),
        Some(before),
        "the persistent TUN was deleted and recreated"
    );
}

/// A node restarted with the same identity on a persistent TUN its previous
/// run left configured (killed or crashed, so stop never ran) reopens it and
/// configures it again, rather than failing on its own leftover address.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn restart_with_the_same_identity_reconfigures_a_persistent_tun_left_by_an_unclean_exit() {
    let ns = TunNetns::new();
    let address = *crate::Identity::generate().address();
    let before = ns.leftover_persistent_tun(address);
    ns.assert_restart_reconfigures(before, address);
}

/// A node restarted with a new identity on a persistent TUN a previous run
/// left configured reopens it, drops the previous run's mesh address, and
/// does not fail on the previous run's `fd00::/8` route. A mesh address and
/// an `fd00::/8` route on another interface are left alone.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn restart_with_a_new_identity_reconfigures_a_persistent_tun_left_by_an_unclean_exit() {
    let ns = TunNetns::new();
    let n = ns.0.as_str();
    let other = |args: &[&str]| {
        let mut full = vec!["-n", n];
        full.extend_from_slice(args);
        crate::testutil::run_ok("ip", &full);
    };
    other(&["link", "add", "fipsother0", "type", "dummy"]);
    other(&["link", "set", "fipsother0", "up"]);
    other(&[
        "-6",
        "addr",
        "add",
        "fd99::1/128",
        "dev",
        "fipsother0",
        "nodad",
    ]);
    other(&[
        "-6",
        "route",
        "add",
        "fd00::/8",
        "dev",
        "fipsother0",
        "metric",
        "2000",
    ]);
    let others = || {
        let out = |args: &[&str]| {
            let o = std::process::Command::new("ip")
                .args(["-n", n])
                .args(args)
                .output()
                .unwrap();
            String::from_utf8(o.stdout).unwrap()
        };
        (
            out(&["-6", "addr", "show", "dev", "fipsother0", "scope", "global"]),
            out(&["-6", "route", "show", "fd00::/8", "dev", "fipsother0"]),
        )
    };
    let untouched = others();
    assert!(untouched.0.contains("fd99::1/128") && untouched.1.contains("metric 2000"));

    let before = ns.leftover_persistent_tun(*crate::Identity::generate().address());
    ns.assert_restart_reconfigures(before, *crate::Identity::generate().address());
    assert_eq!(
        others(),
        untouched,
        "another interface's mesh address or fd00::/8 route was changed"
    );
}

/// Only a TUN may be reused; every other link kind, and a link with no kind
/// (a physical interface), is refused with an error naming the interface and
/// its kind. Runs without root.
#[test]
fn existing_link_verdict_refuses_every_kind_but_tun() {
    use rtnetlink::packet_route::link::InfoKind;
    assert!(platform::existing_link_verdict(NAME, Some(&InfoKind::Tun)).is_ok());
    let refused = [
        (None, "no link kind"),
        (Some(InfoKind::Dummy), "dummy"),
        (Some(InfoKind::Bridge), "bridge"),
        (Some(InfoKind::Veth), "veth"),
        (Some(InfoKind::Wireguard), "wireguard"),
        (Some(InfoKind::Other("tailscale".to_string())), "tailscale"),
    ];
    for (kind, named) in refused {
        let err = platform::existing_link_verdict(NAME, kind.as_ref())
            .expect_err("a link that is not a TUN is refused")
            .to_string();
        assert!(
            err.contains(NAME) && err.contains(named),
            "{kind:?}: the error names {NAME} and {named}: {err}"
        );
    }
}

/// Stopping the node, as the daemon's stop does, removes the `fd00::/8`
/// policy rule startup added, so it does not outlive the TUN.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn stopping_the_tun_removes_the_fd00_rule_it_added() {
    let ns = TunNetns::new();
    let device = ns.create().expect("the TUN is created");
    let rules = ns.mesh_rules();
    assert!(
        rules.len() == 1 && rules[0].contains("to fd00::/8 lookup main"),
        "precondition: startup adds one fd00::/8 rule: {rules:?}"
    );

    ns.stop().expect("stop succeeds");
    drop(device);
    assert_eq!(
        ns.mesh_rules(),
        Vec::<String>::new(),
        "the fd00::/8 rule outlived the stopped TUN"
    );
}

/// `TunDevice::shutdown`, the other public way to tear the TUN down, removes
/// the rule too.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn a_tun_device_shutdown_removes_the_fd00_rule() {
    let ns = TunNetns::new();
    let device = ns.create().expect("the TUN is created");
    assert_eq!(
        ns.mesh_rules().len(),
        1,
        "precondition: startup adds one fd00::/8 rule"
    );

    ns.shutdown(device).expect("shutdown succeeds");
    assert_eq!(
        ns.mesh_rules(),
        Vec::<String>::new(),
        "the fd00::/8 rule outlived the shut-down TUN"
    );
}

/// A node that exits without stopping (killed or crashed) leaves its rule
/// behind. While it ran, every `fd00::/8` destination went to the TUN; once
/// the TUN is gone, a ULA network another routing table owns (here one laid
/// out like Tailscale's, table 52 at priority 5270) must be routed through
/// that table, not out the main table's default route.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn a_rule_left_by_an_exit_without_stop_sends_other_ula_traffic_to_its_own_table() {
    let ns = TunNetns::new();
    ns.ip(&["link", "add", "lan0", "type", "dummy"]);
    ns.ip(&["link", "set", "lan0", "up"]);
    ns.ip(&["-6", "route", "add", "default", "dev", "lan0"]);
    ns.ip(&["link", "add", "ts0", "type", "dummy"]);
    ns.ip(&["link", "set", "ts0", "up"]);
    ns.ip(&[
        "-6",
        "route",
        "add",
        "fd7a:115c:a1e0::/48",
        "dev",
        "ts0",
        "table",
        "52",
    ]);
    ns.ip(&["-6", "rule", "add", "pref", "5270", "lookup", "52"]);

    let device = ns.create().expect("the TUN is created");
    assert_eq!(
        ns.route_dev("fd7a:115c:a1e0::1"),
        NAME,
        "while the node runs, fd00::/8 goes to the TUN"
    );
    assert_eq!(
        ns.route_dev("fd12::1"),
        NAME,
        "while the node runs, fd00::/8 goes to the TUN"
    );

    // A non-persistent TUN goes when its descriptor closes, as at a crash.
    drop(device);
    assert_eq!(ns.link(), None, "precondition: the TUN is gone");
    assert_eq!(
        ns.mesh_rules().len(),
        1,
        "precondition: the exit left the rule behind"
    );
    assert_eq!(
        ns.route_dev("fd7a:115c:a1e0::1"),
        "ts0",
        "the leftover rule sends another table's ULA traffic out the default route"
    );
}

/// A host that ran an older version has its `fd00::/8` rule, without
/// `suppress_prefixlength`. Startup replaces it, leaving one rule, rather
/// than adding the new one beside it.
#[test]
#[ignore = "needs root: creates network namespaces"]
fn startup_replaces_an_older_rule_rather_than_adding_beside_it() {
    let ns = TunNetns::new();
    ns.ip(&[
        "-6",
        "rule",
        "add",
        "to",
        "fd00::/8",
        "lookup",
        "main",
        "pref",
        RULE_PRIORITY,
    ]);
    let _device = ns.create().expect("the TUN is created");
    let rules = ns.mesh_rules();
    assert!(
        rules.len() == 1 && rules[0].contains("suppress_prefixlength 0"),
        "one fd00::/8 rule, of the new shape: {rules:?}"
    );
}

/// A host path whose map knows `peer`, with its replica and the node's end of
/// its datagram channel.
fn reader_host(
    peer: crate::ipv6tun::link::PeerKey,
) -> (
    HostPath,
    PathMtuReplica,
    tokio::sync::mpsc::Receiver<crate::ipv6tun::link::Datagram>,
) {
    let state = crate::ipv6tun::core::MeshState::new();
    state.apply(crate::ipv6tun::link::FromMesh::KnownKey { peer });
    let (datagrams, rx) = tokio::sync::mpsc::channel(4);
    let limiter = Arc::new(std::sync::Mutex::new(
        crate::ipv6tun::icmp_rate_limit::IcmpRateLimiter::new(),
    ));
    let host = HostPath {
        state,
        limiter,
        datagrams,
    };
    (host, PathMtuReplica::default(), rx)
}

/// The reader clamps a SYN from the host by the stored path to its
/// destination, in the packet itself, before handing it to the mesh.
#[test]
fn the_reader_clamps_a_syn_by_the_path_to_its_destination() {
    let key = crate::ipv6tun::link::any_key();
    let peer = key.address();
    let ours = *crate::Identity::generate().address();
    let (host, paths, _datagrams) = reader_host(key);
    paths
        .write()
        .unwrap()
        .insert(peer, crate::node::path_mtu::payload_limit(1000));
    let (tun_tx, _tun_rx) = TunTx::bounded(4);

    // A SYN from us to the peer: a 40-byte IPv6 header carrying TCP, then a
    // 24-byte TCP header with data offset 6 and one MSS option of 1440.
    let mut packet = vec![0u8; 64];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(ours.as_bytes());
    packet[24..40].copy_from_slice(peer.as_bytes());
    packet[52] = 6 << 4;
    packet[53] = 0x02;
    packet[60..64].copy_from_slice(&[2, 4, 0x05, 0xa0]);

    assert!(handle_tun_packet(
        &mut packet,
        1360,
        "test0",
        ours,
        &tun_tx,
        &host,
        &paths
    ));
    assert_eq!(u16::from_be_bytes([packet[62], packet[63]]), 863);
}
