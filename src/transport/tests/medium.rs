//! The medium classifiers and the Linux read, from facts captured on real
//! interfaces and from sysfs trees laid out as the kernel lays them out.

use super::*;
use std::fs;
use std::path::Path;

/// The facts of an interface: ARPHRD type, `wireless`, `phy80211`, the
/// `uevent` device type and `device`.
fn facts(
    arphrd: u16,
    wireless: bool,
    phy80211: bool,
    devtype: Option<&str>,
    device: bool,
) -> Sysfs {
    Sysfs {
        arphrd: Some(arphrd),
        wireless,
        phy80211,
        devtype: devtype.map(str::to_owned),
        device,
    }
}

/// The interfaces of a Linux VM host (core-vm, 2026-11-12), read from its
/// `/sys/class/net`: a virtio network card, two bridges, a veth, the
/// loopback interface, a TUN device and a WireGuard-style tunnel.
fn captured_vm() -> Vec<(&'static str, Sysfs)> {
    vec![
        ("enp6s18", facts(1, false, false, None, true)),
        ("docker0", facts(1, false, false, Some("bridge"), false)),
        (
            "br-78c603be1313",
            facts(1, false, false, Some("bridge"), false),
        ),
        ("vethbfb54ca", facts(1, false, false, None, false)),
        ("lo", facts(772, false, false, None, false)),
        ("fipsh0", facts(65534, false, false, None, false)),
        ("tailscale0", facts(65534, false, false, None, false)),
    ]
}

/// A Wi-Fi interface as cfg80211 lays it out: Ethernet-framed, backed by
/// hardware, with the `phy80211` link, the `wireless` directory where the
/// kernel keeps the wireless extensions, and `DEVTYPE=wlan`.
fn wifi() -> Sysfs {
    facts(1, true, true, Some("wlan"), true)
}

#[test]
fn a_network_card_backed_by_hardware_is_wired() {
    assert_eq!(from_sysfs(&captured_vm()[0].1), Medium::Wired);
}

#[test]
fn a_wifi_interface_is_wireless_by_any_one_of_its_three_marks() {
    assert_eq!(from_sysfs(&wifi()), Medium::Wireless);
    // Without the wireless extensions there is no `wireless` directory.
    assert_eq!(
        from_sysfs(&facts(1, false, true, Some("wlan"), true)),
        Medium::Wireless
    );
    assert_eq!(
        from_sysfs(&facts(1, false, true, None, true)),
        Medium::Wireless
    );
    assert_eq!(
        from_sysfs(&facts(1, false, false, Some("wlan"), true)),
        Medium::Wireless
    );
    assert_eq!(
        from_sysfs(&facts(1, true, false, None, true)),
        Medium::Wireless
    );
}

#[test]
fn bridges_veths_tunnels_and_the_loopback_interface_are_unknown() {
    for (name, facts) in captured_vm().into_iter().skip(1) {
        assert_eq!(from_sysfs(&facts), Medium::Unknown, "{name}");
    }
}

#[test]
fn a_hardware_interface_that_names_a_device_type_other_than_wlan_is_unknown() {
    for devtype in ["wwan", "vlan", "bond", "dsa", "gadget"] {
        assert_eq!(
            from_sysfs(&facts(1, false, false, Some(devtype), true)),
            Medium::Unknown,
            "{devtype}"
        );
    }
}

#[test]
fn an_interface_that_is_not_there_is_unknown() {
    assert_eq!(from_sysfs(&Sysfs::default()), Medium::Unknown);
}

/// Lay `facts` out under `root/name` as sysfs does: `type`, a `uevent`
/// with `DEVTYPE` among its lines where there is one, a `wireless`
/// directory, and `phy80211` and `device` as links to directories.
fn lay_out(root: &Path, name: &str, facts: &Sysfs) {
    let dir = root.join(name);
    fs::create_dir_all(&dir).unwrap();
    if let Some(arphrd) = facts.arphrd {
        fs::write(dir.join("type"), format!("{arphrd}\n")).unwrap();
    }
    let mut uevent = format!("INTERFACE={name}\nIFINDEX=3\n");
    if let Some(devtype) = &facts.devtype {
        uevent = format!("DEVTYPE={devtype}\n{uevent}");
    }
    fs::write(dir.join("uevent"), uevent).unwrap();
    if facts.wireless {
        fs::create_dir(dir.join("wireless")).unwrap();
    }
    let targets = root.join(".targets").join(name);
    for (link, present) in [("phy80211", facts.phy80211), ("device", facts.device)] {
        if present {
            let target = targets.join(link);
            fs::create_dir_all(&target).unwrap();
            std::os::unix::fs::symlink(&target, dir.join(link)).unwrap();
        }
    }
}

#[test]
fn the_sysfs_read_gives_back_the_facts_a_tree_lays_out() {
    let root = tempfile::tempdir().unwrap();
    let mut every = captured_vm();
    every.push(("wlp2s0", wifi()));
    for (name, facts) in &every {
        lay_out(root.path(), name, facts);
    }
    for (name, facts) in &every {
        assert_eq!(&read_sysfs(root.path(), name), facts, "{name}");
    }
    assert_eq!(
        from_sysfs(&read_sysfs(root.path(), "wlp2s0")),
        Medium::Wireless
    );
    assert_eq!(
        from_sysfs(&read_sysfs(root.path(), "enp6s18")),
        Medium::Wired
    );
}

#[test]
fn the_sysfs_read_of_an_interface_that_is_not_there_gives_no_facts() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(read_sysfs(root.path(), "eth9"), Sysfs::default());
}

#[test]
fn a_dangling_device_link_is_no_device() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("eth0");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("type"), "1\n").unwrap();
    std::os::unix::fs::symlink(root.path().join("gone"), dir.join("device")).unwrap();
    assert!(!read_sysfs(root.path(), "eth0").device);
    assert_eq!(
        from_sysfs(&read_sysfs(root.path(), "eth0")),
        Medium::Unknown
    );
}

#[test]
fn a_name_that_leaves_the_interface_directory_is_unknown_without_a_read() {
    for name in ["", ".", "..", "../lo", "lo/..", "/"] {
        assert!(!plain_name(name), "{name:?}");
        assert_eq!(read(name), Medium::Unknown, "{name:?}");
    }
    assert!(plain_name("en0"));
    assert!(plain_name("wlp2s0"));
}

/// The loopback interface every Linux host has reads as unknown through
/// the real `/sys/class/net`.
#[cfg(target_os = "linux")]
#[test]
fn the_loopback_interface_of_this_host_reads_as_unknown() {
    assert_eq!(read("lo"), Medium::Unknown);
    assert_eq!(read("fips-no-such-interface"), Medium::Unknown);
}

/// Media words built from `<net/if_media.h>`, not captured on a Mac: an
/// 802.11 interface on autoselect, a gigabit copper port at full duplex,
/// and a word of no type, as an interface with no media gives.
#[test]
fn a_media_word_is_classified_by_its_type_bits() {
    const IFM_AUTO: i32 = 0;
    const IFM_1000_T: i32 = 16;
    const IFM_100_TX: i32 = 6;
    const IFM_FDX: i32 = 0x0010_0000;
    assert_eq!(from_media_word(IFM_IEEE80211 | IFM_AUTO), Medium::Wireless);
    assert_eq!(
        from_media_word(IFM_ETHER | IFM_1000_T | IFM_FDX),
        Medium::Wired
    );
    assert_eq!(from_media_word(IFM_ETHER | IFM_100_TX), Medium::Wired);
    assert_eq!(from_media_word(0), Medium::Unknown);
    // Token ring (0x40) and FDDI (0x60) are neither.
    assert_eq!(from_media_word(0x40), Medium::Unknown);
    assert_eq!(from_media_word(0x60), Medium::Unknown);
}
