//! The medium an interface-bound transport's interface runs over, wired or
//! wireless, as the operating system reports it: the fact a link's path
//! machine ranks paths by when their scores are within the switch margin of
//! each other.
//!
//! The classifiers are pure functions of what the operating system reports,
//! so they are tested on any host from captured facts. The reads are thin:
//! on Linux a few files under `/sys/class/net/<interface>`, on macOS the
//! interface's media word (`SIOCGIFMEDIA`). A transport reads its medium when
//! it binds its interface, at start and again after the interface changes,
//! never on the send path. Anything the read cannot settle is
//! [`Medium::Unknown`], which leaves a path's ranking to its score.

use fips_core::proto::path::Medium;

/// The ARPHRD hardware type of an Ethernet-framed interface (`ARPHRD_ETHER`
/// in `<linux/if_arp.h>`), which Wi-Fi interfaces report as well.
#[cfg(any(target_os = "linux", test))]
const ARPHRD_ETHER: u16 = 1;

/// Where Linux lists its network interfaces.
#[cfg(target_os = "linux")]
const SYSFS_NET: &str = "/sys/class/net";

/// The medium of `interface`, read from the operating system. Unknown where
/// the read fails or the facts do not settle it.
pub(crate) fn read(interface: &str) -> Medium {
    if !plain_name(interface) {
        return Medium::Unknown;
    }
    #[cfg(target_os = "linux")]
    {
        from_sysfs(&read_sysfs(std::path::Path::new(SYSFS_NET), interface))
    }
    #[cfg(target_os = "macos")]
    {
        macos::media_word(interface).map_or(Medium::Unknown, from_media_word)
    }
}

/// Whether `interface` can name an interface without leaving the directory
/// that lists it: not empty, no `/`, and neither `.` nor `..`.
fn plain_name(interface: &str) -> bool {
    !interface.is_empty() && !interface.contains('/') && interface != "." && interface != ".."
}

/// What Linux's sysfs says about one network interface, under
/// `/sys/class/net/<interface>`.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sysfs {
    /// `type`: the interface's ARPHRD hardware type, where it was readable.
    pub(crate) arphrd: Option<u16>,
    /// Whether the `wireless` directory is present: the interface answers
    /// the wireless extensions.
    pub(crate) wireless: bool,
    /// Whether the `phy80211` link is present: the interface belongs to an
    /// 802.11 radio.
    pub(crate) phy80211: bool,
    /// `DEVTYPE` from `uevent`, where the kernel gives one: `wlan`,
    /// `bridge`, `vlan`, `wwan` and the like. A plain network card gives
    /// none.
    pub(crate) devtype: Option<String>,
    /// Whether the `device` link is present: the interface is backed by
    /// hardware, where a bridge, a veth, a VLAN or a tunnel is not.
    pub(crate) device: bool,
}

/// The medium sysfs's facts say: wireless for an 802.11 interface, wired for
/// an Ethernet-framed interface backed by hardware that names no device
/// type, and unknown for anything else. A bridge, a VLAN, a veth or a bond
/// stays unknown, since what lies under it may be a radio, and so does an
/// interface that is not there.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn from_sysfs(facts: &Sysfs) -> Medium {
    if facts.wireless || facts.phy80211 || facts.devtype.as_deref() == Some("wlan") {
        Medium::Wireless
    } else if facts.arphrd == Some(ARPHRD_ETHER) && facts.device && facts.devtype.is_none() {
        Medium::Wired
    } else {
        Medium::Unknown
    }
}

/// Read `interface`'s facts from the sysfs network directory `root`,
/// `/sys/class/net` outside tests. A file that cannot be read is a fact not
/// given, so an interface that is not there reads as no facts at all.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn read_sysfs(root: &std::path::Path, interface: &str) -> Sysfs {
    let dir = root.join(interface);
    let arphrd = std::fs::read_to_string(dir.join("type"))
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let devtype = std::fs::read_to_string(dir.join("uevent"))
        .ok()
        .and_then(|uevent| {
            uevent
                .lines()
                .find_map(|line| line.strip_prefix("DEVTYPE="))
                .map(|ty| ty.trim().to_owned())
        });
    Sysfs {
        arphrd,
        wireless: dir.join("wireless").is_dir(),
        phy80211: dir.join("phy80211").exists(),
        devtype,
        device: dir.join("device").exists(),
    }
}

/// The type bits of a media word (`IFM_NMASK` in `<net/if_media.h>`).
#[cfg(any(target_os = "macos", test))]
const IFM_NMASK: i32 = 0xe0;

/// The type of an Ethernet media word (`IFM_ETHER`).
#[cfg(any(target_os = "macos", test))]
const IFM_ETHER: i32 = 0x20;

/// The type of an 802.11 media word (`IFM_IEEE80211`).
#[cfg(any(target_os = "macos", test))]
const IFM_IEEE80211: i32 = 0x80;

/// The medium a BSD media word says: wireless for an 802.11 type, wired for
/// an Ethernet type, and unknown for any other.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn from_media_word(word: i32) -> Medium {
    match word & IFM_NMASK {
        IFM_IEEE80211 => Medium::Wireless,
        IFM_ETHER => Medium::Wired,
        _ => Medium::Unknown,
    }
}

/// The macOS read: the interface's media word.
#[cfg(target_os = "macos")]
mod macos {
    use crate::ipv6tun::bsdnet::{IOC_INOUT, ioc};
    use std::mem::size_of;

    /// `SIOCGIFMEDIA`, `_IOWR('i', 56, struct ifmediareq)`. The number
    /// carries the structure's size, 44 bytes, and the kernel refuses a
    /// request whose size does not match its own structure, so it is built
    /// from the size rather than written out.
    const SIOCGIFMEDIA: libc::c_ulong = ioc(IOC_INOUT, b'i', 56, size_of::<IfMediaReq>());

    /// `struct ifmediareq`, which the `libc` crate does not define for
    /// Apple targets. Apple's `<net/if.h>` declares it under
    /// `#pragma pack(4)`, so the trailing pointer sits at offset 36 rather
    /// than 40 and the structure is 44 bytes, not the 48 natural alignment
    /// gives on a 64-bit target. `packed(4)` keeps that layout and the
    /// header's field types; no field is aligned above 4 except the
    /// pointer, which is never read and never referenced. The kernel fills
    /// fields this read does not use.
    #[repr(C, packed(4))]
    #[allow(dead_code)]
    struct IfMediaReq {
        /// The interface's name, NUL-terminated.
        ifm_name: [libc::c_char; libc::IFNAMSIZ],
        /// The current media word.
        ifm_current: libc::c_int,
        /// The don't-care mask.
        ifm_mask: libc::c_int,
        /// The media status.
        ifm_status: libc::c_int,
        /// The active media word.
        ifm_active: libc::c_int,
        /// How many words `ifm_ulist` holds; zero asks for none.
        ifm_count: libc::c_int,
        /// The supported media words, not asked for.
        ifm_ulist: *mut libc::c_int,
    }

    const _: () = assert!(size_of::<IfMediaReq>() == 44);
    const _: () = assert!(SIOCGIFMEDIA == 0xC02C_6938);

    /// The media word of `interface`: the active word where the driver
    /// gives one, the current word otherwise. `None` where the ioctl fails,
    /// as it does for an interface with no media, such as a bridge or a
    /// tunnel, or one that is not there.
    pub(super) fn media_word(interface: &str) -> Option<i32> {
        let name = interface.as_bytes();
        if name.len() >= libc::IFNAMSIZ {
            return None;
        }
        let mut ifm_name = [0 as libc::c_char; libc::IFNAMSIZ];
        for (dst, src) in ifm_name.iter_mut().zip(name) {
            *dst = *src as libc::c_char;
        }
        // A null list with a count of zero, so the kernel writes no list.
        let mut req = IfMediaReq {
            ifm_name,
            ifm_current: 0,
            ifm_mask: 0,
            ifm_status: 0,
            ifm_active: 0,
            ifm_count: 0,
            ifm_ulist: std::ptr::null_mut(),
        };
        // SAFETY: plain socket creation; the descriptor is closed below.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return None;
        }
        // SAFETY: `req` is a live `ifmediareq` of the size the request
        // number names, which the ioctl fills in place.
        let ret = unsafe { libc::ioctl(sock, SIOCGIFMEDIA, &raw mut req) };
        // SAFETY: `sock` is the descriptor opened above.
        unsafe { libc::close(sock) };
        if ret < 0 {
            return None;
        }
        // Copies out of the packed structure; no reference to a field.
        let (active, current) = (req.ifm_active, req.ifm_current);
        Some(if active != 0 { active } else { current })
    }
}

#[cfg(test)]
#[path = "tests/medium.rs"]
mod tests;
