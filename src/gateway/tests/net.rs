//! Tests of how the gateway reads the proxy NDP sysctls.

use super::*;

/// A sysctl tree under a temporary directory with `all/proxy_ndp` set to
/// `all` and `<lan>/proxy_ndp` to `lan`; `None` leaves the file out.
fn conf_tree(all: Option<&str>, lan: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, value) in [("all", all), ("br-lan", lan)] {
        std::fs::create_dir_all(dir.path().join(name)).unwrap();
        if let Some(value) = value {
            std::fs::write(
                dir.path().join(name).join("proxy_ndp"),
                format!("{value}\n"),
            )
            .unwrap();
        }
    }
    dir
}

/// Proxy NDP counts as on when either the `all` or the LAN interface's own
/// sysctl is set, off when both read zero, and unknown when neither reads.
#[test]
fn proxy_ndp_is_on_when_all_or_the_lan_interface_sets_it() {
    let cases = [
        (Some("0"), Some("0"), Some(false)),
        (Some("1"), Some("0"), Some(true)),
        (Some("0"), Some("1"), Some(true)),
        (None, Some("1"), Some(true)),
        (Some("0"), None, Some(false)),
        (None, None, None),
    ];
    for (all, lan, expected) in cases {
        let tree = conf_tree(all, lan);
        assert_eq!(
            proxy_on(tree.path(), "br-lan"),
            expected,
            "all {all:?}, br-lan {lan:?}"
        );
    }
}
