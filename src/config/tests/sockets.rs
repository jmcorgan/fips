//! Where the IPv6 adapter's status socket is, derived from the control
//! socket's path, for the daemon and for a client.

use super::*;

#[cfg(unix)]
#[test]
fn the_adapter_socket_is_a_sibling_of_the_control_socket_with_ipv6tun_before_its_extension() {
    let cases = [
        ("/run/fips/control.sock", "/run/fips/control-ipv6tun.sock"),
        (
            "/var/run/fips/control.sock",
            "/var/run/fips/control-ipv6tun.sock",
        ),
        (
            "/run/user/1000/fips/control.sock",
            "/run/user/1000/fips/control-ipv6tun.sock",
        ),
        ("/tmp/fips-control.sock", "/tmp/fips-control-ipv6tun.sock"),
        ("a/node.ctl", "a/node-ipv6tun.ctl"),
        ("a/node", "a/node-ipv6tun"),
        ("a/a.b.c", "a/a.b-ipv6tun.c"),
    ];
    for (control, adapter) in cases {
        assert_eq!(
            ipv6tun_socket(Path::new(control)),
            Some(PathBuf::from(adapter)),
            "control socket {control}"
        );
    }
}

#[cfg(unix)]
#[test]
fn two_control_sockets_in_one_directory_give_two_adapter_sockets() {
    let layouts: [&[&str]; 2] = [
        &["/run/lab/control.sock", "/run/lab/node.sock"],
        &["/run/lab/node.sock", "/run/lab/node.ctl", "/run/lab/node"],
    ];
    for controls in layouts {
        let adapters: Vec<PathBuf> = controls
            .iter()
            .map(|control| ipv6tun_socket(Path::new(control)).unwrap())
            .collect();
        for (i, adapter) in adapters.iter().enumerate() {
            for other in &adapters[i + 1..] {
                assert_ne!(adapter, other, "control sockets {controls:?}");
            }
            for control in controls {
                assert_ne!(adapter, Path::new(control), "control sockets {controls:?}");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn a_control_path_with_no_file_name_gives_no_adapter_socket() {
    assert_eq!(ipv6tun_socket(Path::new("/")), None);
    assert_eq!(ipv6tun_socket(Path::new("..")), None);
    assert_eq!(ipv6tun_socket(Path::new("")), None);
}

#[cfg(unix)]
#[test]
fn the_default_control_socket_gives_the_default_adapter_socket_beside_it() {
    let control = default_control_path();
    let adapter = ipv6tun_socket(&control).unwrap();
    assert_eq!(adapter.parent(), control.parent());
    assert_ne!(adapter, control);
}

#[cfg(unix)]
#[test]
fn a_client_given_a_symlink_to_the_control_socket_finds_the_adapter_beside_the_real_socket() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("control.sock"), b"").unwrap();
    let link = dir.path().join("link.sock");
    std::os::unix::fs::symlink(real.join("control.sock"), &link).unwrap();
    let expected = std::fs::canonicalize(&real)
        .unwrap()
        .join("control-ipv6tun.sock");
    assert_eq!(ipv6tun_client(&link), Some(expected));
}

#[cfg(unix)]
#[test]
fn a_client_given_a_path_that_does_not_exist_derives_from_it_as_given() {
    let dir = tempfile::tempdir().unwrap();
    let control = dir.path().join("missing").join("control.sock");
    assert_eq!(
        ipv6tun_client(&control),
        Some(dir.path().join("missing").join("control-ipv6tun.sock"))
    );
}

#[cfg(windows)]
#[test]
fn the_adapter_port_is_the_control_port_plus_two() {
    let cases = [
        ("21210", Some("21212")),
        ("30000", Some("30002")),
        ("not-a-port", Some("21212")),
        ("0", Some("0")),
        ("65534", None),
    ];
    for (control, adapter) in cases {
        assert_eq!(
            ipv6tun_socket(Path::new(control)),
            adapter.map(PathBuf::from),
            "control port {control}"
        );
    }
}
