//! Tests for the default Unix socket path a root and a non-root process take.

use super::{VarRunPolicy, resolve_for};
use std::path::Path;

/// The Linux policy: `/var/run/fips` is not consulted.
const LINUX: VarRunPolicy = VarRunPolicy {
    consult_existing: false,
    create_private_dir: false,
};

/// The FreeBSD policy: an existing `/var/run/fips` is consulted.
const FREEBSD: VarRunPolicy = VarRunPolicy {
    consult_existing: true,
    create_private_dir: false,
};

/// A valid XDG runtime directory, the only directory that exists.
const XDG: &str = "/run/user/1000";

fn only_xdg(candidate: &Path) -> bool {
    candidate == Path::new(XDG)
}

#[test]
fn a_root_process_never_resolves_a_socket_under_tmp_or_xdg() {
    assert_eq!(
        resolve_for(0, "control.sock", LINUX, Some(Path::new(XDG)), only_xdg),
        "/run/fips/control.sock"
    );
    assert_eq!(
        resolve_for(0, "gateway.sock", LINUX, None, |_| false),
        "/run/fips/gateway.sock"
    );
    assert_eq!(
        resolve_for(0, "control.sock", FREEBSD, Some(Path::new(XDG)), only_xdg),
        "/var/run/fips/control.sock"
    );
    assert_eq!(
        resolve_for(0, "api.sock", FREEBSD, None, |_| false),
        "/var/run/fips/api.sock"
    );
}

#[test]
fn a_root_process_takes_an_existing_run_fips_on_every_policy() {
    let run_fips = |candidate: &Path| candidate == Path::new("/run/fips");
    assert_eq!(
        resolve_for(0, "control.sock", FREEBSD, None, run_fips),
        "/run/fips/control.sock"
    );
    assert_eq!(
        resolve_for(0, "control.sock", LINUX, None, run_fips),
        "/run/fips/control.sock"
    );
}

#[test]
fn a_non_root_process_keeps_the_xdg_and_tmp_fallbacks() {
    assert_eq!(
        resolve_for(1000, "control.sock", LINUX, Some(Path::new(XDG)), only_xdg),
        "/run/user/1000/fips/control.sock"
    );
    assert_eq!(
        resolve_for(1000, "control.sock", LINUX, None, |_| false),
        "/tmp/fips-control.sock"
    );
    assert_eq!(
        resolve_for(1000, "control.sock", FREEBSD, None, |_| false),
        "/tmp/fips-control.sock"
    );
}
