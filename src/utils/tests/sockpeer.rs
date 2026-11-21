//! Tests for the control socket peer check: the trust rule, and reading a
//! connected peer's uid.

use super::{check_server, check_stream, peer_ids, trusted};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

/// The client's own effective uid in the trust table.
const EUID: libc::uid_t = 1000;

/// The `fips` account's uid in the trust table.
const FIPS_UID: libc::uid_t = 990;

#[test]
fn root_the_clients_own_account_and_the_fips_account_are_trusted() {
    assert!(trusted(0, EUID, || Some(FIPS_UID)));
    assert!(trusted(EUID, EUID, || Some(FIPS_UID)));
    assert!(trusted(FIPS_UID, EUID, || Some(FIPS_UID)));
    assert!(trusted(0, 0, || None), "root trusts a root server");
    assert!(
        trusted(0, EUID, || None),
        "root is trusted with no fips account"
    );
}

#[test]
fn any_other_account_is_refused_whatever_its_groups() {
    // A member of group fips runs under its own uid; the rule sees only that.
    assert!(!trusted(1001, EUID, || Some(FIPS_UID)));
    assert!(!trusted(65534, EUID, || Some(FIPS_UID)));
    assert!(
        !trusted(1001, 0, || Some(FIPS_UID)),
        "a root client refuses another account"
    );
    assert!(
        !trusted(FIPS_UID, EUID, || None),
        "no fips account, no fips trust"
    );
    assert!(!trusted(1001, EUID, || None));
}

#[test]
fn root_and_the_clients_own_account_are_trusted_without_looking_up_the_fips_account() {
    let no_lookup = || -> Option<libc::uid_t> { panic!("the fips account was looked up") };

    assert!(trusted(0, EUID, no_lookup));
    assert!(trusted(EUID, EUID, no_lookup));
}

#[test]
fn a_refused_server_is_named_by_path_and_uid() {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    // A uid that is neither root nor ours; the fips account on this host, if
    // any, is skipped over.
    let fips = super::super::sockbind::fips_user_id();
    let other = (1..u32::MAX)
        .map(|n| euid.wrapping_add(n))
        .find(|&uid| uid != 0 && Some(uid) != fips)
        .unwrap();

    let error = check_server(Path::new("/tmp/fips-control.sock"), other).unwrap_err();

    assert!(error.contains("/tmp/fips-control.sock"), "{error}");
    assert!(error.contains(&format!("uid {other}")), "{error}");
    assert!(check_server(Path::new("/tmp/x.sock"), euid).is_ok());
    assert!(check_server(Path::new("/tmp/x.sock"), 0).is_ok());
}

#[test]
fn peer_ids_on_a_listener_of_our_own_report_our_uid_and_gid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    let client = UnixStream::connect(&path).unwrap();

    let (uid, gid) = peer_ids(client.as_fd()).unwrap();

    // SAFETY: geteuid and getegid have no preconditions.
    assert_eq!(uid, unsafe { libc::geteuid() });
    assert_eq!(gid, unsafe { libc::getegid() });
    assert!(check_stream(&path, &client).is_ok());
}
