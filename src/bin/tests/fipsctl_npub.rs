//! fipsctl takes a peer's npub in any letter case, as the daemon does: an
//! argument or public key file holding an upper- or mixed-case npub is read
//! as that npub, not as a host name or a secret key.

use super::*;

/// `text` with every other letter upper-cased.
fn alternating_case(text: &str) -> String {
    text.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

#[test]
fn an_npub_argument_in_any_case_is_taken_as_an_npub_not_a_host_name() {
    let npub = Identity::generate().npub();
    for spelling in [
        npub.clone(),
        npub.to_ascii_uppercase(),
        alternating_case(&npub),
    ] {
        assert_eq!(resolve_peer(&spelling), spelling);
    }
}

#[test]
fn the_address_of_an_npub_in_any_case_is_its_owners() {
    let identity = Identity::generate();
    let npub = identity.npub();
    let expected = identity.address().to_ipv6();
    for spelling in [
        npub.clone(),
        npub.to_ascii_uppercase(),
        alternating_case(&npub),
    ] {
        assert_eq!(
            mesh_address(Some(&spelling), None),
            Ok(expected),
            "{spelling}"
        );
    }
}

#[test]
fn a_public_key_file_holding_an_npub_in_any_case_gives_its_owners_address() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let npub = identity.npub();
    let path = dir.path().join("fips.pub");
    for spelling in [
        npub.clone(),
        npub.to_ascii_uppercase(),
        alternating_case(&npub),
    ] {
        std::fs::write(&path, format!("{spelling}\n")).unwrap();
        assert_eq!(
            address_from_file(&path),
            Ok(identity.address().to_ipv6()),
            "a public key file holding {spelling}"
        );
    }
}
