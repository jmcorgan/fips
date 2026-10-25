//! Tests for `node.native_api.grants`: its file form, the grants in force
//! with the IPv6 adapter's built-in one, and the rules `Config::validate`
//! holds an entry to.

use super::*;

/// A configuration with the TUN set as `tun` and `grants` as the list.
fn with_grants(tun: bool, grants: Vec<GrantConfig>) -> Config {
    let mut config = Config::default();
    config.tun.enabled = tun;
    config.node.native_api.grants = grants;
    config
}

/// An entry for user `uid` naming `ports` and nothing else.
fn uid_ports(uid: u32, ports: &[u16]) -> GrantConfig {
    GrantConfig {
        uid: Some(uid),
        ports: ports.to_vec(),
        ..Default::default()
    }
}

/// The IPv6 adapter's grant among `grants`.
fn adapter(grants: &[Grant]) -> &Grant {
    grants
        .iter()
        .find(|g| g.principal == Principal::Adapter)
        .expect("the adapter's grant is always in force")
}

#[test]
fn the_default_writes_no_grants_key_and_reads_back_equal() {
    let native = NativeApiConfig::default();
    let yaml = serde_yaml::to_string(&native).unwrap();
    assert!(!yaml.contains("grants"), "got: {yaml}");
    let back: NativeApiConfig = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(back, native);
}

#[test]
fn a_grant_reads_from_the_documented_shape() {
    let config: Config = serde_yaml::from_str(
        "node:\n  native_api:\n    grants:\n      - uid: 990\n        ports: [257]\n        \
         keys: false\n        learn: true\n      - gid: 991\n        keys: true\n",
    )
    .unwrap();
    assert_eq!(
        config.node.native_api.grants,
        vec![
            GrantConfig {
                uid: Some(990),
                ports: vec![257],
                learn: true,
                ..Default::default()
            },
            GrantConfig {
                gid: Some(991),
                keys: true,
                ..Default::default()
            },
        ]
    );
    config.validate().expect("both entries are valid");
}

#[test]
fn a_list_naming_only_port_257_leaves_the_adapter_its_port_256_feed_and_learn() {
    let config = with_grants(true, vec![uid_ports(990, &[257])]);
    config.validate().expect("port 257 is grantable");
    let grants = config.node.native_api.effective_grants();
    assert_eq!(
        adapter(&grants),
        &Grant {
            principal: Principal::Adapter,
            ports: vec![256],
            keys: true,
            learn: true,
        }
    );
    assert!(grants.contains(&Grant {
        principal: Principal::Uid(990),
        ports: vec![257],
        keys: false,
        learn: false,
    }));
}

#[test]
fn with_no_grants_the_adapter_alone_holds_port_256() {
    let grants = NativeApiConfig::default().effective_grants();
    assert_eq!(
        grants,
        vec![Grant {
            principal: Principal::Adapter,
            ports: vec![256],
            keys: true,
            learn: true,
        }]
    );
}

#[test]
fn port_256_granted_to_a_user_is_refused_while_the_tun_is_enabled() {
    let err = with_grants(true, vec![uid_ports(0, &[256])])
        .validate()
        .expect_err("the adapter holds 256 while the TUN is enabled");
    let msg = err.to_string();
    assert!(msg.contains("node.native_api.grants[0]"), "got: {msg}");
    assert!(msg.contains("tun.enabled"), "got: {msg}");
}

#[test]
fn port_256_granted_to_a_user_with_the_tun_disabled_takes_the_port_and_leaves_the_adapter_keys_and_learn()
 {
    let config = with_grants(false, vec![uid_ports(0, &[256])]);
    config
        .validate()
        .expect("with the TUN disabled 256 is grantable");
    let grants = config.node.native_api.effective_grants();
    assert_eq!(
        adapter(&grants),
        &Grant {
            principal: Principal::Adapter,
            ports: vec![],
            keys: true,
            learn: true,
        }
    );
}

#[test]
fn a_port_below_256_is_refused() {
    let msg = with_grants(false, vec![uid_ports(990, &[255])])
        .validate()
        .expect_err("255 is refused to everyone")
        .to_string();
    assert!(msg.contains("grants[0] grants port 255"), "got: {msg}");
}

#[test]
fn a_port_from_1024_is_refused() {
    let msg = with_grants(false, vec![uid_ports(990, &[1024])])
        .validate()
        .expect_err("1024 needs no grant")
        .to_string();
    assert!(msg.contains("grants[0] grants port 1024"), "got: {msg}");
}

#[test]
fn port_1023_is_grantable() {
    with_grants(false, vec![uid_ports(990, &[1023])])
        .validate()
        .expect("1023 is the top of the privileged range");
}

#[test]
fn a_port_in_two_entries_is_refused_naming_both() {
    let msg = with_grants(false, vec![uid_ports(990, &[300]), uid_ports(991, &[300])])
        .validate()
        .expect_err("a port has one grantee")
        .to_string();
    assert!(msg.contains("grants[1] grants port 300"), "got: {msg}");
    assert!(msg.contains("grants[0]"), "got: {msg}");
}

#[test]
fn a_port_twice_in_one_entry_is_refused() {
    let msg = with_grants(false, vec![uid_ports(990, &[300, 300])])
        .validate()
        .expect_err("a port is granted once")
        .to_string();
    assert!(msg.contains("grants[0] grants port 300"), "got: {msg}");
}

#[test]
fn an_entry_naming_both_a_uid_and_a_gid_is_refused() {
    let both = GrantConfig {
        gid: Some(991),
        ..uid_ports(990, &[300])
    };
    let msg = with_grants(false, vec![both])
        .validate()
        .expect_err("one principal per entry")
        .to_string();
    assert!(
        msg.contains("grants[0] must name exactly one"),
        "got: {msg}"
    );
}

#[test]
fn an_entry_naming_neither_a_uid_nor_a_gid_is_refused() {
    let neither = GrantConfig {
        ports: vec![300],
        ..Default::default()
    };
    let msg = with_grants(false, vec![neither])
        .validate()
        .expect_err("one principal per entry")
        .to_string();
    assert!(
        msg.contains("grants[0] must name exactly one"),
        "got: {msg}"
    );
}

#[test]
fn an_entry_that_grants_nothing_is_refused() {
    let msg = with_grants(false, vec![uid_ports(990, &[])])
        .validate()
        .expect_err("an empty grant is a mistake")
        .to_string();
    assert!(msg.contains("grants[0] grants nothing"), "got: {msg}");
}
