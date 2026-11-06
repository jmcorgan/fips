//! Tests for the multipath settings: `node.path` (`PathConfig`,
//! `node.rs`), each transport's `role` and the `kind` of UDP and TCP
//! (`transport.rs`), and the rules `Config::validate` refuses them by.

use super::*;
use std::fs;
use tempfile::TempDir;

/// Write each text to its own file in `dir`, in order, and return the paths.
fn write_files(dir: &TempDir, files: &[&str]) -> Vec<PathBuf> {
    files
        .iter()
        .enumerate()
        .map(|(i, text)| {
            let path = dir.path().join(format!("{i}.yaml"));
            fs::write(&path, text).unwrap();
            path
        })
        .collect()
}

/// Load `text` as a configuration file through `Config::load_file`.
fn load_one(text: &str) -> Result<Config, ConfigError> {
    let dir = TempDir::new().unwrap();
    let paths = write_files(&dir, &[text]);
    Config::load_file(&paths[0])
}

/// Every `node.path` key reads from the documented shape, each of the six
/// transports takes all four roles, UDP and TCP take both kinds, and a file
/// that names none of them gets multipath on, the draft's values, the
/// `normal` role and no kind.
#[test]
fn the_path_section_and_transport_roles_parse_with_their_defaults() {
    let config: Config = serde_yaml::from_str(
        "node:\n  path:\n    enabled: true\n    min_samples: 5\n    mix_kinds: true\n    \
         switch:\n      margin: 1.5\n      dwell_secs: 7\n    \
         probe:\n      active_ms: 250\n      standby_ms: 3000\n",
    )
    .unwrap();
    let path = &config.node.path;
    assert!(path.enabled);
    assert_eq!(path.min_samples, 5);
    assert!(path.mix_kinds);
    assert_eq!(path.switch.margin, 1.5);
    assert_eq!(path.switch.dwell_secs, 7);
    assert_eq!(path.probe.active_ms, 250);
    assert_eq!(path.probe.standby_ms, 3000);

    let roles = [
        ("never", TransportRole::Never),
        ("backup", TransportRole::Backup),
        ("normal", TransportRole::Normal),
        ("preferred", TransportRole::Preferred),
    ];
    for (text, role) in roles {
        let line = format!("role: {text}\n");
        let udp: UdpConfig = serde_yaml::from_str(&line).unwrap();
        let tcp: TcpConfig = serde_yaml::from_str(&line).unwrap();
        let tor: TorConfig = serde_yaml::from_str(&line).unwrap();
        let nym: NymConfig = serde_yaml::from_str(&line).unwrap();
        let ble: BleConfig = serde_yaml::from_str(&line).unwrap();
        let ethernet: EthernetConfig =
            serde_yaml::from_str(&format!("interface: eth0\n{line}")).unwrap();
        for (name, got) in [
            ("udp", udp.role),
            ("tcp", tcp.role),
            ("tor", tor.role),
            ("nym", nym.role),
            ("ble", ble.role),
            ("ethernet", ethernet.role),
        ] {
            assert_eq!(got, role, "{name} with `{line}`");
        }
        assert_eq!(role.as_str(), text);
    }

    for (text, kind) in [("local", PathKind::Local), ("internet", PathKind::Internet)] {
        let line = format!("kind: {text}\n");
        let udp: UdpConfig = serde_yaml::from_str(&line).unwrap();
        let tcp: TcpConfig = serde_yaml::from_str(&line).unwrap();
        assert_eq!(udp.kind, Some(kind));
        assert_eq!(tcp.kind, Some(kind));
    }

    let bare: Config = serde_yaml::from_str("node: {}\ntransports:\n  udp: {}\n").unwrap();
    let path = &bare.node.path;
    assert!(path.enabled, "multipath must be on by default");
    assert_eq!(path.min_samples, 2);
    assert!(!path.mix_kinds);
    assert_eq!(path.switch.margin, 1.3);
    assert_eq!(path.switch.dwell_secs, 2);
    assert_eq!(path.probe.active_ms, 200);
    assert_eq!(path.probe.standby_ms, 1000);
    let (_, udp) = bare.transports.udp.iter().next().unwrap();
    assert_eq!(udp.role, TransportRole::Normal);
    assert_eq!(udp.kind, None);
    assert_eq!(TransportRole::default(), TransportRole::Normal);
}

/// A configuration that names no multipath setting writes none back: no
/// `path` section under `node`, and no `role` or `kind` on a transport.
#[test]
fn a_config_that_names_no_path_setting_writes_none_back() {
    let config: Config = serde_yaml::from_str("transports:\n  udp: {}\n  tcp: {}\n").unwrap();
    let yaml = config.to_yaml().unwrap();
    let written: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    assert!(
        written["node"].get("path").is_none(),
        "path written:\n{yaml}"
    );
    for name in ["udp", "tcp"] {
        let transport = &written["transports"][name];
        assert!(
            transport.get("role").is_none(),
            "{name} role written:\n{yaml}"
        );
        assert!(
            transport.get("kind").is_none(),
            "{name} kind written:\n{yaml}"
        );
    }
}

/// `kind` is refused on Ethernet, BLE, Tor and Nym, whose medium fixes the
/// kind of their paths; the same file without it loads.
#[test]
fn a_kind_is_refused_on_a_transport_whose_medium_fixes_one() {
    let sections = [
        "ethernet:\n    interface: eth0\n",
        "ble:\n    adapter: hci0\n",
        "tor:\n    mode: socks5\n",
        "nym:\n    socks5_addr: 127.0.0.1:1080\n",
    ];
    for section in sections {
        let without = format!("transports:\n  {section}");
        assert!(
            load_one(&without).is_ok(),
            "the control file must load:\n{without}"
        );
        let with = format!("{without}    kind: local\n");
        assert!(load_one(&with).is_err(), "`kind` was accepted in:\n{with}");
    }
}

/// The configuration `Config::validate` sees, with `node.path` changed by
/// `change`.
fn with_path(change: impl FnOnce(&mut PathConfig)) -> Config {
    let mut config = Config::default();
    change(&mut config.node.path);
    config
}

/// A change of one `node.path` setting.
type Change = fn(&mut PathConfig);

/// The validation message for a configuration that must be refused.
fn refusal(config: &Config) -> String {
    match config.validate() {
        Err(ConfigError::Validation(msg)) => msg,
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

/// A zero dwell, probe interval or sample count, more than 255 samples, and
/// a margin under 1.0 or not a number are each refused with a message that
/// names the key; the defaults and the boundary values are accepted.
#[test]
fn the_path_knobs_refuse_zero_and_a_margin_under_one() {
    assert!(Config::default().validate().is_ok());
    let accepted = with_path(|p| {
        p.switch.margin = 1.0;
        p.min_samples = 255;
        p.switch.dwell_secs = 1;
        p.probe.active_ms = 1;
        p.probe.standby_ms = 1;
    });
    assert!(accepted.validate().is_ok());

    let cases: [(&str, Change); 7] = [
        ("node.path.switch.dwell_secs", |p| p.switch.dwell_secs = 0),
        ("node.path.probe.active_ms", |p| p.probe.active_ms = 0),
        ("node.path.probe.standby_ms", |p| p.probe.standby_ms = 0),
        ("node.path.min_samples", |p| p.min_samples = 0),
        ("node.path.min_samples", |p| p.min_samples = 256),
        ("node.path.switch.margin", |p| p.switch.margin = 0.9),
        ("node.path.switch.margin", |p| p.switch.margin = f64::NAN),
    ];
    for (key, change) in cases {
        let msg = refusal(&with_path(change));
        assert!(msg.contains(&format!("`{key}`")), "{key}: {msg}");
    }
}

/// The margin refusal is one sentence: no run of two spaces from a wrapped
/// string literal, and the key named once.
#[test]
fn the_margin_refusal_reads_as_one_sentence() {
    let msg = refusal(&with_path(|p| p.switch.margin = 0.5));
    assert!(!msg.contains("  "), "a run of spaces in: {msg:?}");
    assert_eq!(msg.matches("node.path.switch.margin").count(), 1, "{msg}");
}

/// `node.path` layers per key across files, as the rest of `node` does: a
/// later file that sets only `enabled` keeps an earlier file's margin and
/// standby interval, and a third file can turn multipath off again.
#[test]
fn the_path_keys_layer_per_key_across_config_files() {
    let first = "transports:\n  udp: {}\nnode:\n  path:\n    switch:\n      margin: 1.5\n    \
                 probe:\n      standby_ms: 500\n";
    let second = "node:\n  path:\n    enabled: true\n";
    let third = "node:\n  path:\n    enabled: false\n";
    let dir = TempDir::new().unwrap();
    let paths = write_files(&dir, &[first, second, third]);

    let (two, _) = Config::load_from_paths(&paths[..2]).unwrap();
    let path = &two.node.path;
    assert!(path.enabled, "the second file's enabled");
    assert_eq!(path.switch.margin, 1.5, "the first file's margin");
    assert_eq!(
        path.probe.standby_ms, 500,
        "the first file's standby interval"
    );
    assert_eq!(
        path.probe.active_ms, 200,
        "a key no file set keeps its default"
    );

    let (three, _) = Config::load_from_paths(&paths).unwrap();
    let path = &three.node.path;
    assert!(!path.enabled, "the third file's enabled: false");
    assert_eq!(path.switch.margin, 1.5);
    assert_eq!(path.probe.standby_ms, 500);
}
