//! Tests for the removed `node.rekey.enabled` switch: a config file that
//! still sets it loads, the key changes nothing, and a warning says so in
//! the log the daemon sets up after loading.

use super::*;
use std::fs;
use tempfile::TempDir;

/// Load `text` from a file through `load_from_paths`, the path `Config::load`
/// takes, under [`LoadLog::hold`] as the daemon loads it, before any log is
/// set up. Returns the config and the log the replay writes.
///
/// Panics if anything reaches a subscriber during the load itself: in the
/// daemon nothing is listening then, so such an event would be lost.
pub(super) fn load_capturing(text: &str) -> (Config, crate::testutil::LogCapture) {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("fips.yaml");
    fs::write(&path, text).unwrap();
    let ((loaded, held), early) = crate::testutil::capture_logs(|| {
        LoadLog::hold(|| Config::load_from_paths(std::slice::from_ref(&path)))
    });
    assert!(
        early.lines().is_empty(),
        "the load must hold its log until the replay, but emitted {:?}",
        early.lines()
    );
    let ((), logs) = crate::testutil::capture_logs(|| held.replay());
    (loaded.expect("the config must load").0, logs)
}

/// Each case is the value the file sets, if any, and the text the one
/// warning must carry, if one is due.
#[test]
fn a_config_setting_the_removed_rekey_switch_loads_ignores_it_warns_once_after_the_load_and_never_writes_it_back()
 {
    let cases = [
        (Some("false"), Some("this node now starts rekeys")),
        (Some("true"), Some("rekey starts on the")),
        (None, None),
    ];
    for (value, says) in cases {
        let line = value.map_or(String::new(), |v| format!("    enabled: {v}\n"));
        let text =
            format!("node:\n  rekey:\n{line}    after_secs: 300\ntransports:\n  udp: {{}}\n");
        let (config, logs) = load_capturing(&text);

        assert_eq!(
            config.node.rekey.after_secs, 300,
            "enabled: {value:?}: the other rekey keys must still apply"
        );
        let warnings: Vec<String> = logs
            .warnings()
            .into_iter()
            .filter(|w| w.contains("node.rekey.enabled"))
            .collect();
        match says {
            Some(says) => assert!(
                warnings.len() == 1 && warnings[0].contains(says),
                "enabled: {value:?}: one warning must name the removed key and say \
                 {says:?}, got {warnings:?}"
            ),
            None => assert!(
                warnings.is_empty(),
                "a config that never set the key must not be warned about it, got {warnings:?}"
            ),
        }
        let written = serde_yaml::to_string(&config.node.rekey).unwrap();
        assert!(
            !written.contains("enabled"),
            "enabled: {value:?}: the removed key must not be written back, got {written}"
        );
    }
}
