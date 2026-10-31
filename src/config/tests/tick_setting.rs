//! Tests for the removed `node.tick_interval_secs` setting: a config file
//! that still sets it loads, the key changes nothing, and a warning says so
//! in the log the daemon sets up after loading.

use super::rekey_switch::load_capturing;
use super::*;
use std::fs;
use tempfile::TempDir;

/// Each case is the value the file sets, if any. Every value, 1 included,
/// gets the one warning, since the key is gone whatever it says.
#[test]
fn a_config_setting_the_removed_tick_interval_loads_ignores_it_warns_once_after_the_load_and_never_writes_it_back()
 {
    for value in [Some(5), Some(0), Some(3_600), Some(1), None] {
        let line = value.map_or(String::new(), |v| format!("  tick_interval_secs: {v}\n"));
        let text = format!("node:\n{line}  base_rtt_ms: 250\ntransports:\n  udp: {{}}\n");
        let (config, logs) = load_capturing(&text);

        assert_eq!(
            config.node.base_rtt_ms, 250,
            "tick_interval_secs: {value:?}: the other node keys must still apply"
        );
        let warnings: Vec<String> = logs
            .warnings()
            .into_iter()
            .filter(|w| w.contains("node.tick_interval_secs"))
            .collect();
        match value {
            Some(v) => assert!(
                warnings.len() == 1
                    && warnings[0].contains("once a second")
                    && warnings[0].contains(&format!("node.tick_interval_secs: {v}`")),
                "tick_interval_secs: {v}: one warning must name the removed key and its \
                 value and say the tick runs once a second, got {warnings:?}"
            ),
            None => assert!(
                warnings.is_empty(),
                "a config that never set the key must not be warned about it, got {warnings:?}"
            ),
        }
        let written = serde_yaml::to_string(&config.node).unwrap();
        assert!(
            !written.contains("tick_interval_secs"),
            "tick_interval_secs: {value:?}: the removed key must not be written back, got {written}"
        );
    }
}

/// A file that sets the removed key, layered under one that sets another
/// node key, loads and takes the later file's value: the key never reaches
/// the merged node.
#[test]
fn a_layered_load_whose_first_file_sets_the_removed_tick_interval_loads_and_takes_the_later_files_value()
 {
    let temp_dir = TempDir::new().unwrap();
    let first = temp_dir.path().join("first.yaml");
    let second = temp_dir.path().join("second.yaml");
    fs::write(
        &first,
        "node:\n  tick_interval_secs: 5\n  base_rtt_ms: 200\ntransports:\n  udp: {}\n",
    )
    .unwrap();
    fs::write(&second, "node:\n  base_rtt_ms: 300\n").unwrap();
    let (config, _) = Config::load_from_paths(&[first, second])
        .expect("a layered config setting the removed key must load");
    assert_eq!(
        config.node.base_rtt_ms, 300,
        "the later file's value must apply over the earlier file's"
    );
    assert_eq!(
        config.node.legacy_tick, None,
        "the removed key must not survive into the merged node"
    );
}
