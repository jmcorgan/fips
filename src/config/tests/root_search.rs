//! Tests for the warning a root start gives for each config it read from the
//! user config directory, HOME or the working directory (`warn_for`).

use super::{Config, LEGACY_SYSTEM_CONFIG_DIR, NodeConfig, warn_for};
use crate::testutil::capture_logs;
use std::path::PathBuf;

/// What a root start from the search loads when every file is present: the
/// system configs, then the user config, `~/.fips.yaml` and `./fips.yaml`.
fn loaded_with_user_configs() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let user = vec![
        PathBuf::from("/root/.config/fips/fips.yaml"),
        PathBuf::from("/root/.fips.yaml"),
        PathBuf::from("./fips.yaml"),
    ];
    let mut loaded = Config::system_paths();
    loaded.extend(user.iter().cloned());
    (loaded, user)
}

/// Run `warn_for` and return the warnings it logged, which it logs at ERROR.
fn warnings(euid: libc::uid_t, explicit: bool, loaded: &[PathBuf]) -> Vec<String> {
    let ((), logs) = capture_logs(|| warn_for(euid, explicit, loaded));
    logs.lines()
        .into_iter()
        .filter(|line| line.starts_with("ERROR "))
        .collect()
}

#[test]
fn a_root_start_from_the_search_warns_once_for_each_user_config_it_read_naming_the_file_and_the_config_flag()
 {
    let (loaded, user) = loaded_with_user_configs();
    let warnings = warnings(0, false, &loaded);
    assert_eq!(warnings.len(), user.len(), "{warnings:?}");
    for (line, path) in warnings.iter().zip(&user) {
        let field = format!("path={}", path.display());
        assert!(line.split(' ').any(|t| t == field), "{line}");
        assert!(line.contains("while running as root"), "{line}");
        assert!(line.contains("--config"), "{line}");
    }
}

#[test]
fn a_root_start_from_the_search_does_not_warn_for_the_system_config() {
    let system = Config::system_paths();
    let etc = PathBuf::from(LEGACY_SYSTEM_CONFIG_DIR).join("fips.yaml");
    assert!(system.contains(&etc), "{system:?}");
    let warnings = warnings(0, false, &system);
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn a_root_start_with_config_does_not_warn_even_for_a_file_in_home_or_the_working_directory() {
    let (loaded, user) = loaded_with_user_configs();
    for path in &user {
        let warnings = warnings(0, true, std::slice::from_ref(path));
        assert!(warnings.is_empty(), "{path:?}: {warnings:?}");
    }
    let warnings = warnings(0, true, &loaded);
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn a_non_root_start_from_the_search_does_not_warn_for_user_configs() {
    let (loaded, _) = loaded_with_user_configs();
    for euid in [1, 1000, 65534] {
        let warnings = warnings(euid, false, &loaded);
        assert!(warnings.is_empty(), "euid {euid}: {warnings:?}");
    }
}

#[test]
fn every_search_path_after_the_system_paths_draws_a_warning_when_a_root_start_reads_it() {
    let search = Config::search_paths();
    let system = Config::system_paths();
    assert!(search.starts_with(&system), "{search:?}");
    let user = &search[system.len()..];
    assert!(
        user.contains(&PathBuf::from(".").join("fips.yaml")),
        "{search:?}"
    );
    let warnings = warnings(0, false, &search);
    assert_eq!(warnings.len(), user.len(), "{warnings:?}");
}

#[test]
fn no_node_log_level_a_planted_config_can_set_hides_the_warning_about_it() {
    let (loaded, user) = loaded_with_user_configs();
    let ((), logs) = capture_logs(|| warn_for(0, false, &loaded));
    let lines = logs.lines();
    assert_eq!(lines.len(), user.len(), "{lines:?}");
    for setting in [
        None,
        Some("error"),
        Some("ERROR"),
        Some("off"),
        Some("none"),
    ] {
        let node = NodeConfig {
            log_level: setting.map(str::to_string),
            ..NodeConfig::default()
        };
        let filter = tracing::level_filters::LevelFilter::from_level(node.log_level());
        for line in &lines {
            let level: tracing::Level = line.split(' ').next().unwrap().parse().unwrap();
            assert!(level <= filter, "{setting:?} filters out {line}");
        }
    }
}
