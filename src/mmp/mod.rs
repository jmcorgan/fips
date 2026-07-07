//! Metrics Measurement Protocol (MMP) — node-side shell.
//!
//! The MMP protocol core (estimators, sender/receiver/metrics/path-MTU state
//! machines, report codecs and the reporting decisions) lives in the sans-IO
//! [`crate::proto::mmp`] module. What remains here is the shell-only surface:
//! the serde node configuration ([`MmpConfig`]) and the monotonic millisecond
//! clock ([`mono_ms`]) the shell reads at the edge and injects into the owned
//! `u64`-ms state.

use std::sync::LazyLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::proto::mmp::{DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MmpMode};

/// Monotonic millisecond clock for the MMP time seam.
///
/// The owned `proto::mmp` state takes injected `u64` milliseconds rather than
/// reading a clock. The shell reads this process-monotonic clock at each edge
/// and passes the value in; only deltas between two `mono_ms()` reads are ever
/// compared, so the (process-relative) epoch is immaterial.
pub(crate) fn mono_ms() -> u64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_millis() as u64
}

/// MMP configuration (`node.mmp.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmpConfig {
    /// Operating mode (`node.mmp.mode`).
    #[serde(default)]
    pub mode: MmpMode,

    /// Periodic operator log interval in seconds (`node.mmp.log_interval_secs`).
    #[serde(default = "MmpConfig::default_log_interval_secs")]
    pub log_interval_secs: u64,

    /// OWD trend ring buffer size (`node.mmp.owd_window_size`).
    #[serde(default = "MmpConfig::default_owd_window_size")]
    pub owd_window_size: usize,
}

impl Default for MmpConfig {
    fn default() -> Self {
        Self {
            mode: MmpMode::default(),
            log_interval_secs: DEFAULT_LOG_INTERVAL_SECS,
            owd_window_size: DEFAULT_OWD_WINDOW_SIZE,
        }
    }
}

impl MmpConfig {
    fn default_log_interval_secs() -> u64 {
        DEFAULT_LOG_INTERVAL_SECS
    }
    fn default_owd_window_size() -> usize {
        DEFAULT_OWD_WINDOW_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::MmpConfig;
    use crate::proto::mmp::{DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MmpMode};

    #[test]
    fn test_config_default() {
        let config = MmpConfig::default();
        assert_eq!(config.mode, MmpMode::Full);
        assert_eq!(config.log_interval_secs, 30);
        assert_eq!(config.owd_window_size, 32);
    }

    #[test]
    fn test_config_yaml_parse() {
        let yaml = r#"
mode: lightweight
log_interval_secs: 60
owd_window_size: 48
"#;
        let config: MmpConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, MmpMode::Lightweight);
        assert_eq!(config.log_interval_secs, 60);
        assert_eq!(config.owd_window_size, 48);
    }

    #[test]
    fn test_config_yaml_partial() {
        let yaml = "mode: minimal";
        let config: MmpConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, MmpMode::Minimal);
        assert_eq!(config.log_interval_secs, DEFAULT_LOG_INTERVAL_SECS);
        assert_eq!(config.owd_window_size, DEFAULT_OWD_WINDOW_SIZE);
    }
}
