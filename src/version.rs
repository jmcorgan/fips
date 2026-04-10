//! Build version information for FIPS binaries.

use std::sync::LazyLock;

/// Package version from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git commit hash (empty if not available).
const GIT_HASH: &str = env!("FIPS_GIT_HASH");

/// Dirty flag ("-dirty" or empty).
const GIT_DIRTY: &str = env!("FIPS_GIT_DIRTY");

/// Build target triple.
const TARGET: &str = env!("FIPS_TARGET");

/// Short version string for `-V`: `0.1.0 (rev abc1234567)`
#[allow(clippy::const_is_empty)]
static SHORT_VERSION: LazyLock<String> = LazyLock::new(|| {
    if GIT_HASH.is_empty() {
        VERSION.to_string()
    } else {
        format!("{VERSION} (rev {GIT_HASH}{GIT_DIRTY})")
    }
});

/// Long version string for `--version` with build metadata.
static LONG_VERSION: LazyLock<String> =
    LazyLock::new(|| format!("{}\ntarget: {TARGET}", *SHORT_VERSION));

pub fn short_version() -> &'static str {
    &SHORT_VERSION
}

pub fn long_version() -> &'static str {
    &LONG_VERSION
}
