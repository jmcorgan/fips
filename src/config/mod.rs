//! FIPS Configuration System
//!
//! Loads configuration from YAML files with a cascading priority system:
//! 1. `./fips.yaml` (current directory - highest priority)
//! 2. `~/.config/fips/fips.yaml` (user config directory)
//! 3. `/etc/fips/fips.yaml` (system - lowest priority; on macOS
//!    `/usr/local/etc/fips/fips.yaml` is also probed, after `/etc/fips/`)
//!
//! Values from higher priority files override those from lower priority files.
//!
//! # YAML Structure
//!
//! The YAML structure mirrors the sysctl-style paths in the architecture docs.
//! For example, `node.identity.nsec` in the docs corresponds to:
//!
//! ```yaml
//! node:
//!   identity:
//!     nsec: "nsec1..."
//! ```

#[cfg(target_os = "linux")]
mod gateway;
mod node;
mod peer;
mod transport;

use crate::node::REKEY_JITTER_SECS;
use crate::nostr::FRESHNESS_SKEW_TOLERANCE_MS;
use crate::upper::config::{DnsConfig, TunConfig};
use crate::{Identity, IdentityError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "linux")]
pub use gateway::{ConntrackConfig, GatewayConfig, GatewayDnsConfig, PortForward, Proto};
pub use node::{
    BloomConfig, BuffersConfig, CacheConfig, ControlConfig, LimitsConfig, LookupConfig, MmpConfig,
    NodeConfig, NostrRendezvousConfig, NostrRendezvousPolicy, RateLimitConfig, RekeyConfig,
    RendezvousConfig, RetryConfig, SessionConfig, SessionMmpConfig, TreeConfig,
};
pub use peer::{ConnectPolicy, PeerAddress, PeerConfig, TransportSpec};
pub use transport::{
    BleConfig, DirectoryServiceConfig, EthernetConfig, NymConfig, TcpConfig, TorConfig,
    TransportInstances, TransportsConfig, UdpConfig,
};

/// Default config filename.
const CONFIG_FILENAME: &str = "fips.yaml";

/// System-wide config directory, following the platform's packaging layout
/// (`/usr/local/etc/fips` on macOS and FreeBSD, `/etc/fips` otherwise). The
/// daemon derives identity key paths from the config file's location, so
/// anything that reads or writes config-adjacent files should use this one
/// constant.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub const SYSTEM_CONFIG_DIR: &str = "/usr/local/etc/fips";
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
pub const SYSTEM_CONFIG_DIR: &str = "/etc/fips";

/// Default key filename, placed alongside the config file.
const KEY_FILENAME: &str = "fips.key";

/// Default public key filename, placed alongside the key file.
const PUB_FILENAME: &str = "fips.pub";

/// Returns true if the textual `host:port` form refers to a loopback host.
/// Recognizes IPv4 `127.x.x.x`, IPv6 `::1` (with or without brackets), and
/// the literal string `localhost`. Hostnames are conservatively assumed to
/// be non-loopback. Used by `Config::validate()` to reject misconfigured
/// loopback UDP binds combined with non-loopback peer addresses.
fn is_loopback_addr_str(addr: &str) -> bool {
    // Bracketed IPv6: `[::1]:port`
    if let Some(rest) = addr.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = &rest[..end];
        return host == "::1";
    }
    // Plain `host:port` — split on the rightmost ':'.
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1" || host.starts_with("127.")
}

/// Derive the key file path from a config file path.
pub fn key_file_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(KEY_FILENAME)
}

/// Legacy system config directory, from before the platform-packaging move.
///
/// Equal to [`SYSTEM_CONFIG_DIR`] everywhere except where packaging installs
/// outside `/etc`, which makes [`legacy_key_fallback`] inert on those
/// platforms without needing a `cfg` of its own.
const LEGACY_SYSTEM_CONFIG_DIR: &str = "/etc/fips";

/// Find an identity key stranded at the legacy system config directory.
///
/// Adding a second system config directory to the search path moves the
/// directory `resolve_identity` derives the key path from, because that
/// directory comes from whichever config file loaded last. A node that
/// carries a config at both locations would otherwise find no key at the new
/// one and, under `persistent`, generate a fresh identity — silently changing
/// its npub, routing address and mesh IPv6, none of which has a migration
/// path.
///
/// Returns the legacy key only when all of these hold, which confines the
/// fallback to exactly that regression:
///
/// - the two directories actually differ, so this is inert on Linux
/// - no key exists at `key_path`
/// - `key_path` sits in `system_dir`, so an operator using `./fips.yaml` or a
///   user config is never redirected to a system key
/// - a key does exist at `legacy_dir`
fn legacy_key_fallback(key_path: &Path, system_dir: &Path, legacy_dir: &Path) -> Option<PathBuf> {
    if system_dir == legacy_dir || key_path.exists() {
        return None;
    }
    if key_path.parent() != Some(system_dir) {
        return None;
    }
    let legacy = legacy_dir.join(KEY_FILENAME);
    legacy.exists().then_some(legacy)
}

/// Derive the public key file path from a config file path.
pub fn pub_file_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(PUB_FILENAME)
}

/// How `/var/run/fips` participates in Unix control-socket resolution.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VarRunPolicy {
    /// Whether an existing `/var/run/fips` directory participates in resolution.
    consult_existing: bool,
    /// Whether to select `/var/run/fips` before its private leaf exists.
    create_private_dir: bool,
}

#[cfg(target_os = "macos")]
fn default_var_run_policy() -> VarRunPolicy {
    // LaunchDaemons run as root unless their plist declares another user.
    // Selecting the private runtime path before it exists lets ControlSocket
    // create it at every boot; non-root development runs retain XDG and /tmp
    // fallbacks until a packaged daemon has created /var/run/fips.
    VarRunPolicy {
        consult_existing: true,
        create_private_dir: unsafe { libc::geteuid() } == 0,
    }
}

#[cfg(target_os = "freebsd")]
fn default_var_run_policy() -> VarRunPolicy {
    // The rc.d service creates /var/run/fips before starting the daemon.
    VarRunPolicy {
        consult_existing: true,
        create_private_dir: false,
    }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "freebsd"))))]
fn default_var_run_policy() -> VarRunPolicy {
    VarRunPolicy {
        consult_existing: false,
        create_private_dir: false,
    }
}

/// Pure path-selection core used by the host resolver and deterministic tests.
#[cfg(unix)]
fn resolve_default_socket_with(
    filename: &str,
    var_run_policy: VarRunPolicy,
    xdg_runtime_dir: Option<&Path>,
    is_dir: impl Fn(&Path) -> bool,
) -> String {
    if is_dir(Path::new("/run/fips")) {
        return format!("/run/fips/{filename}");
    }

    if var_run_policy.consult_existing {
        let private_var_run = Path::new("/var/run/fips");
        let may_create_private_dir =
            var_run_policy.create_private_dir && is_dir(Path::new("/var/run"));
        if is_dir(private_var_run) || may_create_private_dir {
            return format!("/var/run/fips/{filename}");
        }
    }

    if let Some(xdg) = xdg_runtime_dir
        && is_dir(xdg)
    {
        return xdg
            .join("fips")
            .join(filename)
            .to_string_lossy()
            .into_owned();
    }

    format!("/tmp/fips-{filename}")
}

/// Return whether `parent` is one of the private runtime directories used by
/// the default Unix socket resolver.
///
/// This is intentionally stricter than matching any leaf named `fips`: an
/// explicitly configured existing directory remains operator-owned unless it
/// is also a canonical resolver candidate.
#[cfg(unix)]
fn is_managed_socket_parent_with(
    parent: &Path,
    var_run_policy: VarRunPolicy,
    xdg_runtime_dir: Option<&Path>,
) -> bool {
    parent == Path::new("/run/fips")
        || (var_run_policy.consult_existing && parent == Path::new("/var/run/fips"))
        || xdg_runtime_dir.is_some_and(|xdg| parent == xdg.join("fips"))
}

/// Return whether `parent` is a private runtime directory managed by the
/// default Unix socket resolver on this host.
#[cfg(unix)]
pub(crate) fn is_managed_socket_parent(parent: &Path) -> bool {
    let xdg_runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    is_managed_socket_parent_with(parent, default_var_run_policy(), xdg_runtime_dir.as_deref())
}

/// Resolve a default Unix-socket path under the canonical order:
/// `/run/fips/<filename>` → `/var/run/fips/<filename>` on macOS/FreeBSD →
/// `$XDG_RUNTIME_DIR/fips/<filename>` → `/tmp/fips-<filename>`.
///
/// `/run/fips` is the packaged Linux convention. FreeBSD's rc.d service
/// creates `/var/run/fips` before starting the daemon. A privileged macOS
/// daemon selects `/var/run/fips` even when the private leaf does not exist so
/// it can be recreated at bind time after every boot; non-root macOS clients
/// select it once the daemon has created it. `XDG_RUNTIME_DIR` covers dev runs,
/// and `/tmp` is the last-resort fallback.
///
/// Selection is by *existence*, not writability. A fips-group member
/// whose shell session has not picked up the supplementary group (no
/// re-login after `usermod -aG fips`) cannot tempfile-probe a
/// `root:fips 0750` directory but can still connect to a socket inside
/// it once the kernel checks the actual group at `connect(2)` time —
/// and even where the user genuinely cannot connect, surfacing an
/// `EACCES` from the socket call is clearer than silently steering
/// fipstop / fipsctl to a path the daemon never bound. The daemon's
/// own bind code (`ControlSocket::bind`) creates `/run/fips` if it is
/// missing, so the resolver does not need to materialize the directory
/// itself.
///
/// `XDG_RUNTIME_DIR` is validated as an existing directory before being
/// used; a stale post-logout value (after `pam_systemd` reaps the dir)
/// is treated as missing.
#[cfg(unix)]
pub(crate) fn resolve_default_socket(filename: &str) -> String {
    let xdg_runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    resolve_default_socket_with(
        filename,
        default_var_run_policy(),
        xdg_runtime_dir.as_deref(),
        Path::is_dir,
    )
}

/// Default control socket path for fipsctl / fipstop.
///
/// On Unix, delegates to [`resolve_default_socket`] for the canonical
/// platform runtime directory → `XDG_RUNTIME_DIR` → `/tmp` order. On Windows,
/// returns the default TCP port ("21210").
pub fn default_control_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(resolve_default_socket("control.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from("21210")
    }
}

/// Default gateway control socket path.
///
/// On Unix, delegates to [`resolve_default_socket`] (the same platform order as
/// the main control socket). The gateway daemon itself uses a hardcoded
/// `/run/fips/gateway.sock` since gateway operation requires root for
/// NAT/conntrack management; this client-side resolver falls through
/// gracefully for non-root dev runs that need a gateway socket path. On
/// Windows, returns a placeholder TCP port ("21211").
pub fn default_gateway_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(resolve_default_socket("gateway.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from("21211")
    }
}

/// Read a bare bech32 nsec from a key file.
///
/// The file contents are the private key, and trimming copies it into a
/// second string, so the read buffer is cleared on every exit path rather
/// than dropped as it stands. The returned nsec is the caller's.
pub fn read_key_file(path: &Path) -> Result<String, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    let contents = Zeroizing::new(contents);
    let nsec = contents.trim().to_string();
    if nsec.is_empty() {
        return Err(ConfigError::EmptyKeyFile {
            path: path.to_path_buf(),
        });
    }
    Ok(nsec)
}

/// Open a key or public key file for writing, without following a symlink at
/// the path.
///
/// On Unix the open carries `O_NOFOLLOW`, so a symlink pre-planted at `path`
/// fails the open instead of having its target truncated. When `enforce_mode`
/// is set, `mode` is then applied to the open descriptor (`fchmod`) before the
/// caller writes anything, so a file that already existed at a looser mode is
/// tightened before any secret bytes reach it. The permission change is made
/// through the descriptor rather than `std::fs::set_permissions`, which
/// re-resolves the name and would reopen the window the `O_NOFOLLOW` closes.
///
/// `O_NOFOLLOW` covers only the *final* path component. An attacker who can
/// replace an intermediate directory of the key path is unaffected by it.
///
/// On Windows neither the mode handling nor the symlink protection applies;
/// the file inherits the parent directory's ACLs.
fn open_mode_enforced(
    path: &Path,
    mode: u32,
    enforce_mode: bool,
) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }

    let file = opts.open(path)?;

    #[cfg(unix)]
    if enforce_mode {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }

    #[cfg(not(unix))]
    let _ = (mode, enforce_mode);

    Ok(file)
}

/// Classify a failure to open a key or public key file for writing.
///
/// A refused open is reported as [`ConfigError::KeyPathIsSymlink`] when the
/// path is in fact a symlink. The check is on the path rather than on the
/// errno because `O_NOFOLLOW` reports a final-component symlink as `ELOOP` on
/// Linux and macOS but `EMLINK` on FreeBSD and `EFTYPE` on NetBSD, and this
/// module's `cfg(unix)` is deliberately broader than Linux.
fn classify_open_error(path: &Path, source: std::io::Error) -> ConfigError {
    if path
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return ConfigError::KeyPathIsSymlink {
            path: path.to_path_buf(),
        };
    }
    ConfigError::WriteKeyFile {
        path: path.to_path_buf(),
        source,
    }
}

/// Warn about an existing identity key file the daemon will not rewrite.
///
/// The persistent path reads an existing key and returns without writing it,
/// so a mode loosened by an operator `chmod` or by a restore that did not
/// preserve modes is otherwise never surfaced anywhere. Repairing the mode is
/// deliberately left to the operator; this only reports it. A symlinked key is
/// reported too, since the daemon does not manage the target's mode.
///
/// Unix only: on Windows the file's ACLs are inherited from the parent
/// directory and there is no mode to inspect.
fn warn_unmanaged_key_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let Ok(meta) = path.symlink_metadata() else {
            return;
        };

        if meta.file_type().is_symlink() {
            tracing::warn!(
                path = %path.display(),
                "Identity key file is a symlink; the daemon does not manage the mode of its target"
            );
            return;
        }

        if meta.is_file() && meta.permissions().mode() & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:04o}", meta.permissions().mode() & 0o7777),
                "Identity key file is accessible beyond its owner; expected mode 0600"
            );
        }
    }

    #[cfg(not(unix))]
    let _ = path;
}

/// Write a bare bech32 nsec to a key file with restricted permissions.
///
/// On Unix, the file is opened with `O_NOFOLLOW` (a symlink at the path is
/// refused rather than followed) and forced to mode 0600 (owner read/write
/// only) before any key material is written, so an existing file at a looser
/// mode is corrected rather than inherited.
///
/// Coverage gap: on Windows the file inherits default ACLs from the parent
/// directory, and neither the mode enforcement nor the symlink protection
/// applies. The exclusion is deliberate.
pub fn write_key_file(path: &Path, nsec: &str) -> Result<(), ConfigError> {
    use std::io::Write;

    let mut file =
        open_mode_enforced(path, 0o600, true).map_err(|e| classify_open_error(path, e))?;

    file.write_all(nsec.as_bytes())
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(b"\n")
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

/// Write a bare bech32 npub to a public key file.
///
/// On Unix, the file is opened with `O_NOFOLLOW` (a symlink at the path is
/// refused rather than followed) and created with mode 0644 (owner
/// read/write, others read). The mode is applied at creation only: this file
/// is rewritten on every persistent start, and forcing the mode would reopen
/// an operator-tightened `fips.pub` to world-readable each time.
///
/// Coverage gap: on Windows the file inherits default ACLs from the parent
/// directory, and neither the mode handling nor the symlink protection
/// applies. The exclusion is deliberate.
pub fn write_pub_file(path: &Path, npub: &str) -> Result<(), ConfigError> {
    use std::io::Write;

    let mut file =
        open_mode_enforced(path, 0o644, false).map_err(|e| classify_open_error(path, e))?;

    file.write_all(npub.as_bytes())
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(b"\n")
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

/// Resolve identity from config and key file.
///
/// Behavior depends on `node.identity.persistent`:
///
/// - **`persistent: false`** (default): generate a fresh ephemeral keypair
///   every start. Key files are written for operator visibility but overwritten
///   on each restart.
///
/// - **`persistent: true`**: use three-tier resolution:
///   1. Explicit nsec in config — highest priority
///   2. Persistent key file (`fips.key`) — reused across restarts
///   3. Generate new — creates keypair, writes `fips.key` and `fips.pub`
///
/// - **`nsec` set explicitly**: always uses that, regardless of `persistent`.
///
/// Returns the nsec string (bech32 or hex) to be used for identity creation.
pub fn resolve_identity(
    config: &Config,
    loaded_paths: &[PathBuf],
) -> Result<ResolvedIdentity, ConfigError> {
    use crate::encode_nsec;

    // Explicit nsec in config always wins
    if let Some(nsec) = &config.node.identity.nsec {
        return Ok(ResolvedIdentity {
            nsec: nsec.clone(),
            source: IdentitySource::Config,
        });
    }

    // Determine key file directory from loaded config paths
    let config_ref = if let Some(path) = loaded_paths.last() {
        path.clone()
    } else {
        Config::search_paths()
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("./fips.yaml"))
    };
    let key_path = key_file_path(&config_ref);
    let pub_path = pub_file_path(&config_ref);

    if config.node.identity.persistent {
        // Persistent mode: load existing key file or generate-and-persist
        if key_path.exists() {
            // Held in a guard, not a bare `String`: if the parse below fails,
            // the `?` returns and a bare local would be freed uncleared.
            let nsec = Zeroizing::new(read_key_file(&key_path)?);
            let identity = Identity::from_secret_str(&nsec)?;
            warn_unmanaged_key_file(&key_path);
            if let Err(e) = write_pub_file(&pub_path, &identity.npub()) {
                tracing::warn!(
                    path = %pub_path.display(),
                    error = %e,
                    "Failed to write the public key file"
                );
            }
            return Ok(ResolvedIdentity {
                nsec: nsec.to_string(),
                source: IdentitySource::KeyFile(key_path),
            });
        }

        // No key at the resolved location. Before generating a new identity,
        // check whether one is stranded at the legacy system config directory:
        // generating here would silently change the node's npub, routing
        // address and mesh IPv6.
        if let Some(legacy) = legacy_key_fallback(
            &key_path,
            Path::new(SYSTEM_CONFIG_DIR),
            Path::new(LEGACY_SYSTEM_CONFIG_DIR),
        ) {
            // Guarded for the same reason as the current-path read above.
            let nsec = Zeroizing::new(read_key_file(&legacy)?);
            let identity = Identity::from_secret_str(&nsec)?;
            tracing::warn!(
                legacy = %legacy.display(),
                current = %key_path.display(),
                "Identity key found at the legacy path but not at the current default; \
                 using it so the node keeps its identity — move it to the current path"
            );
            warn_unmanaged_key_file(&legacy);
            if let Err(e) = write_pub_file(&pub_path, &identity.npub()) {
                tracing::warn!(
                    path = %pub_path.display(),
                    error = %e,
                    "Failed to write the public key file"
                );
            }
            return Ok(ResolvedIdentity {
                nsec: nsec.to_string(),
                source: IdentitySource::KeyFile(legacy),
            });
        }

        // No key file anywhere — generate and persist
        let identity = Identity::generate();
        // `keypair()` and `secret_key()` each hand back a whole private key
        // rather than a handle, so both temporaries are bound and erased.
        let mut our_keypair = identity.keypair();
        let mut secret_key = our_keypair.secret_key();
        let nsec = encode_nsec(&secret_key);
        secret_key.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = identity.npub();

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match write_key_file(&key_path, &nsec) {
            Ok(()) => {
                if let Err(e) = write_pub_file(&pub_path, &npub) {
                    tracing::warn!(
                        path = %pub_path.display(),
                        error = %e,
                        "Failed to write the public key file"
                    );
                }
                Ok(ResolvedIdentity {
                    nsec,
                    source: IdentitySource::Generated(key_path),
                })
            }
            Err(e) => {
                tracing::warn!(
                    path = %key_path.display(),
                    error = %e,
                    "Failed to persist the generated identity key; this node is starting with an \
                     ephemeral identity and its npub will change on every start"
                );
                Ok(ResolvedIdentity {
                    nsec,
                    source: IdentitySource::Ephemeral,
                })
            }
        }
    } else {
        // Ephemeral mode (default): fresh keypair every start, write key files
        // for operator visibility
        let identity = Identity::generate();
        // `keypair()` and `secret_key()` each hand back a whole private key
        // rather than a handle, so both temporaries are bound and erased.
        let mut our_keypair = identity.keypair();
        let mut secret_key = our_keypair.secret_key();
        let nsec = encode_nsec(&secret_key);
        secret_key.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = identity.npub();

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // symlink_metadata rather than exists: a dangling symlink at the key
        // path reports exists() == false but is still an existing file the
        // write is about to act on.
        if key_path.symlink_metadata().is_ok() {
            tracing::warn!(
                path = %key_path.display(),
                config_key = "node.identity.persistent",
                "An existing key file at this path is being replaced by a fresh ephemeral \
                 identity; set node.identity.persistent: true to keep the existing identity"
            );
        }

        if let Err(e) = write_key_file(&key_path, &nsec) {
            tracing::warn!(
                path = %key_path.display(),
                error = %e,
                "Failed to write the ephemeral key file"
            );
        }
        if let Err(e) = write_pub_file(&pub_path, &npub) {
            tracing::warn!(
                path = %pub_path.display(),
                error = %e,
                "Failed to write the public key file"
            );
        }

        Ok(ResolvedIdentity {
            nsec,
            source: IdentitySource::Ephemeral,
        })
    }
}

/// Result of identity resolution.
///
/// `nsec` is the node's private key in plaintext. Every local that carries it
/// through [`resolve_identity`] either moves into this struct or is held in a
/// guard that clears it, so this is where the surviving string lives and where
/// clearing it belongs.
/// A caller that wants the value out should take it with [`Option::take`] or
/// `std::mem::take` rather than moving the field, which the `Drop` below
/// forbids.
pub struct ResolvedIdentity {
    /// The nsec string (bech32 or hex) for creating an Identity.
    pub nsec: String,
    /// Where the identity came from.
    pub source: IdentitySource,
}

impl Drop for ResolvedIdentity {
    /// Clear the plaintext private key rather than dropping the allocation
    /// with the key still in it.
    fn drop(&mut self) {
        self.nsec.zeroize();
    }
}

/// Where a resolved identity originated.
pub enum IdentitySource {
    /// From explicit nsec in config file.
    Config,
    /// Loaded from a persistent key file.
    KeyFile(PathBuf),
    /// Generated and saved to a new key file.
    Generated(PathBuf),
    /// Generated but could not be persisted.
    Ephemeral,
}

/// Errors that can occur during configuration loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config file {path}: {source}")]
    ParseYaml {
        path: PathBuf,
        source: serde_yaml::Error,
    },

    #[error("key file is empty: {path}")]
    EmptyKeyFile { path: PathBuf },

    #[error("failed to write key file {path}: {source}")]
    WriteKeyFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("refusing to write key file through a symlink: {path}")]
    KeyPathIsSymlink { path: PathBuf },

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("invalid configuration: {0}")]
    Validation(String),
}

/// Identity configuration (`node.identity.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Secret key in nsec (bech32) or hex format (`node.identity.nsec`).
    /// If not specified, a new keypair will be generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>,

    /// Whether to persist the identity across restarts (`node.identity.persistent`).
    /// When false (default), a fresh ephemeral keypair is generated each start.
    /// When true, the key file is reused across restarts.
    #[serde(default)]
    pub persistent: bool,
}

impl Drop for IdentityConfig {
    /// Clear the plaintext private key.
    ///
    /// This field holds the node's private key for the whole process
    /// lifetime, which is the longest any secret lives in this crate, so
    /// leaving the allocation to be freed with the key still in it is the
    /// largest residue the crate can reach. A caller that needs the value out
    /// should take it with [`Option::take`]; moving the field is what the
    /// `Drop` forbids.
    fn drop(&mut self) {
        self.nsec.zeroize();
    }
}

/// Root configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Node configuration (`node.*`).
    #[serde(default)]
    pub node: NodeConfig,

    /// TUN interface configuration (`tun.*`).
    #[serde(default)]
    pub tun: TunConfig,

    /// DNS responder configuration (`dns.*`).
    #[serde(default)]
    pub dns: DnsConfig,

    /// Transport instances (`transports.*`).
    #[serde(default, skip_serializing_if = "TransportsConfig::is_empty")]
    pub transports: TransportsConfig,

    /// Static peers to connect to (`peers`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,

    /// Gateway configuration (`gateway`).
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayConfig>,
}

impl Config {
    /// Create a new empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from the standard search paths.
    ///
    /// Files are loaded in reverse priority order and merged:
    /// 1. `/etc/fips/fips.yaml` (and `/usr/local/etc/fips/fips.yaml` on macOS;
    ///    loaded first, lowest priority)
    /// 2. `~/.config/fips/fips.yaml` (user config)
    /// 3. `./fips.yaml` (loaded last, highest priority)
    ///
    /// Returns a tuple of (config, paths_loaded) where paths_loaded contains
    /// the paths that were successfully loaded.
    pub fn load() -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let search_paths = Self::search_paths();
        Self::load_from_paths(&search_paths)
    }

    /// Load configuration from specific paths.
    ///
    /// Paths are processed in order, with later paths overriding earlier ones.
    pub fn load_from_paths(paths: &[PathBuf]) -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let mut config = Config::default();
        let mut loaded_paths = Vec::new();

        for path in paths {
            if path.exists() {
                let file_config = Self::load_file(path)?;
                config.merge(file_config);
                loaded_paths.push(path.clone());
            }
        }

        Ok((config, loaded_paths))
    }

    /// Load configuration from a single file.
    pub fn load_file(path: &Path) -> Result<Self, ConfigError> {
        // The config file is the highest-priority home of a plaintext key:
        // `node.identity.nsec` is read straight out of it, so the whole file
        // text is treated as secret for as long as it is held.
        let contents =
            Zeroizing::new(
                std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
                    path: path.to_path_buf(),
                    source: e,
                })?,
            );

        let mut config: Config =
            serde_yaml::from_str(&contents).map_err(|e| ConfigError::ParseYaml {
                path: path.to_path_buf(),
                source: e,
            })?;
        config.normalize_deprecated_keys();
        Ok(config)
    }

    /// COMPAT (drop at the v2 cutover): fold a deprecated `node.discovery:`
    /// block into the `node.lookup.*` (mesh-lookup scalars) and
    /// `node.rendezvous.*` (nostr/LAN peer rendezvous) tables that replaced it.
    ///
    /// Runs at every deserialize boundary (see `load_file`). A present legacy
    /// field fills the corresponding new-table field, so a config that predates
    /// the split keeps behaving identically. When a legacy block is seen, a
    /// one-time deprecation warning names the old→new key moves. Exposed to the
    /// crate so config tests that deserialize directly can invoke it.
    pub(crate) fn normalize_deprecated_keys(&mut self) {
        let Some(compat) = self.node.discovery.take() else {
            return;
        };
        tracing::warn!(
            target: "fips::config",
            "`node.discovery.*` is deprecated and will be removed: mesh-lookup \
             scalars moved to `node.lookup.*`, and peer-rendezvous keys moved to \
             `node.rendezvous.nostr.*` / `node.rendezvous.lan.*`. Please migrate; \
             a legacy `node.discovery` block still applies for now."
        );
        if let Some(v) = compat.ttl {
            self.node.lookup.ttl = v;
        }
        if let Some(v) = compat.attempt_timeouts_secs {
            self.node.lookup.attempt_timeouts_secs = v;
        }
        if let Some(v) = compat.recent_expiry_secs {
            self.node.lookup.recent_expiry_secs = v;
        }
        if let Some(v) = compat.backoff_base_secs {
            self.node.lookup.backoff_base_secs = v;
        }
        if let Some(v) = compat.backoff_max_secs {
            self.node.lookup.backoff_max_secs = v;
        }
        if let Some(v) = compat.forward_min_interval_secs {
            self.node.lookup.forward_min_interval_secs = v;
        }
        if let Some(v) = compat.nostr {
            self.node.rendezvous.nostr = v;
        }
        if let Some(v) = compat.lan {
            self.node.rendezvous.lan = v;
        }
    }

    /// Get the standard search paths in priority order (lowest to highest).
    pub fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // System config — /etc/fips is always probed so existing installs
        // keep working after an upgrade.
        paths.push(PathBuf::from("/etc/fips").join(CONFIG_FILENAME));

        // macOS and FreeBSD packaging install config under /usr/local/etc/fips;
        // probe it after /etc/fips so the packaged file wins over a stale
        // /etc/fips leftover. Read from SYSTEM_CONFIG_DIR rather than a second
        // literal, so this path and the directory `fipsctl keygen` writes into
        // cannot drift apart.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        paths.push(PathBuf::from(SYSTEM_CONFIG_DIR).join(CONFIG_FILENAME));

        // User config directory
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("fips").join(CONFIG_FILENAME));
        }

        // Home directory (legacy location)
        if let Some(home_dir) = dirs::home_dir() {
            paths.push(home_dir.join(".fips.yaml"));
        }

        // Current directory (highest priority)
        paths.push(PathBuf::from(".").join(CONFIG_FILENAME));

        paths
    }

    /// Merge another configuration into this one.
    ///
    /// Values from `other` override values in `self` when present.
    pub fn merge(&mut self, mut other: Config) {
        // Merge node.identity section. The nsec is taken rather than moved
        // out of `other.node.identity`, which clears its private key on drop
        // and so cannot be left partially moved.
        if other.node.identity.nsec.is_some() {
            // Clear whatever this field already held before overwriting it.
            // Assigning over the field drops the old `String` in place, which
            // does not run `Drop for IdentityConfig` and would free a
            // plaintext key uncleared when two config files both carry one.
            if let Some(mut old) = self.node.identity.nsec.take() {
                old.zeroize();
            }
            self.node.identity.nsec = other.node.identity.nsec.take();
        }
        if other.node.identity.persistent {
            self.node.identity.persistent = true;
        }
        // Merge node.leaf_only
        if other.node.leaf_only {
            self.node.leaf_only = true;
        }
        // Merge tun section
        if other.tun.enabled {
            self.tun.enabled = true;
        }
        if other.tun.name.is_some() {
            self.tun.name = other.tun.name;
        }
        if other.tun.mtu.is_some() {
            self.tun.mtu = other.tun.mtu;
        }
        // Merge dns section — higher-priority config always wins for enabled
        self.dns.enabled = other.dns.enabled;
        if other.dns.bind_addr.is_some() {
            self.dns.bind_addr = other.dns.bind_addr;
        }
        if other.dns.port.is_some() {
            self.dns.port = other.dns.port;
        }
        if other.dns.ttl.is_some() {
            self.dns.ttl = other.dns.ttl;
        }
        // Merge transports section
        self.transports.merge(other.transports);
        // Merge peers (replace if non-empty)
        if !other.peers.is_empty() {
            self.peers = other.peers;
        }
        // Merge gateway section — higher-priority config replaces entirely
        #[cfg(target_os = "linux")]
        if other.gateway.is_some() {
            self.gateway = other.gateway;
        }
    }

    /// Create an Identity from this configuration.
    ///
    /// If an nsec is configured, uses that to create the identity.
    /// Otherwise, generates a new random identity.
    pub fn create_identity(&self) -> Result<Identity, ConfigError> {
        match &self.node.identity.nsec {
            Some(nsec) => Ok(Identity::from_secret_str(nsec)?),
            None => Ok(Identity::generate()),
        }
    }

    /// Check if an identity is configured (vs. will be generated).
    pub fn has_identity(&self) -> bool {
        self.node.identity.nsec.is_some()
    }

    /// Check if leaf-only mode is configured.
    pub fn is_leaf_only(&self) -> bool {
        self.node.leaf_only
    }

    /// Derive the node profile from config.
    ///
    /// leaf_only → Leaf (implies non-routing),
    /// disable_routing → NonRouting,
    /// otherwise → Full.
    pub fn node_profile(&self) -> crate::proto::fmp::NodeProfile {
        if self.node.leaf_only {
            crate::proto::fmp::NodeProfile::Leaf
        } else if self.node.disable_routing {
            crate::proto::fmp::NodeProfile::NonRouting
        } else {
            crate::proto::fmp::NodeProfile::Full
        }
    }

    /// Get the configured peers.
    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    /// Get peers that should auto-connect on startup.
    pub fn auto_connect_peers(&self) -> impl Iterator<Item = &PeerConfig> {
        self.peers.iter().filter(|p| p.is_auto_connect())
    }

    /// Validate cross-field configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let nostr = &self.node.rendezvous.nostr;

        let any_transport_advertises_on_nostr = self
            .transports
            .udp
            .iter()
            .any(|(_, cfg)| cfg.advertise_on_nostr())
            || self
                .transports
                .tcp
                .iter()
                .any(|(_, cfg)| cfg.advertise_on_nostr())
            || self
                .transports
                .tor
                .iter()
                .any(|(_, cfg)| cfg.advertise_on_nostr());

        if any_transport_advertises_on_nostr && !nostr.enabled {
            return Err(ConfigError::Validation(
                "at least one transport has `advertise_on_nostr = true`, but `node.rendezvous.nostr.enabled` is false".to_string(),
            ));
        }

        if self.peers.iter().any(|peer| peer.via_nostr) && !nostr.enabled {
            return Err(ConfigError::Validation(
                "at least one peer has `via_nostr = true`, but `node.rendezvous.nostr.enabled` is false".to_string(),
            ));
        }

        for (i, peer) in self.peers.iter().enumerate() {
            if peer.addresses.is_empty() && !peer.via_nostr {
                return Err(ConfigError::Validation(format!(
                    "peers[{i}] ({}): must specify at least one address, or set `via_nostr = true` to resolve endpoints from the Nostr advert",
                    peer.npub
                )));
            }
        }

        let has_nat_udp_advert = self
            .transports
            .udp
            .iter()
            .any(|(_, cfg)| cfg.advertise_on_nostr() && !cfg.is_public());

        if nostr.enabled && has_nat_udp_advert {
            if nostr.dm_relays.is_empty() {
                return Err(ConfigError::Validation(
                    "NAT UDP advert publishing requires `node.rendezvous.nostr.dm_relays` to be non-empty".to_string(),
                ));
            }
            if nostr.stun_servers.is_empty() {
                return Err(ConfigError::Validation(
                    "NAT UDP advert publishing requires `node.rendezvous.nostr.stun_servers` to be non-empty".to_string(),
                ));
            }
        }

        // Reject loopback UDP bind combined with non-loopback peer addresses.
        // Linux pins the source IP to a loopback-bound socket, so packets
        // sent from such a socket to external peers are dropped at the
        // routing layer with no clear error in the daemon log.
        // Outbound-only mode is exempt because it overrides bind_addr to
        // 0.0.0.0:0 (kernel-picked source).
        for (name, cfg) in self.transports.udp.iter() {
            if cfg.outbound_only() {
                continue;
            }
            if is_loopback_addr_str(cfg.bind_addr()) {
                let any_external_peer = self.peers.iter().any(|peer| {
                    peer.addresses
                        .iter()
                        .any(|a| a.transport == "udp" && !is_loopback_addr_str(&a.addr))
                });
                if any_external_peer {
                    let label = name.unwrap_or("(unnamed)");
                    return Err(ConfigError::Validation(format!(
                        "transports.udp[{label}].bind_addr is loopback ({}) but at least one peer has a non-loopback UDP address; \
                         fips cannot reach external peers from a loopback-bound socket. \
                         Use bind_addr: \"0.0.0.0:2121\" (with kernel-firewall hardening if exposure is a concern), or set outbound_only: true.",
                        cfg.bind_addr()
                    )));
                }
            }
        }

        // Reject a peer address naming a transport instance that no
        // configured transport answers to. A qualified name deliberately never
        // falls back: substituting a different instance is the wrong-lane dial
        // the syntax exists to prevent, so the dialer refuses the address and
        // says so at debug. Where the peer has a second address that does
        // resolve, that refusal is invisible — the lane is simply never used,
        // which is the failure the instance names were introduced to fix. A
        // typo, a renamed transport, or a `Named` config collapsed back to
        // `Single` all land here, and all of them are cheaper to find at
        // startup than in a packet capture.
        for peer in &self.peers {
            for addr in &peer.addresses {
                let spec = addr.spec();
                let Some(want) = spec.instance else {
                    continue;
                };
                if spec.kind != "udp" {
                    return Err(ConfigError::Validation(format!(
                        "peer `{}` has address `{}` on transport `{}`, but only `udp` resolves an instance name; \
                         for any other type the dialer would have to pick an arbitrary instance, which is the wrong-lane dial the syntax exists to prevent. \
                         Drop the `/{want}` qualifier to match any instance of `{}`.",
                        peer.npub, addr.addr, addr.transport, spec.kind
                    )));
                }
                let configured: Vec<&str> = self
                    .transports
                    .udp
                    .iter()
                    .filter_map(|(name, _)| name)
                    .collect();
                if !configured.contains(&want) {
                    let known = if configured.is_empty() {
                        "no named udp instances are configured (the udp transport is a single unnamed instance)".to_string()
                    } else {
                        format!("configured udp instances are: {}", configured.join(", "))
                    };
                    return Err(ConfigError::Validation(format!(
                        "peer `{}` has address `{}` on transport `{}`, but no udp transport is configured under the instance name `{want}`; \
                         a qualified name is never substituted, so this address would be skipped at every dial and the peer reached only over its other addresses, if it has any. \
                         {known}.",
                        peer.npub, addr.addr, addr.transport
                    )));
                }
            }
        }

        // Reject rekey triggers that fire immediately and forever. Both
        // arms are checked regardless of `node.rekey.enabled` so that
        // turning rekey on later cannot surface a config error at a
        // surprising moment. There is deliberately no upper bound:
        // u64::MAX is the idiom for disabling one arm of the trigger.
        let rekey = &self.node.rekey;

        if rekey.after_messages == 0 {
            return Err(ConfigError::Validation(
                "`node.rekey.after_messages` must be at least 1; 0 fires the message-count trigger on every poll instead of disabling it. \
                 Use a very large value to effectively disable the message-count trigger."
                    .to_string(),
            ));
        }

        let jitter_secs = REKEY_JITTER_SECS.unsigned_abs();
        if rekey.after_secs <= jitter_secs {
            return Err(ConfigError::Validation(format!(
                "`node.rekey.after_secs` is {}, but must be greater than the per-session rekey jitter of {jitter_secs}s; \
                 each session offsets the interval by a random value in [-{jitter_secs}, +{jitter_secs}] seconds, so a smaller interval saturates to zero \
                 and rekeys on sight for roughly half of sessions. \
                 Use a very large value to effectively disable the timer trigger.",
                rekey.after_secs
            )));
        }

        // The established-link msg1 bucket. Both keys are `Option`, and
        // absent means "derive from max_peers", which is the intended path.
        // An explicit zero is the dangerous state: it does not disable the
        // bucket, it refuses every rekey and restart msg1 from an already
        // established peer, which is a worse failure than the shared-bucket
        // starvation the second bucket exists to prevent.
        let rl = &self.node.rate_limit;

        if rl.established_handshake_burst == Some(0) {
            return Err(ConfigError::Validation(
                "`node.rate_limit.established_handshake_burst` is 0, which refuses every rekey and restart msg1 from an established peer rather than disabling the limit. \
                 Omit the key to derive it from `node.limits.max_peers`, or set a positive burst."
                    .to_string(),
            ));
        }

        if let Some(rate) = rl.established_handshake_rate
            && !(rate.is_finite() && rate > 0.0)
        {
            return Err(ConfigError::Validation(format!(
                "`node.rate_limit.established_handshake_rate` is {rate}, but must be a finite value greater than 0; \
                 a non-positive or non-finite refill rate never replenishes the established-link bucket, so rekey msg1 stops being admitted once the initial burst is spent. \
                 Omit the key to derive it from `node.limits.max_peers` and `node.rekey.after_secs`."
            )));
        }

        // The per-link session-setup bucket. The same trap as above in a
        // non-optional field: zero does not disable the limiter, it refuses
        // every inbound setup message and so refuses every session.
        if rl.session_setup_burst == 0 {
            return Err(ConfigError::Validation(
                "`node.rate_limit.session_setup_burst` is 0, which refuses every inbound SessionSetup rather than disabling the limit. \
                 Set a positive burst; a very large value effectively disables it."
                    .to_string(),
            ));
        }

        let setup_rate = rl.session_setup_rate;
        if !(setup_rate.is_finite() && setup_rate > 0.0) {
            return Err(ConfigError::Validation(format!(
                "`node.rate_limit.session_setup_rate` is {setup_rate}, but must be a finite value greater than 0; \
                 a non-positive or non-finite refill rate never replenishes a link's setup bucket, so that link stops establishing sessions once its initial burst is spent."
            )));
        }

        // The freshness window backstops session-id replay protection: an
        // offer evicted from the replay cache must already be too old to pass
        // the freshness check, or it can be accepted a second time. A signal
        // is acceptable over `signal_ttl_secs` plus the skew tolerance on each
        // side, so that span has to stay strictly inside `replay_window_secs`.
        // Checked regardless of `nostr.enabled`, for the reason the rekey
        // block above gives: enabling the feature later must not surface a
        // config error at a surprising moment.
        let skew_secs = FRESHNESS_SKEW_TOLERANCE_MS / 1000;
        let freshness_window_secs = nostr.signal_ttl_secs.saturating_add(2 * skew_secs);
        if freshness_window_secs >= nostr.replay_window_secs {
            return Err(ConfigError::Validation(format!(
                "`node.rendezvous.nostr.signal_ttl_secs` is {}, which with {skew_secs}s of clock-skew grace on each side makes a traversal signal acceptable over a {freshness_window_secs}s window, \
                 but `node.rendezvous.nostr.replay_window_secs` is {}. \
                 The freshness window must be strictly narrower than the replay window, or a session id evicted from the replay cache is still fresh enough to be accepted a second time. \
                 Raise `replay_window_secs` above {freshness_window_secs}, or lower `signal_ttl_secs`.",
                nostr.signal_ttl_secs, nostr.replay_window_secs
            )));
        }

        // Zero here is the same trap as `established_handshake_burst`: it
        // reads as "no limit" and in fact refuses every inbound offer. The
        // upper bound exists because the per-npub semaphore is built lazily
        // inside the intake path rather than at startup, so an oversized
        // value would panic there instead of failing loudly at load.
        if nostr.max_concurrent_offers_per_npub == 0 {
            return Err(ConfigError::Validation(
                "`node.rendezvous.nostr.max_concurrent_offers_per_npub` is 0, which refuses every inbound traversal offer rather than disabling the per-sender limit. \
                 Omit the key for the default, or set a positive allowance; `max_concurrent_incoming_offers` remains the outer bound."
                    .to_string(),
            ));
        }

        if nostr.max_concurrent_offers_per_npub > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConfigError::Validation(format!(
                "`node.rendezvous.nostr.max_concurrent_offers_per_npub` is {}, which exceeds the maximum {} permits a semaphore can hold. \
                 Use a value at or below `max_concurrent_incoming_offers`, which is the outer bound anything larger is inert against.",
                nostr.max_concurrent_offers_per_npub,
                tokio::sync::Semaphore::MAX_PERMITS
            )));
        }

        Ok(())
    }

    /// Serialize this configuration to YAML.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_empty_config() {
        let config = Config::new();
        assert!(config.node.identity.nsec.is_none());
        assert!(!config.has_identity());
    }

    #[test]
    fn test_parse_yaml_with_nsec() {
        let yaml = r#"
node:
  identity:
    nsec: nsec1qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxfnm5g9
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_some());
        assert!(config.has_identity());
    }

    /// The fips.yaml shipped in the OpenWrt package must keep parsing as the
    /// config schema evolves. Both the 802.11s mesh backhaul entries
    /// (docs/how-to/set-up-80211s-mesh-backhaul.md) and the open-access SSID
    /// entries (docs/how-to/set-up-open-access-ssid.md) ship commented out —
    /// one per radio, so dual-band routers can run either on both bands — so
    /// a stock install that never creates fips-mesh*/fips-ap* logs no
    /// per-boot bind warning; `fips-mesh-setup`/`fips-ap-setup` uncomment the
    /// matching block when they create the interface. Verify both states
    /// parse: as shipped (both inactive), and after the uncomment the helpers
    /// perform.
    #[test]
    fn shipped_openwrt_config_parses() {
        let yaml = include_str!("../../packaging/openwrt-ipk/files/etc/fips/fips.yaml");

        // As shipped: parses, and the mesh/ap entries are commented out (a
        // running daemon binds no fips-mesh*/fips-ap* transport, no warning).
        let config: Config = serde_yaml::from_str(yaml).expect("shipped OpenWrt fips.yaml");
        for name in ["mesh0", "mesh1", "ap0", "ap1"] {
            assert!(
                !config
                    .transports
                    .ethernet
                    .iter()
                    .any(|(n, _)| n == Some(name)),
                "{name} must ship commented out, not active, in fips.yaml"
            );
        }

        // What `fips-mesh-setup`/`fips-ap-setup` produce: uncomment each
        // block, which must still parse into a transport bound to the right
        // netdev.
        let uncommented =
            uncomment_transport_blocks(&uncomment_transport_blocks(yaml, "mesh"), "ap");
        let config: Config = serde_yaml::from_str(&uncommented)
            .expect("fips.yaml with mesh and ap transports uncommented");
        for (name, interface) in [
            ("mesh0", "fips-mesh0"),
            ("mesh1", "fips-mesh1"),
            ("ap0", "fips-ap0"),
            ("ap1", "fips-ap1"),
        ] {
            assert!(
                config
                    .transports
                    .ethernet
                    .iter()
                    .any(|(n, eth)| n == Some(name) && eth.interface == interface),
                "{name} entry missing after uncommenting shipped fips.yaml"
            );
        }
    }

    /// Mirror the setup helpers' block uncomment: strip the `    # ` prefix
    /// from each `# <prefix><N>:` header and its `    #   ` continuation
    /// lines, leaving every other comment untouched.
    fn uncomment_transport_blocks(yaml: &str, prefix: &str) -> String {
        let header = format!("    # {prefix}");
        let mut out = String::new();
        let mut in_block = false;
        for line in yaml.lines() {
            let is_header = line
                .strip_prefix(&header)
                .and_then(|r| r.strip_suffix(':'))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            if is_header {
                in_block = true;
                out.push_str(&line.replacen("    # ", "    ", 1));
            } else if in_block && line.starts_with("    #   ") {
                out.push_str(&line.replacen("    # ", "    ", 1));
            } else {
                in_block = false;
                out.push_str(line);
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn test_parse_yaml_with_hex() {
        let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_some());

        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_parse_yaml_empty() {
        let yaml = "";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_none());
    }

    #[test]
    fn test_parse_yaml_partial() {
        let yaml = r#"
node:
  identity: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_none());
    }

    #[test]
    fn test_merge_configs() {
        let mut base = Config::new();
        base.node.identity.nsec = Some("base_nsec".to_string());

        let mut override_config = Config::new();
        override_config.node.identity.nsec = Some("override_nsec".to_string());

        base.merge(override_config);
        assert_eq!(base.node.identity.nsec, Some("override_nsec".to_string()));
    }

    #[test]
    fn test_merge_preserves_base_when_override_empty() {
        let mut base = Config::new();
        base.node.identity.nsec = Some("base_nsec".to_string());

        let override_config = Config::new();

        base.merge(override_config);
        assert_eq!(base.node.identity.nsec, Some("base_nsec".to_string()));
    }

    #[test]
    fn test_create_identity_from_nsec() {
        let mut config = Config::new();
        config.node.identity.nsec =
            Some("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string());

        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_create_identity_generates_new() {
        let config = Config::new();
        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
        fs::write(&config_path, yaml).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        assert!(config.node.identity.nsec.is_some());
    }

    #[test]
    fn test_load_from_paths_merges() {
        let temp_dir = TempDir::new().unwrap();

        // Create two config files
        let low_priority = temp_dir.path().join("low.yaml");
        let high_priority = temp_dir.path().join("high.yaml");

        fs::write(
            &low_priority,
            r#"
node:
  identity:
    nsec: "low_priority_nsec"
"#,
        )
        .unwrap();

        fs::write(
            &high_priority,
            r#"
node:
  identity:
    nsec: "high_priority_nsec"
"#,
        )
        .unwrap();

        let paths = vec![low_priority.clone(), high_priority.clone()];
        let (config, loaded) = Config::load_from_paths(&paths).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(
            config.node.identity.nsec,
            Some("high_priority_nsec".to_string())
        );
    }

    #[test]
    fn test_load_skips_missing_files() {
        let temp_dir = TempDir::new().unwrap();
        let existing = temp_dir.path().join("exists.yaml");
        let missing = temp_dir.path().join("missing.yaml");

        fs::write(
            &existing,
            r#"
node:
  identity:
    nsec: "existing_nsec"
"#,
        )
        .unwrap();

        let paths = vec![missing, existing.clone()];
        let (config, loaded) = Config::load_from_paths(&paths).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], existing);
        assert_eq!(config.node.identity.nsec, Some("existing_nsec".to_string()));
    }

    #[test]
    fn test_search_paths_includes_expected() {
        let paths = Config::search_paths();

        // Should include current directory
        assert!(paths.iter().any(|p| p.ends_with("fips.yaml")));

        // Should always include /etc/fips as a system config path
        assert!(
            paths
                .iter()
                .any(|p| p.starts_with("/etc/fips") && p.ends_with("fips.yaml"))
        );

        // macOS and FreeBSD should also include /usr/local/etc/fips
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        assert!(
            paths
                .iter()
                .any(|p| p.starts_with("/usr/local/etc/fips") && p.ends_with("fips.yaml"))
        );
    }

    // --- legacy identity-key fallback ---
    //
    // Guards the regression the second system config directory introduces:
    // the key directory follows whichever config file loaded last, so a node
    // carrying config at both locations would find no key at the new one and
    // generate a fresh identity. These drive `legacy_key_fallback` with real
    // directories under a temp root rather than asserting on the constants,
    // and they run on every platform because the function takes both
    // directories as arguments.

    fn write_stub_key(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(KEY_FILENAME);
        std::fs::write(&p, "nsec1stub\n").unwrap();
        p
    }

    #[test]
    fn legacy_key_is_adopted_when_the_new_location_has_none() {
        let root = TempDir::new().unwrap();
        let legacy = root.path().join("etc/fips");
        let system = root.path().join("usr/local/etc/fips");
        std::fs::create_dir_all(&system).unwrap();
        let legacy_key = write_stub_key(&legacy);

        let key_path = system.join(KEY_FILENAME);
        assert_eq!(
            legacy_key_fallback(&key_path, &system, &legacy),
            Some(legacy_key),
            "a key stranded at the legacy path must be adopted, not regenerated"
        );
    }

    #[test]
    fn a_key_at_the_new_location_wins_over_the_legacy_one() {
        let root = TempDir::new().unwrap();
        let legacy = root.path().join("etc/fips");
        let system = root.path().join("usr/local/etc/fips");
        write_stub_key(&legacy);
        let key_path = write_stub_key(&system);

        assert_eq!(legacy_key_fallback(&key_path, &system, &legacy), None);
    }

    #[test]
    fn no_fallback_when_the_two_directories_are_the_same() {
        // The Linux case: nothing moved, so the fallback must be inert even
        // though a key exists at that one directory.
        let root = TempDir::new().unwrap();
        let dir = root.path().join("etc/fips");
        write_stub_key(&dir);
        let absent = dir.join("nonexistent").join(KEY_FILENAME);

        assert_eq!(legacy_key_fallback(&absent, &dir, &dir), None);
    }

    #[test]
    fn no_fallback_for_a_config_outside_the_system_directory() {
        // An operator running with ./fips.yaml or a user config must never be
        // silently redirected to a system key.
        let root = TempDir::new().unwrap();
        let legacy = root.path().join("etc/fips");
        let system = root.path().join("usr/local/etc/fips");
        let elsewhere = root.path().join("home/someone");
        std::fs::create_dir_all(&elsewhere).unwrap();
        write_stub_key(&legacy);

        let key_path = elsewhere.join(KEY_FILENAME);
        assert_eq!(legacy_key_fallback(&key_path, &system, &legacy), None);
    }

    #[test]
    fn no_fallback_when_the_legacy_location_is_empty_too() {
        let root = TempDir::new().unwrap();
        let legacy = root.path().join("etc/fips");
        let system = root.path().join("usr/local/etc/fips");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::create_dir_all(&system).unwrap();

        let key_path = system.join(KEY_FILENAME);
        assert_eq!(legacy_key_fallback(&key_path, &system, &legacy), None);
    }

    #[test]
    fn test_to_yaml() {
        let mut config = Config::new();
        config.node.identity.nsec = Some("test_nsec".to_string());

        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("node:"));
        assert!(yaml.contains("identity:"));
        assert!(yaml.contains("nsec:"));
        assert!(yaml.contains("test_nsec"));
    }

    #[test]
    fn test_key_file_write_read_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        let identity = crate::Identity::generate();
        let nsec = crate::encode_nsec(&identity.keypair().secret_key());

        write_key_file(&key_path, &nsec).unwrap();

        let loaded_nsec = read_key_file(&key_path).unwrap();
        assert_eq!(loaded_nsec, nsec);

        // Verify the loaded nsec produces the same identity
        let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
        assert_eq!(loaded_identity.npub(), identity.npub());
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions() {
        use std::os::unix::fs::MetadataExt;

        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        write_key_file(&key_path, "nsec1test").unwrap();

        let metadata = fs::metadata(&key_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_pub_file_permissions() {
        use std::os::unix::fs::MetadataExt;

        let temp_dir = TempDir::new().unwrap();
        let pub_path = temp_dir.path().join("fips.pub");

        write_pub_file(&pub_path, "npub1test").unwrap();

        let metadata = fs::metadata(&pub_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o644);
    }

    // `resolve_identity` reports its identity-loss conditions only in the log,
    // so the log is what these tests assert on.
    use crate::testutil::capture_logs;

    #[cfg(unix)]
    #[test]
    fn test_write_key_file_refuses_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let victim = temp_dir.path().join("victim");
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&victim, "victim contents\n").unwrap();
        std::os::unix::fs::symlink(&victim, &key_path).unwrap();

        let err = write_key_file(&key_path, "nsec1secret").unwrap_err();
        assert!(matches!(err, ConfigError::KeyPathIsSymlink { .. }), "{err}");

        assert_eq!(fs::read_to_string(&victim).unwrap(), "victim contents\n");
        assert!(
            key_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must be left in place, not replaced"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_write_key_file_fixes_existing_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&key_path, "nsec1old\n").unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        write_key_file(&key_path, "nsec1new").unwrap();

        assert_eq!(fs::metadata(&key_path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(read_key_file(&key_path).unwrap(), "nsec1new");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_pub_file_refuses_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let victim = temp_dir.path().join("victim");
        let pub_path = temp_dir.path().join("fips.pub");

        fs::write(&victim, "victim contents\n").unwrap();
        std::os::unix::fs::symlink(&victim, &pub_path).unwrap();

        let err = write_pub_file(&pub_path, "npub1test").unwrap_err();
        assert!(matches!(err, ConfigError::KeyPathIsSymlink { .. }), "{err}");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "victim contents\n");
    }

    #[test]
    fn test_ephemeral_over_existing_key_warns() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&config_path, "node:\n  identity: {}\n").unwrap();
        let identity = crate::Identity::generate();
        let existing = crate::encode_nsec(&identity.keypair().secret_key());
        write_key_file(&key_path, &existing).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let (resolved, logs) =
            capture_logs(|| resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap());

        assert_ne!(resolved.nsec, existing);
        let warnings = logs.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(&key_path.display().to_string())
                    && w.contains("node.identity.persistent")),
            "expected a warning naming the key path and the config key, got {warnings:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_ephemeral_dangling_symlink_detected() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");
        let key_path = temp_dir.path().join("fips.key");
        let target = temp_dir.path().join("absent-target");

        fs::write(&config_path, "node:\n  identity: {}\n").unwrap();
        std::os::unix::fs::symlink(&target, &key_path).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let (_resolved, logs) =
            capture_logs(|| resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap());

        let warnings = logs.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(&key_path.display().to_string())),
            "expected a warning naming the key path, got {warnings:?}"
        );
        assert!(
            !target.exists(),
            "the write must not have been followed through the dangling symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_persistent_permissive_key_warns() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();
        let identity = crate::Identity::generate();
        let nsec = crate::encode_nsec(&identity.keypair().secret_key());
        write_key_file(&key_path, &nsec).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let (resolved, logs) =
            capture_logs(|| resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap());

        // The key is still read: this warns, it does not refuse or repair.
        assert_eq!(resolved.nsec, nsec);
        let warnings = logs.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(&key_path.display().to_string()) && w.contains("0644")),
            "expected a warning naming the key path and its mode, got {warnings:?}"
        );
    }

    /// Healthy-path regression guard only. This passes against the pre-fix
    /// code vacuously, because that code warns about nothing at all, so it is
    /// not evidence that the fix works: it only catches a future change that
    /// starts warning on an ordinary first ephemeral start.
    #[test]
    fn test_ephemeral_first_run_does_not_warn() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let (_resolved, logs) =
            capture_logs(|| resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap());

        assert!(
            logs.warnings().is_empty(),
            "first ephemeral start must be silent, got {:?}",
            logs.warnings()
        );
    }

    #[test]
    fn test_key_file_empty_error() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&key_path, "").unwrap();

        let result = read_key_file(&key_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_key_file_whitespace_trimmed() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&key_path, "  nsec1test  \n").unwrap();

        let nsec = read_key_file(&key_path).unwrap();
        assert_eq!(nsec, "nsec1test");
    }

    #[test]
    fn test_key_file_path_derivation() {
        let config_path = PathBuf::from("/etc/fips/fips.yaml");
        assert_eq!(
            key_file_path(&config_path),
            PathBuf::from("/etc/fips/fips.key")
        );
        assert_eq!(
            pub_file_path(&config_path),
            PathBuf::from("/etc/fips/fips.pub")
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_key_file_write_read_roundtrip_windows() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        let identity = crate::Identity::generate();
        let nsec = crate::encode_nsec(&identity.keypair().secret_key());

        write_key_file(&key_path, &nsec).unwrap();

        // Verify file was created and can be read back
        let loaded_nsec = read_key_file(&key_path).unwrap();
        assert_eq!(loaded_nsec, nsec);

        // Verify the loaded nsec produces the same identity
        let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
        assert_eq!(loaded_identity.npub(), identity.npub());
    }

    #[test]
    fn test_resolve_identity_from_config() {
        let mut config = Config::new();
        config.node.identity.nsec =
            Some("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string());

        let resolved = resolve_identity(&config, &[]).unwrap();
        assert!(matches!(resolved.source, IdentitySource::Config));
    }

    #[test]
    fn test_resolve_identity_ephemeral_by_default() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

        let config = Config::load_file(&config_path).unwrap();
        assert!(!config.node.identity.persistent);

        let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
        assert!(matches!(resolved.source, IdentitySource::Ephemeral));

        // Key files should still be written for operator visibility
        let key_path = temp_dir.path().join("fips.key");
        let pub_path = temp_dir.path().join("fips.pub");
        assert!(key_path.exists());
        assert!(pub_path.exists());
    }

    #[test]
    fn test_resolve_identity_ephemeral_changes_each_call() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let first = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
        let second = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

        // Each call generates a different key
        assert_ne!(first.nsec, second.nsec);
    }

    #[test]
    fn test_resolve_identity_persistent_from_key_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

        // Write a key file
        let identity = crate::Identity::generate();
        let nsec = crate::encode_nsec(&identity.keypair().secret_key());
        write_key_file(&key_path, &nsec).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        assert!(config.node.identity.persistent);

        let resolved = resolve_identity(&config, &[config_path]).unwrap();
        assert!(matches!(resolved.source, IdentitySource::KeyFile(_)));
        assert_eq!(resolved.nsec, nsec);
    }

    #[test]
    fn test_resolve_identity_persistent_generates_and_persists() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

        assert!(matches!(resolved.source, IdentitySource::Generated(_)));

        // Key file and pub file should now exist
        let key_path = temp_dir.path().join("fips.key");
        let pub_path = temp_dir.path().join("fips.pub");
        assert!(key_path.exists());
        assert!(pub_path.exists());

        // Second resolve should load from key file (not generate new)
        let resolved2 = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
        assert!(matches!(resolved2.source, IdentitySource::KeyFile(_)));
        assert_eq!(resolved.nsec, resolved2.nsec);
    }

    #[test]
    fn test_to_yaml_empty_nsec_omitted() {
        let config = Config::new();
        let yaml = config.to_yaml().unwrap();

        // Empty nsec should not be serialized
        assert!(!yaml.contains("nsec:"));
    }

    #[test]
    fn test_parse_transport_single_instance() {
        let yaml = r#"
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    mtu: 1400
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.transports.udp.len(), 1);
        let instances: Vec<_> = config.transports.udp.iter().collect();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].0, None); // Single instance has no name
        assert_eq!(instances[0].1.bind_addr(), "0.0.0.0:2121");
        assert_eq!(instances[0].1.mtu(), 1400);
    }

    #[test]
    fn test_parse_transport_named_instances() {
        let yaml = r#"
transports:
  udp:
    main:
      bind_addr: "0.0.0.0:2121"
    backup:
      bind_addr: "192.168.1.100:2122"
      mtu: 1280
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.transports.udp.len(), 2);

        let instances: std::collections::HashMap<_, _> = config.transports.udp.iter().collect();

        // Named instances have Some(name)
        assert!(instances.contains_key(&Some("main")));
        assert!(instances.contains_key(&Some("backup")));
        assert_eq!(instances[&Some("main")].bind_addr(), "0.0.0.0:2121");
        assert_eq!(instances[&Some("backup")].bind_addr(), "192.168.1.100:2122");
        assert_eq!(instances[&Some("backup")].mtu(), 1280);
    }

    #[test]
    fn test_parse_transport_empty() {
        let yaml = r#"
transports: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.transports.udp.is_empty());
        assert!(config.transports.is_empty());
    }

    #[test]
    fn test_transport_instances_iter() {
        // Single instance - no name
        let single = TransportInstances::Single(UdpConfig {
            bind_addr: Some("0.0.0.0:2121".to_string()),
            mtu: None,
            ..Default::default()
        });
        let items: Vec<_> = single.iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, None);

        // Named instances - have names
        let mut map = HashMap::new();
        map.insert("a".to_string(), UdpConfig::default());
        map.insert("b".to_string(), UdpConfig::default());
        let named = TransportInstances::Named(map);
        let items: Vec<_> = named.iter().collect();
        assert_eq!(items.len(), 2);
        // All named instances should have Some(name)
        assert!(items.iter().all(|(name, _)| name.is_some()));
    }

    #[test]
    fn test_parse_peer_config() {
        let yaml = r#"
peers:
  - npub: "npub1abc123"
    alias: "gateway"
    addresses:
      - transport: udp
        addr: "192.168.1.1:2121"
        priority: 1
      - transport: tor
        addr: "xyz.onion:2121"
        priority: 2
    connect_policy: auto_connect
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.npub, "npub1abc123");
        assert_eq!(peer.alias, Some("gateway".to_string()));
        assert_eq!(peer.addresses.len(), 2);
        assert!(peer.is_auto_connect());

        // Check addresses are sorted by priority
        let sorted = peer.addresses_by_priority();
        assert_eq!(sorted[0].transport, "udp");
        assert_eq!(sorted[0].priority, 1);
        assert_eq!(sorted[1].transport, "tor");
        assert_eq!(sorted[1].priority, 2);
    }

    #[test]
    fn test_parse_peer_minimal() {
        let yaml = r#"
peers:
  - npub: "npub1xyz"
    addresses:
      - transport: udp
        addr: "10.0.0.1:2121"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.npub, "npub1xyz");
        assert!(peer.alias.is_none());
        // Default connect_policy is auto_connect
        assert!(peer.is_auto_connect());
        // Default priority is 100
        assert_eq!(peer.addresses[0].priority, 100);
    }

    #[test]
    fn test_parse_multiple_peers() {
        let yaml = r#"
peers:
  - npub: "npub1peer1"
    addresses:
      - transport: udp
        addr: "10.0.0.1:2121"
  - npub: "npub1peer2"
    addresses:
      - transport: udp
        addr: "10.0.0.2:2121"
    connect_policy: on_demand
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.auto_connect_peers().count(), 1);
    }

    #[test]
    fn test_peer_config_builder() {
        let peer = PeerConfig::new("npub1test", "udp", "192.168.1.1:2121")
            .with_alias("test-peer")
            .with_address(PeerAddress::with_priority("tor", "xyz.onion:2121", 50));

        assert_eq!(peer.npub, "npub1test");
        assert_eq!(peer.alias, Some("test-peer".to_string()));
        assert_eq!(peer.addresses.len(), 2);
        assert!(peer.is_auto_connect());
    }

    #[test]
    fn test_parse_legacy_discovery_nostr_config_compat() {
        // COMPAT (drop at the v2 cutover): a deprecated `node.discovery.nostr`
        // block must fold into `node.rendezvous.nostr` via normalize.
        let yaml = r#"
node:
  discovery:
    nostr:
      enabled: true
      advertise: false
      policy: configured_only
      open_discovery_max_pending: 12
      app: "fips.nat.test.v1"
      signal_ttl_secs: 45
      advert_relays:
        - "wss://relay-a.example"
      dm_relays:
        - "wss://relay-b.example"
      stun_servers:
        - "stun:stun.example.org:3478"
peers:
  - npub: "npub1peer"
    via_nostr: true
    addresses:
      - transport: udp
        addr: "nat"
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.normalize_deprecated_keys();
        assert!(config.node.rendezvous.nostr.enabled);
        assert!(!config.node.rendezvous.nostr.advertise);
        assert_eq!(config.node.rendezvous.nostr.app, "fips.nat.test.v1");
        assert_eq!(config.node.rendezvous.nostr.signal_ttl_secs, 45);
        assert_eq!(
            config.node.rendezvous.nostr.policy,
            NostrRendezvousPolicy::ConfiguredOnly
        );
        assert_eq!(config.node.rendezvous.nostr.open_discovery_max_pending, 12);
        assert_eq!(
            config.node.rendezvous.nostr.advert_relays,
            vec!["wss://relay-a.example".to_string()]
        );
        assert_eq!(
            config.node.rendezvous.nostr.dm_relays,
            vec!["wss://relay-b.example".to_string()]
        );
        assert_eq!(
            config.node.rendezvous.nostr.stun_servers,
            vec!["stun:stun.example.org:3478".to_string()]
        );
        assert_eq!(
            config.peers[0].addresses[0].addr, "nat",
            "udp:nat address should parse without special-casing in YAML"
        );
        assert!(config.peers[0].via_nostr);
    }

    #[test]
    fn test_parse_lookup_and_rendezvous_new_keys() {
        // The post-split keys parse directly, with no deprecated block and no
        // normalize warning.
        let yaml = r#"
node:
  lookup:
    ttl: 7
    attempt_timeouts_secs: [3, 6]
    forward_min_interval_secs: 9
  rendezvous:
    nostr:
      enabled: true
      app: "fips.new.keys.v1"
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.normalize_deprecated_keys();
        assert_eq!(config.node.lookup.ttl, 7);
        assert_eq!(config.node.lookup.attempt_timeouts_secs, vec![3, 6]);
        assert_eq!(config.node.lookup.forward_min_interval_secs, 9);
        // Unset scalar keeps its default.
        assert_eq!(config.node.lookup.recent_expiry_secs, 10);
        assert!(config.node.rendezvous.nostr.enabled);
        assert_eq!(config.node.rendezvous.nostr.app, "fips.new.keys.v1");
        assert!(config.node.discovery.is_none());
    }

    #[test]
    fn test_legacy_discovery_lookup_scalars_compat() {
        // COMPAT (drop at the v2 cutover): legacy `node.discovery` mesh-lookup
        // scalars must fold into `node.lookup`; unset keys keep their defaults.
        let yaml = r#"
node:
  discovery:
    ttl: 5
    backoff_base_secs: 4
    backoff_max_secs: 30
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.normalize_deprecated_keys();
        assert_eq!(config.node.lookup.ttl, 5);
        assert_eq!(config.node.lookup.backoff_base_secs, 4);
        assert_eq!(config.node.lookup.backoff_max_secs, 30);
        // Unset legacy scalar leaves the new-table default intact.
        assert_eq!(config.node.lookup.attempt_timeouts_secs, vec![1, 2, 4, 8]);
        // The compat block is consumed by normalize.
        assert!(config.node.discovery.is_none());
    }

    #[test]
    fn test_validate_transport_advert_requires_nostr_enabled() {
        let mut config = Config::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            advertise_on_nostr: Some(true),
            ..Default::default()
        });
        config.node.rendezvous.nostr.enabled = false;

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("advertise_on_nostr"));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_validate_peer_via_nostr_requires_nostr_enabled() {
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                via_nostr: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        config.node.rendezvous.nostr.enabled = false;

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("via_nostr"));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_validate_peer_addresses_required_unless_via_nostr() {
        // Empty addresses + via_nostr=false → error.
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("at least one address"));

        // Empty addresses + via_nostr=true + nostr.enabled=true → ok.
        config.peers[0].via_nostr = true;
        config.node.rendezvous.nostr.enabled = true;
        config
            .validate()
            .expect("via_nostr should allow empty addresses");
    }

    #[test]
    fn test_validate_nat_udp_advert_requires_relays_and_stun() {
        let mut config = Config::default();
        config.node.rendezvous.nostr.enabled = true;
        config.node.rendezvous.nostr.dm_relays.clear();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            advertise_on_nostr: Some(true),
            public: Some(false),
            ..Default::default()
        });

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("dm_relays"));

        config.node.rendezvous.nostr.dm_relays = vec!["wss://relay.example".to_string()];
        config.node.rendezvous.nostr.stun_servers.clear();
        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("stun_servers"));
    }

    #[test]
    fn test_is_loopback_addr_str() {
        assert!(is_loopback_addr_str("127.0.0.1:2121"));
        assert!(is_loopback_addr_str("127.0.0.5:9999"));
        assert!(is_loopback_addr_str("[::1]:2121"));
        assert!(is_loopback_addr_str("::1:2121"));
        assert!(is_loopback_addr_str("localhost:80"));
        assert!(!is_loopback_addr_str("0.0.0.0:2121"));
        assert!(!is_loopback_addr_str("192.168.1.1:2121"));
        assert!(!is_loopback_addr_str("[fd00::1]:2121"));
        assert!(!is_loopback_addr_str("core-vm.tail65015.ts.net:2121"));
        assert!(!is_loopback_addr_str("example.com:443"));
    }

    #[test]
    fn test_a_peer_address_naming_a_configured_udp_instance_passes_validation() {
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                addresses: vec![PeerAddress::new("udp/aware", "203.0.113.1:2121")],
                ..Default::default()
            }],
            ..Default::default()
        };
        config.transports.udp = TransportInstances::Named(HashMap::from([
            ("aware".to_string(), UdpConfig::default()),
            ("infra".to_string(), UdpConfig::default()),
        ]));

        config
            .validate()
            .expect("an instance name that matches a configured transport must validate");
    }

    #[test]
    fn test_a_peer_address_naming_an_unconfigured_udp_instance_is_rejected() {
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                addresses: vec![PeerAddress::new("udp/awre", "203.0.113.1:2121")],
                ..Default::default()
            }],
            ..Default::default()
        };
        config.transports.udp = TransportInstances::Named(HashMap::from([
            ("aware".to_string(), UdpConfig::default()),
            ("infra".to_string(), UdpConfig::default()),
        ]));

        let err = config
            .validate()
            .expect_err("a typo in an instance name must not validate");
        let text = err.to_string();
        assert!(
            text.contains("awre"),
            "the error must name the instance asked for: {text}"
        );
        assert!(
            text.contains("aware") && text.contains("infra"),
            "the error must list the instances that do exist: {text}"
        );
    }

    #[test]
    fn test_an_unqualified_peer_address_still_validates_against_named_instances() {
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                addresses: vec![PeerAddress::new("udp", "203.0.113.1:2121")],
                ..Default::default()
            }],
            ..Default::default()
        };
        config.transports.udp =
            TransportInstances::Named(HashMap::from([("aware".to_string(), UdpConfig::default())]));

        config
            .validate()
            .expect("a bare type matches any instance and must stay valid");
    }

    #[test]
    fn test_a_qualified_peer_address_is_rejected_when_the_udp_transport_is_unnamed() {
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                addresses: vec![PeerAddress::new("udp/aware", "203.0.113.1:2121")],
                ..Default::default()
            }],
            ..Default::default()
        };
        config.transports.udp = TransportInstances::Single(UdpConfig::default());

        let err = config
            .validate()
            .expect_err("a Single config has no instance name to match and must not validate");
        assert!(
            err.to_string().contains("no named udp instances"),
            "the error must say why nothing matched: {err}"
        );
    }

    #[test]
    fn test_a_qualified_peer_address_on_a_non_udp_transport_is_rejected() {
        let config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                addresses: vec![PeerAddress::new("ethernet/eth0", "eth0/aa:bb:cc:dd:ee:ff")],
                ..Default::default()
            }],
            ..Default::default()
        };

        let err = config
            .validate()
            .expect_err("only udp resolves an instance name, so any other type must be refused");
        assert!(
            err.to_string().contains("only `udp` resolves"),
            "the error must say which transport types support the syntax: {err}"
        );
    }

    #[test]
    fn test_validate_loopback_bind_with_external_peer_rejected() {
        use crate::config::PeerAddress;
        let mut config = Config::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            ..Default::default()
        });
        config.peers = vec![PeerConfig {
            npub: "npub1peer".to_string(),
            addresses: vec![PeerAddress::new("udp", "core-vm.tail65015.ts.net:2121")],
            ..Default::default()
        }];

        let err = config.validate().expect_err("validation should fail");
        let msg = err.to_string();
        assert!(msg.contains("loopback"), "got: {msg}");
        assert!(msg.contains("non-loopback"), "got: {msg}");
    }

    #[test]
    fn test_validate_loopback_bind_with_loopback_peer_ok() {
        use crate::config::PeerAddress;
        let mut config = Config::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            ..Default::default()
        });
        config.peers = vec![PeerConfig {
            npub: "npub1peer".to_string(),
            addresses: vec![PeerAddress::new("udp", "127.0.0.2:2121")],
            ..Default::default()
        }];

        config
            .validate()
            .expect("loopback peer with loopback bind should validate");
    }

    #[test]
    fn test_validate_outbound_only_exempt_from_loopback_check() {
        use crate::config::PeerAddress;
        let mut config = Config::default();
        // outbound_only overrides bind_addr → 0.0.0.0:0; the loopback
        // check must skip this transport entirely.
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            outbound_only: Some(true),
            ..Default::default()
        });
        config.peers = vec![PeerConfig {
            npub: "npub1peer".to_string(),
            addresses: vec![PeerAddress::new("udp", "core-vm.tail65015.ts.net:2121")],
            ..Default::default()
        }];

        config
            .validate()
            .expect("outbound_only should be exempt from the loopback check");
    }

    #[test]
    fn test_validate_default_rekey_settings_ok() {
        Config::default()
            .validate()
            .expect("shipped default rekey settings must validate");
    }

    #[test]
    fn test_validate_established_burst_zero_rejected() {
        let mut config = Config::default();
        config.node.rate_limit.established_handshake_burst = Some(0);

        let err = config.validate().expect_err("validation should fail");
        let msg = err.to_string();
        assert!(msg.contains("established_handshake_burst"), "got: {msg}");
    }

    #[test]
    fn test_validate_established_rate_non_positive_rejected() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut config = Config::default();
            config.node.rate_limit.established_handshake_rate = Some(bad);

            let err = config
                .validate()
                .expect_err(&format!("validation should fail for {bad}"));
            let msg = err.to_string();
            assert!(
                msg.contains("established_handshake_rate"),
                "for {bad}, got: {msg}"
            );
        }
    }

    #[test]
    fn test_validate_established_bucket_absent_and_positive_accepted() {
        // Absent is the normal path (derived from max_peers) and must validate.
        Config::default()
            .validate()
            .expect("omitted established-bucket keys must validate");

        let mut config = Config::default();
        config.node.rate_limit.established_handshake_burst = Some(1);
        config.node.rate_limit.established_handshake_rate = Some(0.5);
        config
            .validate()
            .expect("positive established-bucket values must validate");
    }

    #[test]
    fn test_validate_rekey_after_messages_zero_rejected() {
        let mut config = Config::default();
        config.node.rekey.after_messages = 0;

        let err = config.validate().expect_err("validation should fail");
        let msg = err.to_string();
        assert!(msg.contains("after_messages"), "got: {msg}");
    }

    #[test]
    fn test_validate_rekey_after_messages_one_accepted() {
        let mut config = Config::default();
        config.node.rekey.after_messages = 1;

        config
            .validate()
            .expect("after_messages = 1 rekeys every message, which is wasteful but well defined");
    }

    #[test]
    fn test_validate_rekey_after_secs_at_or_below_jitter_rejected() {
        let jitter = REKEY_JITTER_SECS.unsigned_abs();

        for after_secs in [0, 1, jitter - 1, jitter] {
            let mut config = Config::default();
            config.node.rekey.after_secs = after_secs;

            match config.validate() {
                Err(e) => assert!(e.to_string().contains("after_secs"), "got: {e}"),
                Ok(()) => panic!("after_secs = {after_secs} should be rejected"),
            }
        }
    }

    #[test]
    fn test_validate_rekey_after_secs_just_above_jitter_accepted() {
        let mut config = Config::default();
        config.node.rekey.after_secs = REKEY_JITTER_SECS.unsigned_abs() + 1;

        config
            .validate()
            .expect("one second above the jitter bound leaves a non-zero effective interval");
    }

    #[test]
    fn test_validate_rekey_unbounded_values_accepted() {
        let mut config = Config::default();
        config.node.rekey.after_secs = u64::MAX;
        config.node.rekey.after_messages = u64::MAX;

        config
            .validate()
            .expect("u64::MAX disables an arm of the trigger and must stay legal");
    }

    #[test]
    fn test_validate_rekey_checked_even_when_disabled() {
        let mut config = Config::default();
        config.node.rekey.enabled = false;
        config.node.rekey.after_messages = 0;

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("after_messages"));

        let mut config = Config::default();
        config.node.rekey.enabled = false;
        config.node.rekey.after_secs = REKEY_JITTER_SECS.unsigned_abs();

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("after_secs"));
    }

    #[test]
    fn test_validate_signal_ttl_at_or_above_the_replay_window_margin_rejected() {
        // 180 is the boundary: 180 + 2 * 60 = 300, which is not strictly less
        // than the default 300s replay window.
        for signal_ttl_secs in [180, 181, 3600, u64::MAX] {
            let mut config = Config::default();
            config.node.rendezvous.nostr.signal_ttl_secs = signal_ttl_secs;

            match config.validate() {
                Err(e) => {
                    let msg = e.to_string();
                    assert!(msg.contains("signal_ttl_secs"), "got: {msg}");
                    assert!(msg.contains("replay_window_secs"), "got: {msg}");
                }
                Ok(()) => panic!("signal_ttl_secs = {signal_ttl_secs} should be rejected"),
            }
        }
    }

    #[test]
    fn test_validate_signal_ttl_just_inside_the_replay_window_margin_accepted() {
        let mut config = Config::default();
        config.node.rendezvous.nostr.signal_ttl_secs = 179;

        config
            .validate()
            .expect("179 + 2 * 60 = 299 leaves the freshness window inside the 300s replay window");
    }

    #[test]
    fn test_validate_per_npub_offer_allowance_of_zero_rejected() {
        let mut config = Config::default();
        config.node.rendezvous.nostr.max_concurrent_offers_per_npub = 0;

        let err = config.validate().expect_err("validation should fail");
        assert!(
            err.to_string().contains("max_concurrent_offers_per_npub"),
            "got: {err}"
        );
    }

    #[test]
    fn test_validate_per_npub_offer_allowance_of_one_accepted() {
        let mut config = Config::default();
        config.node.rendezvous.nostr.max_concurrent_offers_per_npub = 1;

        config
            .validate()
            .expect("an allowance of one offer per sender is restrictive but well defined");
    }

    #[test]
    fn test_validate_shipped_defaults_satisfy_the_freshness_invariant() {
        Config::default()
            .validate()
            .expect("the shipped defaults must satisfy every validation rule");

        // Stated against the constant rather than a literal, so this reds if
        // anyone changes FRESHNESS_SKEW_TOLERANCE_MS or either default without
        // re-checking the relation they jointly have to satisfy.
        let defaults = Config::default();
        let nostr = &defaults.node.rendezvous.nostr;
        assert!(
            nostr.signal_ttl_secs + 2 * (FRESHNESS_SKEW_TOLERANCE_MS / 1000)
                < nostr.replay_window_secs
        );
    }

    #[test]
    fn test_outbound_only_forces_ephemeral_bind() {
        let cfg = UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            outbound_only: Some(true),
            ..Default::default()
        };
        assert_eq!(cfg.bind_addr(), "0.0.0.0:0");
        assert!(cfg.outbound_only());
    }

    #[test]
    fn test_outbound_only_forces_advertise_off() {
        let cfg = UdpConfig {
            advertise_on_nostr: Some(true),
            outbound_only: Some(true),
            ..Default::default()
        };
        assert!(!cfg.advertise_on_nostr());
    }

    #[test]
    fn test_udp_accept_connections_default_true() {
        let cfg = UdpConfig::default();
        assert!(cfg.accept_connections());
    }

    #[cfg(unix)]
    #[test]
    fn test_privileged_macos_bootstraps_private_var_run_path() {
        let path = resolve_default_socket_with(
            "control.sock",
            VarRunPolicy {
                consult_existing: true,
                create_private_dir: true,
            },
            Some(Path::new("/valid/xdg")),
            |candidate| matches!(candidate.to_str(), Some("/var/run" | "/valid/xdg")),
        );

        assert_eq!(path, "/var/run/fips/control.sock");
    }

    #[cfg(unix)]
    #[test]
    fn test_non_privileged_macos_uses_xdg_before_private_var_run_exists() {
        let path = resolve_default_socket_with(
            "control.sock",
            VarRunPolicy {
                consult_existing: true,
                create_private_dir: false,
            },
            Some(Path::new("/valid/xdg")),
            |candidate| candidate == Path::new("/valid/xdg"),
        );

        assert_eq!(path, "/valid/xdg/fips/control.sock");
    }

    #[cfg(unix)]
    #[test]
    fn test_clients_follow_existing_private_var_run_path() {
        let path = resolve_default_socket_with(
            "control.sock",
            VarRunPolicy {
                consult_existing: true,
                create_private_dir: false,
            },
            Some(Path::new("/valid/xdg")),
            |candidate| matches!(candidate.to_str(), Some("/var/run/fips" | "/valid/xdg")),
        );

        assert_eq!(path, "/var/run/fips/control.sock");
    }

    #[cfg(unix)]
    #[test]
    fn test_linux_policy_ignores_var_run_fips() {
        let path = resolve_default_socket_with(
            "control.sock",
            VarRunPolicy {
                consult_existing: false,
                create_private_dir: false,
            },
            Some(Path::new("/valid/xdg")),
            |candidate| matches!(candidate.to_str(), Some("/var/run/fips" | "/valid/xdg")),
        );

        assert_eq!(path, "/valid/xdg/fips/control.sock");
    }

    #[cfg(unix)]
    #[test]
    fn test_managed_socket_parent_matches_only_resolver_candidates() {
        let policy = VarRunPolicy {
            consult_existing: true,
            create_private_dir: true,
        };

        assert!(is_managed_socket_parent_with(
            Path::new("/run/fips"),
            policy,
            Some(Path::new("/valid/xdg")),
        ));
        assert!(is_managed_socket_parent_with(
            Path::new("/var/run/fips"),
            policy,
            Some(Path::new("/valid/xdg")),
        ));
        assert!(is_managed_socket_parent_with(
            Path::new("/valid/xdg/fips"),
            policy,
            Some(Path::new("/valid/xdg")),
        ));
        assert!(!is_managed_socket_parent_with(
            Path::new("/tmp"),
            policy,
            Some(Path::new("/valid/xdg")),
        ));
        assert!(!is_managed_socket_parent_with(
            Path::new("/srv/application/fips"),
            policy,
            Some(Path::new("/valid/xdg")),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_linux_managed_socket_parent_excludes_var_run() {
        let linux_policy = VarRunPolicy {
            consult_existing: false,
            create_private_dir: false,
        };

        assert!(!is_managed_socket_parent_with(
            Path::new("/var/run/fips"),
            linux_policy,
            None,
        ));
    }

    /// Mutex serializing tests that mutate `XDG_RUNTIME_DIR`. `cargo test`
    /// runs tests on multiple threads in the same process, and env mutation
    /// is process-global, so concurrent env-touching tests would race.
    #[cfg(unix)]
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn test_resolve_default_socket_call_sites_agree() {
        // The three resolver call sites must all produce strings that agree
        // on the directory, differing only in the filename suffix.
        let _g = ENV_MUTEX.lock().unwrap();

        let control_client = default_control_path().to_string_lossy().into_owned();
        let gateway_client = default_gateway_path().to_string_lossy().into_owned();
        let control_daemon = ControlConfig::default().socket_path;

        // Daemon-side and client-side control paths must be identical.
        assert_eq!(
            control_daemon, control_client,
            "daemon and client default control-socket paths diverged: \
             daemon={control_daemon}, client={control_client}"
        );

        // Control and gateway must share a parent directory (or /tmp prefix).
        let control_dir = std::path::Path::new(&control_client)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let gateway_dir = std::path::Path::new(&gateway_client)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert_eq!(
            control_dir, gateway_dir,
            "control and gateway default-socket paths picked different directories: \
             control={control_client}, gateway={gateway_client}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_default_socket_xdg_when_no_run_fips() {
        // With /run/fips absent and XDG_RUNTIME_DIR pointing at an
        // existing directory, the resolver picks XDG. On test hosts where
        // /run/fips happens to exist (a real fips deployment), the
        // resolver legitimately picks /run/fips and skips XDG entirely;
        // both outcomes are accepted below.
        let _g = ENV_MUTEX.lock().unwrap();

        let temp_dir = TempDir::new().unwrap();
        let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        // SAFETY: serialized via ENV_MUTEX above.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());
        }

        let path = resolve_default_socket("control.sock");

        // Restore env before asserting so a panic doesn't leak state.
        unsafe {
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }

        // If /run/fips happens to be writable in the test environment (CI
        // running as root, for instance), the resolver legitimately picks
        // /run/fips and skips XDG entirely — likewise /var/run/fips on
        // macOS/FreeBSD. Accept either outcome but demand that one of the
        // canonical prefixes is chosen — never /tmp when XDG was valid.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let canonical_var_run = path.starts_with("/var/run/fips/");
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        let canonical_var_run = false;
        assert!(
            path.starts_with("/run/fips/")
                || canonical_var_run
                || path.starts_with(&format!("{}/fips/", temp_dir.path().display())),
            "expected /run/fips, /var/run/fips, or XDG path, got: {path}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_default_socket_tmp_when_xdg_invalid() {
        // With XDG_RUNTIME_DIR pointing at a non-existent directory and
        // /run/fips absent, the resolver falls through to /tmp. On hosts
        // where /run/fips exists, the resolver legitimately picks it
        // first; both outcomes are accepted below.
        let _g = ENV_MUTEX.lock().unwrap();

        let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        // Use a path that definitely does not exist.
        let bogus = "/nonexistent-xdg-runtime-dir-for-fips-test-zzz";
        // SAFETY: serialized via ENV_MUTEX.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", bogus);
        }

        let path = resolve_default_socket("gateway.sock");

        unsafe {
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }

        // Accept /run/fips/ (test running as root with that dir
        // writable), /var/run/fips/ on macOS/FreeBSD, or /tmp/fips-...
        // (the dev-machine fallback). Never accept the bogus XDG dir
        // leaking through.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let canonical_var_run = path.starts_with("/var/run/fips/");
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        let canonical_var_run = false;
        assert!(
            path.starts_with("/run/fips/") || canonical_var_run || path == "/tmp/fips-gateway.sock",
            "expected /run/fips, /var/run/fips, or /tmp fallback, got: {path}"
        );
        assert!(
            !path.starts_with(bogus),
            "stale/invalid XDG_RUNTIME_DIR leaked into resolver: {path}"
        );
    }
}
