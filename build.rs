use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Git commit hash (short)
    let git_hash = git(&["rev-parse", "--short=10", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=FIPS_GIT_HASH={git_hash}");

    // Dirty working tree
    let dirty = git(&["status", "--porcelain"])
        .map(|out| !out.is_empty())
        .unwrap_or(false);
    if dirty {
        println!("cargo:rustc-env=FIPS_GIT_DIRTY=-dirty");
    } else {
        println!("cargo:rustc-env=FIPS_GIT_DIRTY=");
    }

    // Build target triple
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=FIPS_TARGET={target}");
    }

    // Rebuild when commits change
    watch_head();

    // Support reproducible builds (Debian packaging)
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    // bluer/BlueZ is glibc-linux only: musl cross-compiles (OpenWrt) can't
    // satisfy libdbus-sys's pkg-config cross-compile requirement, and musl
    // router targets don't run BlueZ by default anyway.
    println!("cargo:rustc-check-cfg=cfg(bluer_available)");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let bluer_available = target_os == "linux" && target_env != "musl";
    if bluer_available {
        println!("cargo:rustc-cfg=bluer_available");
    }

    // Whether the BLE transport is compiled at all.
    //
    // This is the set of platforms that have a concrete `BleIo` backend, not
    // the set that could plausibly have one. A platform listed here with no
    // backend behind it does not get "BLE, degraded" — it gets an in-memory
    // transport that starts, reports itself up and never peers, with no error
    // anywhere. Add a platform here only in the same change that adds its
    // backend; `transport::ble` carries a compile-time tripwire that refuses
    // a build where the two disagree.
    println!("cargo:rustc-check-cfg=cfg(ble_available)");
    if bluer_available || target_os == "android" || target_os == "macos" {
        println!("cargo:rustc-cfg=ble_available");
    }

    // CoreBluetooth is privacy-gated (TCC). A process that touches it without
    // an `NSBluetoothAlwaysUsageDescription` in its Info.plist is killed on
    // the spot, and a bare executable has no bundle to carry one — so embed
    // the plist in the binary's `__TEXT,__info_plist` section, where the OS
    // looks for an unbundled tool's.
    if target_os == "macos" {
        let plist = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("packaging/macos/Info.plist");
        println!("cargo:rerun-if-changed={}", plist.display());
        println!(
            "cargo:rustc-link-arg-bin=fips=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            plist.display()
        );
    }
}

/// Run git in the package directory and return its trimmed output, or `None`
/// when git is absent or fails.
fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Resolve a path inside the git directory, as `git rev-parse --git-path`
/// maps it: per-worktree files such as `HEAD` to the worktree's own git
/// directory, shared ones such as refs to the common directory.
fn git_path(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(git(&["rev-parse", "--git-path", name])?);
    let root = std::env::var_os("CARGO_MANIFEST_DIR")?;
    Some(Path::new(&root).join(path))
}

/// Ask cargo to rerun this script when `path` changes.
fn rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

/// Emit rerun triggers that fire when the tree moves to another commit.
///
/// The paths come from git, because `.git` is a directory in a normal
/// checkout but a file in a worktree. Only paths that exist are emitted:
/// cargo counts a missing one as changed, which would rerun the script, and
/// recompile this crate, on every build. With no git (a source tarball, or a
/// container that cannot see a worktree's git directory) nothing is watched,
/// since there is no commit to track.
fn watch_head() {
    // A detached HEAD holds the commit itself, so this file alone covers it.
    let Some(head) = git_path("HEAD").filter(|p| p.is_file()) else {
        return;
    };
    rerun_if_changed(&head);

    let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) else {
        return;
    };
    let Some(loose) = git_path(&branch) else {
        return;
    };
    if loose.is_file() {
        // A commit rewrites the loose ref.
        rerun_if_changed(&loose);
        return;
    }
    // The branch is packed. The next commit on it writes a loose ref, which
    // changes the nearest directory that exists on the way to it.
    if let Some(refs) = git_path("refs") {
        let dir = loose
            .ancestors()
            .skip(1)
            .take_while(|p| p.starts_with(&refs))
            .find(|p| p.is_dir());
        if let Some(dir) = dir {
            rerun_if_changed(dir);
        }
    }
    for name in ["packed-refs", "reftable"] {
        if let Some(path) = git_path(name).filter(|p| p.exists()) {
            rerun_if_changed(&path);
        }
    }
}
