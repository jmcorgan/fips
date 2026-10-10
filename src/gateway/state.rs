//! The pool state the gateway keeps across a restart.
//!
//! The pool writes which addresses a client may still hold an answer for,
//! and how far it may issue, to a file on tmpfs. The next run reads it once,
//! holds those addresses until the answers have expired, and so never hands a
//! cached address to a different node. The file holds no identities and no
//! mappings. It lives only on tmpfs, so a reboot, which ends every client's
//! cache with it, starts from nothing.
//!
//! A file is trusted for one start only: loading it removes it, and a write
//! that fails removes it too, so a start never replays a stretch the run that
//! wrote it has already issued past.

use super::pool::{PoolError, PoolStart, PoolState, VirtualIpPool};
use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Directory the state file is written to.
pub const STATE_DIR: &str = "/var/run/fips-gateway";

/// The state file's name in `STATE_DIR`.
const STATE_FILE: &str = "pool.json";

/// The file a write goes to before it replaces `STATE_FILE`.
const STATE_TMP: &str = "pool.json.tmp";

/// Longest hold a loaded state may impose on the next run.
///
/// It bounds the hold a state file can set. The legitimate load it must
/// exceed is the largest hold a run can write, the DNS TTL plus the grace
/// period, each at most `u32::MAX` seconds. An attacker gains nothing from
/// it: only a local user able to write the state directory can set the hold,
/// and the worst they get is new names refused for that long, an outage they
/// could cause by other means. The value is derived, not measured, and small
/// enough that adding it to an `Instant` cannot overflow on any supported
/// target.
const RESTART_HOLD_MAX_AGE: Duration = Duration::from_secs(2 * u32::MAX as u64);

/// What a start found in the state directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// No state file.
    Absent,
    /// A valid state for this pool.
    Restored(PoolState),
    /// A file that cannot be used, and why.
    Invalid(String),
}

/// Read the state for pool `cidr` of `total` addresses from `dir`, and
/// remove the file.
///
/// Whatever the file holds, it is removed before this returns; a file that
/// cannot be removed is reported as invalid, so it is never trusted twice.
pub fn load(dir: &Path, cidr: &str, total: u32) -> Loaded {
    let path = dir.join(STATE_FILE);
    let read = match fs::read(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Loaded::Absent,
        read => read,
    };
    if let Err(e) = fs::remove_file(&path)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Loaded::Invalid(format!("cannot remove the state file: {e}"));
    }
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(e) => return Loaded::Invalid(format!("cannot read the state file: {e}")),
    };
    let state: PoolState = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(e) => return Loaded::Invalid(format!("cannot parse the state file: {e}")),
    };
    match validate(&state, cidr, total) {
        Ok(()) => Loaded::Restored(state),
        Err(reason) => Loaded::Invalid(reason),
    }
}

/// Why `state` cannot start pool `cidr` of `total` addresses, if it cannot.
fn validate(state: &PoolState, cidr: &str, total: u32) -> Result<(), String> {
    if state.version != 1 {
        return Err(format!("unknown state version {}", state.version));
    }
    if state.pool != cidr || state.total != total {
        return Err(format!(
            "state is for pool {} of {} addresses, not {cidr} of {total}",
            state.pool, state.total
        ));
    }
    if !(1..=total).contains(&state.from) {
        return Err(format!("offset {} is outside the pool", state.from));
    }
    if state.span > total {
        return Err(format!("stretch of {} exceeds the pool", state.span));
    }
    let mut previous = 0;
    for [first, last] in &state.held {
        if *first <= previous || first > last || *last > total {
            return Err(format!(
                "held range {first}-{last} is out of order or outside the pool"
            ));
        }
        previous = *last;
    }
    if state.hold_secs > RESTART_HOLD_MAX_AGE.as_secs() {
        return Err(format!(
            "hold of {} s exceeds {} s",
            state.hold_secs,
            RESTART_HOLD_MAX_AGE.as_secs()
        ));
    }
    Ok(())
}

/// How the pool starts from what was loaded: from the state when there is
/// one, otherwise fresh at `random`.
pub fn start_from(loaded: Loaded, random: u32) -> PoolStart {
    match loaded {
        Loaded::Restored(state) => PoolStart::Restored(state),
        Loaded::Absent | Loaded::Invalid(_) => PoolStart::Fresh { offset: random },
    }
}

/// A pool started from the state directory.
pub struct Started {
    /// The pool.
    pub pool: VirtualIpPool,
    /// What the start found in the state directory.
    pub loaded: Loaded,
    /// How writing a restored pool's holds back went, when it was tried.
    pub carried: Option<io::Result<()>>,
}

/// Start pool `cidr` of `total` addresses at `now` from the state in `dir`,
/// fresh at `random` when there is none, and write a restored pool's holds
/// back at once.
///
/// Loading removes the file, and the first write that lets the pool issue
/// comes only after the start steps that can fail. Without the write back, a
/// start ending between the two, or killed there, would leave no file, and
/// the next start would reissue addresses clients may still hold. It carries
/// no stretch, so a start that keeps failing never adds to what the next one
/// holds.
#[allow(clippy::too_many_arguments)]
pub fn start_pool(
    dir: &Path,
    cidr: &str,
    total: u32,
    ttl_secs: u64,
    grace_secs: u64,
    random: u32,
    now: Instant,
    on_tmpfs: impl Fn(&Path) -> io::Result<bool>,
) -> Result<Started, PoolError> {
    let loaded = load(dir, cidr, total);
    let start = start_from(loaded.clone(), random);
    let pool = VirtualIpPool::start(cidr, ttl_secs, grace_secs, start, now)?;
    let carried = pool.carry_state().map(|state| save(dir, &state, on_tmpfs));
    Ok(Started {
        pool,
        loaded,
        carried,
    })
}

/// Write `state` to `dir`, which must lie on tmpfs.
///
/// Refuses when `dir`'s parent does not exist (it never creates `/var/run`)
/// or is not on tmpfs, as `on_tmpfs` reports, so nothing reaches persistent
/// storage. Creates `dir` with mode 0700, checks it again, and writes the
/// file with mode 0600 through a rename. Any failure removes the state file,
/// so the next start begins fresh rather than from an older state.
pub fn save(
    dir: &Path,
    state: &PoolState,
    on_tmpfs: impl Fn(&Path) -> io::Result<bool>,
) -> io::Result<()> {
    let result = write_state(dir, state, on_tmpfs);
    if result.is_err() {
        for name in [STATE_FILE, STATE_TMP] {
            // Unlinking needs no free space, so this works when the write
            // failed for lack of it.
            let _ = fs::remove_file(dir.join(name));
        }
    }
    result
}

/// The steps of `save`, without its clean-up on failure.
fn write_state(
    dir: &Path,
    state: &PoolState,
    on_tmpfs: impl Fn(&Path) -> io::Result<bool>,
) -> io::Result<()> {
    let parent = dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", dir.display()),
        )
    })?;
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} does not exist", parent.display()),
        ));
    }
    require_tmpfs(parent, &on_tmpfs)?;
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    // A bind mount could put the directory on other storage than its parent.
    require_tmpfs(dir, &on_tmpfs)?;

    let bytes = serde_json::to_vec(state).map_err(io::Error::other)?;
    let tmp = dir.join(STATE_TMP);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    drop(file);
    fs::rename(&tmp, dir.join(STATE_FILE))
}

/// Fail unless `path` is on tmpfs.
fn require_tmpfs(path: &Path, on_tmpfs: &impl Fn(&Path) -> io::Result<bool>) -> io::Result<()> {
    if on_tmpfs(path)? {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} is not on tmpfs; pool state is kept only on tmpfs",
            path.display()
        )))
    }
}

/// Whether `path` lies on a tmpfs file system.
// `f_type` and `TMPFS_MAGIC` differ in type across targets (`c_long` on most
// Linux targets, `c_uint` on s390x, and `f_type`'s width differs between
// glibc and musl), so both are cast to one type; on targets where one is
// already that type the cast is a no-op.
#[allow(clippy::unnecessary_cast)]
pub fn is_tmpfs(path: &Path) -> io::Result<bool> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: an all-zero statfs is valid; statfs fills it in.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a NUL-terminated string and `stat` is a statfs the
    // call may write.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_type as i64 == libc::TMPFS_MAGIC as i64)
}

/// Logs state writes once per change of outcome.
///
/// A gateway whose state directory is not on tmpfs, as in most containers,
/// fails every write the same way, so one warning per process is enough.
#[derive(Debug, Default)]
pub struct SaveLog {
    last_failure: Option<String>,
}

impl SaveLog {
    /// Log the outcome of a write.
    pub fn report(&mut self, result: &io::Result<()>) {
        match result {
            Err(e) => {
                let text = e.to_string();
                if self.last_failure.as_deref() == Some(text.as_str()) {
                    debug!(error = %e, "Pool state not saved");
                } else {
                    warn!(
                        error = %e,
                        "Pool state not saved; after a restart only a random starting address protects answers clients still hold"
                    );
                }
                self.last_failure = Some(text);
            }
            Ok(()) => {
                if self.last_failure.take().is_some() {
                    info!("Pool state saved again");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> PoolState {
        PoolState {
            version: 1,
            pool: "fd01::/120".to_string(),
            total: 255,
            from: 10,
            span: 20,
            held: vec![[1, 3], [7, 7]],
            hold_secs: 120,
        }
    }

    /// A state directory inside a fresh temporary directory, not yet created.
    fn state_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("fips-gateway");
        (root, dir)
    }

    fn always_tmpfs(_: &Path) -> io::Result<bool> {
        Ok(true)
    }

    #[test]
    fn a_saved_state_round_trips_and_is_consumed_by_the_load() {
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();

        assert_eq!(load(&dir, "fd01::/120", 255), Loaded::Restored(state()));
        assert!(!dir.join(STATE_FILE).exists(), "the load removed the file");
        assert_eq!(load(&dir, "fd01::/120", 255), Loaded::Absent);
    }

    #[test]
    fn a_restored_start_that_ends_before_its_first_write_leaves_its_holds_for_the_next() {
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();
        // This run's TTL plus grace (600 s) is longer than the loaded hold
        // (120 s), so a hold re-armed to TTL plus grace shows.
        let now = Instant::now();
        let started = start_pool(&dir, "fd01::/120", 255, 300, 300, 99, now, always_tmpfs).unwrap();
        assert_eq!(started.loaded, Loaded::Restored(state()), "control");
        let carried_ok = matches!(started.carried, Some(Ok(())));
        drop(started);

        // The start ends here, before the pool's first write, as one whose
        // NAT table or route cannot be set up does. The next start must
        // still hold what the previous run may have answered with: offsets
        // 1-3 and 7, and the stretch 10-29, and issue from 30.
        let Loaded::Restored(carried) = load(&dir, "fd01::/120", 255) else {
            panic!("a start that failed after loading the state left none for the next");
        };
        assert!(carried_ok, "the write back reported its outcome");
        assert_eq!(carried.held, vec![[1, 3], [7, 7], [10, 29]]);
        assert_eq!((carried.from, carried.span), (30, 0));
        assert!(
            (1..=state().hold_secs + 1).contains(&carried.hold_secs),
            "the hold is carried, not extended: {}",
            carried.hold_secs
        );

        // A start that keeps failing holds no more each time.
        save(&dir, &carried, always_tmpfs).unwrap();
        let later = now + Duration::from_secs(100);
        start_pool(&dir, "fd01::/120", 255, 300, 300, 99, later, always_tmpfs).unwrap();
        let Loaded::Restored(again) = load(&dir, "fd01::/120", 255) else {
            panic!("the second failed start left no state");
        };
        assert!(
            again.hold_secs <= carried.hold_secs + 1,
            "a second failed start re-armed the hold to {} s from the {} s it loaded",
            again.hold_secs,
            carried.hold_secs
        );
        assert_eq!((again.held, again.from, again.span), (carried.held, 30, 0));
    }

    #[test]
    fn a_fresh_start_writes_no_state_before_its_first_write() {
        let (_root, dir) = state_dir();
        let started = start_pool(
            &dir,
            "fd01::/120",
            255,
            60,
            60,
            99,
            Instant::now(),
            always_tmpfs,
        )
        .unwrap();
        assert_eq!(started.loaded, Loaded::Absent);
        assert!(started.carried.is_none());
        assert!(!dir.join(STATE_FILE).exists());
    }

    #[test]
    fn the_state_file_and_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(STATE_FILE)), 0o600);
    }

    #[test]
    fn a_failed_save_after_a_successful_one_leaves_no_state() {
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();
        // The next write cannot create its temporary file.
        fs::create_dir(dir.join(STATE_TMP)).unwrap();

        assert!(save(&dir, &state(), always_tmpfs).is_err());
        assert_eq!(
            load(&dir, "fd01::/120", 255),
            Loaded::Absent,
            "an older state survived a failed write, so the next start would \
             replay a stretch this run has already issued past"
        );
    }

    #[test]
    fn a_save_whose_directory_is_not_tmpfs_on_the_second_check_leaves_no_state() {
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();
        let dir_check = dir.clone();
        let parent_only = move |p: &Path| Ok(p != dir_check);

        assert!(save(&dir, &state(), parent_only).is_err());
        assert_eq!(load(&dir, "fd01::/120", 255), Loaded::Absent);
    }

    #[test]
    fn a_load_followed_by_a_failed_save_leaves_no_file() {
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();
        assert!(matches!(load(&dir, "fd01::/120", 255), Loaded::Restored(_)));
        fs::create_dir(dir.join(STATE_TMP)).unwrap();

        assert!(save(&dir, &state(), always_tmpfs).is_err());
        assert!(!dir.join(STATE_FILE).exists());
        assert_eq!(load(&dir, "fd01::/120", 255), Loaded::Absent);
    }

    #[test]
    fn a_truncated_file_is_invalid_and_starts_fresh_at_the_random_offset() {
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();
        let path = dir.join(STATE_FILE);
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

        let loaded = load(&dir, "fd01::/120", 255);
        assert!(matches!(loaded, Loaded::Invalid(_)), "{loaded:?}");
        assert_eq!(start_from(loaded, 77), PoolStart::Fresh { offset: 77 });
        assert!(!path.exists(), "an invalid file is consumed too");
    }

    #[test]
    fn a_state_for_another_pool_is_invalid() {
        let (_root, dir) = state_dir();
        save(&dir, &state(), always_tmpfs).unwrap();
        assert!(matches!(
            load(&dir, "fd01::/112", 65535),
            Loaded::Invalid(_)
        ));
    }

    #[test]
    fn a_stretch_longer_than_the_pool_is_invalid() {
        let (_root, dir) = state_dir();
        let mut long = state();
        long.span = 256;
        save(&dir, &long, always_tmpfs).unwrap();
        assert!(matches!(load(&dir, "fd01::/120", 255), Loaded::Invalid(_)));
    }

    #[test]
    fn overlapping_held_ranges_are_invalid() {
        let (_root, dir) = state_dir();
        let mut overlap = state();
        overlap.held = vec![[1, 5], [5, 9]];
        save(&dir, &overlap, always_tmpfs).unwrap();
        assert!(matches!(load(&dir, "fd01::/120", 255), Loaded::Invalid(_)));
    }

    #[test]
    fn a_held_range_ending_past_the_pool_is_invalid() {
        let (_root, dir) = state_dir();
        let mut past = state();
        past.held = vec![[1, 3], [250, 256]];
        save(&dir, &past, always_tmpfs).unwrap();
        let loaded = load(&dir, "fd01::/120", 255);
        assert!(matches!(loaded, Loaded::Invalid(_)), "{loaded:?}");

        // Control: the same range ending at the last offset is accepted.
        past.held = vec![[1, 3], [250, 255]];
        save(&dir, &past, always_tmpfs).unwrap();
        assert!(matches!(load(&dir, "fd01::/120", 255), Loaded::Restored(_)));
    }

    #[test]
    fn an_unbounded_hold_is_invalid_and_starts_fresh_without_panicking() {
        let (_root, dir) = state_dir();
        let mut forever = state();
        forever.hold_secs = u64::MAX;
        save(&dir, &forever, always_tmpfs).unwrap();

        let loaded = load(&dir, "fd01::/120", 255);
        assert!(matches!(loaded, Loaded::Invalid(_)), "{loaded:?}");
        assert_eq!(start_from(loaded, 5), PoolStart::Fresh { offset: 5 });
    }

    #[test]
    fn a_missing_parent_fails_the_save_and_creates_nothing() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("absent").join("fips-gateway");

        assert!(save(&dir, &state(), always_tmpfs).is_err());
        assert!(!root.path().join("absent").exists());
    }

    #[test]
    fn a_parent_not_on_tmpfs_fails_the_save_and_creates_nothing() {
        let (_root, dir) = state_dir();
        let error = save(&dir, &state(), |_| Ok(false)).unwrap_err();

        assert!(error.to_string().contains("not on tmpfs"), "{error}");
        assert!(!dir.exists(), "no directory was created on other storage");
    }

    #[test]
    fn proc_is_not_tmpfs() {
        assert!(!is_tmpfs(Path::new("/proc")).unwrap());
    }

    #[test]
    fn is_tmpfs_is_true_for_a_mounted_tmpfs() {
        let mounts = fs::read_to_string("/proc/self/mounts").unwrap();
        let tmpfs: Vec<&str> = mounts
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                (fields.get(2) == Some(&"tmpfs")).then(|| fields[1])
            })
            .collect();
        let preferred = ["/dev/shm", "/run"]
            .into_iter()
            .filter(|p| tmpfs.contains(p));
        let candidate = preferred
            .chain(tmpfs.iter().copied())
            .find(|p| is_tmpfs(Path::new(p)).is_ok());
        let Some(path) = candidate else {
            panic!("no accessible tmpfs mount is listed in /proc/self/mounts to check against");
        };
        assert!(
            is_tmpfs(Path::new(path)).unwrap(),
            "{path} is listed as tmpfs"
        );
    }
}
