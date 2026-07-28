//! Capture lifecycle: the arm/disarm state machine, the sink file, and the
//! `fipsctl`-facing operations.
//!
//! The toggle — not the writer — creates and opens the sink and publishes its
//! path, so an unwritable directory fails the `on` command loudly instead of
//! being discovered later by a background thread with nobody to report to.
//!
//! Capture state is a single atomic state machine (`Idle`, `Running`,
//! `StoppedByCap`) transitioned by `compare_exchange`. Every accepted control
//! connection is served by its own spawned task, so two simultaneous `on`
//! requests are genuinely concurrent and must not both create a writer.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::recorder;
use super::writer;

/// Default sink directory. Overridable per capture with `--dir`.
pub(crate) const DEFAULT_DIR: &str = "/var/log/fips";

/// Writer flush interval.
pub(crate) const INTERVAL: Duration = Duration::from_secs(10);

/// Size at which a capture stops itself. Reaching it stops the capture rather
/// than rotating: the point of a capture is a bounded, self-describing window.
pub(crate) const BYTE_CAP: u64 = 32 * 1024 * 1024;

pub(crate) const IDLE: u8 = 0;
pub(crate) const RUNNING: u8 = 1;
pub(crate) const STOPPED_BY_CAP: u8 = 2;
/// The writer could not write and stopped itself. Distinct from a cap stop:
/// a capture that died on a full disk produced a truncated window, and calling
/// that "stopped_by_cap" tells the operator it ran to its limit when it did
/// not. The trailer line explaining it goes to the same failing file, so the
/// state is the only signal that survives.
pub(crate) const STOPPED_BY_ERROR: u8 = 3;

static STATE: AtomicU8 = AtomicU8::new(IDLE);
static GATE: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicU64 = AtomicU64::new(0);
static ACTIVE_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static WRITER: Mutex<Option<writer::Handle>> = Mutex::new(None);

/// The per-tick gate. One relaxed load per tick when the feature is compiled in
/// and no capture is running.
#[inline]
pub(crate) fn gate() -> bool {
    GATE.load(Ordering::Relaxed)
}

pub(crate) fn bytes_written() -> u64 {
    BYTES.load(Ordering::Relaxed)
}

pub(crate) fn add_bytes(n: u64) -> u64 {
    BYTES.fetch_add(n, Ordering::Relaxed) + n
}

fn active_path() -> Option<PathBuf> {
    ACTIVE_PATH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn path_display() -> String {
    active_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<none>".to_string())
}

fn state_name(state: u8) -> &'static str {
    match state {
        RUNNING => "running",
        STOPPED_BY_CAP => "stopped_by_cap",
        STOPPED_BY_ERROR => "stopped_by_error",
        _ => "idle",
    }
}

/// Called by the writer when it stops itself. `terminal` is `STOPPED_BY_CAP`
/// or `STOPPED_BY_ERROR`. Returns true if this call is the one that stopped it.
pub(crate) fn mark_stopped(terminal: u8) -> bool {
    debug_assert!(terminal == STOPPED_BY_CAP || terminal == STOPPED_BY_ERROR);
    GATE.store(false, Ordering::Relaxed);
    STATE
        .compare_exchange(RUNNING, terminal, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Join the writer thread, if one exists. Never called while holding another
/// lock the writer might want.
fn reap() {
    let handle = WRITER.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(handle) = handle {
        handle.stop_and_join();
    }
}

/// Arm a capture.
///
/// Opens the sink first and only then starts the writer, so a bad `--dir` is
/// reported to the caller rather than logged into the void.
pub(crate) fn start(
    dir: Option<&str>,
    node_npub: &str,
    tick_period_secs: u64,
) -> Result<serde_json::Value, String> {
    claim()?;

    match open_sink(dir, node_npub, tick_period_secs) {
        Ok((file, path, header_len)) => {
            recorder::reset();
            BYTES.store(header_len, Ordering::Relaxed);
            match writer::spawn(file) {
                Ok(handle) => {
                    *WRITER.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
                    *ACTIVE_PATH.lock().unwrap_or_else(|e| e.into_inner()) = Some(path.clone());
                    GATE.store(true, Ordering::Release);
                    Ok(serde_json::json!({
                        "state": "running",
                        "path": path.display().to_string(),
                        "interval_secs": INTERVAL.as_secs(),
                        "byte_cap": BYTE_CAP,
                    }))
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    BYTES.store(0, Ordering::Relaxed);
                    STATE.store(IDLE, Ordering::Release);
                    Err(format!("cannot start profile writer thread: {e}"))
                }
            }
        }
        Err(e) => {
            BYTES.store(0, Ordering::Relaxed);
            STATE.store(IDLE, Ordering::Release);
            Err(e)
        }
    }
}

/// Take the capture slot, reaping a cap-stopped predecessor if that is what is
/// in the way.
fn claim() -> Result<(), String> {
    match STATE.compare_exchange(IDLE, RUNNING, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(RUNNING) => Err(format!("capture already running: {}", path_display())),
        Err(stopped @ (STOPPED_BY_CAP | STOPPED_BY_ERROR)) => {
            reap();
            *ACTIVE_PATH.lock().unwrap_or_else(|e| e.into_inner()) = None;
            STATE
                .compare_exchange(stopped, RUNNING, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| ())
                .map_err(|_| "capture state changed concurrently; retry".to_string())
        }
        Err(_) => Err("capture in an unexpected state".to_string()),
    }
}

/// Disarm the capture. Succeeds when nothing is running, reporting so.
pub(crate) fn stop() -> Result<serde_json::Value, String> {
    let previous = STATE.load(Ordering::Acquire);
    if previous == IDLE {
        return Ok(serde_json::json!({"state": "idle", "stopped": false}));
    }
    GATE.store(false, Ordering::Release);
    // The writer wakes on the stop message rather than after the interval, so
    // this join returns promptly instead of parking the caller for up to one
    // flush interval.
    reap();
    let path = path_display();
    *ACTIVE_PATH.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let bytes = bytes_written();
    // Clear the counter with the slot: a later `status` while idle must not
    // report the previous capture's byte total as though a capture were live.
    BYTES.store(0, Ordering::Relaxed);
    STATE.store(IDLE, Ordering::Release);
    Ok(serde_json::json!({
        "state": "idle",
        "stopped": true,
        "stopped_by_cap": previous == STOPPED_BY_CAP,
        "stopped_by_error": previous == STOPPED_BY_ERROR,
        "path": path,
        "bytes": bytes,
    }))
}

/// Report capture state. Distinguishes all four states.
pub(crate) fn status() -> serde_json::Value {
    let state = STATE.load(Ordering::Acquire);
    serde_json::json!({
        "state": state_name(state),
        "path": active_path().map(|p| p.display().to_string()),
        "bytes": bytes_written(),
        "byte_cap": BYTE_CAP,
        "interval_secs": INTERVAL.as_secs(),
    })
}

/// Stop and reap at daemon teardown. Idempotent.
pub(crate) fn shutdown() {
    if STATE.load(Ordering::Acquire) != IDLE {
        let _ = stop();
    }
}

/// Create the sink file and write its header block. Returns the open file, its
/// path, and the number of header bytes written.
fn open_sink(
    dir: Option<&str>,
    node_npub: &str,
    tick_period_secs: u64,
) -> Result<(File, PathBuf, u64), String> {
    let dir = PathBuf::from(dir.unwrap_or(DEFAULT_DIR));
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("cannot use profile directory {}: {e}", dir.display()))?;

    let start_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("profile-{}.tsv", compact_utc(start_unix)));

    let mut file = File::create(&path)
        .map_err(|e| format!("cannot create profile file {}: {e}", path.display()))?;

    let header = format!(
        "# fips tick profile\n\
         # node\t{node}\n\
         # build\t{build}\n\
         # platform\t{platform}\n\
         # tick_period_secs\t{period}\n\
         # interval_secs\t{interval}\n\
         # byte_cap\t{cap}\n\
         # start_utc\t{start_utc}\n\
         # start_unix\t{start_unix}\n\
         # NOTE\tstep durations are WALL CLOCK across await points, not CPU time:\n\
         # NOTE\ta step that awaits I/O accrues the wait, and other tasks may run\n\
         # NOTE\tinside that span. That is the intended measure for head-of-line\n\
         # NOTE\tdelay; do not read a large step as CPU cost.\n\
         # NOTE\tarm_starvation is measured directly as (entry time - the deadline\n\
         # NOTE\tthe interval scheduled the tick for). It is NOT derived from\n\
         # NOTE\ttick_entry_gap, which carries no starvation signal by itself:\n\
         # NOTE\tunder a steady delay every gap is exactly one tick period.\n\
         ts_unix\tkind\tdomain\tname\tcount\tmax\ttotal\tunit\n",
        node = node_npub,
        build = crate::version::short_version(),
        platform = std::env::consts::OS,
        period = tick_period_secs,
        interval = INTERVAL.as_secs(),
        cap = BYTE_CAP,
        start_utc = iso_utc(start_unix),
        start_unix = start_unix,
    );
    file.write_all(header.as_bytes())
        .map_err(|e| format!("cannot write profile header to {}: {e}", path.display()))?;

    Ok((file, path, header.len() as u64))
}

/// Break a Unix timestamp into UTC `(year, month, day, hour, minute, second)`.
///
/// Hinnant's `civil_from_days`, era-based. No date crate is in the dependency
/// set and one filename stamp does not justify adding one.
fn utc_parts(unix: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m,
        d,
        (secs / 3_600) as u32,
        ((secs % 3_600) / 60) as u32,
        (secs % 60) as u32,
    )
}

/// `20260727T191500Z` — filename-safe.
fn compact_utc(unix: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(unix);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// `2026-07-27T19:15:00Z` — for the header block.
fn iso_utc(unix: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(unix);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_parts_matches_known_instants() {
        assert_eq!(utc_parts(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(utc_parts(946_684_800), (2000, 1, 1, 0, 0, 0));
        // 2026-07-27T19:15:00Z
        assert_eq!(utc_parts(1_785_179_700), (2026, 7, 27, 19, 15, 0));
        // Leap day.
        assert_eq!(utc_parts(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn stamps_render_expected_shapes() {
        assert_eq!(compact_utc(1_785_179_700), "20260727T191500Z");
        assert_eq!(iso_utc(1_785_179_700), "2026-07-27T19:15:00Z");
    }

    // The lock these tests take is shared with the recorder tests, which
    // mutate the same statics. See `crate::instr::test_serial`.

    #[test]
    fn capture_round_trip_writes_header_and_rows() {
        let _guard = crate::instr::test_serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_str = dir.path().to_str().unwrap().to_string();

        let started = start(Some(&dir_str), "npub1test", 1).expect("start");
        assert_eq!(started["state"], "running");
        assert!(gate(), "gate must be armed while running");
        let path = PathBuf::from(started["path"].as_str().unwrap());

        // A second `on` is refused while one is running, and names the file.
        let refused = start(Some(&dir_str), "npub1test", 1).unwrap_err();
        assert!(refused.contains(&path.display().to_string()), "{refused}");

        // Feed one observation so the drained rows are not all zero.
        recorder::record(
            recorder::Domain::Tick,
            recorder::Step::WholeTick,
            Duration::from_millis(7),
        );

        // Stopping wakes the writer immediately; it drains once more and joins.
        let stopped = stop().expect("stop");
        assert_eq!(stopped["stopped"], true);
        assert_eq!(stopped["stopped_by_cap"], false);
        assert!(!gate(), "gate must be clear after stop");

        let text = std::fs::read_to_string(&path).expect("read capture");
        assert!(text.starts_with("# fips tick profile\n"), "{text}");
        assert!(text.contains("# node\tnpub1test\n"), "{text}");
        assert!(
            text.contains("ts_unix\tkind\tdomain\tname\tcount\tmax\ttotal\tunit\n"),
            "{text}"
        );
        // The final drain emitted one row per emitted step, plus the gauges.
        let rows: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with(|c: char| c.is_ascii_digit()))
            .collect();
        let expected_steps = recorder::STEPS.iter().filter(|s| s.emitted()).count();
        assert_eq!(rows.len(), expected_steps + recorder::N_GAUGES);
        // The 7 ms observation above is in the whole-tick row, converted to
        // microseconds. Bounds rather than equality: the gate is process-wide,
        // so a node under test elsewhere in this binary may have ticked into
        // the same capture window.
        let whole_tick = rows
            .iter()
            .find(|r| r.contains("\tstep\ttick\twhole_tick\t"))
            .expect("whole_tick row");
        let fields: Vec<&str> = whole_tick.split('\t').collect();
        assert_eq!(fields.last(), Some(&"us"), "{whole_tick}");
        assert!(
            fields[4].parse::<u64>().unwrap() >= 1,
            "count: {whole_tick}"
        );
        assert!(
            fields[5].parse::<u64>().unwrap() >= 7_000,
            "max: {whole_tick}"
        );
        assert!(
            rows.iter()
                .any(|r| r.contains("\tgauge\ttick\tarm_starvation\t")),
            "{text}"
        );

        // A stop with nothing running is not an error.
        let again = stop().expect("second stop");
        assert_eq!(again["stopped"], false);
    }

    #[test]
    fn start_fails_loudly_on_an_unwritable_directory() {
        let _guard = crate::instr::test_serial();
        let err = start(Some("/proc/fips-profile-should-not-exist"), "npub1test", 1)
            .expect_err("must fail");
        assert!(err.contains("profile directory"), "{err}");
        // The failed attempt must leave the slot free for the next try.
        assert_eq!(STATE.load(Ordering::Acquire), IDLE);
        assert!(!gate());
    }

    #[test]
    fn status_reports_the_bounds_it_is_enforcing() {
        let _guard = crate::instr::test_serial();
        let value = status();
        assert_eq!(value["byte_cap"], BYTE_CAP);
        assert_eq!(value["interval_secs"], INTERVAL.as_secs());
    }
}
