//! A size-rolling log file for the Windows service.
//!
//! A process started by the service control manager has no standard handles,
//! and writes to its absent stdout report success, so the daemon's log is lost
//! unless it goes to a file. The file is rolled by size, which bounds the disk
//! it can take: `ROLL_KEEP` old files of about `ROLL_BYTES` each, plus the
//! current one.
//!
//! Nothing here may emit a tracing event. The writer runs inside the
//! subscriber with the `SharedLog` lock held, so an event raised from here
//! would re-enter that lock on the same thread and deadlock. A roll that fails
//! is therefore silent; the file growing past its cap is the only sign.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use tracing_subscriber::fmt::MakeWriter;

/// Size at which the service log is rolled.
pub const ROLL_BYTES: u64 = 10 * 1024 * 1024;

/// Number of rolled service log files kept beside the current one.
pub const ROLL_KEEP: u32 = 4;

/// An append-only file that is renamed aside once it would pass `max` bytes.
///
/// Old files are `path.1` (newest) to `path.{keep}` (oldest). Writes are
/// unbuffered, so a `process::exit` right after a log line loses nothing.
pub struct RollingFile {
    path: PathBuf,
    max: u64,
    keep: u32,
    file: Option<File>,
    len: u64,
    limit: u64,
}

/// Open `path` for appending, creating it if absent.
fn append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl RollingFile {
    /// Open or create the log at `path`, keeping `keep` old files (at least
    /// one) and rolling at `max` bytes.
    ///
    /// Bytes already in the file from earlier runs count toward the cap.
    pub fn open(path: &Path, max: u64, keep: u32) -> io::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let file = append(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            max,
            keep: keep.max(1),
            file: Some(file),
            len,
            limit: max,
        })
    }

    /// The path of the `n`th rolled file.
    fn numbered(&self, n: u32) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    /// The open handle, reopening the file if an earlier roll or open left
    /// none. A reopen takes the length from the file itself.
    fn handle(&mut self) -> io::Result<&mut File> {
        let file = match self.file.take() {
            Some(file) => file,
            None => {
                let file = append(&self.path)?;
                self.len = file.metadata()?.len();
                file
            }
        };
        Ok(self.file.insert(file))
    }

    /// Rename the current file aside and shift the older ones down, dropping
    /// the oldest. The next write reopens `path` as a new, empty file.
    ///
    /// The handle is dropped first so that a failed roll reopens cleanly and
    /// nothing is left pointing at `path.1`. Renaming a file this process
    /// holds open is allowed on Windows too (std opens with
    /// `FILE_SHARE_DELETE`); a rename that fails there is one another process
    /// blocks, such as a viewer holding the file without delete sharing.
    fn roll(&mut self) -> io::Result<()> {
        self.file = None;
        for n in (1..self.keep).rev() {
            match fs::rename(self.numbered(n), self.numbered(n + 1)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        fs::rename(&self.path, self.numbered(1))?;
        self.len = 0;
        self.limit = self.max;
        Ok(())
    }

    /// Append `buf` to the current file and count it.
    fn append_buf(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.handle()?.write(buf)?;
        self.len += n as u64;
        Ok(n)
    }
}

impl Write for RollingFile {
    /// Write all of `buf` to one file, rolling first if it would take the
    /// file past its limit. A file that is still empty is never rolled, so a
    /// write larger than the cap lands whole instead of leaving an empty
    /// rolled file behind.
    ///
    /// A roll that fails leaves the current file in use: `buf` is appended to
    /// it and the next attempt waits until another `max` bytes have been
    /// written, so a file held by another process does not turn every write
    /// into a rename attempt. Only a failure to open the file is an error.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let size = buf.len() as u64;
        if self.len > 0 && self.len + size > self.limit && self.roll().is_err() {
            let n = self.append_buf(buf)?;
            self.limit = self.len + self.max;
            return Ok(n);
        }
        self.append_buf(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// A [`RollingFile`] shared between the tracing subscriber, startup error
/// reporting and the panic hook.
#[derive(Clone)]
pub struct SharedLog(Arc<Mutex<RollingFile>>);

/// A [`SharedLog`] held locked for the length of one tracing event.
pub struct LogGuard<'a>(MutexGuard<'a, RollingFile>);

impl Write for LogGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for SharedLog {
    type Writer = LogGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogGuard(self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl SharedLog {
    /// Share `file`.
    pub fn new(file: RollingFile) -> Self {
        Self(Arc::new(Mutex::new(file)))
    }

    /// Write `text` as one line, waiting for the lock.
    pub fn line(&self, text: &str) {
        let mut file = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = file.write_all(format!("{text}\n").as_bytes());
    }

    /// Write `text` as one line if the lock is free, for the panic hook.
    ///
    /// A panic raised while this thread already holds the lock, inside a
    /// tracing event, must not wait for it, so a held lock drops the line. So
    /// does one held by another thread at that moment.
    pub fn try_line(&self, text: &str) {
        let mut file = match self.0.try_lock() {
            Ok(file) => file,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        let _ = file.write_all(format!("{text}\n").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    /// A temporary directory and the log path inside it.
    fn setup() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("fips.log");
        (dir, path)
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    /// The names in `dir`, sorted.
    fn names(dir: &TempDir) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn rolled(path: &Path, n: u32) -> PathBuf {
        PathBuf::from(format!("{}.{n}", path.display()))
    }

    fn shared(path: &Path) -> SharedLog {
        SharedLog::new(RollingFile::open(path, ROLL_BYTES, ROLL_KEEP).unwrap())
    }

    /// Poison the lock the way a real failure would: a thread panics while
    /// holding it.
    fn poison(log: &SharedLog) {
        let held = log.clone();
        let joined = thread::spawn(move || {
            let _guard = held.0.lock().unwrap();
            panic!("a thread panicked holding the log lock");
        })
        .join();
        assert!(joined.is_err());
        assert!(
            log.0.is_poisoned(),
            "the lock must be poisoned for this test"
        );
    }

    /// Emit one `info!` through a real fmt subscriber writing to `log`.
    fn emit(log: &SharedLog, text: &str) {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || tracing::info!("{text}"));
    }

    #[test]
    fn writes_below_the_cap_stay_in_one_file() {
        let (dir, path) = setup();
        let mut file = RollingFile::open(&path, 16, 2).unwrap();
        for chunk in [b"aaaaa", b"bbbbb", b"ccccc"] {
            assert_eq!(file.write(chunk).unwrap(), 5);
        }
        assert_eq!(names(&dir), ["fips.log"]);
        assert_eq!(read(&path), "aaaaabbbbbccccc");
    }

    #[test]
    fn a_write_that_would_cross_the_cap_rolls_first_and_is_not_split() {
        let (dir, path) = setup();
        let mut file = RollingFile::open(&path, 16, 2).unwrap();
        file.write_all(b"aaaaaaaaaa").unwrap();
        file.write_all(b"bbbbbbbbbb").unwrap();
        assert_eq!(names(&dir), ["fips.log", "fips.log.1"]);
        assert_eq!(read(&rolled(&path, 1)), "aaaaaaaaaa");
        assert_eq!(read(&path), "bbbbbbbbbb");
    }

    #[test]
    fn rolling_more_than_keep_times_discards_the_oldest() {
        let (dir, path) = setup();
        let mut file = RollingFile::open(&path, 4, 2).unwrap();
        // Every write after the first fills the file past the cap: five rolls.
        for chunk in [b"aaaa", b"bbbb", b"cccc", b"dddd", b"eeee", b"ffff"] {
            file.write_all(chunk).unwrap();
        }
        assert_eq!(names(&dir), ["fips.log", "fips.log.1", "fips.log.2"]);
        assert_eq!(read(&path), "ffff");
        assert_eq!(read(&rolled(&path, 1)), "eeee");
        assert_eq!(read(&rolled(&path, 2)), "dddd");
    }

    #[test]
    fn reopening_counts_bytes_already_in_the_file() {
        let (dir, path) = setup();
        let mut file = RollingFile::open(&path, 10, 2).unwrap();
        file.write_all(b"aaaaaaaaa").unwrap();
        drop(file);

        let mut file = RollingFile::open(&path, 10, 2).unwrap();
        file.write_all(b"bb").unwrap();
        assert_eq!(names(&dir), ["fips.log", "fips.log.1"]);
        assert_eq!(read(&rolled(&path, 1)), "aaaaaaaaa");
        assert_eq!(read(&path), "bb");
    }

    #[test]
    fn a_write_larger_than_the_cap_lands_whole_in_a_fresh_file() {
        let (dir, path) = setup();
        let mut file = RollingFile::open(&path, 16, 2).unwrap();
        let big = "x".repeat(40);
        file.write_all(big.as_bytes()).unwrap();
        // No roll from the empty file: rolling it would leave an empty
        // fips.log.1 behind.
        assert_eq!(names(&dir), ["fips.log"]);
        assert_eq!(read(&path), big);
    }

    #[test]
    fn a_failed_roll_keeps_writing_to_the_current_file() {
        let (_dir, path) = setup();
        let mut file = RollingFile::open(&path, 16, 1).unwrap();
        file.write_all(b"aaaaaaaaaa").unwrap();
        // A non-empty directory where the roll must rename to: the rename
        // fails on every platform.
        let blocker = rolled(&path, 1);
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("x"), "").unwrap();

        assert_eq!(file.write(b"bbbbbbbbbb").unwrap(), 10);
        assert_eq!(read(&path), "aaaaaaaaaabbbbbbbbbb");
        assert!(blocker.is_dir());
        assert!(blocker.join("x").exists());
    }

    #[test]
    fn a_failed_roll_is_retried_only_after_another_cap_of_bytes() {
        let (_dir, path) = setup();
        let mut file = RollingFile::open(&path, 16, 1).unwrap();
        file.write_all(b"aaaaaaaaaa").unwrap();
        let blocker = rolled(&path, 1);
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("x"), "").unwrap();
        file.write_all(b"bbbbbbbbbb").unwrap();
        fs::remove_dir_all(&blocker).unwrap();

        // 30 bytes: under the 20 + 16 the failed roll set, so no new attempt.
        file.write_all(b"cccccccccc").unwrap();
        assert!(!blocker.exists(), "a roll was retried before another cap");

        // 40 bytes: past it, so the roll runs and now succeeds.
        file.write_all(b"dddddddddd").unwrap();
        assert!(blocker.is_file());
        assert_eq!(read(&blocker), "aaaaaaaaaabbbbbbbbbbcccccccccc");
        assert_eq!(read(&path), "dddddddddd");
    }

    #[test]
    fn shared_log_receives_tracing_events() {
        let (_dir, path) = setup();
        let log = shared(&path);
        emit(&log, "probe line");
        let text = read(&path);
        assert!(text.contains("probe line"), "log was: {text:?}");
        assert!(!text.contains("\x1b["), "log has ANSI codes: {text:?}");
    }

    #[test]
    fn tracing_still_reaches_the_file_after_a_thread_panicked_holding_the_lock() {
        let (_dir, path) = setup();
        let log = shared(&path);
        poison(&log);
        emit(&log, "after poison");
        assert!(read(&path).contains("after poison"));
    }

    #[test]
    fn line_still_writes_after_a_thread_panicked_holding_the_lock() {
        let (_dir, path) = setup();
        let log = shared(&path);
        poison(&log);
        log.line("line after poison");
        assert_eq!(read(&path), "line after poison\n");
    }

    #[test]
    fn try_line_still_writes_after_a_thread_panicked_holding_the_lock() {
        let (_dir, path) = setup();
        let log = shared(&path);
        poison(&log);
        log.try_line("try after poison");
        assert_eq!(read(&path), "try after poison\n");
    }

    #[test]
    fn try_line_returns_without_writing_while_the_lock_is_held() {
        let (_dir, path) = setup();
        let log = shared(&path);
        let guard = log.0.lock().unwrap();

        let (tx, rx) = mpsc::channel();
        let other = log.clone();
        let worker = thread::spawn(move || {
            other.try_line("blocked");
            let _ = tx.send(());
        });
        let returned = rx.recv_timeout(Duration::from_secs(5));
        drop(guard);
        assert!(returned.is_ok(), "try_line blocked on a held lock");
        worker.join().unwrap();
        assert!(!read(&path).contains("blocked"));
    }
}
