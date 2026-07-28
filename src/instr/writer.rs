//! The capture writer: a dedicated, named OS thread with an explicit
//! lifecycle.
//!
//! There is no worker-thread lifecycle in this codebase to copy — the crypto
//! worker pools are never torn down and drop their join handles at spawn — so
//! this one is designed here.
//!
//! Two properties matter:
//!
//! - **It is an OS thread, not a spawned task.** The runtime is
//!   `current_thread`, so file I/O on a task would run on the rx loop's own
//!   thread and stall every `select!` arm, including the one being measured.
//! - **It waits on a channel with a timeout, not on a sleep.** `recv_timeout`
//!   returns immediately when the toggle sends stop, so `off` performs a final
//!   drain and joins promptly instead of parking the caller for up to a full
//!   flush interval.
//!
//! The thread is created lazily when a capture starts, so a node that never
//! arms one never has the thread.

use std::fs::File;
use std::io::Write;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use super::capture::{self, BYTE_CAP, INTERVAL};
use super::recorder::{self, DOMAINS, GAUGES, STEPS};

/// Owner-side handle to the writer thread.
pub(crate) struct Handle {
    stop_tx: Sender<()>,
    join: JoinHandle<()>,
}

impl Handle {
    /// Wake the writer, let it drain once more, and join it.
    pub(crate) fn stop_and_join(self) {
        // A send error means the thread already exited (cap stop); joining is
        // still correct and returns at once.
        let _ = self.stop_tx.send(());
        let _ = self.join.join();
    }
}

/// Start the writer thread on an already-open sink.
pub(crate) fn spawn(file: File) -> std::io::Result<Handle> {
    let (stop_tx, stop_rx) = mpsc::channel();
    let join = thread::Builder::new()
        .name("fips-profile".to_string())
        .spawn(move || run(file, stop_rx))?;
    Ok(Handle { stop_tx, join })
}

/// What one flush cycle decided. Separated from [`run`] so the terminal paths
/// can be driven in a test with a failing sink: the loop below owns the waiting
/// and the state transition, this owns the decision.
#[derive(Debug, PartialEq, Eq)]
enum Cycle {
    Continue,
    CapReached,
    WriteFailed,
}

/// Drain one interval into the sink and decide whether the capture goes on.
fn flush_cycle<W: Write>(file: &mut W) -> Cycle {
    if flush(file).is_err() {
        // The sink is gone or full; stop rather than spinning on a broken file
        // for the rest of the run.
        let _ = note(file, "capture stopped: write error");
        return Cycle::WriteFailed;
    }
    if capture::bytes_written() >= BYTE_CAP {
        let _ = note(
            file,
            &format!("capture stopped: byte cap {BYTE_CAP} reached"),
        );
        let _ = file.flush();
        return Cycle::CapReached;
    }
    Cycle::Continue
}

fn run<W: Write>(mut file: W, stop_rx: Receiver<()>) {
    loop {
        match stop_rx.recv_timeout(INTERVAL) {
            // Stop requested, or the owner went away: final drain, then exit.
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                let _ = flush(&mut file);
                let _ = file.flush();
                return;
            }
            Err(RecvTimeoutError::Timeout) => match flush_cycle(&mut file) {
                Cycle::Continue => {}
                Cycle::WriteFailed => {
                    // The trailer went to the same failing file, so it is not a
                    // signal that survives. `stop` and a subsequent `on` both
                    // clear the state without surfacing it, so an operator would
                    // otherwise never learn the window was truncated.
                    tracing::warn!(
                        target: "fips::instr",
                        "profile capture stopped: write error on the sink"
                    );
                    capture::mark_stopped(capture::STOPPED_BY_ERROR);
                    return;
                }
                Cycle::CapReached => {
                    capture::mark_stopped(capture::STOPPED_BY_CAP);
                    return;
                }
            },
        }
    }
}

/// Append a `#`-prefixed trailer line.
fn note<W: Write>(file: &mut W, text: &str) -> std::io::Result<()> {
    let line = format!("# {text}\n");
    file.write_all(line.as_bytes())?;
    capture::add_bytes(line.len() as u64);
    Ok(())
}

/// Emit one interval: every step of every domain, then the gauges.
///
/// Every emitted step gets a row every interval, including zero-count rows, so
/// "this step did not run" is visible rather than absent. The two steps whose
/// call sites are conditionally compiled are excluded in builds that do not
/// have them, so no row is structurally zero forever.
fn flush<W: Write>(file: &mut W) -> std::io::Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut out = String::with_capacity(4096);
    for domain in DOMAINS {
        for step in STEPS {
            if !step.emitted() {
                continue;
            }
            let (count, max_ns, total_ns) = recorder::take_step(domain, step);
            out.push_str(&format!(
                "{ts}\tstep\t{domain}\t{name}\t{count}\t{max}\t{total}\tus\n",
                domain = domain.name(),
                name = step.name(),
                max = max_ns / 1_000,
                total = total_ns / 1_000,
            ));
        }
    }
    // Gauges carry the tick domain today; the row kind and the unit column keep
    // them distinguishable from the duration rows above.
    for gauge in GAUGES {
        let (count, mut max, mut total) = recorder::take_gauge(gauge);
        if gauge.is_duration() {
            max /= 1_000;
            total /= 1_000;
        }
        out.push_str(&format!(
            "{ts}\tgauge\t{domain}\t{name}\t{count}\t{max}\t{total}\t{unit}\n",
            domain = recorder::Domain::Tick.name(),
            name = gauge.name(),
            unit = gauge.unit(),
        ));
    }

    file.write_all(out.as_bytes())?;
    capture::add_bytes(out.len() as u64);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that fails every write, so the writer's error path is driven by a
    /// real `Err` rather than asserted about.
    struct AlwaysFails;

    impl Write for AlwaysFails {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "no space left on device",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A failing sink ends the capture as a write error, which `run` turns into
    /// `STOPPED_BY_ERROR` — not into a byte-cap stop. The distinction is what
    /// tells an operator that a window is truncated rather than complete.
    ///
    /// **Coverage note.** This drives the decision, not the filesystem
    /// condition. The mesh rehearsal cannot produce one: removing the file
    /// leaves the writer's descriptor valid and writes keep succeeding into the
    /// unlinked inode, and mounting a tiny filesystem inside the test container
    /// is refused. So "a real ENOSPC reaches this branch" stays unexercised;
    /// what is covered is that an `Err` from the sink produces the error
    /// outcome and not the cap outcome.
    #[test]
    fn a_failing_sink_ends_the_cycle_as_an_error_not_a_cap() {
        let _guard = crate::instr::test_serial();
        assert_eq!(flush_cycle(&mut AlwaysFails), Cycle::WriteFailed);
    }

    /// The healthy path must not be reported as either terminal state, or the
    /// test above would pass for a writer that always stops.
    #[test]
    fn a_working_sink_continues() {
        let _guard = crate::instr::test_serial();
        let mut sink: Vec<u8> = Vec::new();
        assert_eq!(flush_cycle(&mut sink), Cycle::Continue);
    }
}
