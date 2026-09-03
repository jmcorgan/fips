//! Kernel link-event sources.
//!
//! A watcher that resolves when the kernel reports that something about the
//! host's network links changed. Callers use it to react to interface state in
//! sub-second time instead of polling for it.
//!
//! | Platform | Source |
//! | -------- | ------ |
//! | Linux | netlink `RTNLGRP_LINK` (`RTM_NEWLINK` / `RTM_DELLINK`) |
//! | macOS, FreeBSD | `PF_ROUTE` socket, `RTM_IFINFO` |
//! | Fallback | none — the watcher never fires, and callers poll |
//!
//! The messages themselves are deliberately **not parsed**. An event is a hint
//! to re-run whatever question the caller actually cares about, which is
//! cheap and authoritative; decoding `nlmsghdr`/`ifinfomsg` payloads to reach
//! the same answer would add a parser whose bugs would become the caller's
//! bugs. Any event on the socket wakes the caller, which then asks its own
//! question directly.
//!
//! Construction is best-effort, and that is the contract: a kernel or sandbox
//! that refuses the socket yields a watcher that never fires. `changed()` then
//! parks forever, which is what makes it safe to `select!` against a poll
//! ticker — the ticker simply always wins, and the caller degrades to polling
//! without a special case.
//!
//! Callers that need a *different* event group should extend
//! `open_link_socket` rather than opening a second socket beside this one:
//! `RTNLGRP_LINK` carries link state only, so a route change with both
//! interfaces up produces no event here.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tracing::{debug, warn};

/// Consecutive receive errors before the event source is abandoned for the
/// caller's poll.
const ERROR_GIVE_UP: u32 = 5;

/// An owned link-event socket. Closes its descriptor on drop.
struct LinkEventSocket {
    fd: RawFd,
}

impl AsRawFd for LinkEventSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for LinkEventSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl LinkEventSocket {
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// Open the platform's link-event socket, non-blocking.
#[cfg(target_os = "linux")]
fn open_link_socket() -> std::io::Result<LinkEventSocket> {
    // RTMGRP_LINK. Spelled as a literal because the constant's name and
    // availability differ across libc versions; the value is ABI.
    const RTMGRP_LINK: u32 = 1;

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let socket = LinkEventSocket { fd };

    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    sa.nl_groups = RTMGRP_LINK;
    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(socket)
}

/// Open the platform's link-event socket, non-blocking.
#[cfg(not(target_os = "linux"))]
fn open_link_socket() -> std::io::Result<LinkEventSocket> {
    // PF_ROUTE delivers RTM_IFINFO (and the rest of the routing messages) to
    // every reader; no bind and no group selection exist for it.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let socket = LinkEventSocket { fd };

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(socket)
}

/// A source of "something about the links changed" wake-ups.
pub struct LinkWatcher {
    /// `None` when no event source could be opened — the caller's poll is then
    /// the whole mechanism, which is exactly the documented fallback.
    inner: Option<AsyncFd<LinkEventSocket>>,
    /// Consecutive receive errors. Reset by any successful read.
    errors: AtomicU32,
    /// Set once the source has been abandoned for good.
    ///
    /// Abandonment has to outlive the future that decided it. `changed()` is
    /// called fresh on every pass of the caller's `select!` and dropped
    /// whenever the poll ticker wins, so a `pending()` inside that future
    /// parks nothing beyond the current pass — without this flag the next pass
    /// re-reads the dead socket, re-counts the error, and re-logs the
    /// give-up warning, once per wake-up, forever.
    given_up: AtomicBool,
}

impl Default for LinkWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkWatcher {
    /// Open the platform link-event source, falling back to nothing.
    pub fn new() -> Self {
        let inner = match open_link_socket() {
            Ok(socket) => match AsyncFd::new(socket) {
                Ok(afd) => Some(afd),
                Err(e) => {
                    debug!(error = %e, "Link event socket not registrable; polling instead");
                    None
                }
            },
            Err(e) => {
                debug!(error = %e, "No link event source available; polling instead");
                None
            }
        };
        Self {
            inner,
            errors: AtomicU32::new(0),
            given_up: AtomicBool::new(false),
        }
    }

    /// Whether an event source is actually backing this watcher.
    pub fn is_event_driven(&self) -> bool {
        self.inner.is_some()
    }

    /// Resolve when the kernel reports a link change.
    ///
    /// Never resolves when no event source is available, which makes it safe
    /// to `select!` against the poll ticker: the ticker simply always wins.
    pub async fn changed(&self) {
        let Some(afd) = &self.inner else {
            std::future::pending::<()>().await;
            unreachable!("pending never resolves")
        };

        // Already abandoned on an earlier pass. Park without touching the
        // socket, so giving up costs one syscall in total rather than one per
        // caller wake-up for the life of the process.
        if self.given_up.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
            unreachable!("pending never resolves")
        }

        loop {
            let Ok(mut guard) = afd.readable().await else {
                // The registration died. Stop firing rather than spinning; the
                // caller's poll continues to cover presence.
                std::future::pending::<()>().await;
                unreachable!("pending never resolves")
            };

            // Drain to WouldBlock so a burst of link messages is one wake-up
            // and the socket buffer does not fill behind us.
            let mut buf = [0u8; 4096];
            let mut saw_event = false;
            let mut failure = None;
            loop {
                match guard.try_io(|inner| inner.get_ref().recv(&mut buf)) {
                    Ok(Ok(n)) if n > 0 => saw_event = true,
                    // A zero-length read. Readiness is *not* cleared by
                    // `try_io` here — it clears only on `WouldBlock` — so
                    // breaking out plainly would leave `readable()` instantly
                    // ready with nothing to read, and this loop would spin
                    // without ever returning `Pending`. That starves the
                    // caller's `select!` of its poll ticker entirely, which
                    // takes presence detection down with it. Clear it by hand
                    // and treat it as a fault, so the give-up path applies.
                    Ok(Ok(_)) => {
                        guard.clear_ready();
                        failure = Some(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                        break;
                    }
                    // A genuine socket error. Distinct from WouldBlock, and
                    // the distinction is the whole point: `try_io` clears
                    // readiness only on WouldBlock, so breaking out of a real
                    // error leaves `readable()` instantly ready, `recv`
                    // failing again, and the loop spinning a core flat with
                    // nothing logged. Clear it by hand and back off.
                    Ok(Err(e)) => {
                        guard.clear_ready();
                        failure = Some(e);
                        break;
                    }
                    // WouldBlock — readiness is cleared, drain complete.
                    Err(_) => break,
                }
            }

            if saw_event {
                self.errors.store(0, Ordering::Relaxed);
                return;
            }

            if let Some(e) = failure {
                let errors = self.errors.fetch_add(1, Ordering::Relaxed) + 1;
                if errors == 1 {
                    // ENOBUFS is the realistic one: a burst of link events
                    // overflowed the socket buffer, so the kernel dropped some.
                    // Losing events is survivable — the caller polls — but the
                    // spin is not, and neither is doing it silently.
                    warn!(error = %e, "Link event source read failed");
                }
                if errors >= ERROR_GIVE_UP {
                    self.given_up.store(true, Ordering::Relaxed);
                    warn!(
                        errors,
                        "Link event source is not recoverable; falling back to \
                         polling for interface presence"
                    );
                    std::future::pending::<()>().await;
                    unreachable!("pending never resolves")
                }
                tokio::time::sleep(Duration::from_millis(100) * errors).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The watcher must construct on any host, with or without a usable event
    /// source, because the binder builds one unconditionally.
    #[tokio::test]
    async fn watcher_constructs_and_reports_its_backing() {
        let w = LinkWatcher::new();

        // On Linux the source is a plain `AF_NETLINK` socket in the
        // `RTNLGRP_LINK` group, which needs no capability and no privilege —
        // so on this platform "a sandbox might refuse it" is not a licence to
        // accept either answer. Discarding the result, which this test used
        // to do, meant nothing anywhere asserted that the event path exists:
        // the 1 s poll is a complete fallback, so the entire suite passed with
        // the source unavailable and no test could tell.
        #[cfg(target_os = "linux")]
        assert!(
            w.is_event_driven(),
            "the netlink link-event source must open on Linux; \
             falling back to the poll here is a silent loss of the fast path"
        );

        // Elsewhere both answers are legitimate, so pin only that asking is
        // safe and that a watcher with no source parks rather than fires.
        #[cfg(not(target_os = "linux"))]
        {
            let backed = w.is_event_driven();
            assert!(
                backed
                    || tokio::time::timeout(Duration::from_millis(50), w.changed())
                        .await
                        .is_err(),
                "a watcher with no source must never resolve"
            );
        }
    }

    /// A descriptor whose `recv` always fails must not become a busy loop.
    ///
    /// `try_io` clears readiness only on `WouldBlock`. Breaking out of a real
    /// error left `readable()` instantly ready, `recv` failing again, and the
    /// loop spinning a core flat with nothing logged — the realistic trigger
    /// being `ENOBUFS` when a burst of link events overflows the socket
    /// buffer. A pipe stands in for that here: `recv` on one answers
    /// `ENOTSOCK`, every time, which is exactly the shape of a persistent
    /// error.
    #[tokio::test]
    async fn a_persistently_failing_source_gives_up_instead_of_spinning() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe()");
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // AsyncFd requires a non-blocking descriptor.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        assert!(unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0);

        let watcher = LinkWatcher {
            inner: Some(AsyncFd::new(LinkEventSocket { fd: read_fd }).expect("register")),
            errors: AtomicU32::new(0),
            given_up: AtomicBool::new(false),
        };

        // Keep producing readiness edges. The error arm calls `clear_ready`,
        // and a descriptor that was already readable before re-registration
        // may never deliver another edge on its own — which would stall the
        // loop at one error and hide whether the give-up path works. A steady
        // trickle stands in for the burst of link events that provokes the
        // real failure.
        let writer = tokio::task::spawn_blocking(move || {
            for _ in 0..200 {
                if unsafe { libc::write(write_fd, b"x".as_ptr().cast(), 1) } < 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            unsafe { libc::close(write_fd) };
        });

        // Never resolves — there is no event to report — but it must reach the
        // give-up state rather than burn until the timeout.
        let fired = tokio::time::timeout(Duration::from_secs(5), watcher.changed()).await;
        assert!(fired.is_err(), "a failing source must not report an event");
        assert!(
            watcher.errors.load(Ordering::Relaxed) >= ERROR_GIVE_UP,
            "the error path must count, back off and stop, not spin silently"
        );

        writer.abort();
    }

    /// A watcher with no event source must never resolve, so a `select!`
    /// against the poll ticker degrades cleanly instead of spinning.
    #[tokio::test]
    async fn a_sourceless_watcher_never_fires() {
        let w = LinkWatcher {
            inner: None,
            errors: AtomicU32::new(0),
            given_up: AtomicBool::new(false),
        };
        let fired = tokio::time::timeout(std::time::Duration::from_millis(50), w.changed()).await;
        assert!(fired.is_err(), "sourceless watcher resolved");
    }
}
