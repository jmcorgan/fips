//! Every public item of the native datagram API client, asserted against a
//! real daemon.
//!
//! ```text
//! native-surface walk /run/fips/api.sock npub1…
//! ```
//!
//! **This is an assertion harness, not a program shape to copy.** It opens
//! flows nobody answers, asks for deadlines only so it can watch them expire,
//! and reaches for `poll(2)` on a descriptor the surface hands out. A program
//! that wanted to do something useful with this API would look like
//! `native-echo`, which is the example to read first.
//!
//! **It reaches past `fips::native::client` for `libc`, and that is a
//! departure.** `native-echo` states as a design property that needing `libc`
//! would mean the client module had failed to hide something. Here the
//! descriptor is the thing under test: `AsRawFd` and `AsFd` exist so a caller
//! can put a flow or a listener in its own event loop, `poll(2)` has no `std`
//! spelling, and asserting that the number really is a pollable descriptor is
//! the whole point of those items. Every `libc` use is inside the platform-gated
//! module below, because `libc` is a `cfg(unix)` dependency and the Windows leg
//! of CI compiles examples.
//!
//! **Every assertion goes through [`surface::step`], and there is no other way
//! to record one.** The count in the terminal line is that recorder's counter
//! rather than a number written into the format string, so a caller comparing
//! it against what it expected catches a block that stopped running as well as
//! a block that failed.
//!
//! **Platform.** The client module is built on Linux and FreeBSD only, so
//! `main` is gated to match, for the reason `native-echo` gives: example
//! targets are compiled by `cargo clippy --all-targets` on every platform in
//! the build matrix, and an ungated file would break those runs rather than
//! this program refusing to start.

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod surface {
    use fips::native::client::{FipsAddr, FipsListener, FipsStream, SOCKET, XOnlyPublicKey};
    use std::env;
    use std::fmt;
    use std::io::{self, Write};
    use std::os::fd::{AsFd, AsRawFd, RawFd};
    use std::path::Path;
    use std::process::ExitCode;
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    /// How long the whole run may take before the watchdog calls it wedged.
    ///
    /// Several of the defects these assertions exist to catch fail by blocking
    /// for ever rather than by returning something wrong, and a container that
    /// never exits reaches no accounting in the driver that started it.
    const WATCHDOG: Duration = Duration::from_secs(30);

    /// The read deadline the expiry assertion arms.
    ///
    /// Long enough that scheduling noise cannot make the wait look absent, short
    /// enough that waiting it out twice costs nothing.
    const DEADLINE: Duration = Duration::from_millis(200);

    /// The largest datagram a flow carries on the harness node.
    ///
    /// A literal, because the number is the assertion: it is what the daemon
    /// computes from `testing/native-api/node.yaml`'s 1472-byte UDP MTU, and the
    /// harness's line-protocol checks assert the same 1362 from the other side.
    /// A walk run against a node configured differently is expected to fail
    /// here, which is why the port band and the socket path are checked too.
    const PAYLOAD: usize = 1362;

    /// The lowest port the daemon's ephemeral allocator ever hands out.
    ///
    /// A floor rather than a value: the allocator is a forward-only cursor
    /// shared with every check that ran before this one, so the exact port
    /// depends on run order and only the range is a property of the surface.
    const EPHEMERAL: u16 = 49152;

    /// The port the walk asks a listener to hold by name.
    ///
    /// From 4800-4809, a band no other check in `testing/native-api/` uses.
    const HELD: u16 = 4800;

    /// The local port the walk asks a flow to be opened from by name.
    const NAMED: u16 = 4801;

    /// How many assertions have held so far.
    static PASSED: AtomicUsize = AtomicUsize::new(0);

    /// The assertion currently running, so a wedge can say which one wedged.
    static IN_FLIGHT: Mutex<&'static str> = Mutex::new("start-up");

    /// Run one assertion, counting it when it holds and ending the run when not.
    ///
    /// The only way to record an assertion, which is what makes [`PASSED`] a
    /// measurement of what ran rather than a number kept by hand.
    ///
    /// It exits rather than returning an error because the walk is a sequence:
    /// a flow that could not be opened has nothing to assert about, and a run
    /// that carried on would bury the first failure under the noise of every
    /// assertion downstream of it.
    pub fn step<T>(name: &'static str, body: impl FnOnce() -> Result<T, String>) -> T {
        // The guard is dropped at the end of this statement rather than held
        // across `body`, or the watchdog could not read the name it needs.
        *IN_FLIGHT
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = name;
        match body() {
            Ok(value) => {
                PASSED.fetch_add(1, Ordering::SeqCst);
                value
            }
            Err(detail) => {
                eprintln!("native-surface: FAILED at {name}: {detail}");
                let _ = io::stderr().flush();
                std::process::exit(1);
            }
        }
    }

    /// Arm a thread that ends the run, by name, if it stops making progress.
    ///
    /// A deadline that never reached the descriptor and a non-blocking mode that
    /// was never set both fail as a `recv` that never returns. Without this the
    /// container would run until something outside it lost patience, and the
    /// evidence of which assertion was in flight would be gone.
    fn watchdog() {
        drop(thread::spawn(|| {
            thread::sleep(WATCHDOG);
            let name = *IN_FLIGHT
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            eprintln!(
                "native-surface: FAILED at {name}: watchdog after {}s",
                WATCHDOG.as_secs()
            );
            let _ = io::stderr().flush();
            std::process::exit(1);
        }));
    }

    /// Compare what a call reported against what the surface promises.
    fn same<T: PartialEq + fmt::Debug>(what: &str, got: T, want: T) -> Result<(), String> {
        if got == want {
            return Ok(());
        }
        Err(format!("{what} is {got:?}, expected {want:?}"))
    }

    /// Assert a call was refused with a particular errno.
    fn errno<T: fmt::Debug>(what: &str, got: io::Result<T>, want: i32) -> Result<(), String> {
        match got {
            Ok(value) => Err(format!(
                "{what} succeeded with {value:?}, expected errno {want}"
            )),
            Err(error) if error.raw_os_error() == Some(want) => Ok(()),
            Err(error) => Err(format!("{what} failed with {error}, expected errno {want}")),
        }
    }

    /// Assert a call refused rather than waiting.
    ///
    /// By kind rather than by errno: `WouldBlock` is what the surface documents,
    /// and it is the one answer both an expired deadline and a non-blocking
    /// descriptor give, which is why the two are told apart here by how long the
    /// call took rather than by what it returned.
    fn blocked<T: fmt::Debug>(what: &str, got: io::Result<T>) -> Result<(), String> {
        match got {
            Ok(value) => Err(format!(
                "{what} succeeded with {value:?}, expected it to refuse to wait"
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(format!(
                "{what} failed with {error}, expected it to refuse to wait"
            )),
        }
    }

    /// Whether `poll(2)` says a descriptor has something to read, right now.
    ///
    /// The one place this file reaches past the client module, and the reason it
    /// is allowed to: what `AsRawFd` and `AsFd` promise is that the number names
    /// a socket an event loop can wait on, and nothing in `std` asks that
    /// question of a bare descriptor.
    fn readable(fd: RawFd) -> Result<bool, String> {
        let mut waiting = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the pointer and count describe one `pollfd` this frame owns,
        // and the descriptor belongs to a stream or listener still alive here.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut waiting), 1, 0) };
        if rc < 0 {
            return Err(format!(
                "poll on descriptor {fd}: {}",
                io::Error::last_os_error()
            ));
        }
        // Without this the mechanism failing and the assertion holding are the
        // same value: the only poll assertion here asserts a NEGATIVE, and a
        // descriptor poll(2) rejects outright comes back rc=1 with POLLNVAL and
        // no POLLIN, which would read as a quiet "nothing to read" pass.
        let broken = waiting.revents & (libc::POLLNVAL | libc::POLLERR);
        if broken != 0 {
            return Err(format!(
                "poll rejected descriptor {fd}, revents {broken:#x}, so it names no open socket"
            ));
        }
        Ok(waiting.revents & libc::POLLIN != 0)
    }

    /// Assert what a freshly opened flow says about the address it was given.
    ///
    /// Through the accessors and `Display` rather than by comparing the whole
    /// address, because those are themselves items under test.
    fn opened(flow: &FipsStream, key: XOnlyPublicKey, port: u16) -> Result<(), String> {
        let want = FipsAddr::new(key, port);
        same("the peer key", flow.peer_addr().key(), key)?;
        same("the peer port", flow.peer_addr().port(), port)?;
        same(
            "the peer address written out",
            flow.peer_addr().to_string(),
            want.to_string(),
        )
    }

    /// Assert the whole surface against the daemon on `sock`.
    ///
    /// `peer` is an npub nothing answers on, which is what most of these
    /// assertions need: a native `connect` is a local registration, so a flow to
    /// a peer that does not exist is a real flow with a real descriptor, and
    /// nothing arriving on it is what makes a deadline observable.
    fn walk(sock: &Path, peer: &str, key: XOnlyPublicKey) {
        // ── Setup entry points ────────────────────────────────────────────
        let held = step("bind_at holds the port it was told to hold", || {
            let listener =
                FipsListener::bind_at(sock, HELD).map_err(|e| format!("bind_at({HELD}): {e}"))?;
            same("the port held", listener.local_addr().port(), HELD)?;
            Ok(listener)
        });

        let ephemeral = step(
            "bind with no socket path resolves SOCKET and takes an ephemeral port",
            || {
                let listener = FipsListener::bind(0).map_err(|e| format!("bind(0): {e}"))?;
                let port = listener.local_addr().port();
                if port < EPHEMERAL {
                    return Err(format!(
                        "the port held is {port}, expected one from {EPHEMERAL} up"
                    ));
                }
                Ok(listener)
            },
        );

        let flow = step(
            "connect_at opens a flow to the peer and port it was given",
            || {
                let port = 4809;
                let flow = FipsStream::connect_at(sock, 0, (key, port))
                    .map_err(|e| format!("connect_at(_, 0, (key, {port})): {e}"))?;
                opened(&flow, key, port)?;
                let local = flow.local_addr().port();
                if local < EPHEMERAL {
                    return Err(format!(
                        "the flow's local port is {local}, expected one from {EPHEMERAL} up"
                    ));
                }
                Ok(flow)
            },
        );

        step(
            "the node's key is the same on a listener and a flow, and is not the peer's",
            || {
                same(
                    "the node key a flow reports",
                    flow.local_addr().key(),
                    ephemeral.local_addr().key(),
                )?;
                if flow.peer_addr().key() == flow.local_addr().key() {
                    return Err("a flow's peer key and node key are the same value".to_string());
                }
                Ok(())
            },
        );

        // ── Addressing: one connect per ToFipsAddr impl ───────────────────
        //
        // Eight impls, eight calls, and the mapping is the audit: `grep -n
        // 'impl.*ToFipsAddr for' src/native/client/mod.rs` returns eight lines.
        // A ninth would have to appear here and in the harness's expected count
        // before either could go green again, which is the intended friction.
        let addr = FipsAddr::new(key, 4807);

        step("connect takes an address by value", || {
            let flow = FipsStream::connect(addr).map_err(|e| format!("connect(FipsAddr): {e}"))?;
            // connect delegates to connect_at with a local port of 0, so a
            // defect that passed some other port instead shows up here as a
            // local port below the ephemeral floor.
            let local = flow.local_addr().port();
            if local < EPHEMERAL {
                return Err(format!(
                    "the flow's local port is {local}, expected one from {EPHEMERAL} up"
                ));
            }
            opened(&flow, key, addr.port())
        });

        step("connect takes a key and a port as a tuple", || {
            let port = 4802;
            let flow = FipsStream::connect((key, port))
                .map_err(|e| format!("connect((XOnlyPublicKey, {port})): {e}"))?;
            opened(&flow, key, port)
        });

        step(
            "connect takes a serialized key and a port as a tuple",
            || {
                let port = 4803;
                let flow = FipsStream::connect((key.serialize(), port))
                    .map_err(|e| format!("connect(([u8; 32], {port})): {e}"))?;
                opened(&flow, key, port)
            },
        );

        step("connect takes an npub slice and a port as a tuple", || {
            let port = 4804;
            let flow = FipsStream::connect((peer, port))
                .map_err(|e| format!("connect((&str, {port})): {e}"))?;
            opened(&flow, key, port)
        });

        step("connect takes an owned npub and a port as a tuple", || {
            let port = 4805;
            let flow = FipsStream::connect((peer.to_string(), port))
                .map_err(|e| format!("connect((String, {port})): {e}"))?;
            opened(&flow, key, port)
        });

        step(
            "connect takes a whole address as one slice, parsed by FromStr",
            || {
                // The only route to `impl ToFipsAddr for str`: a `str` is
                // unsized, so the argument is a `&str` and the blanket impl for
                // `&T` is what dispatches to it.
                let text = format!("{peer}:4806");
                let want =
                    FipsAddr::from_str(&text).map_err(|e| format!("parsing {text:?}: {e}"))?;
                let flow = FipsStream::connect(text.as_str())
                    .map_err(|e| format!("connect({text:?} as &str): {e}"))?;
                opened(&flow, want.key(), want.port())
            },
        );

        step("connect takes a whole address as one owned string", || {
            let text = format!("{peer}:4808");
            let want = FipsAddr::from_str(&text).map_err(|e| format!("parsing {text:?}: {e}"))?;
            let flow =
                FipsStream::connect(text).map_err(|e| format!("connect(a String address): {e}"))?;
            opened(&flow, want.key(), want.port())
        });

        // The borrow is the assertion, not an accident: `&addr` is the only
        // thing that reaches the blanket `impl ToFipsAddr for &T`, and passing
        // `addr` by value as clippy suggests would exercise `impl for FipsAddr`
        // a second time and leave the blanket impl untested with this `T`.
        #[allow(clippy::needless_borrows_for_generic_args)]
        step(
            "connect_from names the local port, taking the address by reference",
            || {
                // The blanket impl again, with a different `T`, which is what
                // makes this a separate exercise rather than a repeat.
                let flow = FipsStream::connect_from(NAMED, &addr)
                    .map_err(|e| format!("connect_from({NAMED}, &FipsAddr): {e}"))?;
                same("the local port asked for", flow.local_addr().port(), NAMED)?;
                opened(&flow, key, addr.port())
            },
        );

        // ── Deadlines ─────────────────────────────────────────────────────
        step(
            "read_timeout reads back the deadline set_read_timeout set",
            || {
                flow.set_read_timeout(Some(DEADLINE))
                    .map_err(|e| format!("set_read_timeout(Some({DEADLINE:?})): {e}"))?;
                let got = flow
                    .read_timeout()
                    .map_err(|e| format!("read_timeout: {e}"))?;
                same("the read deadline", got, Some(DEADLINE))
            },
        );

        step("recv gives up once the read deadline expires", || {
            let mut buf = [0u8; 64];
            let started = Instant::now();
            let outcome = flow.recv(&mut buf);
            let waited = started.elapsed();
            blocked("recv on a flow no peer answers", outcome)?;
            // Both bounds matter: too soon means the deadline never reached the
            // descriptor and the answer came from somewhere else, and too late
            // means it reached a different option than the one that was set.
            if waited < DEADLINE - Duration::from_millis(50) {
                return Err(format!(
                    "recv gave up after {waited:?}, too soon to have waited the {DEADLINE:?} deadline"
                ));
            }
            if waited > Duration::from_secs(5) {
                return Err(format!(
                    "recv waited {waited:?}, far past the {DEADLINE:?} deadline"
                ));
            }
            Ok(())
        });

        step("setting the read deadline to None clears it", || {
            flow.set_read_timeout(None)
                .map_err(|e| format!("set_read_timeout(None): {e}"))?;
            let got = flow
                .read_timeout()
                .map_err(|e| format!("read_timeout: {e}"))?;
            same("the read deadline", got, None)
        });

        step("set_read_timeout refuses a zero duration", || {
            errno(
                "set_read_timeout(Some(0))",
                flow.set_read_timeout(Some(Duration::ZERO)),
                libc::EINVAL,
            )
        });

        step(
            "write_timeout reads back the deadline set_write_timeout set",
            || {
                flow.set_write_timeout(Some(DEADLINE))
                    .map_err(|e| format!("set_write_timeout(Some({DEADLINE:?})): {e}"))?;
                let got = flow
                    .write_timeout()
                    .map_err(|e| format!("write_timeout: {e}"))?;
                same("the write deadline", got, Some(DEADLINE))
            },
        );

        step("setting the write deadline to None clears it", || {
            flow.set_write_timeout(None)
                .map_err(|e| format!("set_write_timeout(None): {e}"))?;
            let got = flow
                .write_timeout()
                .map_err(|e| format!("write_timeout: {e}"))?;
            same("the write deadline", got, None)
        });

        step("set_write_timeout refuses a zero duration", || {
            errno(
                "set_write_timeout(Some(0))",
                flow.set_write_timeout(Some(Duration::ZERO)),
                libc::EINVAL,
            )
        });

        // ── Non-blocking ──────────────────────────────────────────────────
        step("a non-blocking flow refuses to wait in recv", || {
            flow.set_nonblocking(true)
                .map_err(|e| format!("set_nonblocking(true) on a flow: {e}"))?;
            let mut buf = [0u8; 64];
            let started = Instant::now();
            let outcome = flow.recv(&mut buf);
            let waited = started.elapsed();
            blocked("recv on a non-blocking flow", outcome)?;
            // The read deadline was cleared two assertions ago, so a
            // set_nonblocking that did nothing would park here for ever and the
            // watchdog would name this step. This bound therefore carries only
            // the narrow shape where set_nonblocking armed a short deadline
            // instead of the descriptor's mode. It is deliberately loose: it is
            // still an order of magnitude under the cleared-deadline case, and
            // tightening it buys no discrimination while inviting a flake when
            // the runner is loaded.
            if waited > Duration::from_millis(250) {
                return Err(format!(
                    "recv on a non-blocking flow took {waited:?}, which is a wait rather than a refusal"
                ));
            }
            Ok(())
        });

        step("a non-blocking listener refuses to wait in accept", || {
            held.set_nonblocking(true)
                .map_err(|e| format!("set_nonblocking(true) on a listener: {e}"))?;
            blocked("accept on a non-blocking listener", held.accept())
        });

        step(
            "a failed accept is an incoming item rather than the end of the iteration",
            || match held.incoming().next() {
                None => Err("incoming ended, and a listener has no last flow".to_string()),
                Some(item) => blocked("the first incoming item", item),
            },
        );

        // ── Descriptors ───────────────────────────────────────────────────
        step(
            "the flow's borrowed descriptor is the number its raw one gives",
            || {
                same(
                    "the flow's descriptor",
                    flow.as_fd().as_raw_fd(),
                    flow.as_raw_fd(),
                )
            },
        );

        step(
            "the listener's borrowed descriptor is the number its raw one gives",
            || {
                same(
                    "the listener's descriptor",
                    held.as_fd().as_raw_fd(),
                    held.as_raw_fd(),
                )
            },
        );

        step("a flow and a listener hold different descriptors", || {
            let (one, other) = (flow.as_raw_fd(), held.as_raw_fd());
            if one == other {
                return Err(format!("both report descriptor {one}"));
            }
            Ok(())
        });

        step(
            "the flow's descriptor can be duplicated, so it names an open file",
            || {
                flow.as_fd()
                    .try_clone_to_owned()
                    .map(drop)
                    .map_err(|e| format!("duplicating the flow's descriptor: {e}"))
            },
        );

        step(
            "the listener's descriptor can be duplicated, so it names an open file",
            || {
                held.as_fd()
                    .try_clone_to_owned()
                    .map(drop)
                    .map_err(|e| format!("duplicating the listener's descriptor: {e}"))
            },
        );

        step(
            "poll reports neither the flow nor the listener readable while nothing has arrived",
            || {
                if readable(flow.as_raw_fd())? {
                    return Err("the flow is readable and no peer has sent anything".to_string());
                }
                if readable(held.as_raw_fd())? {
                    return Err("the listener is readable and no flow has arrived".to_string());
                }
                Ok(())
            },
        );

        // ── Limits ────────────────────────────────────────────────────────
        step(
            "max_payload is what the daemon computed for this transport",
            || {
                same(
                    "the largest datagram this flow carries",
                    flow.max_payload(),
                    PAYLOAD,
                )
            },
        );

        step(
            "a datagram of exactly max_payload bytes is accepted",
            || {
                let datagram = vec![0x5a; flow.max_payload()];
                flow.send(&datagram)
                    .map_err(|e| format!("send of {} bytes: {e}", datagram.len()))
            },
        );

        step(
            "a datagram one byte past max_payload is refused with EMSGSIZE",
            || {
                let datagram = vec![0x5a; flow.max_payload() + 1];
                errno(
                    "send of one byte past the limit",
                    flow.send(&datagram),
                    libc::EMSGSIZE,
                )
            },
        );
    }

    /// Walk the surface, and print how many assertions held.
    pub fn run() -> ExitCode {
        let mut args = env::args().skip(1);
        let (Some(mode), Some(sock), Some(peer)) = (args.next(), args.next(), args.next()) else {
            eprintln!("usage: native-surface walk <socket-path> <peer-npub>");
            return ExitCode::FAILURE;
        };
        if mode != "walk" {
            eprintln!("native-surface: {mode:?} is not a mode; the modes are: walk");
            return ExitCode::FAILURE;
        }
        // The walk is given a path because `connect_at` and `bind_at` are items
        // in their own right and need one. The forms that take no path resolve
        // SOCKET, which is the same daemon only when the caller mounted it
        // there; a mismatch would fail those calls with ENOENT and read as a
        // defect in the surface rather than in the invocation.
        if sock != SOCKET {
            eprintln!(
                "native-surface: the no-path calls resolve {SOCKET}, so the walk has to be given \
                 that path, not {sock}"
            );
            return ExitCode::FAILURE;
        }
        let node = match FipsAddr::from_str(&format!("{peer}:0")) {
            Ok(node) => node,
            Err(error) => {
                eprintln!("native-surface: {peer:?} is not an npub: {error}");
                return ExitCode::FAILURE;
            }
        };
        let key: XOnlyPublicKey = node.key();

        watchdog();
        walk(Path::new(&sock), &peer, key);

        // The count is the recorder's, not a literal: a block that stopped
        // running still reaches this line, and only the number betrays it.
        println!(
            "native-surface: walk complete, {} assertions passed",
            PASSED.load(Ordering::SeqCst)
        );
        let _ = io::stdout().flush();
        ExitCode::SUCCESS
    }
}

/// Walk the surface once and report.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn main() -> std::process::ExitCode {
    surface::run()
}

/// Refuse cleanly where the native API client is not built.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "native-surface needs the native datagram API client, which is built on \
         Linux and FreeBSD only"
    );
    std::process::ExitCode::FAILURE
}
