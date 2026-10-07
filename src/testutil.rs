//! Crate-wide generic test helpers.

use crate::NodeAddr;

/// Build a `NodeAddr` from a single discriminating byte in position 0.
pub(crate) fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

/// Collects emitted tracing events so a test can assert on a log line.
///
/// Some behaviour is reported only in the log: a structured field an operator
/// greps on is part of the contract even when no counter or return value
/// carries it. Installed with `tracing::subscriber::with_default`, which is
/// thread-local, so tests running in parallel do not see each other's events.
///
/// Thread-local capture alone is not enough. tracing caches whether anyone is
/// interested in a callsite when the callsite is first used, and while a
/// single subscriber exists it asks only the thread that got there first. A
/// test thread with no subscriber of its own falls back to the global
/// default, and with none set that answers "never", so a capture on another
/// thread that later reaches the same callsite never sees its event. The
/// capture helpers therefore install a quiet global default once per test
/// process. It records nothing, but it answers "sometimes", so the callsite
/// is checked again on every event and the capturing thread's subscriber
/// gets to say yes. Lib tests must not set a tracing global default of their
/// own; use [`capture_logs`] or [`capture_logs_scoped`].
///
/// One case is still open: a thread that began registering a callsite before
/// the quiet default was installed can store "never" after the first capture
/// has already rebuilt interest. The next capture's registration rebuilds it
/// again and clears that, so only a capture live at that moment can lose an
/// event. Closing it would mean installing the default before any test runs,
/// which libtest has no hook for.
#[derive(Clone, Default)]
pub(crate) struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl LogCapture {
    /// Every captured line, each prefixed with its level.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    /// Only the captured lines emitted at WARN.
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("WARN"))
            .cloned()
            .collect()
    }

    /// The first captured line whose message is exactly `message`.
    ///
    /// A substring match would let a message match a longer one it is a
    /// prefix of, so the text must be followed by the end of the line or by
    /// another `name=` field.
    pub(crate) fn line(&self, message: &str) -> Option<String> {
        self.lines()
            .into_iter()
            .find(|line| has_message(line, message))
    }

    /// Every captured line whose message is exactly `message`, in order.
    pub(crate) fn lines_with(&self, message: &str) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|line| has_message(line, message))
            .collect()
    }
}

/// Whether the captured `line`'s message is exactly `message`.
fn has_message(line: &str, message: &str) -> bool {
    let needle = format!(" message={message}");
    line.match_indices(&needle)
        .any(|(at, _)| ends_value(&line[at + needle.len()..]))
}

/// Whether `rest`, the text after a field value, starts where that value
/// ends: at the end of the line or at a following ` name=` field.
fn ends_value(rest: &str) -> bool {
    let Some(next) = rest.strip_prefix(' ') else {
        return rest.is_empty();
    };
    let token = next.split(' ').next().unwrap_or("");
    token.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The value of field `name` in a captured `line`, up to the next space.
///
/// The leading space is part of the match, so `age_s` does not match inside
/// `pending_age_s=`. Fields whose values contain spaces cannot be read this
/// way.
pub(crate) fn log_field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!(" {name}=");
    let start = line.find(&needle)? + needle.len();
    line[start..].split(' ').next()
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", field.name(), value));
            }
        }

        let mut fields = Fields(event.metadata().level().to_string());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

/// The process-wide default the capture helpers install; see [`LogCapture`].
///
/// Interested in every callsite but enabled for none, so it records nothing
/// and never makes tracing cache a callsite as uninteresting.
struct QuietDefault;

impl tracing::Subscriber for QuietDefault {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        None
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Install [`QuietDefault`] as the global default, once per test process.
///
/// Panics, on every call, if another global default got there first: capture
/// is then no longer reliable, and a quiet fallback here would bring back the
/// lost-event race without saying so.
fn install_quiet_default() {
    static INSTALLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let installed =
        *INSTALLED.get_or_init(|| tracing::subscriber::set_global_default(QuietDefault).is_ok());
    assert!(
        installed,
        "another tracing global default was set in the lib tests, so log capture \
         is no longer reliable; capture logs with testutil::capture_logs instead"
    );
}

/// Run `f` with a capturing subscriber installed, returning its value and the capture.
pub(crate) fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, LogCapture) {
    use tracing_subscriber::layer::SubscriberExt;

    install_quiet_default();
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let out = tracing::subscriber::with_default(subscriber, f);
    (out, capture)
}

/// Install a capturing subscriber for the rest of the current scope.
///
/// The async counterpart of [`capture_logs`]: an `async` test cannot wrap its
/// awaits in a closure, so it holds this guard instead and reads the capture
/// once the awaited work has run.
pub(crate) fn capture_logs_scoped() -> (LogCapture, tracing::subscriber::DefaultGuard) {
    use tracing_subscriber::layer::SubscriberExt;

    install_quiet_default();
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    (capture, guard)
}

/// Poll `f` every 10ms until it holds or `limit` elapses.
///
/// Uses tokio's clock, so a test running with paused time advances through
/// the waits instead of sleeping.
pub(crate) async fn wait_until<F: FnMut() -> bool>(mut f: F, limit: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if f() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A local TCP address whose SYNs go unanswered once filled.
///
/// A listener with a backlog of one whose accept queue is filled: Linux,
/// macOS and Windows drop further SYNs to a listener whose accept queue is
/// full, so a connect to it times out rather than completing or being
/// refused. How many connects the queue takes before it is full differs by
/// kernel (one on Linux, more on macOS), so filling stops at the first
/// connect that times out. The listener and the fillers must be kept alive
/// for as long as that is relied on.
///
/// FreeBSD answers a SYN to a full queue from its syncache and then resets
/// the connection, so its queue never goes silent. There, filling replaces
/// the listener with a socket bound to the same address that does not
/// listen, and the kernel must be set not to reset a SYN to a port nobody
/// listens on: `net.inet.tcp.blackhole=2` and `net.inet.tcp.blackhole_local=1`
/// (root). Those settings also stop every refused connect on the host, so a
/// test that needs one cannot run in the same pass; the FreeBSD package
/// workflow runs the tests that use a filled `Blackhole` in a pass of their
/// own.
pub(crate) struct Blackhole {
    pub(crate) listener: socket2::Socket,
    fillers: Vec<std::net::TcpStream>,
    pub(crate) addr: std::net::SocketAddr,
}

impl Blackhole {
    /// A listener with backlog 1. Not 0: macOS reads a backlog of 0 as the
    /// system default (about 128), so its queue would not fill.
    ///
    /// When `fill` is false the accept queue is left empty, so at least one
    /// connect completes; [`Blackhole::fill`] fills it later.
    pub(crate) fn open(fill: bool) -> Self {
        use socket2::{Domain, Socket, Type};
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        listener.bind(&bind.into()).unwrap();
        listener.listen(1).unwrap();
        let addr = listener.local_addr().unwrap().as_socket().unwrap();
        let mut bh = Self {
            listener,
            fillers: Vec::new(),
            addr,
        };
        if fill {
            bh.fill();
        }
        bh
    }

    /// A listener whose SYNs already go unanswered.
    pub(crate) fn silent() -> Self {
        Self::open(true)
    }

    /// Fill the listener's accept queue, stopping at the first connect that
    /// times out, which shows a further connect now times out instead of
    /// completing or being refused.
    #[cfg(not(target_os = "freebsd"))]
    pub(crate) fn fill(&mut self) {
        const MAX_FILLERS: usize = 64;
        for _ in 0..=MAX_FILLERS {
            let probe = std::net::TcpStream::connect_timeout(
                &self.addr,
                std::time::Duration::from_millis(200),
            );
            match probe {
                Ok(filler) => self.fillers.push(filler),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return,
                Err(e) => panic!("blackhole is not silent: probe connect returned {e:?}"),
            }
        }
        panic!("blackhole is not silent: {MAX_FILLERS} connects completed");
    }

    /// Accept every filler still queued on the listener, so the address
    /// answers again: the next connect to it, or the next retransmitted SYN
    /// of one already waiting, completes. Returns the accepted far ends,
    /// which the caller keeps alive while it relies on that.
    #[cfg(not(target_os = "freebsd"))]
    pub(crate) fn drain(&mut self) -> Vec<std::net::TcpStream> {
        self.fillers
            .iter()
            .map(|_| std::net::TcpStream::from(self.listener.accept().unwrap().0))
            .collect()
    }

    /// Close the listener and bind a socket that does not listen to the same
    /// address, then check that a connect to it now times out. Connections
    /// the listener already accepted are left as they are.
    #[cfg(target_os = "freebsd")]
    pub(crate) fn fill(&mut self) {
        use socket2::{Domain, Socket, Type};
        let quiet = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        quiet.set_reuse_address(true).unwrap();
        drop(std::mem::replace(&mut self.listener, quiet));
        self.listener.bind(&self.addr.into()).unwrap();
        let probe =
            std::net::TcpStream::connect_timeout(&self.addr, std::time::Duration::from_millis(200));
        match probe {
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            other => panic!(
                "blackhole is not silent: probe connect returned {other:?}; on FreeBSD \
                 this needs net.inet.tcp.blackhole=2 and net.inet.tcp.blackhole_local=1, \
                 and a test using it belongs in package-freebsd.yml's blackhole pass"
            ),
        }
    }

    /// Start listening on the bound socket, so the address answers again: the
    /// next connect to it, or the next retransmitted SYN of one already
    /// waiting, completes. Nothing was queued, so there are no far ends.
    #[cfg(target_os = "freebsd")]
    pub(crate) fn drain(&mut self) -> Vec<std::net::TcpStream> {
        self.listener.listen(1).unwrap();
        Vec::new()
    }

    /// The address in the transport form.
    pub(crate) fn transport_addr(&self) -> crate::transport::TransportAddr {
        crate::transport::TransportAddr::from_string(&self.addr.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The only use of this `warn!` callsite, so the test below controls
    /// which thread reaches it first.
    fn emit() {
        tracing::warn!("first emitted elsewhere");
    }

    /// A callsite first reached by a thread with no subscriber while a
    /// capture is live must still reach the capture when the capturing thread
    /// emits it.
    ///
    /// tracing-core caches a callsite's interest when it is first used. If
    /// the thread that registers it falls back to no subscriber at all, the
    /// cached interest is `never`, and the capturing thread's event is
    /// dropped before its subscriber sees it. Run alone, this test fails
    /// every time without the quiet global default. In the full suite it
    /// fails only when no other capture is live as it runs, so there it
    /// guards the fix without being certain to catch its removal;
    /// `a_thread_without_a_subscriber_gets_the_quiet_default` is the
    /// deterministic guard.
    #[test]
    fn capture_sees_a_warning_first_emitted_by_a_thread_without_a_subscriber() {
        let ((), logs) = capture_logs(|| {
            std::thread::spawn(emit).join().unwrap();
            emit();
        });
        assert_eq!(logs.warnings().len(), 1, "{:?}", logs.lines());
    }

    /// Once a capture has run, a thread with no subscriber of its own falls
    /// back to the quiet default rather than to no subscriber at all. Fails in
    /// any process, whatever else is running, if both capture helpers stop
    /// installing it.
    #[test]
    fn a_thread_without_a_subscriber_gets_the_quiet_default() {
        let ((), _logs) = capture_logs(|| ());
        assert!(
            other_thread_sees_quiet_default(),
            "capture_logs did not install QuietDefault"
        );
    }

    /// The same for [`capture_logs_scoped`]. Run alone it fails if that
    /// helper stops installing the default; in the full suite any
    /// `capture_logs` call installs it first, so there it cannot tell.
    #[test]
    fn a_thread_without_a_subscriber_gets_the_quiet_default_after_a_scoped_capture() {
        let (_logs, _guard) = capture_logs_scoped();
        assert!(
            other_thread_sees_quiet_default(),
            "capture_logs_scoped did not install QuietDefault"
        );
    }

    /// `line` matches the whole message, not a prefix of a longer one, and
    /// `log_field` matches the whole field name, not the tail of a longer
    /// one.
    #[test]
    fn line_and_log_field_match_whole_messages_and_whole_field_names() {
        let ((), logs) = capture_logs(|| {
            tracing::debug!(
                pending_age_s = 40,
                new_our_index = 7,
                "Resent msg2 for duplicate msg1 (same epoch)"
            );
            tracing::debug!(age_s = 12, our_index = 3, "Resent msg2 for duplicate msg1");
        });
        let short = logs
            .line("Resent msg2 for duplicate msg1")
            .expect("the shorter message is found");
        assert_eq!(log_field(&short, "age_s"), Some("12"), "{short}");
        assert_eq!(log_field(&short, "our_index"), Some("3"), "{short}");

        let long = logs
            .line("Resent msg2 for duplicate msg1 (same epoch)")
            .expect("the longer message is found");
        assert_eq!(log_field(&long, "age_s"), None, "{long}");
        assert_eq!(log_field(&long, "our_index"), None, "{long}");
        assert_eq!(log_field(&long, "pending_age_s"), Some("40"), "{long}");
        assert_eq!(logs.line("Resent msg2 for duplicate"), None);
    }

    /// Whether a fresh thread, with no subscriber of its own, falls back to
    /// [`QuietDefault`].
    fn other_thread_sees_quiet_default() -> bool {
        std::thread::spawn(|| tracing::dispatcher::get_default(|d| d.is::<QuietDefault>()))
            .join()
            .unwrap()
    }
}
