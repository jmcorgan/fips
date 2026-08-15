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
#[derive(Clone, Default)]
pub(crate) struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl LogCapture {
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

/// Run `f` with a capturing subscriber installed, returning its value and the capture.
pub(crate) fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, LogCapture) {
    use tracing_subscriber::layer::SubscriberExt;

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

    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    (capture, guard)
}
