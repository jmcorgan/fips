//! Log events raised while a config loads, held until the log is set up.
//!
//! The daemon loads its config before it installs a subscriber, because the
//! config chooses the log level and the log file. An event raised during the
//! load, such as the warning that a removed or deprecated key was set, would
//! reach no subscriber and be lost. Loading under [`LoadLog::hold`] keeps
//! those events, and [`LoadLog::replay`] emits them once the log exists.

use std::sync::{Arc, Mutex};
use tracing::Level;

/// Events held from a config load, each as its level and formatted text.
#[derive(Clone, Default)]
pub struct LoadLog(Arc<Mutex<Vec<(Level, String)>>>);

impl LoadLog {
    /// Run `load` with every event it raises on this thread held, not emitted.
    pub fn hold<T>(load: impl FnOnce() -> T) -> (T, Self) {
        use tracing_subscriber::layer::SubscriberExt;

        let held = Self::default();
        let subscriber = tracing_subscriber::registry().with(held.clone());
        let out = tracing::subscriber::with_default(subscriber, load);
        (out, held)
    }

    /// Emit the held events, in order, to the current subscriber.
    ///
    /// Each keeps its level. The target is `fips::config` for all of them,
    /// because a tracing target must be fixed where the event is written.
    pub fn replay(self) {
        let events = std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()));
        for (level, text) in events {
            match level {
                Level::ERROR => tracing::error!(target: "fips::config", "{text}"),
                Level::WARN => tracing::warn!(target: "fips::config", "{text}"),
                Level::INFO => tracing::info!(target: "fips::config", "{text}"),
                Level::DEBUG => tracing::debug!(target: "fips::config", "{text}"),
                Level::TRACE => tracing::trace!(target: "fips::config", "{text}"),
            }
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LoadLog {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        /// Formats the message, then any other fields as ` name=value`.
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = if field.name() == "message" {
                    write!(self.0, "{value:?}")
                } else {
                    write!(self.0, " {}={value:?}", field.name())
                };
            }
        }

        let mut text = Text(String::new());
        event.record(&mut text);
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((*event.metadata().level(), text.0));
    }
}
