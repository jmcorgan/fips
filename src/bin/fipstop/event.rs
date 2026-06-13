use ratatui::crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub enum Event {
    Key(KeyEvent),
    Resize,
    Tick,
}

/// Upper bound on a single `event::poll` wait. Kept short (vs the full
/// tick interval) so [`EventHandler::stop`] can join the input thread
/// promptly at quit instead of blocking for up to a refresh interval.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

pub struct EventHandler {
    rx: mpsc::Receiver<Event>,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = Arc::clone(&running);

        let handle = thread::spawn(move || {
            let mut last_tick = Instant::now();
            while thread_running.load(Ordering::Relaxed) {
                // Bound the poll by the time left until the next tick, but
                // never longer than POLL_INTERVAL so the running flag is
                // checked (and quit honored) promptly.
                let timeout = tick_rate
                    .saturating_sub(last_tick.elapsed())
                    .min(POLL_INTERVAL);

                match event::poll(timeout) {
                    Ok(true) => match event::read() {
                        Ok(CrosstermEvent::Key(key)) => {
                            if tx.send(Event::Key(key)).is_err() {
                                return;
                            }
                        }
                        Ok(CrosstermEvent::Resize(..)) => {
                            if tx.send(Event::Resize).is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => return,
                    },
                    Ok(false) => {}
                    Err(_) => return,
                }

                if last_tick.elapsed() >= tick_rate {
                    if tx.send(Event::Tick).is_err() {
                        return;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        Self {
            rx,
            running,
            handle: Some(handle),
        }
    }

    pub fn next(&self) -> Result<Event, mpsc::RecvError> {
        self.rx.recv()
    }

    /// Stop the input thread and wait for it to exit. Call this before
    /// restoring the terminal so the thread is not still reading stdin
    /// after raw mode is disabled — otherwise stray bytes (a keystroke or
    /// a terminal query response) echo onto the restored screen, which is
    /// especially visible over SSH/tmux.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EventHandler {
    fn drop(&mut self) {
        self.stop();
    }
}
