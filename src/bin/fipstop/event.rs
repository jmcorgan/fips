use ratatui::crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub enum Event {
    Key(KeyEvent),
    Resize,
    Tick,
}

pub struct EventHandler {
    rx: mpsc::Receiver<Event>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || loop {
            if event::poll(tick_rate).unwrap_or(false) {
                if let Ok(evt) = event::read() {
                    match evt {
                        CrosstermEvent::Key(key) => {
                            if tx.send(Event::Key(key)).is_err() {
                                return;
                            }
                        }
                        CrosstermEvent::Resize(..) => {
                            if tx.send(Event::Resize).is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                // Poll timed out — send a tick
                if tx.send(Event::Tick).is_err() {
                    return;
                }
            }
        });

        Self { rx }
    }

    pub fn next(&self) -> Result<Event, mpsc::RecvError> {
        self.rx.recv()
    }
}
