//! Path MTU tracking for a single session (sans-IO, session-layer only).
//!
//! Destination side observes `path_mtu` from incoming envelopes and emits
//! notifications; source side applies received notifications to bound outbound
//! datagram size. All time inputs are injected `u64` milliseconds.

/// Path MTU tracking for a single session.
///
/// Destination side: observes `path_mtu` from incoming SessionDatagram envelopes
/// and generates PathMtuNotification messages back to the source.
///
/// Source side: applies received PathMtuNotification to limit outbound datagram
/// size. Decrease is immediate; increase requires 3 consecutive notifications.
pub struct PathMtuState {
    /// Current effective path MTU (what we use for sending).
    current_mtu: u16,
    /// Last observed path MTU from incoming datagrams (destination-side).
    last_observed_mtu: u16,
    /// Whether the observed MTU has changed since the last notification.
    observed_changed: bool,
    /// Last time (injected `u64` ms) a PathMtuNotification was sent.
    last_notification_ms: Option<u64>,
    /// Notification interval in ms: max(10s, 5 * SRTT). Default 10s.
    notification_interval_ms: u64,
    /// For source-side increase tracking: consecutive higher-value notifications.
    consecutive_increase_count: u8,
    /// Time (injected `u64` ms) of the first notification in the current
    /// increase sequence.
    first_increase_ms: Option<u64>,
    /// The MTU value being proposed for increase.
    pending_increase_mtu: u16,
}

impl PathMtuState {
    /// Create path MTU state with no initial measurement.
    pub fn new() -> Self {
        Self {
            current_mtu: u16::MAX,
            last_observed_mtu: u16::MAX,
            observed_changed: false,
            last_notification_ms: None,
            notification_interval_ms: 10_000,
            consecutive_increase_count: 0,
            first_increase_ms: None,
            pending_increase_mtu: 0,
        }
    }

    /// Current effective path MTU (source-side, for sending).
    pub fn current_mtu(&self) -> u16 {
        self.current_mtu
    }

    /// Last observed incoming path MTU (destination-side).
    pub fn last_observed_mtu(&self) -> u16 {
        self.last_observed_mtu
    }

    /// Update notification interval from SRTT: max(10s, 5 * SRTT).
    pub fn update_interval_from_srtt(&mut self, srtt_ms: f64) {
        self.notification_interval_ms = ((srtt_ms * 5.0) as u64).max(10_000);
    }

    /// Seed source-side current_mtu from outbound transport MTU.
    ///
    /// Called on each send. Only decreases (never increases) the current_mtu
    /// so the destination's PathMtuNotification can still raise it later.
    /// Ensures current_mtu doesn't stay at u16::MAX before any notification
    /// arrives from the destination.
    pub fn seed_source_mtu(&mut self, outbound_mtu: u16) {
        if outbound_mtu < self.current_mtu {
            self.current_mtu = outbound_mtu;
        }
    }

    // --- Destination side ---

    /// Observe the path_mtu from an incoming SessionDatagram envelope.
    ///
    /// Called on the destination (receiver) side for every session message.
    pub fn observe_incoming_mtu(&mut self, path_mtu: u16) {
        if path_mtu != self.last_observed_mtu {
            self.observed_changed = true;
            self.last_observed_mtu = path_mtu;
        }
    }

    /// Check if a PathMtuNotification should be sent.
    ///
    /// Send on first measurement, on decrease (immediate), or periodic
    /// confirmation at the notification interval. `now_ms` is the injected
    /// monotonic time in milliseconds.
    pub fn should_send_notification(&self, now_ms: u64) -> bool {
        if self.last_observed_mtu == u16::MAX {
            return false; // No measurement yet
        }
        match self.last_notification_ms {
            None => true, // First measurement
            Some(last) => {
                // Immediate on decrease
                if self.observed_changed && self.last_observed_mtu < self.current_mtu {
                    return true;
                }
                // Periodic confirmation
                now_ms.saturating_sub(last) >= self.notification_interval_ms
            }
        }
    }

    /// Build a PathMtuNotification from current state.
    ///
    /// Returns the path_mtu value to send. Caller handles encoding.
    pub fn build_notification(&mut self, now_ms: u64) -> Option<u16> {
        if self.last_observed_mtu == u16::MAX {
            return None;
        }
        self.last_notification_ms = Some(now_ms);
        self.observed_changed = false;
        Some(self.last_observed_mtu)
    }

    // --- Source side ---

    /// Apply a received PathMtuNotification.
    ///
    /// - Decrease: immediate (take the lower value).
    /// - Increase: require 3 consecutive notifications with the same higher
    ///   value, spanning at least 2 * notification_interval.
    ///
    /// `now_ms` is the injected monotonic time in milliseconds. Returns `true`
    /// if the effective MTU changed.
    pub fn apply_notification(&mut self, reported_mtu: u16, now_ms: u64) -> bool {
        if reported_mtu < self.current_mtu {
            // Decrease: immediate
            self.current_mtu = reported_mtu;
            self.consecutive_increase_count = 0;
            self.first_increase_ms = None;
            return true;
        }

        if reported_mtu > self.current_mtu {
            // Increase: track consecutive notifications
            if reported_mtu == self.pending_increase_mtu {
                self.consecutive_increase_count += 1;
            } else {
                // Different value: reset sequence
                self.pending_increase_mtu = reported_mtu;
                self.consecutive_increase_count = 1;
                self.first_increase_ms = Some(now_ms);
            }

            // Accept increase after 3 consecutive spanning 2 * interval
            if self.consecutive_increase_count >= 3
                && let Some(first_ms) = self.first_increase_ms
            {
                let required_ms = self.notification_interval_ms * 2;
                if now_ms.saturating_sub(first_ms) >= required_ms {
                    self.current_mtu = reported_mtu;
                    self.consecutive_increase_count = 0;
                    self.first_increase_ms = None;
                    return true;
                }
            }
        }

        // No change (equal or increase not yet confirmed)
        false
    }
}

impl Default for PathMtuState {
    fn default() -> Self {
        Self::new()
    }
}
