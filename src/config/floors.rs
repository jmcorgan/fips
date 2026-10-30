//! Bounds applied to configured values before a node runs with them.
//!
//! A value outside its bound is not refused: the node runs at the bound and
//! logs one warning naming the key, the configured value and the value used,
//! so a deployed config that sets it keeps starting.

use super::Config;
use crate::node::REKEY_HANDSHAKE;
use crate::peer::machine::DISCOVERY_RESENDS;
use std::fmt::Display;

/// Least time in seconds a link must stay silent before it is declared dead
/// (FRC-1201 Section 6.4).
const DEAD_FLOOR: u64 = 30;

/// Least lifetime in seconds of a coordinate cache entry since it was last
/// written or read (FRC-1404 Section 4.5.1).
const COORD_FLOOR: u64 = 300;

/// Least lifetime in seconds of a Nostr traversal signal (FRC-1601 Section
/// 3.4, as are the three below).
const SIGNAL_FLOOR: u64 = 120;

/// Least time in seconds a punch attempt runs before it is given up.
const ATTEMPT_FLOOR: u64 = 10;

/// Least number of traversal offers a node handles at once.
const OFFERS_FLOOR: usize = 16;

/// Least number of traversal offers a node handles at once from one sender.
const SENDER_FLOOR: usize = 4;

impl Config {
    /// Bring every value a protocol bound covers inside its bound, warning
    /// once for each one changed. A value bounded only for some uses is
    /// kept, and capped where it is used; a warning says so.
    ///
    /// A second call changes nothing.
    pub(crate) fn apply_floors(&mut self) {
        self.floor_linkdead();
        self.warn_resends();
        self.warn_rekey();
        self.floor_coord();
        self.floor_signal();
        self.floor_attempt();
        self.floor_offers();
    }

    /// Raise `node.link_dead_timeout_secs` to 30 s.
    fn floor_linkdead(&mut self) {
        raise(
            "node.link_dead_timeout_secs",
            &mut self.node.link_dead_timeout_secs,
            DEAD_FLOOR,
            "configured value is below the 30 s a link must stay silent before it is declared dead; running at 30 s",
        );
    }

    /// Warn when `node.rate_limit.handshake_max_resends` is above the cap on
    /// a handshake an mDNS advert directs at an unconfigured node.
    ///
    /// The value is kept: dials to configured peers use it as given, and
    /// the retransmit driver caps only those handshakes.
    fn warn_resends(&self) {
        let configured = self.node.rate_limit.handshake_max_resends;
        if configured > DISCOVERY_RESENDS {
            clamped(
                "node.rate_limit.handshake_max_resends",
                configured,
                DISCOVERY_RESENDS,
                "configured value is above the 5 msg1 resends allowed to a handshake an mDNS advert directs at a node not configured to dial; those handshakes resend at most 5 times",
            );
        }
    }

    /// Warn when `node.rate_limit.handshake_timeout_secs` is above the 30 s
    /// term of a link rekey attempt.
    ///
    /// The value is kept: initial link handshakes and session handshakes
    /// use it as given, and the link rekey parameters cap it.
    fn warn_rekey(&self) {
        let configured = self.node.rate_limit.handshake_timeout_secs;
        if configured > REKEY_HANDSHAKE {
            clamped(
                "node.rate_limit.handshake_timeout_secs",
                configured,
                REKEY_HANDSHAKE,
                "configured value is above the 30 s a link rekey attempt may run; link rekey attempts end within 30 s",
            );
        }
    }

    /// Raise `node.cache.coord_ttl_secs` to 300 s.
    fn floor_coord(&mut self) {
        raise(
            "node.cache.coord_ttl_secs",
            &mut self.node.cache.coord_ttl_secs,
            COORD_FLOOR,
            "configured value is below the 300 s least lifetime of a coordinate cache entry; running at 300 s",
        );
    }

    /// Raise `node.rendezvous.nostr.signal_ttl_secs` to 120 s.
    ///
    /// Applied before validation, so the replay-window check sees the
    /// lifetime the node runs with.
    fn floor_signal(&mut self) {
        raise(
            "node.rendezvous.nostr.signal_ttl_secs",
            &mut self.node.rendezvous.nostr.signal_ttl_secs,
            SIGNAL_FLOOR,
            "configured value is below the 120 s least lifetime of a traversal signal; running at 120 s",
        );
    }

    /// Raise `node.rendezvous.nostr.attempt_timeout_secs` to 10 s.
    fn floor_attempt(&mut self) {
        raise(
            "node.rendezvous.nostr.attempt_timeout_secs",
            &mut self.node.rendezvous.nostr.attempt_timeout_secs,
            ATTEMPT_FLOOR,
            "configured value is below the 10 s least punch attempt timeout; running at 10 s",
        );
    }

    /// Raise the two inbound traversal offer limits to 16 at once and 4 from
    /// one sender, 0 included.
    fn floor_offers(&mut self) {
        let nostr = &mut self.node.rendezvous.nostr;
        raise(
            "node.rendezvous.nostr.max_concurrent_incoming_offers",
            &mut nostr.max_concurrent_incoming_offers,
            OFFERS_FLOOR,
            "configured value is below the 16 traversal offers a node must handle at once; running at 16",
        );
        raise(
            "node.rendezvous.nostr.max_concurrent_offers_per_npub",
            &mut nostr.max_concurrent_offers_per_npub,
            SENDER_FLOOR,
            "configured value is below the 4 traversal offers a node must handle at once from one sender; running at 4",
        );
    }
}

/// Raise `value`, configured as `key`, to `floor` when it is below it,
/// logging `why` with the key, the configured value and the value used.
fn raise<T: Copy + PartialOrd + Display>(key: &'static str, value: &mut T, floor: T, why: &str) {
    if *value < floor {
        clamped(key, *value, floor, why);
        *value = floor;
    }
}

/// Log that `key` was configured as `configured` and is used as `used`, for
/// the reason `why`.
fn clamped(key: &'static str, configured: impl Display, used: impl Display, why: &str) {
    tracing::warn!(
        target: "fips::config",
        key,
        configured = %configured,
        used = %used,
        "{why}"
    );
}

#[cfg(test)]
#[path = "tests/floors.rs"]
mod tests;
