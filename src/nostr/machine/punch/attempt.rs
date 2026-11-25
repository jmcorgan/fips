//! A punch attempt, as a machine (FRC-1601 Section 6.3).
//!
//! The attempt probes every planned target once a round, from the start the
//! punch hint names until its duration has passed, and reads what arrives on
//! the traversal socket in the order the FRC's receive steps give: a source
//! that is not a planned target's address is refused before anything else,
//! a probe is acked, an exact target is adopted at once, and a target's
//! address on another port (a symmetric NAT's fresh mapping) is held for a
//! short settle so that an exact target answering inside it wins. It ends
//! with the address to adopt, or with nothing when its timeout passes. The
//! socket and the clocks are the caller's: the attempt says what to send
//! with [`PunchOut`] and is told what arrived.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use fips_core::time::{Instant, deadline};

use super::super::error::Error;
use super::super::types::{PunchHint, PunchPacketKind};
use super::plan::{SourceRank, rank_punch_source};
use super::{PunchAction, build_punch_packet, classify_punch_packet, session_hash};

/// How long the attempt keeps listening for an exact target once it has
/// already held a planned target's address on a different port.
///
/// A source that matches a planned target's IP but not its port is what a
/// symmetric NAT's fresh mapping toward us looks like, and it is worth
/// adopting; a source that matches a target exactly is worth more, so the
/// first remapped source does not end the attempt outright. Raising this
/// delays adoption on the remapped path only, never past the attempt's
/// timeout; lowering it toward zero makes the first remapped source win.
pub const PUNCH_SETTLE: Duration = Duration::from_millis(250);

/// The shortest interval between probe rounds.
const MIN_ROUND_INTERVAL: Duration = Duration::from_millis(20);

/// What the attempt asks its caller to do, or tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchOut {
    /// Send `bytes` to `dst` on the traversal socket. A failed send is
    /// ignored: the next round sends again.
    Send { dst: SocketAddr, bytes: Vec<u8> },
    /// The attempt ended: adopt the socket toward this address.
    Adopt(SocketAddr),
    /// The attempt's timeout passed with nothing to adopt.
    TimedOut,
}

/// What an attempt refused or failed on, counted rather than reported one
/// by one: the peer or a third party sets how many there are, so a record
/// each would trade the adoption the checks close for log volume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    /// Punch packets from a source that is no planned target's address.
    pub unplanned: usize,
    /// Held remapped sources a later one replaced.
    pub superseded: usize,
    /// Receives that failed on the socket.
    pub recv_errors: usize,
    /// The last receive error's text.
    pub last_error: Option<String>,
}

/// One punch attempt.
#[derive(Debug)]
pub struct Attempt<I> {
    session: String,
    targets: Vec<SocketAddr>,
    hash: [u8; 16],
    /// The next probe round, while rounds remain.
    next_round: Option<I>,
    /// Rounds are sent while their instant is before this one. Fixed when
    /// the first round goes out.
    send_until: Option<I>,
    duration: Duration,
    interval: Duration,
    sequence: u32,
    finish_at: I,
    settle_at: Option<I>,
    candidate: Option<SocketAddr>,
    tally: Tally,
    done: bool,
}

impl<I: Instant> Attempt<I> {
    /// An attempt for `session_id` toward `targets`, started at `now` (and
    /// `now_ms` in Unix time), probing per `hint`, and ending at `now` plus
    /// `timeout` if nothing is adopted first. The hint's start, in Unix
    /// time, is converted once to a monotonic deadline. With no target
    /// there is nothing to punch.
    pub fn new(
        session_id: &str,
        targets: Vec<SocketAddr>,
        hint: &PunchHint,
        timeout: Duration,
        now: I,
        now_ms: u64,
    ) -> Result<Self, Error> {
        if targets.is_empty() {
            return Err(Error::Protocol(String::from("no-punch-targets")));
        }
        let start = deadline(
            now,
            Duration::from_millis(hint.start_at_ms.saturating_sub(now_ms)),
        );
        Ok(Self {
            session: String::from(session_id),
            hash: session_hash(session_id),
            targets,
            next_round: Some(start),
            send_until: None,
            duration: Duration::from_millis(hint.duration_ms.max(1)),
            interval: Duration::from_millis(hint.interval_ms).max(MIN_ROUND_INTERVAL),
            sequence: 0,
            finish_at: deadline(now, timeout),
            settle_at: None,
            candidate: None,
            tally: Tally::default(),
            done: false,
        })
    }

    /// What the attempt refused or failed on so far.
    pub fn tally(&self) -> &Tally {
        &self.tally
    }

    /// The next instant at which [`Self::timeout`] is due, while the attempt
    /// runs: the next round, or the end of the settle or of the attempt.
    pub fn deadline(&self) -> Option<I> {
        if self.done {
            return None;
        }
        let end = self
            .settle_at
            .map_or(self.finish_at, |settle| settle.min(self.finish_at));
        Some(self.next_round.map_or(end, |round| round.min(end)))
    }

    /// Run what is due at `now`: the end of the attempt, or a probe round.
    pub fn timeout(&mut self, now: I) -> Vec<PunchOut> {
        if self.done {
            return Vec::new();
        }
        let end = self
            .settle_at
            .map_or(self.finish_at, |settle| settle.min(self.finish_at));
        if now >= end {
            self.done = true;
            return alloc::vec![match self.candidate {
                Some(remote) => PunchOut::Adopt(remote),
                None => PunchOut::TimedOut,
            }];
        }
        let Some(round) = self.next_round.filter(|round| *round <= now) else {
            return Vec::new();
        };
        let until = *self
            .send_until
            .get_or_insert_with(|| deadline(round, self.duration));
        if now >= until {
            self.next_round = None;
            return Vec::new();
        }
        let packet = build_punch_packet(PunchPacketKind::Probe, self.sequence, &self.session);
        self.sequence = self.sequence.wrapping_add(1);
        self.next_round = Some(deadline(now, self.interval));
        self.targets
            .iter()
            .map(|target| PunchOut::Send {
                dst: *target,
                bytes: packet.to_vec(),
            })
            .collect()
    }

    /// A datagram from `src` arrived on the traversal socket at `now`.
    pub fn datagram(&mut self, src: SocketAddr, bytes: &[u8], now: I) -> Vec<PunchOut> {
        if self.done {
            return Vec::new();
        }
        // Ranked ahead of the ack, not only ahead of the adoption: acking a
        // source we never planned to probe is a reflection this node
        // controls, and there is no reason to emit it. The packet's own
        // discriminator is a digest of a value both peers already know and
        // travels in the clear in every probe, so it proves only that the
        // sender saw one.
        let rank = rank_punch_source(src, &self.targets);
        if rank == SourceRank::Unplanned {
            self.tally.unplanned += 1;
            return Vec::new();
        }
        let mut out = Vec::new();
        match classify_punch_packet(bytes, self.hash) {
            PunchAction::Ignore => return out,
            PunchAction::Ack { sequence } => {
                let ack = build_punch_packet(PunchPacketKind::Ack, sequence, &self.session);
                out.push(PunchOut::Send {
                    dst: src,
                    bytes: ack.to_vec(),
                });
            }
            PunchAction::Matched => {}
        }
        if rank == SourceRank::Planned {
            self.done = true;
            out.push(PunchOut::Adopt(src));
        } else {
            self.hold_remapped(src, now);
        }
        out
    }

    /// A receive on the traversal socket failed with `error`. It reports
    /// something about a datagram sent earlier, such as an ICMP error
    /// answering a probe to a closed port, not that the socket is unusable,
    /// so the attempt goes on: the peer's probe can still arrive after it.
    pub fn recv_error(&mut self, error: String) {
        self.tally.recv_errors += 1;
        self.tally.last_error = Some(error);
    }

    /// Hold `remote`, a planned target's address on another port, until the
    /// settle passes, so an exact target answering inside it supersedes it.
    fn hold_remapped(&mut self, remote: SocketAddr, now: I) {
        if self.candidate.replace(remote).is_some() {
            self.tally.superseded += 1;
        }
        self.settle_at
            .get_or_insert_with(|| deadline(now, PUNCH_SETTLE));
    }
}

#[cfg(test)]
#[path = "tests/attempt.rs"]
mod tests;
