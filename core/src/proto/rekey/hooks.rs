//! What the root crate's tests read from and do to a machine, and the
//! reader of source code both crates' tests use to keep deleted rekey rules
//! out.
//!
//! The tests of the session shell quiet a machine's triggers, and the tests
//! of the link shell move a machine's stamps back in time, force the
//! key-epoch bit and the peer's startup epoch, start an own rekey without
//! its trigger and offer an epoch to a worker pool started after promotion,
//! to stand up the states a link reaches after time has passed or after a
//! peer restart. The core's and the root crate's tests each scan their
//! crate's code for the names of the deployed rekey rules of both layers
//! through [`code_idents`], so the two read code the same way. None of
//! these runs a row or is reachable from `step`, and none exists outside
//! test builds.

use alloc::string::String;
use alloc::vec::Vec;

use super::epoch::Slot;
use super::machine::Rekey;
use super::profile::Profile;
use crate::time::{Clock, Duration, Instant};

/// Inspection the root crate's session tests use.
impl<P: Profile, C: Clock> Rekey<P, C> {
    /// Stop the time and message triggers from starting another rekey, as
    /// the largest thresholds a session can be configured with do. Only the
    /// trigger reads them, so nothing in flight changes; a repair still
    /// starts when one falls due.
    #[doc(hidden)]
    pub fn quiet(&mut self) {
        self.params.cfg.after = crate::time::Duration::from_secs(super::MAX_AFTER);
        self.params.cfg.messages = self.params.cfg.soft;
    }

    /// Move the current epoch's rekey age back by `age`, and the link's age
    /// with it when it would otherwise be the younger, since a link is never
    /// younger than its session.
    #[doc(hidden)]
    pub fn backdate_started(&mut self, age: Duration) {
        if let Some(cur) = self.cur.as_mut() {
            cur.started = cur.started.checked_sub(age).unwrap_or(cur.started);
            self.mem.link_since = self.mem.link_since.min(cur.started);
        }
    }

    /// Move the current epoch's timestamp base back by `age`.
    #[doc(hidden)]
    pub fn backdate_base(&mut self, age: Duration) {
        if let Some(base) = self.cur.as_mut().and_then(|cur| cur.base.as_mut()) {
            *base = base.checked_sub(age).unwrap_or(*base);
        }
    }

    /// Move the end of the drain back by `age`, as if its cutover had
    /// happened that much earlier. No-op when nothing is drained.
    #[doc(hidden)]
    pub fn backdate_drain(&mut self, age: Duration) {
        if let Some(d) = self.drain.as_mut() {
            d.deadline = d.deadline.checked_sub(age).unwrap_or(d.deadline);
        }
    }

    /// Move the pending epoch's install instant back by `age`, and a
    /// responder pending's hold with it, as if it had been installed that
    /// much earlier. No-op when nothing is pending.
    #[doc(hidden)]
    pub fn backdate_pending(&mut self, age: Duration) {
        if let Some(ep) = self.epoch_mut(Slot::Pending) {
            ep.started = ep.started.checked_sub(age).unwrap_or(ep.started);
        }
        if let super::cycle::Cycle::PendR(p) = &mut self.cycle {
            p.deadline = p.deadline.checked_sub(age).unwrap_or(p.deadline);
        }
    }

    /// Move the end of dampening back by `age`. No-op when dampening was
    /// never opened.
    #[doc(hidden)]
    pub fn backdate_dampening(&mut self, age: Duration) {
        if let Some(until) = self.mem.damp.as_mut() {
            *until = until.checked_sub(age).unwrap_or(*until);
        }
    }

    /// Reserve a counter and a send key under the epoch in `slot`, any slot,
    /// for a test that forges a frame as the peer holding the other half of
    /// that epoch would seal it.
    #[doc(hidden)]
    pub fn reserve_slot(
        &mut self,
        slot: Slot,
    ) -> Option<(u64, <P::Session as super::profile::SessionKeys>::SendCopy)> {
        use super::profile::SessionKeys;
        self.epoch_mut(slot).map(|ep| ep.session.reserve())
    }

    /// Start an own rekey at `now` whatever the triggers, floors and gates
    /// say, as a scheduled start would, when the cycle is idle: the stand-in
    /// for a trigger that has come, for a test that needs this node's attempt
    /// in flight on a link of a given age. Empty, changing nothing, when an
    /// attempt or a pending epoch is already held.
    #[doc(hidden)]
    pub fn start_now(&mut self, now: C::Instant, env: &mut super::Env<'_, P>) -> super::Outputs<P> {
        let mut out = super::Outputs::new();
        if matches!(self.cycle, super::cycle::Cycle::Idle) {
            self.start(now, env, &mut out);
        }
        out
    }

    /// Make the current epoch's key-epoch bit `k`, standing up the
    /// out-of-step bits a peer restart or a crossing move leaves behind.
    #[doc(hidden)]
    pub fn force_k(&mut self, k: bool) {
        if let Some(cur) = self.cur.as_mut() {
            cur.k = k;
        }
    }

    /// The key-epoch bit last seen on the peer's frames and the replay
    /// record: what a cross-connection move carries that `view` does not
    /// show.
    #[doc(hidden)]
    pub fn memory(&self) -> (Option<bool>, &super::Record) {
        (self.mem.peer_k, &self.record)
    }

    /// The offer a poll with a decrypt-worker pool makes for the current
    /// epoch while no worker holds it, for a test that starts the pool
    /// after the link was promoted and wants the offer without the poll's
    /// other rows. Empty when the epoch has no index or a worker holds it.
    #[doc(hidden)]
    pub fn offer_held(&self) -> super::Outputs<P> {
        let mut out = super::Outputs::new();
        if let Some(ep) = self.cur.as_ref() {
            self.delegate(ep, true, &mut out);
        }
        out
    }

    /// Whether dampening, opened by the peer's last rekey, still holds at
    /// `now`.
    #[doc(hidden)]
    pub fn dampened(&self, now: C::Instant) -> bool {
        self.mem.damp.is_some_and(|until| now < until)
    }

    /// Record `epoch` as the peer's startup epoch, standing up a peer whose
    /// next handshake shows another one as restarted.
    #[doc(hidden)]
    pub fn force_peer_epoch(&mut self, epoch: Option<[u8; 8]>) {
        self.mem.peer_epoch = epoch;
    }
}

/// `source` with every comment and the contents of every string and
/// character literal blanked to spaces, newlines kept, so each line and
/// position of the code stays where it was.
///
/// The tests that fail when a deleted session rule comes back read only
/// code: prose may still describe the deployed rule, and a `//` inside a
/// literal must not hide the code after it on the same line.
#[doc(hidden)]
pub fn code_text(source: &str) -> String {
    let src = source.as_bytes();
    let len = src.len();
    let mut out = src.to_vec();
    let at = |i: usize, s: &[u8]| src.get(i..i + s.len()) == Some(s);
    let mut i = 0;
    while i < len {
        let b = src[i];
        if at(i, b"//") {
            let end = (i..len).find(|&j| src[j] == b'\n').unwrap_or(len);
            blank(&mut out, i, end);
            i = end;
        } else if at(i, b"/*") {
            let (mut depth, mut j) = (1usize, i + 2);
            while j < len && depth > 0 {
                if at(j, b"/*") {
                    depth += 1;
                    j += 2;
                } else if at(j, b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j.min(len));
            i = j;
        } else if b == b'"' {
            let mut j = i + 1;
            while j < len && src[j] != b'"' {
                j += if src[j] == b'\\' { 2 } else { 1 };
            }
            blank(&mut out, i + 1, j.min(len));
            i = j + 1;
        } else if b == b'\'' {
            // A character literal, unless the quote starts a lifetime.
            let width = source[i + 1..].chars().next().map_or(0, char::len_utf8);
            if src.get(i + 1) == Some(&b'\\') {
                let end = (i + 3..len).find(|&j| src[j] == b'\'').unwrap_or(len);
                blank(&mut out, i + 1, end);
                i = end + 1;
            } else if width > 0 && src.get(i + 1 + width) == Some(&b'\'') {
                blank(&mut out, i + 1, i + 1 + width);
                i += width + 2;
            } else {
                i += 1;
            }
        } else if ident(b) {
            // A whole word at once, so only an `r` or `br` that is a word
            // of its own opens a raw string.
            let start = i;
            while i < len && ident(src[i]) {
                i += 1;
            }
            let word = &src[start..i];
            let hashes = src[i..].iter().take_while(|&&c| c == b'#').count();
            if (word == b"r" || word == b"br") && src.get(i + hashes) == Some(&b'"') {
                let body = i + hashes + 1;
                let closes = |j: usize| {
                    src[j] == b'"'
                        && src[j + 1..].iter().take_while(|&&c| c == b'#').count() >= hashes
                };
                let end = (body..len).find(|&j| closes(j)).unwrap_or(len);
                blank(&mut out, body, end);
                i = end + 1 + hashes;
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// The identifiers the code of `source` names, each with its line number,
/// leaving out comments and literals as [`code_text`] does.
#[doc(hidden)]
pub fn code_idents(source: &str) -> Vec<(usize, String)> {
    let code = code_text(source);
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        out.extend(
            line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| !w.is_empty())
                .map(|w| (n + 1, String::from(w))),
        );
    }
    out
}

/// The line numbers in `source` that open an item (a function, an `impl`,
/// a type or a module) which [`code_text`] blanked: lines where the reader
/// took code for a comment or a literal, so a scan through it would read
/// nothing there.
#[doc(hidden)]
pub fn lost_items(source: &str) -> Vec<usize> {
    const OPENS: &[&str] = &[
        "fn ",
        "pub fn ",
        "pub(crate) fn ",
        "impl",
        "struct ",
        "pub struct ",
        "enum ",
        "pub enum ",
        "mod ",
        "pub mod ",
    ];
    let code = code_text(source);
    source
        .lines()
        .zip(code.lines())
        .enumerate()
        .filter(|(_, (src, code))| {
            let (src, code) = (src.trim_start(), code.trim_start());
            OPENS
                .iter()
                .any(|open| src.starts_with(open) && !code.starts_with(open))
        })
        .map(|(n, _)| n + 1)
        .collect()
}

/// Overwrites `out[from..to]` with spaces, keeping its newlines.
fn blank(out: &mut [u8], from: usize, to: usize) {
    for b in &mut out[from..to] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

/// Whether `b` can be part of an identifier.
fn ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
