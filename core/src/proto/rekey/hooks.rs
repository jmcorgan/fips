//! What the root crate's session tests read from a machine, and the reader
//! of source code both crates' tests use to keep deleted session rules out.
//!
//! The tests of the session shell read the counters, keys and jitter the
//! machine keeps, and quiet its triggers. The core's and the root crate's
//! tests each scan their crate's code for the names of the deployed session
//! rekey rules through [`code_idents`], so the two read code the same way.
//! None of these runs a row or is reachable from `step`, and none exists
//! outside test builds.

use alloc::string::String;
use alloc::vec::Vec;

use super::machine::Rekey;
use super::profile::Profile;
use crate::time::Clock;

/// Inspection the root crate's session tests use.
impl<P: Profile, C: Clock> Rekey<P, C> {
    /// The keys of the epoch in `slot`.
    #[doc(hidden)]
    pub fn keys(&self, slot: super::Slot) -> Option<&P::Session> {
        self.epoch(slot).map(|ep| ep.session.as_ref())
    }

    /// Frames sealed under the current epoch so far; zero while opening.
    #[doc(hidden)]
    pub fn sent(&self) -> u64 {
        use super::profile::SessionKeys;
        self.cur.as_ref().map_or(0, |cur| cur.session.sent())
    }

    /// The rekey jitter drawn at the last install or cutover, in whole
    /// seconds.
    #[doc(hidden)]
    pub fn jitter_secs(&self) -> i32 {
        self.mem.jitter
    }

    /// Stop the time and message triggers from starting another rekey, as
    /// the largest thresholds a session can be configured with do. Only the
    /// trigger reads them, so nothing in flight changes; a repair still
    /// starts when one falls due.
    #[doc(hidden)]
    pub fn quiet(&mut self) {
        self.params.cfg.after = crate::time::Duration::from_secs(super::MAX_AFTER);
        self.params.cfg.messages = self.params.cfg.soft;
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
