//! The session and link nodes this release ships.
//!
//! [`ShipFmp`] is the machine on `FmpIk` at the link defaults, behind the
//! root crate's link shell as it stands:
//! every msg1, msg2 and frame of a link goes through `step`, the machine
//! starts and resends its own rekeys, the shell executes the outputs as
//! `run_link_step` in `src/node/handlers/rekey.rs` does, polls the machine
//! on its 1 s tick as `poll_link_rekeys` does, and reaps the link 30 s
//! after the later of the last frame authenticated under any epoch the
//! machine holds and the last cutover, as its link-dead check on the
//! link's MMP receiver and the machine's last frame does.
//!
//! [`ShipFsp`] is the machine on `FspXk` at the session defaults, behind
//! the root crate's session shell as it stands: every setup, ack, msg3 and
//! frame of a session, from its first handshake on, goes through `step`,
//! the machine starts its own rekeys, and the shell executes the outputs as
//! `run_session_outputs` in `src/node/handlers/rekey.rs` does. The shell polls the machine on its
//! 1 s tick, as `poll_session_rekeys` does, and not at the machine's next
//! wake, except that a setup is stepped only after a poll whenever a
//! deadline or start instant of the machine has come, as `poll_overdue`
//! does (the new node's `recv` makes that poll).
//!
//! The shell opens the machine for a first handshake as the root crate's
//! session handlers do: `opening_outbound` when the node wants the
//! session, `opening_inbound` for the first setup, `Open` on a session the
//! peer's setups opened.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::new::{NewFmp, NewFsp};
use super::{End, Got, Out, Pkt};

/// A shipped session node: the machine polled on the shell's tick.
pub(crate) struct ShipFsp {
    n: NewFsp,
}

impl ShipFsp {
    /// A shipped node around `n`, a new session node built established or
    /// with no session yet.
    pub(crate) fn new(n: NewFsp) -> Self {
        Self { n }
    }
}

impl End for ShipFsp {
    fn tick(&mut self, now: u64, out: &mut Vec<Out>) {
        self.n.tick(now, out);
    }

    fn recv(&mut self, now: u64, pkt: &Pkt, out: &mut Vec<Out>) -> Got {
        self.n.recv(now, pkt, out)
    }

    fn data(&mut self, now: u64, seq: u64, out: &mut Vec<Out>) -> bool {
        self.n.data(now, seq, out)
    }

    /// The shell polls the machine on its tick, and before a setup when a
    /// deadline or start instant has come, never on a timer of its own.
    fn wake(&self) -> Option<u64> {
        None
    }

    fn stranger(&mut self, now: u64, n: u8, out: &mut Vec<Out>) {
        self.n.stranger(now, n, out);
    }

    fn open(&mut self, now: u64, out: &mut Vec<Out>) {
        self.n.open(now, out);
    }

    fn alive(&self) -> bool {
        self.n.alive()
    }

    fn quiet(&self) -> bool {
        self.n.quiet()
    }

    fn take_notes(&mut self) -> Vec<String> {
        self.n.take_notes()
    }

    fn name(&self) -> String {
        format!("shipped {}", self.n.name())
    }
}

/// A shipped link node: the machine at the link defaults, polled on the
/// shell's tick.
pub(crate) struct ShipFmp {
    n: NewFmp,
}

impl ShipFmp {
    /// A shipped node around `n`, a new link node built established at the
    /// link defaults.
    pub(crate) fn new(mut n: NewFmp) -> Self {
        n.shipped = true;
        Self { n }
    }
}

impl End for ShipFmp {
    fn tick(&mut self, now: u64, out: &mut Vec<Out>) {
        self.n.tick(now, out);
    }

    fn recv(&mut self, now: u64, pkt: &Pkt, out: &mut Vec<Out>) -> Got {
        self.n.recv(now, pkt, out)
    }

    fn data(&mut self, now: u64, seq: u64, out: &mut Vec<Out>) -> bool {
        self.n.data(now, seq, out)
    }

    /// The shell polls the machine on its tick, never on a timer of its own.
    fn wake(&self) -> Option<u64> {
        None
    }

    fn alive(&self) -> bool {
        self.n.alive()
    }

    fn quiet(&self) -> bool {
        self.n.quiet()
    }

    fn take_notes(&mut self) -> Vec<String> {
        self.n.take_notes()
    }

    fn name(&self) -> String {
        format!("shipped {}", self.n.name())
    }

    fn check(&self) -> Result<(), String> {
        self.n.check()
    }

    fn finish(&mut self) -> Result<(), String> {
        self.n.finish()
    }
}
