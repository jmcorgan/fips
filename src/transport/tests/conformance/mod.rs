//! Lifecycle rules every connection-oriented transport keeps.
//!
//! Each rule is a generic function here, run against each transport kind by
//! a test in that kind's file, which sets the connection up and hands it to
//! the rule through one of the traits below. The rules:
//!
//! 1. A deliberate close lets the writer finish what was queued: a frame
//!    queued just before the close reaches the peer, and the close still
//!    ends the connection (the close half). Stopping the transport after
//!    such a close still ends a writer left draining, within a bound (the
//!    stop half).
//! 2. An accepted connection that sends nothing is closed within its
//!    deadline, and one that sent its first frame is not closed by it.
//! 3. The receive bound is the shared ceiling, not the local `mtu`: a frame
//!    the peer's sender admits is delivered, on the connection it came on,
//!    and only a frame claiming more than the ceiling closes it.
//!
//! `kinds.rs` lists, for every transport kind, the instance of each rule or
//! the reason it has none. See README.md for how to add a kind.

use std::time::Duration;

use tokio::time::Instant;

use crate::transport::framing::{RECV_CEILING, build_established_frame, build_msg1_frame};
use crate::transport::{PacketRx, ReceivedPacket, TransportAddr, TransportError};

mod kinds;
mod nym;
mod tcp;
mod tor;

/// The `mtu` of a receiving end in the receive-bound rule.
const SMALL_MTU: u16 = 1400;

/// The `mtu` of the sending end in the receive-bound rule, above the
/// receiver's.
const LARGE_MTU: u16 = 1500;

/// An established frame of exactly `len` bytes.
fn frame(len: u16) -> Vec<u8> {
    let frame = build_established_frame(len - 32);
    assert_eq!(frame.len(), len as usize);
    frame
}

/// The next packet `rx` delivers within five seconds, if any. A delivered
/// packet returns at once, so the wait costs time only when nothing comes.
async fn next(rx: &mut PacketRx) -> Option<ReceivedPacket> {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .ok()
        .flatten()
}

/// A loopback port free at the time of the call.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ============================================================================
// Rule 1, close half
// ============================================================================

/// One pooled connection of the transport under test, with the far end the
/// test reads.
trait Closing {
    /// Queue `frame` on the connection.
    async fn send(&self, frame: &[u8]) -> Result<usize, TransportError>;
    /// Close the connection deliberately, as the node does.
    async fn close(&self);
    /// The next frame the far end receives within two seconds.
    async fn far_next(&mut self) -> Option<Vec<u8>>;
    /// Whether the far end sees the connection end within five seconds.
    async fn far_ended(&mut self) -> bool;
    /// Stop what the instance started.
    async fn finish(self);
}

/// A frame queued immediately before a deliberate close must still be
/// written, and the close must still end the connection.
///
/// Sending only queues the frame for the connection's writer. A close that
/// stops the writer before it has run discards the frame, which is how a
/// Disconnect sent just before a close, or a handshake message sent just
/// before the losing side of a crossed connection is closed, never reaches
/// the peer. The last check is that the close still closes, so a writer that
/// never exits cannot pass.
async fn a_frame_queued_just_before_a_close_reaches_the_peer(mut c: impl Closing) {
    let frame = build_msg1_frame();

    // Pool the connection and let its writer go idle.
    c.send(&frame)
        .await
        .expect("precondition: the first frame is accepted");
    assert_eq!(
        c.far_next().await,
        Some(frame.clone()),
        "precondition: the first frame reaches the peer"
    );

    // Queue, then close with nothing in between.
    assert_eq!(
        c.send(&frame).await.ok(),
        Some(frame.len()),
        "precondition: the second frame is queued"
    );
    c.close().await;

    assert_eq!(
        c.far_next().await,
        Some(frame),
        "defect: a frame queued just before a close never reached the peer"
    );
    assert!(
        c.far_ended().await,
        "defect: the close did not end the connection once the queue was written"
    );
    c.finish().await;
}

// ============================================================================
// Rule 1, stop half
// ============================================================================

/// A started transport that can have a writer that never finishes seeded in
/// its pool.
trait Stopping {
    /// Pool a connection to `remote` whose writer never finishes. The
    /// returned receiver sees its sender dropped only once the writer task
    /// has ended.
    async fn stuck_writer(&self, remote: &TransportAddr) -> tokio::sync::oneshot::Receiver<()>;
    /// Close the connection to `remote` deliberately.
    async fn close(&self, remote: &TransportAddr);
    /// Stop the transport.
    async fn stop(&mut self) -> Result<(), TransportError>;
}

/// Stopping the transport must stop a writer that is still draining after a
/// deliberate close, rather than leave it to its drain timer.
///
/// The writer holds a oneshot sender and never finishes, so the sender is
/// dropped only once the task has been aborted. A stop that left it draining
/// returns with the sender still held; one that waited on it does not return
/// within the bound.
async fn stopping_the_transport_ends_a_writer_still_draining_after_a_close(
    mut t: impl Stopping,
    remote: TransportAddr,
) {
    let mut guard = t.stuck_writer(&remote).await;
    t.close(&remote).await;
    tokio::time::timeout(Duration::from_secs(2), t.stop())
        .await
        .expect("defect: stop waited on a draining writer")
        .expect("precondition: the transport stops");

    assert!(
        matches!(
            guard.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ),
        "defect: a writer still draining after a close outlived the transport's stop"
    );
}

// ============================================================================
// Rule 2
// ============================================================================

/// A listening transport under test, with the deadline it gives an accepted
/// connection to send its first frame.
trait Accepting {
    /// The far end of one accepted connection.
    type Far;
    /// The deadline the transport was configured with.
    fn deadline(&self) -> Duration;
    /// How late after the deadline the close may come: the lateness of a
    /// real-time timer, or nothing when time is driven by the test.
    fn slack(&self) -> Duration;
    /// How long after the connect begins the test looks for the connection
    /// still held: inside the deadline, with room for a loaded host's
    /// scheduling when time is real.
    fn early(&self) -> Duration;
    /// Open a connection from a far end that sends nothing, and return it
    /// once the transport has accepted it.
    async fn open(&mut self) -> Self::Far;
    /// Send the far end's first frame, and return once it is delivered.
    async fn first_frame(&mut self, far: &mut Self::Far);
    /// Whether the transport still holds the far end's connection.
    async fn held(&self, far: &Self::Far) -> bool;
    /// Let `d` pass.
    async fn age(&mut self, d: Duration);
}

/// The step at which a close after the deadline is looked for.
const STEP: Duration = Duration::from_millis(10);

/// An accepted connection that sends nothing must be kept until its deadline
/// and closed by it, so a silent peer cannot hold the slot.
async fn an_accepted_connection_that_sends_nothing_is_closed_within_the_deadline(
    mut a: impl Accepting,
) {
    let deadline = a.deadline();
    // The transport's deadline runs from its accept, which comes after this
    // instant, so a close seen less than a deadline after it came early.
    let start = Instant::now();
    let far = a.open().await;
    let opened = start.elapsed();
    assert!(
        a.held(&far).await,
        "precondition: the connection is accepted"
    );

    if let Some(wait) = a.early().checked_sub(start.elapsed()) {
        a.age(wait).await;
    }
    let kept = a.held(&far).await;
    let looked = start.elapsed();
    assert!(
        kept || looked >= deadline,
        "defect: an accepted connection was closed before its deadline"
    );
    assert!(
        kept,
        "precondition: the look before the deadline came {looked:?} after the connect, \
         past the {deadline:?} deadline"
    );

    // By the time `open` returned, the accept had happened.
    if let Some(wait) = (opened + deadline).checked_sub(start.elapsed()) {
        a.age(wait).await;
    }
    let mut late = Duration::ZERO;
    while late < a.slack() && a.held(&far).await {
        a.age(STEP).await;
        late += STEP;
    }
    assert!(
        !a.held(&far).await,
        "defect: an accepted connection that sent nothing was held past its deadline"
    );
}

/// An accepted connection that has sent its first frame must not be closed
/// by the first-frame deadline, however long it is quiet within the idle
/// deadline.
async fn an_accepted_connection_that_sent_a_frame_is_kept_past_the_deadline(mut a: impl Accepting) {
    let deadline = a.deadline();
    let mut far = a.open().await;
    a.first_frame(&mut far).await;

    // Four deadlines' worth of quiet after the first frame.
    a.age(deadline * 4).await;
    assert!(
        a.held(&far).await,
        "defect: an accepted connection that sent a frame was closed by the first-frame deadline"
    );
}

// ============================================================================
// Rule 3
// ============================================================================

/// One connection between a sender configured with `LARGE_MTU` and a
/// receiver configured with `SMALL_MTU`, set up by the instance.
trait Carrying {
    /// Send a frame of `len` bytes from the sender over the connection.
    async fn send(&mut self, len: u16);
    /// The next packet the receiver delivers within five seconds.
    async fn next(&mut self) -> Option<ReceivedPacket>;
    /// The receive errors the receiver has recorded.
    fn recv_errors(&self) -> u64;
    /// Whether the receiver still holds the connection.
    async fn kept(&self) -> bool;
    /// The connections established at either end since the instance began.
    fn connections(&self) -> u64;
}

/// Send a frame of `len` bytes and report whether it was delivered and how
/// many receive errors the receiver recorded meanwhile.
async fn deliver(c: &mut impl Carrying, len: u16) -> (bool, u64) {
    let errors_before = c.recv_errors();
    c.send(len).await;
    let delivered = c.next().await.is_some_and(|p| p.data.len() == len as usize);
    tokio::time::sleep(Duration::from_millis(50)).await;
    (delivered, c.recv_errors() - errors_before)
}

/// A frame above the receiver's `mtu` but within the sender's must be
/// delivered, between two frames within both, with no receive error, on the
/// one connection the instance set up.
///
/// Nothing tells a sender its peer's configured `mtu`, so a sender admits
/// every frame up to its own. A receiver bounded by its own value loses the
/// first frame between the two and drops the connection.
async fn a_frame_above_the_receivers_mtu_from_a_sender_configured_higher_is_delivered(
    c: &mut impl Carrying,
) {
    assert_eq!(
        deliver(c, SMALL_MTU).await,
        (true, 0),
        "precondition: a {SMALL_MTU}-byte frame within both mtu values is delivered"
    );
    let (delivered, errors) = deliver(c, LARGE_MTU).await;
    assert_eq!(
        (delivered, errors, c.kept().await),
        (true, 0, true),
        "defect: (delivered, receive errors, connection kept): a {LARGE_MTU}-byte frame the \
         {LARGE_MTU}-mtu sender admits must reach the {SMALL_MTU}-mtu receiver without a \
         receive error, on a connection it keeps"
    );
    assert_eq!(
        deliver(c, SMALL_MTU).await,
        (true, 0),
        "defect: the connection must still carry frames after the larger one"
    );
    assert_eq!(
        c.connections(),
        1,
        "defect: every frame must travel on the one connection, without a redial"
    );
}

/// A receiving end with a raw far end the test writes bytes into.
trait Raw {
    /// Write `bytes` into the connection from the far end.
    async fn write(&mut self, bytes: &[u8]);
    /// The next packet the receiver delivers within five seconds.
    async fn next(&mut self) -> Option<ReceivedPacket>;
    /// The receive errors the receiver has recorded.
    fn recv_errors(&self) -> u64;
    /// Whether the receiver still holds the connection.
    async fn kept(&self) -> bool;
}

/// A frame of the receive ceiling reaches a receiver configured far below
/// it, and a length prefix claiming one payload byte more closes the
/// connection with one receive error.
///
/// The largest frame any sender can admit is `RECV_CEILING` bytes, because
/// `mtu` is a `u16` and `check_mtu` admits no frame longer than the sender's
/// `mtu`. A frame claiming more is beyond every peer's `mtu`, so the
/// receiver refuses it before allocating.
async fn a_frame_of_the_receive_ceiling_is_delivered_and_one_claiming_more_closes(mut r: impl Raw) {
    let errors_before = r.recv_errors();
    r.write(&frame(RECV_CEILING)).await;
    assert!(
        r.next()
            .await
            .is_some_and(|p| p.data.len() == RECV_CEILING as usize),
        "defect: a {RECV_CEILING}-byte frame must be delivered to a {SMALL_MTU}-mtu receiver"
    );
    assert_eq!(
        r.recv_errors() - errors_before,
        0,
        "defect: a {RECV_CEILING}-byte frame was counted as a receive error"
    );

    let mut prefix = frame(64)[..4].to_vec();
    prefix[2..4].copy_from_slice(&(RECV_CEILING - 31).to_le_bytes());
    r.write(&prefix).await;
    let mut waited = Duration::ZERO;
    while waited < Duration::from_secs(2) && r.kept().await {
        tokio::time::sleep(STEP).await;
        waited += STEP;
    }
    assert!(
        !r.kept().await,
        "defect: the receiver must close a connection whose frame exceeds every sender's mtu"
    );
    assert_eq!(
        r.recv_errors() - errors_before,
        1,
        "defect: the refused frame must be counted as one receive error"
    );
}
