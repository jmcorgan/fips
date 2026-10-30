//! Tests that a punch attempt is not ended early by a receive error, such as
//! an ICMP port-unreachable reported on the traversal socket. FRC-1601
//! Section 6.2 forbids ending the attempt for want of an address to adopt
//! sooner than 10 s after it starts, and the socket can still receive.
//!
//! Windows reports a port-unreachable as `WSAECONNRESET` on the socket's next
//! `recv_from` unless `SIO_UDP_CONNRESET` is turned off, which the traversal
//! socket does not do. Linux reports it only on a socket with `IP_RECVERR`
//! set, so the Linux tests set that option to produce the same receive error.
//!
//! - On every platform, an attempt whose only target is a closed port runs
//!   to its timeout on the socket as the runtime makes it.
//! - On Linux, the same attempt runs to its timeout when the
//!   port-unreachable is reported, and a peer's probe arriving after the
//!   reports is still adopted.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::super::PunchHint;
use super::super::traversal::run_punch_attempt;
use super::super::types::BootstrapError;

/// How long each attempt here is given before it may end.
const ATTEMPT: Duration = Duration::from_secs(2);

/// How early an attempt may end and still count as having run to its
/// timeout, for timer and scheduling slack.
const SLACK: Duration = Duration::from_millis(150);

/// A non-blocking UDP socket on 127.0.0.1, as the runtime makes the
/// traversal socket.
fn traversal_socket() -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback socket");
    socket
        .set_nonblocking(true)
        .expect("the punch socket must be non-blocking");
    socket
}

/// A loopback address with no socket bound to it: bind one, note its
/// address, and close it.
fn closed_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback socket");
    socket.local_addr().expect("local address")
}

/// A punch hint that starts at once and probes every 20 ms for the whole
/// attempt.
fn hint() -> PunchHint {
    PunchHint {
        start_at_ms: 0,
        interval_ms: 20,
        duration_ms: ATTEMPT.as_millis() as u64,
    }
}

/// A traversal socket with `IP_RECVERR` set, so that an ICMP
/// port-unreachable answering one of its datagrams fails its next
/// `recv_from` with `ECONNREFUSED`, as `WSAECONNRESET` does on Windows.
#[cfg(target_os = "linux")]
fn reporting_socket() -> std::net::UdpSocket {
    use std::os::fd::AsRawFd;

    let socket = traversal_socket();
    let on: libc::c_int = 1;
    // SAFETY: the descriptor is open for the call, and the option value is a
    // live c_int of the stated size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "setsockopt(IP_RECVERR): {}",
        std::io::Error::last_os_error()
    );
    socket
}

/// Run an attempt on `socket` whose only target is a closed port, and return
/// its result and how long it ran.
async fn attempt_against_a_closed_port(
    socket: &std::net::UdpSocket,
) -> (Result<SocketAddr, BootstrapError>, Duration) {
    let started = Instant::now();
    let result = run_punch_attempt(
        socket,
        "session-closed-port",
        &[closed_port()],
        hint(),
        ATTEMPT,
    )
    .await;
    (result, started.elapsed())
}

/// The deployed socket. On Linux this is the healthy path: no receive error
/// is reported, and the attempt runs to its timeout. On Windows a
/// port-unreachable from the closed target can fail a receive, which must not
/// end the attempt.
#[tokio::test]
async fn a_punch_attempt_runs_to_its_timeout_when_its_target_port_is_closed() {
    let socket = traversal_socket();
    let (result, elapsed) = attempt_against_a_closed_port(&socket).await;
    assert!(
        matches!(result, Err(BootstrapError::PunchTimeout(_))),
        "nothing answers, so the attempt should time out, got {result:?}"
    );
    assert!(
        elapsed + SLACK >= ATTEMPT,
        "the attempt ended after {elapsed:?}, before its {ATTEMPT:?} timeout"
    );
}

/// The same attempt with the receive error made visible on Linux: the
/// port-unreachable answering the first probe fails the next `recv_from`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_reported_port_unreachable_does_not_end_the_punch_attempt_early() {
    let socket = reporting_socket();
    let (result, elapsed) = attempt_against_a_closed_port(&socket).await;
    assert!(
        elapsed + SLACK >= ATTEMPT,
        "a port-unreachable ended the attempt after {elapsed:?}, before its {ATTEMPT:?} \
         timeout, with {result:?}"
    );
    assert!(
        matches!(result, Err(BootstrapError::PunchTimeout(_))),
        "nothing answers, so the attempt should time out, got {result:?}"
    );
}

/// The attempt does not merely last after a receive error, it still listens:
/// with one closed target answering every probe with a reported
/// port-unreachable, a probe from the other, live target arriving 300 ms in
/// is adopted. The peer and the closed port are distinct ports on 127.0.0.1,
/// so the peer's source ranks as a planned target.
///
/// The closed port is the last target of each round on purpose. Linux keeps
/// one pending error per socket, and a send consumes it as a receive does,
/// so a probe sent after the one to the closed port would take the error
/// before the receive loop could see it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_peer_probe_after_a_reported_port_unreachable_is_still_adopted() {
    const SESSION: &str = "session-peer-after-error";

    let socket = reporting_socket();
    let local = socket.local_addr().expect("traversal socket address");
    let peer = traversal_socket();
    let peer_addr = peer.local_addr().expect("peer address");

    let sender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        super::send_probe(&peer, local, SESSION);
        peer
    });

    let started = Instant::now();
    let result = run_punch_attempt(
        &socket,
        SESSION,
        &[peer_addr, closed_port()],
        hint(),
        ATTEMPT,
    )
    .await;
    let elapsed = started.elapsed();
    sender.await.expect("the peer's probe task");

    assert!(
        matches!(result, Ok(adopted) if adopted == peer_addr),
        "the peer's probe should be adopted after the port-unreachable reports, got {result:?} \
         after {elapsed:?}"
    );
}
