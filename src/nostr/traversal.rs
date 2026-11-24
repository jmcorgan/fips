use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tracing::debug;

use super::machine::punch::attempt::{Attempt, PunchOut};
pub(super) use super::machine::punch::plan::{PunchTargetTally, planned_remote_endpoints};
#[cfg(test)]
pub(super) use super::machine::punch::plan::{SourceRank, rank_punch_source};
pub(super) use super::machine::punch::refusal::RefusalWarnGate;
#[cfg(test)]
pub(super) use super::machine::punch::{build_punch_packet, session_hash};
use super::types::{BootstrapError, PunchHint};
use crate::time::HostInstant;

/// Bind a traversal socket on `addr`, non-blocking as STUN and
/// `run_punch_attempt` need it.
///
/// On Windows an ICMP port-unreachable answering one of its datagrams is not
/// reported as a receive error, as on the UDP transport's sockets, so a closed
/// punch target cannot fail the receives the peer's probe arrives on.
pub(super) fn bind_traversal(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    #[cfg(windows)]
    crate::transport::udp::io::ignore_port_unreachable(&socket);
    Ok(socket)
}

/// Probe `targets` from `socket` per `punch`, and return the address whose
/// probe or ack arrives first from a planned target, or a remapped-port
/// candidate once its settle window passes. Ends with `PunchTimeout` when
/// `timeout` passes with nothing to adopt; a failed receive does not end it.
///
/// The attempt is the machine's (`machine/punch/attempt.rs`); this drives it
/// on `socket` and the host's clocks, sending what it asks and handing it
/// what arrives.
pub(super) async fn run_punch_attempt(
    socket: &std::net::UdpSocket,
    session_id: &str,
    targets: &[SocketAddr],
    punch: PunchHint,
    timeout: Duration,
) -> Result<SocketAddr, BootstrapError> {
    let mut attempt: Attempt<HostInstant> = Attempt::new(
        session_id,
        targets.to_vec(),
        &punch,
        timeout,
        mono(),
        now_ms(),
    )?;
    let udp = UdpSocket::from_std(socket.try_clone()?)?;
    let mut buf = [0u8; 2048];
    let mut out = attempt.timeout(mono());
    let result = loop {
        let mut ended = None;
        for step in out.drain(..) {
            match step {
                // A failed send is ignored: the next round sends again.
                PunchOut::Send { dst, bytes } => {
                    let _ = udp.send_to(&bytes, dst).await;
                }
                PunchOut::Adopt(remote) => ended = Some(Ok(remote)),
                PunchOut::TimedOut => {
                    ended = Some(Err(BootstrapError::PunchTimeout(session_id.to_string())));
                }
            }
        }
        if let Some(result) = ended {
            break result;
        }
        let Some(wake) = attempt.deadline() else {
            break Err(BootstrapError::PunchTimeout(session_id.to_string()));
        };
        let wake = tokio::time::Instant::from_std(wake.into());
        out = match tokio::time::timeout_at(wake, udp.recv_from(&mut buf)).await {
            Ok(Ok((len, remote))) => attempt.datagram(remote, &buf[..len], mono()),
            Ok(Err(err)) => {
                attempt.recv_error(format!("{err:?}"));
                Vec::new()
            }
            Err(_) => attempt.timeout(mono()),
        };
    };
    let tally = attempt.tally();
    if tally.unplanned > 0 || tally.superseded > 0 {
        debug!(
            session = %super::runtime::short_id(session_id),
            unplanned = tally.unplanned,
            superseded = tally.superseded,
            "traversal: punch packets refused on their source address"
        );
    }
    if tally.recv_errors > 0 {
        debug!(
            session = %super::runtime::short_id(session_id),
            recv_errors = tally.recv_errors,
            // As the I/O error's `Option` printed it: `Some(<its Debug>)`.
            last_error = %tally
                .last_error
                .as_ref()
                .map_or_else(|| "None".to_string(), |e| format!("Some({e})")),
            "traversal: receive errors on the punch socket"
        );
    }
    result
}

/// The monotonic reading the attempt's deadlines are on: tokio's clock, as
/// the pump reads it.
fn mono() -> HostInstant {
    HostInstant::from(tokio::time::Instant::now().into_std())
}

pub(super) fn nonce() -> String {
    format!("{}-{:016x}", now_ms(), rand::random::<u64>())
}

/// Current Unix time in milliseconds, read from the wall clock on every call.
///
/// This deliberately does not cache a start-of-process anchor and advance it
/// with a monotonic `Instant`. A monotonic clock does not advance while the host
/// is suspended, so an anchored value trails real time by the suspend duration
/// for the remaining life of the process. Every expiry computed from it is then
/// published already in the past, the relay drops the event as expired, and
/// traversal signalling fails until the daemon is restarted.
///
/// About half the consumers publish or serialize the value as an absolute
/// timestamp: the NIP-40 expiration tags on adverts and traversal signals, and
/// the `issuedAt`/`expiresAt` fields of offers and answers. The rest compare it
/// against timestamps on the same basis, including the peer-authored, signed
/// `created_at` of a received advert, so they need it to track real time too.
///
/// The interval-shaped consumers survive a step in the wall clock. A forward
/// step, which is what a resume produces, saturates the punch start delay to
/// zero so punching begins immediately; the attempt's own bounds are monotonic
/// `Instant` deadlines, so its length is unaffected. A backward step lengthens
/// that delay instead and can cost a single punch attempt, which retries.
/// Expiry-driven eviction from the replay window cannot admit a replay, because
/// the freshness window a replayed offer would also have to satisfy
/// (`signal_ttl_secs` plus `FRESHNESS_SKEW_TOLERANCE_MS` on each side, 240s
/// under the shipped defaults) is strictly narrower than the replay window
/// itself (`replay_window_secs`, 300s). `Config::validate` enforces
/// `signal_ttl_secs + 2 * FRESHNESS_SKEW_TOLERANCE_MS < replay_window_secs`, so
/// that margin can no longer be configured away.
///
/// Capacity never removes a live entry. When `note_session_seen` finds
/// `seen_sessions_max_entries` unexpired ids, it refuses the new offer and
/// records nothing, so a full cache costs new traversals until an entry
/// expires but never makes a recorded session replayable. The default is sized
/// so that refusal is not reached through the signal gate: the gate admits at
/// most its two sustained rates plus its two bursts (10/s and 40 signals at
/// the shipped constants, 3040 over a 300s replay window), below the default
/// of 4096.
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
