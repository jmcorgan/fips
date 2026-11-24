use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tracing::debug;

pub(super) use super::machine::punch::plan::{
    PunchTargetTally, SourceRank, planned_remote_endpoints, rank_punch_source,
};
pub(super) use super::machine::punch::refusal::RefusalWarnGate;
pub(super) use super::machine::punch::{
    PunchAction, build_punch_packet, classify_punch_packet, session_hash,
};
use super::types::{BootstrapError, PunchHint, PunchPacketKind};

/// How long the punch loop keeps listening for an exact target match once it
/// has already accepted a planned target's address on a different port.
///
/// A source that matches a planned target's IP but not its port is what a
/// symmetric NAT's fresh mapping toward us looks like, and it is worth
/// adopting; a source that matches a target exactly is worth more, so the
/// first remapped source does not end the attempt outright. Raising this
/// delays adoption on the remapped path only, never past the attempt timeout;
/// lowering it toward zero makes the first remapped source win.
const PUNCH_SETTLE_MS: u64 = 250;

/// Hold a source that matched a planned target's IP on a different port.
///
/// That is what a symmetric NAT's fresh mapping toward us looks like, and it
/// is the main class of pairing punching exists to rescue, so it is adopted
/// rather than dropped. It is held for `PUNCH_SETTLE_MS` first so an exact
/// match arriving inside that window supersedes it; the honest path's latency
/// is unchanged, because an exact match breaks the loop immediately.
fn hold_remapped(
    remote: SocketAddr,
    candidate: &mut Option<SocketAddr>,
    settle_at: &mut Option<tokio::time::Instant>,
    superseded: &mut usize,
) {
    if candidate.replace(remote).is_some() {
        *superseded += 1;
    }
    settle_at.get_or_insert_with(|| {
        tokio::time::Instant::now() + Duration::from_millis(PUNCH_SETTLE_MS)
    });
}

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
pub(super) async fn run_punch_attempt(
    socket: &std::net::UdpSocket,
    session_id: &str,
    targets: &[SocketAddr],
    punch: PunchHint,
    timeout: Duration,
) -> Result<SocketAddr, BootstrapError> {
    if targets.is_empty() {
        return Err(BootstrapError::Protocol("no-punch-targets".to_string()));
    }

    let udp = Arc::new(UdpSocket::from_std(socket.try_clone()?)?);
    let started_at = tokio::time::Instant::now();
    let finish_at = started_at + timeout;
    let delay = Duration::from_millis(punch.start_at_ms.saturating_sub(now_ms()));
    let send_socket = Arc::clone(&udp);
    let send_targets = targets.to_vec();
    let send_session = session_id.to_string();
    let send_handle = tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let end = Instant::now() + Duration::from_millis(punch.duration_ms.max(1));
        let mut sequence = 0u32;
        while Instant::now() < end {
            let packet = build_punch_packet(PunchPacketKind::Probe, sequence, &send_session);
            for target in &send_targets {
                let _ = send_socket.send_to(&packet, target).await;
            }
            sequence = sequence.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(punch.interval_ms.max(20))).await;
        }
    });

    let expected_hash = session_hash(session_id);
    let mut buf = [0u8; 2048];
    // Counted rather than logged per packet: an attacker sets how many of
    // these arrive, so a record each would trade the adoption this closes for
    // log volume. One record at the end of the attempt instead.
    let mut unplanned = 0usize;
    let mut superseded = 0usize;
    // Counted for the same reason: the peer or a third party sets how many
    // receives fail.
    let mut recv_errors = 0usize;
    let mut last_error: Option<std::io::Error> = None;
    let mut candidate: Option<SocketAddr> = None;
    let mut settle_at: Option<tokio::time::Instant> = None;
    let result = loop {
        let deadline = settle_at.map_or(finish_at, |settle| settle.min(finish_at));
        let recv = tokio::time::timeout_at(deadline, udp.recv_from(&mut buf)).await;
        let (len, remote) = match recv {
            Ok(Ok(received)) => received,
            // A failed receive reports something about a datagram sent
            // earlier, such as an ICMP error answering a probe to a closed
            // port or an oversized datagram, not that the socket is unusable.
            // The peer's probe can still arrive after it.
            Ok(Err(err)) => {
                recv_errors += 1;
                last_error = Some(err);
                continue;
            }
            Err(_) => {
                break match candidate {
                    Some(remote) => Ok(remote),
                    None => Err(BootstrapError::PunchTimeout(session_id.to_string())),
                };
            }
        };
        // Ranked ahead of the ack, not only ahead of the adoption: acking a
        // source we never planned to probe is a reflection this node controls,
        // and there is no reason to emit it. The packet's own discriminator is
        // a digest of a value both peers already know and travels in the clear
        // in every probe, so it proves only that the sender saw one.
        let rank = rank_punch_source(remote, targets);
        if rank == SourceRank::Unplanned {
            unplanned += 1;
            continue;
        }
        match classify_punch_packet(&buf[..len], expected_hash) {
            PunchAction::Ignore => continue,
            PunchAction::Ack { sequence } => {
                let ack = build_punch_packet(PunchPacketKind::Ack, sequence, session_id);
                let _ = udp.send_to(&ack, remote).await;
                if rank == SourceRank::Planned {
                    break Ok(remote);
                }
                hold_remapped(remote, &mut candidate, &mut settle_at, &mut superseded);
            }
            PunchAction::Matched => {
                if rank == SourceRank::Planned {
                    break Ok(remote);
                }
                hold_remapped(remote, &mut candidate, &mut settle_at, &mut superseded);
            }
        }
    };
    send_handle.abort();
    if unplanned > 0 || superseded > 0 {
        debug!(
            session = %super::runtime::short_id(session_id),
            unplanned,
            superseded,
            "traversal: punch packets refused on their source address"
        );
    }
    if recv_errors > 0 {
        debug!(
            session = %super::runtime::short_id(session_id),
            recv_errors,
            last_error = ?last_error,
            "traversal: receive errors on the punch socket"
        );
    }
    result
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
