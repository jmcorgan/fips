use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use super::types::{
    BootstrapError, PUNCH_ACK_MAGIC, PUNCH_MAGIC, PunchHint, PunchPacket, PunchPacketKind,
    TraversalAddress,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressSource {
    Local,
    Reflexive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PunchStrategy {
    Lan,
    Reflexive,
    Mixed,
}

/// Upper bound on the punch targets one session may plan.
///
/// The candidate generator (`local_addresses_from_port`) tops out near eight
/// entries on a dual-stack host with four interfaces and is typically three or
/// four, and an honest peer contributes one reflexive address plus the few
/// candidates that share a /24 with us. Eight therefore covers every pairing a
/// real session needs while bounding one accepted signal to 8 x 50 rounds =
/// 400 packets, about 21 KB on the wire at 52 bytes each for IPv4.
const MAX_PUNCH_TARGETS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedPunchTarget {
    pub(super) strategy: PunchStrategy,
    pub(super) local_source: AddressSource,
    pub(super) remote_source: AddressSource,
    pub(super) local: TraversalAddress,
    pub(super) remote: TraversalAddress,
    /// The remote address already parsed and canonicalized by `admit_remote`,
    /// so the endpoint list never has to re-parse peer-supplied text.
    pub(super) remote_ip: IpAddr,
}

fn same_subnet_24(left: &TraversalAddress, right: &TraversalAddress) -> bool {
    let left_parts = left.ip.split('.').collect::<Vec<_>>();
    let right_parts = right.ip.split('.').collect::<Vec<_>>();
    left_parts.len() == 4 && right_parts.len() == 4 && left_parts[..3] == right_parts[..3]
}

/// Addresses that are never a plausible destination for a punch packet, for
/// an advert endpoint or for anything else we would send to directly.
///
/// Private and unique-local ranges are deliberately absent: they are usable
/// on a shared LAN, and `is_private_ip` covers them separately so each caller
/// can decide whether a private destination makes sense for it. The
/// documentation ranges are absent for the same reason, in `is_doc_ip`.
pub(super) fn is_never_punchable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Addresses that only reach a host sharing our local network.
pub(super) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

/// The IPv4 documentation ranges: 192.0.2.0/24, 198.51.100.0/24 and
/// 203.0.113.0/24.
///
/// Held apart from `is_never_punchable_ip` because these ranges stand in for
/// public addresses throughout this crate's traversal tests and in lab
/// topologies that route them internally. An advert must still not name one,
/// so the advert filter keeps this term.
pub(super) fn is_doc_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_documentation(),
        IpAddr::V6(_) => false,
    }
}

/// Why one peer-supplied candidate was refused as a punch destination.
///
/// The four variants are the operationally distinct stories: malformed text,
/// a port that can never be punched, an address that is never routable, and
/// an otherwise valid private address on a network we are not attached to.
/// They stay distinct because the response to each differs; the target cap is
/// counted separately, since it is not a verdict on any one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RejectClass {
    /// The address text did not parse as an IP address.
    Unparsable,
    /// The candidate named port 0.
    ZeroPort,
    /// The address is in a range we never punch (loopback, link-local,
    /// unspecified, multicast, broadcast or CGNAT).
    NeverRoutable,
    /// A private address that shares no /24 with any of our own addresses.
    OffSubnet,
}

impl RejectClass {
    /// The stable field value naming this class in a log record.
    pub(super) fn label(&self) -> &'static str {
        match self {
            RejectClass::Unparsable => "unparsable",
            RejectClass::ZeroPort => "zeroport",
            RejectClass::NeverRoutable => "never-routable",
            RejectClass::OffSubnet => "off-subnet",
        }
    }
}

/// The per-class counts of one planning call, for a single aggregated log
/// record.
///
/// Aggregated deliberately: `remote_addresses` is unbounded, so a record per
/// refused candidate would turn a peer's oversized signal into log volume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct PunchTargetTally {
    /// Candidates the peer offered, including its reflexive address.
    pub(super) offered: usize,
    /// Targets planned after vetting and the cap.
    pub(super) admitted: usize,
    /// Candidates whose address text did not parse.
    pub(super) unparsable: usize,
    /// Candidates naming port 0.
    pub(super) zeroport: usize,
    /// Candidates in a never-routable range.
    pub(super) unroutable: usize,
    /// Private candidates sharing no /24 with us.
    pub(super) offsubnet: usize,
    /// Planned targets discarded by the target cap.
    pub(super) capped: usize,
    /// The class label that refused the peer's reflexive address, if it was
    /// refused. Held apart from the candidate counts because losing the
    /// reflexive branch removes every path that works across arbitrary NATs,
    /// which is a materially different story from losing a host candidate.
    pub(super) reflexive: Option<&'static str>,
    /// The first `ip:port` refused as never-routable or zero-port, kept to one
    /// entry so peer-supplied text cannot inflate the record.
    pub(super) sample: Option<String>,
}

impl PunchTargetTally {
    /// Whether this planning call looks like an attack rather than a routine
    /// mismatch.
    ///
    /// No honest implementation offers unparsable text, port 0, a
    /// never-routable address or more candidates than the cap allows, and an
    /// entirely refused offer is the reflector case itself. An off-subnet-only
    /// refusal is the ordinary dual-homed shape and is not suspicious.
    ///
    /// A refused reflexive address always counts: the /24 gate does not apply
    /// to it, so the only ways it can be refused are the attacker-shaped ones.
    pub(super) fn suspicious(&self) -> bool {
        self.unroutable + self.zeroport + self.unparsable + self.capped > 0
            || (self.offered > 0 && self.admitted == 0)
            || self.reflexive.is_some()
    }

    /// Record one refused candidate against its class, keeping the first
    /// sample.
    fn refuse(&mut self, class: RejectClass, candidate: &TraversalAddress) {
        match class {
            RejectClass::Unparsable => self.unparsable += 1,
            RejectClass::ZeroPort => self.zeroport += 1,
            RejectClass::NeverRoutable => self.unroutable += 1,
            RejectClass::OffSubnet => self.offsubnet += 1,
        }
        self.note(class, candidate);
    }

    /// Record the refusal of the peer's reflexive address, which is counted
    /// on its own rather than with the host candidates.
    fn refuse_reflexive(&mut self, class: RejectClass, candidate: &TraversalAddress) {
        self.reflexive = Some(class.label());
        self.note(class, candidate);
    }

    /// Keep the first never-routable or zero-port address seen, and only that
    /// one.
    fn note(&mut self, class: RejectClass, candidate: &TraversalAddress) {
        if self.sample.is_none()
            && matches!(class, RejectClass::NeverRoutable | RejectClass::ZeroPort)
        {
            self.sample = Some(format!("{}:{}", candidate.ip, candidate.port));
        }
    }
}

/// Parse and vet one peer-supplied traversal candidate.
///
/// Returns the parsed address, or the class of the check that refused it.
/// `lan_refs` are our own addresses that a private candidate must share a /24
/// with. `apply_private_gate` is false for the peer's reflexive address: a
/// STUN server inside the private network legitimately reports a private
/// reflexive address, and dropping it would remove the only branch that works
/// across arbitrary NATs.
fn admit_remote(
    candidate: &TraversalAddress,
    lan_refs: &[TraversalAddress],
    apply_private_gate: bool,
) -> Result<IpAddr, RejectClass> {
    // Canonicalize the IPv4-mapped form so `::ffff:10.0.0.1` cannot present
    // itself as a public v6 address and slip past the checks below.
    let ip = match candidate
        .ip
        .parse::<IpAddr>()
        .map_err(|_| RejectClass::Unparsable)?
    {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    if candidate.port == 0 {
        return Err(RejectClass::ZeroPort);
    }
    if is_never_punchable_ip(ip) {
        return Err(RejectClass::NeverRoutable);
    }
    if apply_private_gate
        && is_private_ip(ip)
        && !lan_refs.iter().any(|our| same_subnet_24(our, candidate))
    {
        return Err(RejectClass::OffSubnet);
    }
    Ok(ip)
}

pub(super) fn plan_punch_targets(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
) -> (Vec<PlannedPunchTarget>, PunchTargetTally) {
    let mut planned = Vec::new();
    let mut tally = PunchTargetTally {
        offered: remote_addresses.len() + usize::from(remote_reflexive_address.is_some()),
        ..PunchTargetTally::default()
    };

    // Our own addresses a peer's private candidate has to share a /24 with.
    // The local reflexive address joins the set when it is itself private,
    // which is what keeps a LAN-STUN deployment able to match while the
    // shipped `share_local_candidates=false` leaves the local list empty.
    let mut lan_refs = local_addresses.to_vec();
    if let Some(reflexive) = local_reflexive_address
        && reflexive.ip.parse::<IpAddr>().is_ok_and(is_private_ip)
    {
        lan_refs.push(reflexive.clone());
    }

    // Everything on the remote side is peer-supplied, so it is vetted once
    // here and the branches below only ever see admitted candidates.
    let remote_reflexive =
        remote_reflexive_address.and_then(|remote| match admit_remote(remote, &lan_refs, false) {
            Ok(ip) => Some((remote, ip)),
            Err(class) => {
                tally.refuse_reflexive(class, remote);
                None
            }
        });
    let remote_candidates = remote_addresses
        .iter()
        .filter_map(|remote| match admit_remote(remote, &lan_refs, true) {
            Ok(ip) => Some((remote, ip)),
            Err(class) => {
                tally.refuse(class, remote);
                None
            }
        })
        .collect::<Vec<_>>();

    let mut push_unique = |target: PlannedPunchTarget| {
        if !planned.iter().any(|existing| existing == &target) {
            planned.push(target);
        }
    };

    // Reflexive ↔ Reflexive first: the only path that's reliable across
    // arbitrary network topologies. Try this before any host-candidate path
    // so we don't latch onto a misleading asymmetric route (e.g. an offer's
    // private host candidate that we can reach one-way via a routed VPN).
    if let (Some(local), Some((remote, remote_ip))) = (local_reflexive_address, remote_reflexive) {
        push_unique(PlannedPunchTarget {
            strategy: PunchStrategy::Reflexive,
            local_source: AddressSource::Reflexive,
            remote_source: AddressSource::Reflexive,
            local: local.clone(),
            remote: remote.clone(),
            remote_ip,
        });
    }

    // Same-LAN paths (matching /24 between local and remote host candidates).
    // Only fires when both sides exposed local candidates AND they share a
    // /24 prefix.
    for local in local_addresses {
        for (remote, remote_ip) in &remote_candidates {
            if same_subnet_24(local, remote) {
                push_unique(PlannedPunchTarget {
                    strategy: PunchStrategy::Lan,
                    local_source: AddressSource::Local,
                    remote_source: AddressSource::Local,
                    local: local.clone(),
                    remote: (*remote).clone(),
                    remote_ip: *remote_ip,
                });
            }
        }
    }

    // Mixed paths cover hairpin and one-side-public scenarios.
    if let Some((remote, remote_ip)) = remote_reflexive {
        for local in local_addresses {
            push_unique(PlannedPunchTarget {
                strategy: PunchStrategy::Mixed,
                local_source: AddressSource::Local,
                remote_source: AddressSource::Reflexive,
                local: local.clone(),
                remote: remote.clone(),
                remote_ip,
            });
        }
    }

    if let Some(local) = local_reflexive_address {
        for (remote, remote_ip) in &remote_candidates {
            push_unique(PlannedPunchTarget {
                strategy: PunchStrategy::Mixed,
                local_source: AddressSource::Reflexive,
                remote_source: AddressSource::Local,
                local: local.clone(),
                remote: (*remote).clone(),
                remote_ip: *remote_ip,
            });
        }
    }

    tally.capped = planned.len().saturating_sub(MAX_PUNCH_TARGETS);
    planned.truncate(MAX_PUNCH_TARGETS);
    tally.admitted = planned.len();
    (planned, tally)
}

/// Socket addresses to punch, in plan order and deduplicated.
///
/// Every remote address is vetted and parsed during planning, so a malformed
/// address in a peer's signal now costs that one candidate instead of failing
/// the whole traversal. The `Result` is kept so the call sites are unchanged
/// and a future check can fail the plan again.
pub(super) fn planned_remote_endpoints(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
) -> Result<(Vec<SocketAddr>, PunchTargetTally), BootstrapError> {
    let mut remotes = Vec::new();
    let (planned, tally) = plan_punch_targets(
        local_addresses,
        local_reflexive_address,
        remote_addresses,
        remote_reflexive_address,
    );
    for target in planned {
        let remote = SocketAddr::new(target.remote_ip, target.remote.port);
        if !remotes.contains(&remote) {
            remotes.push(remote);
        }
    }
    Ok((remotes, tally))
}

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
    let result = loop {
        let recv = tokio::time::timeout_at(finish_at, udp.recv_from(&mut buf)).await;
        let Ok(Ok((len, remote))) = recv else {
            break Err(BootstrapError::PunchTimeout(session_id.to_string()));
        };
        match classify_punch_packet(&buf[..len], expected_hash) {
            PunchAction::Ignore => continue,
            PunchAction::Ack { sequence } => {
                let ack = build_punch_packet(PunchPacketKind::Ack, sequence, session_id);
                let _ = udp.send_to(&ack, remote).await;
                break Ok(remote);
            }
            PunchAction::Matched => break Ok(remote),
        }
    };
    send_handle.abort();
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
/// That covers the expiry route only. `mark_session_seen` also evicts on
/// capacity, dropping the entries nearest expiry once the cache exceeds
/// `seen_sessions_max_entries`, and a session id dropped that way stays
/// replayable for the rest of its freshness window whatever the time relation
/// is. Nothing bounds that route: whether it is reachable depends on the
/// admitted-offer rate against the cache size. The shipped defaults leave a
/// wide margin — filling 2048 entries inside 300s needs about 6.8 admitted
/// offers per second, against roughly 1.2/s from a 16-slot pool whose permits
/// are held for the length of an attempt — but raising
/// `max_concurrent_incoming_offers` narrows it. That admission rate is inferred
/// from the attempt timeout, not measured.
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn session_hash(session_id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(session_id.as_bytes());
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

pub(super) fn build_punch_packet(
    kind: PunchPacketKind,
    sequence: u32,
    session_id: &str,
) -> [u8; 24] {
    let magic = match kind {
        PunchPacketKind::Probe => PUNCH_MAGIC,
        PunchPacketKind::Ack => PUNCH_ACK_MAGIC,
    };
    let mut packet = [0u8; 24];
    packet[..4].copy_from_slice(&magic.to_be_bytes());
    packet[4..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..24].copy_from_slice(&session_hash(session_id));
    packet
}

pub(super) fn parse_punch_packet(bytes: &[u8]) -> Result<PunchPacket, BootstrapError> {
    if bytes.len() < 24 {
        return Err(BootstrapError::Protocol(
            "invalid-punch-packet-length".to_string(),
        ));
    }
    let magic = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| BootstrapError::Protocol("invalid-punch-magic".to_string()))?,
    );
    let kind = match magic {
        PUNCH_MAGIC => PunchPacketKind::Probe,
        PUNCH_ACK_MAGIC => PunchPacketKind::Ack,
        _ => {
            return Err(BootstrapError::Protocol("invalid-punch-magic".to_string()));
        }
    };
    let sequence = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| BootstrapError::Protocol("invalid-punch-seq".to_string()))?,
    );
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes[8..24]);
    Ok(PunchPacket {
        kind,
        sequence,
        session_hash: hash,
    })
}

/// Classification of a received UDP datagram on the punch socket. Returned
/// by [`classify_punch_packet`]; the timing loop performs the actual ack
/// send / break described by the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PunchAction {
    /// Not a valid punch packet for this session — keep listening.
    Ignore,
    /// A matching probe: the driver builds and sends an ack for `sequence`,
    /// then treats the peer as reached.
    Ack { sequence: u32 },
    /// A matching non-probe (ack) packet: the peer is reached, no ack to send.
    Matched,
}

/// Pure classification of a received datagram against the expected session
/// hash. No I/O: the caller sends any ack and decides control flow.
pub(super) fn classify_punch_packet(bytes: &[u8], expected_hash: [u8; 16]) -> PunchAction {
    let Ok(packet) = parse_punch_packet(bytes) else {
        return PunchAction::Ignore;
    };
    if packet.session_hash != expected_hash {
        return PunchAction::Ignore;
    }
    if packet.kind == PunchPacketKind::Probe {
        PunchAction::Ack {
            sequence: packet.sequence,
        }
    } else {
        PunchAction::Matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "session-classify-vectors";

    #[test]
    fn classify_ignores_unparseable_bytes() {
        // P1: too short to parse.
        assert_eq!(
            classify_punch_packet(&[0u8; 4], session_hash(SESSION)),
            PunchAction::Ignore
        );
    }

    #[test]
    fn classify_ignores_mismatched_session_hash() {
        // P2: parseable, but hash is for a different session.
        let packet = build_punch_packet(PunchPacketKind::Probe, 7, SESSION);
        let other_hash = session_hash("some-other-session");
        assert_eq!(
            classify_punch_packet(&packet, other_hash),
            PunchAction::Ignore
        );
    }

    #[test]
    fn classify_probe_matching_hash_acks_with_sequence() {
        // P3: matching probe -> Ack carrying the packet's sequence.
        let packet = build_punch_packet(PunchPacketKind::Probe, 42, SESSION);
        assert_eq!(
            classify_punch_packet(&packet, session_hash(SESSION)),
            PunchAction::Ack { sequence: 42 }
        );
    }

    #[test]
    fn classify_ack_matching_hash_is_matched() {
        // P4: matching non-probe (ack) -> Matched.
        let packet = build_punch_packet(PunchPacketKind::Ack, 3, SESSION);
        assert_eq!(
            classify_punch_packet(&packet, session_hash(SESSION)),
            PunchAction::Matched
        );
    }
}
