use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedPunchTarget {
    pub(super) strategy: PunchStrategy,
    pub(super) local_source: AddressSource,
    pub(super) remote_source: AddressSource,
    pub(super) local: TraversalAddress,
    pub(super) remote: TraversalAddress,
}

fn same_subnet_24(left: &TraversalAddress, right: &TraversalAddress) -> bool {
    let left_parts = left.ip.split('.').collect::<Vec<_>>();
    let right_parts = right.ip.split('.').collect::<Vec<_>>();
    left_parts.len() == 4 && right_parts.len() == 4 && left_parts[..3] == right_parts[..3]
}

pub(super) fn plan_punch_targets(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
) -> Vec<PlannedPunchTarget> {
    let mut planned = Vec::new();

    let mut push_unique = |target: PlannedPunchTarget| {
        if !planned.iter().any(|existing| existing == &target) {
            planned.push(target);
        }
    };

    // Reflexive ↔ Reflexive first: the only path that's reliable across
    // arbitrary network topologies. Try this before any host-candidate path
    // so we don't latch onto a misleading asymmetric route (e.g. an offer's
    // private host candidate that we can reach one-way via a routed VPN).
    if let (Some(local), Some(remote)) = (local_reflexive_address, remote_reflexive_address) {
        push_unique(PlannedPunchTarget {
            strategy: PunchStrategy::Reflexive,
            local_source: AddressSource::Reflexive,
            remote_source: AddressSource::Reflexive,
            local: local.clone(),
            remote: remote.clone(),
        });
    }

    // Same-LAN paths (matching /24 between local and remote host candidates).
    // Only fires when both sides exposed local candidates AND they share a
    // /24 prefix.
    for local in local_addresses {
        for remote in remote_addresses {
            if same_subnet_24(local, remote) {
                push_unique(PlannedPunchTarget {
                    strategy: PunchStrategy::Lan,
                    local_source: AddressSource::Local,
                    remote_source: AddressSource::Local,
                    local: local.clone(),
                    remote: remote.clone(),
                });
            }
        }
    }

    // Mixed paths cover hairpin and one-side-public scenarios.
    if let Some(remote) = remote_reflexive_address {
        for local in local_addresses {
            push_unique(PlannedPunchTarget {
                strategy: PunchStrategy::Mixed,
                local_source: AddressSource::Local,
                remote_source: AddressSource::Reflexive,
                local: local.clone(),
                remote: remote.clone(),
            });
        }
    }

    if let Some(local) = local_reflexive_address {
        for remote in remote_addresses {
            push_unique(PlannedPunchTarget {
                strategy: PunchStrategy::Mixed,
                local_source: AddressSource::Reflexive,
                remote_source: AddressSource::Local,
                local: local.clone(),
                remote: remote.clone(),
            });
        }
    }

    planned
}

pub(super) fn planned_remote_endpoints(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
) -> Result<Vec<SocketAddr>, BootstrapError> {
    let mut remotes = Vec::new();
    for target in plan_punch_targets(
        local_addresses,
        local_reflexive_address,
        remote_addresses,
        remote_reflexive_address,
    ) {
        let remote = SocketAddr::new(
            target
                .remote
                .ip
                .parse()
                .map_err(|_| BootstrapError::Protocol("invalid-remote-ip".to_string()))?,
            target.remote.port,
        );
        if !remotes.contains(&remote) {
            remotes.push(remote);
        }
    }
    Ok(remotes)
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
        let Ok(packet) = parse_punch_packet(&buf[..len]) else {
            continue;
        };
        if packet.session_hash != expected_hash {
            continue;
        }
        if packet.kind == PunchPacketKind::Probe {
            let ack = build_punch_packet(PunchPacketKind::Ack, packet.sequence, session_id);
            let _ = udp.send_to(&ack, remote).await;
        }
        break Ok(remote);
    };
    send_handle.abort();
    result
}

pub(super) fn nonce() -> String {
    format!("{}-{:016x}", now_ms(), rand::random::<u64>())
}

pub(super) fn now_ms() -> u64 {
    struct ClockAnchor {
        started_at: Instant,
        started_unix_ms: u64,
    }

    static ANCHOR: OnceLock<ClockAnchor> = OnceLock::new();

    let anchor = ANCHOR.get_or_init(|| ClockAnchor {
        started_at: Instant::now(),
        started_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0),
    });

    anchor
        .started_unix_ms
        .saturating_add(anchor.started_at.elapsed().as_millis() as u64)
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
