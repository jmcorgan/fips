//! Punch planning: which of a peer's offered addresses this node will probe,
//! from which of its own, in what order, and the tally of what it refused.
//! Everything on the remote side is peer-supplied, so it is vetted here once
//! and bounded before anything walks it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use fips_core::utils::onlink::OnLinkPrefixes;

use super::super::error::Error;
use super::super::types::TraversalAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSource {
    Local,
    Reflexive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchStrategy {
    Lan,
    Reflexive,
    Mixed,
}

/// Upper bound on the punch targets one session may plan.
///
/// The candidate generator (`local_addresses_from_port`) tops out near eight
/// entries on a dual-stack host with four interfaces and is typically three or
/// four, and an honest peer contributes one reflexive address plus the few
/// candidates that share an interface prefix with us. Eight therefore covers
/// every pairing a real session needs while bounding one accepted signal to
/// 8 x 50 rounds = 400 packets, about 21 KB on the wire at 52 bytes each for
/// IPv4.
const MAX_PUNCH_TARGETS: usize = 8;

/// Upper bound on how many candidates one peer's signal may have vetted.
///
/// Vetting is linear in this number and the `push_unique` scan that follows
/// is quadratic in the plan it feeds, so an unbounded candidate list lets one
/// signal buy an unbounded amount of our planning work regardless of the
/// eight-target cap, which only applies after both loops have run. Thirty-two
/// is four times `MAX_PUNCH_TARGETS` and four times what the candidate
/// generator produces on the widest host we have seen, so an honest peer
/// never reaches it. Raising it costs planning work per admitted signal;
/// lowering it costs an honest many-homed peer the tail of its candidate
/// list, which the tally records either way.
const MAX_OFFERED_CANDIDATES: usize = 32;

/// How much the source address of a punch packet is worth as a peer address.
///
/// The packet's own discriminator is a plain digest of a value both peers
/// already know, so it proves only that the sender has seen a probe. What the
/// source address is checked against is the target list this node planned,
/// which is the difference between adopting a peer we chose to probe and
/// adopting whoever replayed those bytes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceRank {
    /// Not an address we planned to probe, and so not adoptable.
    Unplanned,
    /// A planned target's address on a different port.
    RemappedPort,
    /// Exactly a target we planned to probe.
    Planned,
}

/// Rank one punch packet's source address against the targets we planned.
///
/// `targets` holds at most `MAX_PUNCH_TARGETS` entries, so the scan is
/// bounded by construction.
pub fn rank_punch_source(remote: SocketAddr, targets: &[SocketAddr]) -> SourceRank {
    if targets.contains(&remote) {
        SourceRank::Planned
    } else if targets.iter().any(|target| target.ip() == remote.ip()) {
        SourceRank::RemappedPort
    } else {
        SourceRank::Unplanned
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPunchTarget {
    pub strategy: PunchStrategy,
    pub local_source: AddressSource,
    pub remote_source: AddressSource,
    pub local: TraversalAddress,
    pub remote: TraversalAddress,
    /// The remote address already parsed and canonicalized by `admit_remote`,
    /// so the endpoint list never has to re-parse peer-supplied text.
    pub remote_ip: IpAddr,
}

/// One of our own traversal addresses, parsed and with the IPv4-mapped form
/// taken as IPv4, or `None` when the text does not parse.
fn own_ip(address: &TraversalAddress) -> Option<IpAddr> {
    address
        .ip
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
}

/// Addresses that are never a plausible destination for a punch packet, for
/// an advert endpoint or for anything else we would send to directly.
///
/// Private and unique-local ranges are deliberately absent: they are usable
/// on a shared LAN, and `is_private_ip` covers them separately so each caller
/// can decide whether a private destination makes sense for it. The
/// documentation ranges are absent for the same reason, in `is_doc_ip`.
pub fn is_never_punchable_ip(ip: IpAddr) -> bool {
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
pub fn is_private_ip(ip: IpAddr) -> bool {
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
pub fn is_doc_ip(ip: IpAddr) -> bool {
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
pub enum RejectClass {
    /// The address text did not parse as an IP address.
    Unparsable,
    /// The candidate named port 0.
    ZeroPort,
    /// The address is in a range we never punch (loopback, link-local,
    /// unspecified, multicast, broadcast or CGNAT).
    NeverRoutable,
    /// A private address outside every interface prefix that also holds one
    /// of our own addresses, or any unique-local address, which the IPv4
    /// traversal socket cannot reach.
    OffSubnet,
}

impl RejectClass {
    /// The stable field value naming this class in a log record.
    pub fn label(&self) -> &'static str {
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
pub struct PunchTargetTally {
    /// Candidates the peer offered, including its reflexive address.
    pub offered: usize,
    /// Targets planned after vetting and the cap.
    pub admitted: usize,
    /// Candidates whose address text did not parse.
    pub unparsable: usize,
    /// Candidates naming port 0.
    pub zeroport: usize,
    /// Candidates in a never-routable range.
    pub unroutable: usize,
    /// Private candidates refused as off-subnet: outside every interface
    /// prefix that holds one of our own addresses, or unique-local.
    pub offsubnet: usize,
    /// Planned targets discarded by the target cap.
    pub capped: usize,
    /// Candidates past `MAX_OFFERED_CANDIDATES` that were never vetted.
    pub over_offered: usize,
    /// The class label that refused the peer's reflexive address, if it was
    /// refused. Held apart from the candidate counts because losing the
    /// reflexive branch removes every path that works across arbitrary NATs,
    /// which is a materially different story from losing a host candidate.
    pub reflexive: Option<&'static str>,
    /// The first `ip:port` refused as never-routable or zero-port, kept to one
    /// entry so peer-supplied text cannot inflate the record.
    pub sample: Option<String>,
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
    /// A refused reflexive address counts unless the class is `OffSubnet`.
    /// The private-address gate applies to a peer's reflexive address too, so
    /// an off-subnet refusal of it is what an honest peer behind a STUN
    /// server inside its own LAN produces against a node on another network.
    /// The other three classes still have no honest producer.
    ///
    /// For the same reason an offer whose every candidate, the reflexive
    /// address included, was refused as off-subnet is not counted as entirely
    /// refused: two such peers on different private networks produce it on
    /// every attempt.
    ///
    /// A candidate list longer than `MAX_OFFERED_CANDIDATES` counts too: the
    /// generator tops out near eight, so nothing honest reaches the bound.
    pub fn suspicious(&self) -> bool {
        self.unroutable + self.zeroport + self.unparsable + self.capped > 0
            || self.over_offered > 0
            || (self.offered > 0 && self.admitted == 0 && !self.refused_only_off_subnet())
            || self
                .reflexive
                .is_some_and(|label| label != RejectClass::OffSubnet.label())
    }

    /// Whether this planning call refused anything worth a record: fewer
    /// targets planned than candidates offered, or targets lost to the cap,
    /// or candidates past the offer limit. `admitted` counts planned
    /// pairings, not candidates, so a refusal can hide behind them.
    pub fn has_refusals(&self) -> bool {
        self.offered > self.admitted || self.capped > 0 || self.over_offered > 0
    }

    /// Whether every candidate the peer offered, its reflexive address
    /// included, was refused as off-subnet.
    fn refused_only_off_subnet(&self) -> bool {
        self.offsubnet + usize::from(self.reflexive == Some(RejectClass::OffSubnet.label()))
            == self.offered
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
/// A private IPv4 address is admitted only when one of this node's interface
/// prefixes (`on_link`) holds both it and one of `refs`, our own addresses
/// (the local candidates we share, and our reflexive address when that is
/// private). An interface prefix alone is not enough: at the default
/// settings we share no local candidate, and admitting anything inside our
/// prefixes would let any peer aim our probes at hosts on our LAN. A
/// unique-local IPv6 address is always refused, because the traversal socket
/// is IPv4 and could not reach it. The peer's reflexive address gets the
/// same treatment as its other candidates.
fn admit_remote(
    candidate: &TraversalAddress,
    refs: &[IpAddr],
    on_link: &OnLinkPrefixes,
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
    if is_private_ip(ip) && !(ip.is_ipv4() && refs.iter().any(|ours| on_link.share_link(*ours, ip)))
    {
        return Err(RejectClass::OffSubnet);
    }
    Ok(ip)
}

pub fn plan_punch_targets(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
    on_link: &OnLinkPrefixes,
) -> (Vec<PlannedPunchTarget>, PunchTargetTally) {
    let mut planned = Vec::new();
    let mut tally = PunchTargetTally {
        offered: remote_addresses.len() + usize::from(remote_reflexive_address.is_some()),
        ..PunchTargetTally::default()
    };

    // Our own addresses a peer's private candidate has to share an interface
    // prefix with. The local reflexive address joins the set when it is
    // itself private, which is what keeps a deployment whose STUN server sits
    // inside the LAN able to match while the shipped
    // `share_local_candidates=false` leaves the local list empty.
    let mut refs: Vec<IpAddr> = local_addresses.iter().filter_map(own_ip).collect();
    if let Some(reflexive) = local_reflexive_address.and_then(own_ip)
        && is_private_ip(reflexive)
    {
        refs.push(reflexive);
    }

    // A peer names its own candidate list, so bound it before anything walks
    // it. The excess is recorded and discarded rather than failing the whole
    // offer, which would cost an honest many-homed peer its traversal.
    let considered = &remote_addresses[..remote_addresses.len().min(MAX_OFFERED_CANDIDATES)];
    tally.over_offered = remote_addresses.len() - considered.len();

    // Everything on the remote side is peer-supplied, so it is vetted once
    // here and the branches below only ever see admitted candidates.
    let remote_reflexive =
        remote_reflexive_address.and_then(|remote| match admit_remote(remote, &refs, on_link) {
            Ok(ip) => Some((remote, ip)),
            Err(class) => {
                tally.refuse_reflexive(class, remote);
                None
            }
        });
    let remote_candidates = considered
        .iter()
        .filter_map(|remote| match admit_remote(remote, &refs, on_link) {
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

    // Same-LAN paths: one of our interface prefixes holds both a local
    // candidate of ours and the peer's candidate. Only fires when both sides
    // exposed local candidates. IPv4 only, the traversal socket's family.
    for local in local_addresses {
        let Some(local_ip) = own_ip(local) else {
            continue;
        };
        for (remote, remote_ip) in &remote_candidates {
            if local_ip.is_ipv4() && remote_ip.is_ipv4() && on_link.share_link(local_ip, *remote_ip)
            {
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
pub fn planned_remote_endpoints(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
    on_link: &OnLinkPrefixes,
) -> Result<(Vec<SocketAddr>, PunchTargetTally), Error> {
    let mut remotes = Vec::new();
    let (planned, tally) = plan_punch_targets(
        local_addresses,
        local_reflexive_address,
        remote_addresses,
        remote_reflexive_address,
        on_link,
    );
    for target in planned {
        let remote = SocketAddr::new(target.remote_ip, target.remote.port);
        if !remotes.contains(&remote) {
            remotes.push(remote);
        }
    }
    Ok((remotes, tally))
}
