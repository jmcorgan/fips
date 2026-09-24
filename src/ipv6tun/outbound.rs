//! Host-side half of forwarding an IPv6 packet read from the TUN.
//!
//! This side checks the packet, answers the host with ICMPv6 when the mesh
//! cannot take it, and turns the destination address into the 15-byte
//! prefix the mesh resolves. What happens to the packet inside the mesh
//! (session lookup, queueing while a session is set up, discovery) is the
//! mesh's business, reached through the [`Mesh`] trait.
//!
//! The decisions are the synchronous functions [`admit`] and
//! [`path_too_big`]; [`forward`] drives them against a [`Mesh`].

use super::icmp::{IcmpContext, effective_ipv6_mtu};
use std::future::Future;

/// What the outbound path needs from the mesh side.
pub(crate) trait Mesh {
    /// The mesh's handle on a resolved destination, passed back to `send`.
    type Dest;

    /// Largest IPv6 packet, header included, the mesh carries on its
    /// narrowest transport.
    fn ipv6_mtu(&self) -> u16;

    /// Resolve a destination from bytes 1-15 of its IPv6 address, with the
    /// session's current path MTU if a session to it is established.
    fn resolve(&mut self, prefix: &[u8; 15]) -> Option<Route<Self::Dest>>;

    /// Send the packet on the destination's session, or hold it while one
    /// is set up.
    fn send(&mut self, dest: Self::Dest, packet: Vec<u8>) -> impl Future<Output = Outcome> + Send;

    /// Borrow the sender of ICMPv6 replies to the host.
    fn icmp(&mut self) -> IcmpContext<'_>;
}

/// A destination the mesh resolved from an address prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route<D> {
    /// The mesh's handle on the destination.
    pub dest: D,
    /// Current path MTU of an established session to it, `None` when no
    /// session is established or it has no path MTU state.
    pub path_mtu: Option<u16>,
}

/// What the mesh did with a packet handed to [`Mesh::send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Handed to the established session. A send error is logged by the
    /// mesh and not answered to the host.
    Sent,
    /// Held until the destination's session is established.
    Queued,
    /// Refused because the session table is full; the packet comes back so
    /// the host can be told the destination is unreachable.
    TableFull(Vec<u8>),
}

/// The verdict on a packet read from the TUN, before the mesh is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Not an IPv6 packet, or shorter than its fixed header.
    Drop,
    /// Larger than the mesh carries; answer Packet Too Big with this MTU.
    TooBig(u32),
    /// Forward to the destination with this address prefix.
    Forward([u8; 15]),
}

/// Check a packet from the TUN against the node-wide IPv6 MTU and extract
/// its destination prefix.
pub(crate) fn admit(packet: &[u8], ipv6_mtu: u16) -> Admit {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Admit::Drop;
    }

    // Check if packet will fit after FIPS encapsulation
    let effective_mtu = ipv6_mtu as usize;
    if packet.len() > effective_mtu {
        return Admit::TooBig(effective_mtu as u32);
    }

    // Extract destination FipsAddress prefix (IPv6 dest bytes 1-15)
    // IPv6 header: bytes 24-39 are dest addr, so prefix = bytes 25-39
    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&packet[25..40]);
    Admit::Forward(prefix)
}

/// The Packet Too Big MTU for a packet of `len` bytes on a session whose
/// path MTU is `path_mtu`, or `None` if it fits.
///
/// Applies only when the path is narrower than the node-wide `ipv6_mtu`,
/// which [`admit`] has already enforced.
pub(crate) fn path_too_big(len: usize, path_mtu: u16, ipv6_mtu: u16) -> Option<u32> {
    let path_ipv6_mtu = effective_ipv6_mtu(path_mtu) as usize;
    if path_ipv6_mtu < ipv6_mtu as usize && len > path_ipv6_mtu {
        Some(path_ipv6_mtu as u32)
    } else {
        None
    }
}

/// Forward one IPv6 packet read from the TUN into the mesh.
///
/// Packets that are not IPv6, too large for the node, too large for an
/// established session's path, to an unknown destination, or refused for a
/// full session table are answered or dropped here. The rest go to
/// [`Mesh::send`].
pub(crate) async fn forward<M: Mesh>(mesh: &mut M, packet: Vec<u8>) {
    let ipv6_mtu = mesh.ipv6_mtu();
    let prefix = match admit(&packet, ipv6_mtu) {
        Admit::Drop => return,
        Admit::TooBig(mtu) => {
            mesh.icmp().packet_too_big(&packet, mtu);
            return;
        }
        Admit::Forward(prefix) => prefix,
    };

    let Some(route) = mesh.resolve(&prefix) else {
        mesh.icmp().dest_unreachable(&packet);
        return;
    };

    // Check per-destination path MTU learned from MtuExceeded signals.
    // The first oversized packet is forwarded normally and triggers
    // the MtuExceeded signal; subsequent packets are caught here and
    // generate ICMPv6 Packet Too Big back to the application.
    if let Some(mtu) = route
        .path_mtu
        .and_then(|path_mtu| path_too_big(packet.len(), path_mtu, ipv6_mtu))
    {
        mesh.icmp().packet_too_big(&packet, mtu);
        return;
    }

    if let Outcome::TableFull(packet) = mesh.send(route.dest, packet).await {
        mesh.icmp().dest_unreachable(&packet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv6tun::icmp_rate_limit::IcmpRateLimiter;
    use crate::ipv6tun::tun::TunTx;
    use std::net::Ipv6Addr;
    use std::sync::mpsc;

    /// A mesh with one known destination prefix and a scripted send outcome.
    struct FakeMesh {
        ipv6_mtu: u16,
        known: [u8; 15],
        path_mtu: Option<u16>,
        refuse: bool,
        sent: Vec<Vec<u8>>,
        tun_tx: TunTx,
        limiter: IcmpRateLimiter,
    }

    impl Mesh for FakeMesh {
        type Dest = ();

        fn ipv6_mtu(&self) -> u16 {
            self.ipv6_mtu
        }

        fn resolve(&mut self, prefix: &[u8; 15]) -> Option<Route<()>> {
            (*prefix == self.known).then_some(Route {
                dest: (),
                path_mtu: self.path_mtu,
            })
        }

        fn send(&mut self, _dest: (), packet: Vec<u8>) -> impl Future<Output = Outcome> + Send {
            let outcome = if self.refuse {
                Outcome::TableFull(packet)
            } else {
                self.sent.push(packet);
                Outcome::Sent
            };
            async move { outcome }
        }

        fn icmp(&mut self) -> IcmpContext<'_> {
            IcmpContext::new(
                Some(&self.tun_tx),
                "fd00::1".parse().unwrap(),
                &mut self.limiter,
            )
        }
    }

    /// Build a fake mesh and the receiving end of its TUN channel.
    fn fake(ipv6_mtu: u16) -> (FakeMesh, mpsc::Receiver<Vec<u8>>) {
        let (tun_tx, rx) = mpsc::channel();
        let mesh = FakeMesh {
            ipv6_mtu,
            known: dest().octets()[1..16].try_into().unwrap(),
            path_mtu: None,
            refuse: false,
            sent: Vec::new(),
            tun_tx,
            limiter: IcmpRateLimiter::new(),
        };
        (mesh, rx)
    }

    /// The destination the fake mesh knows.
    fn dest() -> Ipv6Addr {
        "fd12:3456:789a::2".parse().unwrap()
    }

    /// An IPv6 UDP packet of `len` bytes from a host address to `dst`.
    fn packet(dst: Ipv6Addr, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        p[6] = 17;
        p[7] = 64;
        let src: Ipv6Addr = "fd00::5".parse().unwrap();
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    /// The ICMPv6 type of a reply written to the TUN.
    fn icmp_type(reply: &[u8]) -> u8 {
        reply[40]
    }

    #[test]
    fn admit_drops_short_and_non_ipv6_packets() {
        assert_eq!(admit(&[0x60; 39], 1280), Admit::Drop);
        let mut p = packet(dest(), 60);
        p[0] = 0x45;
        assert_eq!(admit(&p, 1280), Admit::Drop);
    }

    #[test]
    fn admit_reports_the_node_mtu_for_an_oversized_packet() {
        assert_eq!(admit(&packet(dest(), 1281), 1280), Admit::TooBig(1280));
        assert!(matches!(
            admit(&packet(dest(), 1280), 1280),
            Admit::Forward(_)
        ));
    }

    #[test]
    fn admit_extracts_destination_bytes_one_to_fifteen() {
        let expected: [u8; 15] = dest().octets()[1..16].try_into().unwrap();
        assert_eq!(admit(&packet(dest(), 60), 1280), Admit::Forward(expected));
    }

    #[test]
    fn path_too_big_applies_only_below_the_node_mtu() {
        let node = 1280;
        let narrow = effective_ipv6_mtu(1000);
        assert_eq!(
            path_too_big(narrow as usize + 1, 1000, node),
            Some(narrow as u32)
        );
        assert_eq!(path_too_big(narrow as usize, 1000, node), None);
        // A path at least as wide as the node MTU never answers.
        assert_eq!(path_too_big(1280, 1280 + 77, node), None);
    }

    #[tokio::test]
    async fn forward_answers_unknown_destination_with_unreachable() {
        let (mut mesh, rx) = fake(1280);
        forward(&mut mesh, packet("fd99::1".parse().unwrap(), 60)).await;
        assert!(mesh.sent.is_empty());
        assert_eq!(icmp_type(&rx.try_recv().unwrap()), 1);
    }

    #[tokio::test]
    async fn forward_answers_oversized_for_session_path_with_packet_too_big() {
        let (mut mesh, rx) = fake(1280);
        mesh.path_mtu = Some(1000);
        forward(&mut mesh, packet(dest(), 1200)).await;
        assert!(mesh.sent.is_empty());
        assert_eq!(icmp_type(&rx.try_recv().unwrap()), 2);
    }

    #[tokio::test]
    async fn forward_sends_a_fitting_packet_without_a_reply() {
        let (mut mesh, rx) = fake(1280);
        mesh.path_mtu = Some(1400);
        forward(&mut mesh, packet(dest(), 1200)).await;
        assert_eq!(mesh.sent.len(), 1);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn forward_answers_a_full_session_table_with_unreachable() {
        let (mut mesh, rx) = fake(1280);
        mesh.refuse = true;
        forward(&mut mesh, packet(dest(), 60)).await;
        assert_eq!(icmp_type(&rx.try_recv().unwrap()), 1);
    }
}
