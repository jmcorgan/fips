//! Conntrack sessions read over netlink.
//!
//! A kernel built without `CONFIG_NF_CONNTRACK_PROCFS` has no
//! `/proc/net/nf_conntrack`, while `conntrack -L` still lists the table: it
//! asks the kernel for a dump over `NETLINK_NETFILTER`. This reader does the
//! same, so such a kernel can still pin mappings that carry traffic.

use super::pool::{ConntrackQuerier, ConntrackSnapshot};
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_netfilter::conntrack::{
    ConntrackAttribute, ConntrackMessage, IPTuple, Status, Tuple,
};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Longest wait for each part of the kernel's reply.
///
/// The read runs on a blocking thread once per tick, so a kernel that never
/// answers must not hold that thread for longer than a tick.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Sequence number for the next dump request, so a reply to an earlier
/// request cannot be counted as part of this one.
static NEXT_SEQ: AtomicU32 = AtomicU32::new(1);

/// Whether a dump has more to come after the buffer just counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpState {
    /// The kernel has more of the dump to send.
    More,
    /// The kernel sent the end-of-dump message.
    Done,
}

/// Conntrack querier that dumps the table over netlink.
///
/// Needs `CAP_NET_ADMIN` in the gateway's network namespace, which the
/// gateway already needs for its NAT table.
pub struct NetlinkConntrack;

impl ConntrackQuerier for NetlinkConntrack {
    fn snapshot(&self) -> Result<ConntrackSnapshot, io::Error> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        socket2::SockRef::from(&socket).set_read_timeout(Some(READ_TIMEOUT))?;

        let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        socket.send(&dump_request(seq), 0)?;

        let mut snapshot = ConntrackSnapshot::empty_read();
        loop {
            // Sized by peeking first, so a large batch is not truncated.
            let (buf, _) = socket.recv_from_full()?;
            if count_dump(&buf, seq, &mut snapshot)? == DumpState::Done {
                break;
            }
        }
        Ok(snapshot)
    }
}

/// A request for a dump of the IPv6 conntrack table.
///
/// The family in the netfilter header makes the kernel leave out IPv4
/// entries, which could never name a virtual IP.
fn dump_request(seq: u32) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    header.sequence_number = seq;
    let mut message = NetlinkMessage::new(
        header,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv6, 0, 0),
            ConntrackMessage::Get(vec![]),
        )),
    );
    message.finalize();
    let mut buf = vec![0; message.buffer_len()];
    message.serialize(&mut buf);
    buf
}

/// Add the conntrack entries in one received buffer to `snapshot`.
///
/// An entry counts once for each distinct IPv6 destination among its original
/// and reply tuples, the same rule the proc-file parser applies to a line,
/// and records its binding from original destination to reply source.
/// A message carrying another sequence number is skipped. A dump the kernel
/// flags as interrupted is counted as received: reading the proc file is not
/// atomic across the table either, and failing the read would zero every
/// mapping for the tick.
pub fn count_dump(
    buf: &[u8],
    seq: u32,
    snapshot: &mut ConntrackSnapshot,
) -> Result<DumpState, io::Error> {
    let mut offset = 0;
    while offset < buf.len() {
        let message = NetlinkMessage::<NetfilterMessage>::deserialize(&buf[offset..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // Messages are padded to four bytes. The length is at least a header,
        // or the parse above would have failed, so the walk always advances.
        let len = message.header.length as usize;
        offset += (len + 3) & !3;
        if message.header.sequence_number != seq {
            continue;
        }
        match message.payload {
            NetlinkPayload::Done(_) => return Ok(DumpState::Done),
            NetlinkPayload::Error(e) if e.code.is_some() => return Err(e.to_io()),
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::Conntrack(ConntrackMessage::New(attrs)),
                ..
            }) => count_entry(&attrs, snapshot),
            _ => {}
        }
    }
    Ok(DumpState::More)
}

/// Add one conntrack entry to `snapshot`: once per distinct IPv6
/// destination among its original and reply tuples, and its binding from
/// the original destination to the reply source, replied when the kernel has
/// seen a reply.
fn count_entry(attrs: &[ConntrackAttribute], snapshot: &mut ConntrackSnapshot) {
    let mut seen = HashSet::new();
    let mut orig_dst = None;
    let mut reply_src = None;
    let mut replied = false;
    for attr in attrs {
        let (tuples, original) = match attr {
            ConntrackAttribute::CtaTupleOrig(t) => (t, true),
            ConntrackAttribute::CtaTupleReply(t) => (t, false),
            ConntrackAttribute::CtaStatus(status) => {
                replied = status.contains(Status::SeenReply);
                continue;
            }
            _ => continue,
        };
        for tuple in tuples {
            let Tuple::Ip(ip) = tuple else { continue };
            for field in ip {
                match field {
                    IPTuple::DestinationAddress(IpAddr::V6(dst)) => {
                        seen.insert(*dst);
                        if original {
                            orig_dst = Some(*dst);
                        }
                    }
                    IPTuple::SourceAddress(IpAddr::V6(src)) if !original => {
                        reply_src = Some(*src);
                    }
                    _ => {}
                }
            }
        }
    }
    for dst in seen {
        snapshot.add_session(dst);
    }
    if let (Some(orig_dst), Some(reply_src)) = (orig_dst, reply_src) {
        snapshot.record_binding(orig_dst, reply_src, replied);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{DoneMessage, ErrorMessage};
    use std::net::Ipv6Addr;
    use std::num::NonZeroI32;

    const SEQ: u32 = 7;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// One tuple naming a source and a destination.
    fn tuple(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<Tuple> {
        vec![Tuple::Ip(vec![
            IPTuple::SourceAddress(IpAddr::V6(src)),
            IPTuple::DestinationAddress(IpAddr::V6(dst)),
        ])]
    }

    /// A conntrack entry as a dump reply carries it.
    fn entry(orig: Vec<Tuple>, reply: Vec<Tuple>) -> NetfilterMessage {
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv6, 0, 0),
            ConntrackMessage::New(vec![
                ConntrackAttribute::CtaTupleOrig(orig),
                ConntrackAttribute::CtaTupleReply(reply),
            ]),
        )
    }

    /// Serialise one netlink message with the given sequence number.
    fn frame(payload: NetlinkPayload<NetfilterMessage>, seq: u32) -> Vec<u8> {
        let mut header = NetlinkHeader::default();
        header.sequence_number = seq;
        header.flags = netlink_packet_core::NLM_F_MULTIPART;
        let mut message = NetlinkMessage::new(header, payload);
        message.finalize();
        let mut buf = vec![0; message.buffer_len()];
        message.serialize(&mut buf);
        buf
    }

    fn done() -> NetlinkPayload<NetfilterMessage> {
        NetlinkPayload::Done(DoneMessage::default())
    }

    /// The flow the gateway sees for a LAN client using a virtual IP: the
    /// original tuple is client to virtual IP, and the reply, after DNAT and
    /// masquerade, is the mesh address back to the gateway.
    fn client_flow(virtual_ip: Ipv6Addr) -> NetfilterMessage {
        entry(
            tuple(v6("fd02::20"), virtual_ip),
            tuple(v6("fd9a::1"), v6("fd9a::2")),
        )
    }

    /// Session counts by address, as the tests read them.
    struct Counts(ConntrackSnapshot);

    impl Counts {
        fn get(&self, addr: &Ipv6Addr) -> Option<u32> {
            Some(self.0.sessions_for(*addr)).filter(|n| *n > 0)
        }

        fn len(&self) -> usize {
            self.0.len()
        }
    }

    fn count(buf: &[u8]) -> (Result<DumpState, io::Error>, Counts) {
        let mut snapshot = ConntrackSnapshot::empty_read();
        let state = count_dump(buf, SEQ, &mut snapshot);
        (state, Counts(snapshot))
    }

    #[test]
    fn netlink_dump_counts_an_entry_whose_original_destination_is_the_virtual_ip() {
        let virtual_ip = v6("fd01::1");
        let buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ);

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::More);
        assert_eq!(counts.get(&virtual_ip), Some(1));
        // The reply tuple's destination is counted too, as the proc parser
        // counts every dst= on the line.
        assert_eq!(counts.get(&v6("fd9a::2")), Some(1));
    }

    #[test]
    fn netlink_dump_counts_an_entry_once_when_both_tuples_name_the_address() {
        let addr = v6("fd01::1");
        let hairpin = entry(tuple(addr, addr), tuple(addr, addr));
        let buf = frame(NetlinkPayload::from(hairpin), SEQ);

        let (_, counts) = count(&buf);

        assert_eq!(counts.get(&addr), Some(1));
    }

    #[test]
    fn netlink_dump_counts_each_entry_across_several_messages_in_one_buffer() {
        let virtual_ip = v6("fd01::1");
        let other = v6("fd01::2");
        let mut buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ);
        buf.extend(frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ));
        buf.extend(frame(NetlinkPayload::from(client_flow(other)), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::More);
        assert_eq!(counts.get(&virtual_ip), Some(2));
        assert_eq!(counts.get(&other), Some(1));
    }

    #[test]
    fn netlink_dump_ignores_an_ipv4_entry() {
        let v4 = |s: &str| IpAddr::V4(s.parse().unwrap());
        let ipv4 = NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv4, 0, 0),
            ConntrackMessage::New(vec![ConntrackAttribute::CtaTupleOrig(vec![Tuple::Ip(
                vec![
                    IPTuple::SourceAddress(v4("192.0.2.1")),
                    IPTuple::DestinationAddress(v4("192.0.2.2")),
                ],
            )])]),
        );
        let mut buf = frame(NetlinkPayload::from(ipv4), SEQ);
        buf.extend(frame(NetlinkPayload::from(client_flow(v6("fd01::1"))), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::More);
        assert_eq!(counts.len(), 2, "only the IPv6 entry's two destinations");
    }

    #[test]
    fn netlink_dump_reports_done_on_the_done_message() {
        let virtual_ip = v6("fd01::1");
        let mut buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ);
        buf.extend(frame(done(), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::Done);
        assert_eq!(counts.get(&virtual_ip), Some(1));
    }

    #[test]
    fn netlink_dump_turns_an_eperm_error_message_into_permission_denied() {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(-libc::EPERM);
        let buf = frame(NetlinkPayload::Error(error), SEQ);

        let (state, _) = count(&buf);

        assert_eq!(
            state.expect_err("an error reply must fail the read").kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn netlink_dump_skips_a_message_with_another_sequence_number() {
        let virtual_ip = v6("fd01::1");
        let mut buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ + 1);
        buf.extend(frame(done(), SEQ + 1));
        buf.extend(frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(
            state.unwrap(),
            DumpState::More,
            "another request's end of dump does not end this one"
        );
        assert_eq!(counts.get(&virtual_ip), Some(1));
    }

    /// A DNAT'd entry: the LAN client to `virtual_ip`, and back from
    /// `mesh` to the gateway's fips0 address, with the given status.
    fn dnat_entry(
        virtual_ip: Ipv6Addr,
        mesh: Ipv6Addr,
        status: Option<Status>,
    ) -> NetfilterMessage {
        let mut attrs = vec![
            ConntrackAttribute::CtaTupleOrig(tuple(v6("fd02::20"), virtual_ip)),
            ConntrackAttribute::CtaTupleReply(tuple(mesh, v6("fd9a::1"))),
        ];
        if let Some(status) = status {
            attrs.push(ConntrackAttribute::CtaStatus(status));
        }
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv6, 0, 0),
            ConntrackMessage::New(attrs),
        )
    }

    #[test]
    fn netlink_dump_records_the_reply_source_only_with_seen_reply() {
        let (replied_vip, replied_mesh) = (v6("fd01::5"), v6("fd9a::2"));
        let (quiet_vip, quiet_mesh) = (v6("fd01::6"), v6("fd9a::3"));
        let mut buf = frame(
            NetlinkPayload::from(dnat_entry(
                replied_vip,
                replied_mesh,
                Some(Status::SeenReply | Status::Confirmed),
            )),
            SEQ,
        );
        buf.extend(frame(
            NetlinkPayload::from(dnat_entry(quiet_vip, quiet_mesh, Some(Status::Confirmed))),
            SEQ,
        ));

        let mut snapshot = ConntrackSnapshot::empty_read();
        count_dump(&buf, SEQ, &mut snapshot).unwrap();

        assert!(snapshot.bound_to(replied_vip, replied_mesh));
        assert!(snapshot.replied_from(replied_vip, replied_mesh));
        assert!(
            !snapshot.bound_to(replied_vip, replied_vip),
            "the original destination is not its own reply source"
        );
        assert!(
            snapshot.bound_to(quiet_vip, quiet_mesh),
            "the binding is recorded"
        );
        assert!(
            !snapshot.replied_from(quiet_vip, quiet_mesh),
            "an entry without seen-reply is not a reply"
        );
        assert_eq!(
            snapshot.sessions_for(replied_vip),
            1,
            "pinning is unchanged"
        );
        assert_eq!(snapshot.sessions_for(quiet_vip), 1, "pinning is unchanged");
    }

    #[test]
    fn netlink_dump_rejects_a_buffer_that_does_not_parse() {
        let mut buf = frame(NetlinkPayload::from(client_flow(v6("fd01::1"))), SEQ);
        buf.truncate(buf.len() - 4);

        let (state, _) = count(&buf);

        assert_eq!(
            state.expect_err("a short buffer must fail the read").kind(),
            io::ErrorKind::InvalidData
        );
    }
}
