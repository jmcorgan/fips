//! DNS message screening and reply building for the `.fips` responders.
//!
//! Both the daemon's `.fips` responder and the gateway's forwarder run every
//! datagram they receive through [`screen`] before answering it (the daemon
//! applies its mesh-interface filter first), and build every reply with
//! [`reply`]. The screen decides whether a datagram is
//! a query worth answering at all; the reply builder writes a fresh header,
//! the query's one question byte for byte, and only the records the responder
//! produced, so nothing an untrusted sender put in its datagram is ever sent
//! back beyond the question itself.
//!
//! The module is pure: it does no I/O, reads no clock and knows nothing of
//! `.fips`. The responders' receive loops log and send what it returns.

use std::net::Ipv6Addr;

/// Length of the fixed DNS message header.
pub(crate) const HEADER_LEN: usize = 12;

/// Receive buffer size of both DNS responders, and of the gateway's read of
/// its upstream's answer.
///
/// Bounds how much of a datagram either responder reads. A datagram of this
/// length or more may have been cut short by the read (on Linux the kernel
/// truncates silently), so [`screen`] drops it rather than judge a prefix.
/// The value is not measured: it is the size the gateway already used,
/// larger than the EDNS buffer sizes stub resolvers commonly advertise.
/// An attacker gains nothing from a larger buffer: the reply to any datagram
/// is bounded by its question, not by its length (see [`reply`]).
pub(crate) const MAX_DATAGRAM: usize = 4096;

/// Record type AAAA.
pub(crate) const TYPE_AAAA: u16 = 28;

/// Record type ANY (a QTYPE only).
#[cfg(target_os = "linux")]
pub(crate) const TYPE_ANY: u16 = 255;

/// Record type SOA.
#[cfg(target_os = "linux")]
const TYPE_SOA: u16 = 6;

/// Class IN.
pub(crate) const CLASS_IN: u16 = 1;

/// Class ANY, accepted in a question alongside IN.
const CLASS_ANY: u16 = 255;

/// Header flag AA (authoritative answer), which a caller of [`reply`] may ask for.
pub(crate) const AA: u16 = 0x0400;

/// Header flag RA (recursion available), which a caller of [`reply`] may ask for.
#[cfg(target_os = "linux")]
pub(crate) const RA: u16 = FLAG_RA;

/// Header flag QR: set in a response, clear in a query.
const FLAG_QR: u16 = 0x8000;
/// Header field OPCODE, four bits.
const FLAG_OPCODE: u16 = 0x7800;
/// Header flag RD (recursion desired).
const FLAG_RD: u16 = 0x0100;
/// Header flag RA (recursion available).
const FLAG_RA: u16 = 0x0080;
/// Header flag CD (checking disabled).
const FLAG_CD: u16 = 0x0010;

/// Flags a reply copies from its query: the opcode, RD and CD.
const COPIED_FLAGS: u16 = FLAG_OPCODE | FLAG_RD | FLAG_CD;

/// Flags a caller of [`reply`] may set: AA and RA. Every other bit, Z and
/// TC included, stays clear.
const CALLER_FLAGS: u16 = AA | FLAG_RA;

/// Source ports never answered.
///
/// No resolver sends from these, and they are the UDP services that answer
/// arbitrary input (echo, daytime, quote of the day, chargen, time), so a
/// reply to one could start an endless exchange with it. Port 0 is not a
/// valid source port.
const SERVICE_PORTS: [u16; 6] = [0, 7, 13, 17, 19, 37];

/// Longest name on the wire, counting length bytes and the root (RFC 1035
/// Section 2.3.4).
const MAX_NAME: usize = 255;

/// Largest TTL a resolver honours (RFC 2181 Section 8): a TTL with the top
/// bit set is read as zero.
pub(crate) const MAX_TTL: u32 = 0x7FFF_FFFF;

/// A configured TTL, clamped to [`MAX_TTL`].
pub(crate) fn clamp_ttl(ttl: u32) -> u32 {
    ttl.min(MAX_TTL)
}

/// What [`screen`] decided about a datagram.
pub(crate) enum Screen<'a> {
    /// Send nothing.
    Drop(DropReason),
    /// Send this error reply, header only or with the question.
    Reply(Rcode, Vec<u8>),
    /// A well-formed query: answer it.
    Query(Query<'a>),
}

/// Why [`screen`] dropped a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropReason {
    /// Shorter than a header.
    Short,
    /// Filled the receive buffer, so it may have been truncated.
    FillsBuffer,
    /// QR is set: a response, never answered.
    Response,
    /// Sent from a port in [`SERVICE_PORTS`].
    ServicePort,
    /// Its counts are not a query's.
    NotQueryShaped,
}

impl DropReason {
    /// The reason as a log field value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DropReason::Short => "short",
            DropReason::FillsBuffer => "fills-buffer",
            DropReason::Response => "response",
            DropReason::ServicePort => "service-port",
            DropReason::NotQueryShaped => "not-query-shaped",
        }
    }
}

/// What a responder's dispatch returns to its receive loop, which logs and
/// sends and decides nothing.
pub(crate) enum Outcome<T> {
    /// Send nothing.
    Drop(DropReason),
    /// Send this error reply built by [`screen`].
    Refuse(Rcode, Vec<u8>),
    /// Send the responder's answer.
    Answer(T),
}

/// A query that passed the screen.
pub(crate) struct Query<'a> {
    /// The query's ID.
    pub id: u16,
    /// The query's flags word; a reply copies RD and CD from it.
    flags: u16,
    /// The question, QNAME through QCLASS, exactly as received.
    question: &'a [u8],
    /// The question name in text form, identical to `simple-dns`'s `Name`
    /// display: labels joined by `.`, no trailing dot.
    pub name: String,
    /// The question type, as received.
    pub qtype: u16,
}

#[cfg(target_os = "linux")]
impl Query<'_> {
    /// The question name as it appears on the wire.
    pub(crate) fn qname_wire(&self) -> &[u8] {
        &self.question[..self.question.len() - 4]
    }
}

/// A DNS response code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Rcode(u8);

impl Rcode {
    /// No error.
    pub(crate) const NOERROR: Rcode = Rcode(0);
    /// The query could not be interpreted.
    pub(crate) const FORMERR: Rcode = Rcode(1);
    /// The server could not answer, here because the upstream failed.
    #[cfg(target_os = "linux")]
    pub(crate) const SERVFAIL: Rcode = Rcode(2);
    /// The name does not exist.
    pub(crate) const NXDOMAIN: Rcode = Rcode(3);
    /// The opcode is not supported.
    pub(crate) const NOTIMP: Rcode = Rcode(4);
    /// The server will not answer this query.
    pub(crate) const REFUSED: Rcode = Rcode(5);

    /// The response code in a message's header, from the header's fourth
    /// byte (its low four bits).
    #[cfg(target_os = "linux")]
    pub(crate) fn from_header(header_byte3: u8) -> Rcode {
        Rcode(header_byte3 & 0x0F)
    }
}

/// The code's mnemonic (RFC 6895 Section 2.3) for codes 0 to 10, or its
/// number, as `RCODE11`, for any higher code.
impl std::fmt::Display for Rcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.0 {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            6 => "YXDOMAIN",
            7 => "YXRRSET",
            8 => "NXRRSET",
            9 => "NOTAUTH",
            10 => "NOTZONE",
            code => return write!(f, "RCODE{code}"),
        };
        f.write_str(name)
    }
}

/// A resource record a responder adds to its reply.
pub(crate) struct Record {
    /// Offset, within the reply, of the name the record's owner pointer
    /// names: a position in the question name, which starts at offset 12.
    owner: u16,
    /// The record type.
    rtype: u16,
    /// The record's TTL in seconds.
    ttl: u32,
    /// The record data, written after its length.
    rdata: Vec<u8>,
}

/// An AAAA record for the question name.
pub(crate) fn aaaa(addr: Ipv6Addr, ttl: u32) -> Record {
    Record {
        owner: HEADER_LEN as u16,
        rtype: TYPE_AAAA,
        ttl,
        rdata: addr.octets().to_vec(),
    }
}

/// An SOA record for a negative answer to `query` in `zone`.
///
/// The record is owned by the zone apex, as RFC 2308 Section 3 asks: the
/// point in the question name where its remaining labels equal `zone`'s,
/// ignoring ASCII case. A question not in the zone has its whole name as
/// the owner. `mname` and `rname` are written as their leading labels and a
/// pointer to that apex when they end in `zone` and the question is in it,
/// otherwise whole. Refresh, retry, expire, minimum and the record's TTL are
/// all `ttl`.
///
/// Size: 51 bytes for the gateway's names when the question ends in the
/// zone, 59 otherwise.
#[cfg(target_os = "linux")]
pub(crate) fn soa(
    query: &Query<'_>,
    zone: &str,
    mname: &str,
    rname: &str,
    serial: u32,
    ttl: u32,
) -> Record {
    let apex = zone_offset(query.qname_wire(), zone);
    let owner = (HEADER_LEN + apex.unwrap_or(0)) as u16;
    let pointer = apex.map(|_| owner);
    let mut rdata = Vec::new();
    for name in [mname, rname] {
        write_name(&mut rdata, name, zone, pointer);
    }
    rdata.extend_from_slice(&serial.to_be_bytes());
    for _ in 0..4 {
        rdata.extend_from_slice(&ttl.to_be_bytes());
    }
    Record {
        owner,
        rtype: TYPE_SOA,
        ttl,
        rdata,
    }
}

/// The offset in a wire name (no pointers) where its remaining labels are
/// `zone`'s labels, ignoring ASCII case.
#[cfg(target_os = "linux")]
fn zone_offset(qname: &[u8], zone: &str) -> Option<usize> {
    let zone: Vec<&[u8]> = zone.split('.').map(str::as_bytes).collect();
    let mut starts = Vec::new();
    let mut pos = 0;
    while let Some(&len) = qname.get(pos).filter(|&&len| len != 0) {
        starts.push(pos);
        pos += 1 + len as usize;
    }
    starts.into_iter().find(|&start| {
        let mut pos = start;
        let mut labels = Vec::new();
        while let Some(&len) = qname.get(pos).filter(|&&len| len != 0) {
            labels.push(&qname[pos + 1..pos + 1 + len as usize]);
            pos += 1 + len as usize;
        }
        labels.len() == zone.len()
            && labels
                .iter()
                .zip(&zone)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// Write a dotted name: its labels before `zone` and then `pointer` when it
/// ends in `zone` and a pointer is given, otherwise all its labels and the
/// root.
#[cfg(target_os = "linux")]
fn write_name(out: &mut Vec<u8>, name: &str, zone: &str, pointer: Option<u16>) {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    let zone_len = zone.split('.').count();
    let in_zone = labels.len() > zone_len
        && labels[labels.len() - zone_len..]
            .iter()
            .zip(zone.split('.'))
            .all(|(a, b)| a.eq_ignore_ascii_case(b));
    let (written, tail) = match pointer {
        Some(pointer) if in_zone => (&labels[..labels.len() - zone_len], Some(pointer)),
        _ => (&labels[..], None),
    };
    for label in written {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|&len| len <= 63)
            .expect("SOA names are constants with labels of at most 63 bytes");
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    match tail {
        Some(pointer) => out.extend_from_slice(&(0xC000 | pointer).to_be_bytes()),
        None => out.push(0),
    }
}

/// A one-question query: `id`, no flags, then the name, type and class.
#[cfg(target_os = "linux")]
pub(crate) fn encode_query(id: u16, qname_wire: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + qname_wire.len() + 4);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(qname_wire);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    out
}

/// Decide what to do with a datagram received from `src_port`.
///
/// In order: a datagram shorter than a header, or one that fills the receive
/// buffer, is dropped; a response is dropped; a datagram from a service port
/// is dropped; one whose counts are not a query's (more than one question,
/// any answer or authority record, more than one additional record) is
/// dropped. ASCII text has no zero byte, so text from any service fails the
/// count test. Then an opcode other than QUERY gets a header-only NOTIMP, a
/// datagram with no question a header-only FORMERR, a malformed question a
/// header-only FORMERR, and a class other than IN or ANY a REFUSED carrying
/// the question. Anything else is a [`Query`]. The Z bit is ignored, and the
/// one additional record a query may carry (normally an EDNS OPT) is neither
/// parsed nor echoed.
pub(crate) fn screen(datagram: &[u8], src_port: u16) -> Screen<'_> {
    if datagram.len() < HEADER_LEN {
        return Screen::Drop(DropReason::Short);
    }
    if datagram.len() >= MAX_DATAGRAM {
        return Screen::Drop(DropReason::FillsBuffer);
    }
    let id = word(datagram, 0);
    let flags = word(datagram, 2);
    if flags & FLAG_QR != 0 {
        return Screen::Drop(DropReason::Response);
    }
    if SERVICE_PORTS.contains(&src_port) {
        return Screen::Drop(DropReason::ServicePort);
    }
    let qdcount = word(datagram, 4);
    if qdcount > 1 || word(datagram, 6) != 0 || word(datagram, 8) != 0 || word(datagram, 10) > 1 {
        return Screen::Drop(DropReason::NotQueryShaped);
    }
    if flags & FLAG_OPCODE != 0 {
        let bytes = header(id, flags, Rcode::NOTIMP, 0, [0, 0, 0]);
        return Screen::Reply(Rcode::NOTIMP, bytes);
    }
    if qdcount == 0 {
        return Screen::Reply(
            Rcode::FORMERR,
            header(id, flags, Rcode::FORMERR, 0, [0, 0, 0]),
        );
    }
    match parse_query(datagram) {
        Ok(query) => Screen::Query(query),
        Err((rcode, bytes)) => Screen::Reply(rcode, bytes),
    }
}

/// Parse the question at offset 12 of a datagram whose header has passed the
/// screen, and check its class.
///
/// The name is read label by label: a compression pointer or an extended
/// label type fails (a pointer in the first question can only point at the
/// header or at itself), as does a name longer than 255 bytes or one that
/// runs past the datagram. A failure gives a header-only FORMERR; a class
/// other than IN or ANY gives a REFUSED carrying the question.
fn parse_query(datagram: &[u8]) -> Result<Query<'_>, (Rcode, Vec<u8>)> {
    let id = word(datagram, 0);
    let flags = word(datagram, 2);
    let formerr = || {
        (
            Rcode::FORMERR,
            header(id, flags, Rcode::FORMERR, 0, [0, 0, 0]),
        )
    };

    let mut pos = HEADER_LEN;
    let mut labels: Vec<&[u8]> = Vec::new();
    loop {
        let len = *datagram.get(pos).ok_or_else(formerr)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // A pointer (0xC0) or an extended label type (0x40, 0x80); this also
        // rejects any label longer than 63 bytes.
        if len & 0xC0 != 0 {
            return Err(formerr());
        }
        let label = datagram.get(pos + 1..pos + 1 + len).ok_or_else(formerr)?;
        labels.push(label);
        pos += 1 + len;
        // Length bytes and labels so far, plus the root still to come.
        if pos - HEADER_LEN + 1 > MAX_NAME {
            return Err(formerr());
        }
    }
    let fixed = datagram.get(pos..pos + 4).ok_or_else(formerr)?;
    let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    let qclass = u16::from_be_bytes([fixed[2], fixed[3]]);

    let name = labels
        .iter()
        .map(|label| String::from_utf8_lossy(label))
        .collect::<Vec<_>>()
        .join(".");
    let query = Query {
        id,
        flags,
        question: &datagram[HEADER_LEN..pos + 4],
        name,
        qtype,
    };
    if qclass != CLASS_IN && qclass != CLASS_ANY {
        return Err((Rcode::REFUSED, reply(&query, Rcode::REFUSED, 0, &[], &[])));
    }
    Ok(query)
}

/// Build a reply to `query`.
///
/// The header carries the query's ID, QR set, opcode QUERY, the query's RD
/// and CD, the AA and RA bits the caller asks for in `flags` (no others), and
/// `rcode`. The query's one question follows byte for byte, then `answers`
/// and `authority`. No additional record is added, so TC is never needed.
///
/// Size: a question is at most 259 bytes, an AAAA record 28 bytes, so a reply
/// with one AAAA answer is the query's header and question plus 28 bytes, at
/// most 299 bytes. An SOA from `soa` with the gateway's names is at most 59
/// bytes, and 51 when the question name ends in the zone, so a reply with one
/// is at most 330 bytes.
/// Both are under 512.
pub(crate) fn reply(
    query: &Query<'_>,
    rcode: Rcode,
    flags: u16,
    answers: &[Record],
    authority: &[Record],
) -> Vec<u8> {
    let counts = [1, answers.len() as u16, authority.len() as u16];
    // A query that reaches here has opcode QUERY (0); the reply says so
    // whatever the flags word holds.
    let mut out = header(query.id, query.flags & !FLAG_OPCODE, rcode, flags, counts);
    out.extend_from_slice(query.question);
    for record in answers.iter().chain(authority) {
        out.extend_from_slice(&(0xC000 | record.owner).to_be_bytes());
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        out.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&record.rdata);
    }
    out
}

/// Write a reply header: `id`, QR set, the opcode, RD and CD from
/// `query_flags`, the AA and RA bits of `flags`, `rcode`, and the question,
/// answer and authority counts. Every other bit, Z and TC included, is clear,
/// and the additional count is zero.
fn header(id: u16, query_flags: u16, rcode: Rcode, flags: u16, counts: [u16; 3]) -> Vec<u8> {
    let flags =
        FLAG_QR | (query_flags & COPIED_FLAGS) | (flags & CALLER_FLAGS) | u16::from(rcode.0);
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    for count in counts {
        out.extend_from_slice(&count.to_be_bytes());
    }
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

/// The big-endian `u16` at `offset`; the caller has checked the length.
fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ordinary source port, as a resolver would send from.
    const PORT: u16 = 53000;

    /// `name` in wire form, with a label per dot-separated part.
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A wire name of labels of the given lengths, every label byte `a`.
    fn labelled(lens: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        for &len in lens {
            out.push(len as u8);
            out.extend(std::iter::repeat_n(b'a', len));
        }
        out.push(0);
        out
    }

    /// A message with this header and `body` after it.
    fn message(id: u16, flags: u16, counts: [u16; 4], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        for count in counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    /// A question section entry for the wire name `name`.
    fn question(name: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&qclass.to_be_bytes());
        out
    }

    /// A one-question message asking for `name`.
    fn datagram(id: u16, flags: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        message(
            id,
            flags,
            [1, 0, 0, 0],
            &question(&wire_name(name), qtype, qclass),
        )
    }

    /// A plain AAAA query for `name`, class IN, no flags.
    fn aaaa_query(name: &str) -> Vec<u8> {
        datagram(0x1234, 0, name, TYPE_AAAA, CLASS_IN)
    }

    /// One OPT record with `pad` bytes of padding.
    fn opt(pad: usize) -> Vec<u8> {
        let mut out = vec![0];
        out.extend_from_slice(&41u16.to_be_bytes());
        out.extend_from_slice(&1232u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&((4 + pad) as u16).to_be_bytes());
        out.extend_from_slice(&12u16.to_be_bytes());
        out.extend_from_slice(&(pad as u16).to_be_bytes());
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    /// The reason of a drop; panics on any other decision.
    fn dropped(screen: Screen<'_>) -> DropReason {
        match screen {
            Screen::Drop(reason) => reason,
            Screen::Reply(rcode, _) => panic!("expected a drop, got a {rcode:?} reply"),
            Screen::Query(q) => panic!("expected a drop, got a query for {:?}", q.name),
        }
    }

    /// The rcode and bytes of an error reply; panics on any other decision.
    fn refused(screen: Screen<'_>) -> (Rcode, Vec<u8>) {
        match screen {
            Screen::Reply(rcode, bytes) => (rcode, bytes),
            Screen::Drop(reason) => panic!("expected an error reply, got a drop ({reason:?})"),
            Screen::Query(q) => panic!("expected an error reply, got a query for {:?}", q.name),
        }
    }

    /// The accepted query; panics on any other decision.
    fn accepted(screen: Screen<'_>) -> Query<'_> {
        match screen {
            Screen::Query(q) => q,
            Screen::Drop(reason) => panic!("expected a query, got a drop ({reason:?})"),
            Screen::Reply(rcode, _) => panic!("expected a query, got a {rcode:?} reply"),
        }
    }

    /// The rcode in a reply's header.
    fn rcode_of(reply: &[u8]) -> Rcode {
        Rcode(reply[3] & 0x0F)
    }

    // --- screen, rule by rule ---

    #[test]
    fn a_datagram_shorter_than_a_header_is_dropped() {
        assert_eq!(dropped(screen(&[0u8; 11], PORT)), DropReason::Short);
        assert_eq!(dropped(screen(&[], PORT)), DropReason::Short);
    }

    #[test]
    fn a_datagram_of_4096_bytes_is_dropped_and_one_of_4095_bytes_is_screened() {
        let mut body = question(&wire_name("a.fips"), TYPE_AAAA, CLASS_IN);
        let base = HEADER_LEN + body.len() + 15;
        body.extend_from_slice(&opt(MAX_DATAGRAM - base));
        let full = message(1, 0, [1, 0, 0, 1], &body);
        assert_eq!(full.len(), MAX_DATAGRAM);
        assert_eq!(dropped(screen(&full, PORT)), DropReason::FillsBuffer);

        let mut body = question(&wire_name("a.fips"), TYPE_AAAA, CLASS_IN);
        body.extend_from_slice(&opt(MAX_DATAGRAM - 1 - base));
        let short = message(1, 0, [1, 0, 0, 1], &body);
        assert_eq!(short.len(), MAX_DATAGRAM - 1);
        assert_eq!(accepted(screen(&short, PORT)).name, "a.fips");
    }

    #[test]
    fn a_response_is_dropped() {
        let response = datagram(1, 0x8000, "a.fips", TYPE_AAAA, CLASS_IN);
        assert_eq!(dropped(screen(&response, PORT)), DropReason::Response);
    }

    #[test]
    fn a_query_from_each_service_port_is_dropped_and_from_port_53000_is_answered() {
        let query = aaaa_query("a.fips");
        for port in [0, 7, 13, 17, 19, 37] {
            assert_eq!(
                dropped(screen(&query, port)),
                DropReason::ServicePort,
                "port {port}"
            );
        }
        assert_eq!(accepted(screen(&query, PORT)).name, "a.fips");
    }

    #[test]
    fn a_datagram_with_an_answer_or_authority_record_or_two_additional_records_is_dropped() {
        let body = question(&wire_name("a.fips"), TYPE_AAAA, CLASS_IN);
        for counts in [[1, 1, 0, 0], [1, 0, 1, 0], [1, 0, 0, 2], [2, 0, 0, 0]] {
            let shaped = message(1, 0, counts, &body);
            assert_eq!(
                dropped(screen(&shaped, PORT)),
                DropReason::NotQueryShaped,
                "counts {counts:?}"
            );
        }
        // ASCII text has no zero byte, so its "ANCOUNT" is never zero.
        let text = b"Thu Oct  9 12:00:00 2026\r\n";
        assert_eq!(dropped(screen(text, PORT)), DropReason::NotQueryShaped);
    }

    #[test]
    fn a_non_query_opcode_gets_a_header_only_notimp_with_the_opcode_and_rd_copied() {
        let query = datagram(0x4321, (4 << 11) | 0x0100, "a.fips", TYPE_AAAA, CLASS_IN);
        let (rcode, reply) = refused(screen(&query, PORT));
        assert_eq!(rcode, Rcode::NOTIMP);
        assert_eq!(rcode_of(&reply), Rcode::NOTIMP);
        assert_eq!(reply.len(), HEADER_LEN);
        assert_eq!(word(&reply, 0), 0x4321);
        assert_eq!(word(&reply, 2), 0x8000 | (4 << 11) | 0x0100 | 4);
        assert_eq!(&reply[4..], &[0; 8]);
    }

    #[test]
    fn a_query_with_no_question_gets_a_header_only_formerr() {
        let (rcode, reply) = refused(screen(&message(7, 0, [0, 0, 0, 0], &[]), PORT));
        assert_eq!(rcode, Rcode::FORMERR);
        assert_eq!(rcode_of(&reply), Rcode::FORMERR);
        assert_eq!(reply.len(), HEADER_LEN);
        assert_eq!(word(&reply, 0), 7);
    }

    #[test]
    fn a_question_name_with_a_compression_pointer_or_an_extended_label_type_gets_formerr() {
        for name in [vec![0xC0, 0x0C], vec![1, b'a', 0xC0, 0x00], vec![0x40, 0]] {
            let query = message(1, 0, [1, 0, 0, 0], &question(&name, TYPE_AAAA, CLASS_IN));
            let (rcode, reply) = refused(screen(&query, PORT));
            assert_eq!(rcode, Rcode::FORMERR, "name {name:02x?}");
            assert_eq!(reply.len(), HEADER_LEN);
        }
    }

    #[test]
    fn a_64_byte_label_gets_formerr_and_a_63_byte_label_parses() {
        let long = message(1, 0, [1, 0, 0, 0], &question(&labelled(&[64]), 28, 1));
        assert_eq!(refused(screen(&long, PORT)).0, Rcode::FORMERR);
        let ok = message(1, 0, [1, 0, 0, 0], &question(&labelled(&[63]), 28, 1));
        assert_eq!(accepted(screen(&ok, PORT)).name, "a".repeat(63));
    }

    #[test]
    fn a_256_byte_name_gets_formerr_and_a_255_byte_name_parses() {
        let long_name = labelled(&[63, 63, 63, 62]);
        assert_eq!(long_name.len(), 256);
        let long = message(1, 0, [1, 0, 0, 0], &question(&long_name, 28, 1));
        assert_eq!(refused(screen(&long, PORT)).0, Rcode::FORMERR);

        let name = labelled(&[63, 63, 63, 61]);
        assert_eq!(name.len(), 255);
        let ok = message(1, 0, [1, 0, 0, 0], &question(&name, 28, 1));
        assert_eq!(accepted(screen(&ok, PORT)).question.len(), 259);
    }

    #[test]
    fn a_question_cut_short_gets_formerr() {
        let whole = aaaa_query("a.fips");
        for cut in HEADER_LEN..whole.len() {
            let (rcode, reply) = refused(screen(&whole[..cut], PORT));
            assert_eq!(rcode, Rcode::FORMERR, "cut at {cut}");
            assert_eq!(reply.len(), HEADER_LEN, "cut at {cut}");
        }
    }

    #[test]
    fn a_ch_class_question_gets_refused_with_the_question_and_class_any_is_accepted() {
        for class in [3, 0x8001, 254] {
            let query = datagram(9, 0, "a.fips", TYPE_AAAA, class);
            let (rcode, reply) = refused(screen(&query, PORT));
            assert_eq!(rcode, Rcode::REFUSED, "class {class:#06x}");
            assert_eq!(rcode_of(&reply), Rcode::REFUSED);
            assert_eq!(word(&reply, 4), 1, "QDCOUNT");
            assert_eq!(&reply[HEADER_LEN..], &query[HEADER_LEN..], "the question");
        }
        let any = datagram(9, 0, "a.fips", TYPE_AAAA, 255);
        assert_eq!(accepted(screen(&any, PORT)).name, "a.fips");
    }

    #[test]
    fn a_z_bit_query_is_screened_as_a_query_and_z_is_not_echoed() {
        let query_bytes = datagram(9, 0x0040, "a.fips", TYPE_AAAA, CLASS_IN);
        let query = accepted(screen(&query_bytes, PORT));
        let out = reply(&query, Rcode::NOERROR, 0, &[], &[]);
        assert_eq!(word(&out, 2) & 0x0040, 0);
    }

    #[test]
    fn an_unknown_qtype_is_returned_raw() {
        for qtype in [44, 65, 0xFF00, 0] {
            let bytes = datagram(9, 0, "a.fips", qtype, CLASS_IN);
            assert_eq!(accepted(screen(&bytes, PORT)).qtype, qtype);
        }
    }

    #[test]
    fn one_opt_additional_record_is_accepted_and_not_echoed() {
        let mut body = question(&wire_name("a.fips"), TYPE_AAAA, CLASS_IN);
        body.extend_from_slice(&opt(400));
        let bytes = message(9, 0, [1, 0, 0, 1], &body);
        let query = accepted(screen(&bytes, PORT));
        let out = reply(
            &query,
            Rcode::NOERROR,
            AA,
            &[aaaa(Ipv6Addr::LOCALHOST, 60)],
            &[],
        );
        assert_eq!(word(&out, 10), 0, "ARCOUNT");
        assert_eq!(out.len(), HEADER_LEN + 12 + 28);
    }

    #[test]
    fn the_text_form_of_a_question_name_matches_simple_dns_display() {
        let mut corpus: Vec<Vec<u8>> = vec![
            wire_name("MiXeD.Case.FIPS"),
            wire_name("host-1.a2b-c.fips"),
            labelled(&[63, 1]),
            vec![5, b'.', b'f', b'i', b'p', b's', 0],
            vec![3, b'a', b'.', b'b', 4, b'f', b'i', b'p', b's', 0],
            vec![2, 0xFF, b'a', 4, b'f', b'i', b'p', b's', 0],
            vec![0],
        ];
        corpus.push(labelled(&[63, 63, 63, 61]));
        for name in corpus {
            let bytes = message(9, 0, [1, 0, 0, 0], &question(&name, TYPE_AAAA, CLASS_IN));
            let ours = accepted(screen(&bytes, PORT)).name;
            let theirs = simple_dns::Packet::parse(&bytes)
                .expect("simple-dns parses the corpus")
                .questions[0]
                .qname
                .to_string();
            assert_eq!(ours, theirs, "name {name:02x?}");
        }
    }

    #[test]
    fn clamp_ttl_keeps_2147483647_and_clamps_2147483648_and_u32_max() {
        assert_eq!(clamp_ttl(0), 0);
        assert_eq!(clamp_ttl(300), 300);
        assert_eq!(clamp_ttl(2_147_483_647), 2_147_483_647);
        assert_eq!(clamp_ttl(2_147_483_648), 2_147_483_647);
        assert_eq!(clamp_ttl(u32::MAX), MAX_TTL);
    }

    #[test]
    fn an_rcode_displays_as_its_mnemonic_or_as_its_number_when_unassigned() {
        assert_eq!(Rcode::NOTIMP.to_string(), "NOTIMP");
        assert_eq!(Rcode(10).to_string(), "NOTZONE");
        assert_eq!(Rcode(13).to_string(), "RCODE13");
    }

    #[test]
    fn drop_reasons_log_as_kebab_case_strings() {
        assert_eq!(DropReason::FillsBuffer.as_str(), "fills-buffer");
        assert_eq!(DropReason::NotQueryShaped.as_str(), "not-query-shaped");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn from_header_maps_the_header_rcode_nibble() {
        assert_eq!(Rcode::from_header(0x82), Rcode::SERVFAIL);
        assert_eq!(Rcode::from_header(0x83), Rcode::NXDOMAIN);
        assert_eq!(Rcode::from_header(0x8F), Rcode(15));
        assert_eq!(Rcode::from_header(0x80), Rcode::NOERROR);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn encode_query_matches_simple_dns_new_query_for_the_same_name() {
        use simple_dns::{CLASS, Name, Packet, QTYPE, Question, TYPE};
        let bytes = aaaa_query("GateWay.FIPS");
        let query = accepted(screen(&bytes, PORT));
        let ours = encode_query(0xBEEF, query.qname_wire(), TYPE_AAAA, CLASS_IN);
        let mut packet = Packet::new_query(0xBEEF);
        packet.questions.push(Question::new(
            Name::new_unchecked("GateWay.FIPS"),
            QTYPE::TYPE(TYPE::AAAA),
            CLASS::IN.into(),
            false,
        ));
        assert_eq!(ours, packet.build_bytes_vec().unwrap());
    }

    /// The SOA the gateway puts in a negative answer.
    #[cfg(target_os = "linux")]
    fn gateway_soa(query: &Query<'_>) -> Record {
        soa(query, "fips", "gateway.fips", "nobody.fips", 1, 60)
    }

    /// The owner, MNAME, RNAME and MINIMUM of the one SOA in `out`, as
    /// `simple-dns` parses them.
    #[cfg(target_os = "linux")]
    fn parsed_soa(out: &[u8]) -> (String, String, String, u32) {
        let packet = simple_dns::Packet::parse(out).expect("simple-dns parses the reply");
        assert_eq!(packet.name_servers.len(), 1);
        let record = &packet.name_servers[0];
        match &record.rdata {
            simple_dns::rdata::RData::SOA(soa) => (
                record.name.to_string(),
                soa.mname.to_string(),
                soa.rname.to_string(),
                soa.minimum,
            ),
            other => panic!("expected SOA, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_soa_for_a_fips_question_is_owned_by_the_fips_label_and_the_reply_is_the_query_length_plus_51()
     {
        let bytes = aaaa_query("a.fips");
        assert_eq!(bytes.len(), 24);
        let query = accepted(screen(&bytes, PORT));
        let out = reply(&query, Rcode::NXDOMAIN, RA, &[], &[gateway_soa(&query)]);
        assert_eq!(out.len(), 75);
        assert_eq!(&out[24..26], &[0xC0, 14], "owner points at the fips label");
        let (owner, mname, rname, minimum) = parsed_soa(&out);
        assert_eq!(owner, "fips");
        assert_eq!(mname, "gateway.fips");
        assert_eq!(rname, "nobody.fips");
        assert_eq!(minimum, 60);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_soa_for_an_upper_case_fips_question_still_points_and_parses() {
        let bytes = aaaa_query("Host.FIPS");
        let query = accepted(screen(&bytes, PORT));
        let out = reply(&query, Rcode::NOERROR, RA, &[], &[gateway_soa(&query)]);
        assert_eq!(out.len(), bytes.len() + 51);
        let (owner, mname, rname, _) = parsed_soa(&out);
        assert_eq!(owner, "FIPS");
        assert_eq!(mname, "gateway.FIPS");
        assert_eq!(rname, "nobody.FIPS");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_soa_for_a_question_not_in_the_zone_is_owned_by_the_question_name_and_is_the_query_length_plus_59()
     {
        for name in [
            wire_name("example.com"),
            vec![5, b'.', b'f', b'i', b'p', b's', 0],
        ] {
            let bytes = message(9, 0, [1, 0, 0, 0], &question(&name, TYPE_AAAA, CLASS_IN));
            let query = accepted(screen(&bytes, PORT));
            let out = reply(&query, Rcode::NXDOMAIN, RA, &[], &[gateway_soa(&query)]);
            assert_eq!(out.len(), bytes.len() + 59, "name {name:02x?}");
            assert_eq!(&out[bytes.len()..bytes.len() + 2], &[0xC0, 0x0C]);
            let (owner, mname, rname, _) = parsed_soa(&out);
            assert_eq!(owner, query.name);
            assert_eq!(mname, "gateway.fips");
            assert_eq!(rname, "nobody.fips");
        }
    }

    // --- replies ---

    #[test]
    fn every_reply_and_every_error_reply_is_dropped_when_fed_back_to_the_screen() {
        let bytes = aaaa_query("a.fips");
        let query = accepted(screen(&bytes, PORT));
        let mut replies = vec![
            reply(
                &query,
                Rcode::NOERROR,
                AA,
                &[aaaa(Ipv6Addr::LOCALHOST, 60)],
                &[],
            ),
            reply(&query, Rcode::NOERROR, AA, &[], &[]),
            reply(&query, Rcode::NXDOMAIN, AA, &[], &[]),
        ];
        for bad in [
            datagram(1, 5 << 11, "a.fips", TYPE_AAAA, CLASS_IN),
            message(1, 0, [0, 0, 0, 0], &[]),
            message(1, 0, [1, 0, 0, 0], &[0xC0, 0x0C, 0, 28, 0, 1]),
            datagram(1, 0, "a.fips", TYPE_AAAA, 3),
        ] {
            replies.push(refused(screen(&bad, PORT)).1);
        }
        for out in replies {
            assert_eq!(
                dropped(screen(&out, PORT)),
                DropReason::Response,
                "{out:02x?}"
            );
        }
    }

    #[test]
    fn every_error_reply_copies_rd_and_cd_and_the_id_and_sets_neither_aa_nor_ra() {
        for bad in [
            datagram(0x5151, 0x0110 | (5 << 11), "a.fips", TYPE_AAAA, CLASS_IN),
            message(0x5151, 0x0110, [0, 0, 0, 0], &[]),
            message(0x5151, 0x0110, [1, 0, 0, 0], &[0xC0, 0x0C, 0, 28, 0, 1]),
            datagram(0x5151, 0x0110, "a.fips", TYPE_AAAA, 3),
        ] {
            let (rcode, out) = refused(screen(&bad, PORT));
            let flags = word(&out, 2);
            assert_eq!(word(&out, 0), 0x5151, "{rcode:?}: ID");
            assert_eq!(flags & 0x0110, 0x0110, "{rcode:?}: RD and CD");
            assert_eq!(flags & 0x0400, 0, "{rcode:?}: AA");
            assert_eq!(flags & 0x0080, 0, "{rcode:?}: RA");
            assert_ne!(flags & 0x8000, 0, "{rcode:?}: QR");
        }
    }

    #[test]
    fn a_reply_echoes_the_question_bytes_exactly_and_copies_rd_and_cd_but_not_z_or_opcode_bits() {
        // 0x20 case randomisation: the question's case must survive.
        let bytes = datagram(0x0102, 0x0150, "gAtEwAy.FiPs", 44, CLASS_IN);
        let query = accepted(screen(&bytes, PORT));
        let out = reply(&query, Rcode::NXDOMAIN, AA | 0x0200 | 0x0040, &[], &[]);
        assert_eq!(&out[HEADER_LEN..], &bytes[HEADER_LEN..]);
        assert_eq!(word(&out, 2), 0x8000 | 0x0400 | 0x0110 | 3);
        assert_eq!(&out[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);

        // A query parsed past the opcode rule still gets opcode QUERY back.
        let opcode = datagram(0x0102, 4 << 11, "a.fips", TYPE_AAAA, CLASS_IN);
        let query = parse_query(&opcode).unwrap_or_else(|_| panic!("parses"));
        let out = reply(&query, Rcode::NOERROR, 0, &[], &[]);
        assert_eq!(word(&out, 2) & FLAG_OPCODE, 0);
    }

    #[test]
    fn a_reply_with_an_aaaa_parses_with_simple_dns_and_is_the_query_length_plus_28() {
        let bytes = aaaa_query("Host.fips");
        let query = accepted(screen(&bytes, PORT));
        let addr: Ipv6Addr = "fd12:3456::1".parse().unwrap();
        let out = reply(&query, Rcode::NOERROR, AA, &[aaaa(addr, 300)], &[]);
        assert_eq!(out.len(), bytes.len() + 28);
        let packet = simple_dns::Packet::parse(&out).expect("simple-dns parses the reply");
        assert_eq!(packet.id(), 0x1234);
        assert_eq!(packet.answers.len(), 1);
        let record = &packet.answers[0];
        assert_eq!(record.name.to_string(), "Host.fips");
        assert_eq!(record.ttl, 300);
        match &record.rdata {
            simple_dns::rdata::RData::AAAA(a) => assert_eq!(Ipv6Addr::from(a.address), addr),
            other => panic!("expected AAAA, got {other:?}"),
        }
    }

    #[test]
    fn a_reply_to_a_two_question_datagram_carries_only_the_first_question() {
        let mut name = Vec::new();
        for len in [63usize, 63, 63, 61] {
            name.push(len as u8);
            name.extend(std::iter::repeat_n(0x01u8, len));
        }
        name.push(0);
        let mut body = question(&name, TYPE_AAAA, CLASS_IN);
        body.extend_from_slice(&[0xC0, 0x0D, 0x00, 0x1C, 0x00, 0x01]);
        let bytes = message(9, 0, [2, 0, 0, 0], &body);
        assert_eq!(bytes.len(), 277);
        let query = parse_query(&bytes).unwrap_or_else(|_| panic!("the first question parses"));
        let out = reply(
            &query,
            Rcode::NXDOMAIN,
            AA,
            &[aaaa(Ipv6Addr::LOCALHOST, 1)],
            &[],
        );
        assert_eq!(word(&out, 4), 1, "QDCOUNT");
        assert!(out.len() <= bytes.len() + 28, "{} bytes", out.len());
        assert_eq!(out.len(), HEADER_LEN + 259 + 28);
    }
}
