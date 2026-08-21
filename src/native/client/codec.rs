//! The native API's line protocol, as a client sees it.
//!
//! Pure: no sockets, no descriptors and no node state, so every rule here is
//! testable without a running daemon. It is the client-side mirror of
//! [`crate::native::protocol`], which does the same job for the daemon: one
//! module that knows the encoding, and a shell that knows only I/O.
//!
//! The encoding is the control socket's, one JSON object per line. A client
//! sends `{"command": "...", "params": {...}}` and reads back one
//! [`Response`](crate::control::protocol::Response). **Replies only, in command
//! order**: nothing unsolicited arrives on this socket, so a line is always the
//! answer to the command just written.
//!
//! An arriving flow is not a line. It is one `SOCK_SEQPACKET` message on the
//! listener's own descriptor, carrying the same fields a `connect` reply
//! carries, which is why [`opened`] reads both.
//!
//! **Errors come back as `io::Error` carrying the errno the contract names**,
//! read from `data.errno`. The daemon's `message` is for an operator reading a
//! log and is deliberately dropped: a client that matched on it would be
//! relying on prose, and `io::Error::from_raw_os_error` is the only
//! constructor that leaves `raw_os_error` readable, which is what a C binding
//! would return from the corresponding call.

use crate::identity::{decode_npub, encode_npub};
use secp256k1::XOnlyPublicKey;
use serde_json::{Value, json};
use std::io;

/// An npub in text form, as an x-only public key.
///
/// The client-side half of `fips_pton`: bech32 in one direction, and nothing
/// else. No daemon, no socket, no lookup. A string that is not an npub is
/// `EINVAL`, which is what `inet_pton`'s caller gets for a malformed address.
pub fn pton(text: &str) -> io::Result<XOnlyPublicKey> {
    decode_npub(text).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// An x-only public key as the npub that names it.
///
/// The client-side half of `fips_ntop`, and the exact inverse of [`pton`].
pub fn ntop(key: &XOnlyPublicKey) -> String {
    encode_npub(key)
}

/// The `connect` command line.
///
/// `local` of 0 is the request for an ephemeral port, which is `bind(2)` with
/// port 0. It is spelled out rather than omitted: the daemon reads an absent
/// field the same way, but one spelling means one rule for `connect` and
/// `listen` both.
pub fn connect(peer: &XOnlyPublicKey, remote: u16, local: u16) -> Vec<u8> {
    request(
        "connect",
        json!({"peer": ntop(peer), "remote_port": remote, "local_port": local}),
    )
}

/// The `listen` command line, where 0 asks the daemon to pick the port.
pub fn listen(local: u16) -> Vec<u8> {
    request("listen", json!({"local_port": local}))
}

/// Encode one command as the newline-terminated line the daemon reads.
fn request(command: &str, params: Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(&json!({"command": command, "params": params}))
        .expect("a JSON object built here always serializes");
    line.push(b'\n');
    line
}

/// The `data` of one reply, or the error the daemon reported.
///
/// A refusal becomes an `io::Error` here rather than at the call site, so every
/// setup path reports the same way and none of them has to know that a refusal
/// is spelled as a successful read of an error line.
pub fn reply(line: &[u8]) -> io::Result<Value> {
    let value: Value = serde_json::from_slice(line).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the daemon sent a line that is not JSON: {error}"),
        )
    })?;

    match value.get("status").and_then(Value::as_str) {
        Some("ok") => Ok(value.get("data").cloned().unwrap_or(Value::Null)),
        // A reply carrying no `errno` is `ECONNREFUSED`, which covers a daemon
        // older than the code that added the field and any refusal raised
        // outside the registry.
        Some("error") => Err(io::Error::from_raw_os_error(code(
            value
                .get("data")
                .and_then(|data| data.get("errno"))
                .and_then(Value::as_str)
                .unwrap_or("ECONNREFUSED"),
        ))),
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the daemon reported an unknown status '{other}'"),
        )),
        None => Err(missing("status")),
    }
}

/// The errno a name from the daemon stands for on this platform.
///
/// The daemon sends names rather than numbers because the number belongs to the
/// platform the client was built for and the daemon is not it. An unknown name
/// is `ECONNREFUSED` for the same reason a missing one is: it is the daemon
/// refusing for a reason this client has no row for.
fn code(name: &str) -> i32 {
    match name {
        "EADDRINUSE" => libc::EADDRINUSE,
        "EADDRNOTAVAIL" => libc::EADDRNOTAVAIL,
        "EMFILE" => libc::EMFILE,
        "EINVAL" => libc::EINVAL,
        "EMSGSIZE" => libc::EMSGSIZE,
        "EPIPE" => libc::EPIPE,
        "ETIMEDOUT" => libc::ETIMEDOUT,
        _ => libc::ECONNREFUSED,
    }
}

/// What the daemon said about a flow it opened.
///
/// One shape for two producers. A `connect` reply and a listener's arrival
/// message carry the same fields, because the daemon re-encodes the peer's key
/// itself in both rather than echoing what a client wrote, so one reader serves
/// both and an accepted flow reports its peer exactly as a connected one does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The far end's public key. The address, not a name for one.
    pub peer: XOnlyPublicKey,
    /// This node's own public key, carried so an accepted flow can answer
    /// `getsockname` without consulting the listener that produced it.
    pub node: XOnlyPublicKey,
    /// The local port the flow holds.
    pub local: u16,
    /// The far end's port.
    pub remote: u16,
    /// The largest datagram this flow carries.
    pub max: usize,
}

/// Read a flow description out of a `connect` reply's data or an arrival
/// message.
///
/// The arrival's `flow_id` and `held` are not read. Neither addresses anything
/// a client can name: the flow is named by its descriptor, and the held
/// datagrams are already on that descriptor by the time the message carrying it
/// can be read.
pub fn opened(data: &Value) -> io::Result<Opened> {
    let max = data
        .get("max_payload")
        .and_then(Value::as_u64)
        .ok_or_else(|| missing("max_payload"))?;

    Ok(Opened {
        peer: key(data, "peer")?,
        node: key(data, "node")?,
        local: port(data, "local_port")?,
        remote: port(data, "remote_port")?,
        max: max as usize,
    })
}

/// Read a flow description out of one arrival message.
///
/// The message is a whole JSON object with **no trailing newline**: it is one
/// `SOCK_SEQPACKET` message, so the boundary is the framing and a newline would
/// offer a client a second framing to rely on.
pub fn arrival(message: &[u8]) -> io::Result<Opened> {
    let value: Value = serde_json::from_slice(message).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the daemon sent an arrival that is not JSON: {error}"),
        )
    })?;
    opened(&value)
}

/// What the daemon said about a port it bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// This node's own public key, which is half of the listener's address.
    pub node: XOnlyPublicKey,
    /// The port actually held, which is what a client that asked for 0 needs.
    pub local: u16,
}

/// Read a listener description out of a `listen` reply's data.
///
/// `backlog` is not read. It reports the depth the daemon holds so an operator
/// can size a client's reader, and nothing on this surface takes a depth.
pub fn bound(data: &Value) -> io::Result<Bound> {
    Ok(Bound {
        node: key(data, "node")?,
        local: port(data, "local_port")?,
    })
}

/// Read one npub field as the key it encodes.
fn key(data: &Value, field: &'static str) -> io::Result<XOnlyPublicKey> {
    let text = data
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| missing(field))?;
    pton(text).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the daemon's '{field}' is not an npub"),
        )
    })
}

/// Read one port field, refusing a number that is not one.
fn port(data: &Value, field: &'static str) -> io::Result<u16> {
    let value = data
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| missing(field))?;
    u16::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the daemon's '{field}' is outside the range a port has"),
        )
    })
}

/// The error for a field this client needs and the daemon did not send.
fn missing(field: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the daemon's line has no usable '{field}'"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An npub the daemon could have written. Nothing here reaches a peer.
    const PEER: &str = "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m";

    /// A second one, standing in for the node's own identity.
    const NODE: &str = "npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl";

    /// The `data` of a connect reply, and of an arrival message but for two
    /// fields this client does not read.
    fn flow() -> Value {
        json!({
            "flow_id": 3, "local_port": 49152, "remote_port": 4242,
            "peer": PEER, "node": NODE, "max_payload": 1362,
        })
    }

    #[test]
    fn an_npub_survives_a_round_trip_through_the_two_pure_conversions() {
        let key = pton(PEER).unwrap();
        assert_eq!(ntop(&key), PEER);
    }

    #[test]
    fn a_string_that_is_not_an_npub_is_refused_as_einval() {
        let error = pton("not-an-npub").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        // An nsec is bech32 and the right length, so only the prefix separates
        // it from an address. Taking it would name a key nobody may address.
        assert!(pton("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5").is_err());
    }

    #[test]
    fn a_connect_command_names_the_peer_by_the_daemons_own_spelling() {
        let key = pton(PEER).unwrap();
        let line = connect(&key, 4242, 0);
        assert_eq!(line.last(), Some(&b'\n'));
        let value: Value = serde_json::from_slice(line.trim_ascii_end()).unwrap();
        assert_eq!(value["command"], "connect");
        assert_eq!(value["params"]["peer"], PEER);
        assert_eq!(value["params"]["remote_port"], 4242);
        // Spelled rather than omitted: 0 is the ephemeral request, and one
        // spelling covers connect and listen both.
        assert_eq!(value["params"]["local_port"], 0);
    }

    #[test]
    fn a_listen_command_carries_the_port_the_caller_asked_for() {
        let value: Value = serde_json::from_slice(listen(4242).trim_ascii_end()).unwrap();
        assert_eq!(value["command"], "listen");
        assert_eq!(value["params"]["local_port"], 4242);
    }

    #[test]
    fn an_ok_reply_yields_its_data() {
        let line = br#"{"status":"ok","data":{"local_port":4242}}"#;
        assert_eq!(reply(line).unwrap()["local_port"], 4242);
    }

    #[test]
    fn a_refusal_becomes_the_errno_the_daemon_named() {
        let line = br#"{"status":"error","message":"port 4242 is already in use","data":{"errno":"EADDRINUSE"}}"#;
        let error = reply(line).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EADDRINUSE));
    }

    #[test]
    fn a_refusal_carrying_no_errno_falls_back_to_econnrefused() {
        // A daemon older than the field, or a refusal raised outside the
        // registry. Guessing a more specific code would tell a caller something
        // the daemon did not say.
        let line = br#"{"status":"error","message":"no such flow: 9"}"#;
        assert_eq!(
            reply(line).unwrap_err().raw_os_error(),
            Some(libc::ECONNREFUSED)
        );
        let unknown = br#"{"status":"error","data":{"errno":"EWHATEVER"}}"#;
        assert_eq!(
            reply(unknown).unwrap_err().raw_os_error(),
            Some(libc::ECONNREFUSED)
        );
    }

    #[test]
    fn every_errno_the_daemon_can_name_maps_to_this_platforms_number() {
        // The contract is the number a C binding would return, so a name this
        // client did not translate would silently become ECONNREFUSED and
        // collapse a row of the error table.
        for (name, want) in [
            ("EADDRINUSE", libc::EADDRINUSE),
            ("EADDRNOTAVAIL", libc::EADDRNOTAVAIL),
            ("EMFILE", libc::EMFILE),
            ("EINVAL", libc::EINVAL),
            ("EMSGSIZE", libc::EMSGSIZE),
            ("EPIPE", libc::EPIPE),
            ("ETIMEDOUT", libc::ETIMEDOUT),
        ] {
            assert_eq!(code(name), want, "{name}");
        }
    }

    #[test]
    fn a_line_that_is_not_json_is_reported_as_such() {
        let error = reply(b"not json at all").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_reply_with_no_status_is_refused_rather_than_guessed_at() {
        let error = reply(br#"{"data":{}}"#).unwrap_err();
        assert!(error.to_string().contains("status"), "{error}");
    }

    #[test]
    fn one_reader_describes_a_connect_reply_and_an_arrival_alike() {
        let want = Opened {
            peer: pton(PEER).unwrap(),
            node: pton(NODE).unwrap(),
            local: 49152,
            remote: 4242,
            max: 1362,
        };
        assert_eq!(opened(&flow()).unwrap(), want);

        // The arrival message is the same object with two fields this client
        // does not read. It must not need a second reader.
        let mut arrival = flow();
        arrival["held"] = json!(2);
        assert_eq!(opened(&arrival).unwrap(), want);
    }

    #[test]
    fn a_flow_whose_peer_is_not_an_npub_is_refused_rather_than_carried() {
        // The peer is the address. A client that accepted a hex node address
        // here would report something that cannot be sent to.
        let mut data = flow();
        data["peer"] = json!("aabbccddeeff00112233445566778899");
        let error = opened(&data).unwrap_err();
        assert!(error.to_string().contains("not an npub"), "{error}");
    }

    #[test]
    fn a_reply_missing_the_payload_limit_names_the_field() {
        let mut data = flow();
        data.as_object_mut().unwrap().remove("max_payload");
        let error = opened(&data).unwrap_err();
        assert!(error.to_string().contains("max_payload"), "{error}");
    }

    #[test]
    fn a_port_above_the_range_a_port_has_is_refused() {
        let mut data = flow();
        data["local_port"] = json!(70000);
        let error = opened(&data).unwrap_err();
        assert!(error.to_string().contains("local_port"), "{error}");
    }

    #[test]
    fn a_listen_reply_reports_the_port_actually_held_and_the_nodes_own_key() {
        let data = json!({"local_port": 49152, "node": NODE, "backlog": 16});
        assert_eq!(
            bound(&data).unwrap(),
            Bound {
                node: pton(NODE).unwrap(),
                local: 49152,
            }
        );
    }
}
