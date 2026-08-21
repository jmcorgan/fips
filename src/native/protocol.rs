//! Native datagram API command types and the pure decisions taken over them.
//!
//! No I/O and no node state. The shell in [`super`] reads a line, calls
//! [`parse`], and acts on the typed command. Every rule that can be decided
//! from the request alone is decided here, so it is testable without a socket
//! and without a running node.
//!
//! The encoding is the control socket's: one JSON object per line, shaped
//! `{"command": "...", "params": {...}}`, answered by a
//! [`Response`](crate::control::protocol::Response). The two sockets are
//! separate listeners with separate lifetimes, but there is no reason for a
//! client to learn two envelopes.

use super::registry::RegistryError;
use crate::control::protocol::Request;
use serde::Deserialize;
use thiserror::Error;

/// Highest port reserved for protocol use, per the FSP port registry.
pub const PORT_PROTOCOL_MAX: u16 = 255;

/// Highest port reserved for FIPS standard services. Port 256 in this range is
/// the IPv6 shim ([`FSP_PORT_IPV6_SHIM`](crate::proto::fsp::FSP_PORT_IPV6_SHIM)).
pub const PORT_STANDARD_MAX: u16 = 1023;

/// Lowest port the daemon hands out when a client names no local port.
///
/// Below this the application range is available for an explicit bind, which is
/// what lets a service hold a port a peer can be told about in advance.
pub const PORT_EPHEMERAL_MIN: u16 = 49152;

/// A parsed native API command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Open a flow to a named peer.
    Connect(Connect),
    /// Receive flows from any peer on a local port.
    Listen(Listen),
    /// **Debug, gated.** Make the daemon write bytes the client chose into one
    /// of that client's flows, so the receive direction is exercisable without
    /// a peer.
    Inject(Inject),
    /// **Debug, gated.** Report what the daemon has received on a flow.
    Stats(u64),
    /// **Debug, gated.** Deliver a datagram as though it had arrived from the
    /// mesh, which reaches any listener this node holds.
    Arrive(Arrive),
}

impl Command {
    /// The name a client used, when the command is one of the debug three.
    ///
    /// The three are not a supported interface: they exist for the test
    /// harness, and a node answers them only where
    /// `node.native_api.debug_commands` is on. Whether that key is on is node
    /// configuration and so is not decidable here; classifying the command is,
    /// which is the half this module owns.
    pub fn debug_name(&self) -> Option<&'static str> {
        match self {
            Command::Inject(_) => Some("inject"),
            Command::Stats(_) => Some("stats"),
            Command::Arrive(_) => Some("arrive"),
            Command::Connect(_) | Command::Listen(_) => None,
        }
    }
}

/// Parameters of a `connect` command, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// The far end, as the npub the client supplied. Decoding it to a key is
    /// the shell's job: this module holds no identity types.
    pub peer: String,
    /// The far end's port.
    pub remote: u16,
    /// The local port, or `None` to let the daemon allocate an ephemeral one.
    pub local: Option<u16>,
}

/// Parameters of a `listen` command, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    /// The local port to receive on, or `None` to let the daemon allocate an
    /// ephemeral one. Port 0 and an absent field mean the same thing, which is
    /// what `bind(2)` with port 0 means and what `connect` already accepted.
    pub local: Option<u16>,
}

/// Parameters of the debug `arrive` command, after validation.
///
/// This drives the node's inbound dispatch without a wire, so the rule that
/// decides between an established flow, a listener and a drop is exercised
/// before FSP is involved. The wire is a second caller of the same rule rather
/// than a new one, which is why the command outlived the work that first
/// needed it; it stays behind `node.native_api.debug_commands` because a caller that
/// reaches it can deliver to any listener on this node under any peer identity
/// it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrive {
    /// The peer it appears to come from, as an npub.
    pub peer: String,
    /// Its source port.
    pub src: u16,
    /// Its destination port on this node.
    pub dst: u16,
    /// The payload, decoded from hex.
    pub data: Vec<u8>,
}

/// Parameters of the debug `inject` command, after validation.
///
/// This command exists so the receive direction is testable without a peer
/// sending anything. It can only write into a flow the same connection opened,
/// so it grants that client nothing it does not already have, but it makes the
/// daemon emit bytes the client chose on a path a reader cannot distinguish
/// from the mesh. It is therefore gated on
/// `node.native_api.debug_commands` and off in a packaged node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inject {
    /// Which flow to write into.
    pub flow: u64,
    /// The bytes to write, decoded from the hex the client sent. Hex rather
    /// than text so a check can assert byte fidelity, including bytes that are
    /// not valid UTF-8.
    pub data: Vec<u8>,
    /// How many separate datagrams to write. Sending one payload several times
    /// is how a check observes that message boundaries survive.
    pub repeat: u32,
}

/// Why a client's command was refused.
///
/// Each variant is a distinct refusal a client can act on, rather than one
/// string it would have to parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CommandError {
    /// The command name is not one this API serves.
    #[error("unknown command '{0}'")]
    Unknown(String),

    /// The command needs a `params` object and none was supplied.
    #[error("command '{0}' requires params")]
    NoParams(&'static str),

    /// The `params` object did not match the command's shape.
    #[error("invalid params for '{command}': {reason}")]
    BadParams {
        /// The command whose params failed to parse.
        command: &'static str,
        /// What serde objected to.
        reason: String,
    },

    /// The port is in the range the protocol itself reserves.
    #[error("port {0} is reserved for protocol use")]
    PortProtocol(u16),

    /// The port is in the range reserved for FIPS standard services, which is
    /// where the IPv6 shim lives.
    #[error("port {0} is reserved for FIPS standard services")]
    PortStandard(u16),

    /// A hex field did not decode.
    #[error("invalid hex in '{field}': {reason}")]
    BadHex {
        /// The field that failed to decode.
        field: &'static str,
        /// What the decoder objected to.
        reason: String,
    },

    /// A repeat count outside what the command will do in one call.
    #[error("repeat must be between 1 and {max}, got {got}")]
    BadRepeat {
        /// The largest accepted value.
        max: u32,
        /// What the client asked for.
        got: u32,
    },
}

/// Largest number of datagrams one `inject` writes.
///
/// Bounded because the command runs inline on the connection task: a client
/// asking for a million would hold that task for the duration.
pub const MAX_INJECT_REPEAT: u32 = 64;

/// Raw `connect` parameters, before validation.
#[derive(Debug, Deserialize)]
struct ConnectParams {
    peer: String,
    remote_port: u16,
    #[serde(default)]
    local_port: Option<u16>,
}

/// Raw `listen` parameters, before validation.
#[derive(Debug, Deserialize)]
struct ListenParams {
    #[serde(default)]
    local_port: Option<u16>,
}

/// Raw `stats` parameters, before validation.
#[derive(Debug, Deserialize)]
struct FlowParams {
    flow_id: u64,
}

/// Raw `arrive` parameters, before validation.
#[derive(Debug, Deserialize)]
struct ArriveParams {
    peer: String,
    src_port: u16,
    dst_port: u16,
    data: String,
}

/// Raw `inject` parameters, before validation.
#[derive(Debug, Deserialize)]
struct InjectParams {
    flow_id: u64,
    data: String,
    #[serde(default = "InjectParams::one")]
    repeat: u32,
}

impl InjectParams {
    /// One datagram, when the client names no repeat count.
    fn one() -> u32 {
        1
    }
}

/// Turn a request into a typed command, refusing anything a client may not ask
/// for.
///
/// Port policy is applied here rather than at the registry, so a refusal costs
/// no node state and reads the same whether or not a node is running.
pub fn parse(request: &Request) -> Result<Command, CommandError> {
    match request.command.as_str() {
        "connect" => {
            let params: ConnectParams = take(request, "connect")?;
            check_bindable(params.remote_port)?;
            let local = match params.local_port {
                // Port 0 is the UDP convention for "any port", and a client
                // that reaches for it means the same thing as omitting the
                // field. Accepting both spellings costs one branch and saves a
                // refusal a client would find surprising.
                None | Some(0) => None,
                Some(port) => {
                    check_bindable(port)?;
                    Some(port)
                }
            };
            Ok(Command::Connect(Connect {
                peer: params.peer,
                remote: params.remote_port,
                local,
            }))
        }
        "listen" => {
            let params: ListenParams = take(request, "listen")?;
            // The same rule `connect` applies to its local port, so one
            // spelling of "any port" covers both commands.
            let local = match params.local_port {
                None | Some(0) => None,
                Some(port) => {
                    check_bindable(port)?;
                    Some(port)
                }
            };
            Ok(Command::Listen(Listen { local }))
        }
        "stats" => Ok(Command::Stats(
            take::<FlowParams>(request, "stats")?.flow_id,
        )),
        "arrive" => {
            let params: ArriveParams = take(request, "arrive")?;
            let data = hex::decode(&params.data).map_err(|error| CommandError::BadHex {
                field: "data",
                reason: error.to_string(),
            })?;
            Ok(Command::Arrive(Arrive {
                peer: params.peer,
                src: params.src_port,
                dst: params.dst_port,
                data,
            }))
        }
        "inject" => {
            let params: InjectParams = take(request, "inject")?;
            if params.repeat == 0 || params.repeat > MAX_INJECT_REPEAT {
                return Err(CommandError::BadRepeat {
                    max: MAX_INJECT_REPEAT,
                    got: params.repeat,
                });
            }
            let data = hex::decode(&params.data).map_err(|error| CommandError::BadHex {
                field: "data",
                reason: error.to_string(),
            })?;
            Ok(Command::Inject(Inject {
                flow: params.flow_id,
                data,
                repeat: params.repeat,
            }))
        }
        other => Err(CommandError::Unknown(other.to_string())),
    }
}

/// Deserialize a command's `params` object, naming the command in any error.
fn take<T: for<'de> Deserialize<'de>>(
    request: &Request,
    command: &'static str,
) -> Result<T, CommandError> {
    let params = request
        .params
        .as_ref()
        .ok_or(CommandError::NoParams(command))?;
    serde_json::from_value(params.clone()).map_err(|error| CommandError::BadParams {
        command,
        reason: error.to_string(),
    })
}

/// Decide whether a client may name `port`.
///
/// The tiers come from the FSP port registry, which describes what already
/// ships on the v1 wire: 0-255 is protocol use, and 256-1023 is reserved for
/// FIPS standard services, of which 256 is the IPv6 shim. Only the application
/// range above them is a client's to use.
pub fn check_bindable(port: u16) -> Result<(), CommandError> {
    if port <= PORT_PROTOCOL_MAX {
        return Err(CommandError::PortProtocol(port));
    }
    if port <= PORT_STANDARD_MAX {
        return Err(CommandError::PortStandard(port));
    }
    Ok(())
}

/// The `errno` name a refused setup command reports to its client.
///
/// A client must never match on the message: that is for an operator reading a
/// log, and the codes are the contract. The match is exhaustive over
/// [`RegistryError`] and over the [`CommandError`] its `Port` variant wraps, so
/// a variant added without a code is a compile error rather than a silent
/// `ECONNREFUSED`.
///
/// The names rather than the numbers, because the number belongs to the
/// platform the client is built for and this crate is not it. The client turns
/// the name into `io::Error::from_raw_os_error(libc::EADDRINUSE)` and so on.
pub fn errno(error: &RegistryError) -> &'static str {
    match error {
        // One port, one owner, and one key, one flow. Both are the address a
        // caller asked for and cannot have.
        RegistryError::PortTaken(_) | RegistryError::FlowTaken { .. } => "EADDRINUSE",
        RegistryError::NoPort => "EADDRNOTAVAIL",
        RegistryError::TooManyFlows(_) => "EMFILE",
        // Neither reaches a setup reply today: a full backlog is decided on the
        // receive path and counted rather than answered, and a missing pending
        // flow is a hand-off the daemon lost to its own deadline. If either ever
        // does reach a client, it is the daemon refusing for a reason of its
        // own, which is what the catch-all names.
        RegistryError::BacklogFull(_) | RegistryError::NoPending(_) => "ECONNREFUSED",
        RegistryError::Port(command) => command_errno(command),
    }
}

/// The `errno` name for a command this API refused before any node state was
/// touched.
///
/// A reserved port is `EADDRNOTAVAIL` rather than `EACCES`: `bind(2)` gives
/// `EACCES` below 1024 because that is a privilege question, and this is not
/// one. No client, however privileged, may hold port 256, because the IPv6 shim
/// has it. Everything else here is a malformed command, which is `EINVAL`.
pub fn command_errno(error: &CommandError) -> &'static str {
    match error {
        CommandError::PortProtocol(_) | CommandError::PortStandard(_) => "EADDRNOTAVAIL",
        CommandError::Unknown(_)
        | CommandError::NoParams(_)
        | CommandError::BadParams { .. }
        | CommandError::BadHex { .. }
        | CommandError::BadRepeat { .. } => "EINVAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a request the way the line reader would, from JSON text.
    fn request(text: &str) -> Request {
        serde_json::from_str(text).expect("test request should parse")
    }

    #[test]
    fn connect_carries_the_peer_and_both_ports() {
        let parsed = parse(&request(
            r#"{"command":"connect","params":{"peer":"npub1abc","remote_port":4242,"local_port":5000}}"#,
        ))
        .unwrap();
        assert_eq!(
            parsed,
            Command::Connect(Connect {
                peer: "npub1abc".to_string(),
                remote: 4242,
                local: Some(5000),
            })
        );
    }

    #[test]
    fn an_absent_local_port_asks_for_an_ephemeral_one() {
        let parsed = parse(&request(
            r#"{"command":"connect","params":{"peer":"npub1abc","remote_port":4242}}"#,
        ))
        .unwrap();
        let Command::Connect(connect) = parsed else {
            panic!("expected a connect");
        };
        assert_eq!(connect.local, None);
    }

    #[test]
    fn a_zero_local_port_means_the_same_as_an_absent_one() {
        let parsed = parse(&request(
            r#"{"command":"connect","params":{"peer":"npub1abc","remote_port":4242,"local_port":0}}"#,
        ))
        .unwrap();
        let Command::Connect(connect) = parsed else {
            panic!("expected a connect");
        };
        assert_eq!(connect.local, None);
    }

    #[test]
    fn the_protocol_port_range_is_refused() {
        let error = parse(&request(
            r#"{"command":"listen","params":{"local_port":200}}"#,
        ))
        .unwrap_err();
        assert_eq!(error, CommandError::PortProtocol(200));
    }

    #[test]
    fn the_standard_service_port_range_is_refused() {
        // 256 is the IPv6 shim; refusing the whole tier keeps a client from
        // binding it or anything reserved beside it.
        let error = parse(&request(
            r#"{"command":"listen","params":{"local_port":256}}"#,
        ))
        .unwrap_err();
        assert_eq!(error, CommandError::PortStandard(256));
        assert_eq!(check_bindable(1023), Err(CommandError::PortStandard(1023)));
        assert!(check_bindable(1024).is_ok());
    }

    #[test]
    fn a_remote_port_in_a_reserved_tier_is_refused_too() {
        // The far end's shim is no more addressable than our own: a client that
        // could name port 256 remotely would be injecting into the peer's IPv6
        // plane.
        let error = parse(&request(
            r#"{"command":"connect","params":{"peer":"npub1abc","remote_port":256}}"#,
        ))
        .unwrap_err();
        assert_eq!(error, CommandError::PortStandard(256));
    }

    #[test]
    fn every_refusal_carries_the_errno_its_contract_names() {
        // The rows of the table the client turns into `io::Error`. A client
        // must be able to tell "that port is taken" from "that port is not
        // yours to take" without matching English prose, which is the whole
        // reason the code is on the wire.
        assert_eq!(errno(&RegistryError::PortTaken(4242)), "EADDRINUSE");
        assert_eq!(
            errno(&RegistryError::FlowTaken {
                local: 4242,
                remote: 5000
            }),
            "EADDRINUSE"
        );
        assert_eq!(errno(&RegistryError::NoPort), "EADDRNOTAVAIL");
        assert_eq!(errno(&RegistryError::TooManyFlows(256)), "EMFILE");
        assert_eq!(
            errno(&RegistryError::Port(CommandError::PortStandard(256))),
            "EADDRNOTAVAIL"
        );
        assert_eq!(
            errno(&RegistryError::Port(CommandError::PortProtocol(200))),
            "EADDRNOTAVAIL"
        );

        // And the refusals that never reach the registry.
        assert_eq!(
            command_errno(&CommandError::Unknown("teleport".to_string())),
            "EINVAL"
        );
        assert_eq!(command_errno(&CommandError::NoParams("stats")), "EINVAL");
    }

    #[test]
    fn an_unknown_command_names_itself_in_the_refusal() {
        let error = parse(&request(r#"{"command":"teleport"}"#)).unwrap_err();
        assert_eq!(error, CommandError::Unknown("teleport".to_string()));
    }

    #[test]
    fn a_command_that_needs_params_refuses_without_them() {
        let error = parse(&request(r#"{"command":"stats"}"#)).unwrap_err();
        assert_eq!(error, CommandError::NoParams("stats"));
    }

    #[test]
    fn params_of_the_wrong_shape_name_the_command() {
        let request = Request {
            command: "listen".to_string(),
            params: Some(json!({"local_port": "not a number"})),
        };
        let error = parse(&request).unwrap_err();
        let CommandError::BadParams { command, .. } = error else {
            panic!("expected a params error");
        };
        assert_eq!(command, "listen");
    }

    #[test]
    fn accept_and_reject_are_not_commands_this_api_serves() {
        // They went with the round trip they existed for: a flow is taken by
        // reading the listener's descriptor and refused by closing the one that
        // arrives with it. A client still sending either must be told so.
        for command in ["accept", "reject"] {
            let error = parse(&request(&format!(
                r#"{{"command":"{command}","params":{{"flow_id":7}}}}"#
            )))
            .unwrap_err();
            assert_eq!(error, CommandError::Unknown(command.to_string()));
        }
    }

    #[test]
    fn a_listen_may_name_no_port_and_gets_an_ephemeral_one() {
        for line in [
            r#"{"command":"listen","params":{"local_port":0}}"#,
            r#"{"command":"listen","params":{}}"#,
        ] {
            assert_eq!(
                parse(&request(line)).unwrap(),
                Command::Listen(Listen { local: None }),
                "{line} should ask for an ephemeral port"
            );
        }
        assert_eq!(
            parse(&request(
                r#"{"command":"listen","params":{"local_port":4242}}"#
            ))
            .unwrap(),
            Command::Listen(Listen { local: Some(4242) })
        );
    }
}
