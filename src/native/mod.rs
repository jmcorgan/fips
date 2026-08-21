//! Native datagram API socket (experimental).
//!
//! A client connects to this socket, sends line-delimited JSON commands, and
//! receives line-delimited JSON replies. Both replies that succeed carry a file
//! descriptor in their ancillary data: a flow's descriptor for `connect`, a
//! listener's for `listen`. The client reads and writes datagrams on a flow's
//! descriptor with no framing of any kind, and reads one message per arriving
//! flow on a listener's.
//!
//! The API addresses a peer by public key and a service by FSP port, so a
//! datagram travels from key to key with no IPv6 emulation and no TUN device.
//! Three representations of a peer exist and only two of them are a client's:
//! the x-only public key is the address, the npub is that key written down, and
//! the 16-byte node address is a truncated hash that travels on the wire and
//! appears in no field this API hands a client.
//!
//! **The RPC connection owns nothing.** It carries setup calls and their
//! replies and then has no further part in anything it opened. A flow lives
//! until its own descriptor reaches end of file and a listener until its own
//! does, whichever task holds them, which is what makes a descriptor this API
//! hands back behave like one a syscall would have.
//!
//! **The wire is connected.** A datagram a client writes leaves this node over
//! FSP, and one arriving on a held port reaches its flow. `max_payload` is the
//! real limit: the transport MTU less the FIPS encapsulation and the four-byte
//! port header.
//!
//! **Platform support.** The listener is built on Linux, FreeBSD and macOS.
//! Windows is excluded and cannot be included: it has no `SCM_RIGHTS`, so there
//! is no way to hand a descriptor to another process at all, which is the whole
//! mechanism. macOS needed only the descriptor's socket type, since it has
//! `SCM_RIGHTS` but does not implement `SOCK_SEQPACKET` for `AF_UNIX`; see
//! [`seqpacket`] for the type it uses instead and for the measured difference
//! in how the two report a close. The gate is an explicit platform list rather
//! than `cfg(unix)` so a platform nobody has measured fails to build here
//! instead of failing at `socketpair` on a running node.
//!
//! - `protocol.rs` — the command types and the pure decisions over them. No
//!   I/O, no node state.
//! - `registry.rs` — which local ports are held and where an inbound datagram
//!   goes. Lives inside `Node`; decisions only.
//! - `link.rs` — what a client task asks the node's registry to do.
//! - `seqpacket.rs` — the socket pair behind a flow and behind a listener, the
//!   daemon half under the reactor.
//! - `fdpass.rs` — replies, arrival messages, and the `SCM_RIGHTS` hand-off of
//!   a descriptor, in both directions.
//! - `client/` — a blocking, std-only client an external program links this
//!   crate for, so it speaks the API without knowing the line protocol.

// The registry, its request types and the command types are plain decisions
// over maps and carry no socket. They build everywhere, which is what lets the
// `rx_loop` arm that serves them avoid a `cfg` — `tokio::select!` does not
// accept one. Only the listener and the descriptor machinery are gated.
pub mod link;
pub mod protocol;
pub mod registry;

// Tests only, and compiled on every unix rather than only where the listener
// is, because its whole purpose is to compare one kernel's answer with
// another's. See the module header.
#[cfg(all(test, unix))]
mod dgram_probe;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub mod client;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub mod fdpass;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub mod seqpacket;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub use unix_impl::NativeApi;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod unix_impl {
    use super::fdpass;
    use super::link::{Accepted, DropReason, NativeMessage, Outbound, Outcome};
    use super::protocol::{self, Command, Connect, Inject, Listen};
    use super::registry::{Arrival, Datagram, FlowKey, Limits, RegistryError};
    use super::seqpacket::{Received, Seqpacket, pair, set_rcvbuf, set_sndbuf};
    use crate::config::NativeApiConfig;
    use crate::control::protocol::{Request, Response};
    use crate::identity::{NodeAddr, decode_npub, encode_npub};
    use secp256k1::XOnlyPublicKey;
    use std::collections::HashMap;
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::BufReader;
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::{mpsc, oneshot};
    use tracing::{debug, info, warn};

    /// Largest command line a client may send, in bytes.
    ///
    /// A command carries an npub, two ports and nothing else, so this is
    /// generous by two orders of magnitude. It exists to bound a client that
    /// never sends a newline, not to constrain a real command.
    pub(super) const MAX_COMMAND: usize = 8192;

    /// Receive buffer for a flow, in bytes.
    ///
    /// A datagram longer than this is truncated by the kernel, which is
    /// `SOCK_SEQPACKET` behaviour. Sized well above anything the wire will
    /// carry, because the real limit arrives with the wire and this buffer
    /// should not be the thing that imposes one first.
    const MAX_DATAGRAM: usize = 65535;

    /// Send-buffer bytes allowed per unread arrival on a listener's pair.
    ///
    /// `SO_SNDBUF` on an `AF_UNIX` socket accounts bytes plus per-message
    /// overhead rather than messages, so this is a byte ceiling standing in for
    /// a message count. It is set generously on purpose: the approximation must
    /// err toward accepting an arrival a client would have read rather than
    /// toward dropping it. An arrival message is a few hundred bytes, so this
    /// leaves an order of magnitude of slack, and the number that would settle
    /// it is the real per-message accounting measured on the target kernel.
    ///
    /// **The slack is what a wedged listener holds.** At a `backlog` of 16 this
    /// asks for 64 KB, which Linux doubles, and `AF_UNIX` charges each message
    /// its `skb->truesize` rather than its length, so the buffer takes arrivals
    /// by the hundred rather than by the `backlog`. A client that binds a
    /// listener and then stops reading therefore holds flows on the order of
    /// `node.native_api.max_flows`, not on the order of `backlog`. Sizing this
    /// down would trade that for dropping arrivals a client would have read,
    /// which is the worse failure, so the node-wide ceiling is what bounds it.
    const ARRIVAL_ALLOWANCE: usize = 4096;

    /// The native API listener.
    ///
    /// Binding is separate from serving so the caller can bind synchronously
    /// during startup and see the failure there, in a deterministic order,
    /// rather than at whatever later moment a spawned bind happened to run.
    pub struct NativeApi {
        listener: UnixListener,
        socket_path: PathBuf,
        limits: Limits,
        /// Every flow this node holds a daemon-side half for.
        flows: Arc<Flows>,
        /// Whether this node answers the debug commands at all.
        debug: bool,
    }

    impl NativeApi {
        /// Bind the native API socket under the shared FIPS access policy.
        ///
        /// The socket is mode `0o770` and group `fips`, which is the whole of
        /// the authorization model: any process that can open it can send as
        /// this node's identity. That is why the feature is off by default.
        pub fn bind(config: &NativeApiConfig) -> Result<Self, std::io::Error> {
            let socket_path = PathBuf::from(&config.socket_path);
            let listener = crate::utils::sockbind::bind(&socket_path, "native API")?;

            info!(path = %socket_path.display(), "Native API socket listening");

            Ok(Self {
                listener,
                socket_path,
                limits: Limits {
                    per_flow: config.pending_per_flow,
                    backlog: config.backlog,
                    max_flows: config.max_flows,
                },
                flows: Arc::new(Flows::new()),
                debug: config.debug_commands,
            })
        }

        /// Accept connections until the task is cancelled.
        ///
        /// Each connection is served by its own task and ends with its last
        /// command. `npub` is this node's own address, reported in every setup
        /// reply so a client can answer `getsockname` without asking again.
        pub async fn accept_loop(
            self,
            node: mpsc::Sender<NativeMessage>,
            outbound: mpsc::Sender<Outbound>,
            npub: String,
        ) {
            let npub: Arc<str> = Arc::from(npub);
            loop {
                let (stream, _addr) = match self.listener.accept().await {
                    Ok(conn) => conn,
                    Err(error) => {
                        warn!(error = %error, "Native API accept failed");
                        continue;
                    }
                };

                let node = node.clone();
                let outbound = outbound.clone();
                let flows = Arc::clone(&self.flows);
                let limits = self.limits;
                let npub = Arc::clone(&npub);
                let debug = self.debug;
                tokio::spawn(async move {
                    if let Err(error) =
                        serve(stream, node, outbound, flows, limits, npub, debug).await
                    {
                        debug!(error = %error, "Native API connection ended");
                    }
                });
            }
        }

        /// The path this socket is bound to.
        pub fn socket_path(&self) -> &PathBuf {
            &self.socket_path
        }
    }

    impl Drop for NativeApi {
        fn drop(&mut self) {
            crate::utils::sockbind::cleanup(&self.socket_path, "native API");
        }
    }

    /// What a flow's reader task has observed, published for `stats`.
    #[derive(Debug, Default)]
    struct Counts {
        datagrams: AtomicU64,
        bytes: AtomicU64,
        closed: AtomicBool,
    }

    /// One flow the node holds the daemon-side half of.
    struct Flow {
        /// The local port, reported by `stats`.
        local: u16,
        /// The daemon's half of the client's socket pair, which `inject`
        /// writes into.
        sock: Arc<Seqpacket>,
        counts: Arc<Counts>,
    }

    /// What `stats` reports about one flow.
    struct FlowStats {
        local: u16,
        datagrams: u64,
        bytes: u64,
        closed: bool,
    }

    /// Every flow the node holds a daemon-side half for.
    ///
    /// Node-scoped rather than connection-scoped, because a flow outlives the
    /// RPC connection that opened it and a flow a listener accepted was never
    /// opened on an RPC connection at all. A plain mutex is enough: every
    /// operation is one map lookup, taken from a client or listener task and
    /// never from the `rx_loop`.
    struct Flows {
        held: Mutex<HashMap<u64, Flow>>,
    }

    impl Flows {
        /// An empty table.
        fn new() -> Self {
            Self {
                held: Mutex::new(HashMap::new()),
            }
        }

        /// The table, recovering rather than propagating a poisoned lock.
        ///
        /// A client task that panicked mid-lookup left the map intact, and
        /// refusing every later flow because of it would turn one client's bug
        /// into the node's.
        fn table(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Flow>> {
            self.held
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        /// Record a flow the node now holds.
        fn record(&self, id: u64, flow: Flow) {
            self.table().insert(id, flow);
        }

        /// Forget a flow whose descriptor has closed.
        fn forget(&self, id: u64) {
            self.table().remove(&id);
        }

        /// What the debug `stats` command reports, or `None` for a flow this
        /// node does not hold.
        fn stats(&self, id: u64) -> Option<FlowStats> {
            let table = self.table();
            let flow = table.get(&id)?;
            Some(FlowStats {
                local: flow.local,
                datagrams: flow.counts.datagrams.load(Ordering::Relaxed),
                bytes: flow.counts.bytes.load(Ordering::Relaxed),
                closed: flow.counts.closed.load(Ordering::Relaxed),
            })
        }

        /// The daemon's half of a flow, cloned out so the caller can write to
        /// it without holding the lock across an await.
        fn sock(&self, id: u64) -> Option<Arc<Seqpacket>> {
            self.table().get(&id).map(|flow| Arc::clone(&flow.sock))
        }
    }

    /// A flow's socket pair and inbound queue, before its key is known.
    struct Wiring {
        sock: Arc<Seqpacket>,
        inbound: mpsc::Receiver<Datagram>,
    }

    /// State for one client connection.
    ///
    /// It holds no flow and no listener: both outlive it, and the connection is
    /// a setup channel with nothing to give back when it ends.
    pub(super) struct Connection {
        /// Where registry requests go.
        node: mpsc::Sender<NativeMessage>,
        /// Where datagrams a client wrote go.
        outbound: mpsc::Sender<Outbound>,
        /// The node's flow table, shared with every listener task.
        flows: Arc<Flows>,
        limits: Limits,
        /// This node's own npub, reported in every setup reply.
        npub: Arc<str>,
        /// Whether the debug commands are answered, from
        /// `node.native_api.debug_commands`. Held per connection because it is
        /// fixed for the node's lifetime and reading it here costs no lookup.
        debug: bool,
    }

    /// The node is gone, so nothing further can be registered.
    fn shutting_down() -> Response {
        deny("ECONNREFUSED", "node is shutting down".to_string())
    }

    /// Render a registry refusal for the client.
    fn refused(error: RegistryError) -> Response {
        deny(protocol::errno(&error), error.to_string())
    }

    /// An error reply carrying the code a C binding would return from the
    /// corresponding call.
    ///
    /// The code rides in `data` because [`Response`] has no field for one and
    /// the control socket shares the type. A client reads `data.errno` and never
    /// the message: the message is prose for an operator, and a reply carrying
    /// no code at all is `ECONNREFUSED`, which is what a daemon older than this
    /// contract sends.
    ///
    /// **Every refusal this API makes goes through here**, the debug commands
    /// included. They have no Berkeley call to take a code from, so they use the
    /// nearest one for the argument that was wrong; the alternative is a bare
    /// message, which reaches the client as `ECONNREFUSED` and says the node
    /// declined rather than that the flow does not exist.
    fn deny(errno: &'static str, message: String) -> Response {
        Response {
            status: "error".to_string(),
            data: Some(serde_json::json!({ "errno": errno })),
            message: Some(message),
        }
    }

    impl Connection {
        /// A connection holding nothing.
        fn new(
            node: mpsc::Sender<NativeMessage>,
            outbound: mpsc::Sender<Outbound>,
            flows: Arc<Flows>,
            limits: Limits,
            npub: Arc<str>,
            debug: bool,
        ) -> Self {
            Self {
                node,
                outbound,
                flows,
                limits,
                npub,
                debug,
            }
        }

        /// Send one request to the node and wait for its answer.
        async fn ask<T>(
            &self,
            build: impl FnOnce(oneshot::Sender<T>) -> NativeMessage,
        ) -> Option<T> {
            let (tx, rx) = oneshot::channel();
            self.node.send(build(tx)).await.ok()?;
            rx.await.ok()
        }

        /// Build the descriptor pair and the inbound queue for one flow.
        ///
        /// Returns the client's half plus everything the node keeps. The socket
        /// pair is created before the flow is registered, so a failure here
        /// leaves the registry untouched and needs no rollback.
        fn wire(&self) -> std::io::Result<(Wiring, OwnedFd, mpsc::Sender<Datagram>)> {
            wire_flow(self.limits.per_flow)
        }

        /// Decide the reply to one command, and any descriptor that goes with it.
        ///
        /// Every path returns a `Response` rather than an error, because a bad
        /// command from one client is not a reason to drop its connection or to
        /// disturb any other.
        pub(super) async fn answer(&mut self, line: &[u8]) -> (Response, Option<OwnedFd>) {
            let request: Request = match serde_json::from_slice(line) {
                Ok(request) => request,
                Err(error) => {
                    return (deny("EINVAL", format!("invalid request: {error}")), None);
                }
            };

            let command = match protocol::parse(&request) {
                Ok(command) => command,
                Err(error) => {
                    return (
                        deny(protocol::command_errno(&error), error.to_string()),
                        None,
                    );
                }
            };

            // Refused by name rather than reported as unknown: a client driving
            // the harness needs to tell "this node will not do that" from "this
            // build has no such command", and hiding the difference would send
            // whoever hits it looking for a typo.
            if let Some(name) = command.debug_name()
                && !self.debug
            {
                return (
                    deny(
                        "ECONNREFUSED",
                        format!(
                            "'{name}' is a debug command and is disabled; \
                             set node.native_api.debug_commands to enable it"
                        ),
                    ),
                    None,
                );
            }

            match command {
                Command::Connect(connect) => self.connect(connect).await,
                Command::Listen(listen) => self.listen(listen).await,
                Command::Stats(flow) => (self.stats(flow), None),
                Command::Inject(inject) => (self.inject(inject).await, None),
                Command::Arrive(arrive) => (self.arrive(arrive).await, None),
            }
        }

        /// Open a flow to a named peer.
        async fn connect(&mut self, connect: Connect) -> (Response, Option<OwnedFd>) {
            let peer = match decode_npub(&connect.peer) {
                Ok(key) => key,
                Err(error) => {
                    // The address did not parse. The client library refuses this
                    // before it sends, so reaching it means a caller wrote the
                    // line itself.
                    return (deny("EINVAL", format!("invalid peer: {error}")), None);
                }
            };

            // The pair exists before the port is claimed, so a failure to build
            // it cannot leave a port held by a flow that does not exist.
            let (wiring, fd, sink) = match self.wire() {
                Ok(parts) => parts,
                Err(error) => {
                    // No descriptor to give, which is what `EMFILE` says about a
                    // socket call whatever the underlying cause was.
                    return (
                        deny("EMFILE", format!("could not open a flow: {error}")),
                        None,
                    );
                }
            };

            let answer = self
                .ask(|reply| NativeMessage::Connect {
                    peer,
                    remote: connect.remote,
                    local: connect.local,
                    sink,
                    reply,
                })
                .await;

            let opened = match answer {
                Some(Ok(opened)) => opened,
                Some(Err(error)) => return (refused(error), None),
                None => return (shutting_down(), None),
            };

            let key = FlowKey {
                peer: NodeAddr::from_pubkey(&peer),
                remote: connect.remote,
                local: opened.local,
            };
            start(
                opened.flow,
                key,
                peer,
                wiring,
                &self.outbound,
                &self.node,
                &self.flows,
            );

            (
                Response::ok(serde_json::json!({
                    "flow_id": opened.flow,
                    "local_port": opened.local,
                    "remote_port": connect.remote,
                    // The daemon's own re-encode of the key it decoded, not an
                    // echo of the client's string, so connect and an arrival
                    // name one peer the same way and one reader serves both.
                    "peer": encode_npub(&peer),
                    "node": self.npub.as_ref(),
                    "max_payload": opened.max,
                })),
                Some(fd),
            )
        }

        /// Hold a local port and receive the flows that arrive on it.
        ///
        /// The reply carries the listener's own descriptor, which is what makes
        /// a listener pollable and makes accepting a `recvmsg` rather than a
        /// round trip on this connection.
        async fn listen(&mut self, listen: Listen) -> (Response, Option<OwnedFd>) {
            // The reply reports what the registry enforces, which is the raw
            // configured depth: a reply claiming one while the registry refused
            // every arrival is worse than a refusal at startup. The channel
            // capacity is that number floored at one, because `mpsc::channel(0)`
            // panics and a `Limits` built outside the config loader, as a test's
            // is, is not bound by the loader's floor.
            let backlog = self.limits.backlog;
            let queue = backlog.max(1);
            let (ours, theirs) = match pair() {
                Ok(pair) => pair,
                Err(error) => {
                    return (
                        deny("EMFILE", format!("could not open a listener: {error}")),
                        None,
                    );
                }
            };

            // The buffer is the only bound on arrivals a client has stopped
            // reading, so a failure to size it is worth a warning rather than a
            // refusal: the listener still works, with the system default.
            if let Err(error) = set_sndbuf(&ours, queue * ARRIVAL_ALLOWANCE) {
                warn!(error = %error, "Could not size a native API listener's send buffer");
            }

            let sock = match Seqpacket::new(ours) {
                Ok(sock) => sock,
                Err(error) => {
                    return (
                        deny("EMFILE", format!("could not open a listener: {error}")),
                        None,
                    );
                }
            };

            let (arrivals, incoming) = mpsc::channel::<Arrival>(queue);
            let answer = self
                .ask(|reply| NativeMessage::Listen {
                    port: listen.local,
                    arrivals,
                    reply,
                })
                .await;

            let port = match answer {
                Some(Ok(port)) => port,
                Some(Err(error)) => return (refused(error), None),
                None => return (shutting_down(), None),
            };

            tokio::spawn(watch(
                port,
                sock,
                incoming,
                self.node.clone(),
                self.outbound.clone(),
                Arc::clone(&self.flows),
                self.limits,
                Arc::clone(&self.npub),
            ));

            (
                Response::ok(serde_json::json!({
                    "local_port": port,
                    "node": self.npub.as_ref(),
                    "backlog": backlog,
                })),
                Some(theirs),
            )
        }

        /// Report what a flow's reader task has seen.
        fn stats(&self, flow: u64) -> Response {
            match self.flows.stats(flow) {
                Some(stats) => Response::ok(serde_json::json!({
                    "flow_id": flow,
                    "local_port": stats.local,
                    "rx_datagrams": stats.datagrams,
                    "rx_bytes": stats.bytes,
                    "closed": stats.closed,
                })),
                None => deny("ENOENT", format!("no such flow: {flow}")),
            }
        }

        /// Write bytes into a flow from the daemon's side.
        ///
        /// Addressed node-wide, because a flow is the node's and not the
        /// connection's. Any process that can open the socket can therefore
        /// write into any flow on the node, its own or another client's. That
        /// is why the command is behind `node.native_api.debug_commands`, which
        /// no packaged node has: a caller that can reach it can already deliver
        /// to any listener on the node under any identity it names.
        async fn inject(&self, inject: Inject) -> Response {
            let Some(sock) = self.flows.sock(inject.flow) else {
                return deny("ENOENT", format!("no such flow: {}", inject.flow));
            };

            for index in 0..inject.repeat {
                if let Err(error) = sock.send(&inject.data).await {
                    return deny(
                        "EIO",
                        format!("wrote {index} of {} datagrams: {error}", inject.repeat),
                    );
                }
            }

            Response::ok(serde_json::json!({
                "flow_id": inject.flow,
                "datagrams": inject.repeat,
                "bytes": inject.data.len() as u64 * u64::from(inject.repeat),
            }))
        }

        /// Deliver a datagram as though it had arrived from the mesh.
        ///
        /// Drives the same registry decision the FSP receive path does, so the
        /// dispatch rule is exercised without a peer. The peer's key is decoded
        /// from the npub the caller named, which makes it client-asserted
        /// rather than authenticated; this is the one path where it is, and it
        /// is one of the reasons the command is gated.
        async fn arrive(&self, arrive: super::protocol::Arrive) -> Response {
            let pubkey = match decode_npub(&arrive.peer) {
                Ok(key) => key,
                Err(error) => return deny("EINVAL", format!("invalid peer: {error}")),
            };

            let answer = self
                .ask(|reply| NativeMessage::Arrive {
                    peer: NodeAddr::from_pubkey(&pubkey),
                    pubkey,
                    src: arrive.src,
                    dst: arrive.dst,
                    data: arrive.data,
                    reply,
                })
                .await;

            match answer {
                Some(outcome) => Response::ok(serde_json::json!({
                    "outcome": match outcome {
                        Outcome::Delivered => "delivered".to_string(),
                        Outcome::Announced(_) => "announced".to_string(),
                        Outcome::Held(_) => "held".to_string(),
                        Outcome::Dropped(why) => format!("dropped: {}", why.as_str()),
                    },
                    "flow_id": match outcome {
                        Outcome::Announced(flow) | Outcome::Held(flow) => Some(flow),
                        _ => None,
                    },
                })),
                None => shutting_down(),
            }
        }
    }

    #[cfg(test)]
    impl Connection {
        /// Build a connection wired to a channel a test serves.
        pub(super) fn for_test(
            node: mpsc::Sender<NativeMessage>,
            outbound: mpsc::Sender<Outbound>,
            limits: Limits,
            debug: bool,
        ) -> Self {
            Self::new(
                node,
                outbound,
                Arc::new(Flows::new()),
                limits,
                Arc::from(super::tests::NODE),
                debug,
            )
        }

        /// Wait until a flow's reader task has counted `want` datagrams.
        ///
        /// The reader runs on the same runtime, so this yields rather than
        /// asserting into a race a test would lose intermittently.
        pub(super) async fn settle(&self, flow: u64, want: u64) {
            for _ in 0..1000 {
                match self.flows.stats(flow) {
                    Some(stats) if stats.datagrams >= want => return,
                    _ => tokio::task::yield_now().await,
                }
            }
        }

        /// Wait until a flow's reader task has observed the client's close.
        pub(super) async fn settle_closed(&self, flow: u64) {
            for _ in 0..1000 {
                match self.flows.stats(flow) {
                    Some(stats) if stats.closed => return,
                    _ => tokio::task::yield_now().await,
                }
            }
        }
    }

    /// Build one flow's socket pair and inbound queue.
    ///
    /// A free function rather than a method because the listener's task needs
    /// it too, and a listener has no connection to reach it through.
    fn wire_flow(per_flow: usize) -> std::io::Result<(Wiring, OwnedFd, mpsc::Sender<Datagram>)> {
        let (ours, theirs) = pair()?;

        // `hand_over` writes a flow's whole held batch onto this pair before the
        // client has the descriptor, so nothing is reading while it is written
        // and the batch has to fit in the kernel's buffer.
        //
        // **Both halves are sized because the two kernels charge different
        // ones.** Linux accounts an `AF_UNIX` message against the sender's
        // `SO_SNDBUF`, which is generous by default; BSD queues it in the
        // receiver's `so_rcv`, whose `SOCK_DGRAM` default on Darwin is small
        // enough that a two or three datagram batch fills it. Sizing only the
        // sender, as the listener pair does, leaves the flow pair unbounded by
        // anything this code sets on Darwin, and the first batch past the
        // ceiling destroys the whole arriving flow before its client ever sees
        // it. Neither call is fatal: a flow with a default-sized buffer works,
        // it just holds less.
        let budget = per_flow.max(1) * ARRIVAL_ALLOWANCE;
        if let Err(error) = set_sndbuf(&ours, budget) {
            warn!(error = %error, "Could not size a native API flow's send buffer");
        }
        if let Err(error) = set_rcvbuf(&theirs, budget) {
            warn!(error = %error, "Could not size a native API flow's receive buffer");
        }

        let sock = Arc::new(Seqpacket::new(ours)?);
        let (sink, inbound) = mpsc::channel::<Datagram>(per_flow.max(1));
        Ok((Wiring { sock, inbound }, theirs, sink))
    }

    /// Start a flow's tasks now that its key is final, and record it node-side.
    ///
    /// The reader cannot start any earlier: it stamps every datagram it
    /// forwards with the flow's key and the peer's address, and the local port
    /// is not known until the registry has answered.
    fn start(
        id: u64,
        key: FlowKey,
        peer: XOnlyPublicKey,
        wiring: Wiring,
        outbound: &mpsc::Sender<Outbound>,
        node: &mpsc::Sender<NativeMessage>,
        flows: &Arc<Flows>,
    ) {
        let counts = Arc::new(Counts::default());
        tokio::spawn(drain(
            id,
            key,
            peer,
            Arc::clone(&wiring.sock),
            Arc::clone(&counts),
            outbound.clone(),
            node.clone(),
            Arc::clone(flows),
        ));
        tokio::spawn(feed(Arc::clone(&wiring.sock), wiring.inbound));
        flows.record(
            id,
            Flow {
                local: key.local,
                sock: wiring.sock,
                counts,
            },
        );
    }

    /// Serve one listener until its client closes the descriptor.
    ///
    /// Two arms, and the second is not optional: end of file is observable only
    /// by reading, so a listener that never called `recv` on its own half could
    /// not notice its client had gone and would hold the port for the node's
    /// lifetime. A client has no message to send here, so anything the read arm
    /// produces other than end of file is discarded rather than answered: a
    /// listener that replied would be a second protocol on a socket that has
    /// none.
    #[allow(
        clippy::too_many_arguments,
        reason = "one hand-off of plumbing to a task, with no state to group"
    )]
    async fn watch(
        port: u16,
        sock: Seqpacket,
        mut incoming: mpsc::Receiver<Arrival>,
        node: mpsc::Sender<NativeMessage>,
        outbound: mpsc::Sender<Outbound>,
        flows: Arc<Flows>,
        limits: Limits,
        npub: Arc<str>,
    ) {
        /// What the listener's select produced.
        enum Next {
            /// A peer arrived on this listener's port.
            Arrival(Arrival),
            /// The client closed the listener, or the node went away.
            Done,
            /// The client wrote something a listener has no use for.
            Ignored,
        }

        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            // Both arms are cancel-safe. `mpsc::Receiver::recv` is documented
            // so, and `Seqpacket::recv` holds nothing across a cancellation: it
            // awaits readiness and then performs one `recvmsg`, and
            // `SOCK_SEQPACKET` has no partial message to lose. This is the one
            // property this task's shape depends on.
            let next = tokio::select! {
                arrival = incoming.recv() => match arrival {
                    Some(arrival) => Next::Arrival(arrival),
                    None => Next::Done,
                },
                received = sock.recv(&mut buf) => match received {
                    Ok(Received::Eof) | Err(_) => Next::Done,
                    Ok(Received::Datagram(_)) => Next::Ignored,
                },
            };

            match next {
                Next::Done => break,
                Next::Ignored => continue,
                Next::Arrival(arrival) => {
                    hand_over(arrival, &sock, &node, &outbound, &flows, limits, &npub).await;
                }
            }
        }

        debug!(port, "Native API listener closed by its client");
        let _ = node
            .send(NativeMessage::Release {
                flows: Vec::new(),
                listeners: vec![port],
            })
            .await;
    }

    /// Wire one arriving flow and hand its descriptor to the listener's client.
    ///
    /// Promotion comes first because taking the flow and taking what it held
    /// are one registry operation. Then the held datagrams go onto the flow's
    /// half and the arrival message onto the listener's, in that order, so
    /// whatever arrived before the client could read the arrival is already on
    /// the descriptor by the time the client holds it.
    ///
    /// Both writes are try-sends. They go onto a socket pair whose client half
    /// has not been sent yet, so no process can read either one and a task that
    /// parked on one would stop serving this listener entirely.
    async fn hand_over(
        arrival: Arrival,
        listener: &Seqpacket,
        node: &mpsc::Sender<NativeMessage>,
        outbound: &mpsc::Sender<Outbound>,
        flows: &Arc<Flows>,
        limits: Limits,
        npub: &str,
    ) {
        // A failure here leaves the flow pending, which the registry's own
        // deadline reclaims and counts. Nothing has been promoted yet, so there
        // is nothing to undo.
        let (wiring, theirs, sink) = match wire_flow(limits.per_flow) {
            Ok(parts) => parts,
            Err(error) => {
                warn!(error = %error, "Could not open a socket pair for an arriving flow");
                return;
            }
        };

        let (tx, rx) = oneshot::channel();
        if node
            .send(NativeMessage::Accept {
                flow: arrival.flow,
                sink,
                reply: tx,
            })
            .await
            .is_err()
        {
            return;
        }
        let accepted: Accepted = match rx.await {
            Ok(Ok(accepted)) => accepted,
            // The flow expired between the announcement and this hop, or the
            // node is shutting down. Either way there is nothing to hand over.
            Ok(Err(error)) => {
                debug!(error = %error, "An arriving flow was gone before it could be wired");
                return;
            }
            Err(_) => return,
        };

        // The byte counts are dropped rather than checked: `SOCK_SEQPACKET`
        // writes a message whole or fails, so a short write is not a state
        // this can be in.
        let failed = perform(arrival.flow, &accepted, npub, |step| match step {
            Handoff::Held(datagram) => {
                fdpass::try_send(wiring.sock.raw(), datagram, None).map(drop)
            }
            Handoff::Arrival(message) => {
                fdpass::try_send(listener.raw(), message, Some(theirs.as_fd())).map(drop)
            }
        })
        .err();

        if let Some(reason) = failed {
            // Three parts, and all of them are required: closing the pair,
            // giving the registry entry and its port claim back, and counting
            // the drop. Missing any one leaks a descriptor, a port, or both,
            // once per unread arrival, at a rate a remote peer sets.
            drop(wiring);
            drop(theirs);
            let _ = node
                .send(NativeMessage::Discard {
                    key: accepted.key,
                    reason,
                })
                .await;
            return;
        }

        start(
            arrival.flow,
            accepted.key,
            accepted.peer,
            wiring,
            outbound,
            node,
            flows,
        );
        // Dropping our copy leaves the client holding the only reference to its
        // half, so its close tears the flow down.
        drop(theirs);
    }

    /// What a failed hand-off write says about the client, for the counter.
    ///
    /// Both take the same three-part cleanup, so this decides only what an
    /// operator is told: a gone listener is a client that closed between the
    /// arrival being taken off the queue and this write, which a healthy client
    /// can lose, and anything else is a full send buffer, which is a client that
    /// stopped reading. Reporting the two alike would leave a normal close
    /// looking like a fault.
    ///
    /// **Three errnos mean "gone", because the platforms do not agree.** Linux
    /// `SOCK_SEQPACKET` reports a closed peer as `EPIPE`. Darwin disconnects the
    /// survivor of a `SOCK_DGRAM` pair instead, so its first send gives
    /// `ECONNRESET` and later ones `EDESTADDRREQ`, and neither is `BrokenPipe`.
    /// Matching on the kind alone would file every ordinary macOS listener close
    /// under the counter an operator reads to find a wedged client.
    pub(super) fn why(error: &std::io::Error) -> DropReason {
        let gone = error.kind() == std::io::ErrorKind::BrokenPipe
            || matches!(
                error.raw_os_error(),
                Some(libc::ECONNRESET) | Some(libc::EDESTADDRREQ)
            );
        if gone {
            DropReason::ListenerGone
        } else {
            DropReason::ListenerNotReading
        }
    }

    /// Perform one arriving flow's hand-off, stopping at the first failed write.
    ///
    /// Builds the plan and consumes it here rather than taking one from the
    /// caller, so no caller has a sequence it could reorder. That is the whole
    /// reason this is a function: with the plan built in [`handoff`] and
    /// performed inline in [`hand_over`], reversing the consumption was
    /// invisible to every test, because both writes are synchronous and a
    /// client reading afterwards sees the same bytes either way. Reversed, a
    /// successful arrival write followed by a failed held write hands the
    /// client a live descriptor for a flow the caller then tears down.
    ///
    /// `write` is a parameter for the same reason: the real writes need two
    /// live socket pairs and a descriptor to pass, and a test that supplies
    /// them can observe the result but not the order.
    ///
    /// Returns the reason for the failed write, ready for the caller's counter.
    pub(super) fn perform<W>(
        flow: u64,
        accepted: &Accepted,
        npub: &str,
        mut write: W,
    ) -> Result<(), DropReason>
    where
        W: FnMut(&Handoff<'_>) -> std::io::Result<()>,
    {
        for step in handoff(flow, accepted, npub) {
            write(&step).map_err(|error| why(&error))?;
        }
        Ok(())
    }

    /// One write of a hand-off, in the order the writes must happen.
    pub(super) enum Handoff<'a> {
        /// A datagram the node held for this flow before its client existed.
        Held(&'a Datagram),
        /// The arrival message, which carries the flow's descriptor with it.
        Arrival(Vec<u8>),
    }

    /// The writes that hand one arriving flow to a listener's client, in order.
    ///
    /// **The order is the guarantee.** Every held datagram is on the flow's
    /// descriptor before the arrival message that carries that descriptor, so
    /// whatever arrived before the client could read the arrival is already
    /// there when the client holds it. Losing that drops a peer's opening
    /// message, which this code has done once already.
    ///
    /// Built as a sequence rather than performed inline because the order is
    /// then a value a test can read. Performed inline it is a race no test can
    /// observe: both writes are synchronous and nothing can interleave between
    /// them, so reversing them is invisible to any client that reads afterwards.
    /// The sequence is consumed only by [`perform`], which is why no caller has
    /// one to reorder.
    ///
    /// The arrival reports the whole held batch, because a held write that fails
    /// ends the hand-off before the arrival is ever attempted.
    pub(super) fn handoff<'a>(flow: u64, accepted: &'a Accepted, npub: &str) -> Vec<Handoff<'a>> {
        let mut steps: Vec<Handoff<'a>> = accepted.held.iter().map(Handoff::Held).collect();
        steps.push(Handoff::Arrival(announce(
            flow,
            accepted,
            npub,
            accepted.held.len(),
        )));
        steps
    }

    /// The message a listener's client reads for one arriving flow.
    ///
    /// One `SOCK_SEQPACKET` message per arrival and **no trailing newline**:
    /// the message boundary is the framing, and a newline would offer a client
    /// a second one to rely on. The peer is named by npub, which is the address
    /// its session authenticated; `node` is this node's own npub, carried so an
    /// accepted stream can answer `getsockname` without consulting the listener
    /// that produced it.
    fn announce(id: u64, accepted: &Accepted, npub: &str, held: usize) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "flow_id": id,
            "peer": encode_npub(&accepted.peer),
            "node": npub,
            "local_port": accepted.key.local,
            "remote_port": accepted.key.remote,
            "max_payload": accepted.max,
            "held": held,
        }))
        .unwrap_or_default()
    }

    /// Drain one flow's daemon half, forwarding what the client writes.
    ///
    /// Counting continues alongside the forwarding: `stats` is how a check
    /// observes that a datagram reached the daemon, independently of whether it
    /// then reached a peer.
    #[allow(
        clippy::too_many_arguments,
        reason = "one hand-off of plumbing to a task, with no state to group"
    )]
    async fn drain(
        id: u64,
        key: FlowKey,
        peer: XOnlyPublicKey,
        sock: Arc<Seqpacket>,
        counts: Arc<Counts>,
        outbound: mpsc::Sender<Outbound>,
        node: mpsc::Sender<NativeMessage>,
        flows: Arc<Flows>,
    ) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match sock.recv(&mut buf).await {
                Ok(Received::Datagram(len)) => {
                    counts.datagrams.fetch_add(1, Ordering::Relaxed);
                    counts.bytes.fetch_add(len as u64, Ordering::Relaxed);
                    let sent = outbound
                        .send(Outbound {
                            key,
                            peer,
                            payload: buf[..len].to_vec(),
                        })
                        .await;
                    if sent.is_err() {
                        debug!(local = key.local, "Node is gone, ending this flow");
                        // Still through `free`: the registry send fails too when
                        // the node is gone, but the node's own record of this
                        // flow is in this process and would otherwise outlive
                        // the task that owns it.
                        free(&node, &flows, id, key).await;
                        return;
                    }
                }
                Ok(Received::Eof) => {
                    counts.closed.store(true, Ordering::Relaxed);
                    debug!(local = key.local, "Native API flow closed by its client");
                    free(&node, &flows, id, key).await;
                    return;
                }
                Err(error) => {
                    debug!(local = key.local, error = %error, "Native API flow read failed");
                    free(&node, &flows, id, key).await;
                    return;
                }
            }
        }
    }

    /// Give one flow's registry entry back when its client is done with it.
    ///
    /// A flow lives until its own descriptor reaches end of file, whether it
    /// was connected or accepted, so this is the only site that releases one. A
    /// program serving a flow per exchange depends on it: without the per-flow
    /// release it walks into the node's flow ceiling.
    ///
    /// The node's record goes at the same time, so `stats` on a closed flow
    /// reports what a client would find with any other name: no such flow.
    async fn free(node: &mpsc::Sender<NativeMessage>, flows: &Arc<Flows>, id: u64, key: FlowKey) {
        let _ = node
            .send(NativeMessage::Release {
                flows: vec![key],
                listeners: Vec::new(),
            })
            .await;
        flows.forget(id);
    }

    /// Write datagrams the node delivered onto the client's descriptor.
    ///
    /// **A full client buffer drops the datagram and keeps the flow.** On Linux
    /// this never arrives here: the send reports `EAGAIN` and `Seqpacket::send`
    /// waits for the client to drain. Darwin's `SOCK_DGRAM` has no sender-side
    /// queue to wait on, so an unread client surfaces as `ENOBUFS` on the send
    /// itself. Returning on it would end this flow's only writer while the
    /// registration, the port and the reader all stayed alive, so every later
    /// inbound datagram would be counted as a full queue for the rest of the
    /// flow's life, and a client that resumed reading would never recover.
    /// Dropping the datagram is what a datagram API does when the far end
    /// cannot take it.
    async fn feed(sock: Arc<Seqpacket>, mut inbound: mpsc::Receiver<Datagram>) {
        while let Some(datagram) = inbound.recv().await {
            if let Err(error) = sock.send(&datagram).await {
                if error.raw_os_error() == Some(libc::ENOBUFS) {
                    debug!(error = %error, "Native API flow write dropped a datagram");
                    continue;
                }
                debug!(error = %error, "Native API flow write failed");
                return;
            }
        }
    }

    /// Serve one client connection until it closes or misbehaves.
    ///
    /// The connection carries replies only, in command order. There is no event
    /// on it and so no select over a partially-read command, which was not
    /// cancellation-safe: an arrival becoming ready while the reader waited for
    /// the rest of a line dropped the accumulated bytes, and the client's
    /// half-command vanished with no reply and no error.
    async fn serve(
        stream: UnixStream,
        node: mpsc::Sender<NativeMessage>,
        outbound: mpsc::Sender<Outbound>,
        flows: Arc<Flows>,
        limits: Limits,
        npub: Arc<str>,
        debug: bool,
    ) -> Result<(), std::io::Error> {
        let mut connection = Connection::new(node, outbound, flows, limits, npub, debug);
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();

        while read_command(&mut reader, &mut line).await? {
            let (response, fd) = connection.answer(&line).await;
            let mut json = serde_json::to_vec(&response)?;
            json.push(b'\n');
            fdpass::reply(reader.get_ref(), &json, fd.as_ref().map(AsFd::as_fd)).await?;
            // Dropping our copy leaves the client holding the only reference to
            // its half, so its close tears the flow or the listener down.
            drop(fd);
        }

        Ok(())
    }

    /// Read one newline-terminated command into `line`, refusing an oversized
    /// one.
    ///
    /// Returns `false` at end of file. The buffer is filled and consumed a
    /// chunk at a time so a client that never sends a newline is cut off at
    /// [`MAX_COMMAND`] rather than growing the buffer without bound.
    pub(super) async fn read_command<R>(
        reader: &mut R,
        line: &mut Vec<u8>,
    ) -> Result<bool, std::io::Error>
    where
        R: tokio::io::AsyncBufRead + Unpin,
    {
        use tokio::io::AsyncBufReadExt;

        line.clear();
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(!line.is_empty());
            }

            // The newline may or may not be in this chunk, and the cap has to
            // hold either way. Checking it only on the no-newline branch makes
            // enforcement depend on where the reader happened to split the
            // input, which is a guard that works only intermittently.
            let (take, complete) = match available.iter().position(|byte| *byte == b'\n') {
                Some(end) => (end, true),
                None => (available.len(), false),
            };

            if line.len() + take > MAX_COMMAND {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "native API command too large",
                ));
            }

            line.extend_from_slice(&available[..take]);
            reader.consume(if complete { take + 1 } else { take });

            if complete {
                return Ok(true);
            }
        }
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "freebsd", target_os = "macos")
))]
mod tests {
    use super::link::{self, NativeMessage, Outbound};
    use super::registry::{Limits, Registry};
    use super::unix_impl::Connection;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use tokio::sync::mpsc;

    /// An npub the tests can decode. Any valid one will do; the tests never
    /// reach the peer it names.
    const PEER: &str = "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m";

    /// The npub a test node reports as its own, standing in for the identity a
    /// running daemon would report. A real one, so a reader cannot mistake the
    /// field for something the daemon fabricates.
    pub(super) const NODE: &str = "npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d";

    fn limits() -> Limits {
        Limits {
            per_flow: 4,
            backlog: 2,
            max_flows: 8,
        }
    }

    /// The payload limit the fake node reports, standing in for one derived
    /// from a transport MTU.
    const MAX_PAYLOAD: u16 = 1362;

    /// A connection wired to a task serving a real registry.
    ///
    /// The task runs the same `link::serve` the daemon's `rx_loop` runs, so
    /// these tests exercise the whole request and reply path rather than a
    /// stand-in for it.
    fn connect() -> (Connection, mpsc::Receiver<Outbound>) {
        wire_connection(true)
    }

    /// The same connection with the debug commands off, as a packaged node has
    /// them.
    fn connect_without_debug() -> (Connection, mpsc::Receiver<Outbound>) {
        wire_connection(false)
    }

    /// Build a connection over a real registry, with the debug gate as given.
    fn wire_connection(debug: bool) -> (Connection, mpsc::Receiver<Outbound>) {
        let (tx, mut rx) = mpsc::channel::<NativeMessage>(16);
        tokio::spawn(async move {
            let mut registry = Registry::new(limits());
            let mut now = 0u64;
            while let Some(message) = rx.recv().await {
                link::serve(&mut registry, message, now, MAX_PAYLOAD);
                now += 1;
            }
        });
        let (out_tx, out_rx) = mpsc::channel::<Outbound>(64);
        (Connection::for_test(tx, out_tx, limits(), debug), out_rx)
    }

    /// Send one command and read the reply as JSON.
    async fn ask(connection: &mut Connection, line: &str) -> serde_json::Value {
        let (response, fd) = connection.answer(line.as_bytes()).await;
        assert!(fd.is_none(), "this command should carry no descriptor");
        serde_json::to_value(response).unwrap()
    }

    /// Send one command that opens a flow, returning the reply and descriptor.
    async fn open(connection: &mut Connection, line: &str) -> (serde_json::Value, StdUnixStream) {
        let (response, fd) = connection.answer(line.as_bytes()).await;
        let value = serde_json::to_value(response).unwrap();
        let fd = fd.expect("this command should carry a descriptor");
        (value, StdUnixStream::from(fd))
    }

    /// Bind a listener and keep its descriptor, the way a client does.
    async fn listen(connection: &mut Connection, port: u16) -> (serde_json::Value, StdUnixStream) {
        open(
            connection,
            &format!(r#"{{"command":"listen","params":{{"local_port":{port}}}}}"#),
        )
        .await
    }

    /// Read one arrival message and the flow descriptor that rides with it.
    ///
    /// Goes through the same `recvmsg` a client process runs, so what these
    /// tests assert about the ancillary framing is what a client would see.
    fn accept(listener: &StdUnixStream) -> (serde_json::Value, StdUnixStream) {
        let mut buf = [0u8; 4096];
        let chunk = super::fdpass::recv(listener.as_raw_fd(), &mut buf)
            .expect("an arrival should be readable on the listener");
        let fd: OwnedFd = chunk.fd.expect("an arrival carries the flow's descriptor");
        let value: serde_json::Value =
            serde_json::from_slice(&buf[..chunk.len]).expect("the arrival is one JSON object");
        (value, StdUnixStream::from(fd))
    }

    /// Deliver a datagram as though a peer had sent it.
    fn arrival(src: u16, dst: u16, data: &str) -> String {
        arrival_from(PEER, src, dst, data)
    }

    /// The same, naming the peer, so a test can name one that will not decode.
    fn arrival_from(peer: &str, src: u16, dst: u16, data: &str) -> String {
        format!(
            r#"{{"command":"arrive","params":{{"peer":"{peer}","src_port":{src},"dst_port":{dst},"data":"{data}"}}}}"#
        )
    }

    #[tokio::test]
    async fn closing_one_flow_frees_its_port_while_the_connection_stays_open() {
        let (mut connection, _outbound) = connect();
        let line = format!(
            r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242,"local_port":4243}}}}"#
        );
        let (value, client) = open(&mut connection, &line).await;
        let flow = value["data"]["flow_id"].as_u64().unwrap();

        drop(client);
        connection.settle_closed(flow).await;

        // `settle_closed` observes the reader's flag, which it sets before it
        // sends the release, so the registry may not have processed it yet.
        // Retry rather than sleep: without the reclaim every attempt fails and
        // the loop runs out, which is the failure this test exists to produce.
        let mut last = serde_json::Value::Null;
        for _ in 0..1000 {
            // Not `ask`: a connect that succeeds carries a descriptor, and that
            // is the outcome being waited for.
            let (response, fd) = connection.answer(line.as_bytes()).await;
            last = serde_json::to_value(response).unwrap();
            if last["status"] == "ok" {
                assert!(fd.is_some(), "a reopened flow still gets a descriptor");
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the closed flow never gave its port back: {last}");
    }

    #[tokio::test]
    async fn a_listener_holds_its_port_against_a_second_binder() {
        let (mut connection, _outbound) = connect();
        let (value, _listener) = listen(&mut connection, 4242).await;
        assert_eq!(value["status"], "ok");
        assert_eq!(value["data"]["local_port"], 4242);
        assert_eq!(value["data"]["node"], NODE);
        assert_eq!(value["data"]["backlog"], limits().backlog);

        let value = ask(
            &mut connection,
            r#"{"command":"listen","params":{"local_port":4242}}"#,
        )
        .await;
        assert_eq!(value["status"], "error");
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("already in use"),
            "message was {}",
            value["message"]
        );
    }

    #[tokio::test]
    async fn a_listener_that_names_no_port_is_told_the_one_it_was_given() {
        let (mut connection, _outbound) = connect();
        let (value, _listener) = open(
            &mut connection,
            r#"{"command":"listen","params":{"local_port":0}}"#,
        )
        .await;
        assert_eq!(value["status"], "ok");
        let port = value["data"]["local_port"].as_u64().unwrap();
        assert!(
            port >= u64::from(super::protocol::PORT_EPHEMERAL_MIN),
            "an allocated listener port comes from the ephemeral range, got {port}"
        );

        // The reported port is the one actually held. A reply that echoed the
        // zero it was asked for would leave a client with no port to name.
        let value = ask(
            &mut connection,
            &format!(r#"{{"command":"listen","params":{{"local_port":{port}}}}}"#),
        )
        .await;
        assert_eq!(value["status"], "error");
    }

    #[tokio::test]
    async fn a_reserved_port_is_refused_before_it_reaches_the_registry() {
        let (mut connection, _outbound) = connect();
        let value = ask(
            &mut connection,
            r#"{"command":"listen","params":{"local_port":256}}"#,
        )
        .await;
        assert_eq!(value["status"], "error");
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("standard services")
        );
    }

    #[tokio::test]
    async fn malformed_json_and_unknown_commands_are_refused() {
        let (mut connection, _outbound) = connect();
        let value = ask(&mut connection, "{not json").await;
        assert_eq!(value["status"], "error");
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("invalid request")
        );

        let value = ask(&mut connection, r#"{"command":"teleport"}"#).await;
        assert_eq!(value["status"], "error");
        assert!(value["message"].as_str().unwrap().contains("teleport"));
    }

    #[tokio::test]
    async fn accept_and_reject_are_no_longer_commands() {
        // They were removed with the round trip they served. A client that
        // still sends one must be told the command does not exist, rather than
        // having it quietly ignored or, worse, half-served.
        let (mut connection, _outbound) = connect();
        for command in ["accept", "reject"] {
            let value = ask(
                &mut connection,
                &format!(r#"{{"command":"{command}","params":{{"flow_id":1}}}}"#),
            )
            .await;
            assert_eq!(value["status"], "error", "{command} was answered");
            assert!(
                value["message"].as_str().unwrap().contains(command),
                "the refusal should name {command}: {}",
                value["message"]
            );
        }
    }

    #[tokio::test]
    async fn a_refusal_a_client_acts_on_carries_the_errno_for_it() {
        // A client turns `data.errno` into the error its language's `bind` or
        // `connect` would have returned, and it must never have to match the
        // message to do it. Every row here is one the client library maps.
        let (mut connection, _outbound) = connect();

        let (_value, _listener) = listen(&mut connection, 4242).await;
        let value = ask(
            &mut connection,
            r#"{"command":"listen","params":{"local_port":4242}}"#,
        )
        .await;
        assert_eq!(value["data"]["errno"], "EADDRINUSE", "{value}");

        let value = ask(
            &mut connection,
            r#"{"command":"listen","params":{"local_port":256}}"#,
        )
        .await;
        assert_eq!(value["data"]["errno"], "EADDRNOTAVAIL", "{value}");

        let value = ask(
            &mut connection,
            r#"{"command":"connect","params":{"peer":"not-an-npub","remote_port":4242}}"#,
        )
        .await;
        assert_eq!(value["data"]["errno"], "EINVAL", "{value}");

        let value = ask(&mut connection, r#"{"command":"teleport"}"#).await;
        assert_eq!(value["data"]["errno"], "EINVAL", "{value}");

        // The node's flow ceiling, which is the one row a registry refusal
        // other than a taken port produces. The descriptors are kept so the
        // flows stay open while the ceiling is tested.
        let mut open_flows = Vec::new();
        for index in 0..limits().max_flows {
            let (value, client) = open(
                &mut connection,
                &format!(
                    r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242,"local_port":{}}}}}"#,
                    5000 + index
                ),
            )
            .await;
            assert_eq!(value["status"], "ok", "flow {index} was refused: {value}");
            open_flows.push(client);
        }
        let value = ask(
            &mut connection,
            &format!(
                r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242,"local_port":6000}}}}"#
            ),
        )
        .await;
        assert_eq!(value["data"]["errno"], "EMFILE", "{value}");
    }

    #[tokio::test]
    async fn a_connect_yields_a_descriptor_and_holds_a_port() {
        let (mut connection, _outbound) = connect();
        let (value, mut client) = open(
            &mut connection,
            &format!(
                r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242,"local_port":5000}}}}"#
            ),
        )
        .await;
        assert_eq!(value["status"], "ok");
        assert_eq!(value["data"]["local_port"], 5000);
        assert_eq!(
            value["data"]["peer"], PEER,
            "the reply names the peer by npub, re-encoded from the key it decoded"
        );
        assert_eq!(
            value["data"]["node"], NODE,
            "and names this node, so a client can answer getsockname"
        );
        let flow = value["data"]["flow_id"].as_u64().unwrap();

        client.write_all(b"hello").unwrap();
        connection.settle(flow, 1).await;

        let value = ask(
            &mut connection,
            &format!(r#"{{"command":"stats","params":{{"flow_id":{flow}}}}}"#),
        )
        .await;
        assert_eq!(value["data"]["rx_datagrams"], 1);
        assert_eq!(value["data"]["rx_bytes"], 5);

        // The port the flow holds is now unavailable to a listener.
        let value = ask(
            &mut connection,
            r#"{"command":"listen","params":{"local_port":5000}}"#,
        )
        .await;
        assert_eq!(value["status"], "error");
    }

    #[tokio::test]
    async fn what_a_client_writes_reaches_the_node_with_its_flow_key_and_its_peer() {
        let (mut connection, mut outbound) = connect();
        let (value, mut client) = open(
            &mut connection,
            &format!(
                r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242,"local_port":5000}}}}"#
            ),
        )
        .await;
        assert_eq!(value["data"]["max_payload"], MAX_PAYLOAD);

        client.write_all(b"over the wire").unwrap();

        let sent = tokio::time::timeout(std::time::Duration::from_secs(5), outbound.recv())
            .await
            .expect("the datagram should reach the node")
            .expect("the outbound channel should stay open");
        assert_eq!(sent.payload, b"over the wire");
        assert_eq!(sent.key.local, 5000);
        assert_eq!(sent.key.remote, 4242);
        assert_eq!(
            crate::identity::encode_npub(&sent.peer),
            PEER,
            "the flow carries the peer's address, so the node needs no lookup \
             to start a session"
        );
    }

    #[tokio::test]
    async fn a_bad_peer_is_refused_without_holding_a_port() {
        let (mut connection, _outbound) = connect();
        let value = ask(
            &mut connection,
            r#"{"command":"connect","params":{"peer":"not-an-npub","remote_port":4242,"local_port":5000}}"#,
        )
        .await;
        assert_eq!(value["status"], "error");
        assert!(value["message"].as_str().unwrap().contains("invalid peer"));

        // The port must still be free: a refusal that leaked a reservation
        // would take a port out of service for the node's lifetime.
        let (value, _listener) = listen(&mut connection, 5000).await;
        assert_eq!(value["status"], "ok");
    }

    #[tokio::test]
    async fn an_arrival_reaches_the_listener_descriptor_with_its_flow_and_what_it_held() {
        let (mut connection, _outbound) = connect();
        let (_value, listener) = listen(&mut connection, 4242).await;

        let value = ask(&mut connection, &arrival(5000, 4242, "00ff10")).await;
        assert_eq!(value["status"], "ok");
        assert_eq!(value["data"]["outcome"], "announced");
        let flow = value["data"]["flow_id"].as_u64().unwrap();

        let (message, mut client) = accept(&listener);
        assert_eq!(message["flow_id"], flow);
        assert_eq!(
            message["peer"], PEER,
            "the peer is named by npub, which is its address, and never by hex"
        );
        assert!(
            message.get("peer_addr").is_none(),
            "no client-facing field carries the node address"
        );
        assert_eq!(message["node"], NODE);
        assert_eq!(message["local_port"], 4242);
        assert_eq!(message["remote_port"], 5000);
        assert_eq!(message["max_payload"], MAX_PAYLOAD);
        assert_eq!(message["held"], 1);

        // The datagram that arrived before the client could read the arrival is
        // already on the descriptor, rather than lost to the hand-off.
        let mut buf = [0u8; 64];
        assert_eq!(client.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], &[0x00, 0xff, 0x10]);
    }

    #[test]
    fn a_listener_that_closed_and_one_that_stopped_reading_are_counted_apart() {
        // Both take the same cleanup, so the counter is the only place the
        // difference survives, and an operator reads it to tell a client that
        // closed normally from one that is wedged.
        use super::unix_impl::why;
        use std::io::{Error, ErrorKind};

        assert_eq!(
            why(&Error::from(ErrorKind::BrokenPipe)),
            link::DropReason::ListenerGone
        );
        assert_eq!(
            why(&Error::from(ErrorKind::WouldBlock)),
            link::DropReason::ListenerNotReading
        );
    }

    /// One accepted flow holding `held`, for the hand-off tests.
    fn arrived(held: Vec<Vec<u8>>) -> link::Accepted {
        let peer = crate::identity::decode_npub(PEER).unwrap();
        link::Accepted {
            key: super::registry::FlowKey {
                peer: crate::identity::NodeAddr::from_pubkey(&peer),
                remote: 5000,
                local: 4242,
            },
            peer,
            held,
            max: MAX_PAYLOAD,
        }
    }

    /// What one hand-off write was, for an order assertion.
    fn wrote(step: &super::unix_impl::Handoff<'_>) -> String {
        match step {
            super::unix_impl::Handoff::Held(datagram) => {
                String::from_utf8_lossy(datagram).into_owned()
            }
            super::unix_impl::Handoff::Arrival(_) => "arrival".to_string(),
        }
    }

    #[test]
    fn performing_a_hand_off_writes_every_held_datagram_before_the_arrival_carrying_the_descriptor()
    {
        // Over the writes the daemon actually performs, not over the plan it
        // built. Asserting the plan alone leaves the consumption free to run in
        // any order, and reversed it hands the client a live descriptor for a
        // flow whose held datagrams never reached it.
        use super::unix_impl::perform;

        let accepted = arrived(vec![b"first".to_vec(), b"second".to_vec()]);
        let mut written: Vec<String> = Vec::new();
        let done = perform(9, &accepted, NODE, |step| {
            written.push(wrote(step));
            Ok(())
        });

        assert!(done.is_ok(), "every write succeeded");
        assert_eq!(
            written,
            ["first", "second", "arrival"],
            "the descriptor must be the last thing written, not the first"
        );
    }

    #[test]
    fn a_hand_off_whose_held_write_fails_never_writes_the_arrival_and_names_the_reason() {
        // The arrival is what hands the descriptor over, so attempting it after
        // a lost held datagram would give the client a flow missing its peer's
        // opening message rather than no flow at all.
        use super::unix_impl::perform;
        use std::io::{Error, ErrorKind};

        let accepted = arrived(vec![b"first".to_vec(), b"second".to_vec()]);
        let mut written: Vec<String> = Vec::new();
        let reason = perform(9, &accepted, NODE, |step| {
            written.push(wrote(step));
            Err(Error::from(ErrorKind::WouldBlock))
        })
        .expect_err("the first write failed");

        assert_eq!(reason, link::DropReason::ListenerNotReading);
        assert_eq!(written, ["first"], "the hand-off stopped at the failure");
    }

    #[test]
    fn a_hand_off_whose_arrival_write_fails_reports_the_listener_gone() {
        // A client that closed its listener between the arrival leaving the
        // queue and this write is a race a healthy client can lose, and it must
        // not be counted as a client falling behind.
        use super::unix_impl::{Handoff, perform};
        use std::io::{Error, ErrorKind};

        let accepted = arrived(vec![b"first".to_vec()]);
        let reason = perform(9, &accepted, NODE, |step| match step {
            Handoff::Held(_) => Ok(()),
            Handoff::Arrival(_) => Err(Error::from(ErrorKind::BrokenPipe)),
        })
        .expect_err("the arrival write failed");

        assert_eq!(reason, link::DropReason::ListenerGone);
    }

    #[test]
    fn a_gone_listener_is_recognised_by_every_errno_a_platform_uses_for_it() {
        // The same event, spelled three ways. Linux SOCK_SEQPACKET reports a
        // closed peer as EPIPE; Darwin disconnects the survivor of a SOCK_DGRAM
        // pair, so its first send gives ECONNRESET and later ones EDESTADDRREQ.
        // Matching on ErrorKind::BrokenPipe alone recognises only the first, and
        // would file every ordinary macOS listener close under the counter an
        // operator reads to find a client that has stopped reading.
        //
        // Built from raw errnos rather than ErrorKind, because that is the only
        // form that distinguishes them: ECONNRESET maps to ConnectionReset and
        // EDESTADDRREQ to Uncategorized, and neither is BrokenPipe.
        use super::unix_impl::why;
        use std::io::Error;

        for errno in [libc::EPIPE, libc::ECONNRESET, libc::EDESTADDRREQ] {
            assert_eq!(
                why(&Error::from_raw_os_error(errno)),
                link::DropReason::ListenerGone,
                "errno {errno} should count as a listener that went away"
            );
        }

        // The discrimination has to survive: a full buffer is still a client
        // that stopped reading, and folding everything into ListenerGone would
        // pass the loop above while destroying what the counter is for.
        for errno in [libc::ENOBUFS, libc::EAGAIN] {
            assert_eq!(
                why(&Error::from_raw_os_error(errno)),
                link::DropReason::ListenerNotReading,
                "errno {errno} should still count as a client not reading"
            );
        }
    }

    #[test]
    fn the_hand_off_writes_what_a_flow_held_before_the_arrival_that_carries_it() {
        // The plan, which is the half of the ordering guarantee this test owns:
        // what the batch contains and what the arrival says about it. That the
        // writes then happen in the planned order is the neighbouring test's,
        // and both are needed, because a correct plan consumed backwards is
        // invisible to a client that reads afterwards.
        use super::unix_impl::{Handoff, handoff};

        let accepted = arrived(vec![b"first".to_vec(), b"second".to_vec()]);
        let steps = handoff(9, &accepted, NODE);
        let order: Vec<&str> = steps
            .iter()
            .map(|step| match step {
                Handoff::Held(_) => "held",
                Handoff::Arrival(_) => "arrival",
            })
            .collect();
        assert_eq!(
            order,
            ["held", "held", "arrival"],
            "the descriptor must be the last thing written, not the first"
        );

        let held: Vec<&[u8]> = steps
            .iter()
            .filter_map(|step| match step {
                Handoff::Held(datagram) => Some(datagram.as_slice()),
                Handoff::Arrival(_) => None,
            })
            .collect();
        assert_eq!(held, [b"first".as_slice(), b"second".as_slice()]);

        let Some(Handoff::Arrival(message)) = steps.last() else {
            panic!("the hand-off ends with the arrival");
        };
        let value: serde_json::Value = serde_json::from_slice(message).unwrap();
        assert_eq!(value["held"], 2, "the arrival counts the whole batch");
        assert_eq!(value["flow_id"], 9);
        assert_eq!(value["peer"], PEER);
    }

    #[tokio::test]
    async fn every_datagram_from_one_peer_reaches_the_one_flow_it_belongs_to() {
        // The first datagram from a new peer announces an arrival and the rest
        // join the flow it created, rather than announcing the same peer again.
        // Which of the three the daemon holds and which it delivers depends on
        // when the listener's task wins its hop, so the test asserts what does
        // not depend on that: three datagrams, one flow, in order.
        let (mut connection, _outbound) = connect();
        let (_value, listener) = listen(&mut connection, 4242).await;
        let arrive = arrival(5000, 4242, "aa");

        for _ in 0..3 {
            let value = ask(&mut connection, &arrive).await;
            let outcome = value["data"]["outcome"].as_str().unwrap();
            assert!(
                ["announced", "held", "delivered"].contains(&outcome),
                "a datagram from a peer with a listener on its port was {outcome}"
            );
        }

        let (message, mut client) = accept(&listener);
        assert_eq!(message["local_port"], 4242);

        let mut buf = [0u8; 64];
        for _ in 0..3 {
            assert_eq!(client.read(&mut buf).unwrap(), 1);
            assert_eq!(buf[0], 0xaa);
        }
    }

    #[tokio::test]
    async fn closing_a_listener_descriptor_unbinds_its_port() {
        let (mut connection, _outbound) = connect();
        let (_value, listener) = listen(&mut connection, 4242).await;
        drop(listener);

        // The unbind is what `close(listen_fd)` means in Berkeley, and the
        // daemon can only observe it by reading its own half. Without the read
        // arm the port is held for the node's lifetime and every attempt below
        // fails.
        for _ in 0..1000 {
            let (response, fd) = connection
                .answer(br#"{"command":"listen","params":{"local_port":4242}}"#)
                .await;
            if serde_json::to_value(response).unwrap()["status"] == "ok" {
                assert!(fd.is_some(), "a rebound listener still gets a descriptor");
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the closed listener never gave its port back");
    }

    #[tokio::test]
    async fn closing_the_rpc_connection_leaves_its_flows_and_listeners_alone() {
        // The property the redesign turns on: the RPC connection is a setup
        // channel and owns nothing. Before, dropping it released every flow and
        // listener it had opened, which is what made a stream that outlived its
        // client object unusable.
        // The registry is shared rather than owned by the serving task,
        // because the count has to be taken while the flow and the listener are
        // still open. A task that reported its count on the way out could only
        // be asked after everything under test had ended.
        let registry = std::sync::Arc::new(std::sync::Mutex::new(Registry::new(limits())));
        let (tx, mut rx) = mpsc::channel::<NativeMessage>(16);
        let serving = std::sync::Arc::clone(&registry);
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                let mut held = serving.lock().unwrap();
                link::serve(&mut held, message, 0, MAX_PAYLOAD);
            }
        });

        let (out_tx, _out_rx) = mpsc::channel::<Outbound>(64);
        let mut connection = Connection::for_test(tx.clone(), out_tx, limits(), true);
        let (_value, _listener) = listen(&mut connection, 4242).await;
        let (_value, _client) = open(
            &mut connection,
            &format!(
                r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242,"local_port":5000}}}}"#
            ),
        )
        .await;

        drop(connection);
        // Both descriptors are still open, so neither the flow nor the listener
        // has any reason to end. Give any release the connection might have
        // sent a chance to be served before the count is taken.
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            registry.lock().unwrap().port_count(),
            2,
            "the flow's port and the listener's port both survive the connection"
        );
    }

    #[tokio::test]
    async fn discarding_a_wired_flow_gives_its_port_back_and_counts_the_drop() {
        // The registry half of the three-part cleanup a listener's task runs
        // when it cannot hand a flow over. Driven directly, because the write
        // failure that triggers it needs a client that has stopped reading.
        let mut registry = Registry::new(limits());
        let (arrivals, _arrivals_rx) = mpsc::channel(4);
        registry.listen(Some(4242), arrivals).unwrap();

        let peer = crate::identity::decode_npub(PEER).unwrap();
        let addr = crate::identity::NodeAddr::from_pubkey(&peer);
        let flow = match registry.deliver(addr, peer, 5000, 4242, 0) {
            super::registry::Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        let (sink, _sink_rx) = mpsc::channel(4);
        let (key, _peer, _held) = registry.accept(flow, sink, 0).unwrap();
        assert_eq!(registry.flow_count(), 1);

        let served = link::serve(
            &mut registry,
            NativeMessage::Discard {
                key,
                reason: super::link::DropReason::ListenerNotReading,
            },
            0,
            MAX_PAYLOAD,
        );
        assert_eq!(
            served,
            link::Served::Discarded(super::link::DropReason::ListenerNotReading),
            "the drop is reported so the node counts it"
        );
        assert_eq!(registry.flow_count(), 0, "the flow is gone");
        assert_eq!(
            registry.port_count(),
            1,
            "only the listener's port is left; the flow shared it and claimed none"
        );
    }

    #[tokio::test]
    async fn a_datagram_for_an_unheld_port_is_dropped() {
        let (mut connection, _outbound) = connect();
        let value = ask(&mut connection, &arrival(5000, 9999, "aa")).await;
        assert_eq!(value["status"], "ok");
        assert!(
            value["data"]["outcome"]
                .as_str()
                .unwrap()
                .starts_with("dropped"),
            "outcome was {}",
            value["data"]["outcome"]
        );
    }

    #[tokio::test]
    async fn inject_writes_separate_datagrams_to_the_client() {
        let (mut connection, _outbound) = connect();
        let (value, mut client) = open(
            &mut connection,
            &format!(r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242}}}}"#),
        )
        .await;
        let flow = value["data"]["flow_id"].as_u64().unwrap();

        let value = ask(
            &mut connection,
            &format!(
                r#"{{"command":"inject","params":{{"flow_id":{flow},"data":"00ff10","repeat":3}}}}"#
            ),
        )
        .await;
        assert_eq!(value["status"], "ok");

        // Three reads of three bytes, not one read of nine.
        let mut buf = [0u8; 64];
        for _ in 0..3 {
            assert_eq!(client.read(&mut buf).unwrap(), 3);
            assert_eq!(&buf[..3], &[0x00, 0xff, 0x10]);
        }
    }

    #[tokio::test]
    async fn stats_and_inject_refuse_a_flow_the_node_does_not_hold() {
        let (mut connection, _outbound) = connect();
        let value = ask(
            &mut connection,
            r#"{"command":"stats","params":{"flow_id":99}}"#,
        )
        .await;
        assert_eq!(value["status"], "error");
        assert!(value["message"].as_str().unwrap().contains("no such flow"));
        // The errno, not only the prose: a refusal with no code reaches a
        // client as ECONNREFUSED, which reads as the node declining rather than
        // as the flow not existing.
        assert_eq!(value["data"]["errno"], "ENOENT");

        let value = ask(
            &mut connection,
            r#"{"command":"inject","params":{"flow_id":99,"data":"00"}}"#,
        )
        .await;
        assert_eq!(value["status"], "error");
        assert_eq!(value["data"]["errno"], "ENOENT");
    }

    #[tokio::test]
    async fn a_debug_command_naming_a_peer_it_cannot_decode_refuses_with_einval() {
        // The debug commands answer under the same errno contract as the two
        // setup calls. Without a code the reply reaches a client as
        // ECONNREFUSED, which says nothing about the argument that was wrong.
        let (mut connection, _outbound) = wire_connection(true);
        let value = ask(
            &mut connection,
            &arrival_from("not-an-npub", 4242, 5000, "00"),
        )
        .await;

        assert_eq!(value["status"], "error");
        assert!(value["message"].as_str().unwrap().contains("invalid peer"));
        assert_eq!(value["data"]["errno"], "EINVAL");
    }

    /// The three debug command lines, aimed at a flow that really exists.
    ///
    /// Naming a live flow and a live port is what makes the gate tests
    /// discriminating: with the gate open every one of these succeeds, so a
    /// refusal can only have come from the gate.
    fn debug_commands(flow: u64, local: u16) -> [String; 3] {
        [
            format!(r#"{{"command":"inject","params":{{"flow_id":{flow},"data":"00ff10"}}}}"#),
            format!(r#"{{"command":"stats","params":{{"flow_id":{flow}}}}}"#),
            arrival(4242, local, "00"),
        ]
    }

    /// Open a flow and return its identifier, local port and client half.
    async fn open_flow(connection: &mut Connection) -> (u64, u16, StdUnixStream) {
        let (value, client) = open(
            connection,
            &format!(r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242}}}}"#),
        )
        .await;
        let flow = value["data"]["flow_id"].as_u64().unwrap();
        let local = value["data"]["local_port"].as_u64().unwrap() as u16;
        (flow, local, client)
    }

    #[tokio::test]
    async fn every_debug_command_is_refused_when_the_gate_is_closed() {
        let (mut connection, _outbound) = connect_without_debug();
        let (flow, local, _client) = open_flow(&mut connection).await;

        for line in debug_commands(flow, local) {
            let value = ask(&mut connection, &line).await;
            assert_eq!(value["status"], "error", "{line} was not refused");
            let message = value["message"].as_str().unwrap();
            // The key by name, so an operator reading the refusal knows what to
            // change, and so this cannot pass on some unrelated error.
            assert!(
                message.contains("node.native_api.debug_commands"),
                "{line} was refused for the wrong reason: {message}"
            );
        }

        // The gate refuses the command, not the connection: a client that tries
        // one on a node that will not serve it keeps its flows.
        let (value, _listener) = listen(&mut connection, 4243).await;
        assert_eq!(value["status"], "ok");
    }

    #[tokio::test]
    async fn every_debug_command_is_answered_when_the_gate_is_open() {
        let (mut connection, _outbound) = connect();
        let (flow, local, _client) = open_flow(&mut connection).await;

        for line in debug_commands(flow, local) {
            let value = ask(&mut connection, &line).await;
            assert_eq!(value["status"], "ok", "{line} was refused: {value}");
        }

        // The arrival reaches the flow rather than being dropped for want of a
        // port. The harness asserts the same outcome, and would be asserting
        // nothing if a dropped arrival also answered "ok".
        let value = ask(&mut connection, &debug_commands(flow, local)[2]).await;
        assert_eq!(value["data"]["outcome"], "delivered");
    }

    #[tokio::test]
    async fn an_unreasonable_repeat_is_refused() {
        let (mut connection, _outbound) = connect();
        for repeat in ["0", "99999"] {
            let value = ask(
                &mut connection,
                &format!(
                    r#"{{"command":"inject","params":{{"flow_id":1,"data":"00","repeat":{repeat}}}}}"#
                ),
            )
            .await;
            assert_eq!(value["status"], "error");
            assert!(value["message"].as_str().unwrap().contains("repeat"));
        }
    }

    #[tokio::test]
    async fn closing_the_descriptor_is_seen_by_the_daemon() {
        let (mut connection, _outbound) = connect();
        let (value, client) = open(
            &mut connection,
            &format!(r#"{{"command":"connect","params":{{"peer":"{PEER}","remote_port":4242}}}}"#),
        )
        .await;
        let flow = value["data"]["flow_id"].as_u64().unwrap();

        drop(client);
        connection.settle_closed(flow).await;

        // The node forgets a flow whose descriptor closed, so `stats` answers
        // for it the way it answers for any other name it does not hold.
        let value = ask(
            &mut connection,
            &format!(r#"{{"command":"stats","params":{{"flow_id":{flow}}}}}"#),
        )
        .await;
        assert_eq!(value["status"], "error");
    }

    #[tokio::test]
    async fn the_command_size_cap_holds_on_both_read_paths() {
        use super::unix_impl::{MAX_COMMAND, read_command};
        use tokio::io::BufReader;

        // With a newline in the same chunk, and with none at all: both branches
        // must refuse, or the guard only works for inputs that split the way it
        // expects.
        for input in [
            format!("{}\n", "x".repeat(MAX_COMMAND + 1)),
            "x".repeat(MAX_COMMAND + 1),
        ] {
            let mut reader = BufReader::new(input.as_bytes());
            let mut line = Vec::new();
            let error = read_command(&mut reader, &mut line).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }

        // And the healthy path: a command at exactly the cap is accepted.
        let ok = format!("{}\n", "x".repeat(MAX_COMMAND));
        let mut reader = BufReader::new(ok.as_bytes());
        let mut line = Vec::new();
        assert!(read_command(&mut reader, &mut line).await.unwrap());
        assert_eq!(line.len(), MAX_COMMAND);
    }

    #[tokio::test]
    async fn two_commands_on_one_connection_are_read_in_turn() {
        use super::unix_impl::read_command;
        use tokio::io::BufReader;

        let input = "{\"command\":\"listen\"}\n{\"command\":\"stats\"}\n";
        let mut reader = BufReader::new(input.as_bytes());
        let mut line = Vec::new();

        assert!(read_command(&mut reader, &mut line).await.unwrap());
        assert_eq!(line, br#"{"command":"listen"}"#);
        assert!(read_command(&mut reader, &mut line).await.unwrap());
        assert_eq!(line, br#"{"command":"stats"}"#);
        assert!(!read_command(&mut reader, &mut line).await.unwrap());
    }
}
