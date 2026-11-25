//! The pump: the one task that owns the rendezvous machine.
//!
//! It reads its feeds with no preference among them, so a flood on one
//! cannot starve another: its inbox, where the node's handle, the relay
//! client's authenticator and the pump's own operations post; the relay
//! client's notification stream; the signal router's channel, which only
//! traversal signals are put on; the machine's sockets' datagrams; and the
//! machine's next deadline. Each input is handed to the machine with the
//! step's clock readings; the status the node reads is then stored when it
//! changed, and only after that is every action the machine queued carried
//! out, so a reply never arrives ahead of the status it describes.
//!
//! Carrying out an action never awaits I/O: each relay call, host-name
//! lookup and read of the host's interfaces runs in a task of its own, held
//! in a `JoinSet` and aborted when the pump ends, that posts its result
//! back to the inbox. That is what lets a relay's authentication
//! challenge, which the machine answers, arrive while a relay call is in
//! flight. The machine's UDP sockets are `sockets.rs`'s, each read by a
//! task of its own.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::ops::ControlFlow;
use std::sync::Arc;

use arc_swap::ArcSwap;
use futures::StreamExt;
use nostr::event::{Event, Kind};
use nostr::message::SubscriptionId;
use nostr::types::RelayUrl;
use nostr_sdk::client::ClientNotification;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinSet;

use super::log::{self, FirstEvent};
use super::machine::adverts::assemble::AdvertTransportSnapshot;
use super::machine::error::Error as MachineError;
use super::machine::rendezvous::status::Status;
use super::machine::rendezvous::{
    Action, ConnectId, Input, Interfaces, Now, Outcome, PeerKey, Read, Rendezvous, Reply, ReplyId,
    SubId,
};
use super::relay::{Notifications, RelayClient};
use super::runtime::{Feed, received};
use super::sockets::{DATAGRAM_BACKLOG, Datagram, Sockets};
use super::traversal::now_ms;
#[cfg(test)]
use super::types::CachedOverlayAdvert;
use super::types::{
    ADVERT_KIND, BootstrapEvent, FailureReply, NostrRefetchOutcome, OverlayEndpointAdvert,
    SIGNAL_KIND,
};
use crate::config::PeerConfig;
use crate::identity::OsEntropy;
use crate::node::handoff::EstablishedTraversal;
use crate::time::HostInstant;

/// What the rest of the shell posts to the pump: an input as it is, or a
/// request with the channel its answer goes back on.
#[derive(Debug)]
pub(super) enum Msg {
    Input(Input),
    Auth {
        relay: RelayUrl,
        challenge: String,
        tx: oneshot::Sender<Result<Event, MachineError>>,
    },
    Assemble {
        snapshot: Vec<AdvertTransportSnapshot>,
        tx: oneshot::Sender<()>,
    },
    Endpoints {
        key: PeerKey,
        tx: oneshot::Sender<Result<Vec<OverlayEndpointAdvert>, MachineError>>,
    },
    Connect {
        peer_config: PeerConfig,
    },
    RecordFailure {
        npub: String,
        tx: oneshot::Sender<FailureReply>,
    },
    CachedEndpoints {
        npub: String,
        tx: oneshot::Sender<Option<Vec<OverlayEndpointAdvert>>>,
    },
    OpenDiscovery {
        max: usize,
        skip: BTreeSet<String>,
        tx: oneshot::Sender<Vec<(String, Vec<OverlayEndpointAdvert>, u64)>>,
    },
    Refetch {
        key: PeerKey,
        tx: oneshot::Sender<NostrRefetchOutcome>,
    },
    #[cfg(test)]
    Settle {
        tx: oneshot::Sender<()>,
    },
    #[cfg(test)]
    Inspect {
        npub: String,
        tx: oneshot::Sender<super::machine::rendezvous::io::Inspection>,
    },
    #[cfg(test)]
    InsertAdvert {
        npub: String,
        advert: CachedOverlayAdvert,
        tx: oneshot::Sender<()>,
    },
    #[cfg(test)]
    AwaitAnswer {
        nonce: String,
        tx: oneshot::Sender<()>,
    },
}

/// The pump's inbox.
pub(super) type Inbox = mpsc::UnboundedSender<Msg>;

/// Post a request built by `make` and await its answer: `None` when the
/// pump has gone, so the request was not delivered or not answered.
pub(super) async fn ask<T>(
    inbox: &Inbox,
    make: impl FnOnce(oneshot::Sender<T>) -> Msg,
) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    inbox.send(make(tx)).ok()?;
    rx.await.ok()
}

/// The step's clock readings. The monotonic one is tokio's clock, which
/// reads the host's monotonic clock unless a test has paused it; a paused
/// clock must move the machine's deadlines, or the pump would wake at once
/// for a deadline the host clock has not reached.
pub(super) fn now() -> Now<HostInstant> {
    Now {
        mono: HostInstant::from(tokio::time::Instant::now().into_std()),
        unix_ms: now_ms(),
    }
}

/// Sleep until `deadline`, or forever when there is none.
async fn sleep_until(deadline: Option<HostInstant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at.into())).await,
        None => std::future::pending().await,
    }
}

/// Completes one request with the machine's answer. A payload of the wrong
/// kind would be a machine bug; it is dropped, and the requester sees the
/// pump's empty answer.
type Replier = Box<dyn FnOnce(Reply) + Send>;

/// What the pump hands the node: the events it drains, and the status its
/// synchronous queries read.
pub(super) struct ToNode {
    pub(super) events: mpsc::UnboundedSender<BootstrapEvent>,
    pub(super) status: Arc<ArcSwap<Status>>,
}

/// The pump's state: the machine, the relay client, the answers owed, and
/// the operations in flight.
pub(super) struct Pump {
    machine: Rendezvous<HostInstant, OsEntropy>,
    client: RelayClient,
    inbox: Inbox,
    replies: HashMap<ReplyId, Replier>,
    next_reply: u64,
    /// The relay subscription id each of the machine's subscriptions was
    /// first opened under, so a retry reuses it.
    subscriptions: HashMap<SubId, SubscriptionId>,
    tasks: JoinSet<()>,
    /// The machine's UDP sockets.
    sockets: Sockets,
    /// What the sockets read.
    datagrams: mpsc::Receiver<Datagram>,
    /// The configuration of each connect the node asked for, for the
    /// failure event it may end with.
    connects: HashMap<ConnectId, PeerConfig>,
    next_connect: u64,
    to_node: ToNode,
    first: FirstEvent,
    #[cfg(test)]
    in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// Counts a spawned operation in flight until it is dropped, finished or
/// aborted.
#[cfg(test)]
struct InFlight(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl InFlight {
    fn new(count: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(count)
    }
}

#[cfg(test)]
impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Pump {
    /// A pump for `machine`, carrying out its relay operations on `client`
    /// and posting their results to `inbox`.
    pub(super) fn new(
        machine: Rendezvous<HostInstant, OsEntropy>,
        client: RelayClient,
        inbox: Inbox,
        to_node: ToNode,
    ) -> Self {
        let (datagram_tx, datagrams) = mpsc::channel(DATAGRAM_BACKLOG);
        Self {
            sockets: Sockets::new(datagram_tx, inbox.clone()),
            datagrams,
            machine,
            client,
            inbox,
            replies: HashMap::new(),
            next_reply: 1,
            subscriptions: HashMap::new(),
            tasks: JoinSet::new(),
            connects: HashMap::new(),
            next_connect: 1,
            to_node,
            first: FirstEvent::new(),
            #[cfg(test)]
            in_flight: Default::default(),
        }
    }

    /// The count of operations in flight, which the test handle reads.
    #[cfg(test)]
    pub(super) fn in_flight(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.in_flight.clone()
    }

    /// Run until the machine is shut down, or the relay client's stream or
    /// the signal router's channel ends. The operations still in flight are
    /// aborted on the way out.
    pub(super) async fn run(
        mut self,
        mut notifications: Notifications,
        mut signals: broadcast::Receiver<ClientNotification>,
        mut rx: mpsc::UnboundedReceiver<Msg>,
    ) {
        log::notify_loop_entered();
        loop {
            self.flush();
            if self.machine.stopped() {
                break;
            }
            let deadline = self.machine.poll_timeout();
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(msg) => {
                        let input = self.accept(msg);
                        self.machine.handle(input, now());
                    }
                    None => break,
                },
                note = notifications.next() => match note {
                    Some(note) => {
                        self.first.note();
                        self.dispatch(note);
                    }
                    None => {
                        log::channel_closed(Feed::Pool);
                        break;
                    }
                },
                // A lag is logged and read past; a closed channel ends the
                // pump, which ends rendezvous as the signal task's end did.
                signal = signals.recv() => match received(signal) {
                    ControlFlow::Continue(Some(note)) => {
                        self.first.note();
                        self.dispatch(note);
                    }
                    ControlFlow::Continue(None) => {}
                    ControlFlow::Break(()) => break,
                },
                Some((socket, src, bytes)) = self.datagrams.recv() => {
                    let input = Input::Datagram { socket, src, bytes };
                    self.machine.handle(input, now());
                }
                Some(_) = self.tasks.join_next(), if !self.tasks.is_empty() => {}
                () = sleep_until(deadline) => self.machine.handle_timeout(now()),
            }
        }
        self.tasks.abort_all();
        self.sockets.close_all();
    }

    /// Store the status the step left, if it changed, then carry out every
    /// action the step queued. The status goes first because a reply
    /// completes a `oneshot` another thread can read at once: a caller that
    /// has awaited one must find the status its reply describes.
    fn flush(&mut self) {
        if let Some(status) = self.machine.take_status() {
            self.to_node.status.store(Arc::new(status));
        }
        while let Some(action) = self.machine.poll_action() {
            self.execute(action);
        }
    }

    /// Hand an event a relay delivered to the machine: an advert, or a
    /// traversal signal. A signal normally arrives on the signal router's
    /// channel; one that ever reached the client's stream is handed over
    /// the same way.
    fn dispatch(&mut self, note: ClientNotification) {
        let ClientNotification::Event {
            relay_url, event, ..
        } = note
        else {
            return;
        };
        if event.kind == Kind::Custom(ADVERT_KIND) || event.kind == Kind::Custom(SIGNAL_KIND) {
            let input = Input::RelayEvent {
                relay: relay_url,
                event,
            };
            self.machine.handle(input, now());
        }
    }

    /// Keep `replier` for the machine's answer, under a fresh reply id.
    fn owe(&mut self, replier: Replier) -> ReplyId {
        let reply = ReplyId(self.next_reply);
        self.next_reply += 1;
        self.replies.insert(reply, replier);
        reply
    }

    /// The input `msg` is, with a reply id for a request.
    fn accept(&mut self, msg: Msg) -> Input {
        match msg {
            Msg::Input(input) => input,
            Msg::Auth {
                relay,
                challenge,
                tx,
            } => Input::AuthChallenge {
                relay,
                challenge,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::Auth(event) = payload {
                        let _ = tx.send(event);
                    }
                })),
            },
            Msg::Assemble { snapshot, tx } => Input::Transports {
                snapshot,
                reply: Some(self.owe(Box::new(move |payload| {
                    if let Reply::Assembled = payload {
                        let _ = tx.send(());
                    }
                }))),
            },
            Msg::Endpoints { key, tx } => Input::Endpoints {
                key,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::Endpoints(result) = payload {
                        let _ = tx.send(result);
                    }
                })),
            },
            Msg::Connect { peer_config } => {
                let connect = ConnectId(self.next_connect);
                self.next_connect += 1;
                let npub = peer_config.npub.clone();
                self.connects.insert(connect, peer_config);
                Input::Connect { npub, connect }
            }
            Msg::RecordFailure { npub, tx } => Input::RecordFailure {
                npub,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::Failure(reply) = payload {
                        let _ = tx.send(reply);
                    }
                })),
            },
            Msg::CachedEndpoints { npub, tx } => Input::CachedEndpoints {
                npub,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::CachedEndpoints(endpoints) = payload {
                        let _ = tx.send(endpoints);
                    }
                })),
            },
            Msg::OpenDiscovery { max, skip, tx } => Input::OpenDiscovery {
                max,
                skip,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::OpenDiscovery(candidates) = payload {
                        let _ = tx.send(candidates);
                    }
                })),
            },
            Msg::Refetch { key, tx } => Input::Refetch {
                key,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::Refetch(outcome) = payload {
                        let _ = tx.send(outcome);
                    }
                })),
            },
            #[cfg(test)]
            Msg::Settle { tx } => Input::Settle {
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::Settled = payload {
                        let _ = tx.send(());
                    }
                })),
            },
            #[cfg(test)]
            Msg::Inspect { npub, tx } => Input::Inspect {
                npub,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::Inspected(inspection) = payload {
                        let _ = tx.send(inspection);
                    }
                })),
            },
            #[cfg(test)]
            Msg::InsertAdvert { npub, advert, tx } => Input::InsertAdvert {
                npub,
                advert,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::Settled = payload {
                        let _ = tx.send(());
                    }
                })),
            },
            #[cfg(test)]
            Msg::AwaitAnswer { nonce, tx } => Input::AwaitAnswer {
                nonce,
                reply: self.owe(Box::new(move |payload| {
                    if let Reply::AnswerRouted = payload {
                        let _ = tx.send(());
                    }
                })),
            },
        }
    }

    /// The relay subscription id for the machine's `sub`: drawn the first
    /// time, as 16 random bytes in 32 hex characters (the shape the client's
    /// own ids have), and the same on every retry.
    fn subscription_id(&mut self, sub: SubId) -> SubscriptionId {
        self.subscriptions
            .entry(sub)
            .or_insert_with(|| {
                let mut bytes = [0u8; 16];
                <OsEntropy as fips_core::entropy::EntropySource>::fill(&mut bytes);
                SubscriptionId::new(hex::encode(bytes))
            })
            .clone()
    }

    /// Run `operation` in a task of its own and post the input it gives.
    fn spawn(&mut self, operation: impl Future<Output = Input> + Send + 'static) {
        let inbox = self.inbox.clone();
        #[cfg(test)]
        let counted = InFlight::new(self.in_flight.clone());
        self.tasks.spawn(async move {
            #[cfg(test)]
            let _counted = counted;
            let input = operation.await;
            let _ = inbox.send(Msg::Input(input));
        });
    }

    /// Carry out `action`. Never awaits: relay calls and observations run in
    /// tasks of their own.
    fn execute(&mut self, action: Action) {
        match action {
            Action::Subscribe { req, subs, timeout } => {
                let client = self.client.clone();
                let subs: Vec<_> = subs
                    .into_iter()
                    .map(|(sub, relays, filter)| (self.subscription_id(sub), relays, filter))
                    .collect();
                self.spawn(async move {
                    let subscribe = async {
                        let mut reached = 0;
                        for (id, relays, filter) in subs {
                            reached += client.subscribe(relays, filter, id).await?;
                        }
                        Ok::<usize, super::relay::Error>(reached)
                    };
                    let outcome = match tokio::time::timeout(timeout, subscribe).await {
                        Ok(Ok(reached)) => Outcome::Ok { reached },
                        Ok(Err(e)) => Outcome::Err(e.to_string()),
                        Err(_) => Outcome::TimedOut,
                    };
                    Input::SubscribeDone { req, outcome }
                });
            }
            Action::Publish {
                req,
                relays,
                event,
                timeout,
            } => {
                let client = self.client.clone();
                self.spawn(async move {
                    let send = client.send(&relays, &event);
                    let sent = match timeout {
                        Some(timeout) => tokio::time::timeout(timeout, send).await.ok(),
                        None => Some(send.await),
                    };
                    let outcome = match sent {
                        Some(Ok(reached)) => Outcome::Ok { reached },
                        Some(Err(e)) => Outcome::Err(e.to_string()),
                        None => Outcome::TimedOut,
                    };
                    Input::PublishDone { req, outcome }
                });
            }
            Action::Fetch {
                req,
                relays,
                filter,
                timeout,
            } => {
                let client = self.client.clone();
                self.spawn(async move {
                    let outcome = client
                        .fetch(relays, filter, timeout)
                        .await
                        .map_err(|e| e.to_string());
                    Input::FetchDone { req, outcome }
                });
            }
            Action::Bind { socket } => {
                // Binding does not wait on the network; its result is the
                // machine's next input, after the actions already queued.
                let input = self.sockets.bind(socket);
                let _ = self.inbox.send(Msg::Input(input));
            }
            Action::Resolve { req, host, port } => {
                self.spawn(async move {
                    match tokio::net::lookup_host((host.as_str(), port)).await {
                        Ok(addrs) => Input::Resolved {
                            req,
                            addrs: addrs.collect(),
                        },
                        Err(e) => Input::ResolveFailed {
                            req,
                            error: e.to_string(),
                        },
                    }
                });
            }
            Action::Send { socket, dst, bytes } => self.sockets.send(socket, dst, bytes),
            Action::Close { socket } => self.sockets.release(socket),
            Action::ReadInterfaces { req, read } => {
                let inbox = self.inbox.clone();
                self.tasks.spawn_blocking(move || {
                    let read = match read {
                        Read::Candidates { port } => super::stun::read_candidates(port),
                        Read::OnLink => Interfaces::OnLink(crate::utils::onlink::read_system()),
                    };
                    let _ = inbox.send(Msg::Input(Input::Interfaces { req, read }));
                });
            }
            Action::Adopt {
                socket,
                session,
                peer_npub,
                remote,
                connect,
            } => {
                if let Some(connect) = connect {
                    self.connects.remove(&connect);
                }
                let events = self.to_node.events.clone();
                self.sockets.adopt(socket, move |socket| {
                    let traversal = EstablishedTraversal::new(session, peer_npub, remote, socket)
                        .with_transport_name("nostr-nat");
                    let _ = events.send(BootstrapEvent::Established { traversal });
                });
            }
            Action::Failed { connect, reason } => {
                if let Some(peer_config) = self.connects.remove(&connect) {
                    let _ = self.to_node.events.send(BootstrapEvent::Failed {
                        peer_config,
                        reason,
                    });
                }
            }
            Action::Release { connect } => {
                self.connects.remove(&connect);
            }
            Action::Reply { reply, payload } => {
                if let Some(replier) = self.replies.remove(&reply) {
                    replier(payload);
                }
            }
            Action::Log(line) => log::render(&line),
        }
    }
}

#[cfg(test)]
#[path = "tests/pump.rs"]
mod tests;
