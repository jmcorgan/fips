//! The machine's UDP sockets: binding one, reading its datagrams, sending on
//! it, closing it, and handing a punched one over, each socket read by a
//! task of its own.
//!
//! A socket is bound on `0.0.0.0:0`, non-blocking, as the advert's public
//! address observation and the traversals always bound theirs. Its
//! datagrams go to the pump on one bounded channel shared by every socket;
//! when that channel is full a datagram is dropped, as a full kernel buffer
//! drops one. A receive error, and a send that fails, are reported to the
//! pump's inbox for the machine to judge. A socket a traversal adopts stops
//! being read and is handed over whole: a datagram the task read after the
//! machine's decision is dropped, and the peer's handshake retransmits.

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::machine::rendezvous::{BindStage, Input, SocketId};
use super::pump::{Inbox, Msg};

/// How many datagrams the sockets may have waiting for the pump.
pub(super) const DATAGRAM_BACKLOG: usize = 1024;

/// A datagram one of the sockets read: the socket, its source and bytes.
pub(super) type Datagram = (SocketId, SocketAddr, Vec<u8>);

/// The largest datagram read whole; a longer one is cut, as STUN answers
/// and punch packets never are.
const DATAGRAM_MAX: usize = 2048;

/// What hands a punched socket over, once the sends queued ahead of it
/// have gone out.
type HandOver = Box<dyn FnOnce(std::net::UdpSocket) + Send>;

/// What a socket's task is asked to do, in the order it is asked.
enum Command {
    /// Send the bytes to the address.
    Send(SocketAddr, Vec<u8>),
    /// Stop reading and hand the socket over.
    Adopt(HandOver),
}

/// One bound socket: where its commands go, and the task reading it.
struct Bound {
    commands: mpsc::UnboundedSender<Command>,
    task: JoinHandle<()>,
}

/// The machine's open sockets.
pub(super) struct Sockets {
    open: HashMap<SocketId, Bound>,
    datagrams: mpsc::Sender<Datagram>,
    inbox: Inbox,
}

impl Sockets {
    /// No sockets yet; datagrams go to `datagrams`, errors to `inbox`.
    pub(super) fn new(datagrams: mpsc::Sender<Datagram>, inbox: Inbox) -> Self {
        Self {
            open: HashMap::new(),
            datagrams,
            inbox,
        }
    }

    /// Bind `socket` and start reading it. Returns the input that reports
    /// how that went.
    pub(super) fn bind(&mut self, socket: SocketId) -> Input {
        let failed = |stage, error: std::io::Error| Input::BindFailed {
            socket,
            stage,
            error: error.to_string(),
        };
        let std_socket = match bind_on("0.0.0.0:0".parse().expect("an address")) {
            Ok(s) => s,
            Err((stage, e)) => return failed(stage, e),
        };
        let local = match std_socket.local_addr() {
            Ok(local) => local,
            Err(e) => return failed(BindStage::LocalAddr, e),
        };
        let udp = match UdpSocket::from_std(std_socket) {
            Ok(udp) => udp,
            Err(e) => return failed(BindStage::NonBlocking, e),
        };
        let (commands, outgoing) = mpsc::unbounded_channel();
        let task = tokio::spawn(run(
            socket,
            udp,
            outgoing,
            self.datagrams.clone(),
            self.inbox.clone(),
        ));
        self.open.insert(socket, Bound { commands, task });
        Input::SocketBound { socket, local }
    }

    /// Send `bytes` to `dst` on `socket`.
    pub(super) fn send(&mut self, socket: SocketId, dst: SocketAddr, bytes: Vec<u8>) {
        if let Some(bound) = self.open.get(&socket) {
            let _ = bound.commands.send(Command::Send(dst, bytes));
        }
    }

    /// Stop reading `socket` and drop it.
    pub(super) fn release(&mut self, socket: SocketId) {
        if let Some(bound) = self.open.remove(&socket) {
            bound.task.abort();
        }
    }

    /// Stop reading `socket` and pass it to `hand_over`, once every send
    /// asked of it before has gone out: the ack to the probe a traversal
    /// adopts is what lets the peer adopt in turn.
    pub(super) fn adopt(
        &mut self,
        socket: SocketId,
        hand_over: impl FnOnce(std::net::UdpSocket) + Send + 'static,
    ) {
        if let Some(bound) = self.open.remove(&socket) {
            let _ = bound.commands.send(Command::Adopt(Box::new(hand_over)));
        }
    }

    /// Close every socket.
    pub(super) fn close_all(&mut self) {
        for (_, bound) in self.open.drain() {
            bound.task.abort();
        }
    }
}

/// A UDP socket bound on `addr`, non-blocking, as the machine's sockets
/// are made, or the step that failed and its error.
///
/// On Windows an ICMP port-unreachable answering one of its datagrams is
/// not reported as a receive error, as on the UDP transport's sockets, so a
/// closed punch target cannot fail the receives the peer's probe arrives
/// on.
pub(super) fn bind_on(
    addr: SocketAddr,
) -> Result<std::net::UdpSocket, (BindStage, std::io::Error)> {
    let socket = std::net::UdpSocket::bind(addr).map_err(|e| (BindStage::Bind, e))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| (BindStage::NonBlocking, e))?;
    #[cfg(windows)]
    crate::transport::udp::io::ignore_port_unreachable(&socket);
    Ok(socket)
}

/// Read `udp`'s datagrams onto `datagrams` and carry out what arrives on
/// `outgoing`, in order, until it hands the socket over, `outgoing` closes
/// or the task is aborted.
async fn run(
    socket: SocketId,
    udp: UdpSocket,
    mut outgoing: mpsc::UnboundedReceiver<Command>,
    datagrams: mpsc::Sender<Datagram>,
    inbox: Inbox,
) {
    let mut buf = vec![0u8; DATAGRAM_MAX];
    loop {
        tokio::select! {
            received = udp.recv_from(&mut buf) => match received {
                Ok((len, src)) => {
                    let _ = datagrams.try_send((socket, src, buf[..len].to_vec()));
                }
                Err(e) => {
                    let error = format!("{e:?}");
                    let _ = inbox.send(Msg::Input(Input::RecvError { socket, error }));
                }
            },
            command = outgoing.recv() => match command {
                Some(Command::Adopt(hand_over)) => {
                    if let Ok(adopted) = udp.into_std() {
                        hand_over(adopted);
                    }
                    break;
                }
                Some(Command::Send(dst, bytes)) => {
                    if let Err(e) = udp.send_to(&bytes, dst).await {
                        let _ = inbox.send(Msg::Input(Input::SendFailed {
                            socket,
                            dst,
                            error: e.to_string(),
                        }));
                    }
                }
                None => break,
            },
        }
    }
}

#[cfg(test)]
#[path = "tests/sockets.rs"]
mod tests;
