//! The machine's UDP sockets: binding one, reading its datagrams, sending on
//! it, and closing it, each socket read by a task of its own.
//!
//! A socket is bound on `0.0.0.0:0`, non-blocking, as the advert's public
//! address observation always bound it. Its datagrams go to the pump on one
//! bounded channel shared by every socket; when that channel is full a
//! datagram is dropped, as a full kernel buffer drops one. A receive error,
//! and a send that fails, are reported to the pump's inbox for the machine
//! to judge.

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

/// One bound socket: where its sends go, and the task reading it.
struct Bound {
    sends: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
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
        let std_socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => return failed(BindStage::Bind, e),
        };
        if let Err(e) = std_socket.set_nonblocking(true) {
            return failed(BindStage::NonBlocking, e);
        }
        let local = match std_socket.local_addr() {
            Ok(local) => local,
            Err(e) => return failed(BindStage::LocalAddr, e),
        };
        let udp = match UdpSocket::from_std(std_socket) {
            Ok(udp) => udp,
            Err(e) => return failed(BindStage::NonBlocking, e),
        };
        let (sends, outgoing) = mpsc::unbounded_channel();
        let task = tokio::spawn(run(
            socket,
            udp,
            outgoing,
            self.datagrams.clone(),
            self.inbox.clone(),
        ));
        self.open.insert(socket, Bound { sends, task });
        Input::SocketBound { socket, local }
    }

    /// Send `bytes` to `dst` on `socket`.
    pub(super) fn send(&mut self, socket: SocketId, dst: SocketAddr, bytes: Vec<u8>) {
        if let Some(bound) = self.open.get(&socket) {
            let _ = bound.sends.send((dst, bytes));
        }
    }

    /// Stop reading `socket` and drop it.
    pub(super) fn release(&mut self, socket: SocketId) {
        if let Some(bound) = self.open.remove(&socket) {
            bound.task.abort();
        }
    }

    /// Close every socket.
    pub(super) fn close_all(&mut self) {
        for (_, bound) in self.open.drain() {
            bound.task.abort();
        }
    }
}

/// Read `udp`'s datagrams onto `datagrams` and send what arrives on
/// `outgoing`, until `outgoing` closes or the task is aborted.
async fn run(
    socket: SocketId,
    udp: UdpSocket,
    mut outgoing: mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>,
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
                Err(_) => {
                    let _ = inbox.send(Msg::Input(Input::RecvError { socket }));
                }
            },
            send = outgoing.recv() => match send {
                Some((dst, bytes)) => {
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
