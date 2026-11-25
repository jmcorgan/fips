//! A STUN binding exchange, as a machine: one observation of this host's
//! reflexive address over a list of servers, each tried in turn.
//!
//! For each server the client parses its URL, resolves it (an IP literal
//! needs no lookup), and sends a binding request with a fresh transaction
//! id from the caller's entropy. It retransmits the request from 500 ms,
//! doubling, until the server's deadline, and believes a binding success
//! only from the exact address it asked. The server's wait ends on its
//! deadline, on a receive error, or at once when the first send fails; a
//! failed retransmission leaves the earlier sends in flight and is ignored.
//! The observation ends with the first server that answers, or after the
//! last one fails. The socket, the lookup and the sends are the caller's:
//! the client says what to do with [`Out`] and is told what happened.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use core::marker::PhantomData;
use fips_core::entropy::EntropySource;

use fips_core::time::{Instant, deadline};

use super::{create_stun_binding_request, parse_stun_binding_success, parse_stun_url};

/// The first retransmission interval for a binding request, doubled after
/// each retransmission (RFC 8489 Section 6.2.1).
const INITIAL_RTO: Duration = Duration::from_millis(500);

/// The server address to send a binding request to, from those resolved:
/// the first of the socket's family. A socket cannot send to the other
/// family, so a server with no address of this one is skipped.
pub fn pick_family(
    addrs: impl IntoIterator<Item = SocketAddr>,
    want_v4: bool,
) -> Option<SocketAddr> {
    addrs.into_iter().find(|addr| addr.is_ipv4() == want_v4)
}

/// What the client asks its caller to do, or tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Look `host` up, and report every address it has.
    Resolve { host: String, port: u16 },
    /// Send `bytes` to `dst` on the observation's socket.
    Send { dst: SocketAddr, bytes: Vec<u8> },
    /// A server answered: the reflexive address it reported.
    Succeeded { server: String, mapped: SocketAddr },
    /// A server's wait ended with datagrams from other sources discarded.
    Discarded {
        server: String,
        expected: SocketAddr,
        rejected: u64,
        last_unexpected: Option<SocketAddr>,
    },
    /// Every server failed; the text is the last one's error, as
    /// `BootstrapError` prints it.
    Failed { error: Option<String> },
}

/// Where the current server stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the lookup of the current server.
    Resolving,
    /// The request is out; waiting for the answer.
    Waiting,
    /// The observation has ended.
    Done,
}

/// One observation over a list of STUN servers, drawing its transaction
/// ids from `E`.
#[derive(Debug)]
pub struct Observation<I, E> {
    servers: Vec<String>,
    /// The server being tried.
    index: usize,
    timeout: Duration,
    /// Whether the socket is IPv4.
    want_v4: bool,
    phase: Phase,
    txn: [u8; 12],
    target: Option<SocketAddr>,
    /// The server's deadline, from its first send.
    deadline: Option<I>,
    rto: Duration,
    resend_at: Option<I>,
    rejected: u64,
    last_unexpected: Option<SocketAddr>,
    last_error: Option<String>,
    _entropy: PhantomData<fn() -> E>,
}

impl<I: Instant, E: EntropySource> Observation<I, E> {
    /// An observation over `servers`, giving each `timeout` from its first
    /// send, on a socket of the IPv4 family when `want_v4`.
    pub fn new(servers: Vec<String>, timeout: Duration, want_v4: bool) -> Self {
        Self {
            servers,
            index: 0,
            timeout,
            want_v4,
            phase: Phase::Done,
            txn: [0; 12],
            target: None,
            deadline: None,
            rto: INITIAL_RTO,
            resend_at: None,
            rejected: 0,
            last_unexpected: None,
            last_error: None,
            _entropy: PhantomData,
        }
    }

    /// Start with the first server, at `now`.
    pub fn begin(&mut self, now: I) -> Vec<Out> {
        self.index = 0;
        self.try_server(now)
    }

    /// The next instant at which [`Self::timeout`] is due.
    pub fn deadline(&self) -> Option<I> {
        if self.phase != Phase::Waiting {
            return None;
        }
        match (self.resend_at, self.deadline) {
            (Some(resend), Some(end)) if resend < end => Some(resend),
            (_, end) => end,
        }
    }

    fn server(&self) -> String {
        self.servers[self.index].clone()
    }

    /// Try the server at `self.index`, or end the observation when there is
    /// none left.
    fn try_server(&mut self, now: I) -> Vec<Out> {
        let Some(server) = self.servers.get(self.index).cloned() else {
            self.phase = Phase::Done;
            return alloc::vec![Out::Failed {
                error: self.last_error.take(),
            }];
        };
        let endpoint = match parse_stun_url(&server) {
            Ok(endpoint) => endpoint,
            Err(e) => return self.fail(e.to_string(), now),
        };
        E::fill(&mut self.txn);
        self.target = None;
        self.deadline = None;
        self.resend_at = None;
        self.rto = INITIAL_RTO;
        self.rejected = 0;
        self.last_unexpected = None;
        let host = endpoint
            .host
            .strip_prefix('[')
            .and_then(|trimmed| trimmed.strip_suffix(']'))
            .unwrap_or(&endpoint.host);
        self.phase = Phase::Resolving;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.resolved(alloc::vec![SocketAddr::new(ip, endpoint.port)], now);
        }
        alloc::vec![Out::Resolve {
            host: host.to_string(),
            port: endpoint.port,
        }]
    }

    /// The current server failed with `error`, as `BootstrapError` prints
    /// it; try the next.
    fn fail(&mut self, error: String, now: I) -> Vec<Out> {
        self.last_error = Some(error);
        self.index += 1;
        self.try_server(now)
    }

    /// The current server's wait ended without an answer.
    fn expire(&mut self, now: I) -> Vec<Out> {
        let server = self.server();
        let mut out = Vec::new();
        // One line per server rather than per datagram: a flooder controls
        // the rate.
        if self.rejected > 0
            && let Some(expected) = self.target
        {
            out.push(Out::Discarded {
                server: server.clone(),
                expected,
                rejected: self.rejected,
                last_unexpected: self.last_unexpected,
            });
        }
        out.extend(self.fail(format!("stun failed: timed out waiting for {server}"), now));
        out
    }

    /// The lookup of the current server gave `addrs`.
    pub fn resolved(&mut self, addrs: Vec<SocketAddr>, now: I) -> Vec<Out> {
        if self.phase != Phase::Resolving {
            return Vec::new();
        }
        let Some(target) = pick_family(addrs, self.want_v4) else {
            let server = self.server();
            return self.fail(format!("stun failed: no address for {server}"), now);
        };
        self.target = Some(target);
        self.phase = Phase::Waiting;
        self.deadline = Some(deadline(now, self.timeout));
        self.resend_at = Some(deadline(now, self.rto));
        alloc::vec![Out::Send {
            dst: target,
            bytes: create_stun_binding_request(self.txn).to_vec(),
        }]
    }

    /// The lookup of the current server failed with `error`, the I/O
    /// error's text.
    pub fn resolve_failed(&mut self, error: String, now: I) -> Vec<Out> {
        if self.phase != Phase::Resolving {
            return Vec::new();
        }
        self.fail(format!("io error: {error}"), now)
    }

    /// A datagram from `src` arrived on the socket.
    pub fn datagram(&mut self, src: SocketAddr, bytes: &[u8], now: I) -> Vec<Out> {
        if self.phase != Phase::Waiting {
            return Vec::new();
        }
        if Some(src) != self.target {
            self.rejected += 1;
            self.last_unexpected = Some(src);
            return Vec::new();
        }
        let Some(mapped) = parse_stun_binding_success(bytes, &self.txn) else {
            return Vec::new();
        };
        let _ = now;
        self.phase = Phase::Done;
        alloc::vec![Out::Succeeded {
            server: self.server(),
            mapped,
        }]
    }

    /// Receiving on the socket failed: the current server's wait ends.
    pub fn recv_error(&mut self, now: I) -> Vec<Out> {
        if self.phase != Phase::Waiting {
            return Vec::new();
        }
        self.expire(now)
    }

    /// A send to `dst` failed with `error`, the I/O error's text. The first
    /// send of a server failing ends that server at once; a failed
    /// retransmission leaves the earlier sends in flight.
    pub fn send_failed(&mut self, dst: SocketAddr, error: String, now: I) -> Vec<Out> {
        if self.phase != Phase::Waiting || Some(dst) != self.target || self.rto != INITIAL_RTO {
            return Vec::new();
        }
        self.fail(format!("io error: {error}"), now)
    }

    /// Run what is due at `now`: a retransmission, or the end of the
    /// current server's wait.
    pub fn timeout(&mut self, now: I) -> Vec<Out> {
        if self.phase != Phase::Waiting {
            return Vec::new();
        }
        if self.deadline.is_some_and(|end| now >= end) {
            return self.expire(now);
        }
        match (self.resend_at, self.target) {
            (Some(resend), Some(target)) if now >= resend => {
                self.rto *= 2;
                self.resend_at = Some(deadline(now, self.rto));
                alloc::vec![Out::Send {
                    dst: target,
                    bytes: create_stun_binding_request(self.txn).to_vec(),
                }]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "tests/client.rs"]
mod tests;
