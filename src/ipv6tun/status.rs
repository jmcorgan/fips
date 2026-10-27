//! What the IPv6 adapter reports about itself, and the socket it answers on.
//!
//! The adapter's TUN and DNS starts and stops publish what they change on a
//! watch, and [`StatusSource::read`] assembles an [`Ipv6TunStatus`] from it
//! when asked, reading the IPv6 MTU the node last published and the queue's
//! drop count as they are at that moment. The adapter's own status socket
//! answers `show_status` with its keys of the node's status, and
//! `show_listening_sockets`. That socket sits beside the node's control
//! socket, at the path [`crate::config::ipv6tun_socket`] derives from it, and
//! is bound only while the control socket is. `fipsctl` and `fipstop` merge
//! its answer into the node's with [`crate::control::compose`].
//!
//! The listening-sockets panel is the sockets reachable on the TUN, each
//! classified against the loaded `inet fips` firewall. [`listening`]
//! gathers the host facts and [`render`] turns them into the reply, with no
//! I/O of its own.

use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use portable_atomic::AtomicU64;
use serde_json::{Value, json};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::core::MeshState;
use super::firewall_state::FilterClassifier;
use super::listening::{ListeningSocket, enumerate};
use super::tun::TunState;
use crate::control::protocol::{Request, Response};

/// What the IPv6 adapter reports about itself, as read at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6TunStatus {
    /// The TUN device's state.
    pub tun_state: TunState,
    /// Kernel name of the TUN device this node created, while one is up.
    pub tun_name: Option<String>,
    /// The node-wide IPv6 MTU, from the payload limit the node last
    /// published to the adapter.
    pub effective_ipv6_mtu: u16,
    /// Where the `.fips` DNS responder listens, while it runs.
    pub dns_local_addr: Option<SocketAddr>,
    /// Packets toward the host dropped on a full queue since the current
    /// queue came up: the TUN writer's, or an embedder's TUN channel.
    pub host_drops: u64,
}

/// What the adapter's TUN and DNS starts and stops change, as they publish
/// it.
#[derive(Clone, Debug)]
pub(crate) struct Shown {
    /// The TUN device's state.
    pub(crate) tun_state: TunState,
    /// The TUN device's kernel name, while one is up.
    pub(crate) tun_name: Option<String>,
    /// The DNS responder's bound address, while it runs.
    pub(crate) dns_local_addr: Option<SocketAddr>,
    /// The drop count of the queue toward the host, while there is one.
    pub(crate) drops: Option<Arc<AtomicU64>>,
}

/// Where the status socket reads the adapter's status: what its starts and
/// stops published, and the state the node's messages left, for the MTU.
#[derive(Clone)]
pub(crate) struct StatusSource {
    /// What the adapter's starts and stops published.
    pub(crate) shown: watch::Receiver<Shown>,
    /// The state the node's messages left, for the MTU.
    pub(crate) mesh: MeshState,
}

impl StatusSource {
    /// The adapter's status now.
    pub(crate) fn read(&self) -> Ipv6TunStatus {
        let shown = self.shown.borrow();
        Ipv6TunStatus {
            tun_state: shown.tun_state,
            tun_name: shown.tun_name.clone(),
            effective_ipv6_mtu: self.mesh.ipv6_mtu(),
            dns_local_addr: shown.dns_local_addr,
            host_drops: shown
                .drops
                .as_ref()
                .map_or(0, |drops| drops.load(Ordering::Relaxed)),
        }
    }
}

/// The adapter's reply to `show_status`: its keys of the node's status, and
/// the count of packets dropped toward the host.
pub(crate) fn render_status(status: &Ipv6TunStatus) -> Value {
    json!({
        "tun_state": status.tun_state.to_string(),
        "tun_name": status.tun_name.as_deref().unwrap_or("-"),
        "effective_ipv6_mtu": status.effective_ipv6_mtu,
        "host_drops": status.host_drops,
    })
}

/// What the status socket answers from: the status, our mesh address, and
/// the configured TUN name the panel falls back to while no TUN is up.
#[derive(Clone)]
pub(crate) struct Responder {
    /// The adapter's status.
    pub(crate) source: StatusSource,
    /// Our mesh address.
    pub(crate) fips0: Ipv6Addr,
    /// The configured TUN name (`tun.name`).
    pub(crate) configured: String,
}

impl Responder {
    /// Answer one request to the adapter's status socket.
    pub(crate) fn answer(&self, request: &Request) -> Response {
        match request.command.as_str() {
            "show_status" => Response::ok(render_status(&self.source.read())),
            "show_listening_sockets" => Response::ok(listening(self.fips0, &self.panel_tun())),
            command => Response::error(format!("unknown command: {command}")),
        }
    }

    /// The TUN the listening panel reports on: the one up, or the configured
    /// name while none is.
    pub(crate) fn panel_tun(&self) -> String {
        self.source
            .read()
            .tun_name
            .unwrap_or_else(|| self.configured.clone())
    }
}

/// Bind the adapter's status socket beside the control socket at `control`
/// and answer on it until the runtime ends. Logs and returns when no path
/// follows from `control` or the bind fails.
pub(crate) async fn serve(control: String, responder: Responder) {
    let Some(path) = crate::config::ipv6tun_socket(Path::new(&control)) else {
        warn!(
            control = %control,
            "No IPv6 adapter status socket path follows from the control socket path"
        );
        return;
    };
    let listener = match Listener::bind(path) {
        Ok(listener) => listener,
        Err(e) => {
            warn!(error = %e, "Failed to bind IPv6 adapter status socket");
            return;
        }
    };
    loop {
        let stream = match listener.accept().await {
            Ok(Some(stream)) => stream,
            Ok(None) => continue,
            Err(e) => {
                warn!(error = %e, "IPv6 adapter status socket accept failed");
                continue;
            }
        };
        let responder = responder.clone();
        tokio::spawn(async move {
            let answer = |request: Request| async move { responder.answer(&request) };
            match crate::control::serve(stream, answer).await {
                Ok(true) => {}
                Ok(false) => debug!("IPv6 adapter status socket write failed or timed out"),
                Err(e) => debug!(error = %e, "IPv6 adapter status connection error"),
            }
        });
    }
}

/// The status socket's listener: a Unix socket under the FIPS access
/// policy, with the control socket's mode and group, removed when dropped.
#[cfg(unix)]
struct Listener {
    /// The bound socket.
    inner: tokio::net::UnixListener,
    /// Its path, for removal.
    path: PathBuf,
}

#[cfg(unix)]
impl Listener {
    /// Bind at `path`.
    fn bind(path: PathBuf) -> std::io::Result<Self> {
        let inner = crate::utils::sockbind::bind(&path, "IPv6 adapter status")?;
        info!(path = %path.display(), "IPv6 adapter status socket listening");
        Ok(Self { inner, path })
    }

    /// The next client.
    async fn accept(&self) -> std::io::Result<Option<tokio::net::UnixStream>> {
        Ok(Some(self.inner.accept().await?.0))
    }
}

#[cfg(unix)]
impl Drop for Listener {
    /// Remove the socket file.
    fn drop(&mut self) {
        crate::utils::sockbind::cleanup(&self.path, "IPv6 adapter status");
    }
}

/// The status socket's listener: TCP on localhost, at the port the path
/// names. Like the control port, any local user can reach it.
#[cfg(windows)]
struct Listener {
    /// The bound socket.
    inner: tokio::net::TcpListener,
}

#[cfg(windows)]
impl Listener {
    /// Bind on localhost at the port `path` names.
    fn bind(path: PathBuf) -> std::io::Result<Self> {
        let port: u16 = path
            .to_string_lossy()
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let std_listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))?;
        std_listener.set_nonblocking(true)?;
        let inner = tokio::net::TcpListener::from_std(std_listener)?;
        info!(port, "IPv6 adapter status socket listening on localhost");
        Ok(Self { inner })
    }

    /// The next client, or `None` for one not on localhost.
    async fn accept(&self) -> std::io::Result<Option<tokio::net::TcpStream>> {
        let (stream, addr) = self.inner.accept().await?;
        if !addr.ip().is_loopback() {
            warn!(addr = %addr, "Rejected non-localhost IPv6 adapter status connection");
            return Ok(None);
        }
        Ok(Some(stream))
    }
}

/// The listening-sockets panel for the TUN `tun` and our mesh address
/// `fips0`: enumerate the sockets reachable on it, query the loaded
/// firewall, and render both.
pub(crate) fn listening(fips0: Ipv6Addr, tun: &str) -> Value {
    let sockets = enumerate(fips0);
    let classifier = FilterClassifier::query();
    render(&classifier, tun, fips0, &sockets)
}

/// Classify each socket against the loaded firewall baseline and build the
/// panel's reply.
///
/// A loaded table that does not police `tun` (scoped to another interface,
/// or scoped in a way the classifier cannot read) protects nothing on the
/// TUN, so the reply reports it exactly as if no table were loaded.
pub(crate) fn render(
    classifier: &FilterClassifier,
    tun: &str,
    fips0: Ipv6Addr,
    sockets: &[ListeningSocket],
) -> Value {
    let unpoliced = FilterClassifier::no_firewall();
    let classifier = if classifier.polices(tun) {
        classifier
    } else {
        &unpoliced
    };
    let rows: Vec<Value> = sockets
        .iter()
        .map(|s| {
            let filter = classifier.classify(s.proto, s.port);
            json!({
                "proto": s.proto.as_str(),
                "local_addr": s.local_addr.to_string(),
                "port": s.port,
                "pid": s.pid,
                "process": s.process,
                "filter": filter.as_str(),
                "wildcard_bind": s.wildcard_bind,
            })
        })
        .collect();

    json!({
        "fips0_addr": fips0.to_string(),
        "firewall_active": classifier.is_active(),
        "sockets": rows,
    })
}

#[cfg(test)]
#[path = "tests/status.rs"]
mod tests;
