//! Listening-socket enumeration for the fipstop "Listening on fips0" panel.
//!
//! Walks `/proc/net/tcp6` and `/proc/net/udp6` and pairs each entry with
//! the owning PID/process name (resolved by walking `/proc/<pid>/fd/`).
//! Results are filtered to entries reachable from the fips0 interface —
//! sockets bound to the IPv6 wildcard `::` or to the node's own
//! fd00::/8 address. IPv4 listeners are not enumerated; fips0 is
//! IPv6-only.
//!
//! Linux-only. Non-Linux callers receive an empty vector.
//!
//! See [`crate::control::firewall_state`] for the per-port nftables
//! filter classification that pairs with this enumeration.
//!
//! See `docs/design/fips-security.md` for the operator-side narrative
//! that motivates the panel.

use std::net::{IpAddr, Ipv6Addr};

/// Transport protocol of a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// One listening socket reachable from fips0.
#[derive(Debug, Clone)]
pub struct ListeningSocket {
    pub proto: Proto,
    pub local_addr: Ipv6Addr,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
    /// True when bound to `::` rather than the fips0 address — a hint
    /// that the bind is not fips0-specific (the operator may not have
    /// intended to expose the service over the mesh).
    pub wildcard_bind: bool,
}

/// Enumerate listening IPv6 sockets reachable from fips0.
///
/// On non-Linux targets (where `/proc` does not exist), returns an
/// empty vector.
#[cfg(target_os = "linux")]
pub fn enumerate(fips0_addr: Ipv6Addr) -> Vec<ListeningSocket> {
    use procfs::net::TcpState;

    let inode_to_pid = build_inode_to_pid_map();

    let mut out: Vec<ListeningSocket> = Vec::new();

    if let Ok(entries) = procfs::net::tcp6() {
        for e in entries {
            if e.state != TcpState::Listen {
                continue;
            }
            if let Some(sock) = build_entry(
                Proto::Tcp,
                e.local_address.ip(),
                e.local_address.port(),
                e.inode,
                &inode_to_pid,
                fips0_addr,
            ) {
                out.push(sock);
            }
        }
    }

    if let Ok(entries) = procfs::net::udp6() {
        for e in entries {
            // /proc/net/udp has no dedicated LISTEN state; treat any
            // socket with a wildcard remote as a listener. Connected
            // UDP sockets (the kernel after a connect(2)) carry a
            // non-wildcard remote and are excluded.
            if !e.remote_address.ip().is_unspecified() {
                continue;
            }
            if let Some(sock) = build_entry(
                Proto::Udp,
                e.local_address.ip(),
                e.local_address.port(),
                e.inode,
                &inode_to_pid,
                fips0_addr,
            ) {
                out.push(sock);
            }
        }
    }

    // Stable order: proto, then port, then PID. Helps the UI panel
    // not flicker as kernel re-orders entries between ticks.
    out.sort_by(|a, b| {
        a.proto
            .as_str()
            .cmp(b.proto.as_str())
            .then(a.port.cmp(&b.port))
            .then(a.pid.cmp(&b.pid))
    });
    out
}

#[cfg(not(target_os = "linux"))]
pub fn enumerate(_fips0_addr: Ipv6Addr) -> Vec<ListeningSocket> {
    Vec::new()
}

/// Decide whether a listening socket is reachable from fips0 and, if
/// so, build a [`ListeningSocket`] row for it.
#[cfg(target_os = "linux")]
fn build_entry(
    proto: Proto,
    local: IpAddr,
    port: u16,
    inode: u64,
    inode_to_pid: &std::collections::HashMap<u64, (u32, String)>,
    fips0_addr: Ipv6Addr,
) -> Option<ListeningSocket> {
    let v6 = match local {
        IpAddr::V6(a) => a,
        // procfs emits v4-mapped addresses for AF_INET6 dual-stack
        // sockets bound to 0.0.0.0; treat the prefix as v6 wildcard.
        IpAddr::V4(_) => return None,
    };

    let is_wildcard = v6.is_unspecified();
    let is_fips0_addr = v6 == fips0_addr;

    if !is_wildcard && !is_fips0_addr {
        // Bound to ::1 or to some non-fips0 specific address —
        // not reachable over the mesh.
        return None;
    }

    let (pid, process) = match inode_to_pid.get(&inode) {
        Some((p, c)) => (Some(*p), Some(c.clone())),
        None => (None, None),
    };

    Some(ListeningSocket {
        proto,
        local_addr: v6,
        port,
        pid,
        process,
        wildcard_bind: is_wildcard,
    })
}

/// Build a map of socket inode → (pid, comm) by walking `/proc/<pid>/fd/`.
///
/// Best-effort: processes the daemon cannot read (permission, vanished
/// between listing and stat) are silently skipped, leaving those
/// sockets in the output with `pid: None`.
#[cfg(target_os = "linux")]
fn build_inode_to_pid_map() -> std::collections::HashMap<u64, (u32, String)> {
    use procfs::process::FDTarget;

    let mut map = std::collections::HashMap::new();

    let procs = match procfs::process::all_processes() {
        Ok(p) => p,
        Err(_) => return map,
    };

    for proc_res in procs {
        let process = match proc_res {
            Ok(p) => p,
            Err(_) => continue,
        };
        let stat = match process.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let fds = match process.fd() {
            Ok(f) => f,
            Err(_) => continue,
        };
        for fd_res in fds {
            let fd = match fd_res {
                Ok(f) => f,
                Err(_) => continue,
            };
            if let FDTarget::Socket(inode) = fd.target {
                map.insert(inode, (stat.pid as u32, stat.comm.clone()));
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_as_str() {
        assert_eq!(Proto::Tcp.as_str(), "tcp");
        assert_eq!(Proto::Udp.as_str(), "udp");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enumerate_runs_without_panicking() {
        // The daemon's own listening sockets (control socket is unix,
        // not v6, so it doesn't show up; transports may or may not).
        // Just confirm the call returns and produces a valid (possibly
        // empty) vector.
        let _ = enumerate(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_entry_filters_non_fips0_binds() {
        let inode_map = std::collections::HashMap::new();
        let fips0 = Ipv6Addr::new(0xfd97, 0, 0, 0, 0, 0, 0, 1);

        // Wildcard — accepted.
        let r = build_entry(
            Proto::Tcp,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            22,
            0,
            &inode_map,
            fips0,
        );
        assert!(r.is_some());
        assert!(r.unwrap().wildcard_bind);

        // fips0 address — accepted.
        let r = build_entry(Proto::Tcp, IpAddr::V6(fips0), 22, 0, &inode_map, fips0);
        assert!(r.is_some());
        assert!(!r.unwrap().wildcard_bind);

        // Loopback — rejected.
        let r = build_entry(
            Proto::Tcp,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            22,
            0,
            &inode_map,
            fips0,
        );
        assert!(r.is_none());

        // Different specific address — rejected.
        let other = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let r = build_entry(Proto::Tcp, IpAddr::V6(other), 22, 0, &inode_map, fips0);
        assert!(r.is_none());

        // IPv4 — rejected (fips0 is IPv6-only).
        let r = build_entry(
            Proto::Tcp,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            22,
            0,
            &inode_map,
            fips0,
        );
        assert!(r.is_none());
    }
}
