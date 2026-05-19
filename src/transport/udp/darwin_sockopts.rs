// Applied at `ConnectedPeerSocket::open` (dormant in this PR; see
// `connected_peer.rs`). Linux toolchain only checks gates — keep
// the module visible on Linux so clippy doesn't lose track.
#![allow(dead_code)]

//! Darwin UDP socket tuning.
//!
//! macOS does not expose UDP GSO/TSO to userspace tunnels, so high-rate
//! Wi-Fi sends are often limited by per-datagram kernel scheduling. The
//! service type is the one low-cost Darwin hint that can change how the
//! socket is queued by the host networking stack and Wi-Fi WMM.

#![cfg(target_os = "macos")]

use std::io;
use std::os::fd::RawFd;
use std::sync::OnceLock;

use tracing::{debug, warn};

const SO_NET_SERVICE_TYPE: libc::c_int = 0x1116;

const NET_SERVICE_TYPE_BE: libc::c_int = 0;
const NET_SERVICE_TYPE_BK: libc::c_int = 1;
const NET_SERVICE_TYPE_SIG: libc::c_int = 2;
const NET_SERVICE_TYPE_VI: libc::c_int = 3;
const NET_SERVICE_TYPE_VO: libc::c_int = 4;
const NET_SERVICE_TYPE_RV: libc::c_int = 5;
const NET_SERVICE_TYPE_AV: libc::c_int = 6;
const NET_SERVICE_TYPE_OAM: libc::c_int = 7;
const NET_SERVICE_TYPE_RD: libc::c_int = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NetServiceType {
    name: &'static str,
    value: libc::c_int,
}

const VPN_SERVICE_TYPE: NetServiceType = NetServiceType {
    name: "oam",
    value: NET_SERVICE_TYPE_OAM,
};

#[derive(Debug)]
struct Tuning {
    service_type: Option<NetServiceType>,
}

static TUNING: OnceLock<Tuning> = OnceLock::new();

pub(crate) fn apply_udp_socket_tuning(fd: RawFd, context: &'static str) {
    if let Some(service_type) = tuning().service_type {
        match set_sockopt_int(
            fd,
            libc::SOL_SOCKET,
            SO_NET_SERVICE_TYPE,
            service_type.value,
        ) {
            Ok(()) => {
                debug!(
                    context,
                    service_type = service_type.name,
                    value = service_type.value,
                    "set Darwin UDP SO_NET_SERVICE_TYPE"
                );
            }
            Err(err) => {
                warn!(
                    context,
                    service_type = service_type.name,
                    value = service_type.value,
                    %err,
                    "failed to set Darwin UDP SO_NET_SERVICE_TYPE"
                );
            }
        }
    }
}

fn tuning() -> &'static Tuning {
    TUNING.get_or_init(|| {
        let service_type = match std::env::var("FIPS_MACOS_NET_SERVICE_TYPE") {
            Ok(raw) => match parse_net_service_type(&raw) {
                Ok(service_type) => service_type,
                Err(()) => {
                    warn!(
                        value = %raw,
                        default = "off",
                        "invalid FIPS_MACOS_NET_SERVICE_TYPE, using default"
                    );
                    None
                }
            },
            // Apple documents NET_SERVICE_TYPE_OAM as fitting VPN tunnels, but
            // measured MacBook Wi-Fi sends regressed badly with OAM/RD/VI
            // marking in 2026-05 local LAN tests. Leave Darwin UDP sockets at
            // the kernel default unless an experiment opts in via env.
            Err(_) => None,
        };

        Tuning { service_type }
    })
}

fn parse_net_service_type(raw: &str) -> Result<Option<NetServiceType>, ()> {
    let normalized = raw.trim().to_ascii_lowercase().replace(['-', '_'], "");
    let service_type = match normalized.as_str() {
        "" | "off" | "none" | "disabled" | "disable" | "unset" | "default" => None,
        "vpn" | "oam" => Some(VPN_SERVICE_TYPE),
        "be" | "besteffort" => Some(NetServiceType {
            name: "be",
            value: NET_SERVICE_TYPE_BE,
        }),
        "bk" | "background" => Some(NetServiceType {
            name: "bk",
            value: NET_SERVICE_TYPE_BK,
        }),
        "sig" | "signaling" => Some(NetServiceType {
            name: "sig",
            value: NET_SERVICE_TYPE_SIG,
        }),
        "vi" | "interactivevideo" | "video" => Some(NetServiceType {
            name: "vi",
            value: NET_SERVICE_TYPE_VI,
        }),
        "vo" | "interactivevoice" | "voice" => Some(NetServiceType {
            name: "vo",
            value: NET_SERVICE_TYPE_VO,
        }),
        "rv" | "responsivemultimedia" | "responsivemultimediavideo" => Some(NetServiceType {
            name: "rv",
            value: NET_SERVICE_TYPE_RV,
        }),
        "av" | "multimedia" | "audiovideo" => Some(NetServiceType {
            name: "av",
            value: NET_SERVICE_TYPE_AV,
        }),
        "rd" | "responsivedata" => Some(NetServiceType {
            name: "rd",
            value: NET_SERVICE_TYPE_RD,
        }),
        _ => return Err(()),
    };
    Ok(service_type)
}

fn set_sockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_service_type_aliases() {
        assert_eq!(parse_net_service_type("off").unwrap(), None);
        assert_eq!(parse_net_service_type("default").unwrap(), None);
        assert_eq!(
            parse_net_service_type("vpn").unwrap(),
            Some(VPN_SERVICE_TYPE)
        );
        assert_eq!(
            parse_net_service_type("interactive_video").unwrap(),
            Some(NetServiceType {
                name: "vi",
                value: NET_SERVICE_TYPE_VI
            })
        );
        assert_eq!(
            parse_net_service_type("responsive-data").unwrap(),
            Some(NetServiceType {
                name: "rd",
                value: NET_SERVICE_TYPE_RD
            })
        );
        assert!(parse_net_service_type("wat").is_err());
    }
}
