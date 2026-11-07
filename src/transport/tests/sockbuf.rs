//! Socket buffer sizing: forced first, plain as the fallback.

use super::*;
use std::os::unix::io::AsRawFd;

/// 2 MB, the transports' default request and well above the default
/// `net.core` ceilings.
const ASK: usize = 2 * 1024 * 1024;

fn udp_socket() -> std::net::UdpSocket {
    std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket")
}

/// What the plain option alone gives a fresh socket for `ASK`.
fn plain_only(which: Buffer) -> usize {
    let socket = udp_socket();
    setsockopt_int(socket.as_raw_fd(), which.plain(), ASK as libc::c_int).unwrap();
    getsockopt_int(socket.as_raw_fd(), which.plain()).unwrap() as usize
}

#[test]
fn a_sized_buffer_is_never_smaller_than_the_plain_option_alone_gives() {
    // Holds with or without CAP_NET_ADMIN: forced, the grant is the request;
    // refused, the fallback is the plain option itself.
    for which in [Buffer::Recv, Buffer::Send] {
        let socket = udp_socket();
        let granted = set_buffer(socket.as_raw_fd(), which, ASK).unwrap();
        assert_eq!(granted.requested, ASK);
        assert!(
            granted.actual >= plain_only(which),
            "{which:?}: granted {} is below the plain option's {}",
            granted.actual,
            plain_only(which)
        );
        assert_eq!(
            granted.actual,
            getsockopt_int(socket.as_raw_fd(), which.plain()).unwrap() as usize,
            "{which:?}: the grant must be what the kernel reports"
        );
    }
}

#[test]
fn a_buffer_held_below_the_request_reads_as_clamped() {
    // The kernel's default ceiling, doubled, against a 2 MB request: the
    // Ethernet socket's size before its buffers were forced.
    let capped = Granted {
        requested: ASK,
        actual: 425_984,
    };
    assert!(capped.clamped());
    // Linux reports twice what it accepted, so a forced grant reads high.
    let forced = Granted {
        requested: ASK,
        actual: 2 * ASK,
    };
    assert!(!forced.clamped());
}

#[test]
fn a_descriptor_that_is_not_a_socket_is_an_error() {
    assert!(set_buffer(-1, Buffer::Recv, ASK).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn with_cap_net_admin_a_buffer_is_granted_past_the_kernel_ceiling() {
    let ceiling: usize = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let ask = 4 * ceiling;
    let socket = udp_socket();
    let probe = setsockopt_int(socket.as_raw_fd(), libc::SO_RCVBUFFORCE, ask as libc::c_int);
    if probe.is_err() {
        // Unprivileged: forcing is refused, and the test above covers the
        // fallback. Loud on a runner that claims privilege.
        assert!(
            std::env::var_os("FIPS_TEST_PRIVILEGED").is_none(),
            "this runner declares FIPS_TEST_PRIVILEGED but SO_RCVBUFFORCE was \
             refused: {probe:?}"
        );
        return;
    }
    let socket = udp_socket();
    let granted = set_buffer(socket.as_raw_fd(), Buffer::Recv, ask).unwrap();
    assert_eq!(
        granted.actual,
        2 * ask,
        "forcing should grant the request past rmem_max ({ceiling})"
    );
    assert!(!granted.clamped());
}
