//! Tests for `../io_macos.rs`: the BPF ioctl request numbers, checked against
//! the `<sys/ioccom.h>` encoding of their `<net/bpf.h>` definitions.

use super::*;

/// `_IOW(group, num, type)` from `<sys/ioccom.h>`: `IOC_IN`, then the size of
/// the argument in bits 16 to 28, the group in bits 8 to 15 and the number in
/// bits 0 to 7.
const fn iow(group: u8, num: u8, len: usize) -> libc::c_ulong {
    const IOC_IN: libc::c_ulong = 0x8000_0000;
    const IOCPARM_MASK: libc::c_ulong = 0x1fff;
    IOC_IN
        | ((len as libc::c_ulong & IOCPARM_MASK) << 16)
        | ((group as libc::c_ulong) << 8)
        | num as libc::c_ulong
}

const UINT: usize = std::mem::size_of::<libc::c_uint>();

// These are evaluated when the test target compiles, not when it runs, so the
// macOS cross-check on Linux catches a wrong request number that no Linux test
// run can reach.

// The encoder reproduces the two `_IOW(..., u_int)` requests already proven on
// a Mac, so the check below is not an encoder agreeing with itself.
const _: () = assert!(BIOCIMMEDIATE == iow(b'B', 112, UINT));
const _: () = assert!(BIOCSHDRCMPLT == iow(b'B', 117, UINT));

const _: () = assert!(BIOCSSEESENT == iow(b'B', 119, UINT));
