#!/usr/bin/env python3
# ── Serial-console driver for the FreeBSD 16 build VM ───────────────────────
# The official 16.0-CURRENT VM image has no sshd enabled and no way to enable
# it from outside: its root filesystem is UFS, which Linux cannot safely write.
# What the image does have is a root account with an empty password (PAM's
# nullok accepts it without a prompt) and, once freebsd16-vm.sh has told the
# EFI loader console=comconsole through the ESP's loader.env, a getty on the
# serial port. This script logs in there, runs the setup script the same
# freebsd16-vm.sh placed on the ESP, and logs out again. sshd is reachable
# from then on and the console is not used any further.
#
# Every byte the driver reads is appended to its log file; qemu's own logfile
# on the same chardev holds the complete transcript, from power-on.
#
# Usage: freebsd16-console.py <console unix socket> <console log> <boot timeout s>
#
# Exit 0 = logged in, setup script returned 0. Exit 1 = no login prompt within
# the boot timeout, the login was refused, or the setup script failed; the
# log says which.
# ─────────────────────────────────────────────────────────────────────────────
import re
import socket
import sys
import time

# The setup script runs after the root filesystem grew on first boot and
# sshd's host keys were generated; a slow TCG run takes a while for both.
SETUP_TIMEOUT = 300
# Login banner and prompt after "root" is typed.
LOGIN_TIMEOUT = 120
# Root's shell on the image is sh(1), whose prompt is "root@<host>:<cwd> # ".
PROMPT = rb"root@\S+:\S* # "


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__ or "usage: freebsd16-console.py <socket> <log> <boot timeout>",
              file=sys.stderr)
        return 2
    sock_path, log_path, boot_timeout = sys.argv[1], sys.argv[2], int(sys.argv[3])

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    sock.settimeout(1.0)
    log = open(log_path, "ab", buffering=0)
    buf = b""

    def fail(msg: str) -> int:
        print(f"freebsd16-console: {msg}; see {log_path}", file=sys.stderr)
        return 1

    def expect(patterns, timeout):
        """Read the console until one of the byte regexes matches.

        Returns (index, match) for the first pattern that matches, or
        (None, None) on timeout or a closed connection. Consumed input up to
        the end of the match is dropped from the buffer so a later expect()
        cannot re-match it.
        """
        nonlocal buf
        deadline = time.monotonic() + timeout
        while True:
            for i, pat in enumerate(patterns):
                m = re.search(pat, buf)
                if m:
                    buf = buf[m.end():]
                    return i, m
            if time.monotonic() > deadline:
                return None, None
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return None, None
            log.write(chunk)
            buf = (buf + chunk)[-65536:]

    def send(text: str) -> None:
        sock.sendall(text.encode())

    # 1. Boot to the login prompt. This spans the loader, the kernel, first-boot
    #    growfs and the whole rc sequence; the timeout is the caller's.
    idx, _ = expect([rb"login: "], boot_timeout)
    if idx is None:
        return fail(f"no login prompt on the serial console within {boot_timeout}s")

    # 2. Log in as root. The image's root has an empty password and PAM's
    #    nullok accepts it without prompting, but accept a Password: prompt
    #    too rather than depend on that.
    send("root\r")
    idx, _ = expect([PROMPT, rb"Password:", rb"login: "], LOGIN_TIMEOUT)
    if idx == 1:
        send("\r")
        idx, _ = expect([PROMPT, rb"login: "], LOGIN_TIMEOUT)
        idx = {0: 0, 1: 2}.get(idx)
    if idx is None:
        return fail("no shell prompt after typing root")
    if idx == 2:
        return fail("root login refused at the console")

    # 3. Run the setup script from the ESP, which fstab mounts at /boot/efi.
    #    The echoed command line contains the literal "$?", so requiring
    #    digits keeps the match on the result rather than the echo.
    send("sh /boot/efi/ci/setup.sh; echo CI-SETUP-RC=$?\r")
    idx, m = expect([rb"CI-SETUP-RC=(\d+)[\r\n]"], SETUP_TIMEOUT)
    if idx is None:
        return fail(f"setup script did not finish within {SETUP_TIMEOUT}s")
    rc = int(m.group(1))
    if rc != 0:
        return fail(f"setup script exited {rc}")

    # 4. Log out so the console is left at a login prompt, not a root shell.
    send("exit\r")
    expect([rb"login: "], 30)
    return 0


if __name__ == "__main__":
    sys.exit(main())
