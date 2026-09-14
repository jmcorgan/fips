#!/bin/bash
# ── FreeBSD 16.0-CURRENT build VM for the pfSense package ───────────────────
# pfSense CE 2.9 and Plus 26.x run on FreeBSD 16, so the package they install
# is FreeBSD:16:amd64 and has to be built on a FreeBSD 16 host. There is no
# 16.0-RELEASE until late 2027, vmactions/freebsd-vm (which the other FreeBSD
# jobs use) stops at 15.1, and nobody else publishes a FreeBSD 16 CI image.
# What exists is the project's own 16.0-CURRENT snapshot VM image, of which
# download.freebsd.org keeps only the newest one or two, so a snapshot URL is
# dead within weeks.
#
# This script boots one such snapshot under qemu on the Linux runner:
#
#   1. fetches the pinned image, from this repository's `ci-images` release
#      first and from download.freebsd.org second, and checks it against the
#      pinned SHA-512 whichever source served it. Only the hash decides; the
#      mirror exists so the build does not depend on the snapshot still being
#      published, not to be trusted on its own;
#   2. writes into the image's EFI system partition (FAT, which Linux can write
#      safely; the UFS root cannot be) a loader.env that turns on the serial
#      console, plus a setup script and an ssh public key generated for this
#      run;
#   3. boots it with UEFI firmware, logs in as root on the serial console
#      (freebsd16-console.py) and runs that setup script, which enables sshd
#      with key-only root login;
#   4. waits for ssh, after which `ssh`, `push` and `pull` carry the build.
#
# Static linking makes the snapshot's date irrelevant to the package: a static
# binary depends only on the kernel syscall ABI, stable within a major. The pin
# is for reproducibility and for not breaking when the snapshot rotates, and
# it is refreshed on a decision, not on a schedule. How to refresh it is in
# packaging/pfsense/README.md.
#
# Usage: freebsd16-vm.sh up
#        freebsd16-vm.sh ssh [command...]
#        freebsd16-vm.sh push <local dir> <remote dir>
#        freebsd16-vm.sh pull <remote path> <local dir>
#        freebsd16-vm.sh down
#
# Needs qemu-system-x86_64, qemu-img, OVMF firmware, xz, sfdisk, mtools
# (mcopy, mmd, mdir), ssh, ssh-keygen and python3. KVM is used when /dev/kvm
# is writable and qemu falls back to TCG otherwise, which works and is
# several times slower.
#
# Exit 0 = the subcommand succeeded. Any other exit is a failure; `up` prints
# the tail of the console log on the way out so a boot failure is readable.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── The pinned snapshot ──────────────────────────────────────────────────────
# FreeBSD-<branch>-<arch>-ufs-<YYYYMMDD>-<git hash>-<build>.raw.xz from the
# dated directory, never the unsuffixed name under Latest/, which changes
# content without changing name. The SHA-512 is what was downloaded over HTTPS
# from download.freebsd.org on the date below; the freebsd-snapshots
# announcement for a build, when one is sent, carries the same value signed.
#
# The 20260907 build is the one snapshot published when this was pinned. Its
# name carries "nullhash-nullcount" where the git hash and build number
# belong, and no announcement was sent for it, so this hash is HTTPS-only.
# Re-pin to the next announced build (packaging/pfsense/README.md says how).
FREEBSD16_IMAGE="${FREEBSD16_IMAGE:-FreeBSD-16.0-CURRENT-amd64-ufs-20260907-nullhash-nullcount.raw.xz}"
FREEBSD16_IMAGE_SHA512="${FREEBSD16_IMAGE_SHA512:-b23f57475cf60744258f344df3bb5311aafc6240b501d637f2d04efce6350333eb2b1fdb7a4b9b8c9dd5bb562e36ab6d3a328f77a4ca22670e7daa263280728f}"
FREEBSD16_IMAGE_ORIGIN="${FREEBSD16_IMAGE_ORIGIN:-https://download.freebsd.org/snapshots/VM-IMAGES/16.0-CURRENT/amd64/20260907/}"
# Pinned on 2026-09-14.

# The durable copy: an asset on this repository's `ci-images` release. On a
# fork, GITHUB_REPOSITORY names the fork, so a fork tests against its own copy.
FREEBSD16_IMAGE_MIRROR="${FREEBSD16_IMAGE_MIRROR:-https://github.com/${GITHUB_REPOSITORY:-jmcorgan/fips}/releases/download/ci-images/}"

# ── VM shape ─────────────────────────────────────────────────────────────────
VM_MEM_MB="${VM_MEM_MB:-6144}"
VM_CPUS="${VM_CPUS:-$(nproc)}"
# The image is 6 GiB; a release build of fips plus the packages it needs wants
# more. The image grows its root filesystem to the disk on first boot.
VM_DISK_GB="${VM_DISK_GB:-24}"
VM_SSH_PORT="${VM_SSH_PORT:-2222}"
# Loader, kernel, first-boot growfs and the rc sequence, under KVM or TCG.
VM_BOOT_TIMEOUT="${VM_BOOT_TIMEOUT:-900}"

STATE="${FREEBSD16_VM_STATE:-${RUNNER_TEMP:-/tmp}/freebsd16-vm}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONSOLE_DRIVER="$SCRIPT_DIR/freebsd16-console.py"

SSH_OPTS=(
    -i "$STATE/id_ed25519"
    -p "$VM_SSH_PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile="$STATE/known_hosts"
    -o LogLevel=ERROR
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=8
)
SSH_TARGET="root@127.0.0.1"

log() { printf '==> %s\n' "$*"; }
die() { printf 'freebsd16-vm: %s\n' "$*" >&2; exit 1; }

need() {
    local missing=()
    for t in "$@"; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
    [ ${#missing[@]} -eq 0 ] || die "missing tools: ${missing[*]}"
}

# The UEFI firmware. Debian/Ubuntu ship the 4M images under /usr/share/OVMF;
# the older 2M names and the Arch/Fedora locations are accepted so the script
# also runs on a developer machine.
find_ovmf() {
    local code vars
    for code in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
                /usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/edk2/ovmf/OVMF_CODE.fd; do
        [ -r "$code" ] || continue
        vars="${code/CODE/VARS}"
        [ -r "$vars" ] || continue
        printf '%s\n%s\n' "$code" "$vars"
        return 0
    done
    return 1
}

# Download the pinned image from the first source that serves it and verify
# it. A source that is absent (404, unreachable) is skipped; a source that
# serves bytes with the wrong hash is a failure, not a reason to try the next.
fetch_image() {
    local dest="$STATE/$FREEBSD16_IMAGE" url src
    for src in "$FREEBSD16_IMAGE_MIRROR" "$FREEBSD16_IMAGE_ORIGIN"; do
        url="${src}${FREEBSD16_IMAGE}"
        log "fetching $url"
        if ! curl -fsSL --retry 3 --retry-delay 5 -o "$dest.part" "$url"; then
            log "not available from $src"
            rm -f "$dest.part"
            continue
        fi
        local got
        got=$(sha512sum "$dest.part" | awk '{print $1}')
        if [ "$got" != "$FREEBSD16_IMAGE_SHA512" ]; then
            rm -f "$dest.part"
            die "SHA-512 mismatch for $url
  expected $FREEBSD16_IMAGE_SHA512
  got      $got
The pinned image is not what this source serves. Nothing was booted."
        fi
        mv "$dest.part" "$dest"
        log "SHA-512 verified (source: $src)"
        return 0
    done
    die "the pinned image $FREEBSD16_IMAGE is available from neither
  $FREEBSD16_IMAGE_MIRROR
  $FREEBSD16_IMAGE_ORIGIN
The snapshot has rotated out and the repository has no mirrored copy. See
'Refreshing the FreeBSD 16 CI image' in packaging/pfsense/README.md."
}

# Byte offset of the EFI system partition inside the raw image, from its GPT.
# sfdisk's dump gives the partition start in sectors and the sector size it
# assumed; use both rather than hard-coding 512.
esp_offset() {
    local dump start sector
    dump=$(sfdisk -d "$1" 2>/dev/null) || die "sfdisk could not read $1"
    sector=$(printf '%s\n' "$dump" | awk '/^sector-size:/ { print $2; exit }')
    start=$(printf '%s\n' "$dump" \
        | awk -F'[ ,=]+' 'toupper($0) ~ /C12A7328-F81F-11D2-BA4B-00A0C93EC93B/ {
              for (i = 1; i <= NF; i++) if ($i == "start") { print $(i+1); exit } }')
    [ -n "$start" ] || die "no EFI system partition found in $1"
    echo $(( start * ${sector:-512} ))
}

# Place a file into the ESP. mtools reads FAT straight out of the raw image at
# an offset, so no loop device and no root are needed on the runner.
esp_put() {
    local img="$1" offset="$2" src="$3" dst="$4"
    MTOOLS_SKIP_CHECK=1 mcopy -o -i "$img@@$offset" "$src" "::$dst"
}
esp_mkdir() {
    local img="$1" offset="$2" dir="$3"
    MTOOLS_SKIP_CHECK=1 mdir -i "$img@@$offset" "::$dir" >/dev/null 2>&1 \
        || MTOOLS_SKIP_CHECK=1 mmd -i "$img@@$offset" "::$dir"
}

console_tail() {
    if [ -s "$STATE/console.log" ]; then
        echo "---- last 60 lines of the serial console ----" >&2
        tail -n 60 "$STATE/console.log" | tr -d '\r' >&2
        echo "---------------------------------------------" >&2
    fi
}

qemu_pid() {
    [ -s "$STATE/qemu.pid" ] || return 1
    local pid
    pid=$(cat "$STATE/qemu.pid")
    kill -0 "$pid" 2>/dev/null || return 1
    echo "$pid"
}

cmd_up() {
    need qemu-system-x86_64 qemu-img xz sfdisk mcopy mmd mdir ssh ssh-keygen python3 curl sha512sum
    local ovmf_code ovmf_vars
    { read -r ovmf_code; read -r ovmf_vars; } < <(find_ovmf) \
        || die "no OVMF firmware found (install the ovmf package)"

    mkdir -p "$STATE"
    qemu_pid >/dev/null && die "a VM is already running (pid $(cat "$STATE/qemu.pid")); run 'down' first"
    rm -f "$STATE/console.log" "$STATE/console.sock" "$STATE/known_hosts"
    # An EXIT trap, not ERR: die() exits, and the ERR trap does not run on exit.
    trap '[ $? -eq 0 ] || console_tail' EXIT

    # 1. The image.
    fetch_image
    log "decompressing"
    xz -d -T0 -f "$STATE/$FREEBSD16_IMAGE"
    local disk="$STATE/${FREEBSD16_IMAGE%.xz}"
    qemu-img resize -q -f raw "$disk" "${VM_DISK_GB}G"

    # 2. What goes into the ESP.
    ssh-keygen -q -t ed25519 -N '' -C "fips-ci-$(date -u +%Y%m%dT%H%M%SZ)" -f "$STATE/id_ed25519"

    # Only plain name=value lines: loader.efi reads this file itself, before
    # the lua interpreter that understands quoting and *_load is up. It is
    # read before loader.conf, so anything loader.conf sets would win; the
    # defaults leave console alone. console=comconsole gives the kernel and
    # getty the serial port.
    printf 'console=comconsole\n' > "$STATE/loader.env"

    # Runs once, as root, on the serial console. Key-only root login: the empty
    # console password is the image's, and it is not reachable over ssh.
    cat > "$STATE/setup.sh" <<'EOF'
set -e
sysrc -q sshd_enable=YES
printf '\nPermitRootLogin prohibit-password\n' >> /etc/ssh/sshd_config
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cp /boot/efi/ci/authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
service sshd start
EOF

    local offset
    offset=$(esp_offset "$disk")
    log "writing loader.env, setup script and ssh key into the ESP (offset $offset)"
    esp_mkdir "$disk" "$offset" /efi/freebsd
    esp_put   "$disk" "$offset" "$STATE/loader.env" /efi/freebsd/loader.env
    esp_mkdir "$disk" "$offset" /ci
    esp_put   "$disk" "$offset" "$STATE/setup.sh" /ci/setup.sh
    esp_put   "$disk" "$offset" "$STATE/id_ed25519.pub" /ci/authorized_keys

    # 3. Boot.
    local accel=(-accel tcg -cpu max)
    if [ -w /dev/kvm ]; then
        accel=(-accel kvm -cpu host)
        log "booting with KVM"
    else
        log "WARNING: /dev/kvm is not writable; booting with TCG, expect a several-times slower run"
    fi
    cp "$ovmf_vars" "$STATE/OVMF_VARS.fd"
    qemu-system-x86_64 \
        -name freebsd16-ci \
        -machine q35 "${accel[@]}" -smp "$VM_CPUS" -m "$VM_MEM_MB" \
        -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
        -drive if=pflash,format=raw,file="$STATE/OVMF_VARS.fd" \
        -drive file="$disk",format=raw,if=virtio,cache=unsafe \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$VM_SSH_PORT-:22" \
        -device virtio-net-pci,netdev=net0 \
        -chardev "socket,id=console,path=$STATE/console.sock,server=on,wait=off,logfile=$STATE/console.log" \
        -serial chardev:console \
        -display none -vga none \
        -daemonize -pidfile "$STATE/qemu.pid"
    log "qemu started (pid $(cat "$STATE/qemu.pid")); waiting for the login prompt"

    # 4. Console login and setup. The chardev already logs the console, so
    #    the driver appends to a separate transcript of its own view.
    python3 "$CONSOLE_DRIVER" "$STATE/console.sock" "$STATE/console-driver.log" "$VM_BOOT_TIMEOUT"

    # 5. ssh.
    log "waiting for sshd on 127.0.0.1:$VM_SSH_PORT"
    local _
    for _ in $(seq 1 60); do
        if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 "$SSH_TARGET" true 2>/dev/null; then
            log "VM is up: $(ssh "${SSH_OPTS[@]}" "$SSH_TARGET" 'uname -srm; freebsd-version -ku | paste -sd " " -; pkg config abi 2>/dev/null || true' | paste -sd '|' -)"
            trap - EXIT
            return 0
        fi
        sleep 5
    done
    die "sshd did not answer within 300s of the console setup finishing"
}

cmd_ssh() {
    exec ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "$@"
}

# Copy a directory tree into the VM. .git and target are left out: the build
# does not need the history (build.rs tolerates a missing git) and target is
# a stale artifact of whatever host ran last.
cmd_push() {
    local src="$1" dst="$2"
    # The remote path is meant to expand here, on the runner.
    # shellcheck disable=SC2029
    tar -C "$src" --exclude=./.git --exclude=./target -cf - . \
        | ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "mkdir -p '$dst' && tar -xf - -C '$dst'"
}

# Copy a file or directory out of the VM into a local directory.
cmd_pull() {
    local remote="$1" dst="$2"
    mkdir -p "$dst"
    # The remote path is meant to expand here, on the runner.
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "tar -cf - -C '$(dirname "$remote")' '$(basename "$remote")'" \
        | tar -xf - -C "$dst"
}

cmd_down() {
    local pid
    if ! pid=$(qemu_pid); then
        log "no VM running"
        return 0
    fi
    log "shutting the VM down"
    # Only wait for a power-off that was actually requested; after a failed
    # boot there is no sshd to ask, and the VM is simply killed.
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 "$SSH_TARGET" 'shutdown -p now' >/dev/null 2>&1; then
        local _
        for _ in $(seq 1 24); do
            kill -0 "$pid" 2>/dev/null || { log "VM powered off"; rm -f "$STATE/qemu.pid"; return 0; }
            sleep 5
        done
        log "VM did not power off in 120s; killing qemu"
    else
        log "sshd not reachable; killing qemu"
    fi
    kill "$pid" 2>/dev/null || true
    rm -f "$STATE/qemu.pid"
}

case "${1:-}" in
    up)   shift; cmd_up "$@" ;;
    ssh)  shift; cmd_ssh "$@" ;;
    push) shift; [ $# -eq 2 ] || die "usage: $0 push <local dir> <remote dir>"; cmd_push "$@" ;;
    pull) shift; [ $# -eq 2 ] || die "usage: $0 pull <remote path> <local dir>"; cmd_pull "$@" ;;
    down) shift; cmd_down "$@" ;;
    *)    die "usage: $0 up | ssh [command...] | push <local dir> <remote dir> | pull <remote path> <local dir> | down" ;;
esac
