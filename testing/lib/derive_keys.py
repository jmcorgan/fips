#!/usr/bin/env python3
"""Derive deterministic nostr nsec/npub from mesh-name and node-name.

Usage: derive-keys.py <mesh-name> <node-name>
Output: nsec=<hex>\nnpub=<bech32>

Derivation: nsec = sha256(mesh_name + "|" + node_name)
            npub = bech32("npub", secp256k1_pubkey_x(nsec))

Pure Python, no external dependencies.
"""

import hashlib
import sys

# --- secp256k1 ---

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _modinv(a, m):
    return pow(a, m - 2, m)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1) * _modinv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


# --- bech32 (BIP-173) ---

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_encode(hrp, data_5bit):
    hrp_expand = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    polymod = _bech32_polymod(hrp_expand + data_5bit + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data_5bit + checksum)


def _convertbits(data, frombits, tobits):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


# --- public API ---

def derive(mesh_name, node_name):
    nsec_hex = hashlib.sha256(f"{mesh_name}|{node_name}".encode()).hexdigest()
    k = int(nsec_hex, 16)
    pub = _scalar_mult(k, (Gx, Gy))
    x_hex = format(pub[0], "064x")
    data_5bit = _convertbits(list(bytes.fromhex(x_hex)), 8, 5)
    npub = _bech32_encode("npub", data_5bit)
    return nsec_hex, npub


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <mesh-name> <node-name>", file=sys.stderr)
        sys.exit(1)
    nsec, npub = derive(sys.argv[1], sys.argv[2])
    print(f"nsec={nsec}")
    print(f"npub={npub}")
