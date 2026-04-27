import socket
import struct


MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020


def build_success(txn_id: bytes, addr: tuple[str, int]) -> bytes:
    ip_bytes = socket.inet_aton(addr[0])
    cookie_bytes = MAGIC_COOKIE.to_bytes(4, "big")
    x_port = addr[1] ^ (MAGIC_COOKIE >> 16)
    x_ip = bytes(ip_bytes[i] ^ cookie_bytes[i] for i in range(4))
    value = b"\x00\x01" + struct.pack("!H", x_port) + x_ip
    attr = struct.pack("!HH", STUN_ATTR_XOR_MAPPED_ADDRESS, len(value)) + value
    header = struct.pack("!HHI", STUN_BINDING_SUCCESS, len(attr), MAGIC_COOKIE) + txn_id
    return header + attr


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 3478))
    while True:
        data, remote = sock.recvfrom(2048)
        if len(data) < 20:
            continue
        msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
        txn_id = data[8:20]
        if msg_type != STUN_BINDING_REQUEST or msg_len != 0 or cookie != MAGIC_COOKIE:
            continue
        sock.sendto(build_success(txn_id, remote), remote)


if __name__ == "__main__":
    main()
