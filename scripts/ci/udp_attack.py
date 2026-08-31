#!/usr/bin/env python3
"""UDP protocol attack helper for the TapAuth E2E suite.

Two subcommands:

  sniff [--port N] [--duration SECS]
      Passively capture hex-encoded UDP payloads of EncryptedPacket datagrams
      that were sent TO the daemon's port (i.e. server->client messages such as
      AuthenticationGrant). One hex string per line; the first line is the first
      captured grant. Requires root (CAP_NET_RAW).

  send <hex_payload> [--corrupt] [--host H] [--port N]
      Re-inject a captured datagram. With --corrupt, the last byte (inside the
      AES-GCM tag region) is flipped so that AEAD verification must fail while
      the protobuf framing and temporal identifier stay intact. Sending itself
      works unprivileged.

Requires only the Python standard library.

NOTE: The daemon drops datagrams whose source address is one of the host's own
addresses unless it runs with TAPAUTH_DEV_MODE set (self-send filter, requires
the dev-udp-loopback feature). The E2E always injects with TAPAUTH_DEV_MODE=1 on
the daemon, which is why loopback injection is accepted.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

# AF_PACKET frames on Linux carry a synthesized 14-byte Ethernet header, which
# is what `sniff` parses below.
ETH_P_IPV6 = 0x86DD
ETH_P_IP = 0x0800
ETH_P_VLAN = 0x8100

MIN_ENCRYPTED_PACKET_LEN = 40  # 16B temporal id + alg + nonce + tag minimum


def parse_ipv4(data: bytes) -> tuple[str, str, int, int, bytes] | None:
    """Return (src, dst, sport, dport, payload) for an IPv4 UDP packet."""
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if len(data) < ihl:
        return None
    protocol = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    l4 = data[ihl:]
    if protocol != 17 or len(l4) < 8:  # UDP
        return None
    sport, dport, length = struct.unpack("!HHH", l4[:6])
    payload = l4[8:length] if length >= 8 and len(l4) >= length else l4[8:]
    return src, dst, sport, dport, payload


def parse_ipv6(data: bytes) -> tuple[str, str, int, int, bytes] | None:
    """Return (src, dst, sport, dport, payload) for an IPv6 UDP packet."""
    if len(data) < 40:
        return None
    if data[0] >> 4 != 6:
        return None
    next_header = data[6]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    l4 = data[40:]
    if next_header != 17 or len(l4) < 8:  # UDP (no extension header handling)
        return None
    sport, dport, length = struct.unpack("!HHH", l4[:6])
    payload = l4[8:length] if length >= 8 and len(l4) >= length else l4[8:]
    return src, dst, sport, dport, payload


def strip_link_layer(frame: bytes) -> bytes | None:
    """Strip the (synthesized) Ethernet header and any VLAN tags from a frame."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    while ethertype == ETH_P_VLAN:  # 802.1Q tag(s)
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4
    if ethertype not in (ETH_P_IP, ETH_P_IPV6):
        return None
    return frame[offset:]


def looks_like_encrypted_packet(payload: bytes) -> bool:
    """EncryptedPacket protobuf: field 1 (temporal_identifier), wire type 2, 16 bytes."""
    return len(payload) >= MIN_ENCRYPTED_PACKET_LEN and payload[0] == 0x0A and payload[1] == 0x10


def sniff(port: int, duration: float) -> int:
    """Capture server->client EncryptedPacket datagrams via AF_PACKET.

    Opens one raw socket per network interface (lo included) and prints one
    hex-encoded UDP payload per line (flushed immediately) for every datagram
    whose destination port matches and that is not a broadcast or multicast.
    Requires root (CAP_NET_RAW). This deliberately replaces tcpdump in the
    E2E: tcpdump's -Z privilege drop plus per-run buffering behaved
    nondeterministically on CI runners (occasionally writing only the 24-byte
    pcap header).
    """
    import select

    try:
        sockets = []
        for _if_index, if_name in socket.if_nameindex():
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            try:
                s.bind((if_name, 0))
            except OSError:
                continue  # interface went away or cannot be captured on
            s.setblocking(False)
            sockets.append(s)
    except PermissionError:
        print("ERROR: AF_PACKET capture requires root", file=sys.stderr)
        return 1
    if not sockets:
        print("ERROR: no capturable interfaces found", file=sys.stderr)
        return 1

    deadline = time.time() + duration
    try:
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            readable, _, _ = select.select(sockets, [], [], min(0.5, remaining))
            for s in readable:
                frame = s.recv(65535)
                # On AF_PACKET, loopback frames carry a synthesized 14-byte
                # Ethernet header, so link-layer parsing matches EN10MB.
                l3 = strip_link_layer(frame)
                if l3 is None:
                    continue
                parsed = parse_ipv4(l3) or parse_ipv6(l3)
                if parsed is None:
                    continue
                _src, dst, _sport, dport, payload = parsed
                if dport != port or is_broadcast_dst(dst):
                    continue
                if not looks_like_encrypted_packet(payload):
                    continue
                print(payload.hex(), flush=True)
    finally:
        for s in sockets:
            s.close()
    return 0


def is_broadcast_dst(dst: str) -> bool:
    return dst in ("255.255.255.255", "ff02::1") or dst.endswith(".255")


def send_packet(hex_payload: str, host: str, port: int, corrupt: bool) -> None:
    data = bytes.fromhex(hex_payload)
    if corrupt:
        # Flip one bit in the final byte (AES-256-GCM tag region). Protobuf
        # framing and the temporal identifier stay intact, so the packet must
        # fail AEAD verification (and only that).
        data = data[:-1] + bytes([data[-1] ^ 0x01])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(data, (host, port))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_send = sub.add_parser("send", help="re-inject a captured payload")
    p_send.add_argument("hex_payload")
    p_send.add_argument("--corrupt", action="store_true", help="flip a tag bit (must fail AEAD)")
    p_send.add_argument("--host", default="127.0.0.1")
    p_send.add_argument("--port", type=int, default=36692)

    p_sniff = sub.add_parser("sniff", help="capture server->client payloads live (requires root)")
    p_sniff.add_argument("--port", type=int, default=36692)
    p_sniff.add_argument("--duration", type=float, default=30.0)

    args = parser.parse_args()
    if args.command == "sniff":
        return sniff(args.port, args.duration)
    if args.command == "send":
        send_packet(args.hex_payload, args.host, args.port, args.corrupt)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
