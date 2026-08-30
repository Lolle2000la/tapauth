#!/usr/bin/env python3
"""UDP protocol attack helper for the TapAuth E2E suite.

Two subcommands:

  extract-grants <pcap> [--port N]
      Parse a tcpdump-captured pcap file and print hex-encoded UDP payloads of
      EncryptedPacket datagrams that were sent TO the daemon's port (i.e.
      server->client messages such as AuthenticationGrant). One hex string per
      line; the first line is the first captured grant.

  send <hex_payload> [--corrupt] [--host H] [--port N]
      Re-inject a captured datagram. With --corrupt, the last byte (inside the
      AES-GCM tag region) is flipped so that AEAD verification must fail while
      the protobuf framing and temporal identifier stay intact.

Requires only the Python standard library. Root is needed by the caller to run
tcpdump; sending itself works unprivileged.

NOTE: The daemon drops datagrams whose source address is one of the host's own
addresses unless it runs with TAPAUTH_DEV_MODE set (self-send filter). The E2E
always injects with TAPAUTH_DEV_MODE=1 on the daemon, which is why loopback
injection is accepted.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys

# pcap linktype values we know how to parse
LT_EN10MB = 1  # Ethernet, 14-byte header
LT_LINUX_SLL = 113  # Linux cooked capture, 16-byte header
LT_LINUX_SLL2 = 276  # Linux cooked capture v2, 20-byte header

LINKTYPE_HEADER_LEN = {LT_EN10MB: 14, LT_LINUX_SLL: 16, LT_LINUX_SLL2: 20}

PCAP_MAGIC_BE_USEC = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_LE_USEC = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE_NSEC = b"\xa1\xb2<\x8d"
PCAP_MAGIC_LE_NSEC = b"\x8d<\xb2\xa1"

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


def extract_l3(linktype: int, frame: bytes) -> bytes | None:
    """Strip the link-layer (and any VLAN tags) to yield an IP packet."""
    if linktype == LT_EN10MB:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        while ethertype == ETH_P_VLAN:  # 802.1Q tag(s)
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
            offset += 4
        return frame[offset:]
    if linktype == LT_LINUX_SLL:
        if len(frame) < 16:
            return None
        protocol = struct.unpack("!H", frame[14:16])[0]
        return frame[16:] if protocol in (ETH_P_IP, ETH_P_IPV6) else None
    if linktype == LT_LINUX_SLL2:
        if len(frame) < 20:
            return None
        protocol = struct.unpack("!H", frame[0:2])[0]
        return frame[20:] if protocol in (ETH_P_IP, ETH_P_IPV6) else None
    return None


def looks_like_encrypted_packet(payload: bytes) -> bool:
    """EncryptedPacket protobuf: field 1 (temporal_identifier), wire type 2, 16 bytes."""
    return len(payload) >= MIN_ENCRYPTED_PACKET_LEN and payload[0] == 0x0A and payload[1] == 0x10


def is_broadcast_dst(dst: str) -> bool:
    return dst in ("255.255.255.255", "ff02::1") or dst.endswith(".255")


def extract_grants(pcap_path: str, port: int) -> list[str]:
    with open(pcap_path, "rb") as fh:
        magic = fh.read(4)
        if magic == PCAP_MAGIC_BE_USEC or magic == PCAP_MAGIC_BE_NSEC:
            endian = ">"
        elif magic == PCAP_MAGIC_LE_USEC or magic == PCAP_MAGIC_LE_NSEC:
            endian = "<"
        else:
            raise SystemExit(
                f"ERROR: {pcap_path} is not a pcap file (magic={magic.hex()})"
            )
        # remaining global header: vmaj(H) vmin(H) thiszone(i) sigfigs(I) snaplen(I) network(I)
        fields = struct.unpack(endian + "HHiIII", fh.read(20))
        linktype = fields[5] & 0xFFFF  # high bits may carry linktype class info

        grants: list[str] = []
        while True:
            pkthdr = fh.read(16)
            if len(pkthdr) < 16:
                break
            (_ts_sec, _ts_frac, incl_len, _orig_len) = struct.unpack(endian + "IIII", pkthdr)
            frame = fh.read(incl_len)
            if len(frame) < incl_len:
                break
            l3 = extract_l3(linktype, frame)
            if l3 is None:
                continue
            parsed = parse_ipv4(l3) or parse_ipv6(l3)
            if parsed is None:
                continue
            _src, dst, _sport, dport, payload = parsed
            if dport != port or is_broadcast_dst(dst):
                continue  # daemon->server broadcasts (requests/confirmations)
            if not looks_like_encrypted_packet(payload):
                continue
            grants.append(payload.hex())
        return grants


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

    p_extract = sub.add_parser("extract-grants", help="print captured server->client payloads as hex")
    p_extract.add_argument("pcap")
    p_extract.add_argument("--port", type=int, default=36692)

    p_send = sub.add_parser("send", help="re-inject a captured payload")
    p_send.add_argument("hex_payload")
    p_send.add_argument("--corrupt", action="store_true", help="flip a tag bit (must fail AEAD)")
    p_send.add_argument("--host", default="127.0.0.1")
    p_send.add_argument("--port", type=int, default=36692)

    args = parser.parse_args()
    if args.command == "extract-grants":
        grants = extract_grants(args.pcap, args.port)
        if not grants:
            print("ERROR: no EncryptedPacket datagrams captured", file=sys.stderr)
            return 1
        for grant in grants:
            print(grant)
        return 0
    if args.command == "send":
        send_packet(args.hex_payload, args.host, args.port, args.corrupt)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
