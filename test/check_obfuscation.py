#!/usr/bin/env python3
"""Scan a pcap for the WireGuard packet signature.

Stock WireGuard message types are 0x01-0x04 in the first payload byte followed by
three zero bytes (reserved). AmneziaWG replaces these with random 32-bit magic
headers, so a correctly-obfuscated capture should contain NO such packets.

Prints ``CLEAN`` if at least one UDP/443 packet was seen and none carried the
WireGuard signature; otherwise prints a description of the offending packet(s) or
``NOCAP`` if no UDP/443 traffic was captured. Stdlib only (manual pcap parse).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

WG_TYPES = {1, 2, 3, 4}


def packets(data: bytes):
    if len(data) < 24:
        return
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xA1B2C3D4:
        end = "<"
    elif magic == 0xD4C3B2A1:
        end = ">"
    else:
        return  # not a classic pcap we understand
    off = 24
    while off + 16 <= len(data):
        _ts, _us, caplen, _orig = struct.unpack(end + "IIII", data[off : off + 16])
        off += 16
        if off + caplen > len(data):
            break
        yield data[off : off + caplen]
        off += caplen


def udp443_payload(frame: bytes) -> bytes | None:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != 0x0800:  # IPv4 only (test underlay is v4)
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17:  # UDP
        return None
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    sport, dport = struct.unpack("!HH", udp[0:4])
    if 443 not in (sport, dport):
        return None
    return udp[8:]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_obfuscation.py CAPTURE.pcap", file=sys.stderr)
        return 2
    data = Path(sys.argv[1]).read_bytes()
    seen = 0
    offenders: list[str] = []
    for frame in packets(data):
        payload = udp443_payload(frame)
        if payload is None:
            continue
        seen += 1
        if len(payload) >= 4 and payload[0] in WG_TYPES and payload[1:4] == b"\x00\x00\x00":
            offenders.append(payload[:4].hex())
    if seen == 0:
        print("NOCAP")
    elif offenders:
        print(f"WG-signature in {len(offenders)}/{seen} pkts e.g. {offenders[0]}")
    else:
        print("CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
