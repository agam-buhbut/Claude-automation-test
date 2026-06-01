#!/usr/bin/env python3
"""Adaptive-floor cover-traffic (chaff) daemon for the AmneziaWG VPN server.

Purpose
-------
Against a *passive* adversary watching the encrypted UDP flow between a client
and the server, the volume/timing of that flow leaks when the user is active and
roughly how much they transfer. This daemon keeps each connected peer's flow at
or above a configurable *floor* rate by injecting random-sized ICMP-echo packets
*through the tunnel*. Because the packets are ICMP echo, the client's OS replies
automatically — so the floor is maintained in **both** directions for **any**
client (including the Android app, which cannot run a custom daemon).

It is *adaptive*: each tick it measures the peer's real throughput from
``awg show <iface> dump`` and only sends enough chaff to reach the floor. Real
traffic therefore suppresses chaff (no wasted mobile data when the user is busy).

Honest limits (see docs/DESIGN.md): this hides *idle-vs-active* and coarse volume.
It does NOT make the flow perfectly constant-rate, so a global adversary doing
fine-grained burst/timing correlation across both endpoints is out of scope —
that is inherent to a single-hop tunnel.

Runs as root (raw ICMP socket / CAP_NET_RAW). Chaff is itself encrypted and
obfuscated by AmneziaWG, so on the wire it is indistinguishable from real tunnel
traffic.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_echo(ident: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    chk = icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, chk, ident & 0xFFFF, seq & 0xFFFF)
    return header + payload


@dataclass
class Peer:
    pubkey: str
    target_ip: str
    last_handshake: int
    bytes_seen: int
    seq: int = 0
    deficit_carry: float = 0.0  # fractional bytes carried between ticks


@dataclass
class Chaff:
    iface: str
    floor_bps: int  # target floor in BITS per second per peer
    tick: float
    min_pkt: int
    max_pkt: int
    stale_after: int  # seconds since handshake after which a peer is "offline"
    peers: dict[str, Peer] = field(default_factory=dict)

    def _dump(self) -> list[list[str]]:
        out = subprocess.run(
            ["awg", "show", self.iface, "dump"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip().splitlines()
        # First line is the interface itself; peers follow.
        return [line.split("\t") for line in out[1:]]

    @staticmethod
    def _first_v4(allowed: str) -> str | None:
        for cidr in allowed.split(","):
            cidr = cidr.strip()
            ip = cidr.split("/")[0]
            if ":" not in ip and ip:
                return ip
        return None

    def refresh_peers(self, now: int) -> None:
        for fields in self._dump():
            # dump peer columns: pubkey psk endpoint allowed-ips handshake rx tx keepalive
            if len(fields) < 8:
                continue
            pubkey, _psk, _ep, allowed, hs, rx, tx, _ka = fields[:8]
            target = self._first_v4(allowed)
            if target is None:
                continue
            seen = int(rx) + int(tx)
            handshake = int(hs)
            p = self.peers.get(pubkey)
            if p is None:
                self.peers[pubkey] = Peer(pubkey, target, handshake, seen)
            else:
                p.target_ip = target
                p.last_handshake = handshake
                # bytes_seen updated by caller after computing delta

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        ident = os.getpid() & 0xFFFF
        floor_bytes_per_tick = self.floor_bps / 8.0 * self.tick
        next_t = time.monotonic()
        print(
            f"chaff: iface={self.iface} floor={self.floor_bps}bps "
            f"tick={self.tick}s pkt={self.min_pkt}-{self.max_pkt}B",
            file=sys.stderr,
            flush=True,
        )
        while True:
            now = int(time.time())
            self.refresh_peers(now)
            for fields in self._dump():
                if len(fields) < 8:
                    continue
                pubkey, _psk, _ep, _allowed, hs, rx, tx, _ka = fields[:8]
                p = self.peers.get(pubkey)
                if p is None:
                    continue
                seen = int(rx) + int(tx)
                delta = max(0, seen - p.bytes_seen)
                p.bytes_seen = seen
                p.last_handshake = int(hs)

                # Skip peers with no recent handshake (not connected).
                if now - p.last_handshake > self.stale_after:
                    continue

                deficit = floor_bytes_per_tick - delta + p.deficit_carry
                if deficit <= 0:
                    p.deficit_carry = 0.0
                    continue
                self._emit(sock, p, deficit)
            next_t += self.tick
            sleep = next_t - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_t = time.monotonic()  # we fell behind; resync

    def _emit(self, sock: socket.socket, p: Peer, deficit: float) -> None:
        """Send random-sized chaff totalling ~deficit bytes, with intra-tick jitter."""
        sent = 0.0
        # IP(20)+ICMP(8) overhead per packet approximates on-wire bytes pre-encryption.
        while sent < deficit:
            size = self.min_pkt + int.from_bytes(os.urandom(2), "big") % (
                self.max_pkt - self.min_pkt + 1
            )
            payload = os.urandom(max(0, size - 8))
            p.seq = (p.seq + 1) & 0xFFFF
            pkt = build_echo(os.getpid(), p.seq, payload)
            try:
                sock.sendto(pkt, (p.target_ip, 0))
            except OSError:
                return
            sent += size + 20  # + IP header
            # Small jitter so packets aren't perfectly back-to-back.
            time.sleep((int.from_bytes(os.urandom(1), "big") / 255.0) * 0.01)
        p.deficit_carry = sent - deficit  # carry overshoot negative next tick


def main() -> int:
    ap = argparse.ArgumentParser(description="AmneziaWG cover-traffic daemon")
    ap.add_argument("--iface", default="awg0")
    ap.add_argument(
        "--floor-kbps",
        type=int,
        default=16,
        help="per-peer floor rate in kbit/s (default 16 ≈ 7 MB/h)",
    )
    ap.add_argument("--tick", type=float, default=0.25)
    ap.add_argument("--min-pkt", type=int, default=64)
    ap.add_argument("--max-pkt", type=int, default=1200)
    ap.add_argument("--stale-after", type=int, default=200)
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("chaff: must run as root (raw ICMP socket)", file=sys.stderr)
        return 1

    Chaff(
        iface=args.iface,
        floor_bps=args.floor_kbps * 1000,
        tick=args.tick,
        min_pkt=args.min_pkt,
        max_pkt=args.max_pkt,
        stale_after=args.stale_after,
    ).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
