# Cover traffic (chaff)

`chaff.py` raises each connected peer's tunnel flow to a configurable **floor**
rate by injecting random-sized ICMP-echo packets *through* the AmneziaWG tunnel.

## Why this design

| Property | How |
|----------|-----|
| Works for **Android** (no client daemon) | ICMP echo → client OS auto-replies, so both directions are padded without running anything on the client. |
| **Adaptive** (no wasted mobile data) | Each tick it reads real throughput from `awg show … dump` and sends only enough chaff to reach the floor; busy periods send little or no chaff. |
| **Indistinguishable on the wire** | Chaff rides inside the encrypted+obfuscated tunnel — to a passive observer it is identical to real tunnel traffic. |
| **Random sizes/timing** | Packet sizes drawn 64–1200 B with intra-tick jitter, so the padding itself has no fixed signature. |

## What it defeats / does not defeat

- ✅ Hides **idle-vs-active**: an observer near a client can no longer tell when
  the user is actually using the link — the flow never drops to zero.
- ✅ Raises the cost of **coarse volume** analysis (a noise floor masks small flows).
- ❌ Not a perfect constant-rate shaper: very large real bursts still exceed the
  floor and remain visible. Capping the ceiling would require pacing real traffic
  and cannot be done on the unmodified Android client.
- ❌ A *global* adversary observing both endpoints with fine-grained timing
  correlation is out of scope — that is inherent to any **single-hop** tunnel
  (see `docs/DESIGN.md`).

## Tuning

```
awg-chaff --floor-kbps 16   # default ≈ 7 MB/h per peer; raise for stronger
                            # masking, lower to save mobile data
```

Runs as a hardened systemd service (`awg-chaff.service`, `CAP_NET_RAW` only).
