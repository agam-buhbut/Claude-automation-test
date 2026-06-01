# Single-Hop Obfuscated VPN — Design

## Goal

A single-hop VPN endpoint on a Debian server serving **two simultaneous
clients** — one Android, one Debian — that is:

- **Secured** — modern AEAD crypto, mutual authentication, perfect forward
  secrecy, anti-replay.
- **Anonymising** — both clients egress from one shared exit IP; no DNS/IPv6
  leaks; traffic patterns masked.
- **Obfuscated** — indistinguishable from non-VPN traffic to a passive
  observer (no WireGuard fingerprint).
- **Hardened** — silent and resilient against an active, trained adversary
  positioned at either endpoint.
- **Audited and tested** — by automated network-namespace simulation plus an
  external probe/leak audit before real-client rollout.

## Topology

```
   Android client ──NAT──┐
                         ├──▶  Internet  ──▶  [ Debian server / VPN endpoint ]
   Debian  client ──NAT──┘        (UDP, port-forwarded when needed)   │
                                                                      ▼
                                                          NAT / exit to Internet
                                                          unbound DNS (tunnel-only)
```

Single hop: each client ↔ server directly (no chained relays). Both clients
are connected at the same time and share the server as their sole exit.

## Core protocol: AmneziaWG

WireGuard provides the cryptographic core; AmneziaWG adds the anti-DPI layer.

**Why WireGuard-family (vs OpenVPN/IPsec):**
- Noise_IKpsk2 handshake — Curve25519 ECDH, ChaCha20-Poly1305 AEAD, BLAKE2s.
- Perfect forward secrecy (ephemeral keys re-negotiated ~every 2 min).
- **Silent by design**: an unauthenticated packet gets *no response*. To a
  scanner the UDP port is indistinguishable from closed — directly defeats the
  active adversary's reconnaissance.
- Tiny, auditable codebase → small attack surface.
- Built-in replay protection (sliding-window nonce counter).

**Why AmneziaWG on top of stock WireGuard:**
Stock WireGuard is *secure* but *fingerprintable* — its handshake has a fixed
first byte and characteristic packet sizes, so a passive DPI box can flag "this
is WireGuard" even though it can't decrypt it. AmneziaWG removes that signature:

| Param            | Effect                                                      |
|------------------|-------------------------------------------------------------|
| `Jc`             | Count of random **junk packets** sent before the handshake. |
| `Jmin` / `Jmax`  | Size bounds of those junk packets.                          |
| `S1` / `S2`      | Random bytes prepended to init / response handshake packets.|
| `H1`–`H4`        | Replace the four fixed WireGuard message-type headers with random values. |

These parameters must be **identical on every peer**. They turn the recognisable
WireGuard handshake into bytes with no fixed structure → no passive signature,
and the junk/probing-resistance also frustrates *active* DPI classification.

AmneziaWG is single-hop WireGuard — it does not add a relay, so it satisfies the
"single hop" requirement while addressing obfuscation.

## Layered defenses (mapped to the threat model)

### Against the passive adversary ("covering of traffic")
1. **Protocol obfuscation** — AmneziaWG junk + header randomisation (above).
2. **Full-tunnel routing** — `AllowedIPs = 0.0.0.0/0, ::/0` on clients; the only
   thing visible on a client's local network is obfuscated UDP to one host.
3. **Shared exit IP** — server masquerades both clients behind its single
   address; an outside observer cannot attribute an outbound flow to a specific
   client (anonymity set k = number of concurrent clients).
4. **DNS confinement** — `unbound` on the server, reachable only from the tunnel
   subnet; clients use it as sole resolver → no plaintext DNS on the local link.
5. **Cover traffic** — a constant-rate chaff daemon (see `cover-traffic/`) keeps
   the tunnel's volume/timing envelope roughly constant so the passive observer
   cannot infer when the user is active or how much they transfer. Honest limits
   documented in that module.

### Against the active, trained adversary (per-endpoint hardening)
1. **Mutual static-key auth + per-peer PSK** — `PresharedKey` adds a symmetric
   secret on top of the asymmetric handshake (defense-in-depth, incl. a hedge
   against future quantum attacks on Curve25519).
2. **Silent firewall** — `nftables` default-drop; the obfuscated UDP port is the
   only ingress, and even it never replies to non-authenticating packets.
3. **Anti-replay** — WireGuard sliding-window counter rejects replayed packets.
4. **Rate-limiting** — per-source limits on the handshake port blunt flooding /
   resource-exhaustion probes.
5. **Kernel hardening** — `rp_filter`, no source routing, no ICMP redirects,
   syncookies, martian logging.
6. **Key hygiene** — keys generated from the kernel CSPRNG, stored `0600`
   root-owned, never committed (`.gitignore` enforces this).

## Server implementation choice

AmneziaWG is built from source (not in Debian apt):
- **Data plane:** `amneziawg-go` (userspace TUN) by default — reproducible,
  no kernel-header/DKMS coupling, ample throughput for two clients. Kernel
  module is an optional later optimisation (measure first).
- **Control plane:** `amneziawg-tools` (`awg`, `awg-quick`).

## What this design deliberately does NOT claim

- It is **single-hop**, so it does **not** provide anonymity against an adversary
  who can observe *both* the client link and the server's exit simultaneously
  (a global passive adversary / the server operator). That requires multi-hop
  (Tor-like) and is explicitly out of scope per the "single hop" requirement.
- Cover traffic raises the cost of traffic-analysis but cannot make a single-hop
  tunnel perfectly indistinguishable under unlimited observation; limits are
  documented honestly rather than overstated.
