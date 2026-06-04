# Security Audit & Test Report

Audit performed by the implementer against the live server. Two automated
harnesses, both re-runnable:

| Harness | What it does | Result |
|---------|--------------|--------|
| `test/sim-clients.sh all` | Runs **both** client configs as real AmneziaWG peers in separate network namespaces, connecting to the live server **simultaneously**, exercising the true data path (tunnel → server NAT → real Internet). | **14/14 pass** |
| `test/audit.sh` | Read-only static/hardening audit of the live server (crypto, firewall, sysctl, key hygiene, DNS exposure, services). | **21/21 pass** |

## Functional results (`sim-clients.sh`)

1. **Simultaneous dual handshake** — android + debian peers connected at the same time.
2. **Tunnel reachability** — both ping the server's tunnel IP.
3. **Tunnel-only DNS** — both resolve via `unbound` at `10.8.0.1` (DNSSEC `ad`).
4. **Full-tunnel egress** — each client reaches the Internet *only* through the
   tunnel (no route exists except via the server); both surface a server-side
   exit IP, not their own.
5. **Lateral isolation** — android cannot reach debian's tunnel IP.
6. **Obfuscation** — a live packet capture contains **no** WireGuard-typed packets
   (verified by `test/check_obfuscation.py`: no `0x01–0x04` + 3×`0x00` headers).
7. **Firewall silence** — a forged UDP datagram to the VPN port gets **no** reply;
   no TCP ports are open to an untrusted source.
8. **Cover-traffic floor** — with the peer idle, the chaff daemon sustains
   ~20 KB / 5 s of bidirectional padding (floor maintained, client auto-replies).

## Hardening results (`audit.sh`)

Crypto/obfuscation (junk packets active, magic headers randomised & distinct,
per-peer PSK), firewall (input+forward default-drop, client isolation, masquerade,
per-source flood meter), kernel (`rp_filter`, no redirects/source-route,
syncookies), key hygiene (config `0600 root`, no secrets in git), DNS not exposed
on the public interface, all services healthy.

## Threat-model mapping

| Adversary capability | Control | Verified by |
|----------------------|---------|-------------|
| Passive: "is this a VPN?" | AmneziaWG junk + randomised headers; UDP/443 ≈ QUIC | test [6] (no WG fingerprint) |
| Passive: "when/how much is the user active?" | adaptive-floor cover traffic | test [8] |
| Passive: "what is the user resolving?" | DNS confined to the tunnel via unbound | test [3], audit DNS-exposure |
| Active: port scan / probe | default-drop, silent (no reply to non-auth) | test [7], audit firewall |
| Active: forge/replay | Noise_IKpsk2 mutual auth + PSK; WG anti-replay window + handshake timestamp | audit (PSK present); design lineage |
| Active: flood / resource exhaustion | per-source new-flow rate meter on UDP/443 | audit firewall |
| Active: pivot from one compromised client | client↔client forward DROP | test [5], audit |
| Active: route injection / redirects | sysctl: no redirects, no source route, strict rp_filter | audit kernel |

## Cryptographic review

AmneziaWG (`amneziawg-go`) inherits WireGuard's Noise_IKpsk2 construction
unchanged: X25519 ECDH, ChaCha20-Poly1305 AEAD, BLAKE2s, HKDF. Properties:
perfect forward secrecy (ephemeral keys rekeyed ~every 2 min), identity hiding of
the responder, replay-protected data channel (sliding-window counter) and
replay-protected handshakes (monotonic TAI64N timestamp, greatest-seen rule). The
mandatory per-peer **PresharedKey** mixes an additional symmetric secret into the
KDF — defense-in-depth and a hedge against a future quantum break of X25519. Keys
are generated from the kernel CSPRNG (`awg genkey`/`genpsk`) and never leave
`secrets/` (mode 0600, git-ignored).

The obfuscation layer (junk packets, magic headers, init/response padding) only
adds/relocates bytes around the handshake; it does **not** alter the cryptographic
core, so it adds no cryptographic weakness while removing the on-wire fingerprint.

## Findings

- **F1 — Dynamic / CGNAT WAN (informational, environment).** The test uplink is
  behind carrier-grade NAT with a **rotating public-IP pool** (observed exits
  `5.29.14.6`, `77.137.71.251`, `77.137.77.208` across runs). Consequences:
  (a) the client `Endpoint` IP is not stable; (b) the "single shared exit IP"
  anonymity property degrades into "mixed into the ISP's CGNAT pool." Client real
  IPs remain masked and full-tunnel still holds. **Recommendation:** deploy behind
  a static public IP (or use dynamic DNS for the `Endpoint`); on a static-IP
  server both clients share exactly one exit, as designed. The endpoint generator
  takes the public endpoint as a parameter to support a DDNS hostname.

- **F2 — Single-hop limitation (by design).** A *global* adversary able to watch
  both a client's link and the server's egress simultaneously can correlate flows;
  no single-hop tunnel prevents this. Out of scope per the "single hop"
  requirement; cover traffic raises but does not eliminate correlation cost.

- **F3 — Cover traffic is floor-only (limitation).** Chaff maintains a *minimum*
  rate, masking idle-vs-active and small flows, but does not cap large real
  bursts (a constant-rate shaper would, but cannot be installed on the unmodified
  Android client). Android upstream padding depends on the OS answering the
  tunnelled ICMP echoes; downstream padding is unconditional.

- **F4 — Replay test is design-verified, not live-injected (transparency).** The
  data/handshake anti-replay properties are inherited from upstream WireGuard and
  asserted here via PSK presence + code lineage, not a live packet-injection test.
  A live replay-injection test is a recommended addition.

- **F5 — Firewall persistence; an auto-reapply watchdog was tried and reverted.**
  During validation the live `nft` ruleset was once found empty despite
  `nftables.service` being `enabled` (the service was enabled ~1h45m *after* boot,
  so it had not run this boot). The correct fix is simply ensuring the boot path
  loads it — verified by `systemctl restart nftables` (re-loads the 55-line ruleset
  and logs cleanly). A "self-healing" watchdog that *auto-reapplied* the ruleset
  every 2 min was briefly added and then **reverted**: during the F6 incident below
  it fought the operator's manual `nft flush` (silently restoring the firewall
  within 2 min), removing exactly the manual override needed in an emergency.
  Lesson: a hardening endpoint must never strip the operator's ability to take it
  down by hand. Do **not** auto-reapply firewall state.

- **F6 — Shared-medium contention under real full-tunnel load (environmental).**
  With the real Android client on the **same Wi-Fi** as the server, full-tunnel
  makes the server a Wi-Fi *relay*: every byte the client browses crosses the
  server's single radio ~4× (RX from client over the tunnel → TX to the router →
  RX the reply → TX back to the client over the tunnel), on a half-duplex medium
  behind CGNAT, shared with the server's own uplink. Under a real browsing load
  this saturated the radio/uplink and starved **both** the client's traffic and the
  server's own control plane simultaneously. Confirmed *not* a packet-filter drop
  (OUTPUT policy `accept`; `ct established` accepted first in input+forward; zero
  nft drops/martians; `nf_conntrack` 8/262144; 8 cores at load ~0.04; chaff
  correctly suppresses under load). Recovery was immediate once the client
  disconnected (load removed). **Mitigations / recommendations:** (a) put the
  server on a **wired** uplink, or place the client **off-LAN**, so the relay no
  longer contends for the client's own Wi-Fi airtime; (b) prefer split-tunnel, or
  rate-limit forwarded traffic to reserve uplink headroom, where heavy full-tunnel
  throughput is not required; (c) traffic-control QoS to prioritise host-origin
  packets would help the server's TX ordering but cannot govern 802.11 airtime from
  one station and was **not** applied blind on this single-queue Wi-Fi interface.
  The tunnel itself is correct and leak-free under moderate load; this ceiling is a
  property of the test environment (Wi-Fi-relay server, CGNAT, same-LAN client),
  not of the VPN design.

## Re-running

```bash
sudo test/sim-clients.sh all   # functional, simultaneous 2-client
sudo test/audit.sh             # static hardening audit
```
