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

## Re-running

```bash
sudo test/sim-clients.sh all   # functional, simultaneous 2-client
sudo test/audit.sh             # static hardening audit
```
