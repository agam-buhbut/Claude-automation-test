# Single-Hop Obfuscated VPN

A hardened, single-hop VPN endpoint on Debian serving **two simultaneous
clients** (one Android, one Debian), built on **AmneziaWG** — WireGuard's
cryptographic core plus a DPI/obfuscation layer.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design and threat model.

## Goals (per spec)

- Functional endpoint usable by **two clients at once** — ✔ (peers `android`, `debian`)
- **Secured** — Noise_IKpsk2: Curve25519 / ChaCha20-Poly1305, PFS, per-peer PSK
- **Anonymising** — shared exit IP, full-tunnel, tunnel-only DNS, no leaks
- **Obfuscated** — AmneziaWG junk packets + randomised headers; UDP/443 ≈ QUIC
- **Hardened** — silent firewall, anti-replay, rate-limited, sysctl-hardened
- **Audited + tested** — network-namespace simulation + external probe/leak audit

## Layout

```
server/    build, key/config generation, bring-up, hardening
clients/   Android (QR) and Debian client provisioning
cover-traffic/  constant-rate chaff daemon (traffic-analysis resistance)
test/      network-namespace 2-client simulation + audit harness
docs/      design, threat model, audit report
secrets/   keys + live configs — GIT-IGNORED, never committed
```

## Quick start (server)

```bash
sudo apt install -y golang-go build-essential pkg-config libmnl-dev \
     nftables qrencode unbound iproute2
server/build-amneziawg.sh      # build + install AmneziaWG from source
python3 server/gen-config.py [PUBLIC_ENDPOINT]   # generate keys + configs
sudo server/setup-server.sh    # bring up awg0 (userspace) via systemd
sudo server/apply-hardening.sh # nftables + sysctl hardening (Pass 3)
```

Private keys never leave `secrets/`. Client configs are delivered out-of-band
(QR for Android, encrypted file for Debian).

## Status

Built incrementally; see git history. Each "pass" (endpoint → obfuscation/DNS →
hardening → test/audit → client rollout) is committed and pushed on completion.
