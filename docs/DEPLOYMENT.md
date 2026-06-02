# Deployment & Reachability

## Reachability investigation (server uplink)

Measured on the server's Wi‑Fi uplink (`wlp1s0`):

- **IPv4 is carrier-grade NAT (CGNAT).** The external IPv4 rotates between
  multiple pool addresses within seconds (`5.29.14.6` ↔ `77.137.71.251`), and a
  traceroute shows the local router (`192.168.1.1`) followed by several hidden
  carrier hops before the ISP core (`213.57.1.69`). **Consequence:** forwarding
  `UDP/443` on the home router does **not** expose the server to the Internet —
  the authoritative NAT is upstream at the carrier and is not user-controllable.
- **IPv6 is currently absent.** A global IPv6 address was present at first recon
  but is no longer assigned to `wlp1s0` (link-local only, no IPv6 default route,
  IPv6 unreachable). So IPv6-direct is not available *as currently configured*.

## Decision: LAN endpoint for real-client validation

Because neither inbound Internet path is currently available, the real clients
are validated over the **local network**: the client `Endpoint` is the server's
LAN address `192.168.1.3:443`. Both the Android phone and the Debian client
connect to it directly while on the home Wi‑Fi — bypassing CGNAT entirely. This
is a fully real test of the actual client software (Amnezia app + AmneziaWG on
Debian) against the live, hardened server, including simultaneous operation,
full-tunnel egress, tunnel DNS, and obfuscation. Only Internet-side traversal is
out of scope on this uplink, and that is an environment limitation, not a VPN
defect.

## Going remote (off-LAN clients)

To serve clients that are **not** on the home LAN, the server needs a genuine
public ingress for `UDP/443`. In order of preference for this environment:

1. **Persistent global IPv6 + inbound allow (recommended).** The ISP already
   handed out IPv6 once; make it persistent on the router and allow inbound
   `UDP/443` to the server in the router's IPv6 firewall (no NAT needed). Set the
   client `Endpoint` to the server's global IPv6 (or, better, a DDNS AAAA record,
   since the delegated prefix can change).
2. **Non-CGNAT public IPv4 + port-forward.** Obtain a real public IPv4 from the
   ISP (often an option/upgrade), forward `UDP/443` → `192.168.1.3`, and use a
   DDNS A record for the `Endpoint` (the address may still be dynamic).

Then regenerate client configs for the public endpoint — **keys and obfuscation
parameters are unchanged; only the `Endpoint` line differs**:

```bash
python3 server/gen-config.py vpn.example.org   # DDNS hostname or public IP/IPv6
clients/make-qr.sh --show                       # re-issue Android QR
# redeliver secrets/client-debian.conf to the Debian client
```

No server-side service restart is required for an endpoint change (the endpoint
lives only in the client configs).
