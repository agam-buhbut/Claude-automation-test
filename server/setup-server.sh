#!/usr/bin/env bash
# Idempotent installer for the AmneziaWG single-hop VPN server endpoint.
#
# Brings up awg0 from secrets/awg0.conf using the userspace amneziawg-go data
# plane, persisted via systemd. Does NOT configure NAT/firewall — that lives in
# server/firewall.nft (applied by server/apply-hardening.sh) so all packet-filter
# policy is in one auditable place.
#
# Prereqs: amneziawg-go, awg, awg-quick on PATH (see server/build-amneziawg.sh);
#          secrets/awg0.conf generated (see server/gen-config.py).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE="awg0"
CONF_SRC="${REPO}/secrets/${IFACE}.conf"
CONF_DST="/etc/amnezia/amneziawg/${IFACE}.conf"

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

for b in amneziawg-go awg awg-quick; do
    command -v "$b" >/dev/null || { echo "missing binary: $b" >&2; exit 1; }
done
[[ -f "$CONF_SRC" ]] || { echo "missing $CONF_SRC (run gen-config.py)" >&2; exit 1; }

# 1. Install config (root-only).
install -d -m700 /etc/amnezia/amneziawg
install -m600 "$CONF_SRC" "$CONF_DST"

# 2. systemd drop-in: force the userspace data plane (no amneziawg kernel module).
install -d -m755 "/etc/systemd/system/awg-quick@${IFACE}.service.d"
cat >"/etc/systemd/system/awg-quick@${IFACE}.service.d/10-userspace.conf" <<EOF
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
EOF

# 3. Enable IPv4/IPv6 forwarding (routing through the tunnel).
cat >/etc/sysctl.d/99-awg-forward.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -q --system

# 4. (Re)start the interface via systemd.
systemctl daemon-reload
if ip link show "$IFACE" &>/dev/null; then
    WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick down "$IFACE" || true
fi
systemctl enable "awg-quick@${IFACE}" >/dev/null
systemctl restart "awg-quick@${IFACE}"

echo "awg0 endpoint up via systemd. Status:" >&2
systemctl is-active "awg-quick@${IFACE}"
