#!/usr/bin/env bash
# Self-contained AmneziaWG client installer for the *second* Debian machine.
# Run ON that client (not the server). Idempotent.
#
#   sudo ./install-client.sh client-debian.conf
#
# Builds AmneziaWG from source (userspace data plane), installs the supplied
# config, brings the tunnel up via systemd, and verifies the handshake + egress.
# Requires the config file (delivered out-of-band) as argument $1.
set -euo pipefail

CONF="${1:-}"
IFACE="awg0"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -f "$CONF" ]] || { echo "usage: $0 client-debian.conf" >&2; exit 1; }

echo "[1/5] installing build + runtime dependencies..." >&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq golang-go build-essential pkg-config libmnl-dev git \
    iproute2 openresolv iptables curl

if ! command -v amneziawg-go >/dev/null; then
    echo "[2/5] building AmneziaWG (userspace)..." >&2
    tmp=$(mktemp -d)
    git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git "$tmp/go"
    git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-tools.git "$tmp/tools"
    make -C "$tmp/go" >/dev/null
    install -m755 "$tmp/go/amneziawg-go" /usr/bin/amneziawg-go
    make -C "$tmp/tools/src" >/dev/null
    make -C "$tmp/tools/src" install >/dev/null
    rm -rf "$tmp"
else
    echo "[2/5] AmneziaWG already installed, skipping build" >&2
fi

echo "[3/5] installing config..." >&2
install -d -m700 /etc/amnezia/amneziawg
install -m600 "$CONF" "/etc/amnezia/amneziawg/${IFACE}.conf"

echo "[4/5] bringing up tunnel via systemd (userspace)..." >&2
install -d -m755 "/etc/systemd/system/awg-quick@${IFACE}.service.d"
cat >"/etc/systemd/system/awg-quick@${IFACE}.service.d/10-userspace.conf" <<EOF
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
EOF
systemctl daemon-reload
ip link show "$IFACE" &>/dev/null && \
    WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick down "$IFACE" || true
systemctl enable --now "awg-quick@${IFACE}"

echo "[5/5] verifying..." >&2
sleep 3
hs=$(awg show "$IFACE" latest-handshakes | awk '{print $2}')
if [[ -n "$hs" && "$hs" != "0" ]]; then
    echo "  handshake OK (ts=$hs)" >&2
else
    echo "  WARNING: no handshake yet — check Endpoint reachability/firewall" >&2
fi
echo -n "  exit IP via tunnel: " >&2; curl -s --max-time 10 https://api.ipify.org >&2; echo >&2
echo "done." >&2
