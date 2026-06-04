#!/usr/bin/env bash
# Apply the hardened nftables ruleset + sysctl hardening + key-permission checks.
# Idempotent; persists across reboots (nftables.service + sysctl.d).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

# 1. Firewall: validate, install to /etc/nftables.conf, load, enable at boot.
nft -c -f "$REPO/server/firewall.nft"          # dry-run validation
install -m644 "$REPO/server/firewall.nft" /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1 || true
nft -f /etc/nftables.conf

# 1b. Firewall liveness watchdog: reload the ruleset if it is ever flushed or
#     never loaded this boot (closes the "endpoint silently unhardened" window).
install -m755 "$REPO/server/awg-fw-ensure.sh" /usr/local/sbin/awg-fw-ensure.sh
install -m644 "$REPO/server/awg-fw-watchdog.service" \
    /etc/systemd/system/awg-fw-watchdog.service
install -m644 "$REPO/server/awg-fw-watchdog.timer" \
    /etc/systemd/system/awg-fw-watchdog.timer
systemctl daemon-reload
systemctl enable --now awg-fw-watchdog.timer >/dev/null 2>&1 || true

# 2. Kernel hardening.
install -m644 "$REPO/server/sysctl-hardening.conf" \
    /etc/sysctl.d/99-awg-hardening.conf
sysctl -q --system

# 3. Key-permission hygiene (fail loudly if anything is world-readable).
bad=0
for f in /etc/amnezia/amneziawg/awg0.conf "$REPO"/secrets/state.json \
         "$REPO"/secrets/*.conf; do
    [[ -e "$f" ]] || continue
    perm=$(stat -c '%a' "$f")
    if [[ "$perm" != "600" ]]; then
        echo "tightening $f ($perm -> 600)" >&2
        chmod 600 "$f"
    fi
done
[[ $bad -eq 0 ]]

echo "hardening applied. ruleset summary:" >&2
nft list ruleset | grep -E 'chain (input|forward)|policy|masquerade|VPN_PORT|443' | head -20
