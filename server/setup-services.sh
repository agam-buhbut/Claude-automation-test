#!/usr/bin/env bash
# Install the tunnel-only DNS resolver and the cover-traffic daemon.
# Idempotent. Run after setup-server.sh.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

# --- tunnel-only recursive resolver (unbound) ---
command -v unbound >/dev/null || { echo "unbound not installed" >&2; exit 1; }
install -m644 "$REPO/server/unbound-awg.conf" /etc/unbound/unbound.conf.d/awg.conf
# Ensure the DNSSEC root trust anchor exists (Debian ships a known-good copy).
if [[ ! -s /var/lib/unbound/root.key ]]; then
    install -o unbound -g unbound -m644 /usr/share/dns/root.key /var/lib/unbound/root.key
fi
unbound-checkconf >/dev/null
systemctl enable unbound >/dev/null 2>&1 || true
systemctl restart unbound

# --- cover-traffic daemon ---
install -m755 "$REPO/cover-traffic/chaff.py" /usr/local/bin/awg-chaff
install -m644 "$REPO/cover-traffic/awg-chaff.service" /etc/systemd/system/awg-chaff.service
systemctl daemon-reload
systemctl enable --now awg-chaff

echo "services:" >&2
for s in unbound awg-chaff; do printf '  %-10s %s\n' "$s" "$(systemctl is-active "$s")" >&2; done
