#!/usr/bin/env bash
# Reload the hardened nftables ruleset if it has gone missing.
#
# Liveness guard for the VPN endpoint firewall. If the `inet filter` table (our
# default-drop input/forward policy) is absent — flushed by a stray command, a
# crashed reload, or an enable-after-boot race where nftables.service never ran
# this boot — re-apply /etc/nftables.conf and log it. Idempotent and silent when
# the firewall is already present, so it is safe to run on a short timer.
#
# Rationale: an endpoint whose packet filter is silently down is unhardened
# against an active adversary. This closes that window to at most one timer
# interval instead of "until someone notices".
set -euo pipefail

CONF="/etc/nftables.conf"

if nft list table inet filter >/dev/null 2>&1; then
    exit 0   # firewall present — nothing to do
fi

logger -t awg-fw-ensure "inet filter table absent — reloading ${CONF}"
if nft -f "$CONF"; then
    logger -t awg-fw-ensure "firewall reloaded successfully"
else
    logger -t awg-fw-ensure "ERROR: firewall reload failed"
    exit 1
fi
