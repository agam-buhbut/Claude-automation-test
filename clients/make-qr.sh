#!/usr/bin/env bash
# Render the Android client config as a QR code for import into the Amnezia app.
# Writes a PNG to secrets/ (git-ignored) and, with --show, prints a scannable
# QR directly in the terminal (works over SSH).
#
# NOTE: the QR encodes the client PRIVATE KEY. Treat both the PNG and the
# on-screen code as secret — anyone who scans it gains full client access.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="${REPO}/secrets/client-android.conf"
PNG="${REPO}/secrets/client-android.png"

[[ -f "$CONF" ]] || { echo "missing $CONF (run server/gen-config.py)" >&2; exit 1; }
command -v qrencode >/dev/null || { echo "qrencode not installed" >&2; exit 1; }

qrencode -t PNG -o "$PNG" < "$CONF"
chmod 600 "$PNG"
echo "wrote $PNG ($(stat -c%s "$PNG") bytes)" >&2

if [[ "${1:-}" == "--show" ]]; then
    echo "Scan with the Amnezia app  (Add config -> scan QR):" >&2
    qrencode -t ANSIUTF8 < "$CONF"
fi
