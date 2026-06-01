#!/usr/bin/env bash
# Build + install AmneziaWG from source (userspace data plane + control tools).
# Reproduces the toolchain used by the server. Requires: go, gcc, make, git,
# pkg-config, libmnl-dev. Installs amneziawg-go, awg, awg-quick to /usr.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${REPO}/build"
mkdir -p "$BUILD"

clone() { [[ -d "$BUILD/$2" ]] || git clone --depth=1 "$1" "$BUILD/$2"; }
clone https://github.com/amnezia-vpn/amneziawg-go.git    amneziawg-go
clone https://github.com/amnezia-vpn/amneziawg-tools.git amneziawg-tools

echo "building amneziawg-go..." >&2
make -C "$BUILD/amneziawg-go" >/dev/null
sudo install -m755 "$BUILD/amneziawg-go/amneziawg-go" /usr/bin/amneziawg-go

echo "building amneziawg-tools..." >&2
make -C "$BUILD/amneziawg-tools/src" >/dev/null
sudo make -C "$BUILD/amneziawg-tools/src" install >/dev/null

echo "installed:" >&2
for b in amneziawg-go awg awg-quick; do printf '  %s -> %s\n' "$b" "$(command -v "$b")" >&2; done
