#!/usr/bin/env python3
"""Generate AmneziaWG server + client configs for the single-hop obfuscated VPN.

All cryptographic material (private keys, pre-shared keys) and the shared
obfuscation parameters are generated once and persisted to ``secrets/state.json``
(mode 0600, git-ignored). Re-running is idempotent: existing secrets are reused,
only the rendered config files are rewritten. This lets us regenerate configs
(e.g. after changing the endpoint) without rotating keys.

Keys come from the kernel CSPRNG via ``awg genkey`` / ``awg genpsk``; obfuscation
parameters use Python's ``secrets`` module (CSPRNG). Nothing here invents crypto.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SECRETS_DIR = REPO / "secrets"
STATE_FILE = SECRETS_DIR / "state.json"


class ConfigError(Exception):
    """Raised when config generation cannot proceed."""


# --- network / obfuscation parameters (non-secret defaults) -----------------

V4_NET = "10.8.0.0/24"
V6_NET = "fd42:8::/64"
SERVER_V4 = "10.8.0.1"
SERVER_V6 = "fd42:8::1"
LISTEN_PORT = 443  # UDP/443 → blends with QUIC (HTTP/3) to a passive observer
MTU = 1280  # conservative for mobile/NAT paths + obfuscation padding overhead

# Endpoint reachable by clients. Overridden via argv[1]; default = current WAN.
DEFAULT_ENDPOINT = "77.137.77.208"

PEERS = {
    "android": {"v4": "10.8.0.2", "v6": "fd42:8::2"},
    "debian": {"v4": "10.8.0.3", "v6": "fd42:8::3"},
}


def awg(*args: str, stdin: str | None = None) -> str:
    """Run an ``awg`` subcommand and return trimmed stdout."""
    try:
        out = subprocess.run(
            ["awg", *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as e:
        raise ConfigError("awg (amneziawg-tools) not found on PATH") from e
    except subprocess.CalledProcessError as e:
        raise ConfigError(f"awg {' '.join(args)} failed: {e.stderr.strip()}") from e
    return out.stdout.strip()


def gen_keypair() -> tuple[str, str]:
    """Return (private_key, public_key)."""
    priv = awg("genkey")
    pub = awg("pubkey", stdin=priv)
    return priv, pub


def gen_psk() -> str:
    return awg("genpsk")


def distinct_headers() -> list[int]:
    """Four distinct random uint32 magic headers, all > 4 (avoid WG defaults 1-4)."""
    headers: set[int] = set()
    while len(headers) < 4:
        headers.add(secrets.randbelow(0x7FFFFFFF - 5) + 5)
    return sorted(headers)


@dataclass
class Obfuscation:
    """AmneziaWG classic obfuscation parameters (must match on every peer)."""

    Jc: int = 4  # junk packet count before handshake
    Jmin: int = 50  # min junk packet size
    Jmax: int = 1000  # max junk packet size
    S1: int = 86  # init-packet junk size
    S2: int = 574  # response-packet junk size (constraint: S1+56 != S2)
    H1: int = 0
    H2: int = 0
    H3: int = 0
    H4: int = 0

    def __post_init__(self) -> None:
        if not self.H1:
            self.H1, self.H2, self.H3, self.H4 = distinct_headers()
        if self.S1 + 56 == self.S2:
            raise ConfigError("invalid obfuscation: S1+56 must not equal S2")

    def lines(self) -> list[str]:
        return [f"{k} = {v}" for k, v in asdict(self).items()]


@dataclass
class Entity:
    """A keypair holder (server or a client)."""

    name: str
    private_key: str
    public_key: str


@dataclass
class State:
    endpoint: str
    obfs: Obfuscation
    server: Entity
    peers: dict[str, Entity] = field(default_factory=dict)
    psks: dict[str, str] = field(default_factory=dict)  # peer_name -> psk

    @classmethod
    def load_or_create(cls, endpoint: str) -> "State":
        if STATE_FILE.exists():
            raw = json.loads(STATE_FILE.read_text())
            state = cls(
                endpoint=endpoint,  # endpoint is overridable per run
                obfs=Obfuscation(**raw["obfs"]),
                server=Entity(**raw["server"]),
                peers={n: Entity(**e) for n, e in raw["peers"].items()},
                psks=raw["psks"],
            )
            return state

        spriv, spub = gen_keypair()
        state = cls(
            endpoint=endpoint,
            obfs=Obfuscation(),
            server=Entity("server", spriv, spub),
        )
        for name in PEERS:
            cpriv, cpub = gen_keypair()
            state.peers[name] = Entity(name, cpriv, cpub)
            state.psks[name] = gen_psk()
        state.save()
        return state

    def save(self) -> None:
        SECRETS_DIR.mkdir(mode=0o700, exist_ok=True)
        payload = {
            "obfs": asdict(self.obfs),
            "server": asdict(self.server),
            "peers": {n: asdict(e) for n, e in self.peers.items()},
            "psks": self.psks,
        }
        STATE_FILE.write_text(json.dumps(payload, indent=2))
        STATE_FILE.chmod(0o600)


# --- rendering --------------------------------------------------------------


def render_server(state: State) -> str:
    lines = [
        "# AmneziaWG server — single-hop obfuscated VPN endpoint",
        "# Generated by server/gen-config.py — do NOT commit (contains private key)",
        "[Interface]",
        f"Address = {SERVER_V4}/24, {SERVER_V6}/64",
        f"ListenPort = {LISTEN_PORT}",
        f"PrivateKey = {state.server.private_key}",
        f"MTU = {MTU}",
        *state.obfs.lines(),
    ]
    for name, ent in state.peers.items():
        p = PEERS[name]
        lines += [
            "",
            f"# peer: {name}",
            "[Peer]",
            f"PublicKey = {ent.public_key}",
            f"PresharedKey = {state.psks[name]}",
            f"AllowedIPs = {p['v4']}/32, {p['v6']}/128",
        ]
    return "\n".join(lines) + "\n"


def render_client(state: State, name: str) -> str:
    ent = state.peers[name]
    p = PEERS[name]
    return (
        "\n".join(
            [
                f"# AmneziaWG client config — {name}",
                "# Import into the Amnezia app (Android) or awg-quick (Linux).",
                "[Interface]",
                f"Address = {p['v4']}/32, {p['v6']}/128",
                f"PrivateKey = {ent.private_key}",
                f"DNS = {SERVER_V4}",
                f"MTU = {MTU}",
                *state.obfs.lines(),
                "",
                "[Peer]",
                f"PublicKey = {state.server.public_key}",
                f"PresharedKey = {state.psks[name]}",
                f"Endpoint = {state.endpoint}:{LISTEN_PORT}",
                "AllowedIPs = 0.0.0.0/0, ::/0",  # full-tunnel
                "PersistentKeepalive = 25",
            ]
        )
        + "\n"
    )


def main() -> int:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ENDPOINT
    state = State.load_or_create(endpoint)

    server_conf = SECRETS_DIR / "awg0.conf"
    server_conf.write_text(render_server(state))
    server_conf.chmod(0o600)

    for name in state.peers:
        client_conf = SECRETS_DIR / f"client-{name}.conf"
        client_conf.write_text(render_client(state, name))
        client_conf.chmod(0o600)

    print(f"server pubkey : {state.server.public_key}", file=sys.stderr)
    print(f"endpoint      : {endpoint}:{LISTEN_PORT}", file=sys.stderr)
    print(f"wrote         : {server_conf}", file=sys.stderr)
    for name in state.peers:
        print(f"wrote         : {SECRETS_DIR / f'client-{name}.conf'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
