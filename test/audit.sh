#!/usr/bin/env bash
# Read-only security audit of the live VPN server. Makes no changes.
# Complements the functional end-to-end test (sim-clients.sh) with static
# configuration / hardening checks.   sudo test/audit.sh
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

echo "== Crypto / obfuscation =="
dump=$(awg show awg0 dump)
read -r _ _ _ jc _ _ _ _ _ _ h1 h2 h3 h4 _ <<<"$(echo "$dump" | head -1 | tr '\t' ' ')"
[[ "${jc:-0}" -gt 0 ]] && ok "junk-packet obfuscation active (Jc=$jc)" || bad "no junk packets (Jc)"
if [[ "$h1" != "1" && "$h2" != "2" && "$h3" != "3" && "$h4" != "4" \
      && "$h1" != "$h2" && "$h1" != "$h3" && "$h1" != "$h4" ]]; then
    ok "magic headers randomised & distinct (not WG defaults)"
else bad "magic headers look default/duplicated (H=$h1,$h2,$h3,$h4)"; fi
npeer=$(echo "$dump" | tail -n +2 | wc -l)
npsk=$(awg show awg0 preshared-keys | grep -cvE 'none$')
[[ "$npsk" -eq "$npeer" && "$npeer" -gt 0 ]] \
    && ok "all $npeer peers have a PresharedKey (extra symmetric layer)" \
    || bad "only $npsk/$npeer peers have a PSK"

echo "== Firewall =="
# Capture once into variables — grepping a pipe with `grep -q` under pipefail can
# SIGPIPE the producer (nft) on long output and yield a false failure.
input_chain=$(nft list chain inet filter input)
fwd_chain=$(nft list chain inet filter forward)
ruleset=$(nft list ruleset)
grep -q 'policy drop' <<<"$input_chain" && ok "input policy = drop (silent)" || bad "input not default-drop"
grep -q 'policy drop' <<<"$fwd_chain" && ok "forward policy = drop" || bad "forward not default-drop"
grep -qE 'iifname "awg0" oifname "awg0" drop' <<<"$fwd_chain" && ok "client<->client isolation rule present" || bad "no client isolation rule"
grep -q 'masquerade' <<<"$ruleset" && ok "egress masquerade present" || bad "no masquerade"
grep -q 'awgflood' <<<"$input_chain" && ok "per-source flood limiter on VPN port" || bad "no flood limiter"

echo "== Kernel hardening =="
for kv in net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 \
          net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.all.accept_source_route=0 \
          net.ipv4.tcp_syncookies=1; do
    k=${kv%=*}; want=${kv#*=}; have=$(sysctl -n "$k" 2>/dev/null)
    [[ "$have" == "$want" ]] && ok "$k=$have" || bad "$k=$have (want $want)"
done

echo "== Key hygiene =="
p=$(stat -c '%a %U' /etc/amnezia/amneziawg/awg0.conf 2>/dev/null)
[[ "$p" == "600 root" ]] && ok "server config 600 root" || bad "server config perms: $p"
wr=$(find "$REPO/secrets" -type f ! -perm 600 2>/dev/null | wc -l)
[[ "$wr" -eq 0 ]] && ok "no over-permissive files in secrets/" || bad "$wr secret file(s) not 600"
git -C "$REPO" ls-files | grep -qE 'secrets/|\.key$' && bad "secrets tracked in git!" || ok "no secrets tracked in git"

echo "== DNS exposure =="
# unbound must NOT answer on the public LAN interface.
if timeout 3 dig +time=2 +tries=1 @192.168.1.3 example.com >/dev/null 2>&1; then
    bad "resolver answers on public interface (192.168.1.3)"
else ok "resolver not reachable on public interface"; fi

echo "== Services =="
for s in awg-quick@awg0 unbound awg-chaff; do
    a=$(systemctl is-active "$s"); [[ "$a" == active ]] && ok "$s active" || bad "$s = $a"
done
# nftables is a oneshot (loads /etc/nftables.conf at boot then exits, so
# is-active=inactive is expected). What matters: enabled for boot + rules loaded.
en=$(systemctl is-enabled nftables 2>/dev/null)
if [[ "$en" == enabled ]] && nft list table inet filter >/dev/null 2>&1; then
    ok "nftables enabled at boot & ruleset loaded"
else bad "nftables not enabled ($en) or ruleset absent"; fi

echo "----------------------------------------"
echo "AUDIT: $PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
