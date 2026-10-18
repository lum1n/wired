#!/usr/bin/env bash
# NAT traversal scenario, rootless (user + network namespaces).
#
#   a (192.168.1.2) -> nat1 (masquerade) -\
#                                          pub: anchor on 10.0.1.1
#   b (192.168.2.2) -> nat2 (masquerade) -/
#
# 1. a dials echo@b: must succeed and become direct (hole punched).
# 2. UDP between the NATs is dropped: must still succeed via the relay.
#
# Usage: tests/interop/nat.sh   (builds first; needs ip, nft, unshare)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
if [[ "${1:-}" != "--inside" ]]; then
    cargo build -q --manifest-path "$root/Cargo.toml" --bin wired --example probe
    exec unshare -Urnm --propagation private "$0" --inside
fi

W="$root/target/debug/wired"
P="$root/target/debug/examples/probe"
work=$(mktemp -d)
mount -t tmpfs none /run
mkdir -p /run/netns

ns() { ip netns add "$1"; ip -n "$1" link set lo up; }
link() { # link <ns1> <if1> <addr1> <ns2> <if2> <addr2>
    ip link add "$2" type veth peer name "$5"
    ip link set "$2" netns "$1"; ip link set "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"; ip -n "$4" addr add "$6" dev "$5"
    ip -n "$1" link set "$2" up; ip -n "$4" link set "$5" up
}
masquerade() { # masquerade <ns> <uplink>
    ip netns exec "$1" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$1" nft -f - <<NFT
table ip nat {
    chain post {
        type nat hook postrouting priority 100;
        oifname "$2" masquerade
    }
}
# Like a home router: drop unsolicited inbound UDP instead of answering it.
# Otherwise conntrack records the probe and remaps the inside host's port.
table ip filter {
    chain input {
        type filter hook input priority 0;
        iifname "$2" meta l4proto udp ct state new drop
    }
}
NFT
}

for n in pub nat1 nat2 a b; do ns $n; done
link pub p1 10.0.1.1/24 nat1 u1 10.0.1.2/24
link pub p2 10.0.2.1/24 nat2 u2 10.0.2.2/24
link nat1 d1 192.168.1.1/24 a e1 192.168.1.2/24
link nat2 d2 192.168.2.1/24 b e2 192.168.2.2/24
ip netns exec pub sysctl -qw net.ipv4.ip_forward=1
ip -n nat1 route add default via 10.0.1.1
ip -n nat2 route add default via 10.0.2.1
ip -n a route add default via 192.168.1.1
ip -n b route add default via 192.168.2.1
masquerade nat1 u1
masquerade nat2 u2

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

ip netns exec pub "$W" anchor --name vps --public-host 10.0.1.1 --state-dir "$work/vps" \
    >"$work/invite" 2>"$work/vps.log" & pids+=($!)
for _ in $(seq 50); do [[ -s "$work/invite" ]] && break; sleep 0.1; done
export WIRED_INVITE=$(cat "$work/invite")

ip netns exec b "$P" serve b 2>"$work/b.log" & pids+=($!)
sleep 2

fail=0
out=$(ip netns exec a "$P" dial a b 2>"$work/a1.log") || true
echo "[1] NAT <-> NAT:     ${out//$'\n'/ }"
[[ "$out" == *"roundtrip=ok"* && "$out" == *"path=Direct"* ]] || { echo "    FAIL (want direct)"; fail=1; }

ip netns exec pub nft -f - <<'NFT'
table ip filter {
    chain forward_udp {
        type filter hook forward priority 0;
        meta l4proto udp drop
    }
}
NFT
out=$(ip netns exec a "$P" dial a2 b 2>"$work/a2.log") || true
echo "[2] UDP blocked:     ${out//$'\n'/ }"
[[ "$out" == *"roundtrip=ok"* && "$out" == *"path=Relay"* ]] || { echo "    FAIL (want relay)"; fail=1; }

if [[ $fail != 0 ]]; then
    for f in "$work"/*.log; do echo "--- $f"; tail -${LOG_LINES:-20} "$f"; done
fi
exit $fail
