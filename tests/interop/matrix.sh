#!/usr/bin/env bash
# Cross-language matrix: an echo server in each binding, dialed from each binding.
# Usage: tests/interop/matrix.sh   (builds everything first)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

echo "building..."
cargo build -q --manifest-path "$root/Cargo.toml" --bin wired --example probe
(cd "$root/bindings/go" && ./scripts/build.sh >/dev/null && go build -o "$work/go-echo" ./cmd/wired-echo)
(cd "$root/bindings/node" && node scripts/build.mjs >/dev/null)
(cd "$root/bindings/swift" && ./scripts/build.sh >/dev/null && swift build -q -c release --product wired-echo)

declare -A run=(
    [rust]="$root/target/debug/examples/probe"
    [go]="$work/go-echo"
    [node]="node $root/bindings/node/examples/echo.js"
    [swift]="$root/bindings/swift/.build/release/wired-echo"
)
langs=(rust go node swift)

"$root/target/debug/wired" anchor --name vps --port 0 --qad-port 0 --public-host 127.0.0.1 \
    --state-dir "$work/vps" >"$work/invite" 2>"$work/vps.log" & pids+=($!)
for _ in $(seq 50); do [[ -s "$work/invite" ]] && break; sleep 0.1; done
export WIRED_INVITE=$(cat "$work/invite")

for l in "${langs[@]}"; do
    ${run[$l]} serve "$l-srv" 2>"$work/$l-srv.log" & pids+=($!)
done
sleep 3

fail=0
printf '%-8s' "dial→"; printf '%-8s' "${langs[@]}"; echo
for from in "${langs[@]}"; do
    printf '%-8s' "$from"
    for to in "${langs[@]}"; do
        if out=$(timeout 30 ${run[$from]} dial "$from-to-$to" "$to-srv" 2>"$work/$from-$to.log") \
            && [[ "$out" == *"roundtrip=ok"* ]]; then
            printf '%-8s' ok
        else
            printf '%-8s' FAIL; fail=1
        fi
    done
    echo
done
if [[ $fail != 0 ]]; then
    for f in "$work"/*.log; do echo "--- $f"; tail -5 "$f"; done
fi
exit $fail
