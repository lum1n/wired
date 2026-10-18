#!/usr/bin/env bash
# Builds libwired_ffi.a and places it where cgo looks: lib/<goos>_<goarch>/.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
cargo build --manifest-path "$root/Cargo.toml" -p wired-ffi --release
dest="$here/lib/$(go env GOOS)_$(go env GOARCH)"
mkdir -p "$dest"
cp "$root/target/release/libwired_ffi.a" "$dest/"
echo "built $dest/libwired_ffi.a"
