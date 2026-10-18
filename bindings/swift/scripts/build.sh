#!/usr/bin/env bash
# Builds the Rust library for this host, regenerates the Swift bindings and
# places the static library where Package.swift links it (lib/).
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
profile=${PROFILE:-release}
flag=$([[ $profile == release ]] && echo --release || true)

cargo build --manifest-path "$root/Cargo.toml" -p wired-swift $flag
case "$(uname)" in
    Darwin) dylib=libwired_swift.dylib ;;
    *) dylib=libwired_swift.so ;;
esac
out="$root/target/$profile"

gen=$(mktemp -d)
cargo run -q --manifest-path "$root/Cargo.toml" -p wired-swift --bin uniffi-bindgen -- \
    generate --library "$out/$dylib" --language swift --out-dir "$gen"
cp "$gen/Wired.swift" "$here/Sources/Wired/Wired.swift"
cp "$gen/WiredFFI.h" "$here/Sources/WiredFFI/include/WiredFFI.h"
# The generated modulemap imports Darwin; this one works on Linux too.
cat >"$here/Sources/WiredFFI/include/module.modulemap" <<'MAP'
module WiredFFI {
    header "WiredFFI.h"
    export *
}
MAP
rm -rf "$gen"

mkdir -p "$here/lib"
cp "$out/libwired_swift.a" "$here/lib/"
echo "built $here/lib/libwired_swift.a"
