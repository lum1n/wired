#!/usr/bin/env bash
# macOS only: builds WiredFFI.xcframework for iOS, the iOS simulator and macOS.
# Then point Package.swift at it with WIRED_XCFRAMEWORK=1.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
targets=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin)
for t in "${targets[@]}"; do
    rustup target add "$t" >/dev/null
    cargo build --manifest-path "$root/Cargo.toml" -p wired-swift --release --target "$t"
done
work=$(mktemp -d)
lipo -create "$root/target/aarch64-apple-ios-sim/release/libwired_swift.a" \
    "$root/target/x86_64-apple-ios/release/libwired_swift.a" -output "$work/libwired_swift_sim.a"
lipo -create "$root/target/aarch64-apple-darwin/release/libwired_swift.a" \
    "$root/target/x86_64-apple-darwin/release/libwired_swift.a" -output "$work/libwired_swift_macos.a"
headers="$here/Sources/WiredFFI/include"
rm -rf "$here/WiredFFI.xcframework"
xcodebuild -create-xcframework \
    -library "$root/target/aarch64-apple-ios/release/libwired_swift.a" -headers "$headers" \
    -library "$work/libwired_swift_sim.a" -headers "$headers" \
    -library "$work/libwired_swift_macos.a" -headers "$headers" \
    -output "$here/WiredFFI.xcframework"
echo "built $here/WiredFFI.xcframework"
