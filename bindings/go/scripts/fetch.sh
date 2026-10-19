#!/usr/bin/env bash
# Downloads libwired_ffi.a from a release instead of building it, so no Rust toolchain is needed.
#   fetch.sh [version] [dir]
# version defaults to this checkout's (from Cargo.toml), dir to lib/<goos>_<goarch>/ where cgo
# looks. For a module that depends on this one, pick a dir and build with CGO_LDFLAGS=-L<dir>.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
repo=${WIRED_REPO:-lum1n/wired}

version=${1:-}
if [ -z "$version" ]; then
  version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$here/../../Cargo.toml" | head -n1)
fi
version=${version#v}
goos=$(go env GOOS)
goarch=$(go env GOARCH)
dest=${2:-"$here/lib/${goos}_$goarch"}

case "$goos-$goarch" in
  linux-amd64) platform=linux-x64 ;;
  linux-arm64) platform=linux-arm64 ;;
  darwin-arm64) platform=darwin-arm64 ;;
  *) echo "no release build for $goos/$goarch; run scripts/build.sh" >&2; exit 1 ;;
esac

asset="wired-go-$version-$platform.tar.gz"
base="https://github.com/$repo/releases/download/v$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
(
  cd "$tmp"
  grep " $asset\$" SHA256SUMS > want || { echo "$asset is not in SHA256SUMS" >&2; exit 1; }
  if command -v sha256sum >/dev/null; then sha256sum -c want; else shasum -a 256 -c want; fi
) >/dev/null
mkdir -p "$dest"
tar -xzf "$tmp/$asset" -C "$dest"
echo "fetched $dest/libwired_ffi.a ($version)"
