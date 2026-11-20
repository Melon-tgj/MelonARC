#!/usr/bin/env bash
# Check the two executables that ship in the .app before signing: both must be
# arm64 and both must declare the macOS 13.0 deployment floor. The shell must
# also carry the pinned Xcode SDK. `lipo` and `xcrun vtool` ship with Xcode; no
# third-party Mach-O reader is involved.
set -euo pipefail

expected_sdk=26.2

check_binary() {
  binary=$1
  want_sdk=${2:-}
  if [ ! -f "$binary" ]; then
    echo "::error::missing binary: $binary"
    exit 1
  fi
  arch=$(lipo -archs "$binary")
  if [ "$arch" != "arm64" ]; then
    echo "::error::$binary contains $arch, expected arm64 only"
    exit 1
  fi
  build=$(xcrun vtool -show-build "$binary" 2>&1)
  if ! printf '%s\n' "$build" | grep -Eq 'minos[[:space:]]+13\.0'; then
    echo "::error::$binary does not declare minos 13.0"
    printf '%s\n' "$build"
    exit 1
  fi
  if [ -n "$want_sdk" ] && ! printf '%s\n' "$build" | grep -Eq "sdk[[:space:]]+${want_sdk//./\\.}"; then
    echo "::error::$binary was not built with SDK $want_sdk"
    printf '%s\n' "$build"
    exit 1
  fi
  printf 'ok: %s arch=%s minos=13.0%s\n' "$binary" "$arch" "${want_sdk:+ sdk=$want_sdk}"
}

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <app-binary> <core-binary>" >&2
  exit 2
fi
check_binary "$1" "$expected_sdk"
check_binary "$2"
