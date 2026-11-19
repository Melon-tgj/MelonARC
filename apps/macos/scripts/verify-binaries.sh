#!/usr/bin/env bash
# Check the two executables that ship in the .app before signing: both must be
# arm64 and both must declare the macOS 13.0 deployment floor. `lipo` and
# `vtool` ship with Xcode; no third-party Mach-O reader is involved.
set -euo pipefail

check_binary() {
  binary=$1
  if [ ! -f "$binary" ]; then
    echo "::error::missing binary: $binary"
    exit 1
  fi
  arch=$(lipo -archs "$binary")
  if [ "$arch" != "arm64" ]; then
    echo "::error::$binary contains $arch, expected arm64 only"
    exit 1
  fi
  build=$(vtool -show-build "$binary" 2>&1)
  if ! printf '%s\n' "$build" | grep -Eq 'minos[[:space:]]+13\.0'; then
    echo "::error::$binary does not declare minos 13.0"
    printf '%s\n' "$build"
    exit 1
  fi
  printf 'ok: %s arch=%s minos=13.0\n' "$binary" "$arch"
}

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <app-binary> <core-binary>" >&2
  exit 2
fi
check_binary "$1"
check_binary "$2"
