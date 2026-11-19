#!/usr/bin/env bash
# Build the darwin/arm64 core that Xcode copies into Contents/MacOS.
# The Go toolchain is selected by go.mod; no SDK is needed (CGO is off).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
project=$(cd "$here/.." && pwd)
repo=$(cd "$here/../../.." && pwd)
out=${1:-"$project/MelonARC/Core/melonarc-core"}

mkdir -p "$(dirname "$out")"
cd "$repo"
go version
# The deployment floor is an input to both binaries. Setting it here keeps the
# Go core in step with the MACOSX_DEPLOYMENT_TARGET used by the Xcode target.
MACOSX_DEPLOYMENT_TARGET=13.0 CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/melonarc-core
file "$out"
