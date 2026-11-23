#!/usr/bin/env bash
# Build the darwin/arm64 core that Xcode copies into Contents/MacOS.
# The Go toolchain is selected by go.mod; no SDK is needed (CGO is off).
#
# Release builds report the preview number. MELONARC_CORE_VERSION is the only
# input: set it to an empty string for a development build with no injection,
# in which case internal/version.Default (0.1.0-dev) is reported. A plain
# `go build` outside this script also leaves that default in place.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
project=$(cd "$here/.." && pwd)
repo=$(cd "$here/../../.." && pwd)
out=${1:-"$project/MelonARC/Core/melonarc-core"}
core_version=${MELONARC_CORE_VERSION-0.1.0-preview.1}

ldflags="-s -w"
if [ -n "$core_version" ]; then
  ldflags="$ldflags -X github.com/melon-tgj/melonarc/internal/version.Version=$core_version"
fi

mkdir -p "$(dirname "$out")"
cd "$repo"
go version
# The deployment floor is an input to both binaries. Setting it here keeps the
# Go core in step with the MACOSX_DEPLOYMENT_TARGET used by the Xcode target.
MACOSX_DEPLOYMENT_TARGET=13.0 CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -ldflags "$ldflags" -o "$out" ./cmd/melonarc-core
file "$out"
