#!/bin/sh
# Build the preview release archive: two binaries, the documents that ship with
# them, and one tar.gz whose digest is printed at the end.
#
# Usage:
#   scripts/build-release.sh 0.1.0-preview.1
#
# What it does, in order:
#   1. builds melonarc-core and melonarc-cli for linux/amd64 with -trimpath and
#      "-s -w", and injects the version into internal/version.Version;
#   2. fills a staging directory melonarc-<version>-linux-amd64/ with the two
#      binaries, the example configuration, the licence and the three documents a
#      reader needs before running a binary from the internet;
#   3. writes dist-release/melonarc-<version>-linux-amd64.tar.gz and prints its
#      SHA-256.
#
# It does not tag, does not publish and does not touch the network. The archive
# is not claimed to be bit-reproducible: tar records modification times and gzip
# records the time it ran.
#
# The whole point of the injected version is that the archive, the binaries and
# the documents agree on one number, so the two binaries are asked what they are
# after the build. Running them is the check; on a machine that cannot execute a
# linux/amd64 binary the build still succeeds and the check is skipped.

set -u

usage() {
    cat <<'EOF'
usage: scripts/build-release.sh <version>

Build dist-release/melonarc-<version>-linux-amd64.tar.gz from the current tree.
The version is injected into the binaries and into the archive name, for example
0.1.0-preview.1.
EOF
}

die() {
    printf 'build-release: %s\n' "$*" >&2
    exit 1
}

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi

version=$1
# The version becomes part of a directory name this script deletes and recreates,
# so it may not contain a slash, a space or a shell metacharacter.
case $version in
    '' | *[!0-9A-Za-z._+-]* | [!0-9A-Za-z]*)
        die "not a version string: '$version'"
        ;;
esac

# Repository root, derived from where this script lives rather than from the
# caller's working directory.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || die "cannot resolve the script directory"
root=$(dirname -- "$here") || die "cannot resolve the repository root"
[ -f "$root/go.mod" ] || die "$root does not look like the repository root"

command -v go >/dev/null 2>&1 || die "go is not on PATH"

name="melonarc-$version-linux-amd64"
out="$root/dist-release"
stage="$out/$name"
tarball="$out/$name.tar.gz"

# Re-runnable: the two paths below are the ones this script owns, and they are
# computed from a validated version, never from an argument used verbatim.
rm -rf -- "$stage" "$tarball" || die "cannot clear the previous output"
mkdir -p -- "$stage" || die "cannot create $stage"

printf 'build-release: building %s\n' "$version"

ldflags="-s -w -X github.com/melon-tgj/melonarc/internal/version.Version=$version"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "$ldflags" -o "$stage/melonarc-core" ./cmd/melonarc-core ||
    die "melonarc-core did not build"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "$ldflags" -o "$stage/melonarc-cli" ./cmd/melonarc-cli ||
    die "melonarc-cli did not build"

for file in LICENSE README.md THIRD-PARTY-NOTICES.md SECURITY.md; do
    [ -f "$root/$file" ] || die "$file is missing from the repository root"
    cp -- "$root/$file" "$stage/$file" || die "cannot copy $file"
done
[ -f "$root/examples/melonarc.conf" ] || die "examples/melonarc.conf is missing"
cp -- "$root/examples/melonarc.conf" "$stage/melonarc.conf" || die "cannot copy the example configuration"

# Sizes are printed because the two numbers a preview reader asks about first are
# "how big is the download" and "did the strip flags actually apply".
bytes() {
    wc -c <"$1" | tr -d ' '
}
printf 'build-release: melonarc-core %s bytes\n' "$(bytes "$stage/melonarc-core")"
printf 'build-release: melonarc-cli  %s bytes\n' "$(bytes "$stage/melonarc-cli")"

# The binaries answer with the injected number. They cannot be executed when this
# runs on a non-linux host, which is not an error for a cross build.
if [ "$(uname -s 2>/dev/null)" = "Linux" ] && [ "$(uname -m 2>/dev/null)" = "x86_64" ]; then
    reported=$("$stage/melonarc-cli" version 2>/dev/null) || reported=""
    if [ "$reported" != "melonarc-cli $version" ]; then
        die "the built CLI reports '$reported', expected 'melonarc-cli $version'"
    fi
    printf 'build-release: the built CLI reports %s\n' "$reported"
else
    printf 'build-release: not a linux/x86_64 host, so the injected version was not read back\n'
fi

tar -czf "$tarball" -C "$out" "$name" || die "cannot write $tarball"

if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum -- "$tarball" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 -- "$tarball" | cut -d' ' -f1)
else
    die "no sha256sum or shasum on PATH, so the archive cannot be identified"
fi

printf 'build-release: %s\n' "$tarball"
printf 'build-release: %s bytes\n' "$(bytes "$tarball")"
printf 'build-release: sha256 %s\n' "$digest"
