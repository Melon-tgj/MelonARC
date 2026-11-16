#!/bin/sh
# Build the preview release archive: two binaries, the documents that ship with
# them, the third-party licence texts, and one tar.gz whose digest is printed at
# the end.
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
#   3. copies the licence texts of every third-party module linked into
#      melonarc-core into licenses/, one file per module (checklist B2);
#   4. writes dist-release/melonarc-<version>-linux-amd64.tar.gz and prints its
#      SHA-256.
#
# It does not tag, does not publish and does not touch the network. The archive
# is not claimed to be bit-reproducible: tar records modification times and gzip
# records the time it ran. The licence texts are read from the local Go module
# cache with GOPROXY=off, so a build cannot quietly download a text instead.
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
tmp="$out/.build-release-licences"

# Re-runnable: the paths below are the ones this script owns, and they are
# computed from a validated version, never from an argument used verbatim.
rm -rf -- "$stage" "$tarball" "$tmp" || die "cannot clear the previous output"
mkdir -p -- "$stage" "$tmp" || die "cannot create $stage"

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

# --- third-party licence texts (pre-release checklist B2) -------------------
#
# Which modules: the dep lines of the core we just built are the authoritative
# answer to "what is in the artefact". THIRD-PARTY-NOTICES.md section 1 is the
# published index, so the two sets are compared first: a dependency change that
# is not reflected in that file fails the build instead of shipping an archive
# whose notices and licence texts disagree.
#
# Which texts: every LICENSE/LICENCE/COPYING/NOTICE file at the root of that
# exact module version in the local Go module cache. A module that ships
# several (the SQLite driver does) gets all of them in its one bundle, each
# under a separator naming the original file. Each source is checked to exist
# and to be non-empty before it is copied verbatim.

expected_linked=17
awk '
    /^## 1\./ { in1 = 1; next }
    /^## 2\./ { in1 = 0 }
    in1 && /^\| `/ {
        split($0, f, "|")
        m = f[2]; v = f[3]
        gsub(/[` \t]/, "", m)
        gsub(/[ \t]/, "", v)
        if (m != "" && v ~ /^v/) print m "@" v
    }
' "$root/THIRD-PARTY-NOTICES.md" | LC_ALL=C sort > "$tmp/notices" ||
    die "cannot read THIRD-PARTY-NOTICES.md section 1"
go version -m "$stage/melonarc-core" |
    awk '$1 == "dep" { print $2 "@" $3 }' |
    LC_ALL=C sort > "$tmp/deps" || die "cannot read the core build info"
cmp -s "$tmp/notices" "$tmp/deps" ||
    die "THIRD-PARTY-NOTICES.md section 1 is out of sync with the core's linked modules"
nmods=$(wc -l < "$tmp/deps" | tr -d ' ')
# The count is a tripwire, not a derived value: stage 21/24 recorded 17 linked
# modules. A dependency change has to update the notices table and this number
# together; failing closed is better than shipping a stale licence set.
[ "$nmods" -eq "$expected_linked" ] ||
    die "expected $expected_linked linked modules, found $nmods (update the notices and this script together)"

licdir="$stage/licenses"
mkdir -p -- "$licdir" || die "cannot create $licdir"
nlic=0
while IFS= read -r mod; do
    [ -n "$mod" ] || continue

    # Cache-only lookup. GOPROXY=off makes an uncached module fail instead of
    # being fetched, which keeps the archive's licence texts local and auditable.
    dir=$(GOPROXY=off GOSUMDB=off go mod download -json "$mod" 2>/dev/null |
          sed -n 's/^[[:space:]]*"Dir":[[:space:]]*"\([^"]*\)".*/\1/p')
    [ -n "$dir" ] && [ -d "$dir" ] ||
        die "no local module-cache copy of $mod (GOPROXY=off)"

    find "$dir" -maxdepth 1 -type f \
        \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) \
        -print | LC_ALL=C sort > "$tmp/files" || die "cannot list licence files in $dir"
    [ -s "$tmp/files" ] || die "no licence file found in $dir"

    safe=$(printf '%s' "$mod" | tr '/' '_')
    target="$licdir/$safe.txt"
    nfiles=$(wc -l < "$tmp/files" | tr -d ' ')
    {
        printf 'Third-party licence texts for %s\n' "$mod"
        # Symbolic, not absolute: a shipped file must not carry a local account
        # name (pre-release checklist A7). The bundle still names the exact
        # module version, which is what a reader needs to find the source.
        printf 'Source: local Go module cache, $GOMODCACHE/%s\n' "$mod"
        printf '\n'
        printf 'Generated by scripts/build-release.sh (pre-release checklist B2).\n'
        printf 'Each section below is a byte-for-byte copy of the named licence\n'
        printf 'file at the root of this exact module version. The separator lines\n'
        printf 'are added by the build script and are not part of any licence text.\n'
        printf 'Files included (%s):\n' "$nfiles"
        while IFS= read -r f; do printf '  - %s\n' "${f##*/}"; done < "$tmp/files"
        printf '\n'
    } > "$target" || die "cannot write $target"

    while IFS= read -r f; do
        [ -s "$f" ] || die "licence file is missing or empty: $f"
        printf '\n===== %s =====\n\n' "${f##*/}" >> "$target" || die "cannot write $target"
        cat "$f" >> "$target" || die "cannot copy $f"
        printf '\n' >> "$target" || die "cannot write $target"
        nlic=$((nlic + 1))
    done < "$tmp/files"
    printf 'build-release: licences %s -> %s (%s file(s))\n' "$mod" "$safe.txt" "$nfiles"
done < "$tmp/deps"
printf 'build-release: %s module licence bundles, %s licence files\n' "$nmods" "$nlic"
rm -rf -- "$tmp" || die "cannot clear $tmp"

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
