#!/usr/bin/env bash
# Validates the frozen candidate and records the facts a reviewer needs to
# reproduce it: source commit, Xcode build number, candidate version and the
# SHA-256 of the .dmg file itself. Apple tools do the signing and hashing; this
# script only checks their output and writes the manifest beside the artifact.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)

app=$1
dmg=$2
commit=$3
build_number=$4
version=$5
metadata=$6

fail() {
  echo "::error::$1"
  exit 1
}

[ -d "$app" ] || fail "the candidate app is missing: $app"
[ -f "$dmg" ] || fail "the candidate DMG is missing: $dmg"
[ -f "$dmg.sha256" ] || fail "the DMG checksum file is missing: $dmg.sha256"

dmg_name=$(basename "$dmg")
app_name=$(basename "$app")
[[ "$dmg_name" =~ ^melonarc-[A-Za-z0-9._-]+-macos-arm64\.dmg$ ]] \
  || fail "the DMG name must be melonarc-<version>-macos-arm64.dmg: $dmg_name"
[ "$app_name" = "MelonARC.app" ] || fail "the bundle name must be MelonARC.app: $app_name"

resources="$app/Contents/Resources"
for document in LICENSE THIRD-PARTY-NOTICES.md SECURITY.md README.md PRIVACY.md; do
  [ -s "$resources/$document" ] || fail "the bundle has no bundled declaration: $document"
done
grep -q 'GNU GENERAL PUBLIC LICENSE' "$resources/LICENSE" \
  || fail "the bundled license is not the GPL text"
grep -q 'GPL-3.0-only' "$resources/THIRD-PARTY-NOTICES.md" \
  || fail "the bundled notices do not state GPL-3.0-only"
grep -q 'Privacy statement' "$resources/PRIVACY.md" \
  && grep -q '隐私声明' "$resources/PRIVACY.md" \
  || fail "the bundled privacy statement is not bilingual"

# The core in this bundle is the authority for what the bundle has to declare.
# Section 1 of the bundled notices is the published index; its Darwin column
# must name the same module versions, each with a non-empty licence text bundle.
command -v go >/dev/null 2>&1 || fail "go is required to verify the bundled core's modules"
core="$app/Contents/MacOS/melonarc-core"
[ -f "$core" ] || fail "the bundled core is missing: $core"
licdir="$resources/licenses"
[ -d "$licdir" ] || fail "the bundle has no third-party licence texts: $licdir"

licence_work=$(mktemp -d "${TMPDIR:-/tmp}/melonarc-licence-check.XXXXXX")
trap 'rm -rf "$licence_work"' EXIT
awk '
    /^## 1\./ { in1 = 1; next }
    /^## 2\./ { in1 = 0 }
    in1 && /^\| `/ {
        split($0, f, "|")
        m = f[2]; v = f[3]; darwin = f[6]
        gsub(/[` \t]/, "", m)
        gsub(/[ \t]/, "", v)
        gsub(/[ \t]/, "", darwin)
        if (darwin != "yes" && darwin != "no") exit 1
        if (m != "" && v ~ /^v/ && darwin == "yes") print m "@" v
    }
' "$resources/THIRD-PARTY-NOTICES.md" > "$licence_work/declared" \
  || fail "cannot read the Darwin column of the bundled notices"
LC_ALL=C sort "$licence_work/declared" > "$licence_work/sorted-declared" \
  || fail "cannot sort the declared Darwin modules"
go version -m "$core" | awk '$1 == "dep" { print $2 "@" $3 }' | LC_ALL=C sort > "$licence_work/deps" \
  || fail "cannot read the bundled core's build info"
[ -s "$licence_work/deps" ] || fail "the bundled core reports no linked modules"
if ! cmp -s "$licence_work/sorted-declared" "$licence_work/deps"; then
  diff -u "$licence_work/sorted-declared" "$licence_work/deps" >&2 || true
  fail "the bundled notices' Darwin column does not match the bundled core's linked modules"
fi
while IFS= read -r mod; do
  [ -n "$mod" ] || continue
  safe=$(printf '%s' "$mod" | tr '/' '_')
  bundle="$licdir/$safe.txt"
  [ -s "$bundle" ] || fail "missing or empty licence bundle for $mod: $bundle"
done < "$licence_work/deps"

bash "$here/verify-app-icon.sh" "$app"

copyright=$(plutil -extract NSHumanReadableCopyright raw -o - "$app/Contents/Info.plist") \
  || fail "the bundle copyright could not be read"
printf '%s\n' "$copyright" | grep -q 'GPL-3.0-only' \
  || fail "the bundle copyright does not state GPL-3.0-only"

minimum=$(plutil -extract LSMinimumSystemVersion raw -o - "$app/Contents/Info.plist") \
  || fail "the bundle minimum system version could not be read"
[ "$minimum" = "13.0" ] || fail "the bundle minimum system version is $minimum, expected 13.0"

short_version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist") \
  || fail "the bundle short version could not be read"
bundle_id=$(plutil -extract CFBundleIdentifier raw -o - "$app/Contents/Info.plist") \
  || fail "the bundle identifier could not be read"
bundle_build=$(plutil -extract CFBundleVersion raw -o - "$app/Contents/Info.plist") \
  || fail "the bundle build could not be read"
[ "$bundle_build" = "$build_number" ] \
  || fail "the bundle build $bundle_build disagrees with the frozen build $build_number"
[ "$bundle_id" = "org.melonarc.app" ] || fail "the bundle identifier is $bundle_id, expected org.melonarc.app"
[[ "$short_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "the bundle short version is not numeric: $short_version"
[[ "$build_number" =~ ^[0-9]+$ ]] || fail "the frozen build is not decimal: $build_number"

shell_arch=$(xcrun lipo -archs "$app/Contents/MacOS/MelonARC" | awk '{print $1}')
core_arch=$(xcrun lipo -archs "$app/Contents/MacOS/melonarc-core" | awk '{print $1}')
[ "$shell_arch" = arm64 ] && [ "$core_arch" = arm64 ] \
  || fail "the verified executables must both be arm64: shell=$shell_arch core=$core_arch"

expected=$(shasum -a 256 "$dmg" | awk '{print $1}')
recorded=$(awk '{print $1}' "$dmg.sha256")
[ "$expected" = "$recorded" ] || fail "the checksum sidecar does not match the DMG file"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "the DMG checksum is not a SHA-256 digest"

mkdir -p "$(dirname "$metadata")"
python3 - "$metadata" "$dmg_name" "$commit" "$build_number" "$version" "$expected" \
  "$short_version" "$shell_arch" "$minimum" "$bundle_id" <<'PY'
import json
import sys

path, dmg, commit, build, version, digest, short_version, arch, minimum, bundle_id = sys.argv[1:]
manifest = {
    "schema_version": 1,
    "candidate": dmg,
    "commit": commit,
    "build_number": build,
    "version": version,
    "short_version": short_version,
    "arch": arch,
    "minimum_system_version": minimum,
    "bundle_id": bundle_id,
    "license": "GPL-3.0-only",
    "sha256": digest,
    "declarations": [
        "LICENSE",
        "THIRD-PARTY-NOTICES.md",
        "SECURITY.md",
        "README.md",
        "PRIVACY.md",
    ],
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, ensure_ascii=False, indent=2, sort_keys=True)
    handle.write("\n")
PY

echo "ok: candidate $dmg_name $(printf '%s' "$expected" | cut -c1-12)…"
