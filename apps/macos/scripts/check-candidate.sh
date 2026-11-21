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

bash "$here/verify-app-icon.sh" "$app"

copyright=$(plutil -extract NSHumanReadableCopyright raw -o - "$app/Contents/Info.plist") \
  || fail "the bundle copyright could not be read"
printf '%s\n' "$copyright" | grep -q 'GPL-3.0-only' \
  || fail "the bundle copyright does not state GPL-3.0-only"

minimum=$(plutil -extract LSMinimumSystemVersion raw -o - "$app/Contents/Info.plist") \
  || fail "the bundle minimum system version could not be read"
[ "$minimum" = "13.0" ] || fail "the bundle minimum system version is $minimum, expected 13.0"

expected=$(shasum -a 256 "$dmg" | awk '{print $1}')
recorded=$(awk '{print $1}' "$dmg.sha256")
[ "$expected" = "$recorded" ] || fail "the checksum sidecar does not match the DMG file"

mkdir -p "$(dirname "$metadata")"
python3 - "$metadata" "$dmg_name" "$commit" "$build_number" "$version" "$expected" <<'PY'
import json
import sys

path, dmg, commit, build, version, digest = sys.argv[1:]
manifest = {
    "candidate": dmg,
    "commit": commit,
    "build_number": build,
    "version": version,
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
