#!/usr/bin/env bash
# Sign the bundled core and then the app (inside out), verify the seals, and
# package a read-only compressed DMG with Apple's hdiutil. The checksum is of
# the .dmg file itself, not of its mounted contents.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
app=$1
dmg=$2
name=$(basename "$app")
core="$app/Contents/MacOS/melonarc-core"
main="$app/Contents/MacOS/${name%.app}"

if [ ! -x "$core" ] || [ ! -x "$main" ]; then
  echo "::error::bundle is missing an executable: $app"
  exit 1
fi
mkdir -p "$(dirname "$dmg")"

# Ad-hoc identity, Hardened Runtime, no entitlements, sandbox off.
codesign --force --sign - --options runtime "$core"
codesign --force --sign - --options runtime "$app"

for binary in "$core" "$main"; do
  info=$(codesign --display --verbose=4 "$binary" 2>&1)
  if ! printf '%s\n' "$info" | grep -Eq 'flags=.*runtime'; then
    echo "::error::$binary is missing the runtime flag"
    printf '%s\n' "$info"
    exit 1
  fi
done
codesign --verify --deep --strict --verbose=2 "$app"

hdiutil create -volname "${name%.app}" -srcfolder "$app" -ov -format UDZO "$dmg"
hdiutil verify "$dmg"

mount=$(mktemp -d "${TMPDIR:-/tmp}/melonarc-verify.XXXXXX")
detach() {
  if mount | grep -Fq "$mount "; then
    hdiutil detach "$mount" >/dev/null
  fi
  rmdir "$mount" 2>/dev/null || true
}
trap detach EXIT
hdiutil attach -readonly -nobrowse -mountpoint "$mount" "$dmg" >/dev/null

mounted="$mount/$name"
if [ ! -d "$mounted" ]; then
  echo "::error::$name is missing from the mounted DMG"
  exit 1
fi
codesign --verify --deep --strict --verbose=2 "$mounted"
bash "$here/verify-binaries.sh" \
  "$mounted/Contents/MacOS/${name%.app}" \
  "$mounted/Contents/MacOS/melonarc-core"
detach
trap - EXIT

shasum -a 256 "$dmg" > "$dmg.sha256"
cat "$dmg.sha256"
printf 'ok: signed, mounted and verified %s\n' "$dmg"
