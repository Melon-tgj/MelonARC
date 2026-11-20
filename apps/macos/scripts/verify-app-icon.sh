#!/usr/bin/env bash
# Check that the finished .app contains a real, decodable icon. An icon name in
# Info.plist is not enough: actool silently skips invalid slots, and signing
# still seals an app with no icon resource (build 30). Apple's plutil,
# iconutil, assetutil and shasum do the parsing; the report is deliberately
# identical for the signed app and for the mounted DMG copy.
set -euo pipefail

fail() {
  echo "::error::$1"
  exit 1
}

app=${1:-}
build_log=${2:-}
[ -n "$app" ] || fail "usage: $0 <app> [xcodebuild-release.log]"
[ -d "$app" ] || fail "the app bundle is missing: $app"

plist="$app/Contents/Info.plist"
resources="$app/Contents/Resources"
[ -f "$plist" ] || fail "the app has no Info.plist: $plist"

if [ -n "$build_log" ]; then
  [ -f "$build_log" ] || fail "the build log is missing: $build_log"
  if grep -i 'unassigned child' "$build_log" | grep -qi 'appicon'; then
    fail "the build log reports an unassigned AppIcon child"
  fi
  if grep -Eqi 'appicon.*(invalid|unsupported|ignored)[[:space:]]+(slot|size|scale)' "$build_log"; then
    fail "the build log reports an invalid AppIcon slot"
  fi
fi

names=""
for key in CFBundleIconFile CFBundleIconName; do
  value=$(plutil -extract "$key" raw -o - "$plist" 2>/dev/null || true)
  [ -n "$value" ] || continue
  name=${value%.icns}
  case " $names " in
    *" $name "*) ;;
    *) names="$names $name" ;;
  esac
done
[ -n "$names" ] || fail "Info.plist declares no CFBundleIconFile or CFBundleIconName"

iconset=$(mktemp -d "${TMPDIR:-/tmp}/melonarc-iconset.XXXXXX")
trap 'rm -rf "$iconset"' EXIT

for name in $names; do
  icns="$resources/${name}.icns"
  relative=${icns#"$app/"}
  [ -f "$icns" ] || fail "the icon named in Info.plist has no resource: $relative"
  iconutil -c iconset -o "$iconset/$name.iconset" "$icns" \
    || fail "iconutil could not decode $relative"
  for representation in icon_16x16.png icon_128x128.png icon_512x512.png; do
    image="$iconset/$name.iconset/$representation"
    [ -f "$image" ] || fail "$relative has no $representation representation"
    pixels=$(sips -g pixelWidth -g pixelHeight "$image" \
      | awk '/pixelWidth:/ { w = $2 } /pixelHeight:/ { h = $2 } END { print w "x" h }')
    want=${representation#icon_}
    want=${want%.png}
    [ "$pixels" = "$want" ] || fail "$image is $pixels, expected $want"
  done
  shopt -s nullglob
  high=("$iconset/$name.iconset"/*@2x.png)
  shopt -u nullglob
  [ "${#high[@]}" -gt 0 ] || fail "$relative has no high-resolution representation"
  digest=$(shasum -a 256 "$icns" | awk '{print $1}')
  printf 'icon: %s sha256=%s\n' "$relative" "$digest"
done

car="$resources/Assets.car"
if [ -f "$car" ]; then
  info=$(xcrun assetutil --info "$car" 2>&1) \
    || fail "assetutil could not read ${car#"$app/"}"
  entries=$(printf '%s\n' "$info" | grep -ic 'appicon' || true)
  printf 'car: %s appicon-entries=%s\n' "${car#"$app/"}" "$entries"
fi
