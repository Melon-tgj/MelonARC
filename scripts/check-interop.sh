#!/bin/sh
# Interop gate: did this run actually verify every protocol against a reference
# implementation?
#
# The interop tests skip when they cannot run, which is the right behaviour for a
# checkout that never downloaded the reference binaries: the package still builds
# and the rest of the suite still passes. The same behaviour is wrong for a gate,
# where a skip has to be read as "this protocol was not verified" and not as
# "nothing went wrong".
#
# Usage:
#   MELONARC_INTEROP_DIR=$HOME/interop-bin scripts/check-interop.sh
#
# Exit codes:
#   0  every TestInterop case (parent and subtest) passed
#   1  at least one case skipped or failed, or no case ran at all
#   2  MELONARC_INTEROP_DIR is unset or empty, so there was nothing to check
#
# Layout and versions are in docs/interop-testing.md.

set -u

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

dir=${MELONARC_INTEROP_DIR:-}
if [ -z "$dir" ]; then
    cat >&2 <<'EOF'
check-interop: MELONARC_INTEROP_DIR is not set, so there is nothing to check.

The interop tests dial a reference implementation of each protocol instead of a
peer of our own, and look for it under $MELONARC_INTEROP_DIR/<protocol>/server
(shadowsocks, vmess, trojan, vless, snell, hysteria2, tuic). Without that
directory every case skips, and a skip is not a pass.

See docs/interop-testing.md for the versions, the release pages, how to verify
the downloads and how to lay out the slots.
EOF
    exit 2
fi

if [ ! -d "$dir" ]; then
    die "check-interop: $dir is not a directory"
fi

if ! command -v go >/dev/null 2>&1; then
    die "check-interop: go is not on PATH"
fi

out=$(mktemp "${TMPDIR:-/tmp}/check-interop.XXXXXX") || die "check-interop: cannot create a temporary file"
trap 'rm -f "$out"' EXIT HUP INT TERM

status=0
go test ./internal/outbound/ -run TestInterop -count=1 -v >"$out" 2>&1 || status=$?

# Test names never contain spaces: go replaces them with underscores when it
# builds a test name, so a leading "TestInterop" followed by non-space is exact.
passed=$(sed -n 's/^ *--- PASS: \(TestInterop[^ ]*\).*/\1/p' "$out" | sort -u)
skipped=$(sed -n 's/^ *--- SKIP: \(TestInterop[^ ]*\).*/\1/p' "$out" | sort -u)
failed=$(sed -n 's/^ *--- FAIL: \(TestInterop[^ ]*\).*/\1/p' "$out" | sort -u)

count() {
    if [ -z "$1" ]; then
        printf '0'
        return
    fi
    printf '%s\n' "$1" | wc -l | tr -d ' '
}

problems=0

if [ -n "$failed" ]; then
    problems=$((problems + 1))
    printf 'check-interop: FAILED\n' >&2
    printf '%s\n' "$failed" | sed 's/^/  FAIL /' >&2
fi

if [ -n "$skipped" ]; then
    problems=$((problems + 1))
    printf 'check-interop: SKIPPED (a skip means this protocol was not verified)\n' >&2
    printf '%s\n' "$skipped" | sed 's/^/  SKIP /' >&2
fi

if [ -z "$passed" ] && [ "$problems" -eq 0 ]; then
    # A filter that matches nothing would otherwise read as success.
    problems=$((problems + 1))
    printf 'check-interop: no TestInterop case ran; the filter or the package path is wrong\n' >&2
fi

if [ "$problems" -ne 0 ] || [ "$status" -ne 0 ]; then
    # Always print the captured run: a name-only failure list cannot be
    # diagnosed from CI logs, where the temp file is gone with the runner.
    printf 'check-interop: go test exited %d; its full output follows\n' "$status" >&2
    sed 's/^/  | /' "$out" >&2
    printf 'check-interop: %s\n' "$dir" >&2
    exit 1
fi

printf 'check-interop: %s case(s) passed, no case skipped: %s\n' "$(count "$passed")" "$dir"
