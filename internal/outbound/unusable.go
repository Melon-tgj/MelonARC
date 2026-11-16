package outbound

import "strings"

// Unusable names a protocol this build implements but whose interoperability
// has not been confirmed, and why it must still be treated as unusable.
//
// It exists so the daemon can say this out loud when a configuration relies on
// one of them. The support matrix in README.md is the source of truth; the
// entries below are the same statement in machine-readable form, and a protocol
// leaves this list only when the evidence behind it changes.
type Unusable struct {
	// Protocol is the [Proxy] type, lower case as the configuration writes it.
	Protocol string
	// Reason is one sentence the daemon logs. It names the fix and the
	// missing evidence, because "unusable" alone invites the reader to assume
	// the implementation is absent.
	Reason string
}

// unusableProtocols lists the types a configuration must not rely on.
//
// It is empty. The two entries it held since stage 15 — hysteria2 and tuic —
// described a repair that had landed without any traffic carried against a
// reference server since. That evidence now exists: both pass the interop gate
// in CI (GitHub Actions, ubuntu, 2026-11-16) against their pinned reference
// servers, TCP and UDP business alike, and the README matrix rows moved to
// Verified with that run behind them. A type is listed here only while the
// matrix says Unusable, so the list emptied when the matrix changed.
//
// The list and the mechanism around it stay. An entry belongs here when a
// protocol's evidence stops supporting what the matrix claims — a regression
// found by a re-run, a repair that has not been re-tested — and adding one back
// is a documentation change backed by that evidence, not a code change made to
// quiet a warning.
var unusableProtocols = []Unusable{}

// UnusableProtocols returns the protocols a configuration must not rely on.
//
// The caller gets a copy: a list that decides what the daemon warns about is
// not something a caller may edit at run time. An empty list is a valid answer
// and the caller must not treat it as missing data.
func UnusableProtocols() []Unusable {
	out := make([]Unusable, len(unusableProtocols))
	copy(out, unusableProtocols)
	return out
}

// IsUnusable reports whether a [Proxy] type is on that list, and why. The type
// is matched the way New matches it: case-insensitively and without surrounding
// space, so "Hysteria2" is the same protocol as "hysteria2".
func IsUnusable(typ string) (Unusable, bool) {
	name := strings.ToLower(strings.TrimSpace(typ))
	for _, entry := range unusableProtocols {
		if entry.Protocol == name {
			return entry, true
		}
	}
	return Unusable{}, false
}
