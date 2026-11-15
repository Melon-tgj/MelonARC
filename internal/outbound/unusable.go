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

// unusableProtocols lists the types a configuration must not rely on. Both
// entries describe the same situation: the repair landed (stage 15) and has
// known-answer tests behind it, but no real traffic has been carried since, so
// neither may be reported as working.
var unusableProtocols = []Unusable{
	{
		Protocol: "hysteria2",
		Reason: "known unusable: the stage 15 fixes are in place, but real interoperability " +
			"with a reference server has not been re-verified; keep it out of any stable setup",
	},
	{
		Protocol: "tuic",
		Reason: "known unusable: the stage 15 fixes are in place, but real interoperability " +
			"with a reference server has not been re-verified; keep it out of any stable setup",
	},
}

// UnusableProtocols returns the protocols a configuration must not rely on.
//
// The caller gets a copy: a list that decides what the daemon warns about is
// not something a caller may edit at run time.
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
