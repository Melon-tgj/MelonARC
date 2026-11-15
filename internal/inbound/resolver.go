package inbound

import "sync/atomic"

// ResolverHolder is the resolver a running process is currently using. A reload
// builds a new resolver and swaps it in, and everything that answers DNS on
// behalf of the daemon reads it from here rather than keeping the one it was
// started with.
//
// The TUN inbound needs it because its device is created once, at startup, and
// is never rebuilt by a reload: naming a device is a privileged operation, while
// the [Host] table and the upstream list behind the resolver are ordinary
// configuration that may change at any time. Without a shared holder the DNS
// answers the device gives would be frozen at the configuration the process
// started with, which is exactly the kind of "reloaded but not really" state the
// reload contract exists to avoid.
//
// One load per query: a lookup that is already running when the swap happens
// finishes on the resolver it started with, and every query after the swap uses
// the new one. Mixing the two inside a single question is the only outcome that
// would be wrong, and holding the pointer for the duration of a question is what
// prevents it.
//
// A nil *ResolverHolder is valid and holds nothing, so a service built without
// one — every test that does not care — behaves as if the resolver were absent.
type ResolverHolder struct {
	ref atomic.Pointer[Resolver]
}

// NewResolverHolder returns a holder carrying r, which may be nil.
func NewResolverHolder(r Resolver) *ResolverHolder {
	h := &ResolverHolder{}
	h.Store(r)
	return h
}

// Load returns the resolver in force, or nil when the holder carries none.
func (h *ResolverHolder) Load() Resolver {
	if h == nil {
		return nil
	}
	ref := h.ref.Load()
	if ref == nil {
		return nil
	}
	return *ref
}

// Store replaces the resolver. A nil resolver is stored as "none", which turns
// the TUN DNS path into a SERVFAIL answer instead of a panic.
func (h *ResolverHolder) Store(r Resolver) {
	if h == nil {
		return
	}
	h.ref.Store(&r)
}
