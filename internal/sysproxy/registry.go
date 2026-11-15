package sysproxy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// registryNames are the values this backend takes over, in write order. The
// enable flag is last: while the addresses are being written the proxy stays
// off, so a failure cannot leave the machine sending traffic to a half written
// address. A restore walks the list in reverse for the same reason.
var registryNames = []string{valueServer, valueOverride, valueEnable}

// internetSettingsKey is where the desktop keeps the proxy of the user.
const internetSettingsKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// The value names of that key.
const (
	valueEnable   = "ProxyEnable"
	valueServer   = "ProxyServer"
	valueOverride = "ProxyOverride"
)

// registryValue is one captured registry value. An entry that did not exist has
// an empty kind, which is what a restore deletes instead of writing.
type registryValue struct {
	name string
	kind string
	data string
}

// registry is the proxy setting of a desktop that keeps it in the registry.
//
// It writes through reg.exe rather than through the registry API so that the
// package needs nothing outside the standard library and so that the same code
// path can be exercised on the machine the tests run on.
type registry struct {
	run runner
}

// newRegistry returns a backend that writes through reg.exe.
func newRegistry(run runner) *registry {
	return &registry{run: run}
}

// Name implements Backend.
func (r *registry) Name() string { return "registry" }

// Enabled implements Backend.
func (r *registry) Enabled(ctx context.Context) (bool, error) {
	values, err := r.read(ctx, valueEnable)
	if err != nil {
		return false, err
	}
	if len(values) == 0 {
		return false, nil
	}
	on, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(values[0].data), "0x"), 16, 32)
	if err != nil {
		return false, fmt.Errorf("ProxyEnable is %q, which is not a number", values[0].data)
	}
	return on != 0, nil
}

// registryWrites is the value each field gets during a takeover of s.
func registryWrites(s Settings) []registryValue {
	return []registryValue{
		{name: valueServer, kind: "REG_SZ", data: proxyServerList(s)},
		{name: valueOverride, kind: "REG_SZ", data: strings.Join(s.BypassList(), ";")},
		{name: valueEnable, kind: "REG_DWORD", data: "1"},
	}
}

// Plan implements Backend. A value that did not exist before the takeover is
// recorded with Present=false, which is what makes a restore delete it instead
// of leaving a zero value behind.
func (r *registry) Plan(ctx context.Context, s Settings) (Snapshot, error) {
	before, err := r.snapshot(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	fields := make([]Field, 0, len(registryWrites(s)))
	for _, w := range registryWrites(s) {
		f := Field{
			Key:         w.name,
			Written:     w.data,
			WrittenKind: w.kind,
		}
		if old, ok := findRegistryValue(before, w.name); ok {
			f.Present = true
			f.Before = canonicalRegistryData(old.data, old.kind)
			f.BeforeKind = old.kind
		}
		fields = append(fields, f)
	}
	return Snapshot{Fields: fields}, nil
}

// Commit implements Backend.
func (r *registry) Commit(ctx context.Context, snap Snapshot) error {
	for _, f := range snap.Fields {
		if err := r.add(ctx, registryValue{name: f.Key, kind: f.WrittenKind, data: f.Written}); err != nil {
			return r.rollback(ctx, snapshotValues(snap.Fields), err)
		}
	}
	return nil
}

// Restore implements Backend.
func (r *registry) Restore(ctx context.Context, snap Snapshot) (RestoreResult, error) {
	return restoreFields(snap.Fields,
		func(f Field) (registryValue, bool, error) {
			values, err := r.read(ctx, f.Key)
			if err != nil {
				return registryValue{}, false, err
			}
			if len(values) == 0 {
				return registryValue{}, false, nil
			}
			return values[0], true, nil
		},
		func(f Field, current registryValue) bool {
			return strings.EqualFold(current.kind, f.WrittenKind) &&
				sameRegistryData(current.data, f.Written, f.WrittenKind)
		},
		func(f Field) error {
			return r.add(ctx, registryValue{name: f.Key, kind: f.BeforeKind, data: f.Before})
		},
		func(f Field) error {
			_, err := r.run(ctx, "reg", "delete", internetSettingsKey, "/v", f.Key, "/f")
			return err
		},
	)
}

// Apply is the one-shot form of Plan plus Commit, kept for callers that do not
// need the takeover to be recorded and restored later.
func (r *registry) Apply(ctx context.Context, s Settings) error {
	snap, err := r.Plan(ctx, s)
	if err != nil {
		return err
	}
	return r.Commit(ctx, snap)
}

// Clear implements Backend.
//
// Disabling comes first and the addresses are left in place: a machine with the
// proxy switched off and a stale address is harmless, while the other order
// leaves a switched on proxy pointing at a listener that is going away.
func (r *registry) Clear(ctx context.Context) error {
	return r.add(ctx, registryValue{name: valueEnable, kind: "REG_DWORD", data: "0"})
}

// snapshot captures the three values this backend writes.
func (r *registry) snapshot(ctx context.Context) ([]registryValue, error) {
	return r.read(ctx, registryNames...)
}

// snapshotValues turns the persisted fields back into registry values for the
// rollback path. Values that were absent are simply not in the result, and
// rollback deletes them.
func snapshotValues(fields []Field) []registryValue {
	out := make([]registryValue, 0, len(fields))
	for _, f := range fields {
		if f.Present {
			out = append(out, registryValue{name: f.Key, kind: f.BeforeKind, data: f.Before})
		}
	}
	return out
}

// findRegistryValue looks a captured value up by name. reg.exe echoes the name
// as it was queried, but the comparison stays case insensitive because the
// registry itself treats value names that way.
func findRegistryValue(values []registryValue, name string) (registryValue, bool) {
	for _, v := range values {
		if strings.EqualFold(v.name, name) {
			return v, true
		}
	}
	return registryValue{}, false
}

// canonicalRegistryData renders a value read from reg.exe in the form a later
// reg add accepts. A DWORD is printed as 0x0 but is written as decimal, so a
// snapshot that kept the hex spelling would restore it ambiguously.
func canonicalRegistryData(data, kind string) string {
	value := strings.TrimSpace(data)
	if !strings.EqualFold(strings.TrimSpace(kind), "REG_DWORD") {
		return value
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(value), "0x"), 16, 32)
	if err != nil {
		return value
	}
	return strconv.FormatUint(n, 10)
}

// sameRegistryData compares a value read back from the registry with the one
// this program wrote. reg.exe prints a DWORD as 0x1 while the write takes 1,
// so the two spellings have to compare equal.
func sameRegistryData(current, written, kind string) bool {
	if !strings.EqualFold(strings.TrimSpace(kind), "REG_DWORD") {
		return strings.TrimSpace(current) == strings.TrimSpace(written)
	}
	parse := func(value string) (uint64, error) {
		return strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x"), 16, 32)
	}
	a, errA := parse(current)
	b, errB := parse(written)
	return errA == nil && errB == nil && a == b
}

// read returns the values that exist among names.
func (r *registry) read(ctx context.Context, names ...string) ([]registryValue, error) {
	out := make([]registryValue, 0, len(names))
	for _, name := range names {
		text, err := r.run(ctx, "reg", "query", internetSettingsKey, "/v", name)
		if err != nil {
			// A value that is not there is the normal state of a machine that
			// never had a proxy, so it is not treated as a failure: the caller
			// gets no entry, and a restore deletes instead of writing.
			continue
		}
		if value, ok := parseRegistryValue(text, name); ok {
			out = append(out, value)
		}
	}
	return out, nil
}

// add writes one value.
func (r *registry) add(ctx context.Context, v registryValue) error {
	_, err := r.run(ctx, "reg", "add", internetSettingsKey, "/v", v.name, "/t", v.kind, "/d", v.data, "/f")
	if err != nil {
		return fmt.Errorf("write %s: %w", v.name, err)
	}
	return nil
}

// rollback restores the captured values, deleting the ones that did not exist.
func (r *registry) rollback(ctx context.Context, before []registryValue, cause error) error {
	seen := make(map[string]bool, len(before))
	for _, v := range before {
		seen[v.name] = true
		if err := r.add(ctx, v); err != nil {
			return fmt.Errorf("%w (and %s could not be restored: %v)", cause, v.name, err)
		}
	}
	for _, name := range []string{valueEnable, valueServer, valueOverride} {
		if seen[name] {
			continue
		}
		if _, err := r.run(ctx, "reg", "delete", internetSettingsKey, "/v", name, "/f"); err != nil {
			return fmt.Errorf("%w (and %s could not be removed again: %v)", cause, name, err)
		}
	}
	return fmt.Errorf("%w (the previous settings were restored)", cause)
}

// proxyServerList renders the address list the desktop reads: one entry per
// protocol, separated by semicolons.
func proxyServerList(s Settings) string {
	parts := make([]string, 0, 3)
	if s.HTTP != "" {
		parts = append(parts, "http="+s.HTTP, "https="+s.HTTP)
	}
	if s.SOCKS5 != "" {
		parts = append(parts, "socks="+s.SOCKS5)
	}
	return strings.Join(parts, ";")
}

// parseRegistryValue reads one value out of the output of reg query. The line
// looks like "    ProxyEnable    REG_DWORD    0x1".
func parseRegistryValue(out, name string) (registryValue, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[0], name) {
			continue
		}
		// The data may contain spaces, so it is everything after the type.
		data := strings.TrimSpace(strings.Join(fields[2:], " "))
		return registryValue{name: fields[0], kind: fields[1], data: data}, true
	}
	return registryValue{}, false
}
