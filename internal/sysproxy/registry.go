package sysproxy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

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

// Apply implements Backend.
//
// The enable flag is written last. That order is the whole reason a failure here
// cannot leave a machine with an enabled proxy that points somewhere wrong: as
// long as the addresses are being written the proxy stays off.
func (r *registry) Apply(ctx context.Context, s Settings) error {
	before, err := r.snapshot(ctx)
	if err != nil {
		return err
	}

	server := proxyServerList(s)
	writes := []registryValue{
		{name: valueServer, kind: "REG_SZ", data: server},
		{name: valueOverride, kind: "REG_SZ", data: strings.Join(s.BypassList(), ";")},
		{name: valueEnable, kind: "REG_DWORD", data: "1"},
	}
	for _, w := range writes {
		if err := r.add(ctx, w); err != nil {
			return r.rollback(ctx, before, err)
		}
	}
	return nil
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
	return r.read(ctx, valueEnable, valueServer, valueOverride)
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
