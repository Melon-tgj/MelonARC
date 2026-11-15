package sysproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// The schemas of the desktop proxy setting. The parent holds the mode, the
// children hold one proxy each, which is why a complete picture needs all four.
const (
	proxySchema = "org.gnome.system.proxy"
	httpSchema  = "org.gnome.system.proxy.http"
	httpsSchema = "org.gnome.system.proxy.https"
	socksSchema = "org.gnome.system.proxy.socks"
)

// runner runs one settings tool and returns its standard output. Tests replace
// it, which is what keeps this file free of a desktop.
type runner func(ctx context.Context, name string, args ...string) (string, error)

// gsettings is the proxy setting of a desktop that stores it in gsettings.
type gsettings struct {
	run runner
}

// newGSettings returns a backend that writes through gsettings.
func newGSettings(run runner) *gsettings {
	return &gsettings{run: run}
}

// Name implements Backend.
func (g *gsettings) Name() string { return "gsettings" }

// Enabled implements Backend.
func (g *gsettings) Enabled(ctx context.Context) (bool, error) {
	out, err := g.run(ctx, "gsettings", "get", proxySchema, "mode")
	if err != nil {
		return false, err
	}
	mode := unquote(out)
	// "auto" points the desktop at a configuration script and is as much a
	// configured proxy as "manual" is; neither is the state a stopped daemon
	// should leave the machine in.
	return mode != "" && mode != "none", nil
}

// gsettingsWrites is every field a takeover of s changes. The order is part of
// the safety contract: the mode comes first, so a failure while the addresses
// are being written leaves a machine whose proxy is already on but whose other
// fields are still being restored; see rollback.
func gsettingsWrites(s Settings) []write {
	httpHost, httpPort := splitListen(s.HTTP)
	socksHost, socksPort := splitListen(s.SOCKS5)
	return []write{
		{proxySchema, "mode", quote("manual")},
		// The https proxy is the same listener: the inbound answers CONNECT,
		// which is what a browser sends to the proxy of an https URL.
		{httpSchema, "host", quote(httpHost)},
		{httpSchema, "port", strconv.Itoa(httpPort)},
		{httpsSchema, "host", quote(httpHost)},
		{httpsSchema, "port", strconv.Itoa(httpPort)},
		{socksSchema, "host", quote(socksHost)},
		{socksSchema, "port", strconv.Itoa(socksPort)},
		{proxySchema, "ignore-hosts", formatStringList(s.BypassList())},
	}
}

// Plan implements Backend. A key that cannot be read stops the whole
// operation: taking over a setting whose previous value is unknown would make
// it impossible to put back.
func (g *gsettings) Plan(ctx context.Context, s Settings) (Snapshot, error) {
	writes := gsettingsWrites(s)
	fields := make([]Field, 0, len(writes))
	for _, w := range writes {
		out, err := g.run(ctx, "gsettings", "get", w.schema, w.key)
		if err != nil {
			return Snapshot{}, fmt.Errorf("read %s %s: %w", w.schema, w.key, err)
		}
		fields = append(fields, Field{
			Schema:  w.schema,
			Key:     w.key,
			Before:  strings.TrimSpace(out),
			Present: true, // a gsettings key always has a value, even if it is the default
			Written: w.value,
		})
	}
	return Snapshot{Fields: fields}, nil
}

// Commit implements Backend.
func (g *gsettings) Commit(ctx context.Context, snap Snapshot) error {
	before := make([]write, 0, len(snap.Fields))
	for _, f := range snap.Fields {
		before = append(before, write{f.Schema, f.Key, f.Before})
	}
	for _, f := range snap.Fields {
		if _, err := g.run(ctx, "gsettings", "set", f.Schema, f.Key, f.Written); err != nil {
			return g.rollback(ctx, before, err)
		}
	}
	return nil
}

// Restore implements Backend.
func (g *gsettings) Restore(ctx context.Context, snap Snapshot) (RestoreResult, error) {
	return restoreFields(snap.Fields,
		func(f Field) (string, bool, error) {
			out, err := g.run(ctx, "gsettings", "get", f.Schema, f.Key)
			if err != nil {
				return "", false, err
			}
			return strings.TrimSpace(out), true, nil
		},
		func(f Field, current string) bool { return sameGVariant(current, f.Written) },
		func(f Field) error {
			_, err := g.run(ctx, "gsettings", "set", f.Schema, f.Key, f.Before)
			return err
		},
		func(f Field) error {
			return fmt.Errorf("%s %s has no value to delete", f.Schema, f.Key)
		},
	)
}

// Apply is the one-shot form of Plan plus Commit, kept for callers that do not
// need the takeover to be recorded and restored later.
func (g *gsettings) Apply(ctx context.Context, s Settings) error {
	snap, err := g.Plan(ctx, s)
	if err != nil {
		return err
	}
	return g.Commit(ctx, snap)
}

// Clear implements Backend.
func (g *gsettings) Clear(ctx context.Context) error {
	_, err := g.run(ctx, "gsettings", "set", proxySchema, "mode", quote("none"))
	return err
}

// write is one gsettings assignment.
type write struct {
	schema string
	key    string
	value  string
}

// sameGVariant compares a value read back from the desktop with the literal
// this program wrote. The desktop is free to reformat a list — spacing around
// commas and brackets differs between versions — so lists are compared entry
// by entry rather than byte for byte. A reformat is not a user change.
func sameGVariant(current, written string) bool {
	normalise := func(value string) string {
		value = strings.TrimSpace(value)
		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			return unquote(value)
		}
		inner := strings.TrimSpace(value[1 : len(value)-1])
		if inner == "" {
			return "[]"
		}
		parts := make([]string, 0, 4)
		start, quoted, escaped := 0, false, false
		for i := 0; i < len(inner); i++ {
			switch {
			case escaped:
				escaped = false
			case inner[i] == '\\' && quoted:
				escaped = true
			case inner[i] == '\'':
				quoted = !quoted
			case inner[i] == ',' && !quoted:
				parts = append(parts, unquote(inner[start:i]))
				start = i + 1
			}
		}
		parts = append(parts, unquote(inner[start:]))
		return "[" + strings.Join(parts, "\x00") + "]"
	}
	return normalise(current) == normalise(written)
}

// rollback puts the captured values back and reports both the original failure
// and whatever the restore could not do.
func (g *gsettings) rollback(ctx context.Context, before []write, cause error) error {
	restored := make([]write, 0, len(before))
	for _, w := range before {
		if _, err := g.run(ctx, "gsettings", "set", w.schema, w.key, w.value); err != nil {
			return fmt.Errorf("%w (and %d of %d settings could not be restored: %v)",
				cause, len(before)-len(restored), len(before), err)
		}
		restored = append(restored, w)
	}
	return fmt.Errorf("%w (the previous settings were restored)", cause)
}

// splitListen turns "host:port" into the two fields a proxy setting stores. An
// empty address becomes the empty host and port 0, which is how the desktop
// spells "no proxy of this kind".
func splitListen(addr string) (string, int) {
	if addr == "" {
		return "", 0
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return host, 0
	}
	return host, n
}

// quote renders a string as a GVariant string literal.
func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `\'`) + "'"
}

// unquote strips the quotes gsettings prints around a string value.
func unquote(value string) string {
	out := strings.TrimSpace(value)
	if len(out) >= 2 && out[0] == '\'' && out[len(out)-1] == '\'' {
		return strings.ReplaceAll(out[1:len(out)-1], `\'`, "'")
	}
	return out
}

// formatStringList renders a list the way gsettings reads one: brackets, quoted
// entries, comma separated.
func formatStringList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, quote(value))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// osRunner runs a settings tool of this machine.
//
// The stderr of a tool that failed is the only thing that says what the desktop
// did not like, so it is part of the error rather than something the user has to
// reproduce by hand.
func osRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			detail := strings.TrimSpace(string(exitErr.Stderr))
			if detail == "" {
				detail = exitErr.Error()
			}
			return string(out), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), detail)
		}
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("%s is not installed on this machine: %w", name, err)
		}
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}
