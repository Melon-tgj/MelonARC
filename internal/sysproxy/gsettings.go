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

// Apply implements Backend.
func (g *gsettings) Apply(ctx context.Context, s Settings) error {
	httpHost, httpPort := splitListen(s.HTTP)
	socksHost, socksPort := splitListen(s.SOCKS5)

	writes := []write{
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
	return g.writeAll(ctx, writes)
}

// Clear implements Backend.
func (g *gsettings) Clear(ctx context.Context) error {
	return g.writeAll(ctx, []write{{proxySchema, "mode", quote("none")}})
}

// write is one gsettings assignment.
type write struct {
	schema string
	key    string
	value  string
}

// writeAll applies the writes and restores what was there before if any of them
// fails.
//
// The snapshot is taken first, for the schemas about to change only: reading a
// value is what makes a restore possible, and a restore that cannot read what it
// is replacing would be a guess.
func (g *gsettings) writeAll(ctx context.Context, writes []write) error {
	before, err := g.read(ctx, writes)
	if err != nil {
		return err
	}
	for _, w := range writes {
		if _, err := g.run(ctx, "gsettings", "set", w.schema, w.key, w.value); err != nil {
			return g.rollback(ctx, before, err)
		}
	}
	return nil
}

// read captures the values of every key about to be written.
//
// A key that cannot be read stops the whole operation: writing a setting whose
// previous value is unknown is writing a setting that cannot be put back, and
// the half applied state this package exists to avoid is exactly what that
// would produce on the next failure.
func (g *gsettings) read(ctx context.Context, writes []write) ([]write, error) {
	before := make([]write, 0, len(writes))
	for _, w := range writes {
		out, err := g.run(ctx, "gsettings", "get", w.schema, w.key)
		if err != nil {
			return nil, fmt.Errorf("read %s %s: %w", w.schema, w.key, err)
		}
		before = append(before, write{w.schema, w.key, strings.TrimSpace(out)})
	}
	return before, nil
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
