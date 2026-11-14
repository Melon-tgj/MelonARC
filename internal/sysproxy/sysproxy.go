// Package sysproxy points the desktop proxy setting of the machine at the local
// inbound listeners, and puts it back.
//
// The scope is deliberately narrow. It does not intercept traffic, it does not
// start a listener and it does not decide whether the setting should be on: it
// writes the setting the configuration asked for through the desktop's own
// tool, so the change is visible in the system settings panel and can be undone
// by hand.
//
// One property is worth the code it costs: a failure never leaves a half applied
// setting behind. The desktop proxy has several fields, and a machine whose
// HTTP proxy points at a listener while its SOCKS5 proxy does not is worse than
// one with no proxy at all — the first looks configured and silently breaks
// half the traffic. Every backend therefore reads the current values before it
// writes, and restores them if any write fails.
package sysproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

// Settings is what the desktop proxy is pointed at.
type Settings struct {
	// HTTP is the host:port of the HTTP inbound, empty when it is off.
	HTTP string
	// SOCKS5 is the host:port of the SOCKS5 inbound, empty when it is off.
	SOCKS5 string
	// Bypass lists the hosts the desktop proxy must not be used for. It always
	// contains the loopback names: the API, the token file and the listeners
	// themselves are on this machine, and sending them through the proxy would
	// either loop or fail.
	Bypass []string
}

// DefaultBypass is the set every configuration gets, whether or not it declares
// one. Loopback traffic is never proxied: the daemon's own API lives there.
var DefaultBypass = []string{"localhost", "127.0.0.1", "::1"}

// ErrUnsupported reports that this desktop has no proxy setting this build knows
// how to write.
var ErrUnsupported = errors.New("this platform has no system proxy setting this build can write")

// ErrNoListener reports that there is nothing to point the desktop proxy at.
var ErrNoListener = errors.New("no inbound listener is configured")

// Backend is the proxy setting of one desktop.
type Backend interface {
	// Name identifies the setting in a log line: "gsettings", "registry".
	Name() string
	// Enabled reports whether the desktop proxy is on.
	Enabled(ctx context.Context) (bool, error)
	// Apply points the desktop proxy at these listeners. When it returns an
	// error the setting is what it was before the call.
	Apply(ctx context.Context, s Settings) error
	// Clear turns the desktop proxy off, which is the state a machine that
	// stops proxying has to be left in.
	Clear(ctx context.Context) error
}

// Controller applies the configured setting and puts it back on shutdown.
type Controller struct {
	backend Backend
	logger  *slog.Logger
	// applied records that this process turned the setting on, so shutting down
	// only clears a setting it is responsible for. A setting the user turned on
	// by hand is not ours to remove.
	applied bool
}

// New returns the controller of this machine's desktop setting.
func New(logger *slog.Logger) *Controller {
	return &Controller{backend: platform(), logger: loggerOrDiscard(logger)}
}

// WithBackend returns a controller over a specific backend, which is what a test
// uses.
func WithBackend(b Backend, logger *slog.Logger) *Controller {
	return &Controller{backend: b, logger: loggerOrDiscard(logger)}
}

// Backend returns the backend the controller writes through.
func (c *Controller) Backend() Backend { return c.backend }

// Enable points the desktop proxy at the listeners.
//
// An error is returned with the reason in it, and the setting is left as it was:
// that is the whole contract, because the alternative is a machine with a
// half written proxy configuration and no way to tell from the outside.
func (c *Controller) Enable(ctx context.Context, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := c.backend.Apply(ctx, s); err != nil {
		return fmt.Errorf("the system proxy could not be set (%s): %w", c.backend.Name(), err)
	}
	c.applied = true
	c.logger.Info("system proxy set", "backend", c.backend.Name(), "http", s.HTTP, "socks5", s.SOCKS5)
	return nil
}

// Disable turns the desktop proxy off. It is called on shutdown for a setting
// this process applied, and from the startup path when the configuration does
// not ask for one but a previous run left it on.
func (c *Controller) Disable(ctx context.Context) error {
	if err := c.backend.Clear(ctx); err != nil {
		return fmt.Errorf("the system proxy could not be cleared (%s): %w", c.backend.Name(), err)
	}
	c.applied = false
	c.logger.Info("system proxy cleared", "backend", c.backend.Name())
	return nil
}

// Applied reports whether this process turned the setting on.
func (c *Controller) Applied() bool { return c.applied }

// Enabled reports whether the desktop proxy is on.
func (c *Controller) Enabled(ctx context.Context) (bool, error) {
	return c.backend.Enabled(ctx)
}

// Release turns the setting off if this process turned it on. It is what the
// daemon defers at startup, and it is safe to call more than once.
func (c *Controller) Release(ctx context.Context) error {
	if !c.applied {
		return nil
	}
	return c.Disable(ctx)
}

// Validate checks that there is something to point at and that every address is
// one the desktop can use.
//
// A host is required, not just a port: a desktop proxy field takes host:port,
// and a listener bound to every interface cannot be described to it at all.
func (s Settings) Validate() error {
	if s.HTTP == "" && s.SOCKS5 == "" {
		return ErrNoListener
	}
	for _, addr := range []string{s.HTTP, s.SOCKS5} {
		if addr == "" {
			continue
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("%q is not a host:port address: %w", addr, err)
		}
		if host == "" {
			return fmt.Errorf("%q has no host: the desktop proxy needs the address of a listener", addr)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%q has an invalid port", addr)
		}
	}
	return nil
}

// BypassList returns the bypass entries with the defaults, without duplicates,
// in the order they are written.
//
// The defaults come first so a desktop shows them first, and a configured entry
// that repeats one is dropped rather than written twice.
func (s Settings) BypassList() []string {
	seen := make(map[string]bool, len(DefaultBypass)+len(s.Bypass))
	out := make([]string, 0, len(DefaultBypass)+len(s.Bypass))
	for _, entry := range append(append([]string{}, DefaultBypass...), s.Bypass...) {
		value := strings.TrimSpace(entry)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// loggerOrDiscard returns a logger that swallows everything when l is nil.
func loggerOrDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
