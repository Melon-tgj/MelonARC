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
//
// Ownership is the other property. This package does not "turn the proxy off"
// when it leaves: it puts back the values that were there before the takeover,
// including the absence of a value that did not exist, and only for fields that
// still hold what this program wrote. A user who changes a field while the
// daemon runs keeps that change. The snapshot is persisted before the first
// write, so a process that is killed outright still leaves the next start a way
// to put the machine back.
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
	"time"
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

// ErrRollbackIncomplete reports that a failed takeover could not be undone: some
// of the values this program wrote are still in force.
//
// It is the one case in which the takeover record must survive a failure. A
// backend that undid everything leaves nothing to restore, so the record is
// removed; a backend that could not (a tool that stopped answering, a permission
// that was refused half way) leaves the machine partially configured, and the
// next start needs the record to put it back.
var ErrRollbackIncomplete = errors.New("the settings written before the failure could not all be undone")

// ErrNoListener reports that there is nothing to point the desktop proxy at.
var ErrNoListener = errors.New("no inbound listener is configured")

// Backend is the proxy setting of one desktop.
type Backend interface {
	// Name identifies the setting in a log line: "gsettings", "registry",
	// "networksetup".
	Name() string
	// Enabled reports whether the desktop proxy is on.
	Enabled(ctx context.Context) (bool, error)
	// Plan reads the current values and describes the writes a takeover would
	// make. It changes nothing. Splitting this from Commit is what lets the
	// controller persist the snapshot before the machine is touched.
	Plan(ctx context.Context, s Settings) (Snapshot, error)
	// Commit performs the writes of a Plan. On a failure it restores what it
	// already wrote and reports the reason. When that rollback could not undo
	// every field the error wraps ErrRollbackIncomplete, and the controller
	// keeps the takeover record for the next start.
	Commit(ctx context.Context, snap Snapshot) error
	// Restore puts a snapshot back, skipping every field whose current value no
	// longer equals what this program wrote. A value that was absent before the
	// takeover is deleted rather than written.
	Restore(ctx context.Context, snap Snapshot) (RestoreResult, error)
	// Clear turns the desktop proxy off. It is the fallback for a setting left
	// by a build that had no snapshot; a normal shutdown uses Restore.
	Clear(ctx context.Context) error
}

// Controller applies the configured setting and puts it back on shutdown.
type Controller struct {
	backend Backend
	logger  *slog.Logger
	// path is where the takeover record is kept. An empty path disables
	// persistence, which is what a test without a data directory uses.
	path string
	// snapshot is the takeover of this process, kept in memory so Release does
	// not depend on the disk still being readable during shutdown.
	snapshot Snapshot
	// applied records that this process turned the setting on, so shutting down
	// only restores a setting it is responsible for. A setting the user turned
	// on by hand is not ours to remove.
	applied bool
}

// New returns the controller of this machine's desktop setting. snapshotPath is
// the file in which the takeover is recorded; it must live in the data
// directory so that it survives a restart of the process.
func New(logger *slog.Logger, snapshotPath string) *Controller {
	return &Controller{backend: platform(), logger: loggerOrDiscard(logger), path: snapshotPath}
}

// WithBackend returns a controller over a specific backend, which is what a test
// uses.
func WithBackend(b Backend, logger *slog.Logger, snapshotPath string) *Controller {
	return &Controller{backend: b, logger: loggerOrDiscard(logger), path: snapshotPath}
}

// Backend returns the backend the controller writes through.
func (c *Controller) Backend() Backend { return c.backend }

// Enable points the desktop proxy at the listeners.
//
// Any takeover a previous process did not release is put back first, then the
// values about to be replaced are persisted before the first write. An error
// leaves the setting as it was and removes the record that is no longer
// needed — unless the backend could not undo what it had already written, in
// which case the record is kept so the next start can finish the job.
func (c *Controller) Enable(ctx context.Context, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := c.Recover(ctx); err != nil {
		return err
	}
	snap, err := c.backend.Plan(ctx, s)
	if err != nil {
		return fmt.Errorf("the system proxy could not be read (%s): %w", c.backend.Name(), err)
	}
	snap.Backend = c.backend.Name()
	snap.TakenAt = time.Now()
	if err := saveSnapshot(c.path, snap); err != nil {
		return fmt.Errorf("the system proxy takeover could not be recorded: %w", err)
	}
	if err := c.backend.Commit(ctx, snap); err != nil {
		if errors.Is(err, ErrRollbackIncomplete) {
			// Part of what this program wrote is still in force. The record is
			// the only description of it, so it stays on disk for the next
			// start; this process also keeps it in memory, so a shutdown that
			// does reach Release still gets a chance to put the machine back.
			c.snapshot = snap
			c.applied = true
			c.logger.Error("the system proxy is only partly set and the partial write could not be undone; the takeover record is kept",
				"backend", c.backend.Name(), "error", err)
			return fmt.Errorf("the system proxy could not be set (%s), and what was written before the failure could not all be put back; the takeover record is kept so the next start can restore it: %w",
				c.backend.Name(), err)
		}
		// Commit already rolled the fields back. Nothing is ours any more, so
		// the record must not tell the next start to restore them again.
		if rerr := removeSnapshot(c.path); rerr != nil {
			c.logger.Warn("the system proxy takeover record could not be removed", "path", c.path, "error", rerr)
		}
		return fmt.Errorf("the system proxy could not be set (%s): %w", c.backend.Name(), err)
	}
	c.snapshot = snap
	c.applied = true
	c.logger.Info("system proxy set", "backend", c.backend.Name(), "http", s.HTTP, "socks5", s.SOCKS5)
	return nil
}

// Disable turns the desktop proxy off without restoring the previous values.
// It is the fallback for a setting left by a build that had no snapshot; a
// normal shutdown goes through Release, which restores.
func (c *Controller) Disable(ctx context.Context) error {
	if err := c.backend.Clear(ctx); err != nil {
		return fmt.Errorf("the system proxy could not be cleared (%s): %w", c.backend.Name(), err)
	}
	c.applied = false
	c.logger.Info("system proxy cleared", "backend", c.backend.Name())
	return nil
}

// Recover puts back a takeover that a previous process did not live to
// release. It is called at startup whether or not the new configuration asks
// for a system proxy: a hard kill must not leave the machine pointing at a
// listener that no longer exists. A missing record is the normal case.
func (c *Controller) Recover(ctx context.Context) error {
	found, err := recoverSnapshot(ctx, c.path, c.backend)
	if err != nil {
		return fmt.Errorf("the previous system proxy takeover could not be restored: %w", err)
	}
	if found {
		c.logger.Warn("restored a system proxy takeover left by a previous run", "backend", c.backend.Name())
	}
	return nil
}

// Applied reports whether this process turned the setting on.
func (c *Controller) Applied() bool { return c.applied }

// Enabled reports whether the desktop proxy is on.
func (c *Controller) Enabled(ctx context.Context) (bool, error) {
	return c.backend.Enabled(ctx)
}

// Release puts the settings back if this process turned them on. It restores
// the values from before the takeover, not an empty proxy, and leaves alone
// any field the user changed in the meantime. It is safe to call more than
// once.
func (c *Controller) Release(ctx context.Context) error {
	if !c.applied {
		return nil
	}
	snap := c.snapshot
	// The disk copy is authoritative when it is still there: it is the same
	// record the next start would use, so restoring it here and restoring it
	// there can never disagree. An empty path means this controller never
	// persisted anything, so the in-memory copy is the only one.
	if c.path != "" {
		if fromDisk, err := loadSnapshot(c.path); err == nil {
			snap = fromDisk
		}
	}
	result, err := c.backend.Restore(ctx, snap)
	if err != nil {
		return fmt.Errorf("the system proxy could not be restored (%s): %w", c.backend.Name(), err)
	}
	if err := removeSnapshot(c.path); err != nil {
		return err
	}
	c.applied = false
	c.logger.Info("system proxy restored", "backend", c.backend.Name(),
		"fields", result.Restored, "kept", result.Kept)
	return nil
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
