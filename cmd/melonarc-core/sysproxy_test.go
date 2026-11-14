package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/sysproxy"
)

// fakeProxy records what the daemon asked the desktop to do.
type fakeProxy struct {
	enabled  int
	released int
	settings sysproxy.Settings
	err      error
}

func (f *fakeProxy) Enable(_ context.Context, s sysproxy.Settings) error {
	f.enabled++
	f.settings = s
	return f.err
}

func (f *fakeProxy) Release(context.Context) error {
	f.released++
	return nil
}

// TestSysproxySettingsFollowTheListeners checks the mapping from the [General]
// section to the desktop setting: the listeners are used as they are bound, and
// the bypass list is what the configuration declared.
func TestSysproxySettingsFollowTheListeners(t *testing.T) {
	g := config.General{
		HTTPListen:        "127.0.0.1:7890",
		SOCKS5Listen:      "127.0.0.1:7891",
		SystemProxy:       true,
		SystemProxyBypass: []string{"*.internal"},
	}
	got := sysproxySettings(g)
	if got.HTTP != g.HTTPListen || got.SOCKS5 != g.SOCKS5Listen {
		t.Errorf("settings = %+v, want the two listeners", got)
	}
	if len(got.Bypass) != 1 || got.Bypass[0] != "*.internal" {
		t.Errorf("bypass = %v, want the configured entry", got.Bypass)
	}
}

// TestApplySystemProxyIsOffByDefault keeps a daemon that was not asked to
// configure the machine from touching it.
func TestApplySystemProxyIsOffByDefault(t *testing.T) {
	proxy := &fakeProxy{}
	g := config.General{HTTPListen: "127.0.0.1:7890"}
	if err := applySystemProxy(context.Background(), g, proxy, testLogger()); err != nil {
		t.Fatalf("applySystemProxy: %v", err)
	}
	if proxy.enabled != 0 {
		t.Error("the desktop proxy was written although system-proxy is off")
	}
}

// TestApplySystemProxyWritesTheListeners checks the happy path.
func TestApplySystemProxyWritesTheListeners(t *testing.T) {
	proxy := &fakeProxy{}
	g := config.General{HTTPListen: "127.0.0.1:7890", SOCKS5Listen: "127.0.0.1:7891", SystemProxy: true}
	if err := applySystemProxy(context.Background(), g, proxy, testLogger()); err != nil {
		t.Fatalf("applySystemProxy: %v", err)
	}
	if proxy.enabled != 1 {
		t.Fatalf("the desktop proxy was written %d times, want 1", proxy.enabled)
	}
	if proxy.settings.HTTP != "127.0.0.1:7890" || proxy.settings.SOCKS5 != "127.0.0.1:7891" {
		t.Errorf("settings = %+v", proxy.settings)
	}
}

// TestApplySystemProxyReportsAFailure checks that a desktop setting that cannot
// be written stops the daemon with a message that names the setting and keeps
// the reason: the user has to be able to act on it.
func TestApplySystemProxyReportsAFailure(t *testing.T) {
	proxy := &fakeProxy{err: errors.New("gsettings is not installed on this machine")}
	g := config.General{HTTPListen: "127.0.0.1:7890", SystemProxy: true}

	err := applySystemProxy(context.Background(), g, proxy, testLogger())
	if err == nil {
		t.Fatal("applySystemProxy succeeded although the setting could not be written")
	}
	for _, want := range []string{"system-proxy", "gsettings is not installed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// TestRestartRequiredNamesTheSystemProxy keeps the reload answer honest: a
// changed desktop proxy setting does not take effect until a restart, and the
// reason it cannot is that writing it would change where every application on
// the machine sends its traffic.
func TestRestartRequiredNamesTheSystemProxy(t *testing.T) {
	base := config.General{HTTPListen: "127.0.0.1:7890"}
	next := base
	next.SystemProxy = true

	if got := restartRequired(base, next); len(got) != 1 || got[0] != "system-proxy" {
		t.Errorf("restart_required = %v, want [system-proxy]", got)
	}

	// The bypass list is part of the same setting.
	withBypass := next
	withBypass.SystemProxyBypass = []string{"*.internal"}
	if got := restartRequired(next, withBypass); len(got) != 1 || got[0] != "system-proxy" {
		t.Errorf("restart_required = %v, want [system-proxy] for a changed bypass list", got)
	}

	// Nothing changed means nothing to restart for.
	if got := restartRequired(next, next); len(got) != 0 {
		t.Errorf("restart_required = %v, want none", got)
	}
}

// TestSystemProxyNote renders the -check summary.
func TestSystemProxyNote(t *testing.T) {
	off := config.General{}
	if got := systemProxyNote(off); got != "off" {
		t.Errorf("note = %q, want off", got)
	}
	on := config.General{
		HTTPListen:        "127.0.0.1:7890",
		SOCKS5Listen:      "127.0.0.1:7891",
		SystemProxy:       true,
		SystemProxyBypass: []string{"*.internal"},
	}
	got := systemProxyNote(on)
	for _, want := range []string{"http 127.0.0.1:7890", "socks5 127.0.0.1:7891", "bypass *.internal"} {
		if !strings.Contains(got, want) {
			t.Errorf("note = %q, want it to mention %q", got, want)
		}
	}
}
