package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/datadir"
	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/policy"
)

// testLogger discards the daemon log during tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testResolver builds the resolver the daemon uses, with an upstream lookup that
// refuses every name: these tests only reach loopback addresses, and a real
// lookup would make them depend on the network.
func testResolver(t *testing.T) *dns.Resolver {
	t.Helper()
	resolver, err := dns.New(dns.Options{
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return nil, errors.New("name lookup is disabled in this test")
		},
	})
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	return resolver
}

// TestBuildRegistryProbesThroughMembers wires a configuration the way the daemon
// does and checks that the group decides on real probe results: two proxies that
// cannot be reached must both go down, leaving the direct member active.
func TestBuildRegistryProbesThroughMembers(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	raw := fmt.Sprintf(`[General]
log-level = error

[Proxy]
dead = socks5, 127.0.0.1, 9
later = trojan, 127.0.0.1, 9, password

[Proxy Group]
auto = url-test, dead, later, DIRECT, url=%s, interval=60, timeout=2

[Rule]
FINAL,auto
`, target.URL)

	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dialers, err := buildDialers(cfg, testResolver(t), testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	if _, err := dialers.Dialer("DIRECT"); err != nil {
		t.Fatalf("DIRECT is missing: %v", err)
	}
	if _, err := dialers.Dialer("later"); err != nil {
		t.Fatalf("the second proxy has no dialer: %v", err)
	}
	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	group, ok := registry.Group("auto")
	if !ok {
		t.Fatal("the group was not registered")
	}
	urlTest, ok := group.(*policy.URLTest)
	if !ok {
		t.Fatalf("group is %T, want *policy.URLTest", group)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	urlTest.Check(ctx)

	if got := urlTest.Active(); got != "DIRECT" {
		t.Fatalf("active = %q, want DIRECT: the probe did not follow the members", got)
	}
	status := urlTest.Status()
	for _, member := range status.Members {
		switch member.Name {
		case "DIRECT":
			if !member.Healthy || member.Latency <= 0 {
				t.Fatalf("DIRECT status = %+v, want healthy with a latency", member)
			}
		default:
			if member.Healthy {
				t.Fatalf("%s status = %+v, want unhealthy", member.Name, member)
			}
		}
	}
}

// TestBuildDialersRejectsBadOptions makes sure a mistake in a [Proxy] line is a
// startup error rather than a silent dial without authentication.
func TestBuildDialersRejectsBadOptions(t *testing.T) {
	raw := `[General]
log-level = error

[Proxy]
broken = socks5, 127.0.0.1, 1080, username=alice

[Proxy Group]
manual = select, broken, DIRECT

[Rule]
FINAL,manual
`
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := buildDialers(cfg, testResolver(t), testLogger()); err == nil {
		t.Fatal("buildDialers accepted a username without a password")
	}
}

// TestBuildRegistryCarriesThePinnedMember checks the rule a reload relies on:
// a pin is applied to the rebuilt manual group by name, and only when that
// member is still declared; a group that decides on its own has no pin at all.
func TestBuildRegistryCarriesThePinnedMember(t *testing.T) {
	raw := `[General]
log-level = error

[Proxy]
alpha = socks5, 127.0.0.1, 1080
beta = socks5, 127.0.0.1, 1081

[Proxy Group]
manual = select, alpha, beta
auto = fallback, alpha, beta, url=http://probe.test/

[Rule]
FINAL,manual
`
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dialers, err := buildDialers(cfg, testResolver(t), testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}

	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	defer registry.Close()

	manual, ok := registry.Group("manual")
	if !ok {
		t.Fatal("the manual group was not registered")
	}
	// A rebuilt group starts on its first member: the pin is applied at the
	// moment of the swap, not while the rebuild runs.
	if got := manual.Active(); got != "alpha" {
		t.Errorf("a freshly built manual group routes to %q, want its first member", got)
	}

	carry := map[string]string{"manual": "beta", "auto": "beta", "gone": "alpha"}
	applySelections(carry, registry)
	if got := manual.Active(); got != "beta" {
		t.Errorf("manual group routes to %q, want the carried member beta", got)
	}
	// A group that decides on its own has no pin to carry: its active member is
	// whatever the probe round produced, and this rebuild starts at the top.
	auto, ok := registry.Group("auto")
	if !ok {
		t.Fatal("the fallback group was not registered")
	}
	if got := auto.Active(); got != "alpha" {
		t.Errorf("fallback group routes to %q, want its first member", got)
	}

	// A pin whose member the configuration no longer lists cannot be honoured.
	registry2, err := buildRegistry(cfg, dialers)
	if err != nil {
		t.Fatalf("buildRegistry with a stale pin: %v", err)
	}
	defer registry2.Close()
	applySelections(map[string]string{"manual": "gamma"}, registry2)
	stale, _ := registry2.Group("manual")
	if got := stale.Active(); got != "alpha" {
		t.Errorf("a stale pin left the group on %q, want the first member", got)
	}

	// droppedSelections is how that outcome becomes visible.
	dropped := droppedSelections(map[string]string{"manual": "gamma", "gone": "alpha"}, registry2)
	if len(dropped) != 2 {
		t.Fatalf("dropped = %v, want both lost selections", dropped)
	}
	// Sorted, so the missing group comes before the stale member.
	if !strings.Contains(dropped[0], "gone") || !strings.Contains(dropped[1], "manual: gamma") {
		t.Errorf("dropped = %v, want the missing group and the stale pin", dropped)
	}
}

// TestStartupOutputDoesNotDiscloseToken uses a server with a known token and
// checks both channels a startup notice can reach: stdout and the structured
// log. The address and the token file path are still reported, so an operator
// can find the credential without it ever being copied into a terminal log.
func TestStartupOutputDoesNotDiscloseToken(t *testing.T) {
	const token = "a-known-startup-token-that-must-not-be-published"
	srv, err := api.New(api.Options{
		Addr:     "127.0.0.1:0",
		Token:    token,
		Provider: &daemonState{},
		Version:  "test",
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})
	tokenPath := datadir.TokenPath(t.TempDir())
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	stdout := captureStdout(t, func() { announceAPI(srv, tokenPath, logger) })
	for name, output := range map[string]string{"stdout": stdout, "log": logs.String()} {
		if strings.Contains(output, token) {
			t.Errorf("startup %s disclosed the bearer token: %q", name, output)
		}
	}
	if !strings.Contains(stdout, srv.URL()) {
		t.Errorf("startup output has no listen address: %q", stdout)
	}
	if !strings.Contains(stdout, tokenPath) {
		t.Errorf("startup output has no token file path: %q", stdout)
	}
	if !strings.Contains(logs.String(), tokenPath) {
		t.Errorf("startup log has no token file path: %q", logs.String())
	}
}
