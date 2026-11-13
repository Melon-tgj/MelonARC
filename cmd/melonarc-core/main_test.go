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
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
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
// does and checks that the group decides on real probe results: a proxy that
// cannot be reached and a protocol this build does not implement must both go
// down, leaving the direct member active.
func TestBuildRegistryProbesThroughMembers(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	raw := fmt.Sprintf(`[General]
log-level = error

[Proxy]
dead = socks5, 127.0.0.1, 9
later = vmess, 127.0.0.1, 443

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
		t.Fatalf("the unimplemented protocol has no dialer: %v", err)
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
