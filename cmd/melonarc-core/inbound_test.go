package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// The ports the command tests use come from below the ephemeral range.
const (
	freePortBase = 20000
	freePortSpan = 2000
)

// freePortNext hands out the next candidate. A counter rather than ":0", because
// a port the kernel allocated to the probe listener goes straight back into the
// pool when that listener closes, and the next listener in this process can be
// given the same number. A test that then dials it reaches its own listener
// instead of a refused port, which no assertion can survive. Ports below the
// ephemeral range are never allocated by ":0".
var freePortNext atomic.Int64

// freePort returns a port nothing is listening on. Nothing binds a reserved port
// between here and the listener without a race, which is acceptable in a test and
// keeps the addresses fixed, as configuration validation requires.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < freePortSpan; i++ {
		port := freePortBase + int(freePortNext.Add(1)%freePortSpan)
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		return port
	}
	t.Fatalf("no free port in %d..%d", freePortBase, freePortBase+freePortSpan)
	return 0
}

// wireDaemon builds everything the daemon builds after a configuration is
// validated, in the same order.
func wireDaemon(t *testing.T, cfg *config.Config) (*rules.Program, []*inbound.Service) {
	t.Helper()
	program := compileTestRules(t, cfg)
	resolver := testResolver(t)
	dialers, err := buildDialers(cfg, resolver, testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	registry, err := buildRegistry(cfg, dialers, nil)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	t.Cleanup(registry.Close)
	handler, err := buildHandler(program, registry, dialers, resolver, inbound.NewMetrics(0), testLogger())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	services, err := startInbounds(cfg.General, handler, inbound.NewMetrics(0), testLogger())
	if err != nil {
		t.Fatalf("startInbounds: %v", err)
	}
	t.Cleanup(func() { closeInbounds(services, testLogger()) })
	return program, services
}

// TestInboundsServeFromConfiguration walks the whole assembly: a configuration
// text decides the listen addresses and the credentials, and the resulting
// listeners serve both protocols through the rule pipeline.
func TestInboundsServeFromConfiguration(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "wired origin")
	}))
	defer origin.Close()

	httpPort, socksPort := freePort(t), freePort(t)
	raw := fmt.Sprintf(`[General]
log-level = error
http-listen = 127.0.0.1:%d
socks5-listen = 127.0.0.1:%d
socks5-username = alice
socks5-password = s3cret

[Proxy]
spare = socks5, 127.0.0.1, 9

[Proxy Group]
manual = select, spare, DIRECT

[Rule]
DOMAIN-SUFFIX,internal.test,DIRECT
FINAL,DIRECT
`, httpPort, socksPort)

	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	_, services := wireDaemon(t, cfg)
	if len(services) != 2 {
		t.Fatalf("listeners = %d, want two", len(services))
	}

	target := origin.URL
	host := mustHost(t, target)

	t.Run("http inbound", func(t *testing.T) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpPort))
		if err != nil {
			t.Fatalf("parse proxy URL: %v", err)
		}
		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		}
		defer client.CloseIdleConnections()
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("GET through the http inbound: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "wired origin" {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("socks5 inbound with the configured credentials", func(t *testing.T) {
		client := mustSOCKS5(t, socksPort, "alice", "s3cret")
		conn := mustDial(t, client, host)
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "wired origin" {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("socks5 inbound refuses the wrong password", func(t *testing.T) {
		client := mustSOCKS5(t, socksPort, "alice", "wrong")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if conn, err := client.DialContext(ctx, host); err == nil {
			conn.Close()
			t.Fatal("the listener accepted the wrong password")
		}
	})
}

// TestStartInboundsClosesWhatItOpened checks that a listener which cannot bind
// does not leave the one before it running.
func TestStartInboundsClosesWhatItOpened(t *testing.T) {
	// Hold a port so the second listener cannot have it.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer blocker.Close()
	taken := blocker.Addr().(*net.TCPAddr).Port
	httpPort := freePort(t)

	raw := fmt.Sprintf(`[General]
log-level = error
http-listen = 127.0.0.1:%d
socks5-listen = 127.0.0.1:%d

[Rule]
FINAL,DIRECT
`, httpPort, taken)
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	program := compileTestRules(t, cfg)
	resolver := testResolver(t)
	dialers, err := buildDialers(cfg, resolver, testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	registry, err := buildRegistry(cfg, dialers, nil)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	defer registry.Close()
	handler, err := buildHandler(program, registry, dialers, resolver, inbound.NewMetrics(0), testLogger())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	if _, err := startInbounds(cfg.General, handler, inbound.NewMetrics(0), testLogger()); err == nil {
		t.Fatal("startInbounds accepted an address that is already taken")
	}
	// The HTTP listener that did bind must have been released again.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("the http listener survived a failed startup")
	}
}

// mustHost returns the host:port of a URL.
func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		t.Fatalf("%q is not a URL: %v", rawURL, err)
	}
	return u.Host
}

// mustSOCKS5 builds a SOCKS5 client for a listener on the loopback interface.
func mustSOCKS5(t *testing.T, port int, username, password string) *outbound.SOCKS5 {
	t.Helper()
	client, err := outbound.NewSOCKS5(outbound.SOCKS5Options{
		Server:   "127.0.0.1",
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	return client
}

// mustDial opens a stream with a bounded context.
func mustDial(t *testing.T, dialer outbound.Dialer, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
