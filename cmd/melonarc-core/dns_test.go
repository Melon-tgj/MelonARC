package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// startAssemblyEcho serves an echo endpoint on a loopback port and returns its
// address.
func startAssemblyEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return listener.Addr().String()
}

// TestStateExplainShowsTheResolution checks the report the local API serves for
// /v1/rules/explain: it goes through the pipeline, so a name says which lookup
// decided its address rules instead of pretending the address was given.
func TestStateExplainShowsTheResolution(t *testing.T) {
	raw := `[General]
log-level = error

[Rule]
IP-CIDR,203.0.113.0/24,DIRECT
FINAL,REJECT

[Host]
pinned.test = 203.0.113.7
`
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	program := compileTestRules(t, cfg)
	resolver, err := buildResolver(cfg)
	if err != nil {
		t.Fatalf("buildResolver: %v", err)
	}
	dialers, err := buildDialers(cfg, resolver, testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	defer registry.Close()
	handler, err := buildHandler(program, registry, dialers, resolver, inbound.NewMetrics(0), testLogger())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	state := &daemonState{
		cfg: cfg, program: program, registry: registry, handler: handler,
		version: "test", startedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	view, err := state.Explain(ctx, api.ExplainRequest{Name: "pinned.test", Port: 443, Network: "tcp"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if !view.Matched || view.Target != config.TargetDirect {
		t.Fatalf("decision = %q, want DIRECT", view.Target)
	}
	if view.Resolution == nil || view.Resolution.Source != string(dns.SourceHosts) {
		t.Fatalf("resolution = %+v, want the [Host] source", view.Resolution)
	}
	if len(view.Resolution.Addrs) != 1 || view.Resolution.Addrs[0] != "203.0.113.7" {
		t.Fatalf("resolution addresses = %v", view.Resolution.Addrs)
	}
	if !strings.Contains(view.Report, "resolution: 203.0.113.7 (hosts)") {
		t.Fatalf("report =\n%s\nwant the resolution line", view.Report)
	}
	// The configuration view reports the size of the table, never its content.
	if got := state.Config(ctx).HostCount; got != 1 {
		t.Fatalf("host count = %d, want 1", got)
	}
}

// TestAssemblyResolvesMappedNames checks the wiring the daemon does: the [Host]
// section reaches the resolver, and the DIRECT dialer asks that resolver instead
// of the system one. Without both halves the mapping would apply to rule matching
// only, and a direct connection to a mapped name would still go to the public
// address.
func TestAssemblyResolvesMappedNames(t *testing.T) {
	echo := startAssemblyEcho(t)
	_, port, err := net.SplitHostPort(echo)
	if err != nil {
		t.Fatalf("split %q: %v", echo, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}

	raw := `[General]
log-level = error

[Rule]
IP-CIDR,127.0.0.0/8,DIRECT
FINAL,DIRECT

[Host]
pinned.test = 127.0.0.1
`
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	resolver, err := buildResolver(cfg)
	if err != nil {
		t.Fatalf("buildResolver: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := resolver.Resolve(ctx, "pinned.test")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Source != dns.SourceHosts {
		t.Fatalf("source = %q, want %q: the [Host] table did not reach the resolver",
			res.Source, dns.SourceHosts)
	}

	dialers, err := buildDialers(cfg, resolver, testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	dialer, err := dialers.Dialer(config.TargetDirect)
	if err != nil {
		t.Fatalf("DIRECT is missing: %v", err)
	}
	direct, ok := dialer.(*outbound.Direct)
	if !ok {
		t.Fatalf("DIRECT is %T, want *outbound.Direct", dialer)
	}
	if direct.Lookup == nil {
		t.Fatal("DIRECT has no lookup: a mapped name would be resolved by the system resolver")
	}

	conn, err := direct.DialContext(ctx, net.JoinHostPort("pinned.test", strconv.Itoa(portNumber)))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want %q", buf, "hello")
	}
}
