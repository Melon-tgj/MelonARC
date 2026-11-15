package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/inbound"
)

// apiGet reads one endpoint of the local API with the test token and decodes
// the answer into T.
func apiGet[T any](t *testing.T, srv *api.Server, path string) T {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL()+path, nil)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s answered %d", path, resp.StatusCode)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

// connectThrough performs a CONNECT handshake and returns the status code,
// without failing on a non-200 answer: the failures are the point here.
func connectThrough(t *testing.T, proxyAddr, target string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	var code int
	if _, err := fmt.Sscanf(status, "HTTP/1.1 %d", &code); err != nil {
		t.Fatalf("parse status line %q: %v", strings.TrimSpace(status), err)
	}
	return code
}

// TestAPIShowsInboundMetricsAndFailures starts the assembled core, sends
// connections through the inbound listener - a successful one, a refused one, a
// rejected one and one that needs the [Host] table - and checks that the read
// only endpoints report what happened.
func TestAPIShowsInboundMetricsAndFailures(t *testing.T) {
	echo := startAssemblyEcho(t)
	echoPort := portOf(t, echo)
	deadProxy := freePort(t)
	deadTarget := freePort(t)
	rejectPort := freePort(t)
	httpListen := freePort(t)

	raw := fmt.Sprintf(`[General]
log-level = error
http-listen = 127.0.0.1:%d
socks5-listen = off

[Proxy]
dead = socks5, 127.0.0.1, %d

[Proxy Group]
manual = select, dead, DIRECT

[Host]
proxied.test = 127.0.0.1

[Rule]
DOMAIN,proxied.test,DIRECT
DEST-PORT,%d,DIRECT
DEST-PORT,%d,REJECT
FINAL,manual
`, httpListen, deadProxy, echoPort, rejectPort)

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
	// The mapped name has to be answered by the [Host] table, which is what the
	// DNS counters below have to show.
	dialers, err := buildDialers(cfg, resolver, testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	t.Cleanup(registry.Close)

	metrics := inbound.NewMetrics(inbound.DefaultFailureCapacity)
	handler, err := buildHandler(program, registry, dialers, resolver, metrics, testLogger())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	services, err := startInbounds(cfg.General, handler, metrics, testLogger())
	if err != nil {
		t.Fatalf("startInbounds: %v", err)
	}
	t.Cleanup(func() { closeInbounds(services, testLogger()) })
	if len(services) != 1 {
		t.Fatalf("started %d listeners, want the http one only", len(services))
	}
	proxyAddr := services[0].Addr()

	state := &daemonState{
		cfg:       cfg,
		program:   program,
		registry:  registry,
		handler:   handler,
		metrics:   metrics,
		resolver:  resolver,
		version:   "test",
		startedAt: time.Now(),
	}
	srv, err := api.New(api.Options{Addr: "127.0.0.1:0", Token: "test-token", Provider: state, Version: "test"})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Close(ctx); err != nil {
			t.Errorf("api close: %v", err)
		}
	})

	// Before any traffic every counter is zero and the record is empty.
	if before := apiGet[api.InboundView](t, srv, "/v1/inbound"); before.Accepted != 0 || before.Failures != 0 {
		t.Fatalf("counters before any connection = %+v", before)
	}

	const wantConnections = 4
	if code := connectThrough(t, proxyAddr, echo); code != http.StatusOK {
		t.Fatalf("CONNECT to the origin answered %d, want 200", code)
	}
	if code := connectThrough(t, proxyAddr, fmt.Sprintf("127.0.0.1:%d", deadTarget)); code != http.StatusBadGateway {
		t.Fatalf("CONNECT to a dead destination answered %d, want 502", code)
	}
	if code := connectThrough(t, proxyAddr, fmt.Sprintf("127.0.0.1:%d", rejectPort)); code != http.StatusForbidden {
		t.Fatalf("CONNECT to a rejected destination answered %d, want 403", code)
	}
	if code := connectThrough(t, proxyAddr, fmt.Sprintf("proxied.test:%d", echoPort)); code != http.StatusOK {
		t.Fatalf("CONNECT to a mapped name answered %d, want 200", code)
	}

	// The handlers release their connections asynchronously, so the open count
	// is polled while the accepted count is already final.
	deadline := time.Now().Add(10 * time.Second)
	var inboundView api.InboundView
	for {
		inboundView = apiGet[api.InboundView](t, srv, "/v1/inbound")
		if inboundView.Accepted == wantConnections && inboundView.Open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters did not settle: %+v", inboundView)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if len(inboundView.Inbounds) != 1 || inboundView.Inbounds[0].Protocol != "http" {
		t.Fatalf("listeners = %+v, want the http listener only", inboundView.Inbounds)
	}
	if got := inboundView.Inbounds[0].Accepted; got != wantConnections {
		t.Errorf("accepted = %d, want %d", got, wantConnections)
	}
	if inboundView.Failures != 1 || inboundView.Rejected != 1 {
		t.Errorf("failures = %d, rejected = %d, want 1 and 1", inboundView.Failures, inboundView.Rejected)
	}
	if inboundView.FailureLogCapacity != inbound.DefaultFailureCapacity {
		t.Errorf("failure log capacity = %d, want %d",
			inboundView.FailureLogCapacity, inbound.DefaultFailureCapacity)
	}
	if inboundView.FailureLogCount != 2 {
		t.Errorf("failure log holds %d records, want 2", inboundView.FailureLogCount)
	}

	failures := apiGet[api.FailureListView](t, srv, "/v1/failures")
	if failures.Count != 2 || len(failures.Failures) != 2 {
		t.Fatalf("failures = %+v", failures)
	}
	refused := failures.Failures[0]
	if refused.Target != fmt.Sprintf("127.0.0.1:%d", deadTarget) {
		t.Errorf("first record targets %q", refused.Target)
	}
	if refused.Category != "refused" || refused.Stage != "dial" || refused.Network != "tcp" {
		t.Errorf("first record = %+v, want a refused dial over tcp", refused)
	}
	if refused.Policy != "manual" {
		t.Errorf("first record policy = %q, want the rule target", refused.Policy)
	}
	if refused.Time == "" {
		t.Error("the first record has no timestamp")
	}
	blocked := failures.Failures[1]
	if blocked.Category != "rejected" || blocked.Target != fmt.Sprintf("127.0.0.1:%d", rejectPort) {
		t.Errorf("second record = %+v, want the rejected destination", blocked)
	}

	// A limit narrows the answer but not the record.
	if limited := apiGet[api.FailureListView](t, srv, "/v1/failures?limit=1"); len(limited.Failures) != 1 || limited.Count != 2 {
		t.Errorf("limited view = %+v, want the newest record of two", limited)
	}

	// The manual group never moves off the member the user picked, and the
	// failure it suffered is visible on that member.
	policies := apiGet[struct {
		Policies []api.PolicyView `json:"policies"`
	}](t, srv, "/v1/policies")
	if len(policies.Policies) != 1 {
		t.Fatalf("policies = %+v", policies.Policies)
	}
	manual := policies.Policies[0]
	if manual.Name != "manual" || manual.Active != "dead" {
		t.Fatalf("policy = %+v, want the manual selection to stay on dead", manual)
	}
	if manual.AllUnhealthy {
		t.Errorf("a manual group reported itself all-unhealthy: %+v", manual.Members)
	}
	var deadMember api.MemberView
	for _, m := range manual.Members {
		if m.Name == "dead" {
			deadMember = m
		}
	}
	if deadMember.Failures != 1 {
		t.Errorf("member %q failures = %d, want 1", deadMember.Name, deadMember.Failures)
	}
	if deadMember.CheckedAt == "" {
		t.Error("the member failure carries no timestamp")
	}

	// The mapped name was answered from the [Host] table, so it counts as a
	// resolution and leaves the cache untouched.
	dnsView := apiGet[api.DNSView](t, srv, "/v1/dns")
	if dnsView.MaxEntries != 1024 {
		t.Errorf("max entries = %d, want the default", dnsView.MaxEntries)
	}
	if dnsView.Succeeded < 1 {
		t.Errorf("resolutions succeeded = %d, want the mapped name counted", dnsView.Succeeded)
	}
	if dnsView.Entries != 0 || dnsView.CacheHits != 0 || dnsView.CacheMisses != 0 {
		t.Errorf("dns view = %+v, want an untouched cache for a [Host] answer", dnsView)
	}
}

// portOf returns the port of a host:port address.
func portOf(t *testing.T, address string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("%q is not host:port: %v", address, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q is not a number: %v", port, err)
	}
	return n
}
